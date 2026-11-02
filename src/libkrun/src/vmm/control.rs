//! Correlated native control. Accepted work belongs to the VM, never to a waiting caller.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Instant;

use crossbeam_channel::{Sender, bounded};
pub use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};

use crate::vmm::vstate::VcpuHandle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuCommandKind {
    Park,
    PrepareResume { paused_ticks: u64 },
    Release,
    Stop,
}

#[derive(Clone, Copy, Debug)]
pub struct CpuCommand {
    pub request: RequestId,
    pub barrier: BarrierRequest,
    pub kind: CpuCommandKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuAckKind {
    Parked,
    Prepared,
    Released,
    Stopped,
}

impl CpuCommandKind {
    fn acknowledgement(self) -> CpuAckKind {
        match self {
            Self::Park => CpuAckKind::Parked,
            Self::PrepareResume { .. } => CpuAckKind::Prepared,
            Self::Release => CpuAckKind::Released,
            Self::Stop => CpuAckKind::Stopped,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CpuAck {
    pub request: RequestId,
    pub key: BarrierKey,
    pub cpu_id: u8,
    pub kind: CpuAckKind,
    pub result: Result<(), String>,
}

#[derive(Debug)]
pub enum CpuSubmission {
    Accepted { kick_error: Option<String> },
    Rejected(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlFailure {
    Deadline,
    CallerTimeout,
    OwnerUnavailable,
    WakeUnknown(String),
    Busy,
    InvalidToken,
    InvalidOperation,
    Exhausted,
    Unsupported(String),
    Participant(String),
    FailedFenced,
}

impl std::fmt::Display for ControlFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native control: {self:?}")
    }
}

impl std::error::Error for ControlFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PauseOwner {
    User,
    Capture,
}

#[derive(Clone, Debug)]
pub struct PauseToken {
    run: Arc<()>,
    generation: BarrierGeneration,
    owner: PauseOwner,
}

impl PartialEq for PauseToken {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.run, &other.run)
            && self.generation == other.generation
            && self.owner == other.owner
    }
}
impl Eq for PauseToken {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlState {
    Running,
    Pausing { key: BarrierKey, failed: bool },
    Paused(PauseToken),
    Resuming { key: BarrierKey },
    RollingBack { key: BarrierKey },
    FailedFenced,
    Stopping,
    Stopped,
}

#[derive(Clone, Debug)]
pub enum ControlReply {
    Paused(PauseToken),
    State(ControlState),
    Complete,
}

#[derive(Clone, Debug)]
pub(crate) enum RequestKind {
    Pause(PauseOwner),
    Resume(PauseToken),
    CancelPause(OperationId),
    Status,
    Stop,
}

#[derive(Clone, Debug)]
pub(crate) struct ControlRequest {
    pub id: RequestId,
    pub operation: OperationId,
    pub deadline: Instant,
    pub kind: RequestKind,
    pub reply: Sender<Result<ControlReply, ControlFailure>>,
}

#[derive(Clone)]
pub(crate) struct ControlClient {
    tx: PollableChannelSender<ControlRequest>,
    next_request: Arc<AtomicU64>,
}

impl ControlClient {
    pub fn channel() -> std::io::Result<(Self, PollableChannelReciever<ControlRequest>)> {
        let (tx, rx) = pollable_channel()?;
        Ok((
            Self {
                tx,
                next_request: Arc::new(AtomicU64::new(1)),
            },
            rx,
        ))
    }

    pub fn call(
        &self,
        operation: OperationId,
        deadline: Instant,
        kind: RequestKind,
    ) -> Result<ControlReply, ControlFailure> {
        if Instant::now() >= deadline {
            return Err(ControlFailure::Deadline);
        }
        let id = self
            .next_request
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map(RequestId)
            .map_err(|_| ControlFailure::Exhausted)?;
        let (reply, receiver) = bounded(1);
        // The pollable channel enqueues before waking. A wake error is an unknown
        // outcome, not permission to discard or implicitly cancel the request.
        self.tx
            .send(ControlRequest {
                id,
                operation,
                deadline,
                kind,
                reply,
            })
            .map_err(|error| ControlFailure::WakeUnknown(error.to_string()))?;
        receiver
            .recv_deadline(deadline)
            .map_err(|error| match error {
                crossbeam_channel::RecvTimeoutError::Timeout => ControlFailure::CallerTimeout,
                crossbeam_channel::RecvTimeoutError::Disconnected => {
                    ControlFailure::OwnerUnavailable
                }
            })?
    }
}

#[derive(Default)]
struct CpuSlot {
    accepted: bool,
    acknowledgement: Option<Result<(), String>>,
}

struct CpuBatch {
    command: CpuCommand,
    slots: Vec<CpuSlot>,
}

/// The actual backend mailbox journal, also used by the diagnostic native probe.
/// This is a CPU sub-barrier and cannot mint a whole-machine pause token.
pub(crate) struct CpuController {
    count: usize,
    batches: Vec<CpuBatch>,
}

impl CpuController {
    pub fn new(cpu_count: usize) -> Self {
        Self {
            count: cpu_count,
            batches: Vec::with_capacity(3),
        }
    }

    pub fn active_request(&self) -> Option<(RequestId, BarrierRequest, CpuCommandKind)> {
        self.batches.last().map(|batch| {
            (
                batch.command.request,
                batch.command.barrier,
                batch.command.kind,
            )
        })
    }

    pub fn reconciled(&self) -> bool {
        self.batches.iter().all(|batch| {
            batch
                .slots
                .iter()
                .all(|slot| !slot.accepted || slot.acknowledgement.is_some())
        })
    }

    pub fn begin(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
        kind: CpuCommandKind,
        handles: &[VcpuHandle],
    ) -> Result<(), ControlFailure> {
        if handles.len() != self.count || self.count == 0 {
            return Err(ControlFailure::Unsupported(
                "empty or changed CPU topology".into(),
            ));
        }
        if self.reconciled() {
            self.batches.clear();
        } else if kind != CpuCommandKind::Stop
            && !self.batches.last().is_some_and(|batch| {
                kind == CpuCommandKind::Park
                    && batch.command.kind == CpuCommandKind::Park
                    && batch.command.barrier.key == barrier.key
            })
        {
            return Err(ControlFailure::Busy);
        }
        let command = CpuCommand {
            request,
            barrier,
            kind,
        };
        let mut batch = CpuBatch {
            command,
            slots: (0..self.count).map(|_| CpuSlot::default()).collect(),
        };
        let mut failure = None;
        for (index, handle) in handles.iter().enumerate() {
            match handle.send_control(command) {
                CpuSubmission::Accepted { kick_error } => {
                    batch.slots[index].accepted = true;
                    if let Some(error) = kick_error {
                        failure.get_or_insert(ControlFailure::Participant(error));
                    }
                }
                CpuSubmission::Rejected(error) => {
                    failure.get_or_insert(ControlFailure::Participant(error));
                }
            }
        }
        self.batches.push(batch);
        failure.map_or(Ok(()), Err)
    }

    fn acknowledge(&mut self, source: usize, ack: CpuAck) {
        if usize::from(ack.cpu_id) != source {
            return;
        }
        for batch in &mut self.batches {
            if batch.command.request == ack.request
                && batch.command.barrier.key == ack.key
                && batch.command.kind.acknowledgement() == ack.kind
            {
                if let Some(slot) = batch.slots.get_mut(source)
                    && slot.accepted
                    && slot.acknowledgement.is_none()
                {
                    slot.acknowledgement = Some(ack.result);
                }
                return;
            }
        }
    }

    pub fn poll(&mut self, handles: &mut [VcpuHandle]) -> Poll<Result<(), ControlFailure>> {
        for (index, handle) in handles.iter().enumerate() {
            loop {
                match handle.try_control_ack() {
                    Ok(Some(ack)) => self.acknowledge(index, ack),
                    Ok(None) => break,
                    Err(error) => {
                        if self.batches.last().is_some_and(|batch| {
                            batch.command.kind != CpuCommandKind::Stop
                                && batch.slots[index].acknowledgement.is_none()
                        }) {
                            return Poll::Ready(Err(ControlFailure::Participant(error)));
                        }
                        break;
                    }
                }
            }
        }
        let Some(batch) = self.batches.last() else {
            return Poll::Ready(Ok(()));
        };
        if batch.command.kind == CpuCommandKind::Stop {
            let mut pending = false;
            for handle in handles {
                match handle.reap() {
                    Ok(true) => {}
                    Ok(false) => pending = true,
                    Err(error) => return Poll::Ready(Err(ControlFailure::Participant(error))),
                }
            }
            if !pending {
                return Poll::Ready(Ok(()));
            }
        } else {
            for slot in &batch.slots {
                if !slot.accepted {
                    return Poll::Ready(Err(ControlFailure::Participant(
                        "CPU command was not accepted".into(),
                    )));
                }
                if let Some(Err(error)) = &slot.acknowledgement {
                    return Poll::Ready(Err(ControlFailure::Participant(error.clone())));
                }
            }
            if self.reconciled() {
                return Poll::Ready(Ok(()));
            }
        }
        if Instant::now() >= batch.command.barrier.deadline {
            Poll::Ready(Err(ControlFailure::Deadline))
        } else {
            Poll::Pending
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Park,
    Devices,
    Maintenance,
    Routes,
    CancelPark,
    CancelDevices,
    Rearm,
    ResumeDevices,
    Prepare,
    Release,
    Stop,
}

pub(crate) struct ActiveControl {
    pub request: ControlRequest,
    pub barrier: BarrierRequest,
    pub original: BarrierKey,
    pub owner: PauseOwner,
    pub phase: Phase,
    pub failed: bool,
    pub devices_begun: bool,
    pub routes_begun: bool,
    pub maintenance_closed: bool,
    pub cpu_parked_at: Option<u64>,
}

pub(crate) struct ControlOwner {
    pub client: ControlClient,
    pub receiver: PollableChannelReciever<ControlRequest>,
    pub state: ControlState,
    pub active: Option<ActiveControl>,
    pub cpus: CpuController,
    run: Arc<()>,
    generation: u64,
    last_operation: u64,
}

impl ControlOwner {
    pub fn new() -> std::io::Result<Self> {
        let (client, receiver) = ControlClient::channel()?;
        Ok(Self {
            client,
            receiver,
            state: ControlState::Running,
            active: None,
            cpus: CpuController::new(0),
            run: Arc::new(()),
            generation: 0,
            last_operation: 0,
        })
    }

    pub fn reserve(&mut self, operation: OperationId) -> Result<(), ControlFailure> {
        if operation.0 <= self.last_operation {
            return Err(ControlFailure::InvalidOperation);
        }
        self.last_operation = operation.0;
        Ok(())
    }

    pub fn next_key(&mut self, operation: OperationId) -> Result<BarrierKey, ControlFailure> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(ControlFailure::Exhausted)?;
        Ok(BarrierKey {
            operation,
            generation: BarrierGeneration(self.generation),
        })
    }

    pub fn token(&self, key: BarrierKey, owner: PauseOwner) -> PauseToken {
        PauseToken {
            run: self.run.clone(),
            generation: key.generation,
            owner,
        }
    }

    pub fn validate_token(&self, token: &PauseToken) -> bool {
        matches!(&self.state, ControlState::Paused(current) if current == token)
    }
}

impl crate::vmm::Vmm {
    pub(crate) fn register_control_roles(
        &self,
        events: &mut polly::event_manager::EventManager,
    ) -> Result<(), polly::event_manager::Error> {
        use polly::event_manager::DispatchRole;
        use std::os::fd::AsRawFd;
        events.set_dispatch_role(self.control.receiver.as_raw_fd(), DispatchRole::Control)?;
        events.set_dispatch_role(self.exit_evt.as_raw_fd(), DispatchRole::Exit)
    }

    pub(crate) fn control_pending(&self) -> bool {
        self.control.active.is_some() && !matches!(self.control.state, ControlState::Paused(_))
    }

    pub(crate) fn service_control(&mut self, events: &mut polly::event_manager::EventManager) {
        while let Ok(Some(request)) = self.control.receiver.try_recv() {
            let reply = request.reply.clone();
            if let Err(error) = self.accept_control(request, events) {
                let _ = reply.try_send(Err(error));
            }
        }
        self.poll_control(events);
    }

    fn accept_control(
        &mut self,
        request: ControlRequest,
        events: &mut polly::event_manager::EventManager,
    ) -> Result<(), ControlFailure> {
        if matches!(request.kind, RequestKind::Status) {
            let _ = request
                .reply
                .try_send(Ok(ControlReply::State(self.control.state.clone())));
            return Ok(());
        }
        if Instant::now() >= request.deadline {
            return Err(ControlFailure::Deadline);
        }
        if matches!(request.kind, RequestKind::Stop) {
            self.control.reserve(request.operation)?;
            if let Some(previous) = self.control.active.take() {
                let _ = previous
                    .request
                    .reply
                    .try_send(Err(ControlFailure::FailedFenced));
            }
            let barrier = BarrierRequest {
                key: BarrierKey {
                    operation: request.operation,
                    generation: BarrierGeneration(self.control.generation),
                },
                deadline: request.deadline,
            };
            self.control.state = ControlState::Stopping;
            self.control.active = Some(ActiveControl {
                request,
                barrier,
                original: barrier.key,
                owner: PauseOwner::User,
                phase: Phase::Stop,
                failed: false,
                devices_begun: false,
                routes_begun: false,
                maintenance_closed: false,
                cpu_parked_at: None,
            });
            let active = self
                .control
                .active
                .as_ref()
                .ok_or(ControlFailure::FailedFenced)?;
            // Even rejection cannot release the remaining accepted stop commands.
            let _ = self.control.cpus.begin(
                active.request.id,
                barrier,
                CpuCommandKind::Stop,
                &self.vcpus_handles,
            );
            return Ok(());
        }
        match &request.kind {
            RequestKind::Pause(owner) => {
                if self.control.state != ControlState::Running {
                    return Err(ControlFailure::Busy);
                }
                if self.vcpus_handles.is_empty() {
                    return Err(ControlFailure::Unsupported("empty CPU topology".into()));
                }
                self.mmio_device_manager
                    .preflight_quiesce()
                    .map_err(|error| ControlFailure::Unsupported(error.to_string()))?;
                self.control.reserve(request.operation)?;
                let barrier = BarrierRequest {
                    key: self.control.next_key(request.operation)?,
                    deadline: request.deadline,
                };
                let owner = *owner;
                self.control.state = ControlState::Pausing {
                    key: barrier.key,
                    failed: false,
                };
                self.control.active = Some(ActiveControl {
                    request,
                    barrier,
                    original: barrier.key,
                    owner,
                    phase: Phase::Park,
                    failed: false,
                    devices_begun: false,
                    routes_begun: false,
                    maintenance_closed: false,
                    cpu_parked_at: None,
                });
                // A partially installed ingress fence remains journal-owned on error.
                let result = events
                    .begin_ingress_fence(barrier)
                    .map_err(|error| ControlFailure::Participant(format!("{error:?}")))
                    .and_then(|()| {
                        let id = self
                            .control
                            .active
                            .as_ref()
                            .map(|active| active.request.id)
                            .ok_or(ControlFailure::FailedFenced)?;
                        self.control.cpus.begin(
                            id,
                            barrier,
                            CpuCommandKind::Park,
                            &self.vcpus_handles,
                        )
                    });
                if let Err(error) = result {
                    self.fail_control(error);
                }
                Ok(())
            }
            RequestKind::Resume(token) => {
                if !self.control.validate_token(token) {
                    return Err(ControlFailure::InvalidToken);
                }
                self.control.reserve(request.operation)?;
                let mut active = self
                    .control
                    .active
                    .take()
                    .ok_or(ControlFailure::InvalidToken)?;
                active.barrier = BarrierRequest {
                    key: BarrierKey {
                        operation: request.operation,
                        generation: active.original.generation,
                    },
                    deadline: request.deadline,
                };
                active.request = request;
                active.phase = Phase::Rearm;
                active.failed = false;
                self.control.state = ControlState::Resuming {
                    key: active.barrier.key,
                };
                self.control.active = Some(active);
                self.begin_rearm();
                Ok(())
            }
            RequestKind::CancelPause(original) => {
                if !matches!(self.control.state, ControlState::Pausing { key, .. } if key.operation == *original)
                {
                    return Err(ControlFailure::InvalidOperation);
                }
                self.control.reserve(request.operation)?;
                let mut active = self
                    .control
                    .active
                    .take()
                    .ok_or(ControlFailure::InvalidOperation)?;
                let _ = active
                    .request
                    .reply
                    .try_send(Err(ControlFailure::Participant(
                        "pause explicitly cancelled".into(),
                    )));
                active.barrier = BarrierRequest {
                    key: BarrierKey {
                        operation: request.operation,
                        generation: active.original.generation,
                    },
                    deadline: request.deadline,
                };
                active.request = request;
                active.phase = Phase::CancelPark;
                active.failed = false;
                self.control.state = ControlState::RollingBack {
                    key: active.barrier.key,
                };
                let reconcile = BarrierRequest {
                    key: active.original,
                    deadline: active.barrier.deadline,
                };
                let id = active.request.id;
                self.control.active = Some(active);
                if let Err(error) = self.control.cpus.begin(
                    id,
                    reconcile,
                    CpuCommandKind::Park,
                    &self.vcpus_handles,
                ) {
                    self.fail_control(error);
                }
                Ok(())
            }
            RequestKind::Status | RequestKind::Stop => Err(ControlFailure::InvalidOperation),
        }
    }

    fn fail_control(&mut self, error: ControlFailure) {
        if let Some(active) = &mut self.control.active {
            active.failed = true;
            self.control.state = match active.phase {
                Phase::Park | Phase::Devices | Phase::Maintenance | Phase::Routes => {
                    ControlState::Pausing {
                        key: active.original,
                        failed: true,
                    }
                }
                Phase::Stop => ControlState::Stopping,
                _ => ControlState::FailedFenced,
            };
            let _ = active.request.reply.try_send(Err(error));
        }
    }

    fn begin_rearm(&mut self) {
        let Some(active) = &mut self.control.active else {
            return;
        };
        if !active.routes_begun {
            active.phase = Phase::ResumeDevices;
            return;
        }
        #[cfg(target_os = "linux")]
        let result = self.mmio_device_manager.begin_irq_rearm(
            self.vm.fd_owner(),
            active.original,
            active.barrier,
        );
        #[cfg(target_os = "macos")]
        let result = self
            .mmio_device_manager
            .begin_irq_rearm(active.original, active.barrier);
        if let Err(error) = result {
            self.fail_control(ControlFailure::Participant(error.to_string()));
        }
    }

    pub(crate) fn poll_control(&mut self, events: &mut polly::event_manager::EventManager) {
        let Some(mut active) = self.control.active.take() else {
            return;
        };
        let result = self.advance_control(&mut active, events);
        self.control.active = Some(active);
        match result {
            Err(error) => {
                self.fail_control(error);
                if self.control.state == ControlState::FailedFenced {
                    if let Some(active) = &self.control.active
                        && let Err(error) = events.fail_closed(active.barrier)
                    {
                        log::error!("failed native control safety fence: {error:?}");
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(remapper) = self.vm.host_memory_remapper() {
                        remapper.close_admission();
                    }
                }
            }
            Ok(false) => {}
            Ok(true) => {
                if matches!(
                    self.control.state,
                    ControlState::Running | ControlState::Stopped
                ) {
                    self.control.active = None;
                }
            }
        }
    }

    fn advance_control(
        &mut self,
        active: &mut ActiveControl,
        events: &mut polly::event_manager::EventManager,
    ) -> Result<bool, ControlFailure> {
        if active.failed && active.phase != Phase::Stop {
            let _ = self.control.cpus.poll(&mut self.vcpus_handles);
            if active.devices_begun {
                let _ = self
                    .mmio_device_manager
                    .quiescence
                    .poll_quiesce(active.original);
            }
            if active.routes_begun {
                let _ = self.mmio_device_manager.poll_irq_routes(active.original);
            }
            return Ok(false);
        }
        if matches!(self.control.state, ControlState::Paused(_)) {
            return Ok(false);
        }
        if Instant::now() >= active.barrier.deadline && active.phase != Phase::Stop {
            return Err(ControlFailure::Deadline);
        }
        match active.phase {
            Phase::Park | Phase::CancelPark => {
                match self.control.cpus.poll(&mut self.vcpus_handles) {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(result) => result?,
                }
                if active.cpu_parked_at.is_none() {
                    active.cpu_parked_at = Some(cpu_clock());
                }
                if active.phase == Phase::CancelPark {
                    active.phase = Phase::CancelDevices;
                } else {
                    let result = self
                        .mmio_device_manager
                        .quiescence
                        .begin_quiesce(active.barrier);
                    active.devices_begun = self
                        .mmio_device_manager
                        .quiescence
                        .request()
                        .is_some_and(|request| request.key == active.original);
                    result.map_err(|error| ControlFailure::Participant(error.to_string()))?;
                    active.phase = Phase::Devices;
                }
            }
            Phase::Devices => {
                match self
                    .mmio_device_manager
                    .quiescence
                    .poll_quiesce(active.original)
                {
                    Ok(Poll::Pending) => return Ok(false),
                    Ok(Poll::Ready(())) => {}
                    Err(error) => return Err(ControlFailure::Participant(error.to_string())),
                }
                active.phase = Phase::Maintenance;
                #[cfg(target_os = "macos")]
                if let Some(remapper) = self.vm.host_memory_remapper() {
                    remapper.close_admission();
                }
                active.maintenance_closed = true;
            }
            Phase::Maintenance => {
                #[cfg(target_os = "macos")]
                if let Some(remapper) = self.vm.host_memory_remapper() {
                    if !remapper
                        .poll_quiesced()
                        .map_err(|error| ControlFailure::Participant(error.to_string()))?
                    {
                        return Ok(false);
                    }
                }
                events
                    .park_callbacks(active.original)
                    .map_err(|error| ControlFailure::Participant(format!("{error:?}")))?;
                active.phase = Phase::Routes;
                #[cfg(target_os = "linux")]
                let result = self
                    .mmio_device_manager
                    .begin_irq_fence(self.vm.fd_owner(), active.barrier);
                #[cfg(target_os = "macos")]
                let result = self.mmio_device_manager.begin_irq_fence(active.barrier);
                active.routes_begun =
                    self.mmio_device_manager.irq_barrier_key() == Some(active.original);
                result.map_err(|error| ControlFailure::Participant(error.to_string()))?;
            }
            Phase::Routes => {
                match self
                    .mmio_device_manager
                    .poll_irq_routes(active.original)
                    .map_err(|error| ControlFailure::Participant(error.to_string()))?
                {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(()) => {}
                }
                if Instant::now() >= active.barrier.deadline {
                    return Err(ControlFailure::Deadline);
                }
                let token = self.control.token(active.original, active.owner);
                self.control.state = ControlState::Paused(token.clone());
                let _ = active
                    .request
                    .reply
                    .try_send(Ok(ControlReply::Paused(token)));
                return Ok(true);
            }
            Phase::CancelDevices => {
                if active.devices_begun {
                    let _ = self
                        .mmio_device_manager
                        .quiescence
                        .poll_quiesce(active.original);
                    if !self
                        .mmio_device_manager
                        .quiescence
                        .quiescence_settled(active.original)
                        .map_err(|error| ControlFailure::Participant(error.to_string()))?
                    {
                        return Ok(false);
                    }
                }
                if active.routes_begun {
                    let _ = self.mmio_device_manager.poll_irq_routes(active.original);
                    #[cfg(target_os = "linux")]
                    if self.mmio_device_manager.irq_routes().is_none() {
                        return Ok(false);
                    }
                }
                active.phase = Phase::Rearm;
                if active.routes_begun {
                    #[cfg(target_os = "linux")]
                    let result = self.mmio_device_manager.begin_irq_rearm(
                        self.vm.fd_owner(),
                        active.original,
                        active.barrier,
                    );
                    #[cfg(target_os = "macos")]
                    let result = self
                        .mmio_device_manager
                        .begin_irq_rearm(active.original, active.barrier);
                    result.map_err(|error| ControlFailure::Participant(error.to_string()))?;
                } else {
                    active.phase = Phase::ResumeDevices;
                }
            }
            Phase::Rearm => {
                match self
                    .mmio_device_manager
                    .poll_irq_routes(active.barrier.key)
                    .map_err(|error| ControlFailure::Participant(error.to_string()))?
                {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(()) => active.phase = Phase::ResumeDevices,
                }
            }
            Phase::ResumeDevices => {
                if active.devices_begun {
                    self.mmio_device_manager
                        .quiescence
                        .begin_resume(active.original, active.barrier)
                        .map_err(|error| ControlFailure::Participant(error.to_string()))?;
                }
                active.phase = Phase::Prepare;
            }
            Phase::Prepare => {
                if active.devices_begun {
                    match self
                        .mmio_device_manager
                        .quiescence
                        .poll_resume(active.barrier.key)
                        .map_err(|error| ControlFailure::Participant(error.to_string()))?
                    {
                        Poll::Pending => return Ok(false),
                        Poll::Ready(()) => {}
                    }
                }
                #[cfg(target_os = "macos")]
                if active.maintenance_closed {
                    if let Some(remapper) = self.vm.host_memory_remapper() {
                        remapper.reopen_admission();
                    }
                }
                events
                    .reopen_ingress(active.original, active.barrier)
                    .map_err(|error| ControlFailure::Participant(format!("{error:?}")))?;
                let paused_ticks = cpu_clock()
                    .checked_sub(active.cpu_parked_at.unwrap_or_else(cpu_clock))
                    .ok_or(ControlFailure::Exhausted)?;
                self.control.cpus.begin(
                    active.request.id,
                    active.barrier,
                    CpuCommandKind::PrepareResume { paused_ticks },
                    &self.vcpus_handles,
                )?;
                active.phase = Phase::Release;
            }
            Phase::Release => {
                match self.control.cpus.poll(&mut self.vcpus_handles) {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(result) => result?,
                }
                if self
                    .control
                    .cpus
                    .active_request()
                    .is_some_and(|(_, _, kind)| {
                        matches!(kind, CpuCommandKind::PrepareResume { .. })
                    })
                {
                    self.control.cpus.begin(
                        active.request.id,
                        active.barrier,
                        CpuCommandKind::Release,
                        &self.vcpus_handles,
                    )?;
                } else {
                    if Instant::now() >= active.barrier.deadline {
                        return Err(ControlFailure::Deadline);
                    }
                    self.control.state = ControlState::Running;
                    let _ = active.request.reply.try_send(Ok(ControlReply::Complete));
                    return Ok(true);
                }
            }
            Phase::Stop => {
                match self.control.cpus.poll(&mut self.vcpus_handles) {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(Err(ControlFailure::Deadline)) => {
                        let _ = active.request.reply.try_send(Err(ControlFailure::Deadline));
                        return Ok(false);
                    }
                    Poll::Ready(result) => result?,
                }
                // IRQ workers retain their own VM fd and route owners. Reclaim
                // them before allowing the outer VM resources to be dropped.
                if !self.mmio_device_manager.poll_irq_cleanup() {
                    return Ok(false);
                }
                self.stop(i32::from(crate::vmm::FC_EXIT_CODE_OK));
                return Ok(false);
            }
        }
        Ok(false)
    }
}

fn cpu_clock() -> u64 {
    #[cfg(target_os = "macos")]
    {
        unsafe { hvf::mach_absolute_time() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use crate::vmm::control::{
        ControlOwner, ControlState, CpuAck, CpuAckKind, CpuBatch, CpuCommand, CpuCommandKind,
        CpuController, CpuSlot, PauseOwner, RequestId,
    };
    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
    use std::time::{Duration, Instant};

    fn key() -> BarrierKey {
        BarrierKey {
            operation: OperationId(1),
            generation: BarrierGeneration(1),
        }
    }

    fn journal() -> CpuController {
        CpuController {
            count: 2,
            batches: vec![CpuBatch {
                command: CpuCommand {
                    request: RequestId(7),
                    barrier: BarrierRequest {
                        key: key(),
                        deadline: Instant::now() + Duration::from_secs(1),
                    },
                    kind: CpuCommandKind::Park,
                },
                slots: (0..2)
                    .map(|_| CpuSlot {
                        accepted: true,
                        acknowledgement: None,
                    })
                    .collect(),
            }],
        }
    }

    fn ack(cpu_id: u8) -> CpuAck {
        CpuAck {
            request: RequestId(7),
            key: key(),
            cpu_id,
            kind: CpuAckKind::Parked,
            result: Ok(()),
        }
    }

    #[test]
    fn cpu_journal_requires_every_exact_ack() {
        let mut journal = journal();
        let mut wrong = ack(0);
        wrong.request = RequestId(8);
        journal.acknowledge(0, wrong);
        journal.acknowledge(1, ack(0));
        assert!(!journal.reconciled());
        let mut wrong_generation = ack(0);
        wrong_generation.key.generation = BarrierGeneration(2);
        journal.acknowledge(0, wrong_generation);
        let mut wrong_kind = ack(0);
        wrong_kind.kind = CpuAckKind::Released;
        journal.acknowledge(0, wrong_kind);
        journal.acknowledge(0, ack(0));
        journal.acknowledge(0, ack(0));
        assert!(!journal.reconciled());
        journal.acknowledge(1, ack(1));
        assert!(journal.reconciled());
    }

    #[test]
    fn control_client_drop_retains_accepted_request() {
        use crate::vmm::control::{ControlClient, ControlReply, ControlRequest, RequestKind};
        let (client, receiver) = ControlClient::channel().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let (reply, waiting_caller) = crossbeam_channel::bounded(1);
        client
            .tx
            .send(ControlRequest {
                id: RequestId(1),
                operation: OperationId(1),
                deadline,
                kind: RequestKind::Pause(PauseOwner::User),
                reply,
            })
            .unwrap();
        drop(waiting_caller);
        let request = receiver.try_recv().unwrap().unwrap();
        assert_eq!(request.operation, OperationId(1));
        assert_eq!(request.deadline, deadline);
        assert!(request.reply.try_send(Ok(ControlReply::Complete)).is_err());
    }

    #[test]
    fn control_tokens_are_run_bound_and_consumed() {
        let mut owner = ControlOwner::new().unwrap();
        let foreign = ControlOwner::new().unwrap();
        let token = owner.token(key(), PauseOwner::User);
        owner.state = ControlState::Paused(token.clone());
        assert!(owner.validate_token(&token));
        assert!(!owner.validate_token(&foreign.token(key(), PauseOwner::User)));
        assert!(!owner.validate_token(&owner.token(key(), PauseOwner::Capture)));
        assert!(!owner.validate_token(&owner.token(
            BarrierKey {
                generation: BarrierGeneration(2),
                ..key()
            },
            PauseOwner::User
        )));
        owner.state = ControlState::Running;
        assert!(!owner.validate_token(&token));
        owner.generation = u64::MAX;
        assert!(owner.next_key(OperationId(2)).is_err());
    }

    #[test]
    fn cpu_journal_reconciliation_keeps_late_original_ownership() {
        let mut journal = journal();
        let deadline = journal.batches[0].command.barrier.deadline;
        let original = journal.batches[0].command;
        journal.batches.push(CpuBatch {
            command: CpuCommand {
                request: RequestId(8),
                ..original
            },
            slots: (0..2)
                .map(|_| CpuSlot {
                    accepted: true,
                    acknowledgement: None,
                })
                .collect(),
        });
        for cpu in 0..2 {
            journal.acknowledge(
                cpu,
                CpuAck {
                    request: RequestId(8),
                    ..ack(cpu as u8)
                },
            );
        }
        assert!(!journal.reconciled());
        assert_eq!(journal.batches[0].command.barrier.deadline, deadline);
        for cpu in 0..2 {
            journal.acknowledge(cpu, ack(cpu as u8));
        }
        assert!(journal.reconciled());
    }

    #[test]
    fn control_operation_ids_never_reuse_authority() {
        let mut owner = ControlOwner::new().unwrap();
        assert!(owner.reserve(OperationId(1)).is_ok());
        assert!(owner.reserve(OperationId(1)).is_err());
        assert!(owner.reserve(OperationId(0)).is_err());
        assert!(owner.reserve(OperationId(2)).is_ok());
    }
}
