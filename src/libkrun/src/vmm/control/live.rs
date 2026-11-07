use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
#[cfg(any(
    test,
    all(
        not(feature = "tee"),
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            all(target_os = "macos", target_arch = "aarch64")
        )
    )
))]
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex, TryLockError};
use std::task::Poll;
use std::time::Instant;

use crossbeam_channel::Sender;
use devices::virtio::VirtioDevice;
use devices::virtio::generation::GenerationObservation;
use devices::virtio::lifecycle::{ActivationExposure, ProviderFault};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};

#[cfg(any(
    test,
    all(
        not(feature = "tee"),
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            all(target_os = "macos", target_arch = "aarch64")
        )
    )
))]
use crate::api::live::OutputReceipt;
use crate::api::live::{
    ActivationStage, BaselineImage, CaptureId, CaptureStage, CaptureStatus, CaptureTicket,
    CompletedCapture, ExecutionCaptureReceipt, ExecutionOutputs, FlushReceipt, LiveError,
    LiveSnapshot, LiveStage, LiveSubject, MemoryCaptureRequest, MemoryOutputs, OutputProblem,
    OutputRole,
};
use crate::vmm::Vmm;
use crate::vmm::control::{
    BarrierKey, BarrierRequest, ControlFailure, ControlOwner, ControlReply, ControlState,
    GenerationTicket, OperationId, PauseOwner, PauseToken, Phase, RequestId, RequestKind,
    RestoreToken,
};
use crate::vmm::execution::StateBinding;
use crate::vmm::memory::image::{RamOutputFiles, ValidatedRamLayout};
use crate::vmm::memory::{AttemptId, CompletedCandidate, DirtyCrossoverPercent, RamCaptureRequest};

type Reply = Sender<Result<ControlReply, ControlFailure>>;

#[derive(Debug)]
pub(crate) enum LiveRequest {
    Flush(PauseToken),
    Execution {
        pause: PauseToken,
        binding: Box<StateBinding>,
        outputs: ExecutionOutputs,
    },
    Memory {
        ticket: CaptureTicket,
        request: MemoryCaptureRequest,
        outputs: MemoryOutputs,
    },
    Status(CaptureId),
    Accept {
        ticket: CaptureTicket,
        sealed: Box<BaselineImage>,
    },
    Abandon(CaptureTicket),
    Release(CaptureId),
    Preserve(PauseToken),
    RecoverMemoryCut {
        pausing: OperationId,
    },
    Generation(GenerationTicket),
    Activation {
        restore: RestoreToken,
        generation: GenerationTicket,
    },
    Layout,
    Snapshot,
    Baseline,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    Profile(crate::vmm::linux::execution::KvmCaptureProfile),
    #[cfg(all(
        feature = "native-device-probe",
        feature = "blk",
        feature = "net",
        target_os = "linux",
        target_arch = "x86_64",
        not(any(feature = "tee", feature = "aws-nitro"))
    ))]
    IrqProbe(crate::api::live::irq_probe::ProbeRequest),
}
impl LiveRequest {
    pub(crate) fn context(&self) -> (LiveStage, LiveSubject) {
        match self {
            Self::Flush(pause) => (LiveStage::Flush, LiveSubject::Pause(pause.clone())),
            Self::Execution { binding, .. } => (
                LiveStage::Execution,
                LiveSubject::Capture(CaptureId::new(binding.capture)),
            ),
            Self::Memory { ticket, .. } => (LiveStage::Memory, LiveSubject::Capture(ticket.id())),
            Self::Status(id) => (LiveStage::Status, LiveSubject::Capture(*id)),
            Self::Accept { ticket, .. } => (LiveStage::Accept, LiveSubject::Capture(ticket.id())),
            Self::Abandon(ticket) => (LiveStage::Abandon, LiveSubject::Capture(ticket.id())),
            Self::Release(id) => (LiveStage::Release, LiveSubject::Capture(*id)),
            Self::Preserve(pause) => (LiveStage::Preserve, LiveSubject::Pause(pause.clone())),
            Self::RecoverMemoryCut { pausing } => {
                (LiveStage::MemoryCutRecovery, LiveSubject::Pausing(*pausing))
            }
            Self::Generation(ticket) => (
                LiveStage::GenerationPoll,
                LiveSubject::Generation(ticket.clone()),
            ),
            Self::Activation { restore, .. } => (
                LiveStage::ActivationRelease,
                LiveSubject::Restore(restore.clone()),
            ),
            Self::Layout | Self::Snapshot | Self::Baseline => {
                (LiveStage::Observation, LiveSubject::Vm)
            }
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Self::Profile(_) => (LiveStage::Profile, LiveSubject::Vm),
            #[cfg(all(
                feature = "native-device-probe",
                feature = "blk",
                feature = "net",
                target_os = "linux",
                target_arch = "x86_64",
                not(any(feature = "tee", feature = "aws-nitro"))
            ))]
            Self::IrqProbe(_) => (LiveStage::Observation, LiveSubject::Vm),
        }
    }
}
#[derive(Clone, Debug)]
pub enum LiveReply {
    Flush(FlushReceipt),
    Execution(Arc<ExecutionCaptureReceipt>),
    Memory(CompletedCapture),
    Status(CaptureStatus),
    Baseline(crate::vmm::memory::BaselineToken),
    CurrentBaseline(Option<crate::vmm::memory::BaselineToken>),
    Pause(PauseToken),
    Generation(GenerationObservation),
    Layout(Arc<ValidatedRamLayout>),
    Snapshot(LiveSnapshot),
    Complete,
    #[cfg(all(
        feature = "native-device-probe",
        feature = "blk",
        feature = "net",
        target_os = "linux",
        target_arch = "x86_64",
        not(any(feature = "tee", feature = "aws-nitro"))
    ))]
    IrqProbe(crate::api::live::irq_probe::ProbeObservation),
}
struct PendingExecution {
    outputs: ExecutionOutputs,
    reply: Reply,
}
struct CaptureRecord {
    ticket: CaptureTicket,
    operation: OperationId,
    status: CaptureStatus,
    execution: Option<Arc<ExecutionCaptureReceipt>>,
    pending: Option<PendingExecution>,
    execution_failure: Option<LiveError>,
    attempt: Option<AttemptId>,
    candidate: Option<CompletedCandidate>,
    accepted_stream: Option<[u8; 32]>,
    terminal: bool,
}
impl CaptureRecord {
    fn resolved(&self) -> bool {
        matches!(
            self.status,
            CaptureStatus::Accepted { .. } | CaptureStatus::Abandoned(_)
        )
    }
}
struct ActivationDevice {
    device: Arc<Mutex<dyn VirtioDevice>>,
    begun: bool,
    prepared: bool,
}
/// All-provider activation exposure, a prepare-all/commit barrier:
///
/// ```text
///   begin/poll each provider ── fallible, gate closed, nothing visible
///        │ any failure, deadline, stop, revoked authority, invalidation
///        ├──────────────────────────────► seal(): no provider ever exposed
///        │ every provider prepared
///        ▼
///   hold every provider lock ─► re-validate each prepared state
///        ─► recheck authority + deadline ─► exposure.open(): one atomic commit
/// ```
///
/// Providers bind `exposure` on acceptance and stay effectively fenced until it
/// opens, so a provider that prepares before another fails exposes nothing and
/// no rollback is ever needed. Holding every provider lock across validation
/// and the open means no worker restart, reset or quiesce can replace a
/// prepared state between its proof and the commit.
struct ActivationBarrier {
    request: BarrierRequest,
    exposure: ActivationExposure,
    devices: Vec<ActivationDevice>,
}
/// The retained restore authority and caller of one accepted release.
struct ActivationRelease {
    restore: RestoreToken,
    generation: GenerationTicket,
    barrier: ActivationBarrier,
    reply: Reply,
}
impl ActivationBarrier {
    fn new(request: BarrierRequest, devices: Vec<Arc<Mutex<dyn VirtioDevice>>>) -> Self {
        Self {
            request,
            exposure: ActivationExposure::new(),
            devices: devices
                .into_iter()
                .map(|device| ActivationDevice {
                    device,
                    begun: false,
                    prepared: false,
                })
                .collect(),
        }
    }
    fn failure(&self, stage: ActivationStage, fault: ProviderFault) -> LiveError {
        LiveError::Activation {
            stage,
            fault,
            accepted: self.devices.iter().any(|entry| entry.begun),
        }
    }
    /// Drive every provider's fallible preparation. Never exposes anything.
    fn prepare(&mut self) -> Poll<Result<(), LiveError>> {
        if Instant::now() >= self.request.deadline {
            return Poll::Ready(Err(
                self.failure(ActivationStage::Poll, ProviderFault::Deadline)
            ));
        }
        let mut failure = None;
        for entry in &mut self.devices {
            if entry.prepared {
                continue;
            }
            let mut device = match entry.device.try_lock() {
                Ok(device) => device,
                Err(TryLockError::WouldBlock) => continue,
                Err(TryLockError::Poisoned(_)) => {
                    let stage = if entry.begun {
                        ActivationStage::Poll
                    } else {
                        ActivationStage::Begin
                    };
                    failure = Some((stage, ProviderFault::DeviceLock));
                    break;
                }
            };
            let Some(provider) = device.state_provider_mut() else {
                failure = Some((ActivationStage::Begin, ProviderFault::Unsupported));
                break;
            };
            if !entry.begun {
                match provider.begin_activation_release(self.request, &self.exposure) {
                    Ok(()) => entry.begun = true,
                    Err(error) if !error.accepted && error.fault == ProviderFault::LockBusy => {
                        continue;
                    }
                    Err(error) => {
                        entry.begun = error.accepted;
                        failure = Some((ActivationStage::Begin, error.fault));
                        break;
                    }
                }
            }
            match provider.poll_activation_release(self.request.key) {
                Ok(Poll::Ready(())) => entry.prepared = true,
                Ok(Poll::Pending) => {}
                Err(fault) => {
                    failure = Some((ActivationStage::Poll, fault));
                    break;
                }
            }
        }
        if let Some((stage, fault)) = failure {
            Poll::Ready(Err(self.failure(stage, fault)))
        } else if self.devices.iter().all(|entry| entry.prepared) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    /// The only exposure point. Any failure seals the shared gate; success is
    /// one atomic open after every provider, authority and the absolute
    /// deadline are rechecked.
    fn settle(
        &mut self,
        stopping: bool,
        authority: impl FnOnce() -> Result<(), LiveError>,
    ) -> Poll<Result<(), LiveError>> {
        let result = if stopping {
            Err(self.failure(ActivationStage::Poll, ProviderFault::InvalidTransition))
        } else {
            match self.prepare() {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => Err(error),
                Poll::Ready(Ok(())) => match self.commit(authority) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                },
            }
        };
        if result.is_err() {
            self.exposure.seal();
        }
        Poll::Ready(result)
    }
    /// Re-prove every prepared provider under its device lock, then open. The
    /// guards are held until after the open so no provider transition can
    /// interleave; contention only retries, it never commits a stale proof.
    fn commit(
        &self,
        authority: impl FnOnce() -> Result<(), LiveError>,
    ) -> Poll<Result<(), LiveError>> {
        let mut guards = Vec::with_capacity(self.devices.len());
        for entry in &self.devices {
            match entry.device.try_lock() {
                Ok(guard) => guards.push(guard),
                Err(TryLockError::WouldBlock) => return Poll::Pending,
                Err(TryLockError::Poisoned(_)) => {
                    return Poll::Ready(Err(
                        self.failure(ActivationStage::Poll, ProviderFault::DeviceLock)
                    ));
                }
            }
        }
        for guard in &guards {
            let Some(provider) = guard.state_provider() else {
                return Poll::Ready(Err(
                    self.failure(ActivationStage::Poll, ProviderFault::Unsupported)
                ));
            };
            match provider.validate_activation_prepared(self.request.key) {
                Ok(Poll::Ready(())) => {}
                Ok(Poll::Pending) => return Poll::Pending,
                Err(fault) => return Poll::Ready(Err(self.failure(ActivationStage::Poll, fault))),
            }
        }
        let result = authority().and_then(|()| {
            if Instant::now() >= self.request.deadline {
                Err(self.failure(ActivationStage::Poll, ProviderFault::Deadline))
            } else if self.exposure.open() {
                Ok(())
            } else {
                Err(self.failure(ActivationStage::Poll, ProviderFault::InvalidTransition))
            }
        });
        drop(guards);
        Poll::Ready(result)
    }
}
#[derive(Default)]
pub(crate) struct LiveOwner {
    records: BTreeMap<CaptureId, CaptureRecord>,
    released: BTreeSet<CaptureId>,
    source_run: Option<[u8; 16]>,
    next_capture: u64,
    activation: Option<ActivationRelease>,
    pub(crate) activation_released: bool,
    pub(crate) activation_failed: bool,
    #[cfg(all(
        feature = "native-device-probe",
        feature = "blk",
        feature = "net",
        target_os = "linux",
        target_arch = "x86_64",
        not(any(feature = "tee", feature = "aws-nitro"))
    ))]
    pub(crate) irq_probe: Option<crate::vmm::control::irq_probe::ProbeOwner>,
}
impl LiveOwner {
    pub(crate) fn pending(&self) -> bool {
        #[cfg(all(
            feature = "native-device-probe",
            feature = "blk",
            feature = "net",
            target_os = "linux",
            target_arch = "x86_64",
            not(any(feature = "tee", feature = "aws-nitro"))
        ))]
        if self.irq_probe.as_ref().is_some_and(|probe| probe.pending()) {
            return true;
        }
        self.records.values().any(|record| record.pending.is_some()) || self.activation.is_some()
    }
    pub(crate) fn unresolved(&self) -> bool {
        #[cfg(all(
            feature = "native-device-probe",
            feature = "blk",
            feature = "net",
            target_os = "linux",
            target_arch = "x86_64",
            not(any(feature = "tee", feature = "aws-nitro"))
        ))]
        if self.irq_probe.as_ref().is_some_and(|probe| probe.pending()) {
            return true;
        }
        self.records.values().any(|record| !record.resolved())
    }
    fn validate_ticket(&self, run: &Arc<()>, ticket: &CaptureTicket) -> Result<(), LiveError> {
        if !Arc::ptr_eq(&ticket.run, run)
            || self
                .records
                .get(&ticket.id)
                .is_none_or(|record| record.ticket != *ticket)
        {
            return Err(ControlFailure::InvalidToken.into());
        }
        Ok(())
    }
    fn status(&self, id: CaptureId) -> Result<CaptureStatus, LiveError> {
        if self.released.contains(&id) {
            return Ok(CaptureStatus::Released);
        }
        Ok(self
            .records
            .get(&id)
            .ok_or(ControlFailure::InvalidToken)?
            .status
            .clone())
    }
    fn release(&mut self, id: CaptureId) -> Result<(), LiveError> {
        if self.released.contains(&id) {
            return Ok(());
        }
        let record = self.records.get(&id).ok_or(ControlFailure::InvalidToken)?;
        if !record.resolved() {
            return Err(ControlFailure::Busy.into());
        }
        self.records.remove(&id);
        self.released.insert(id);
        Ok(())
    }
}
fn answer(reply: &Reply, result: Result<LiveReply, LiveError>) {
    let _ = reply.try_send(Ok(ControlReply::Live(result)));
}
fn output_error(role: OutputRole, problem: OutputProblem) -> LiveError {
    LiveError::Output { role, problem }
}
fn io_error(role: OutputRole, source: std::io::Error) -> LiveError {
    LiveError::Io {
        role,
        source: Arc::new(source),
    }
}
fn require_cloexec(file: &File, role: OutputRole) -> Result<(), LiveError> {
    let flags = fcntl(file, FcntlArg::F_GETFD)
        .map_err(|error| io_error(role, std::io::Error::from_raw_os_error(error as i32)))?;
    if FdFlag::from_bits_retain(flags).contains(FdFlag::FD_CLOEXEC) {
        Ok(())
    } else {
        Err(output_error(role, OutputProblem::CloseOnExec))
    }
}
fn inspect(file: &File, role: OutputRole, empty: bool) -> Result<(u64, u64, u64), LiveError> {
    let metadata = file.metadata().map_err(|error| io_error(role, error))?;
    if !metadata.is_file() {
        return Err(output_error(role, OutputProblem::NotRegular));
    }
    require_cloexec(file, role)?;
    let flags = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL)
            .map_err(|error| io_error(role, std::io::Error::from_raw_os_error(error as i32)))?,
    );
    if flags.contains(OFlag::O_APPEND) {
        return Err(output_error(role, OutputProblem::Append));
    }
    #[cfg(target_os = "linux")]
    if flags.contains(OFlag::O_DIRECT) {
        return Err(output_error(role, OutputProblem::DirectIo));
    }
    #[cfg(target_os = "linux")]
    if flags.contains(OFlag::O_PATH) {
        return Err(output_error(role, OutputProblem::PathOnly));
    }
    if flags.intersection(OFlag::O_ACCMODE) != OFlag::O_RDWR
        && flags.intersection(OFlag::O_ACCMODE) != OFlag::O_WRONLY
    {
        return Err(output_error(role, OutputProblem::Access));
    }
    if matches!(role, OutputRole::Ram | OutputRole::Layout)
        && flags.intersection(OFlag::O_ACCMODE) != OFlag::O_RDWR
    {
        return Err(output_error(role, OutputProblem::Access));
    }
    if empty && metadata.len() != 0 {
        return Err(output_error(role, OutputProblem::NotEmpty));
    }
    Ok((metadata.dev(), metadata.ino(), metadata.len()))
}
#[cfg(any(
    test,
    all(
        not(feature = "tee"),
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            all(target_os = "macos", target_arch = "aarch64")
        )
    )
))]
fn write_object(
    file: &File,
    role: OutputRole,
    bytes: &[u8],
    binding: &StateBinding,
) -> Result<OutputReceipt, LiveError> {
    file.write_all_at(bytes, 0)
        .map_err(|error| io_error(role, error))?;
    file.sync_all().map_err(|error| io_error(role, error))?;
    let (device, inode, length) = inspect(file, role, false)?;
    if length != bytes.len() as u64 {
        return Err(output_error(role, OutputProblem::Changed));
    }
    Ok(OutputReceipt {
        role,
        device,
        inode,
        length,
        binding: binding.clone(),
    })
}
fn inspect_outputs(files: &[(OutputRole, &File); 2]) -> Result<[(u64, u64, u64); 2], LiveError> {
    let facts = [
        inspect(files[0].1, files[0].0, true)?,
        inspect(files[1].1, files[1].0, true)?,
    ];
    if facts[0].0 == facts[1].0 && facts[0].1 == facts[1].1 {
        return Err(output_error(files[1].0, OutputProblem::Alias));
    }
    Ok(facts)
}

impl ControlOwner {
    fn memory_cut_recovery_key(&self, pausing: OperationId) -> Result<BarrierKey, ControlFailure> {
        let key = match self.state {
            ControlState::Pausing { key, failed: true } if key.operation == pausing => key,
            _ => return Err(ControlFailure::InvalidOperation),
        };
        if !self.active.as_ref().is_some_and(|active| {
            active.original == key
                && active.request.operation == pausing
                && matches!(active.request.kind, RequestKind::Pause(_))
                && active.phase == Phase::Cut
                && active.failed
        }) {
            return Err(ControlFailure::InvalidOperation);
        }
        Ok(key)
    }
}

impl Vmm {
    fn live_pause_key(&self, pause: &PauseToken) -> Result<BarrierKey, LiveError> {
        if !self.control.validate_token(pause) {
            return Err(ControlFailure::InvalidToken.into());
        }
        self.control
            .active
            .as_ref()
            .map(|active| active.original)
            .ok_or_else(|| ControlFailure::InvalidToken.into())
    }
    fn live_ticket(&self, ticket: &CaptureTicket) -> Result<(), LiveError> {
        self.control.live.validate_ticket(&self.control.run, ticket)
    }
    fn preflight_live_outputs(&self, files: &[(OutputRole, &File); 2]) -> Result<(), LiveError> {
        let facts = inspect_outputs(files)?;
        let devices = self.mmio_device_manager.quiescence.live_devices();
        for ((role, _), fact) in files.iter().zip(facts) {
            if self
                .memory
                .protects_output(fact.0, fact.1)
                .map_err(|error| io_error(*role, error))?
            {
                return Err(output_error(*role, OutputProblem::Alias));
            }
            for record in self.control.live.records.values() {
                if let Some(execution) = &record.execution {
                    for previous in [&execution.execution, &execution.devices] {
                        if previous.device == fact.0 && previous.inode == fact.1 {
                            return Err(output_error(*role, OutputProblem::Alias));
                        }
                    }
                }
                if let Some(candidate) = &record.candidate
                    && candidate
                        .receipt()
                        .output_identities()
                        .iter()
                        .any(|previous| previous.0 == fact.0 && previous.1 == fact.1)
                {
                    return Err(output_error(*role, OutputProblem::Alias));
                }
            }
            for (_, device) in &devices {
                let device = device.try_lock().map_err(|_| ControlFailure::Busy)?;
                let identities = device
                    .state_provider()
                    .ok_or_else(|| LiveError::Execution("provider absent".into()))?
                    .backing_file_identities()
                    .map_err(|error| {
                        LiveError::Execution(format!("backing identity: {error:?}"))
                    })?;
                if identities.contains(&(fact.0, fact.1)) {
                    return Err(output_error(*role, OutputProblem::Alias));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn accept_live(
        &mut self,
        request: LiveRequest,
        id: RequestId,
        operation: OperationId,
        deadline: Instant,
        reply: Reply,
    ) {
        let result = self.dispatch_live(request, id, operation, deadline, &reply);
        match result {
            Ok(Some(result)) => answer(&reply, Ok(result)),
            Ok(None) => {}
            Err(error) => answer(&reply, Err(error)),
        }
    }
    fn dispatch_live(
        &mut self,
        request: LiveRequest,
        id: RequestId,
        operation: OperationId,
        deadline: Instant,
        reply: &Reply,
    ) -> Result<Option<LiveReply>, LiveError> {
        if Instant::now() >= deadline {
            return Err(ControlFailure::Deadline.into());
        }
        #[cfg(all(
            feature = "native-device-probe",
            feature = "blk",
            feature = "net",
            target_os = "linux",
            target_arch = "x86_64",
            not(any(feature = "tee", feature = "aws-nitro"))
        ))]
        {
            if let LiveRequest::IrqProbe(request) = request {
                return self.dispatch_irq_probe(request, operation, deadline, reply);
            }
            if self
                .control
                .live
                .irq_probe
                .as_ref()
                .is_some_and(|probe| probe.pending())
            {
                return Err(ControlFailure::Busy.into());
            }
        }
        if !matches!(
            request,
            LiveRequest::Status(_)
                | LiveRequest::Generation(_)
                | LiveRequest::Layout
                | LiveRequest::Snapshot
                | LiveRequest::Baseline
        ) {
            self.control.reserve(operation)?;
        }
        let result = match request {
            #[cfg(all(
                feature = "native-device-probe",
                feature = "blk",
                feature = "net",
                target_os = "linux",
                target_arch = "x86_64",
                not(any(feature = "tee", feature = "aws-nitro"))
            ))]
            LiveRequest::IrqProbe(_) => return Err(ControlFailure::InvalidOperation.into()),
            LiveRequest::Status(id) => LiveReply::Status(self.control.live.status(id)?),
            LiveRequest::Baseline => LiveReply::CurrentBaseline(self.memory.baseline_token()),
            LiveRequest::Layout => LiveReply::Layout(self.memory_layout().map_err(|error| {
                LiveError::from(crate::vmm::memory::CaptureError::Image(error))
            })?),
            LiveRequest::Snapshot => {
                let mut file_backings = Vec::new();
                for fact in self.memory_domain.file_backing_identities() {
                    let fact = fact.map_err(|error| io_error(OutputRole::Ram, error))?;
                    file_backings.push((fact.device, fact.inode));
                }
                let mut providers = Vec::new();
                for (attachment, device) in self.mmio_device_manager.quiescence.live_devices() {
                    let device = device.try_lock().map_err(|_| ControlFailure::Busy)?;
                    let activation_fenced = device
                        .state_provider()
                        .ok_or(ControlFailure::FailedFenced)?
                        .activation_fenced()
                        .map_err(|error| {
                            LiveError::Execution(format!("activation observation: {error:?}"))
                        })?;
                    providers.push(crate::api::live::LiveProviderSnapshot {
                        attachment,
                        activation_fenced,
                    });
                }
                LiveReply::Snapshot(LiveSnapshot {
                    state: self.control.state.clone(),
                    backing: self.memory_domain.backing_kind(),
                    file_backings,
                    tracking: self.memory_domain.tracking_mode(),
                    coverage_valid: self.memory_domain.coverage_valid(),
                    pending_dirty_pages: self.memory.pending_dirty_count(),
                    native_commands_reconciled: self.control.cpus.reconciled(),
                    activation_released: self.control.live.activation_released,
                    activation_failed: self.control.live.activation_failed,
                    restore_installation: self.memory.restore_installation(),
                    providers,
                    time_preparation: self.execution.preparation_observation().cloned(),
                })
            }
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            LiveRequest::Profile(profile) => {
                if self.control.state != ControlState::Running || self.control.live.unresolved() {
                    return Err(ControlFailure::Busy.into());
                }
                if matches!(
                    profile,
                    crate::vmm::linux::execution::KvmCaptureProfile::ResetPit
                ) {
                    return Err(ControlFailure::Unsupported(
                        "diagnostic PIT profile is not a live API profile".into(),
                    )
                    .into());
                }
                self.execution.profile = Some(profile);
                LiveReply::Complete
            }
            LiveRequest::Generation(ticket) => {
                if !Arc::ptr_eq(&ticket.run, &self.control.run) {
                    return Err(ControlFailure::InvalidToken.into());
                }
                LiveReply::Generation(ticket.observe(Instant::now()))
            }
            LiveRequest::RecoverMemoryCut { pausing } => {
                let key = self.control.memory_cut_recovery_key(pausing)?;
                #[cfg(not(feature = "tee"))]
                {
                    self.recover_memory_cut(key)?;
                    match &self.control.state {
                        ControlState::Paused(token) => LiveReply::Pause(token.clone()),
                        _ => return Err(ControlFailure::FailedFenced.into()),
                    }
                }
                #[cfg(feature = "tee")]
                {
                    let _ = key;
                    return Err(ControlFailure::Unsupported(
                        "tracked memory is unsupported for confidential VMs".into(),
                    )
                    .into());
                }
            }
            LiveRequest::Flush(pause) => {
                let key = self.live_pause_key(&pause)?;
                self.flush_live_native(key)?;
                LiveReply::Flush(FlushReceipt {
                    pause,
                    attachments: self.mmio_device_manager.quiescence.attachment_identities(),
                })
            }
            LiveRequest::Execution {
                pause,
                binding,
                outputs,
            } => {
                let binding = *binding;
                let key = self.live_pause_key(&pause)?;
                binding
                    .validate()
                    .map_err(|error| LiveError::Execution(error.to_string()))?;
                let capture = CaptureId::new(binding.capture);
                if self.control.live.unresolved() || self.memory.has_attempt() {
                    return Err(ControlFailure::Busy.into());
                }
                if self.control.live.records.contains_key(&capture)
                    || self.control.live.released.contains(&capture)
                    || self
                        .control
                        .live
                        .source_run
                        .is_some_and(|run| run != binding.source_run)
                {
                    return Err(ControlFailure::InvalidToken.into());
                }
                self.preflight_live_outputs(&[
                    (OutputRole::Execution, &outputs.execution),
                    (OutputRole::Devices, &outputs.devices),
                ])?;
                let sequence = self
                    .control
                    .live
                    .next_capture
                    .checked_add(1)
                    .ok_or(ControlFailure::Exhausted)?;
                let ticket = CaptureTicket {
                    run: self.control.run.clone(),
                    sequence,
                    id: capture,
                    pause,
                };
                self.control.live.next_capture = sequence;
                self.control.live.source_run = Some(binding.source_run);
                let mut record = CaptureRecord {
                    ticket: ticket.clone(),
                    operation,
                    status: CaptureStatus::ExecutionPending(ticket),
                    execution: None,
                    pending: Some(PendingExecution {
                        outputs,
                        reply: reply.clone(),
                    }),
                    execution_failure: None,
                    attempt: None,
                    candidate: None,
                    accepted_stream: None,
                    terminal: false,
                };
                let barrier = BarrierRequest { key, deadline };
                if let Err(error) = self.start_live_execution(id, barrier, binding) {
                    record.execution_failure = Some(error.with_context(
                        operation,
                        LiveStage::Execution,
                        LiveSubject::Capture(capture),
                    ));
                }
                self.control.live.records.insert(capture, record);
                return Ok(None);
            }
            LiveRequest::Memory {
                ticket,
                request,
                outputs,
            } => {
                self.live_ticket(&ticket)?;
                self.live_pause_key(&ticket.pause)?;
                if !matches!(
                    self.control
                        .live
                        .records
                        .get(&ticket.id)
                        .map(|record| &record.status),
                    Some(CaptureStatus::ExecutionComplete(_))
                ) {
                    return Err(ControlFailure::Busy.into());
                }
                let crossover = if request.full_at_dirty_percent == 0 {
                    None
                } else {
                    Some(DirtyCrossoverPercent::new(request.full_at_dirty_percent)?)
                };
                self.preflight_live_outputs(&[
                    (OutputRole::Ram, &outputs.ram),
                    (OutputRole::Layout, &outputs.layout),
                ])?;
                let request = match crossover {
                    None => RamCaptureRequest::Full,
                    Some(crossover) => RamCaptureRequest::Incremental {
                        baseline: request.baseline.as_ref(),
                        crossover,
                    },
                };
                let attempt = self.begin_memory_capture(&ticket.pause, request)?;
                if let Some(record) = self.control.live.records.get_mut(&ticket.id) {
                    record.attempt = Some(attempt.clone());
                    record.status = CaptureStatus::MemoryPending(ticket.clone());
                }
                match self.write_memory_capture(
                    &ticket.pause,
                    &attempt,
                    RamOutputFiles::new(outputs.ram, outputs.layout),
                    deadline,
                ) {
                    Ok(candidate) => {
                        let completed = CompletedCapture {
                            ticket: ticket.clone(),
                            ram: candidate.shared_receipt(),
                            full_reason: candidate.full_reason(),
                            memory_generation: candidate.memory_generation(),
                        };
                        let record = self
                            .control
                            .live
                            .records
                            .get_mut(&ticket.id)
                            .ok_or(ControlFailure::InvalidToken)?;
                        record.status = CaptureStatus::CandidateComplete(completed.clone());
                        record.candidate = Some(candidate);
                        LiveReply::Memory(completed)
                    }
                    Err(error) => {
                        let error = LiveError::from(error).with_context(
                            operation,
                            LiveStage::Memory,
                            LiveSubject::Capture(ticket.id()),
                        );
                        if let Some(record) = self.control.live.records.get_mut(&ticket.id) {
                            record.status = CaptureStatus::Failed {
                                ticket,
                                stage: CaptureStage::Memory,
                                cause: error.clone(),
                            };
                        }
                        return Err(error);
                    }
                }
            }
            LiveRequest::Accept { ticket, sealed } => {
                let sealed = *sealed;
                self.live_ticket(&ticket)?;
                self.live_pause_key(&ticket.pause)?;
                require_cloexec(&sealed.ram, OutputRole::Ram)?;
                require_cloexec(&sealed.layout, OutputRole::Layout)?;
                let record = self
                    .control
                    .live
                    .records
                    .get(&ticket.id)
                    .ok_or(ControlFailure::InvalidToken)?;
                if let CaptureStatus::Accepted { baseline, .. } = &record.status {
                    // Idempotency still authenticates the exact completion and supplied descriptors.
                    let candidate = record
                        .candidate
                        .as_ref()
                        .ok_or(ControlFailure::InvalidToken)?;
                    if record.accepted_stream != Some(sealed.authentication.stream) {
                        return Err(ControlFailure::InvalidToken.into());
                    }
                    candidate
                        .seal(sealed.ram, sealed.layout, sealed.authentication)
                        .map_err(|error| {
                            LiveError::from(crate::vmm::memory::CaptureError::Image(error))
                        })?;
                    return Ok(Some(LiveReply::Baseline(baseline.clone())));
                }
                let candidate = record
                    .candidate
                    .as_ref()
                    .ok_or(ControlFailure::Busy)?
                    .clone();
                let stream = sealed.authentication.stream;
                let image = candidate
                    .seal(sealed.ram, sealed.layout, sealed.authentication)
                    .map_err(|error| {
                        LiveError::from(crate::vmm::memory::CaptureError::Image(error))
                    })?;
                let baseline = self.accept_memory(&ticket.pause, candidate, image)?;
                let record = self
                    .control
                    .live
                    .records
                    .get_mut(&ticket.id)
                    .ok_or(ControlFailure::InvalidToken)?;
                record.status = CaptureStatus::Accepted {
                    ticket,
                    baseline: baseline.clone(),
                };
                record.accepted_stream = Some(stream);
                self.execution.retire_serialization();
                LiveReply::Baseline(baseline)
            }
            LiveRequest::Abandon(ticket) => {
                self.live_ticket(&ticket)?;
                self.live_pause_key(&ticket.pause)?;
                let record = self
                    .control
                    .live
                    .records
                    .get(&ticket.id)
                    .ok_or(ControlFailure::InvalidToken)?;
                if matches!(record.status, CaptureStatus::Abandoned(_)) {
                    return Ok(Some(LiveReply::Complete));
                }
                if record.resolved() || !record.terminal || record.pending.is_some() {
                    return Err(ControlFailure::Busy.into());
                }
                if let Some(attempt) = record.attempt.clone() {
                    self.abandon_memory(&ticket.pause, &attempt)?;
                }
                let record = self
                    .control
                    .live
                    .records
                    .get_mut(&ticket.id)
                    .ok_or(ControlFailure::InvalidToken)?;
                record.candidate = None;
                record.attempt = None;
                record.status = CaptureStatus::Abandoned(ticket);
                self.execution.retire_serialization();
                LiveReply::Complete
            }
            LiveRequest::Release(id) => {
                self.control.live.release(id)?;
                LiveReply::Complete
            }
            LiveRequest::Preserve(pause) => {
                let key = self.live_pause_key(&pause)?;
                if self.control.live.unresolved() || self.memory.has_attempt() {
                    return Err(ControlFailure::Busy.into());
                }
                let token = self.control.token(key, PauseOwner::User);
                self.memory
                    .bind_pause(key, &token)
                    .map_err(ControlFailure::Memory)?;
                self.control.state = ControlState::Paused(token.clone());
                if let Some(active) = self.control.active.as_mut() {
                    active.owner = PauseOwner::User;
                }
                LiveReply::Pause(token)
            }
            LiveRequest::Activation {
                restore,
                generation,
            } => {
                self.activation_authority(&restore, &generation)?;
                if self.control.live.activation_failed {
                    return Err(ControlFailure::FailedFenced.into());
                }
                if self.control.live.activation_released {
                    return Ok(Some(LiveReply::Complete));
                }
                if self.control.state != ControlState::Running
                    || self.control.live.activation.is_some()
                {
                    return Err(ControlFailure::Busy.into());
                }
                let devices = self
                    .mmio_device_manager
                    .quiescence
                    .live_devices()
                    .into_iter()
                    .filter(|(identity, _)| {
                        matches!(identity.device_type, devices::DeviceType::Virtio(1 | 19))
                    })
                    .map(|(_, device)| device)
                    .collect();
                let request = BarrierRequest {
                    key: BarrierKey {
                        operation,
                        generation: restore.key.generation,
                    },
                    deadline,
                };
                self.control.live.activation = Some(ActivationRelease {
                    restore,
                    generation,
                    barrier: ActivationBarrier::new(request, devices),
                    reply: reply.clone(),
                });
                return Ok(None);
            }
        };
        Ok(Some(result))
    }
    pub(crate) fn poll_live(&mut self) {
        #[cfg(all(
            feature = "native-device-probe",
            feature = "blk",
            feature = "net",
            target_os = "linux",
            target_arch = "x86_64",
            not(any(feature = "tee", feature = "aws-nitro"))
        ))]
        self.poll_irq_probe();
        let pending = self
            .control
            .live
            .records
            .iter()
            .find_map(|(id, record)| record.pending.as_ref().map(|_| *id));
        if let Some(id) = pending {
            let Some(mut record) = self.control.live.records.remove(&id) else {
                return;
            };
            let stopping = matches!(
                self.control.state,
                ControlState::Stopping | ControlState::Stopped
            );
            let progress = if stopping || record.execution_failure.is_some() {
                let _ = self.control.cpus.poll(&mut self.vcpus_handles);
                if self.control.cpus.reconciled()
                    || (stopping && self.vcpus_handles.iter().all(|handle| handle.is_finished()))
                {
                    Poll::Ready(Err(record
                        .execution_failure
                        .clone()
                        .unwrap_or_else(|| ControlFailure::FailedFenced.into())))
                } else {
                    Poll::Pending
                }
            } else {
                self.poll_live_execution()
            };
            match progress {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    if let Err(error) = result {
                        let error = error.with_context(
                            record.operation,
                            LiveStage::Execution,
                            LiveSubject::Capture(record.ticket.id()),
                        );
                        record.execution_failure.get_or_insert(error);
                    }
                    if (self.control.cpus.reconciled()
                        || (stopping
                            && self.vcpus_handles.iter().all(|handle| handle.is_finished())))
                        && let Some(pending) = record.pending.take()
                    {
                        let result = if let Some(cause) = &record.execution_failure {
                            Err(cause.clone())
                        } else {
                            self.finish_live_execution(&record, &pending.outputs)
                        };
                        // Closure of both descriptors precedes every terminal reply/status.
                        drop(pending.outputs);
                        record.terminal = true;
                        match result {
                            Ok(receipt) => {
                                let receipt = Arc::new(receipt);
                                record.execution = Some(receipt.clone());
                                record.status = CaptureStatus::ExecutionComplete(receipt.clone());
                                answer(&pending.reply, Ok(LiveReply::Execution(receipt)));
                            }
                            Err(error) => {
                                let error = error.with_context(
                                    record.operation,
                                    LiveStage::Execution,
                                    LiveSubject::Capture(record.ticket.id()),
                                );
                                record.status = CaptureStatus::Failed {
                                    ticket: record.ticket.clone(),
                                    stage: CaptureStage::Execution,
                                    cause: error.clone(),
                                };
                                answer(&pending.reply, Err(error));
                            }
                        }
                    }
                }
            }
            self.control.live.records.insert(id, record);
        }
        self.poll_live_activation();
    }
    /// Exact restore token plus acknowledged FreshIdentity ticket for its cut.
    fn activation_authority(
        &self,
        restore: &RestoreToken,
        generation: &GenerationTicket,
    ) -> Result<(), LiveError> {
        self.control.validate_restore_token(restore)?;
        self.validate_generation_ticket(generation)?;
        if generation.stopped != restore.key
            || generation.attempt.request().flags != 1
            || !matches!(
                generation.observe(Instant::now()),
                GenerationObservation::Acknowledged(_)
            )
        {
            return Err(ControlFailure::InvalidToken.into());
        }
        Ok(())
    }
    fn poll_live_activation(&mut self) {
        let Some(mut release) = self.control.live.activation.take() else {
            return;
        };
        // Stop is serialized on this owner thread: a latched stop always wins
        // over a commit that has not happened yet.
        let stopping = matches!(
            self.control.state,
            ControlState::Stopping | ControlState::Stopped | ControlState::FailedFenced
        );
        let restore = &release.restore;
        let generation = &release.generation;
        let result = match release
            .barrier
            .settle(stopping, || self.activation_authority(restore, generation))
        {
            Poll::Pending => {
                self.control.live.activation = Some(release);
                return;
            }
            Poll::Ready(result) => result,
        };
        match result {
            Ok(()) => self.control.live.activation_released = true,
            // The gate is sealed: every provider stays effectively fenced and
            // retains its accepted release state until the normal terminal stop.
            Err(_) => self.control.live.activation_failed = true,
        }
        answer(&release.reply, result.map(|()| LiveReply::Complete));
    }
}

#[cfg(all(
    not(feature = "tee"),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
impl Vmm {
    fn start_live_execution(
        &mut self,
        id: RequestId,
        barrier: BarrierRequest,
        binding: StateBinding,
    ) -> Result<(), LiveError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let profile = self
            .execution
            .profile
            .clone()
            .ok_or_else(|| LiveError::Execution("capture profile absent".into()))?;
        self.begin_execution_capture(
            id,
            barrier,
            binding,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            &profile,
            false,
        )
        .map_err(LiveError::Execution)
    }
    fn poll_live_execution(&mut self) -> Poll<Result<(), LiveError>> {
        self.poll_execution_capture()
            .map(|result| result.map(|_| ()).map_err(LiveError::Execution))
    }
    fn finish_live_execution(
        &self,
        record: &CaptureRecord,
        outputs: &ExecutionOutputs,
    ) -> Result<ExecutionCaptureReceipt, LiveError> {
        let execution = self
            .execution
            .captured_envelope()
            .ok_or_else(|| LiveError::Execution("execution envelope absent".into()))?;
        let devices = self.captured_devices().map_err(LiveError::Execution)?;
        let binding = &execution.binding;
        if binding.capture != record.ticket.id.bytes() || devices.binding != *binding {
            return Err(ControlFailure::InvalidToken.into());
        }
        let execution_bytes = execution
            .encode()
            .map_err(|error| LiveError::Execution(error.to_string()))?;
        let device_bytes = devices
            .encode()
            .map_err(|error| LiveError::Execution(error.to_string()))?;
        let execution = write_object(
            &outputs.execution,
            OutputRole::Execution,
            &execution_bytes,
            binding,
        )?;
        let devices = write_object(
            &outputs.devices,
            OutputRole::Devices,
            &device_bytes,
            binding,
        )?;
        Ok(ExecutionCaptureReceipt {
            ticket: record.ticket.clone(),
            execution,
            devices,
        })
    }
    fn flush_live_native(&self, key: BarrierKey) -> Result<(), LiveError> {
        self.flush_devices_for_capture(key)
            .map_err(LiveError::Execution)
    }
}
#[cfg(not(all(
    not(feature = "tee"),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
)))]
impl Vmm {
    fn start_live_execution(
        &mut self,
        _: RequestId,
        _: BarrierRequest,
        _: StateBinding,
    ) -> Result<(), LiveError> {
        Err(ControlFailure::Unsupported("execution capture lane".into()).into())
    }
    fn poll_live_execution(&mut self) -> Poll<Result<(), LiveError>> {
        Poll::Ready(Err(ControlFailure::Unsupported(
            "execution capture lane".into(),
        )
        .into()))
    }
    fn finish_live_execution(
        &self,
        _: &CaptureRecord,
        _: &ExecutionOutputs,
    ) -> Result<ExecutionCaptureReceipt, LiveError> {
        Err(ControlFailure::Unsupported("execution capture lane".into()).into())
    }
    fn flush_live_native(&self, _: BarrierKey) -> Result<(), LiveError> {
        Err(ControlFailure::Unsupported("execution capture lane".into()).into())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use crate::api::live::ExecutionOutputs;
    use crate::api::live::{
        CaptureId, CaptureStatus, CaptureTicket, LiveError, OutputProblem, OutputRole,
    };
    #[cfg(target_os = "linux")]
    use crate::vmm::control::ControlClient;
    #[cfg(target_os = "linux")]
    use crate::vmm::control::live::LiveRequest;
    use crate::vmm::control::live::{
        CaptureRecord, LiveOwner, inspect, inspect_outputs, write_object,
    };
    use crate::vmm::control::{
        ActiveControl, BarrierGeneration, BarrierKey, BarrierRequest, ControlFailure, ControlOwner,
        ControlRequest, ControlState, GenerationAuthority, OperationId, PauseOwner, Phase,
        RequestId, RequestKind,
    };
    use crate::vmm::execution::StateBinding;
    use std::fs::{self, File, OpenOptions};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use utils::tempfile::TempFile;

    fn key() -> BarrierKey {
        BarrierKey {
            operation: OperationId(1),
            generation: BarrierGeneration(1),
        }
    }
    fn failed_memory_cut_owner() -> ControlOwner {
        let mut owner = ControlOwner::new(BarrierGeneration(0)).unwrap();
        owner.reserve(key().operation).unwrap();
        let barrier = BarrierRequest {
            key: key(),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let (reply, _waiting) = crossbeam_channel::bounded(1);
        owner.active = Some(ActiveControl {
            request: ControlRequest {
                id: RequestId(1),
                operation: key().operation,
                deadline: barrier.deadline,
                kind: RequestKind::Pause(PauseOwner::Capture),
                reply,
            },
            barrier,
            original: key(),
            owner: PauseOwner::Capture,
            phase: Phase::Cut,
            failed: true,
            devices_begun: true,
            routes_begun: true,
            maintenance_closed: true,
            cpu_parked_at: Some(0),
        });
        owner.state = ControlState::Pausing {
            key: key(),
            failed: true,
        };
        owner
    }

    #[test]
    fn memory_cut_recovery_authenticates_exact_failed_pause_operation() {
        let mut owner = failed_memory_cut_owner();
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(2)),
            Err(ControlFailure::InvalidOperation)
        );
        assert_eq!(owner.memory_cut_recovery_key(OperationId(1)), Ok(key()));
        assert_eq!(
            owner.reserve(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
        owner.reserve(OperationId(2)).unwrap();
        assert_eq!(owner.memory_cut_recovery_key(OperationId(1)), Ok(key()));

        for phase in [
            Phase::Admission,
            Phase::MemoryDrain,
            Phase::RecoverCut,
            Phase::Stop,
        ] {
            owner.active.as_mut().unwrap().phase = phase;
            assert_eq!(
                owner.memory_cut_recovery_key(OperationId(1)),
                Err(ControlFailure::InvalidOperation)
            );
        }
        owner.active.as_mut().unwrap().phase = Phase::Cut;
        owner.active.as_mut().unwrap().original.generation = BarrierGeneration(2);
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
        owner.active.as_mut().unwrap().original = key();
        owner.active.as_mut().unwrap().request.operation = OperationId(2);
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
        owner.active.as_mut().unwrap().request.operation = OperationId(1);
        owner.active.as_mut().unwrap().request.kind = RequestKind::CancelPause(OperationId(1));
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
    }

    #[test]
    fn memory_cut_recovery_refuses_nonfailed_and_consumed_pause_authority() {
        let mut owner = failed_memory_cut_owner();
        owner.active.as_mut().unwrap().failed = false;
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
        owner.active.as_mut().unwrap().failed = true;
        owner.state = ControlState::Pausing {
            key: key(),
            failed: false,
        };
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
        owner.state = ControlState::Paused(owner.token(key(), PauseOwner::Capture));
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
        owner.state = ControlState::Pausing {
            key: key(),
            failed: true,
        };
        owner.active = None;
        assert_eq!(
            owner.memory_cut_recovery_key(OperationId(1)),
            Err(ControlFailure::InvalidOperation)
        );
    }

    fn binding() -> StateBinding {
        StateBinding {
            native_producer: "live-owner-unit".into(),
            silo_producer: [1; 32],
            profile: [2; 32],
            topology: [3; 32],
            ram_layout: [4; 32],
            source_run: [5; 16],
            pause_generation: 1,
            capture: [6; 16],
        }
    }
    #[test]
    fn output_roles_reject_alias_access_append_nonempty_and_missing_cloexec() {
        let first = TempFile::new().unwrap();
        let second = TempFile::new().unwrap();
        for file in [first.as_file(), second.as_file()] {
            nix::fcntl::fcntl(
                file,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )
            .unwrap();
        }
        let writable = OpenOptions::new()
            .write(true)
            .open(first.as_path())
            .unwrap();
        assert!(matches!(
            inspect(&writable, OutputRole::Ram, true),
            Err(LiveError::Output {
                problem: OutputProblem::Access,
                ..
            })
        ));
        let readonly = File::open(first.as_path()).unwrap();
        assert!(matches!(
            inspect(&readonly, OutputRole::Execution, true),
            Err(LiveError::Output {
                problem: OutputProblem::Access,
                ..
            })
        ));
        let append = OpenOptions::new()
            .append(true)
            .open(first.as_path())
            .unwrap();
        assert!(matches!(
            inspect(&append, OutputRole::Execution, true),
            Err(LiveError::Output {
                problem: OutputProblem::Append,
                ..
            })
        ));
        let same_inode = OpenOptions::new()
            .read(true)
            .write(true)
            .open(first.as_path())
            .unwrap();
        assert!(matches!(
            inspect_outputs(&[
                (OutputRole::Execution, first.as_file()),
                (OutputRole::Devices, &same_inode)
            ]),
            Err(LiveError::Output {
                problem: OutputProblem::Alias,
                ..
            })
        ));
        assert!(
            inspect_outputs(&[
                (OutputRole::Execution, first.as_file()),
                (OutputRole::Devices, second.as_file())
            ])
            .is_ok()
        );
        let receipt = write_object(
            first.as_file(),
            OutputRole::Execution,
            b"portable-state",
            &binding(),
        )
        .unwrap();
        assert_eq!(receipt.length, 14);
        assert_eq!(receipt.binding, binding());
        assert_eq!(fs::read(first.as_path()).unwrap(), b"portable-state");
        assert!(matches!(
            inspect(first.as_file(), OutputRole::Execution, true),
            Err(LiveError::Output {
                problem: OutputProblem::NotEmpty,
                ..
            })
        ));
        nix::fcntl::fcntl(
            second.as_file(),
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .unwrap();
        assert!(matches!(
            inspect(second.as_file(), OutputRole::Devices, true),
            Err(LiveError::Output {
                problem: OutputProblem::CloseOnExec,
                ..
            })
        ));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn caller_timeout_retains_moved_output_files_in_real_control_queue() {
        let first = TempFile::new().unwrap();
        let second = TempFile::new().unwrap();
        let execution = OpenOptions::new()
            .read(true)
            .write(true)
            .open(first.as_path())
            .unwrap();
        let devices = OpenOptions::new()
            .read(true)
            .write(true)
            .open(second.as_path())
            .unwrap();
        let execution_fd = execution.as_raw_fd();
        let devices_fd = devices.as_raw_fd();
        let execution_link = fs::read_link(format!("/proc/self/fd/{execution_fd}")).unwrap();
        let devices_link = fs::read_link(format!("/proc/self/fd/{devices_fd}")).unwrap();
        let authority = ControlOwner::new(BarrierGeneration(0)).unwrap();
        let pause = authority.token(key(), PauseOwner::Capture);
        let (client, receiver) = ControlClient::channel().unwrap();
        let caller = std::thread::spawn(move || {
            client.call(
                OperationId(2),
                Instant::now() + Duration::from_millis(30),
                RequestKind::Live(LiveRequest::Execution {
                    pause,
                    binding: Box::new(binding()),
                    outputs: ExecutionOutputs { execution, devices },
                }),
            )
        });
        assert!(matches!(
            caller.join().unwrap(),
            Err(ControlFailure::CallerTimeout)
        ));
        assert_eq!(
            fs::read_link(format!("/proc/self/fd/{execution_fd}")).unwrap(),
            execution_link
        );
        assert_eq!(
            fs::read_link(format!("/proc/self/fd/{devices_fd}")).unwrap(),
            devices_link
        );
        let request = receiver.try_recv().unwrap().unwrap();
        assert_eq!(request.operation, OperationId(2));
        assert!(matches!(
            &request.kind,
            RequestKind::Live(LiveRequest::Execution { .. })
        ));
        drop(request);
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{execution_fd}")).ok(),
            Some(execution_link)
        );
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{devices_fd}")).ok(),
            Some(devices_link)
        );
        assert_eq!(first.as_file().metadata().unwrap().len(), 0);
        assert_eq!(second.as_file().metadata().unwrap().len(), 0);
    }
    #[test]
    fn exact_ticket_status_abandon_and_release_keep_run_local_authority() {
        let owner = ControlOwner::new(BarrierGeneration(0)).unwrap();
        let pause = owner.token(key(), PauseOwner::Capture);
        let ticket = CaptureTicket {
            run: owner.run.clone(),
            sequence: 1,
            id: CaptureId::new(binding().capture),
            pause,
        };
        let mut live = LiveOwner::default();
        live.records.insert(
            ticket.id(),
            CaptureRecord {
                ticket: ticket.clone(),
                operation: OperationId(1),
                status: CaptureStatus::ExecutionPending(ticket.clone()),
                execution: None,
                pending: None,
                execution_failure: None,
                attempt: None,
                candidate: None,
                accepted_stream: None,
                terminal: true,
            },
        );
        assert!(live.validate_ticket(&owner.run, &ticket).is_ok());
        assert!(
            matches!(live.status(ticket.id()).unwrap(), CaptureStatus::ExecutionPending(current) if current == ticket)
        );
        assert!(matches!(
            live.release(ticket.id()),
            Err(LiveError::Control(ControlFailure::Busy))
        ));
        let mut foreign = ticket.clone();
        foreign.run = Arc::new(());
        assert!(matches!(
            live.validate_ticket(&owner.run, &foreign),
            Err(LiveError::Control(ControlFailure::InvalidToken))
        ));
        let mut stale = ticket.clone();
        stale.sequence += 1;
        assert!(live.validate_ticket(&owner.run, &stale).is_err());
        live.records.get_mut(&ticket.id()).unwrap().status =
            CaptureStatus::Abandoned(ticket.clone());
        assert!(!live.unresolved());
        live.release(ticket.id()).unwrap();
        live.release(ticket.id()).unwrap();
        assert!(matches!(
            live.status(ticket.id()).unwrap(),
            CaptureStatus::Released
        ));
        assert!(matches!(
            live.status(CaptureId::new([99; 16])),
            Err(LiveError::Control(ControlFailure::InvalidToken))
        ));
    }
    #[test]
    fn capture_pause_transfer_invalidates_only_capture_owner_token() {
        let mut owner = ControlOwner::new(BarrierGeneration(0)).unwrap();
        let capture = owner.token(key(), PauseOwner::Capture);
        owner.state = ControlState::Paused(capture.clone());
        assert!(owner.validate_token(&capture));
        let user = owner.token(key(), PauseOwner::User);
        owner.state = ControlState::Paused(user.clone());
        assert!(!owner.validate_token(&capture));
        assert!(owner.validate_token(&user));
        assert_eq!(user.generation(), capture.generation());
        assert_eq!(user.owner(), PauseOwner::User);
        assert_eq!(owner.token(key(), PauseOwner::User), user);
    }

    #[test]
    fn restore_token_is_issued_only_for_exact_prepared_owner_and_survives_release() {
        let mut owner = ControlOwner::new(BarrierGeneration(0)).unwrap();
        assert!(matches!(
            owner.restore_token(),
            Err(ControlFailure::InvalidToken)
        ));
        owner.state = ControlState::RestorePrepared { key: key() };
        let token = owner.restore_token().unwrap();
        assert!(owner.validate_restore_token(&token).is_ok());
        let mut foreign = ControlOwner::new(BarrierGeneration(0)).unwrap();
        foreign.state = ControlState::RestorePrepared { key: key() };
        assert_eq!(
            foreign.validate_restore_token(&token),
            Err(ControlFailure::InvalidToken)
        );
        assert_eq!(
            owner.generation_authority(&GenerationAuthority::RestoreToken(token.clone()), false),
            Ok(key())
        );
        owner.state = ControlState::Running;
        assert!(owner.validate_restore_token(&token).is_ok());
        assert_eq!(
            owner.generation_authority(&GenerationAuthority::RestoreToken(token), false),
            Err(ControlFailure::InvalidToken)
        );
    }

    #[cfg(feature = "net")]
    type SharedNet = Arc<std::sync::Mutex<devices::virtio::Net>>;

    #[cfg(feature = "net")]
    fn activation_request(
        operation: u64,
        deadline: std::time::Instant,
    ) -> crate::vmm::control::BarrierRequest {
        crate::vmm::control::BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(9),
            },
            deadline,
        }
    }

    /// A real restored, resumed, still-fenced network provider and its peer.
    #[cfg(feature = "net")]
    fn restored_net(name: &str) -> (SharedNet, std::os::unix::net::UnixDatagram) {
        use devices::legacy::DummyIrqChip;
        use devices::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
        };
        use devices::virtio::{InterruptTransport, Net};
        use std::os::unix::net::UnixDatagram;
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let cut = activation_request(31, deadline);
        let (source_socket, _source_peer) = UnixDatagram::pair().unwrap();
        let mut source =
            Net::new_managed(name.into(), source_socket.into(), [2, 0, 0, 0, 0, 1], 0).unwrap();
        source.begin_quiesce(cut).unwrap();
        assert!(source.poll_quiesce(cut.key).unwrap().is_ready());
        let payload = source.capture_payload(cut.key).unwrap();
        let (socket, peer) = UnixDatagram::pair().unwrap();
        let mut net =
            Net::new_restore_binding(name.into(), socket.into(), [2, 0, 0, 0, 0, 2], 0).unwrap();
        net.prepare_restore(
            cut,
            &payload,
            DormantDeviceContext {
                memory: crate::vmm::memory::runtime_memory_for_test(
                    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
                ),
                interrupt: InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    format!("{name}-activation"),
                    None,
                )
                .unwrap(),
                activated: false,
                reclaim_policy: RestoredReclaimPolicy::Disabled,
            },
        )
        .unwrap();
        let resume = activation_request(32, deadline);
        assert!(matches!(
            net.begin_resume(resume, Vec::new()),
            ResumeAcceptance::Accepted
        ));
        assert!(net.poll_resume(resume.key).unwrap().is_ready());
        (Arc::new(std::sync::Mutex::new(net)), peer)
    }

    #[cfg(feature = "net")]
    fn fenced(net: &SharedNet) -> Option<bool> {
        use devices::virtio::lifecycle::VirtioStateProvider;
        net.lock().unwrap().activation_fenced().unwrap()
    }

    #[cfg(feature = "net")]
    fn activation_barrier(
        nets: &[&SharedNet],
        deadline: std::time::Instant,
    ) -> crate::vmm::control::live::ActivationBarrier {
        crate::vmm::control::live::ActivationBarrier::new(
            activation_request(33, deadline),
            nets.iter()
                .map(|net| {
                    let device: Arc<std::sync::Mutex<dyn devices::virtio::VirtioDevice>> =
                        (*net).clone();
                    device
                })
                .collect(),
        )
    }

    /// Poll until `index` finished local preparation while another provider is busy.
    #[cfg(feature = "net")]
    fn prepare_only(
        barrier: &mut crate::vmm::control::live::ActivationBarrier,
        index: usize,
        deadline: std::time::Instant,
    ) {
        while !barrier.devices[index].prepared {
            assert!(
                barrier
                    .settle(false, || unreachable!("no commit while a provider is busy"))
                    .is_pending()
            );
            assert!(std::time::Instant::now() < deadline, "preparation stalled");
        }
    }

    #[cfg(feature = "net")]
    fn settled(
        barrier: &mut crate::vmm::control::live::ActivationBarrier,
        mut authority: impl FnMut() -> Result<(), LiveError>,
        deadline: std::time::Instant,
    ) -> Result<(), LiveError> {
        loop {
            match barrier.settle(false, &mut authority) {
                std::task::Poll::Ready(result) => return result,
                std::task::Poll::Pending => {
                    assert!(
                        std::time::Instant::now() < deadline + std::time::Duration::from_secs(1),
                        "barrier never settled"
                    );
                }
            }
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_transport_ownership_does_not_refuse_or_expose_early() {
        use crate::vmm::device_manager::quiescence::{AttachmentIdentity, DeviceQuiescence};
        use devices::legacy::DummyIrqChip;
        use devices::virtio::{MmioTransport, VirtioDevice};
        use std::sync::Mutex;
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let (first, _first_peer) = restored_net("eth0");
        let (second, _second_peer) = restored_net("eth1");
        let mut inventory = DeviceQuiescence::default();
        let mut transports = Vec::new();
        for (index, net) in [&first, &second].into_iter().enumerate() {
            let device: Arc<Mutex<dyn VirtioDevice>> = net.clone();
            let transport = Arc::new(Mutex::new(
                MmioTransport::new(
                    crate::vmm::memory::runtime_memory_for_test(
                        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
                    ),
                    DummyIrqChip::new().into(),
                    device.clone(),
                    None,
                )
                .unwrap(),
            ));
            inventory.retain_transport(
                AttachmentIdentity {
                    device_type: devices::DeviceType::Virtio(1),
                    configured_id: format!("eth{index}"),
                    address: 0xd000_0000 + index as u64 * 0x1000,
                    irq: 5 + index as u32,
                },
                transport.clone(),
                device,
            );
            transports.push(transport);
        }
        // Keep real bus-owner guards across inventory, preparation and commit,
        // rather than racing a timed lock release.
        let _first_transport = transports[0].try_lock().unwrap();
        let _second_transport = transports[1].try_lock().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let devices = inventory
            .live_devices()
            .into_iter()
            .map(|(_, device)| device)
            .collect();
        let mut barrier = super::ActivationBarrier::new(activation_request(33, deadline), devices);
        let second_owner = second.try_lock().unwrap();
        prepare_only(&mut barrier, 0, deadline);
        assert!(!barrier.devices[1].begun);
        assert!(!barrier.exposure.is_open());
        assert_eq!(fenced(&first), Some(true));
        let first_owner = first.try_lock().unwrap();
        drop(second_owner);
        prepare_only(&mut barrier, 1, deadline);
        assert!(!barrier.exposure.is_open());
        assert!(!barrier.exposure.is_sealed());
        assert_eq!(fenced(&second), Some(true));
        drop(first_owner);
        let mut commits = 0;
        settled(
            &mut barrier,
            || {
                commits += 1;
                Ok(())
            },
            deadline,
        )
        .unwrap();
        assert_eq!(commits, 1);
        assert!(barrier.exposure.is_open());
        assert_eq!(fenced(&first), Some(false));
        assert_eq!(fenced(&second), Some(false));
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_exposes_no_provider_until_every_provider_is_prepared() {
        let (first, _first_peer) = restored_net("eth0");
        let (second, _second_peer) = restored_net("eth1");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut barrier = activation_barrier(&[&first, &second], deadline);
        let held = second.lock().unwrap();
        prepare_only(&mut barrier, 0, deadline);
        assert!(!barrier.devices[1].begun);
        assert_eq!(
            fenced(&first),
            Some(true),
            "a prepared provider stays fenced while another is still pending"
        );
        assert!(!barrier.exposure.is_open());
        drop(held);
        assert_eq!(fenced(&second), Some(true));
        let mut commits = 0;
        let result = settled(
            &mut barrier,
            || {
                commits += 1;
                Ok(())
            },
            deadline,
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(commits, 1, "authority is rechecked once, at the commit");
        assert!(barrier.exposure.is_open());
        assert_eq!(fenced(&first), Some(false));
        assert_eq!(fenced(&second), Some(false));
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_provider_failure_after_partial_preparation_exposes_nothing() {
        let (first, _first_peer) = restored_net("eth0");
        let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        // A cold provider has no restored fence to release and refuses begin.
        let cold: SharedNet = Arc::new(std::sync::Mutex::new(
            devices::virtio::Net::new_managed("eth1".into(), socket.into(), [2, 0, 0, 0, 0, 3], 0)
                .unwrap(),
        ));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut barrier = activation_barrier(&[&first, &cold], deadline);
        let held = cold.lock().unwrap();
        prepare_only(&mut barrier, 0, deadline);
        drop(held);
        let result = settled(
            &mut barrier,
            || unreachable!("no commit after a provider failure"),
            deadline,
        );
        assert!(
            matches!(
                result,
                Err(LiveError::Activation {
                    stage: crate::api::live::ActivationStage::Begin,
                    fault: devices::virtio::lifecycle::ProviderFault::InvalidTransition,
                    accepted: true,
                })
            ),
            "{result:?}"
        );
        assert!(barrier.exposure.is_sealed());
        assert!(!barrier.exposure.open(), "no later commit can reopen it");
        assert_eq!(
            fenced(&first),
            Some(true),
            "the already prepared provider never became visible"
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_deadline_with_a_busy_provider_seals_every_provider() {
        let (first, _first_peer) = restored_net("eth0");
        let (second, _second_peer) = restored_net("eth1");
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        let mut barrier = activation_barrier(&[&first, &second], deadline);
        let held = second.lock().unwrap();
        prepare_only(&mut barrier, 0, deadline);
        let result = settled(
            &mut barrier,
            || unreachable!("no commit past the absolute deadline"),
            deadline,
        );
        drop(held);
        assert!(std::time::Instant::now() >= deadline);
        assert!(
            matches!(
                result,
                Err(LiveError::Activation {
                    stage: crate::api::live::ActivationStage::Poll,
                    fault: devices::virtio::lifecycle::ProviderFault::Deadline,
                    accepted: true,
                })
            ),
            "{result:?}"
        );
        assert!(barrier.exposure.is_sealed());
        assert_eq!(fenced(&first), Some(true));
        assert_eq!(fenced(&second), Some(true));
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_latched_stop_wins_over_an_uncommitted_release() {
        let (first, _first_peer) = restored_net("eth0");
        let (second, _second_peer) = restored_net("eth1");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        let mut untouched = activation_barrier(&[&first, &second], deadline);
        let result = untouched.settle(true, || unreachable!("stop precedes any commit"));
        assert!(
            matches!(
                result,
                std::task::Poll::Ready(Err(LiveError::Activation {
                    fault: devices::virtio::lifecycle::ProviderFault::InvalidTransition,
                    accepted: false,
                    ..
                }))
            ),
            "{result:?}"
        );
        assert!(untouched.exposure.is_sealed());
        assert!(untouched.devices.iter().all(|entry| !entry.begun));

        let mut barrier = activation_barrier(&[&first, &second], deadline);
        let held = second.lock().unwrap();
        prepare_only(&mut barrier, 0, deadline);
        drop(held);
        let result = barrier.settle(true, || unreachable!("stop precedes any commit"));
        assert!(
            matches!(
                result,
                std::task::Poll::Ready(Err(LiveError::Activation {
                    fault: devices::virtio::lifecycle::ProviderFault::InvalidTransition,
                    accepted: true,
                    ..
                }))
            ),
            "{result:?}"
        );
        assert!(barrier.exposure.is_sealed());
        assert_eq!(fenced(&first), Some(true));
        assert_eq!(fenced(&second), Some(true));
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_revoked_authority_at_commit_exposes_nothing() {
        let (first, _first_peer) = restored_net("eth0");
        let (second, _second_peer) = restored_net("eth1");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut barrier = activation_barrier(&[&first, &second], deadline);
        let result = settled(
            &mut barrier,
            || Err(ControlFailure::InvalidToken.into()),
            deadline,
        );
        assert!(
            matches!(
                result,
                Err(LiveError::Control(ControlFailure::InvalidToken))
            ),
            "{result:?}"
        );
        assert!(barrier.devices.iter().all(|entry| entry.prepared));
        assert!(barrier.exposure.is_sealed());
        assert_eq!(fenced(&first), Some(true));
        assert_eq!(fenced(&second), Some(true));
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_provider_transition_between_prepare_and_commit_exposes_nothing() {
        use devices::virtio::lifecycle::VirtioStateProvider;
        let (first, _first_peer) = restored_net("eth0");
        let (second, _second_peer) = restored_net("eth1");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut barrier = activation_barrier(&[&first, &second], deadline);
        let held = second.lock().unwrap();
        prepare_only(&mut barrier, 0, deadline);
        // The already prepared provider leaves Running before the last one is
        // ready; its earlier proof must not be committed.
        first
            .lock()
            .unwrap()
            .begin_quiesce(activation_request(34, deadline))
            .unwrap();
        drop(held);
        let result = settled(
            &mut barrier,
            || unreachable!("no authority check after a failed provider proof"),
            deadline,
        );
        assert!(
            matches!(
                result,
                Err(LiveError::Activation {
                    stage: crate::api::live::ActivationStage::Poll,
                    fault: devices::virtio::lifecycle::ProviderFault::InvalidTransition,
                    accepted: true,
                })
            ),
            "{result:?}"
        );
        assert!(barrier.devices.iter().all(|entry| entry.prepared));
        assert!(barrier.exposure.is_sealed());
        assert_eq!(fenced(&first), Some(true));
        assert_eq!(fenced(&second), Some(true));
    }

    #[cfg(feature = "net")]
    #[test]
    fn activation_barrier_commit_contention_retries_without_a_stale_commit() {
        let (first, _first_peer) = restored_net("eth0");
        let (second, _second_peer) = restored_net("eth1");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut barrier = activation_barrier(&[&first, &second], deadline);
        let held_second = second.lock().unwrap();
        prepare_only(&mut barrier, 0, deadline);
        // Hold the prepared provider so the last preparation completes while the
        // commit cannot take every provider lock.
        let held_first = first.lock().unwrap();
        drop(held_second);
        prepare_only(&mut barrier, 1, deadline);
        assert!(
            barrier
                .settle(false, || unreachable!(
                    "no commit without every provider lock"
                ))
                .is_pending()
        );
        assert!(!barrier.exposure.is_open());
        assert!(!barrier.exposure.is_sealed(), "contention is not failure");
        drop(held_first);
        let mut commits = 0;
        let result = settled(
            &mut barrier,
            || {
                commits += 1;
                Ok(())
            },
            deadline,
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(commits, 1);
        assert!(barrier.exposure.is_open());
        assert_eq!(fenced(&first), Some(false));
        assert_eq!(fenced(&second), Some(false));
    }
}
