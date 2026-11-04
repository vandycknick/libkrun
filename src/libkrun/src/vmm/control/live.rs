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
use devices::virtio::lifecycle::ProviderFault;
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
    BaselineImage, CaptureId, CaptureStage, CaptureStatus, CaptureTicket, CompletedCapture,
    ExecutionCaptureReceipt, ExecutionOutputs, FlushReceipt, LiveError, LiveSnapshot, LiveStage,
    LiveSubject, MemoryCaptureRequest, MemoryOutputs, OutputProblem, OutputRole,
};
use crate::vmm::Vmm;
use crate::vmm::control::{
    BarrierKey, BarrierRequest, ControlFailure, ControlReply, ControlState, GenerationTicket,
    OperationId, PauseOwner, PauseToken, RequestId, RestoreToken,
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
    complete: bool,
}
struct ActivationRelease {
    request: BarrierRequest,
    devices: Vec<ActivationDevice>,
    reply: Reply,
    failure: Option<LiveError>,
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
}
impl LiveOwner {
    pub(crate) fn pending(&self) -> bool {
        self.records.values().any(|record| record.pending.is_some()) || self.activation.is_some()
    }
    pub(crate) fn unresolved(&self) -> bool {
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
        let devices = self
            .mmio_device_manager
            .quiescence
            .live_devices()
            .map_err(|error| LiveError::Execution(error.to_string()))?;
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
                let identity = device
                    .state_provider()
                    .ok_or_else(|| LiveError::Execution("provider absent".into()))?
                    .backing_file_identity()
                    .map_err(|error| {
                        LiveError::Execution(format!("backing identity: {error:?}"))
                    })?;
                if identity == Some((fact.0, fact.1)) {
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
                for (attachment, device) in self
                    .mmio_device_manager
                    .quiescence
                    .live_devices()
                    .map_err(|error| LiveError::Execution(error.to_string()))?
                {
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
                self.control.validate_restore_token(&restore)?;
                self.validate_generation_ticket(&generation)?;
                if generation.stopped != restore.key
                    || generation.attempt.request().flags != 1
                    || !matches!(
                        generation.observe(Instant::now()),
                        GenerationObservation::Acknowledged(_)
                    )
                {
                    return Err(ControlFailure::InvalidToken.into());
                }
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
                    .map_err(|error| LiveError::Execution(error.to_string()))?
                    .into_iter()
                    .filter(|(identity, _)| {
                        matches!(identity.device_type, devices::DeviceType::Virtio(1 | 19))
                    })
                    .map(|(_, device)| ActivationDevice {
                        device,
                        begun: false,
                        complete: false,
                    })
                    .collect();
                self.control.live.activation = Some(ActivationRelease {
                    request: BarrierRequest {
                        key: BarrierKey {
                            operation,
                            generation: restore.key.generation,
                        },
                        deadline,
                    },
                    devices,
                    reply: reply.clone(),
                    failure: None,
                });
                return Ok(None);
            }
        };
        Ok(Some(result))
    }
    pub(crate) fn poll_live(&mut self) {
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
    fn poll_live_activation(&mut self) {
        let Some(mut release) = self.control.live.activation.take() else {
            return;
        };
        let mut accepted = release.devices.iter().any(|entry| entry.begun);
        if Instant::now() >= release.request.deadline
            || matches!(
                self.control.state,
                ControlState::Stopping | ControlState::Stopped | ControlState::FailedFenced
            )
        {
            let fault = if Instant::now() >= release.request.deadline {
                ProviderFault::Deadline
            } else {
                ProviderFault::InvalidTransition
            };
            release.failure.get_or_insert(LiveError::Activation {
                stage: crate::api::live::ActivationStage::Poll,
                fault,
                accepted,
            });
        }
        if release.failure.is_none() {
            for entry in &mut release.devices {
                if entry.complete {
                    continue;
                }
                let mut device = match entry.device.try_lock() {
                    Ok(device) => device,
                    Err(TryLockError::WouldBlock) => continue,
                    Err(TryLockError::Poisoned(_)) => {
                        release.failure = Some(LiveError::Activation {
                            stage: crate::api::live::ActivationStage::Begin,
                            fault: ProviderFault::DeviceLock,
                            accepted,
                        });
                        break;
                    }
                };
                let Some(provider) = device.state_provider_mut() else {
                    release.failure = Some(LiveError::Activation {
                        stage: crate::api::live::ActivationStage::Begin,
                        fault: ProviderFault::Unsupported,
                        accepted,
                    });
                    break;
                };
                if !entry.begun {
                    match provider.begin_activation_release(release.request) {
                        Ok(()) => {
                            entry.begun = true;
                            accepted = true;
                        }
                        Err(error) if !error.accepted && error.fault == ProviderFault::LockBusy => {
                            continue;
                        }
                        Err(error) => {
                            entry.begun = error.accepted;
                            accepted |= error.accepted;
                            release.failure = Some(LiveError::Activation {
                                stage: crate::api::live::ActivationStage::Begin,
                                fault: error.fault,
                                accepted,
                            });
                            break;
                        }
                    }
                }
                match provider.poll_activation_release(release.request.key) {
                    Ok(Poll::Ready(())) => entry.complete = true,
                    Ok(Poll::Pending) => {}
                    Err(fault) => {
                        release.failure = Some(LiveError::Activation {
                            stage: crate::api::live::ActivationStage::Poll,
                            fault,
                            accepted: true,
                        });
                        break;
                    }
                }
            }
        }
        if let Some(error) = &release.failure {
            self.control.live.activation_failed = true;
            answer(&release.reply, Err(error.clone()));
            // Providers retain accepted release ownership until the normal terminal stop.
            self.control.live.activation = Some(release);
        } else if release.devices.iter().all(|entry| entry.complete) {
            self.control.live.activation_released = true;
            answer(&release.reply, Ok(LiveReply::Complete));
        } else {
            self.control.live.activation = Some(release);
        }
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
    use crate::vmm::control::live::LiveRequest;
    use crate::vmm::control::live::{
        CaptureRecord, LiveOwner, inspect, inspect_outputs, write_object,
    };
    use crate::vmm::control::{
        BarrierGeneration, BarrierKey, ControlFailure, ControlOwner, ControlState,
        GenerationAuthority, OperationId, PauseOwner,
    };
    #[cfg(target_os = "linux")]
    use crate::vmm::control::{ControlClient, RequestKind};
    use crate::vmm::execution::StateBinding;
    use std::fs::{self, File, OpenOptions};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    #[cfg(target_os = "linux")]
    use std::time::{Duration, Instant};
    use utils::tempfile::TempFile;

    fn key() -> BarrierKey {
        BarrierKey {
            operation: OperationId(1),
            generation: BarrierGeneration(1),
        }
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
}
