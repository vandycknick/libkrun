//! Rust-only whole-machine capture and activation control.
//!
//! Accepted requests own their files until native terminality. A caller deadline
//! bounds observation, never cancellation. Completed receipts have no writers.

#[cfg(all(
    feature = "native-device-probe",
    feature = "blk",
    feature = "net",
    target_os = "linux",
    target_arch = "x86_64",
    not(any(feature = "tee", feature = "aws-nitro"))
))]
pub mod irq_probe;

#[cfg(all(
    not(any(feature = "tee", feature = "aws-nitro")),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
pub mod inspection;

#[cfg(all(
    not(any(feature = "tee", feature = "aws-nitro")),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
pub mod restore;

pub use arch::guest_memory::{
    BackingKind, DirtyEffect, DirtyFailure, DirtyLocation, DirtyOperation, TrackingMode,
};
pub use devices::virtio::lifecycle::ProviderFault;
use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Instant;

pub use crate::vmm::control::{GenerationTicket, RestoreToken};
pub use crate::vmm::execution::kvm;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use crate::vmm::execution::runtime::KvmCaptureProfile;
pub use crate::vmm::execution::runtime::TimePreparation;
pub use crate::vmm::execution::{
    CpuExecutionState, CpuTimePlan, ExecutionEnvelope, ExecutionLane, StateBinding,
    VmExecutionState,
};
pub use crate::vmm::memory::image::{
    AuthenticatedRamImage, RamCaptureMode, RamCaptureReceipt, RamImageAuthentication,
    RamImageError, RamIoStats, RamSeedMethod, ValidatedRamLayout,
};
pub use crate::vmm::memory::{
    BaselineToken, CaptureError, FullCaptureReason, RestoreInstallationEvidence,
};
pub use devices::virtio::generation::{GenerationObservation, GenerationSnapshot};

use crate::api::vmm_builder::VmmHandle;
use crate::vmm::control::live::{LiveReply, LiveRequest};
use crate::vmm::control::{
    ControlFailure, ControlReply, GenerationAuthority, GenerationMode, OperationId, PauseToken,
    RequestKind,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CaptureId([u8; 16]);
impl CaptureId {
    pub fn new(value: [u8; 16]) -> Self {
        Self(value)
    }
    pub fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct CaptureTicket {
    pub(crate) run: Arc<()>,
    pub(crate) sequence: u64,
    pub(crate) id: CaptureId,
    pub(crate) pause: PauseToken,
}
impl CaptureTicket {
    pub fn id(&self) -> CaptureId {
        self.id
    }
}
impl PartialEq for CaptureTicket {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.run, &other.run)
            && self.sequence == other.sequence
            && self.id == other.id
            && self.pause == other.pause
    }
}
impl Eq for CaptureTicket {}

#[derive(Debug)]
pub struct ExecutionOutputs {
    pub execution: File,
    pub devices: File,
}
#[derive(Debug)]
pub struct MemoryOutputs {
    pub ram: File,
    pub layout: File,
}
#[derive(Debug)]
pub struct BaselineImage {
    pub ram: File,
    pub layout: File,
    pub authentication: RamImageAuthentication,
}
#[derive(Clone, Debug)]
pub struct MemoryCaptureRequest {
    pub baseline: Option<BaselineToken>,
    pub full_at_dirty_percent: u8,
}
impl Default for MemoryCaptureRequest {
    fn default() -> Self {
        Self {
            baseline: None,
            full_at_dirty_percent: 60,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputRole {
    Execution,
    Devices,
    Ram,
    Layout,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputProblem {
    NotRegular,
    Access,
    Append,
    DirectIo,
    PathOnly,
    NotEmpty,
    Alias,
    Changed,
    CloseOnExec,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputReceipt {
    pub role: OutputRole,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub binding: StateBinding,
}
#[derive(Clone, Debug)]
pub struct FlushReceipt {
    pub pause: PauseToken,
    pub attachments: Vec<crate::vmm::device_manager::quiescence::AttachmentIdentity>,
}
#[derive(Clone, Debug)]
pub struct ExecutionCaptureReceipt {
    pub ticket: CaptureTicket,
    pub execution: OutputReceipt,
    pub devices: OutputReceipt,
}
#[derive(Clone, Debug)]
pub struct CompletedCapture {
    pub ticket: CaptureTicket,
    pub ram: Arc<RamCaptureReceipt>,
    pub full_reason: Option<FullCaptureReason>,
    pub memory_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureStage {
    Execution,
    Memory,
    Accept,
}
#[derive(Clone, Debug)]
pub enum CaptureStatus {
    ExecutionPending(CaptureTicket),
    ExecutionComplete(Arc<ExecutionCaptureReceipt>),
    MemoryPending(CaptureTicket),
    CandidateComplete(CompletedCapture),
    Accepted {
        ticket: CaptureTicket,
        baseline: BaselineToken,
    },
    Abandoned(CaptureTicket),
    Failed {
        ticket: CaptureTicket,
        stage: CaptureStage,
        cause: LiveError,
    },
    Released,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationStage {
    Begin,
    Poll,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveStage {
    Flush,
    Execution,
    Memory,
    Status,
    Accept,
    Abandon,
    Release,
    Preserve,
    MemoryCutRecovery,
    GenerationPrepare,
    GenerationPoll,
    GenerationSnapshot,
    GenerationResume,
    ActivationRelease,
    Observation,
    Profile,
}
#[derive(Clone, Debug)]
pub enum LiveSubject {
    Vm,
    Pause(PauseToken),
    Pausing(OperationId),
    Capture(CaptureId),
    Restore(RestoreToken),
    Generation(GenerationTicket),
}
#[derive(Clone, Debug)]
pub enum LiveError {
    Control(ControlFailure),
    Capture(Arc<CaptureError>),
    Execution(String),
    Output {
        role: OutputRole,
        problem: OutputProblem,
    },
    Io {
        role: OutputRole,
        source: Arc<io::Error>,
    },
    Activation {
        stage: ActivationStage,
        fault: devices::virtio::lifecycle::ProviderFault,
        accepted: bool,
    },
    Operation {
        operation: OperationId,
        stage: LiveStage,
        subject: LiveSubject,
        cause: Arc<LiveError>,
    },
}
impl std::fmt::Display for LiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native live: {self:?}")
    }
}
impl LiveError {
    pub(crate) fn with_context(
        self,
        operation: OperationId,
        stage: LiveStage,
        subject: LiveSubject,
    ) -> Self {
        if matches!(self, Self::Operation { .. }) {
            self
        } else {
            Self::Operation {
                operation,
                stage,
                subject,
                cause: Arc::new(self),
            }
        }
    }
}
impl std::error::Error for LiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Operation { cause, .. } => Some(cause.as_ref()),
            Self::Control(cause) => Some(cause),
            Self::Capture(cause) => Some(cause.as_ref()),
            Self::Io { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
impl From<ControlFailure> for LiveError {
    fn from(value: ControlFailure) -> Self {
        Self::Control(value)
    }
}
impl From<CaptureError> for LiveError {
    fn from(value: CaptureError) -> Self {
        Self::Capture(Arc::new(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationKind {
    FreshIdentity,
    ClockOnly,
}
pub enum StoppedOwner<'a> {
    Paused(&'a PauseToken),
    Restore(&'a RestoreToken),
}

#[derive(Clone, Debug)]
pub struct LiveProviderSnapshot {
    pub attachment: crate::vmm::device_manager::quiescence::AttachmentIdentity,
    /// Effective fence: `Some(true)` until the all-provider exposure commit,
    /// even after this provider finished its local release preparation.
    pub activation_fenced: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct LiveSnapshot {
    pub state: crate::vmm::control::ControlState,
    pub backing: arch::guest_memory::BackingKind,
    pub file_backings: Vec<(u64, u64)>,
    pub tracking: Option<arch::guest_memory::TrackingMode>,
    pub coverage_valid: bool,
    pub pending_dirty_pages: usize,
    pub native_commands_reconciled: bool,
    pub activation_released: bool,
    pub restore_installation: Option<RestoreInstallationEvidence>,
    pub providers: Vec<LiveProviderSnapshot>,
    pub activation_failed: bool,
    pub time_preparation: Option<TimePreparation>,
}

impl VmmHandle {
    pub fn baseline(&self, deadline: Instant) -> Result<Option<BaselineToken>, LiveError> {
        match self.live_call(OperationId(0), deadline, LiveRequest::Baseline)? {
            LiveReply::CurrentBaseline(token) => Ok(token),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    fn live_call(
        &self,
        operation: OperationId,
        deadline: Instant,
        request: LiveRequest,
    ) -> Result<LiveReply, LiveError> {
        let (stage, subject) = request.context();
        let result = match self
            .control
            .call(operation, deadline, RequestKind::Live(request))
        {
            Ok(ControlReply::Live(result)) => result,
            Ok(_) => Err(ControlFailure::OwnerUnavailable.into()),
            Err(cause) => Err(cause.into()),
        };
        result.map_err(|cause| cause.with_context(operation, stage, subject))
    }
    fn generation_call(
        &self,
        operation: OperationId,
        deadline: Instant,
        request: RequestKind,
        stage: LiveStage,
        subject: LiveSubject,
    ) -> Result<ControlReply, LiveError> {
        self.control
            .call(operation, deadline, request)
            .map_err(|cause| LiveError::from(cause).with_context(operation, stage, subject))
    }
    /// Recovers tracking for the exact failed pause without restoring coverage.
    ///
    /// `operation` must be a fresh operation ID, distinct from `pausing`. Recovery
    /// retains the stopped machine cut; only accepting a full baseline restores
    /// incremental coverage. A failed recovery leaves the machine fenced.
    pub fn recover_memory_cut(
        &self,
        pausing: OperationId,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<PauseToken, LiveError> {
        match self.live_call(
            operation,
            deadline,
            LiveRequest::RecoverMemoryCut { pausing },
        )? {
            LiveReply::Pause(token) => Ok(token),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn flush_writable_disks(
        &self,
        pause: &PauseToken,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<FlushReceipt, LiveError> {
        match self.live_call(operation, deadline, LiveRequest::Flush(pause.clone()))? {
            LiveReply::Flush(receipt) => Ok(receipt),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn capture_execution(
        &self,
        pause: &PauseToken,
        binding: StateBinding,
        outputs: ExecutionOutputs,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<ExecutionCaptureReceipt, LiveError> {
        match self.live_call(
            operation,
            deadline,
            LiveRequest::Execution {
                pause: pause.clone(),
                binding: Box::new(binding),
                outputs,
            },
        )? {
            LiveReply::Execution(receipt) => Ok(receipt.as_ref().clone()),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn capture_memory(
        &self,
        ticket: &CaptureTicket,
        request: MemoryCaptureRequest,
        outputs: MemoryOutputs,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<CompletedCapture, LiveError> {
        match self.live_call(
            operation,
            deadline,
            LiveRequest::Memory {
                ticket: ticket.clone(),
                request,
                outputs,
            },
        )? {
            LiveReply::Memory(receipt) => Ok(receipt),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn capture_status(
        &self,
        capture: CaptureId,
        deadline: Instant,
    ) -> Result<CaptureStatus, LiveError> {
        match self.live_call(OperationId(0), deadline, LiveRequest::Status(capture))? {
            LiveReply::Status(status) => Ok(status),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn accept_baseline(
        &self,
        ticket: &CaptureTicket,
        sealed: BaselineImage,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<BaselineToken, LiveError> {
        match self.live_call(
            operation,
            deadline,
            LiveRequest::Accept {
                ticket: ticket.clone(),
                sealed: Box::new(sealed),
            },
        )? {
            LiveReply::Baseline(token) => Ok(token),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn abandon_capture(
        &self,
        ticket: &CaptureTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.live_complete(operation, deadline, LiveRequest::Abandon(ticket.clone()))
    }
    pub fn release_capture(
        &self,
        capture: CaptureId,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.live_complete(operation, deadline, LiveRequest::Release(capture))
    }
    pub fn preserve_pause(
        &self,
        pause: PauseToken,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<PauseToken, LiveError> {
        match self.live_call(operation, deadline, LiveRequest::Preserve(pause))? {
            LiveReply::Pause(token) => Ok(token),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    fn live_complete(
        &self,
        operation: OperationId,
        deadline: Instant,
        request: LiveRequest,
    ) -> Result<(), LiveError> {
        match self.live_call(operation, deadline, request)? {
            LiveReply::Complete => Ok(()),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn prepare_generation(
        &self,
        owner: StoppedOwner<'_>,
        kind: GenerationKind,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<GenerationTicket, LiveError> {
        let (authority, subject) = match owner {
            StoppedOwner::Paused(token) => (
                GenerationAuthority::Pause(token.clone()),
                LiveSubject::Pause(token.clone()),
            ),
            StoppedOwner::Restore(token) => (
                GenerationAuthority::RestoreToken(token.clone()),
                LiveSubject::Restore(token.clone()),
            ),
        };
        let mode = match kind {
            GenerationKind::FreshIdentity => GenerationMode::Fresh,
            GenerationKind::ClockOnly => GenerationMode::ClockOnly,
        };
        match self.generation_call(
            operation,
            deadline,
            RequestKind::PrepareGeneration {
                authority,
                mode,
                deadline,
            },
            LiveStage::GenerationPrepare,
            subject,
        )? {
            ControlReply::Generation(ticket) => Ok(ticket),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn poll_generation(
        &self,
        ticket: &GenerationTicket,
        deadline: Instant,
    ) -> Result<GenerationObservation, LiveError> {
        match self.live_call(
            OperationId(0),
            deadline,
            LiveRequest::Generation(ticket.clone()),
        )? {
            LiveReply::Generation(observation) => Ok(observation),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn generation_snapshot(&self, deadline: Instant) -> Result<GenerationSnapshot, LiveError> {
        match self.generation_call(
            OperationId(0),
            deadline,
            RequestKind::GenerationSnapshot,
            LiveStage::GenerationSnapshot,
            LiveSubject::Vm,
        )? {
            ControlReply::GenerationSnapshot(snapshot) => Ok(snapshot),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn resume_generation(
        &self,
        pause: PauseToken,
        generation: &GenerationTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        match self.generation_call(
            operation,
            deadline,
            RequestKind::ResumeGeneration(pause, generation.clone()),
            LiveStage::GenerationResume,
            LiveSubject::Generation(generation.clone()),
        )? {
            ControlReply::Complete => Ok(()),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn resume_restored(
        &self,
        restore: &RestoreToken,
        generation: &GenerationTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        match self.generation_call(
            operation,
            deadline,
            RequestKind::ResumeRestored(restore.clone(), generation.clone()),
            LiveStage::GenerationResume,
            LiveSubject::Restore(restore.clone()),
        )? {
            ControlReply::Complete => Ok(()),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    /// Release every restored network and vsock activation fence as one commit.
    ///
    /// All fallible provider preparation completes while a shared exposure gate
    /// keeps both network directions and non-control vsock fenced; the owner then
    /// holds every provider lock, has each re-prove its exact prepared state,
    /// rechecks this exact restore token, the acknowledged FreshIdentity ticket,
    /// `deadline` and stop, and opens every provider with one atomic commit.
    /// `Ok` means all providers are exposed; a replay after that is `Ok`. A
    /// refusal before acceptance (authority, `Busy` while one is in flight)
    /// changes nothing. Any failure of an accepted release seals the gate: no
    /// provider was or will be exposed, `activation_failed` is set and later
    /// calls report `FailedFenced`. A caller timeout is not a fence receipt;
    /// the owner keeps the release to its original deadline, observable through
    /// `live_snapshot`.
    pub fn release_activation_fences(
        &self,
        restore: &RestoreToken,
        generation: &GenerationTicket,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.live_complete(
            operation,
            deadline,
            LiveRequest::Activation {
                restore: restore.clone(),
                generation: generation.clone(),
            },
        )
    }
    pub fn ram_layout(&self, deadline: Instant) -> Result<Arc<ValidatedRamLayout>, LiveError> {
        match self.live_call(OperationId(0), deadline, LiveRequest::Layout)? {
            LiveReply::Layout(layout) => Ok(layout),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    pub fn live_snapshot(&self, deadline: Instant) -> Result<LiveSnapshot, LiveError> {
        match self.live_call(OperationId(0), deadline, LiveRequest::Snapshot)? {
            LiveReply::Snapshot(snapshot) => Ok(snapshot),
            _ => Err(ControlFailure::OwnerUnavailable.into()),
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub fn set_capture_profile(
        &self,
        profile: KvmCaptureProfile,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), LiveError> {
        self.live_complete(operation, deadline, LiveRequest::Profile(profile))
    }
}
