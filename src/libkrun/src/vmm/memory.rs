use std::fs::File;
use std::num::NonZeroU64;
use std::sync::{Arc, OnceLock};
use std::task::Poll;
use std::time::Instant;

use crate::vmm::Vmm;
use crate::vmm::control::{BarrierKey, ControlFailure, ControlState, PauseToken};
use crate::vmm::execution::{ExecutionLane, StateBinding};
use crate::vmm::memory::image::{
    AdmittedRamImage, RamCaptureIdentity, RamCaptureMode, RamCaptureReceipt, RamHashSelection,
    RamIdentityAnchor, RamIdentityGeneration, RamIdentityPolicy, RamImageError, RamImageFailure,
    RamInputAuthority, RamIoScratch, RamOutputFiles, RamWriteMode, ValidatedRamLayout,
};
#[cfg(not(feature = "tee"))]
use arch::guest_memory::DirtyEffect;
use arch::guest_memory::{
    ClosingMemory, ConstructionAuthority, CpuTrackingEpoch, DirtyFailure, DirtyPageMap,
    DomainControl, DrainedMemory, MemoryCut, MemoryError, NativeEffectsPermit, TopologyGeneration,
    TrackingMode,
};

pub mod image;

#[derive(Clone, Debug)]
struct TrackerIdentity(Arc<()>);
impl PartialEq for TrackerIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for TrackerIdentity {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineToken {
    tracker: TrackerIdentity,
    topology: TopologyGeneration,
    memory_generation: u64,
    identity_anchor: RamIdentityAnchor,
    identity_anchor_generation: RamIdentityGeneration,
}
impl BaselineToken {
    pub fn memory_generation(&self) -> u64 {
        self.memory_generation
    }
    pub fn identity_anchor(&self) -> RamIdentityAnchor {
        self.identity_anchor
    }
    pub fn identity_anchor_generation(&self) -> RamIdentityGeneration {
        self.identity_anchor_generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptId {
    tracker: TrackerIdentity,
    sequence: u64,
}
impl AttemptId {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            tracker: TrackerIdentity(Arc::new(())),
            sequence: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirtyCrossoverPercent(u8);
impl DirtyCrossoverPercent {
    pub(crate) fn new(percent: u8) -> Result<Self, CaptureError> {
        if !(1..=60).contains(&percent) {
            return Err(CaptureError::Crossover);
        }
        Ok(Self(percent))
    }
}
impl Default for DirtyCrossoverPercent {
    fn default() -> Self {
        Self(60)
    }
}

pub(crate) enum RamCaptureRequest<'a> {
    Full,
    Incremental {
        baseline: Option<&'a BaselineToken>,
        crossover: DirtyCrossoverPercent,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FullCaptureReason {
    Requested,
    NoBaseline,
    BaselineToken,
    CoverageLost,
    DirtyCrossover,
}

#[derive(Debug)]
pub enum CaptureError {
    Busy,
    InvalidPause,
    InvalidAttempt,
    InvalidCandidate,
    Execution,
    Exhausted,
    Crossover,
    Deadline,
    Memory(MemoryError),
    Tracking(DirtyFailure),
    Image(RamImageError),
    Write(Arc<RamImageFailure>),
}
impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RAM capture: {self:?}")
    }
}
impl std::error::Error for CaptureError {}
impl From<MemoryError> for CaptureError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
impl From<RamImageError> for CaptureError {
    fn from(value: RamImageError) -> Self {
        Self::Image(value)
    }
}

struct AcceptedBaseline {
    token: BaselineToken,
    image: Arc<AdmittedRamImage>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum AttemptState {
    Writing,
    Completed,
    Failed,
}
struct CaptureAttempt {
    id: AttemptId,
    key: BarrierKey,
    generation: u64,
    cut_generation: u64,
    topology: TopologyGeneration,
    binding: StateBinding,
    layout: Arc<ValidatedRamLayout>,
    full_reason: Option<FullCaptureReason>,
    identity_policy: RamIdentityPolicy,
    state: AttemptState,
    failure: Option<Arc<RamImageFailure>>,
}

#[derive(Clone)]
pub(crate) struct CompletedCandidate {
    id: AttemptId,
    generation: u64,
    receipt: Arc<RamCaptureReceipt>,
    full_reason: Option<FullCaptureReason>,
}
impl CompletedCandidate {
    pub(crate) fn receipt(&self) -> &RamCaptureReceipt {
        &self.receipt
    }
    pub(crate) fn shared_receipt(&self) -> Arc<RamCaptureReceipt> {
        self.receipt.clone()
    }
    pub(crate) fn full_reason(&self) -> Option<FullCaptureReason> {
        self.full_reason
    }
    pub(crate) fn memory_generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn seal(
        &self,
        ram: File,
        layout: File,
        authentication: RamInputAuthority,
    ) -> Result<Arc<AdmittedRamImage>, RamImageError> {
        image::seal_completed(&self.receipt, ram, layout, authentication).map(Arc::new)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreInstallationEvidence {
    pub tracking_before_install: bool,
    pub complete: bool,
    pub dirty_pages: usize,
}

pub struct MemoryCoordinator {
    pub(crate) control: DomainControl,
    pub(crate) construction: Option<ConstructionAuthority>,
    pending: Option<DirtyPageMap>,
    identity_dirty: Option<DirtyPageMap>,
    identity_anchor: RamIdentityAnchor,
    identity_anchor_generation: RamIdentityGeneration,
    key: Option<BarrierKey>,
    pause: Option<PauseToken>,
    closing: Option<ClosingMemory>,
    drained: Option<DrainedMemory>,
    native: Option<Arc<NativeEffectsPermit>>,
    cut: Option<MemoryCut>,
    next: Option<CpuTrackingEpoch>,
    tracker: TrackerIdentity,
    baseline: Option<AcceptedBaseline>,
    attempt: Option<CaptureAttempt>,
    next_attempt: u64,
    next_memory_generation: u64,
    tracking_failure: Option<DirtyFailure>,
    layout: OnceLock<Arc<ValidatedRamLayout>>,
    scratch: Option<RamIoScratch>,
    restore_installation: Option<RestoreInstallationEvidence>,
}
impl MemoryCoordinator {
    pub(crate) fn has_closing(&self) -> bool {
        self.closing.is_some()
    }
    pub(crate) fn has_attempt(&self) -> bool {
        self.attempt.is_some()
    }
    pub(crate) fn pending_dirty_count(&self) -> usize {
        self.pending.as_ref().map_or(0, DirtyPageMap::count)
    }
    pub(crate) fn baseline_token(&self) -> Option<BaselineToken> {
        self.baseline.as_ref().map(|baseline| {
            let mut token = baseline.token.clone();
            if !self.control.domain().coverage_valid() {
                token.identity_anchor = RamIdentityAnchor::Unknown;
                token.identity_anchor_generation = RamIdentityGeneration::Unknown;
            }
            token
        })
    }
    pub(crate) fn restore_installation(&self) -> Option<RestoreInstallationEvidence> {
        self.restore_installation
    }
    #[cfg(any(
        test,
        all(
            not(any(feature = "tee", feature = "aws-nitro")),
            any(
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ),
                all(target_os = "macos", target_arch = "aarch64")
            )
        )
    ))]
    pub(crate) fn observe_restore_install_begin(&mut self) -> Result<(), MemoryError> {
        if self.restore_installation.is_some()
            || self.control.domain().tracking_mode() != Some(TrackingMode::Capture)
            || self.control.domain().backing_kind()
                != arch::guest_memory::BackingKind::RestoredPrivate
        {
            return Err(MemoryError::State);
        }
        self.restore_installation = Some(RestoreInstallationEvidence {
            tracking_before_install: true,
            complete: false,
            dirty_pages: 0,
        });
        Ok(())
    }
    #[cfg(any(
        test,
        all(
            not(any(feature = "tee", feature = "aws-nitro")),
            any(
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ),
                all(target_os = "macos", target_arch = "aarch64")
            )
        )
    ))]
    pub(crate) fn observe_restore_install_complete(&mut self) -> Result<(), MemoryError> {
        let dirty_pages = self.pending_dirty_count();
        let evidence = self
            .restore_installation
            .as_mut()
            .ok_or(MemoryError::State)?;
        if evidence.complete || self.cut.is_none() || self.next.is_none() {
            return Err(MemoryError::State);
        }
        evidence.dirty_pages = dirty_pages;
        evidence.complete = true;
        Ok(())
    }
    pub(crate) fn protects_output(&self, device: u64, inode: u64) -> Result<bool, std::io::Error> {
        if self
            .baseline
            .as_ref()
            .is_some_and(|baseline| baseline.image.aliases(device, inode))
        {
            return Ok(true);
        }
        for identity in self.control.domain().file_backing_identities() {
            let identity = identity?;
            if identity.device == device && identity.inode == inode {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn new(control: DomainControl, construction: ConstructionAuthority) -> Self {
        Self {
            control,
            construction: Some(construction),
            pending: None,
            identity_dirty: None,
            identity_anchor: RamIdentityAnchor::Unknown,
            identity_anchor_generation: RamIdentityGeneration::Unknown,
            key: None,
            pause: None,
            closing: None,
            drained: None,
            native: None,
            cut: None,
            next: None,
            tracker: TrackerIdentity(Arc::new(())),
            baseline: None,
            attempt: None,
            next_attempt: 1,
            next_memory_generation: 1,
            tracking_failure: None,
            layout: OnceLock::new(),
            scratch: None,
            restore_installation: None,
        }
    }
    pub(crate) fn finish_untracked(&mut self) -> Result<(), MemoryError> {
        self.control
            .finish_untracked(self.construction.take().ok_or(MemoryError::State)?)
    }
    #[cfg(not(feature = "tee"))]
    pub(crate) fn finish_tracked(&mut self, epoch: CpuTrackingEpoch) -> Result<(), MemoryError> {
        self.control
            .finish_tracked(self.construction.take().ok_or(MemoryError::State)?, epoch)?;
        self.pending = Some(DirtyPageMap::new(self.control.domain().layout()));
        self.identity_dirty = Some(DirtyPageMap::new(self.control.domain().layout()));
        Ok(())
    }
    #[cfg(not(feature = "tee"))]
    pub(crate) fn seed_restored(
        &mut self,
        image: Arc<AdmittedRamImage>,
    ) -> Result<(), MemoryError> {
        if self.baseline.is_some()
            || self.pending.is_none()
            || self.next_memory_generation != 1
            || self.control.domain().backing_kind()
                != arch::guest_memory::BackingKind::RestoredPrivate
        {
            return Err(MemoryError::State);
        }
        image
            .layout()
            .validate_registered(self.control.domain().layout())
            .map_err(|_| MemoryError::Geometry)?;
        self.layout
            .set(image.layout().clone())
            .map_err(|_| MemoryError::State)?;
        let generation = match image.authority() {
            RamInputAuthority::IdentifiedSnapshot(_) => 1,
            RamInputAuthority::OwnedLocalCut {
                materialization_generation,
                ..
            } => *materialization_generation,
        };
        let next_generation = generation.checked_add(1).ok_or(MemoryError::State)?;
        self.identity_anchor = image.authority().identity_anchor();
        self.identity_anchor_generation = match self.identity_anchor {
            RamIdentityAnchor::Unknown => RamIdentityGeneration::Unknown,
            RamIdentityAnchor::Identified { .. } => RamIdentityGeneration::Identified {
                generation: NonZeroU64::MIN,
            },
        };
        self.baseline = Some(AcceptedBaseline {
            token: BaselineToken {
                tracker: self.tracker.clone(),
                topology: self.control.domain().topology_generation(),
                memory_generation: generation,
                identity_anchor: self.identity_anchor,
                identity_anchor_generation: self.identity_anchor_generation,
            },
            image,
        });
        self.next_memory_generation = next_generation;
        Ok(())
    }
    pub(crate) fn begin_close(&mut self, key: BarrierKey) -> Result<(), MemoryError> {
        if self.key.is_some_and(|current| current != key) {
            return Err(MemoryError::Authority);
        }
        if self.key.is_none() {
            self.closing = Some(self.control.close()?);
            self.key = Some(key);
        }
        Ok(())
    }
    pub(crate) fn poll_drained(&mut self) -> Poll<Result<(), MemoryError>> {
        if self.drained.is_some() {
            return Poll::Ready(Ok(()));
        }
        let Some(closing) = self.closing.as_ref() else {
            return Poll::Ready(Err(MemoryError::State));
        };
        match self.control.poll_drained(closing) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(drained)) => {
                match self.control.native_effects(&drained) {
                    Ok(permit) => self.native = Some(Arc::new(permit)),
                    Err(error) => return Poll::Ready(Err(error)),
                }
                self.drained = Some(drained);
                Poll::Ready(Ok(()))
            }
        }
    }
    pub(crate) fn native(&self) -> Result<Arc<NativeEffectsPermit>, String> {
        self.native
            .clone()
            .ok_or("native memory authority absent".into())
    }
    pub(crate) fn begin_runtime_native(&mut self) -> Result<(), MemoryError> {
        if self.native.is_none() {
            self.native = Some(Arc::new(self.control.runtime_native_effects()?));
        }
        Ok(())
    }
    pub(crate) fn retire_native(&mut self) {
        self.native = None;
    }
    pub(crate) fn bind_pause(
        &mut self,
        key: BarrierKey,
        pause: &PauseToken,
    ) -> Result<(), MemoryError> {
        self.validate_ready(key)?;
        self.pause = Some(pause.clone());
        Ok(())
    }
    fn validate_ready(&self, key: BarrierKey) -> Result<(), MemoryError> {
        if self.key != Some(key) {
            return Err(MemoryError::Authority);
        }
        self.control.validate_epoch(
            self.cut.as_ref().ok_or(MemoryError::State)?,
            self.next.as_ref().ok_or(MemoryError::State)?,
        )
    }
    #[cfg(not(feature = "tee"))]
    fn finish_tracking_recovery(
        &mut self,
        key: BarrierKey,
        next: CpuTrackingEpoch,
    ) -> Result<(), MemoryError> {
        if self.key != Some(key)
            || self.has_attempt()
            || self
                .tracking_failure
                .as_ref()
                .is_none_or(|failure| failure.effect == DirtyEffect::PreEffectRefusal)
        {
            return Err(MemoryError::Authority);
        }
        self.control
            .validate_epoch(self.cut.as_ref().ok_or(MemoryError::State)?, &next)?;
        self.next = Some(next);
        self.tracking_failure = None;
        Ok(())
    }
    pub(crate) fn reopen(&mut self, key: BarrierKey) -> Result<(), ControlFailure> {
        if self.has_attempt() {
            return Err(ControlFailure::Busy);
        }
        self.validate_ready(key).map_err(ControlFailure::Memory)?;
        self.control
            .reopen(
                self.cut
                    .as_ref()
                    .ok_or(ControlFailure::Memory(MemoryError::State))?,
                self.next
                    .as_ref()
                    .ok_or(ControlFailure::Memory(MemoryError::State))?,
            )
            .map_err(ControlFailure::Memory)?;
        self.cut = None;
        self.next = None;
        self.key = None;
        self.pause = None;
        self.closing = None;
        self.drained = None;
        self.tracking_failure = None;
        Ok(())
    }
    fn begin_attempt(
        &mut self,
        key: BarrierKey,
        request: RamCaptureRequest<'_>,
        identity_policy: RamIdentityPolicy,
        binding: StateBinding,
        layout: Arc<ValidatedRamLayout>,
    ) -> Result<AttemptId, CaptureError> {
        if self.has_attempt() {
            return Err(CaptureError::Busy);
        }
        self.validate_ready(key)?;
        let next_attempt = self
            .next_attempt
            .checked_add(1)
            .ok_or(CaptureError::Exhausted)?;
        let next_generation = self
            .next_memory_generation
            .checked_add(1)
            .ok_or(CaptureError::Exhausted)?;
        let pending = self.pending.as_ref().ok_or(MemoryError::State)?;
        if let RamIdentityPolicy::SinceAnchor { stream } = identity_policy
            && (self.identity_anchor != (RamIdentityAnchor::Identified { stream })
                || !self.control.domain().coverage_valid())
        {
            return Err(CaptureError::InvalidCandidate);
        }
        // Harvest before writing so failed and abandoned attempts retain complete identity coverage.
        self.identity_dirty
            .as_mut()
            .ok_or(MemoryError::State)?
            .merge(pending)?;
        let full_reason = select_full(
            request,
            self.baseline.as_ref().map(|baseline| &baseline.token),
            self.control.domain().coverage_valid(),
            pending.count(),
            pending.page_count(),
        );
        if self.scratch.is_none() {
            self.scratch = Some(RamIoScratch::new()?);
        }
        let id = AttemptId {
            tracker: self.tracker.clone(),
            sequence: self.next_attempt,
        };
        self.attempt = Some(CaptureAttempt {
            id: id.clone(),
            key,
            generation: self.next_memory_generation,
            cut_generation: self.cut.as_ref().ok_or(MemoryError::State)?.generation(),
            topology: self.control.domain().topology_generation(),
            binding,
            layout,
            full_reason,
            identity_policy,
            state: AttemptState::Writing,
            failure: None,
        });
        self.next_attempt = next_attempt;
        self.next_memory_generation = next_generation;
        Ok(id)
    }
    fn write_attempt(
        &mut self,
        key: BarrierKey,
        id: &AttemptId,
        mut output: RamOutputFiles,
        deadline: Instant,
    ) -> Result<CompletedCandidate, CaptureError> {
        self.validate_ready(key)?;
        let attempt = self
            .attempt
            .as_mut()
            .filter(|attempt| {
                attempt.id == *id && attempt.key == key && attempt.state == AttemptState::Writing
            })
            .ok_or(CaptureError::InvalidAttempt)?;
        let cut = self.cut.as_ref().ok_or(MemoryError::State)?;
        output.protect_baseline(
            self.baseline
                .as_ref()
                .map(|baseline| baseline.image.clone()),
        );
        let mode = if attempt.full_reason.is_some() {
            RamWriteMode::Full
        } else {
            RamWriteMode::Incremental {
                baseline: &self
                    .baseline
                    .as_ref()
                    .ok_or(CaptureError::InvalidAttempt)?
                    .image,
                dirty: self.pending.as_ref().ok_or(MemoryError::State)?,
            }
        };
        let identity = RamCaptureIdentity {
            selection: match attempt.identity_policy {
                RamIdentityPolicy::None => RamHashSelection::None,
                RamIdentityPolicy::Full => RamHashSelection::Full,
                RamIdentityPolicy::SinceAnchor { stream } => RamHashSelection::SinceAnchor {
                    stream,
                    dirty: self.identity_dirty.as_ref().ok_or(MemoryError::State)?,
                },
            },
            anchor: if self.control.domain().coverage_valid() {
                self.identity_anchor
            } else {
                RamIdentityAnchor::Unknown
            },
            anchor_generation: if self.control.domain().coverage_valid() {
                self.identity_anchor_generation
            } else {
                RamIdentityGeneration::Unknown
            },
            predecessor_generation: self
                .baseline
                .as_ref()
                .map_or(0, |baseline| baseline.token.memory_generation),
            identity_dirty_pages: self
                .identity_dirty
                .as_ref()
                .ok_or(MemoryError::State)?
                .count(),
            materialization_dirty_pages: self.pending.as_ref().ok_or(MemoryError::State)?.count(),
            byte_baseline: self
                .baseline
                .as_ref()
                .zip(self.pending.as_ref())
                .map(|(baseline, dirty)| (baseline.image.as_ref(), dirty)),
        };
        match image::writer::write_ram_image(
            id.clone(),
            key,
            cut,
            &attempt.binding,
            attempt.layout.clone(),
            identity,
            mode,
            output,
            self.scratch.as_mut().ok_or(MemoryError::State)?,
            deadline,
        ) {
            Ok(receipt) => {
                attempt.state = AttemptState::Completed;
                Ok(CompletedCandidate {
                    id: id.clone(),
                    generation: attempt.generation,
                    receipt: Arc::new(receipt),
                    full_reason: attempt.full_reason,
                })
            }
            Err(failure) => {
                let failure = Arc::new(failure);
                attempt.state = AttemptState::Failed;
                attempt.failure = Some(failure.clone());
                Err(CaptureError::Write(failure))
            }
        }
    }
    fn accept_attempt(
        &mut self,
        key: BarrierKey,
        candidate: CompletedCandidate,
        image: Arc<AdmittedRamImage>,
    ) -> Result<BaselineToken, CaptureError> {
        self.validate_ready(key)?;
        let attempt = self
            .attempt
            .as_ref()
            .filter(|attempt| {
                attempt.id == candidate.id
                    && attempt.key == key
                    && attempt.state == AttemptState::Completed
            })
            .ok_or(CaptureError::InvalidCandidate)?;
        let cut = self.cut.as_ref().ok_or(MemoryError::State)?;
        if attempt.cut_generation != cut.generation()
            || attempt.topology != self.control.domain().topology_generation()
        {
            return Err(CaptureError::InvalidCandidate);
        }
        candidate.receipt.matches(
            &attempt.id,
            key,
            cut,
            &attempt.binding,
            &attempt.layout,
            &image,
        )?;
        if !self.control.domain().coverage_valid()
            && candidate.receipt.mode() != RamCaptureMode::Full
        {
            return Err(CaptureError::InvalidCandidate);
        }
        if self.pending.is_none() {
            return Err(MemoryError::State.into());
        }
        match (attempt.identity_policy, image.authority()) {
            (
                RamIdentityPolicy::None,
                RamInputAuthority::OwnedLocalCut {
                    materialization_generation,
                    ..
                },
            ) if *materialization_generation == attempt.generation => {}
            (
                RamIdentityPolicy::Full | RamIdentityPolicy::SinceAnchor { .. },
                RamInputAuthority::IdentifiedSnapshot(_),
            ) => {}
            _ => return Err(CaptureError::InvalidCandidate),
        }
        let anchor = match image.authority() {
            RamInputAuthority::IdentifiedSnapshot(authentication) => {
                RamIdentityAnchor::Identified {
                    stream: authentication.stream,
                }
            }
            RamInputAuthority::OwnedLocalCut { .. } if !self.control.domain().coverage_valid() => {
                RamIdentityAnchor::Unknown
            }
            RamInputAuthority::OwnedLocalCut { .. } => self.identity_anchor,
        };
        let anchor_generation = match image.authority() {
            RamInputAuthority::IdentifiedSnapshot(_) => RamIdentityGeneration::Identified {
                generation: NonZeroU64::new(attempt.generation).ok_or(CaptureError::Exhausted)?,
            },
            RamInputAuthority::OwnedLocalCut { .. } if anchor == RamIdentityAnchor::Unknown => {
                RamIdentityGeneration::Unknown
            }
            RamInputAuthority::OwnedLocalCut { .. } => self.identity_anchor_generation,
        };
        let token = BaselineToken {
            tracker: self.tracker.clone(),
            topology: attempt.topology,
            memory_generation: attempt.generation,
            identity_anchor: anchor,
            identity_anchor_generation: anchor_generation,
        };
        if candidate.receipt.mode() == RamCaptureMode::Full {
            self.control
                .restore_coverage(cut, self.next.as_ref().ok_or(MemoryError::State)?)?;
        }
        if matches!(image.authority(), RamInputAuthority::IdentifiedSnapshot(_)) {
            self.identity_dirty
                .as_mut()
                .ok_or(MemoryError::State)?
                .clear();
        }
        self.identity_anchor = anchor;
        self.identity_anchor_generation = anchor_generation;
        self.pending.as_mut().ok_or(MemoryError::State)?.clear();
        self.baseline = Some(AcceptedBaseline {
            token: token.clone(),
            image,
        });
        self.attempt = None;
        self.tracking_failure = None;
        Ok(token)
    }
    fn abandon_attempt(&mut self, key: BarrierKey, id: &AttemptId) -> Result<(), CaptureError> {
        self.validate_ready(key)?;
        if !self
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.id == *id && attempt.key == key)
        {
            return Err(CaptureError::InvalidAttempt);
        }
        self.attempt = None;
        Ok(())
    }
}

fn select_full(
    request: RamCaptureRequest<'_>,
    accepted: Option<&BaselineToken>,
    coverage_valid: bool,
    dirty: usize,
    total: usize,
) -> Option<FullCaptureReason> {
    match request {
        RamCaptureRequest::Full => Some(FullCaptureReason::Requested),
        RamCaptureRequest::Incremental {
            baseline,
            crossover,
        } => {
            if accepted.is_none() {
                Some(FullCaptureReason::NoBaseline)
            } else if !coverage_valid {
                Some(FullCaptureReason::CoverageLost)
            } else if baseline.is_none() || baseline != accepted {
                Some(FullCaptureReason::BaselineToken)
            } else if (dirty as u128) * 100 >= (total as u128) * u128::from(crossover.0) {
                Some(FullCaptureReason::DirtyCrossover)
            } else {
                None
            }
        }
    }
}

impl Vmm {
    pub(crate) fn memory_layout(&self) -> Result<Arc<ValidatedRamLayout>, RamImageError> {
        if self.memory_domain.tracking_mode() != Some(TrackingMode::Capture) {
            return Err(RamImageError::Authority(MemoryError::State));
        }
        let lane = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            ExecutionLane::KvmX86
        } else if cfg!(target_os = "linux") {
            ExecutionLane::KvmArm64
        } else {
            ExecutionLane::HvfArm64
        };
        if let Some(layout) = self.memory.layout.get() {
            layout.validate_source(self.memory_domain.layout(), &self.arch_memory_info, lane)?;
            return Ok(layout.clone());
        }
        let layout = Arc::new(ValidatedRamLayout::from_registered(
            self.memory_domain.layout(),
            &self.arch_memory_info,
            lane,
        )?);
        let _ = self.memory.layout.set(layout.clone());
        Ok(self.memory.layout.get().cloned().unwrap_or(layout))
    }
    pub(crate) fn baseline_token(&self) -> Option<BaselineToken> {
        self.memory.baseline_token()
    }
    fn paused_memory_key(&self, token: &PauseToken) -> Result<BarrierKey, CaptureError> {
        if !matches!(&self.control.state, ControlState::Paused(current) if current == token)
            || self.memory.pause.as_ref() != Some(token)
        {
            return Err(CaptureError::InvalidPause);
        }
        let key = self.memory.key.ok_or(CaptureError::InvalidPause)?;
        self.memory.validate_ready(key)?;
        Ok(key)
    }
    fn memory_capture_binding(
        &self,
        key: BarrierKey,
        layout: &ValidatedRamLayout,
    ) -> Result<&StateBinding, CaptureError> {
        if self.execution.failed_install
            || !self.control.cpus.reconciled()
            || !self
                .execution
                .retained
                .as_ref()
                .is_some_and(|cut| cut.key == key)
        {
            return Err(CaptureError::Execution);
        }
        let envelope = self
            .execution
            .envelope
            .as_ref()
            .ok_or(CaptureError::Execution)?;
        if envelope.page_granule != self.memory_domain.layout().granule()
            || envelope.memory_regions.len() != self.memory_domain.layout().regions().len()
            || envelope
                .memory_regions
                .iter()
                .zip(self.memory_domain.layout().regions())
                .any(|(saved, actual)| *saved != actual.guest_range())
            || envelope.binding.pause_generation != key.generation.0
            || self.execution.binding.as_ref() != Some(&envelope.binding)
            || self
                .memory
                .layout
                .get()
                .is_none_or(|prepared| prepared.canonical_bytes() != layout.canonical_bytes())
        {
            return Err(CaptureError::Execution);
        }
        Ok(&envelope.binding)
    }
    fn validate_attempt_binding(
        &self,
        key: BarrierKey,
        id: &AttemptId,
    ) -> Result<(), CaptureError> {
        let attempt = self
            .memory
            .attempt
            .as_ref()
            .filter(|attempt| attempt.id == *id && attempt.key == key)
            .ok_or(CaptureError::InvalidAttempt)?;
        let layout = self.memory_layout()?;
        if self.memory_capture_binding(key, &layout)? != &attempt.binding {
            return Err(CaptureError::Execution);
        }
        Ok(())
    }
    pub(crate) fn begin_memory_capture(
        &mut self,
        pause: &PauseToken,
        request: RamCaptureRequest<'_>,
        identity_policy: RamIdentityPolicy,
    ) -> Result<AttemptId, CaptureError> {
        let key = self.paused_memory_key(pause)?;
        let layout = self.memory_layout()?;
        let binding = self.memory_capture_binding(key, &layout)?.clone();
        self.memory
            .begin_attempt(key, request, identity_policy, binding, layout)
    }
    pub(crate) fn write_memory_capture(
        &mut self,
        pause: &PauseToken,
        attempt: &AttemptId,
        output: RamOutputFiles,
        deadline: Instant,
    ) -> Result<CompletedCandidate, CaptureError> {
        let key = self.paused_memory_key(pause)?;
        self.validate_attempt_binding(key, attempt)?;
        self.memory.write_attempt(key, attempt, output, deadline)
    }
    pub(crate) fn accept_memory(
        &mut self,
        pause: &PauseToken,
        candidate: CompletedCandidate,
        image: Arc<AdmittedRamImage>,
    ) -> Result<BaselineToken, CaptureError> {
        let key = self.paused_memory_key(pause)?;
        self.validate_attempt_binding(key, &candidate.id)?;
        self.memory.accept_attempt(key, candidate, image)
    }
    pub(crate) fn abandon_memory(
        &mut self,
        pause: &PauseToken,
        attempt: &AttemptId,
    ) -> Result<(), CaptureError> {
        let key = self.paused_memory_key(pause)?;
        self.memory.abandon_attempt(key, attempt)
    }
    #[cfg(any(feature = "native-execution-probe", feature = "native-device-probe"))]
    fn diagnostic_memory_key(&self, key: BarrierKey) -> Result<(), CaptureError> {
        if self.execution.failed_install || !self.control.cpus.reconciled() {
            return Err(CaptureError::Execution);
        }
        let prepared = matches!(self.control.state, ControlState::RestorePrepared { key: current } if current == key)
            && !self.control.cpus.release_may_have_run();
        let fixture = cfg!(feature = "native-execution-probe")
            && !self.mmio_device_manager.quiescence.has_transports()
            && self
                .mmio_device_manager
                .quiescence
                .legacy_attachments()
                .is_empty()
            && self.control.cpus.captured_at(key);
        if !prepared && !fixture {
            return Err(CaptureError::InvalidPause);
        }
        self.memory.validate_ready(key)?;
        Ok(())
    }
    #[cfg(any(feature = "native-execution-probe", feature = "native-device-probe"))]
    pub(crate) fn diagnostic_begin_memory_capture(
        &mut self,
        key: BarrierKey,
        request: RamCaptureRequest<'_>,
        identity_policy: RamIdentityPolicy,
    ) -> Result<AttemptId, CaptureError> {
        self.diagnostic_memory_key(key)?;
        let layout = self.memory_layout()?;
        let binding = self.memory_capture_binding(key, &layout)?.clone();
        self.memory
            .begin_attempt(key, request, identity_policy, binding, layout)
    }
    #[cfg(any(feature = "native-execution-probe", feature = "native-device-probe"))]
    pub(crate) fn diagnostic_write_memory_capture(
        &mut self,
        key: BarrierKey,
        attempt: &AttemptId,
        output: RamOutputFiles,
        deadline: Instant,
    ) -> Result<CompletedCandidate, CaptureError> {
        self.diagnostic_memory_key(key)?;
        self.validate_attempt_binding(key, attempt)?;
        self.memory.write_attempt(key, attempt, output, deadline)
    }
    #[cfg(any(feature = "native-execution-probe", feature = "native-device-probe"))]
    pub(crate) fn diagnostic_accept_memory(
        &mut self,
        key: BarrierKey,
        candidate: CompletedCandidate,
        image: Arc<AdmittedRamImage>,
    ) -> Result<BaselineToken, CaptureError> {
        self.diagnostic_memory_key(key)?;
        self.validate_attempt_binding(key, &candidate.id)?;
        self.memory.accept_attempt(key, candidate, image)
    }
    #[cfg(any(feature = "native-execution-probe", feature = "native-device-probe"))]
    pub(crate) fn diagnostic_abandon_memory(
        &mut self,
        key: BarrierKey,
        attempt: &AttemptId,
    ) -> Result<(), CaptureError> {
        self.diagnostic_memory_key(key)?;
        self.memory.abandon_attempt(key, attempt)
    }
    #[cfg(any(feature = "native-execution-probe", feature = "native-device-probe"))]
    pub(crate) fn diagnostic_memory_dirty_pages(
        &self,
        key: BarrierKey,
    ) -> Result<&DirtyPageMap, CaptureError> {
        self.diagnostic_memory_key(key)?;
        self.memory
            .pending
            .as_ref()
            .ok_or(CaptureError::Memory(MemoryError::State))
    }
    pub fn memory_dirty_pages(&self, token: &PauseToken) -> Result<&DirtyPageMap, String> {
        self.paused_memory_key(token)
            .map_err(|error| error.to_string())?;
        self.memory
            .pending
            .as_ref()
            .ok_or("memory tracking disabled".into())
    }
    pub(crate) fn finalize_source_memory(
        &mut self,
        structural_lane: bool,
    ) -> Result<(), crate::vmm::Error> {
        #[cfg(not(feature = "tee"))]
        {
            use crate::vmm::device_manager::quiescence::ManagerFault;
            use devices::virtio::lifecycle::ProviderFault;
            let mut eligible = structural_lane
                && !self.memory_domain.external_mapping_exported()
                && self.memory_domain.layout().validate_capture().is_ok()
                && cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));
            if eligible {
                let controller = self.execution_controller.try_lock().map_err(|error| {
                    crate::vmm::Error::Control(ControlFailure::Participant(error.to_string()))
                })?;
                eligible = controller.execution_state_supported();
            }
            if eligible {
                match self.mmio_device_manager.preflight_quiesce() {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.fault,
                            ManagerFault::Provider(ProviderFault::Unsupported)
                                | ManagerFault::MissingLegacyProvider(_)
                        ) =>
                    {
                        eligible = false
                    }
                    Err(error) => {
                        return Err(crate::vmm::Error::Control(ControlFailure::Participant(
                            error.to_string(),
                        )));
                    }
                }
            }
            if eligible {
                let epoch = self
                    .vm
                    .arm_initial(
                        self.memory
                            .construction
                            .as_ref()
                            .ok_or(crate::vmm::Error::Memory(MemoryError::State))?,
                    )
                    .map_err(crate::vmm::Error::DirtyMemory)?;
                return self
                    .memory
                    .finish_tracked(epoch)
                    .map_err(crate::vmm::Error::Memory);
            }
        }
        #[cfg(feature = "tee")]
        let _ = structural_lane;
        self.memory
            .finish_untracked()
            .map_err(crate::vmm::Error::Memory)
    }
    #[cfg(not(feature = "tee"))]
    pub(crate) fn finish_memory_cut(&mut self, key: BarrierKey) -> Result<bool, ControlFailure> {
        if self.memory.key != Some(key) {
            return Err(ControlFailure::Memory(MemoryError::Authority));
        }
        if let Some(failure) = self.memory.tracking_failure {
            return Err(ControlFailure::DirtyMemory(failure));
        }
        if self.memory.cut.is_some() {
            return self
                .memory
                .validate_ready(key)
                .map(|()| true)
                .map_err(ControlFailure::Memory);
        }
        if !self.control.cpus.reconciled() {
            return Ok(false);
        }
        self.memory.retire_native();
        let drained = self
            .memory
            .drained
            .as_ref()
            .ok_or(ControlFailure::Memory(MemoryError::State))?;
        match self.memory.control.poll_native_drained(drained) {
            Poll::Pending => return Ok(false),
            Poll::Ready(result) => result.map_err(ControlFailure::Memory)?,
        }
        let cut = self
            .memory
            .control
            .seal(drained)
            .map_err(ControlFailure::Memory)?;
        self.memory.cut = Some(cut);
        let cut = self
            .memory
            .cut
            .as_ref()
            .ok_or(ControlFailure::Memory(MemoryError::State))?;
        let pending = self
            .memory
            .pending
            .as_mut()
            .ok_or(ControlFailure::Memory(MemoryError::State))?;
        self.memory
            .control
            .drain_host_dirty(cut, pending)
            .map_err(ControlFailure::Memory)?;
        let next = self
            .vm
            .collect_cpu_dirty(cut, pending)
            .and_then(|harvest| self.vm.rearm_cpu_dirty(cut, harvest));
        match next {
            Ok(next) => {
                self.memory.next = Some(next);
                Ok(true)
            }
            Err(error) => {
                if error.effect != DirtyEffect::PreEffectRefusal {
                    self.memory_domain.invalidate_coverage();
                }
                self.memory.tracking_failure = Some(error);
                Err(ControlFailure::DirtyMemory(error))
            }
        }
    }
    #[cfg(feature = "tee")]
    pub(crate) fn finish_memory_cut(&mut self, _key: BarrierKey) -> Result<bool, ControlFailure> {
        Err(ControlFailure::Unsupported(
            "tracked memory is unsupported for confidential VMs".into(),
        ))
    }
    #[cfg(not(feature = "tee"))]
    pub(crate) fn recover_memory_cut(&mut self, key: BarrierKey) -> Result<bool, CaptureError> {
        let failure = self
            .memory
            .tracking_failure
            .ok_or(CaptureError::InvalidAttempt)?;
        if failure.effect == DirtyEffect::PreEffectRefusal
            || self.execution.failed_install
            || self.memory.has_attempt()
            || !self.control.cpus.reconciled()
            || !self.control.cpus.captured_at(key)
            || !matches!(self.control.state, ControlState::Pausing { key: current, failed: true } if current == key)
            || !self
                .execution
                .retained
                .as_ref()
                .is_some_and(|cut| cut.key == key)
        {
            return Err(CaptureError::Execution);
        }
        let active = self
            .control
            .active
            .as_ref()
            .filter(|active| {
                active.original == key
                    && active.phase == crate::vmm::control::Phase::Cut
                    && active.failed
            })
            .ok_or(CaptureError::Execution)?;
        let owner = active.owner;
        if self.memory.key != Some(key) {
            return Err(CaptureError::InvalidAttempt);
        }
        let cut = self.memory.cut.as_ref().ok_or(MemoryError::State)?;
        self.memory.control.validate_cut(cut)?;
        let pending = self.memory.pending.as_mut().ok_or(MemoryError::State)?;
        let next = self
            .vm
            .reestablish_cpu_dirty(cut, pending)
            .map_err(|error| {
                self.memory.tracking_failure = Some(error);
                CaptureError::Tracking(error)
            })?;
        self.memory.finish_tracking_recovery(key, next)?;
        let token = self.control.token(key, owner);
        self.memory.bind_pause(key, &token)?;
        self.control.state = ControlState::Paused(token);
        if let Some(active) = self.control.active.as_mut() {
            active.failed = false;
        }
        Ok(true)
    }
    #[cfg(all(
        feature = "native-device-probe",
        not(feature = "tee"),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(crate) fn diagnostic_fail_next_memory_harvest(&mut self) -> Result<u32, CaptureError> {
        if self.control.state != ControlState::Running
            || self.control.active.is_some()
            || self.execution.failed_install
            || self.memory.has_attempt()
            || self.memory.has_closing()
            || self.memory_domain.tracking_mode() != Some(TrackingMode::Capture)
        {
            return Err(CaptureError::Execution);
        }
        let permit = self.memory.control.runtime_native_effects()?;
        self.vm
            .arm_cpu_dirty_get_fault(&permit)
            .map_err(CaptureError::Tracking)
    }
    #[cfg(all(
        feature = "native-device-probe",
        not(feature = "tee"),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(crate) fn diagnostic_recover_memory_cut(&mut self) -> Result<PauseToken, CaptureError> {
        let key = match self.control.state {
            ControlState::Pausing { key, failed: true } => key,
            _ => return Err(CaptureError::InvalidPause),
        };
        self.recover_memory_cut(key)?;
        self.memory.pause.clone().ok_or(CaptureError::InvalidPause)
    }
    #[cfg(all(
        feature = "native-device-probe",
        not(feature = "tee"),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(crate) fn diagnostic_memory_recovery_observation(
        &self,
    ) -> Option<&crate::vmm::linux::vstate::CpuDirtyRecoveryObservation> {
        self.vm.cpu_dirty_recovery_observation()
    }
    #[cfg(all(
        feature = "native-device-probe",
        not(feature = "tee"),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(crate) fn diagnostic_memory_coverage_valid(&self) -> bool {
        self.memory_domain.coverage_valid()
    }
    #[cfg(all(
        feature = "native-device-probe",
        not(feature = "tee"),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(crate) fn diagnostic_memory_full_required(&self) -> bool {
        let token = self
            .memory
            .baseline
            .as_ref()
            .map(|baseline| &baseline.token);
        let Some(pending) = self.memory.pending.as_ref() else {
            return true;
        };
        select_full(
            RamCaptureRequest::Incremental {
                baseline: token,
                crossover: DirtyCrossoverPercent::default(),
            },
            token,
            self.memory_domain.coverage_valid(),
            pending.count(),
            pending.page_count(),
        )
        .is_some()
    }
    #[cfg(all(
        feature = "native-device-probe",
        not(feature = "tee"),
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(crate) fn diagnostic_memory_tracking_failure(&self) -> Option<DirtyFailure> {
        self.memory.tracking_failure
    }
    pub(crate) fn reopen_memory_for_resume(
        &mut self,
        key: BarrierKey,
    ) -> Result<bool, ControlFailure> {
        if self.memory.has_attempt() {
            return Err(ControlFailure::Busy);
        }
        if self.memory_domain.tracking_mode() != Some(TrackingMode::Capture) {
            return Err(ControlFailure::Memory(MemoryError::State));
        }
        if self.memory.key.is_some() {
            // Cancellation after an uncertain GET must restore actual tracking
            // before reopening writers. It does not restore coverage validity or
            // retire the pending union: the next accepted image must be full.
            #[cfg(not(feature = "tee"))]
            if self
                .memory
                .tracking_failure
                .as_ref()
                .is_some_and(|failure| failure.effect != DirtyEffect::PreEffectRefusal)
            {
                if self.memory.key != Some(key)
                    || !self.control.cpus.reconciled()
                    || !self.control.cpus.captured_at(key)
                    || !self
                        .execution
                        .retained
                        .as_ref()
                        .is_some_and(|cut| cut.key == key)
                {
                    return Err(ControlFailure::Memory(MemoryError::Authority));
                }
                let cut = self
                    .memory
                    .cut
                    .as_ref()
                    .ok_or(ControlFailure::Memory(MemoryError::State))?;
                self.memory
                    .control
                    .validate_cut(cut)
                    .map_err(ControlFailure::Memory)?;
                let pending = self
                    .memory
                    .pending
                    .as_mut()
                    .ok_or(ControlFailure::Memory(MemoryError::State))?;
                let next = self
                    .vm
                    .reestablish_cpu_dirty(cut, pending)
                    .map_err(ControlFailure::DirtyMemory)?;
                self.memory
                    .finish_tracking_recovery(key, next)
                    .map_err(ControlFailure::Memory)?;
            }
            if self.memory.next.is_none() && !self.finish_memory_cut(key)? {
                return Ok(false);
            }
            self.memory.reopen(key)?;
        }
        self.memory
            .begin_runtime_native()
            .map_err(ControlFailure::Memory)?;
        Ok(true)
    }
}

#[cfg(test)]
pub(crate) fn runtime_memory_for_test(
    memory: vm_memory::GuestMemoryMmap,
) -> devices::virtio::RuntimeGuestMemory {
    let (domain, construction, mut control) = arch::guest_memory::MemoryDomain::construct(
        memory,
        4096,
        arch::guest_memory::BackingKind::Boot,
    )
    .unwrap();
    control.finish_untracked(construction).unwrap();
    devices::virtio::RuntimeGuestMemory::new(domain)
}

#[cfg(all(test, not(feature = "tee"), target_arch = "x86_64"))]
mod tests {
    use crate::vmm::control::{
        BarrierGeneration, BarrierKey, ControlFailure, ControlOwner, ControlState, OperationId,
        PauseOwner,
    };
    use crate::vmm::execution::{ExecutionLane, StateBinding};
    use crate::vmm::memory::image::{
        AdmittedRamImage, RamCaptureMode, RamIdentityAnchor, RamIdentityPolicy,
        RamImageAuthentication, RamInputAuthority, RamOutputFiles, RamSeedMethod,
        ValidatedRamLayout,
    };
    use crate::vmm::memory::{
        BaselineToken, CaptureError, CompletedCandidate, DirtyCrossoverPercent, FullCaptureReason,
        MemoryCoordinator, RamCaptureRequest, TrackerIdentity, select_full,
    };
    use arch::ArchMemoryInfo;
    use arch::guest_memory::{BackingKind, MemoryDomain, PageIndex};
    use std::fs::File;
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant};
    use utils::tempfile::TempFile;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn key(generation: u64) -> BarrierKey {
        BarrierKey {
            operation: OperationId(generation),
            generation: BarrierGeneration(generation),
        }
    }
    fn binding(key: BarrierKey) -> StateBinding {
        StateBinding {
            live_state_schema: crate::api::capabilities::LIVE_STATE_SCHEMA.into(),
            architecture: crate::api::capabilities::guest_architecture().into(),
            profile: [2; 32],
            topology: [3; 32],
            ram_layout: [4; 32],
            source_run: [5; 16],
            pause_generation: key.generation.0,
            capture: [6; 16],
        }
    }
    fn coordinator() -> MemoryCoordinator {
        coordinator_with_backing(BackingKind::Boot)
    }
    fn coordinator_with_backing(backing: BackingKind) -> MemoryCoordinator {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 10 * 4096)]).unwrap();
        let (domain, authority, control) = MemoryDomain::construct(memory, 4096, backing).unwrap();
        let epoch = authority.issue_epoch(1).unwrap();
        let mut coordinator = MemoryCoordinator::new(control, authority);
        coordinator.finish_tracked(epoch).unwrap();
        assert!(coordinator.layout.get().is_none());
        assert!(domain.coverage_valid());
        coordinator
    }
    fn layout(coordinator: &MemoryCoordinator) -> Arc<ValidatedRamLayout> {
        let length = coordinator.control.domain().layout().page_count() as u64 * 4096;
        Arc::new(
            ValidatedRamLayout::from_registered(
                coordinator.control.domain().layout(),
                &ArchMemoryInfo {
                    ram_below_gap: length,
                    ram_above_gap: 0,
                    ram_last_addr: length,
                    shm_start_addr: 1 << 32,
                    page_size: 4096,
                    initrd_addr: length,
                    firmware_addr: 0,
                },
                ExecutionLane::KvmX86,
            )
            .unwrap(),
        )
    }
    fn stop(coordinator: &mut MemoryCoordinator, key: BarrierKey) {
        coordinator.begin_close(key).unwrap();
        assert!(matches!(coordinator.poll_drained(), Poll::Ready(Ok(()))));
        coordinator.retire_native();
        let cut = coordinator
            .control
            .seal(coordinator.drained.as_ref().unwrap())
            .unwrap();
        coordinator
            .control
            .drain_host_dirty(&cut, coordinator.pending.as_mut().unwrap())
            .unwrap();
        coordinator.next = Some(cut.issue_epoch(key.generation.0 + 1).unwrap());
        coordinator.cut = Some(cut);
    }
    struct Outputs {
        ram: TempFile,
        layout: TempFile,
        changes: TempFile,
    }
    impl Outputs {
        fn new() -> Self {
            Self {
                ram: TempFile::new().unwrap(),
                layout: TempFile::new().unwrap(),
                changes: TempFile::new().unwrap(),
            }
        }
        fn owned(&self) -> RamOutputFiles {
            RamOutputFiles::new(
                self.ram.as_file().try_clone().unwrap(),
                self.layout.as_file().try_clone().unwrap(),
                self.changes.as_file().try_clone().unwrap(),
            )
        }
        fn seal(
            &self,
            candidate: &mut CompletedCandidate,
            key: BarrierKey,
        ) -> Arc<AdmittedRamImage> {
            candidate
                .seal(
                    File::open(self.ram.as_path()).unwrap(),
                    File::open(self.layout.as_path()).unwrap(),
                    RamInputAuthority::IdentifiedSnapshot(RamImageAuthentication {
                        state: binding(key),
                        stream: [0; 32],
                    }),
                )
                .unwrap()
        }
    }
    fn begin(
        coordinator: &mut MemoryCoordinator,
        key: BarrierKey,
        request: RamCaptureRequest<'_>,
    ) -> crate::vmm::memory::AttemptId {
        let identity = match coordinator
            .baseline_token()
            .map(|token| token.identity_anchor())
        {
            Some(RamIdentityAnchor::Identified { stream })
                if !matches!(request, RamCaptureRequest::Full) =>
            {
                RamIdentityPolicy::SinceAnchor { stream }
            }
            _ => RamIdentityPolicy::Full,
        };
        coordinator
            .begin_attempt(key, request, identity, binding(key), layout(coordinator))
            .unwrap()
    }
    fn capture(
        coordinator: &mut MemoryCoordinator,
        key: BarrierKey,
        request: RamCaptureRequest<'_>,
    ) -> (crate::vmm::memory::AttemptId, CompletedCandidate, Outputs) {
        let id = begin(coordinator, key, request);
        let output = Outputs::new();
        let candidate = coordinator
            .write_attempt(
                key,
                &id,
                output.owned(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        (id, candidate, output)
    }
    fn accept_full(
        coordinator: &mut MemoryCoordinator,
        key: BarrierKey,
    ) -> (BaselineToken, Arc<AdmittedRamImage>, Outputs) {
        let (_, mut candidate, output) = capture(coordinator, key, RamCaptureRequest::Full);
        let image = output.seal(&mut candidate, key);
        let token = coordinator
            .accept_attempt(key, candidate, image.clone())
            .unwrap();
        (token, image, output)
    }

    #[test]
    fn crossover_is_exact_and_tokens_are_process_local() {
        let coordinator = coordinator();
        let token = BaselineToken {
            tracker: coordinator.tracker.clone(),
            topology: coordinator.control.domain().topology_generation(),
            memory_generation: 1,
            identity_anchor: RamIdentityAnchor::Unknown,
            identity_anchor_generation: crate::vmm::memory::image::RamIdentityGeneration::Unknown,
        };
        fn request(baseline: Option<&BaselineToken>) -> RamCaptureRequest<'_> {
            RamCaptureRequest::Incremental {
                baseline,
                crossover: DirtyCrossoverPercent::default(),
            }
        }
        assert_eq!(
            select_full(request(Some(&token)), Some(&token), true, 5, 10),
            None
        );
        assert_eq!(
            select_full(request(Some(&token)), Some(&token), true, 6, 10),
            Some(FullCaptureReason::DirtyCrossover)
        );
        assert_eq!(
            select_full(request(Some(&token)), Some(&token), true, 0, 10),
            None
        );
        assert_eq!(
            select_full(request(None), Some(&token), true, 0, 10),
            Some(FullCaptureReason::BaselineToken)
        );
        let mut stale = token.clone();
        stale.memory_generation += 1;
        assert_eq!(
            select_full(request(Some(&stale)), Some(&token), true, 0, 10),
            Some(FullCaptureReason::BaselineToken)
        );
        let mut foreign = token.clone();
        foreign.tracker = TrackerIdentity(Arc::new(()));
        assert_ne!(foreign, token);
        assert_eq!(
            select_full(request(Some(&foreign)), Some(&token), true, 0, 10),
            Some(FullCaptureReason::BaselineToken)
        );
        assert_eq!(
            select_full(request(Some(&token)), Some(&token), false, 0, 10),
            Some(FullCaptureReason::CoverageLost)
        );
        assert_eq!(
            select_full(request(Some(&token)), None, true, 0, 10),
            Some(FullCaptureReason::NoBaseline)
        );
        assert!(DirtyCrossoverPercent::new(0).is_err());
        assert!(DirtyCrossoverPercent::new(61).is_err());
        assert_eq!(
            select_full(
                RamCaptureRequest::Incremental {
                    baseline: Some(&token),
                    crossover: DirtyCrossoverPercent::new(10).unwrap()
                },
                Some(&token),
                true,
                1,
                10
            ),
            Some(FullCaptureReason::DirtyCrossover)
        );
    }

    #[test]
    fn unresolved_attempt_blocks_reopen_and_retains_exact_pause_and_dirties() {
        let mut coordinator = coordinator();
        drop(
            coordinator
                .control
                .domain()
                .write(GuestAddress(0), 1)
                .unwrap(),
        );
        let key = key(1);
        stop(&mut coordinator, key);
        let mut owner = ControlOwner::new(BarrierGeneration(1)).unwrap();
        let pause = owner.token(key, PauseOwner::Capture);
        owner.state = ControlState::Paused(pause.clone());
        coordinator.bind_pause(key, &pause).unwrap();
        let id = begin(&mut coordinator, key, RamCaptureRequest::Full);
        assert_eq!(coordinator.reopen(key), Err(ControlFailure::Busy));
        assert_eq!(
            owner.validate_memory_resume(&pause, coordinator.has_attempt()),
            Err(ControlFailure::Busy)
        );
        assert_eq!(coordinator.pause.as_ref(), Some(&pause));
        assert!(owner.validate_token(&pause));
        assert_eq!(coordinator.pending.as_ref().unwrap().count(), 1);
        assert!(matches!(
            coordinator.begin_attempt(
                key,
                RamCaptureRequest::Full,
                RamIdentityPolicy::Full,
                binding(key),
                layout(&coordinator)
            ),
            Err(CaptureError::Busy)
        ));
        let foreign = crate::vmm::memory::AttemptId::for_test();
        assert!(matches!(
            coordinator.abandon_attempt(key, &foreign),
            Err(CaptureError::InvalidAttempt)
        ));
        coordinator.abandon_attempt(key, &id).unwrap();
        assert_eq!(coordinator.pending.as_ref().unwrap().count(), 1);
        assert!(coordinator.abandon_attempt(key, &id).is_err());
        assert!(
            owner
                .validate_memory_resume(&pause, coordinator.has_attempt())
                .is_ok()
        );
        owner.state = ControlState::RestorePrepared { key };
        assert_eq!(owner.restore_release_key(true), Err(ControlFailure::Busy));
        assert_eq!(owner.state, ControlState::RestorePrepared { key });
        assert_eq!(owner.restore_release_key(false), Ok(key));
        coordinator.reopen(key).unwrap();
        assert!(
            coordinator
                .control
                .domain()
                .write(GuestAddress(0), 1)
                .is_ok()
        );
    }

    #[test]
    fn failed_write_requires_abandonment_and_keeps_all_following_epoch_writes() {
        let mut coordinator = coordinator();
        drop(
            coordinator
                .control
                .domain()
                .write(GuestAddress(0), 1)
                .unwrap(),
        );
        stop(&mut coordinator, key(1));
        let id = begin(&mut coordinator, key(1), RamCaptureRequest::Full);
        let output = Outputs::new();
        assert!(matches!(
            coordinator.write_attempt(key(1), &id, output.owned(), Instant::now()),
            Err(CaptureError::Write(_))
        ));
        assert!(coordinator.attempt.as_ref().unwrap().failure.is_some());
        assert!(matches!(
            coordinator.write_attempt(
                key(1),
                &id,
                output.owned(),
                Instant::now() + Duration::from_secs(5)
            ),
            Err(CaptureError::InvalidAttempt)
        ));
        assert_eq!(coordinator.reopen(key(1)), Err(ControlFailure::Busy));
        coordinator.abandon_attempt(key(1), &id).unwrap();
        coordinator.reopen(key(1)).unwrap();
        drop(
            coordinator
                .control
                .domain()
                .write(GuestAddress(4096), 1)
                .unwrap(),
        );
        stop(&mut coordinator, key(2));
        assert_eq!(coordinator.pending.as_ref().unwrap().count(), 2);
        assert!(
            coordinator
                .pending
                .as_ref()
                .unwrap()
                .contains(PageIndex::new(0))
        );
        assert!(
            coordinator
                .pending
                .as_ref()
                .unwrap()
                .contains(PageIndex::new(1))
        );
    }

    #[test]
    fn exact_candidate_acceptance_zero_updates_and_zero_dirty_recapture() {
        let mut coordinator = coordinator();
        coordinator
            .control
            .domain()
            .write(GuestAddress(0), 4096)
            .unwrap()
            .write_view(0, 4096)
            .unwrap()
            .write_slice(&[9; 4096], 0)
            .unwrap();
        stop(&mut coordinator, key(1));
        let (first_token, first_image, _first_files) = accept_full(&mut coordinator, key(1));
        assert_eq!(first_token.memory_generation(), 1);
        assert_eq!(coordinator.pending.as_ref().unwrap().count(), 0);
        coordinator.reopen(key(1)).unwrap();
        coordinator
            .control
            .domain()
            .write(GuestAddress(0), 4096)
            .unwrap()
            .write_view(0, 4096)
            .unwrap()
            .write_slice(&[0; 4096], 0)
            .unwrap();
        stop(&mut coordinator, key(2));
        let request = RamCaptureRequest::Incremental {
            baseline: Some(&first_token),
            crossover: DirtyCrossoverPercent::default(),
        };
        let (id, mut candidate, output) = capture(&mut coordinator, key(2), request);
        assert_eq!(candidate.receipt().mode(), RamCaptureMode::Incremental);
        let stats = candidate.receipt().stats();
        // Reflink identity units use live data plus cut-proven zeros; rebuilds compose B and D.
        let cloned = stats.seed_method == RamSeedMethod::Clone;
        assert_eq!(
            stats.live_bytes_read + stats.known_zero_bytes_skipped,
            if cloned { 10 * 4096 } else { 4096 }
        );
        assert_eq!(
            stats.baseline_bytes_read + stats.baseline_hole_bytes,
            if cloned { 0 } else { 9 * 4096 }
        );
        assert_eq!(stats.identity_bytes_hashed, 0);
        assert_eq!(
            candidate
                .receipt()
                .changes()
                .identified()
                .unwrap()
                .record_count(),
            1
        );
        assert_eq!(
            std::fs::read(output.ram.as_path()).unwrap(),
            vec![0; 10 * 4096]
        );
        let image = output.seal(&mut candidate, key(2));
        assert!(
            coordinator
                .accept_attempt(key(2), candidate, first_image)
                .is_err()
        );
        assert_eq!(coordinator.pending.as_ref().unwrap().count(), 1);
        assert_eq!(coordinator.baseline.as_ref().unwrap().token, first_token);
        coordinator.abandon_attempt(key(2), &id).unwrap();
        drop(image);
        let (_, mut candidate, output) = capture(
            &mut coordinator,
            key(2),
            RamCaptureRequest::Incremental {
                baseline: Some(&first_token),
                crossover: DirtyCrossoverPercent::default(),
            },
        );
        let image = output.seal(&mut candidate, key(2));
        let accepted = coordinator
            .accept_attempt(key(2), candidate, image)
            .unwrap();
        assert_eq!(accepted.memory_generation(), 3);
        let (_, candidate, output) = capture(
            &mut coordinator,
            key(2),
            RamCaptureRequest::Incremental {
                baseline: Some(&accepted),
                crossover: DirtyCrossoverPercent::default(),
            },
        );
        assert_eq!(candidate.receipt().mode(), RamCaptureMode::Incremental);
        assert_eq!(candidate.receipt().stats().live_bytes_read, 0);
        assert_eq!(
            std::fs::metadata(output.ram.as_path()).unwrap().len(),
            10 * 4096
        );
    }

    #[test]
    fn foreign_candidate_and_dropped_candidate_do_not_resolve_current_attempt() {
        let mut first = coordinator();
        let mut second = coordinator();
        stop(&mut first, key(1));
        stop(&mut second, key(1));
        let (first_id, candidate, _files) = capture(&mut first, key(1), RamCaptureRequest::Full);
        drop(candidate);
        assert_eq!(first.reopen(key(1)), Err(ControlFailure::Busy));
        let (second_id, mut candidate, files) =
            capture(&mut second, key(1), RamCaptureRequest::Full);
        let image = files.seal(&mut candidate, key(1));
        assert!(matches!(
            first.accept_attempt(key(1), candidate, image),
            Err(CaptureError::InvalidCandidate)
        ));
        assert!(first.baseline.is_none());
        assert_eq!(first.attempt.as_ref().unwrap().id, first_id);
        first.abandon_attempt(key(1), &first_id).unwrap();
        second.abandon_attempt(key(1), &second_id).unwrap();
    }

    #[test]
    fn lost_coverage_requires_full_acceptance_and_child_seed_is_fresh_without_clearing_writes() {
        let mut source = coordinator();
        stop(&mut source, key(1));
        let (source_token, image, _files) = accept_full(&mut source, key(1));
        source.control.domain().invalidate_coverage();
        let (id, candidate, _files) = capture(
            &mut source,
            key(1),
            RamCaptureRequest::Incremental {
                baseline: Some(&source_token),
                crossover: DirtyCrossoverPercent::default(),
            },
        );
        assert_eq!(
            candidate.full_reason(),
            Some(FullCaptureReason::CoverageLost)
        );
        assert_eq!(candidate.receipt().mode(), RamCaptureMode::Full);
        source.abandon_attempt(key(1), &id).unwrap();
        assert!(!source.control.domain().coverage_valid());
        let (_, mut candidate, files) = capture(&mut source, key(1), RamCaptureRequest::Full);
        let replacement = files.seal(&mut candidate, key(1));
        source
            .accept_attempt(key(1), candidate, replacement)
            .unwrap();
        assert!(source.control.domain().coverage_valid());
        let mut child = coordinator_with_backing(BackingKind::RestoredPrivate);
        child.seed_restored(image.clone()).unwrap();
        let child_token = child.baseline.as_ref().unwrap().token.clone();
        assert_eq!(child_token.memory_generation(), 1);
        assert_ne!(child_token, source_token);
        assert!(Arc::ptr_eq(child.layout.get().unwrap(), image.layout()));
        assert_eq!(child.pending.as_ref().unwrap().count(), 0);
        drop(child.control.domain().write(GuestAddress(4096), 1).unwrap());
        stop(&mut child, key(2));
        assert!(child.pending.as_ref().unwrap().contains(PageIndex::new(1)));
        let (_, candidate, output) = capture(
            &mut child,
            key(2),
            RamCaptureRequest::Incremental {
                baseline: Some(&child_token),
                crossover: DirtyCrossoverPercent::default(),
            },
        );
        let stats = candidate.receipt().stats();
        let cloned = stats.seed_method == RamSeedMethod::Clone;
        assert_eq!(
            stats.live_bytes_read + stats.known_zero_bytes_skipped,
            if cloned { 10 * 4096 } else { 4096 }
        );
        assert_eq!(
            stats.baseline_bytes_read + stats.baseline_hole_bytes,
            if cloned { 0 } else { 9 * 4096 }
        );
        assert_eq!(stats.identity_bytes_hashed, 0);
        assert_eq!(
            candidate
                .receipt()
                .changes()
                .identified()
                .unwrap()
                .record_count(),
            1
        );
        assert_eq!(
            std::fs::read(output.ram.as_path()).unwrap(),
            vec![0; 10 * 4096]
        );
    }

    #[test]
    fn result_release_and_abandon_keep_readonly_baseline_and_pending_union() {
        let mut coordinator = coordinator();
        coordinator
            .control
            .domain()
            .write(GuestAddress(0), 1)
            .unwrap()
            .write_view(0, 1)
            .unwrap()
            .write_slice(&[9], 0)
            .unwrap();
        stop(&mut coordinator, key(1));
        let (baseline, image, files) = accept_full(&mut coordinator, key(1));
        drop(image);
        drop(files);
        assert_eq!(coordinator.baseline_token(), Some(baseline.clone()));
        coordinator.reopen(key(1)).unwrap();
        coordinator
            .control
            .domain()
            .write(GuestAddress(4096), 1)
            .unwrap()
            .write_view(0, 1)
            .unwrap()
            .write_slice(&[7], 0)
            .unwrap();
        stop(&mut coordinator, key(2));
        let request = RamCaptureRequest::Incremental {
            baseline: Some(&baseline),
            crossover: DirtyCrossoverPercent::default(),
        };
        let (attempt, candidate, output) = capture(&mut coordinator, key(2), request);
        assert!(candidate.receipt().writers_closed());
        assert_eq!(candidate.receipt().mode(), RamCaptureMode::Incremental);
        let stats = candidate.receipt().stats();
        let cloned = stats.seed_method == RamSeedMethod::Clone;
        assert_eq!(
            stats.live_bytes_read + stats.known_zero_bytes_skipped,
            if cloned { 10 * 4096 } else { 4096 }
        );
        assert_eq!(
            stats.baseline_bytes_read + stats.baseline_hole_bytes,
            if cloned { 0 } else { 9 * 4096 }
        );
        assert_eq!(stats.identity_bytes_hashed, 10 * 4096);
        assert_eq!(
            candidate
                .receipt()
                .changes()
                .identified()
                .unwrap()
                .record_count(),
            1
        );
        let bytes = std::fs::read(output.ram.as_path()).unwrap();
        assert_eq!(bytes[0], 9);
        assert_eq!(bytes[4096], 7);
        drop(candidate);
        drop(output);
        assert!(
            coordinator.has_attempt(),
            "caller drop cannot resolve an accepted attempt"
        );
        assert_eq!(coordinator.reopen(key(2)), Err(ControlFailure::Busy));
        coordinator.abandon_attempt(key(2), &attempt).unwrap();
        assert_eq!(coordinator.baseline_token(), Some(baseline.clone()));
        assert_eq!(coordinator.pending_dirty_count(), 1);
        let request = RamCaptureRequest::Incremental {
            baseline: Some(&baseline),
            crossover: DirtyCrossoverPercent::default(),
        };
        let (_, mut candidate, output) = capture(&mut coordinator, key(2), request);
        assert_eq!(candidate.receipt().mode(), RamCaptureMode::Incremental);
        assert_eq!(
            candidate.receipt().stats().live_bytes_read
                + candidate.receipt().stats().known_zero_bytes_skipped,
            if candidate.receipt().stats().seed_method == RamSeedMethod::Clone {
                10 * 4096
            } else {
                4096
            }
        );
        assert_eq!(candidate.receipt().stats().identity_bytes_hashed, 10 * 4096);
        assert_eq!(candidate.receipt().identity_dirty_pages(), 1);
        assert_eq!(candidate.receipt().materialization_dirty_pages(), 1);
        assert_eq!(std::fs::read(output.ram.as_path()).unwrap(), bytes);
        let image = output.seal(&mut candidate, key(2));
        let next = coordinator
            .accept_attempt(key(2), candidate, image)
            .unwrap();
        assert_ne!(next, baseline);
        assert_eq!(coordinator.pending_dirty_count(), 0);
    }

    #[test]
    fn uncertain_harvest_recovery_keeps_union_and_requires_exact_epoch_then_full_acceptance() {
        use arch::guest_memory::{DirtyEffect, DirtyFailure, DirtyLocation, DirtyOperation};
        let mut memory = coordinator();
        stop(&mut memory, key(1));
        let (baseline, _image, _files) = accept_full(&mut memory, key(1));
        memory.reopen(key(1)).unwrap();
        memory
            .control
            .domain()
            .write(GuestAddress(4096), 1)
            .unwrap()
            .write_view(0, 1)
            .unwrap()
            .write_slice(&[0x7b], 0)
            .unwrap();
        stop(&mut memory, key(2));
        memory.control.domain().invalidate_coverage();
        memory.tracking_failure = Some(DirtyFailure {
            operation: DirtyOperation::Collect,
            location: DirtyLocation::Vm,
            effect: DirtyEffect::CoverageLost,
            native_code: 5,
        });
        memory.next = None;
        let mut foreign = coordinator();
        stop(&mut foreign, key(2));
        let epoch = foreign.cut.as_ref().unwrap().issue_epoch(3).unwrap();
        assert!(memory.finish_tracking_recovery(key(2), epoch).is_err());
        let epoch = memory.cut.as_ref().unwrap().issue_epoch(3).unwrap();
        assert!(memory.finish_tracking_recovery(key(3), epoch).is_err());
        assert!(memory.tracking_failure.is_some());
        assert!(memory.pending.as_ref().unwrap().contains(PageIndex::new(1)));
        let epoch = memory.cut.as_ref().unwrap().issue_epoch(3).unwrap();
        memory.finish_tracking_recovery(key(2), epoch).unwrap();
        assert!(memory.tracking_failure.is_none());
        assert!(!memory.control.domain().coverage_valid());
        assert!(memory.pending.as_ref().unwrap().contains(PageIndex::new(1)));
        let repeated = memory.cut.as_ref().unwrap().issue_epoch(3).unwrap();
        assert_eq!(
            memory.finish_tracking_recovery(key(2), repeated),
            Err(arch::guest_memory::MemoryError::Authority)
        );
        assert!(!memory.control.domain().coverage_valid());
        assert!(memory.pending.as_ref().unwrap().contains(PageIndex::new(1)));
        memory.reopen(key(2)).unwrap();
        stop(&mut memory, key(3));
        let (_, mut candidate, output) = capture(
            &mut memory,
            key(3),
            RamCaptureRequest::Incremental {
                baseline: Some(&baseline),
                crossover: DirtyCrossoverPercent::default(),
            },
        );
        assert_eq!(
            candidate.full_reason(),
            Some(FullCaptureReason::CoverageLost)
        );
        assert_eq!(std::fs::read(output.ram.as_path()).unwrap()[4096], 0x7b);
        let image = output.seal(&mut candidate, key(3));
        memory.accept_attempt(key(3), candidate, image).unwrap();
        assert!(memory.control.domain().coverage_valid());
        assert_eq!(memory.pending_dirty_count(), 0);
    }

    #[test]
    fn restore_installation_evidence_samples_armed_tracking_and_actual_dirty_union() {
        let mut boot = coordinator();
        assert_eq!(
            boot.observe_restore_install_begin(),
            Err(arch::guest_memory::MemoryError::State)
        );
        let mut coordinator = coordinator_with_backing(BackingKind::RestoredPrivate);
        coordinator.begin_close(key(1)).unwrap();
        assert!(matches!(coordinator.poll_drained(), Poll::Ready(Ok(()))));
        coordinator.observe_restore_install_begin().unwrap();
        let native = coordinator.native().unwrap();
        native
            .write(GuestAddress(4096), 1)
            .unwrap()
            .write_view(0, 1)
            .unwrap()
            .write_slice(&[8], 0)
            .unwrap();
        drop(native);
        coordinator.retire_native();
        let cut = coordinator
            .control
            .seal(coordinator.drained.as_ref().unwrap())
            .unwrap();
        coordinator
            .control
            .drain_host_dirty(&cut, coordinator.pending.as_mut().unwrap())
            .unwrap();
        coordinator.next = Some(cut.issue_epoch(2).unwrap());
        coordinator.cut = Some(cut);
        coordinator.observe_restore_install_complete().unwrap();
        let evidence = coordinator.restore_installation().unwrap();
        assert!(evidence.tracking_before_install);
        assert!(evidence.complete);
        assert_eq!(evidence.dirty_pages, 1);
        assert_eq!(coordinator.pending_dirty_count(), 1);
    }

    #[test]
    fn checked_counter_exhaustion_has_no_attempt_or_output_effects() {
        for attempts_exhausted in [false, true] {
            let mut coordinator = coordinator();
            stop(&mut coordinator, key(1));
            if attempts_exhausted {
                coordinator.next_attempt = u64::MAX;
            } else {
                coordinator.next_memory_generation = u64::MAX;
            }
            assert!(matches!(
                coordinator.begin_attempt(
                    key(1),
                    RamCaptureRequest::Full,
                    RamIdentityPolicy::Full,
                    binding(key(1)),
                    layout(&coordinator)
                ),
                Err(CaptureError::Exhausted)
            ));
            assert!(!coordinator.has_attempt());
            assert!(coordinator.baseline.is_none());
            assert!(coordinator.scratch.is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enospc_mid_overlay_requires_abandonment_and_retains_dirties() {
        use crate::vmm::memory::image::{RamImageEffects, RamImageError};
        use std::os::unix::fs::FileExt;
        use std::process::Command;

        const SELECTOR: &str =
            "vmm::memory::tests::enospc_mid_overlay_requires_abandonment_and_retains_dirties";
        let Some(directory) = std::env::var_os("LIBKRUN_RAM_ENOSPC_DIR") else {
            let probe = Command::new("unshare")
                .args(["--user", "--map-root-user", "--mount", "/bin/true"])
                .output();
            if !probe.as_ref().is_ok_and(|output| output.status.success()) {
                eprintln!("isolated tmpfs ENOSPC test requires unshare user/mount namespaces");
                return;
            }
            let result = Command::new("unshare")
                .args(["--user", "--map-root-user", "--mount", "/bin/sh", "-c"])
                .arg(
                    "dir=$(mktemp -d) || exit 1; \
                     trap 'umount \"$dir\" 2>/dev/null; rmdir \"$dir\"' EXIT; \
                     mount -t tmpfs -o size=4096,nr_inodes=16 tmpfs \"$dir\" || exit 77; \
                     LIBKRUN_RAM_ENOSPC_DIR=\"$dir\" \"$1\" \"$2\" --exact --test-threads=1 --nocapture",
                )
                .arg("ram-enospc")
                .arg(std::env::current_exe().unwrap())
                .arg(SELECTOR)
                .output()
                .unwrap();
            if result.status.code() == Some(77) {
                eprintln!("isolated tmpfs ENOSPC test requires permission to mount tmpfs");
                return;
            }
            assert!(
                result.status.success(),
                "ENOSPC child failed: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        };
        for unhashed in [false, true] {
            let mut coordinator = coordinator();
            stop(&mut coordinator, key(1));
            let (initial, baseline_files) =
                capture_identity(&mut coordinator, key(1), RamIdentityPolicy::Full);
            let baseline_token = adopt_identity(&mut coordinator, key(1), initial, &baseline_files);
            let RamIdentityAnchor::Identified { stream } = baseline_token.identity_anchor() else {
                panic!("identified baseline required")
            };
            let original = std::fs::read(baseline_files.ram.as_path()).unwrap();
            coordinator.reopen(key(1)).unwrap();
            for address in [0, 8192] {
                coordinator
                    .control
                    .domain()
                    .write(GuestAddress(address), 4096)
                    .unwrap()
                    .write_view(0, 4096)
                    .unwrap()
                    .write_slice(&[0x5a; 4096], 0)
                    .unwrap();
            }
            stop(&mut coordinator, key(2));
            assert_eq!(coordinator.pending_dirty_count(), 2);
            let attempt = coordinator
                .begin_attempt(
                    key(2),
                    RamCaptureRequest::Incremental {
                        baseline: Some(&baseline_token),
                        crossover: DirtyCrossoverPercent::default(),
                    },
                    if unhashed {
                        RamIdentityPolicy::None
                    } else {
                        RamIdentityPolicy::SinceAnchor { stream }
                    },
                    binding(key(2)),
                    layout(&coordinator),
                )
                .unwrap();
            let ram_path = std::path::Path::new(&directory).join("ram");
            let ram = File::options()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&ram_path)
                .unwrap();
            let outputs = Outputs::new();
            let output = RamOutputFiles::new(
                ram,
                outputs.layout.as_file().try_clone().unwrap(),
                TempFile::new().unwrap().as_file().try_clone().unwrap(),
            );
            let error = match coordinator.write_attempt(
                key(2),
                &attempt,
                output,
                Instant::now() + Duration::from_secs(5),
            ) {
                Ok(_) => panic!("ENOSPC mid-overlay must fail the attempt"),
                Err(error) => error,
            };
            let CaptureError::Write(failure) = error else {
                panic!("expected image write failure");
            };
            assert!(matches!(&failure.error, RamImageError::Io { source, .. }
            if source.raw_os_error() == Some(nix::errno::Errno::ENOSPC as i32)));
            assert_eq!(failure.effects, RamImageEffects::Started);
            assert_eq!(failure.stats.seed_method, RamSeedMethod::Rebuild);
            assert_eq!(failure.stats.overlay_bytes_written, 4096);
            if unhashed {
                assert_eq!(failure.stats.identity_bytes_hashed, 0);
                assert_eq!(failure.stats.whole_file_bytes_hashed, 0);
                assert_eq!(failure.stats.map_nodes_written, 0);
            }
            let mut first = [0; 4096];
            File::open(&ram_path)
                .unwrap()
                .read_exact_at(&mut first, 0)
                .unwrap();
            assert_eq!(first, [0x5a; 4096]);
            assert_eq!(coordinator.pending_dirty_count(), 2);
            assert_eq!(coordinator.baseline_token(), Some(baseline_token.clone()));
            assert_eq!(coordinator.reopen(key(2)), Err(ControlFailure::Busy));
            assert!(coordinator.attempt.as_ref().unwrap().failure.is_some());
            coordinator.abandon_attempt(key(2), &attempt).unwrap();
            assert!(!coordinator.has_attempt());
            assert_eq!(coordinator.pending_dirty_count(), 2);
            assert_eq!(coordinator.identity_dirty.as_ref().unwrap().count(), 2);
            assert_eq!(coordinator.baseline_token(), Some(baseline_token.clone()));
            assert_eq!(
                std::fs::read(baseline_files.ram.as_path()).unwrap(),
                original
            );
            let (retry, files) = capture_identity(
                &mut coordinator,
                key(2),
                if unhashed {
                    RamIdentityPolicy::None
                } else {
                    RamIdentityPolicy::SinceAnchor { stream }
                },
            );
            assert_eq!(retry.receipt().stats().overlay_bytes_written, 8192);
            adopt_identity(&mut coordinator, key(2), retry, &files);
            assert_eq!(coordinator.pending_dirty_count(), 0);
            if unhashed {
                assert_eq!(coordinator.identity_dirty.as_ref().unwrap().count(), 2);
                let (snapshot, files) = capture_identity(
                    &mut coordinator,
                    key(2),
                    RamIdentityPolicy::SinceAnchor { stream },
                );
                assert_eq!(
                    snapshot.receipt().stats().live_bytes_read
                        + snapshot.receipt().stats().known_zero_bytes_skipped,
                    if snapshot.receipt().stats().seed_method == RamSeedMethod::Clone {
                        10 * 4096
                    } else {
                        0
                    }
                );
                assert_eq!(snapshot.receipt().stats().overlay_bytes_written, 0);
                assert_eq!(snapshot.receipt().stats().identity_bytes_hashed, 10 * 4096);
                adopt_identity(&mut coordinator, key(2), snapshot, &files);
            }
            assert_eq!(coordinator.identity_dirty.as_ref().unwrap().count(), 0);
            drop(failure);
            std::fs::remove_file(ram_path).unwrap();
        }
    }

    #[test]
    fn accepted_baseline_survives_publication_release_and_next_incremental_matches_full() {
        use std::os::unix::fs::MetadataExt;

        let mut coordinator = coordinator();
        for (address, byte) in [(0, 0x91), (8192, 0x22), (8 * 4096, 0x43)] {
            coordinator
                .control
                .domain()
                .write(GuestAddress(address), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[byte; 4096], 0)
                .unwrap();
        }
        stop(&mut coordinator, key(1));
        let (_, mut candidate, retained_staging) =
            capture(&mut coordinator, key(1), RamCaptureRequest::Full);
        let baseline_map = crate::vmm::memory::image::changes::read_test_changes(
            retained_staging.changes.as_file(),
        );
        let image = retained_staging.seal(&mut candidate, key(1));
        let retained = Arc::downgrade(&image);
        let token = coordinator
            .accept_attempt(key(1), candidate, image.clone())
            .unwrap();
        let original = std::fs::read(retained_staging.ram.as_path()).unwrap();
        let original_layout = std::fs::read(retained_staging.layout.as_path()).unwrap();
        let metadata = retained_staging.ram.as_file().metadata().unwrap();
        let fingerprint = (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        );
        coordinator.reopen(key(1)).unwrap();
        drop(image);
        assert_eq!(retained.strong_count(), 1);
        assert_eq!(coordinator.baseline_token(), Some(token.clone()));

        for (generation, changed) in [(2, false), (3, true)] {
            if changed {
                for (address, byte) in [(0, 0), (4096, 0x87)] {
                    coordinator
                        .control
                        .domain()
                        .write(GuestAddress(address), 4096)
                        .unwrap()
                        .write_view(0, 4096)
                        .unwrap()
                        .write_slice(&[byte; 4096], 0)
                        .unwrap();
                }
            }
            let key = key(generation);
            stop(&mut coordinator, key);
            let (attempt, incremental, output) = capture(
                &mut coordinator,
                key,
                RamCaptureRequest::Incremental {
                    baseline: Some(&token),
                    crossover: DirtyCrossoverPercent::default(),
                },
            );
            assert_eq!(incremental.receipt().mode(), RamCaptureMode::Incremental);
            assert_eq!(
                incremental.receipt().stats().known_zero_bytes_skipped,
                if changed && incremental.receipt().stats().seed_method == RamSeedMethod::Clone {
                    6 * 4096
                } else {
                    0
                }
            );
            if !changed {
                assert_eq!(incremental.receipt().stats().live_bytes_read, 0);
                assert_eq!(
                    incremental
                        .receipt()
                        .changes()
                        .identified()
                        .unwrap()
                        .record_count(),
                    0
                );
            } else {
                assert_eq!(incremental.receipt().stats().zero_run_bytes_covered, 4096);
            }
            let mut resolved_map = baseline_map.clone();
            for (chunk, digest) in
                crate::vmm::memory::image::changes::read_test_changes(output.changes.as_file())
            {
                resolved_map.insert(chunk, digest);
            }
            coordinator.abandon_attempt(key, &attempt).unwrap();
            let (full_attempt, _full, full_files) =
                capture(&mut coordinator, key, RamCaptureRequest::Full);
            assert_eq!(
                std::fs::read(output.ram.as_path()).unwrap(),
                std::fs::read(full_files.ram.as_path()).unwrap()
            );
            resolved_map.retain(|_, value| value.is_some());
            assert_eq!(
                resolved_map,
                crate::vmm::memory::image::changes::read_test_changes(full_files.changes.as_file())
            );
            assert_eq!(
                std::fs::read(output.layout.as_path()).unwrap(),
                std::fs::read(full_files.layout.as_path()).unwrap()
            );
            assert_eq!(coordinator.baseline_token(), Some(token.clone()));
            assert!(
                retained
                    .upgrade()
                    .unwrap()
                    .aliases(fingerprint.0, fingerprint.1)
            );
            assert_eq!(
                std::fs::read(retained_staging.ram.as_path()).unwrap(),
                original
            );
            assert_eq!(
                std::fs::read(retained_staging.layout.as_path()).unwrap(),
                original_layout
            );
            let metadata = retained_staging.ram.as_file().metadata().unwrap();
            assert_eq!(
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.len(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec()
                ),
                fingerprint
            );
            coordinator.abandon_attempt(key, &full_attempt).unwrap();
            coordinator.reopen(key).unwrap();
        }
    }

    fn four_unit_coordinator() -> MemoryCoordinator {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4 * 65536)]).unwrap();
        let (_, authority, control) =
            MemoryDomain::construct(memory, 4096, BackingKind::Boot).unwrap();
        let epoch = authority.issue_epoch(1).unwrap();
        let mut memory = MemoryCoordinator::new(control, authority);
        memory.finish_tracked(epoch).unwrap();
        memory
    }

    fn write_page(memory: &MemoryCoordinator, page: usize, value: u8) {
        memory
            .control
            .domain()
            .write(GuestAddress((page * 4096) as u64), 4096)
            .unwrap()
            .write_view(0, 4096)
            .unwrap()
            .write_slice(&[value; 4096], 0)
            .unwrap();
    }

    fn capture_identity(
        memory: &mut MemoryCoordinator,
        key: BarrierKey,
        identity: RamIdentityPolicy,
    ) -> (CompletedCandidate, Outputs) {
        let baseline = memory.baseline_token();
        let request = RamCaptureRequest::Incremental {
            baseline: baseline.as_ref(),
            crossover: DirtyCrossoverPercent::default(),
        };
        let id = memory
            .begin_attempt(key, request, identity, binding(key), layout(memory))
            .unwrap();
        let files = Outputs::new();
        let candidate = memory
            .write_attempt(
                key,
                &id,
                files.owned(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        (candidate, files)
    }

    fn adopt_identity(
        memory: &mut MemoryCoordinator,
        key: BarrierKey,
        candidate: CompletedCandidate,
        files: &Outputs,
    ) -> BaselineToken {
        let authority = if *candidate.receipt().identity_policy() == RamIdentityPolicy::None {
            RamInputAuthority::OwnedLocalCut {
                state: binding(key),
                materialization_generation: candidate.memory_generation(),
            }
        } else {
            RamInputAuthority::IdentifiedSnapshot(RamImageAuthentication {
                state: binding(key),
                stream: stream_root(
                    &independent_units(&std::fs::read(files.ram.as_path()).unwrap()),
                    candidate.receipt().packed_len(),
                ),
            })
        };
        let image = candidate
            .seal(
                File::open(files.ram.as_path()).unwrap(),
                File::open(files.layout.as_path()).unwrap(),
                authority,
            )
            .unwrap();
        memory.accept_attempt(key, candidate, image).unwrap()
    }

    fn independent_units(bytes: &[u8]) -> Vec<Option<[u8; 32]>> {
        use sha2::{Digest, Sha256};
        bytes
            .chunks(65536)
            .map(|unit| {
                unit.iter()
                    .any(|byte| *byte != 0)
                    .then(|| Sha256::digest(unit).into())
            })
            .collect()
    }

    fn stream_root(units: &[Option<[u8; 32]>], length: u64) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        assert!(units.len() <= 64);
        let bitmap = units
            .iter()
            .enumerate()
            .fold(0u64, |bits, (index, digest)| {
                bits | if digest.is_some() { 1 << index } else { 0 }
            });
        let head = if bitmap == 0 {
            None
        } else {
            let mut leaf = Sha256::new();
            leaf.update(b"silo:stream-map:leaf:v2\n");
            leaf.update(bitmap.to_le_bytes());
            for digest in units.iter().flatten() {
                leaf.update(digest);
            }
            let mut digest: [u8; 32] = leaf.finalize().into();
            for height in 1..=4 {
                let mut branch = Sha256::new();
                branch.update(b"silo:stream-map:branch:v2\n");
                branch.update([height]);
                branch.update(1u64.to_le_bytes());
                branch.update(digest);
                digest = branch.finalize().into();
            }
            Some(digest)
        };
        let mut root = Sha256::new();
        root.update(b"silo:stream:v2\n");
        root.update([16]);
        root.update(length.to_le_bytes());
        root.update([u8::from(head.is_some())]);
        if let Some(head) = head {
            root.update(head);
        }
        root.finalize().into()
    }

    fn assert_unhashed(candidate: &CompletedCandidate, files: &Outputs) {
        let receipt = candidate.receipt();
        assert_eq!(*receipt.identity_policy(), RamIdentityPolicy::None);
        assert!(matches!(
            receipt.changes(),
            crate::vmm::memory::image::RamChangeAuthority::None
        ));
        assert_eq!(receipt.stats().identity_bytes_hashed, 0);
        assert_eq!(receipt.stats().map_nodes_written, 0);
        assert_eq!(receipt.stats().whole_file_bytes_hashed, 0);
        assert_eq!(files.changes.as_file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn accepted_forks_preserve_identity_union_but_write_only_latest_dirties() {
        use crate::vmm::memory::image::changes::read_test_changes;
        for anchored in [true, false] {
            let mut memory = four_unit_coordinator();
            let mut expected = vec![0x11; 4 * 65536];
            for page in 0..64 {
                write_page(&memory, page, 0x11);
            }
            let mut retained = Vec::new();
            let mut units = vec![None; 4];
            if anchored {
                stop(&mut memory, key(1));
                let (candidate, files) =
                    capture_identity(&mut memory, key(1), RamIdentityPolicy::Full);
                for (index, digest) in read_test_changes(files.changes.as_file()) {
                    units[index as usize] = digest;
                }
                adopt_identity(&mut memory, key(1), candidate, &files);
                retained.push(files);
                memory.reopen(key(1)).unwrap();
            }
            let initial_anchor = memory.identity_anchor;
            let initial_anchor_generation = memory.identity_anchor_generation;
            write_page(&memory, 0, 0x41);
            write_page(&memory, 0, 0x42);
            expected[..4096].fill(0x42);
            write_page(&memory, 1, 0x55);
            write_page(&memory, 1, 0x11);
            write_page(&memory, 2, 0);
            expected[8192..12288].fill(0);
            stop(&mut memory, key(2));
            let (candidate, files) = capture_identity(&mut memory, key(2), RamIdentityPolicy::None);
            assert_unhashed(&candidate, &files);
            assert_eq!(std::fs::read(files.ram.as_path()).unwrap(), expected);
            let first = adopt_identity(&mut memory, key(2), candidate, &files);
            assert_eq!(memory.pending_dirty_count(), 0);
            assert_eq!(first.identity_anchor(), initial_anchor);
            assert_eq!(
                first.identity_anchor_generation(),
                initial_anchor_generation
            );
            retained.clear();
            retained.push(files);
            memory.reopen(key(2)).unwrap();

            write_page(&memory, 16, 0x52);
            expected[65536..65536 + 4096].fill(0x52);
            write_page(&memory, 0, 0x43);
            expected[..4096].fill(0x43);
            stop(&mut memory, key(3));
            let (candidate, files) = capture_identity(&mut memory, key(3), RamIdentityPolicy::None);
            assert_unhashed(&candidate, &files);
            assert_eq!(candidate.receipt().mode(), RamCaptureMode::Incremental);
            assert_eq!(candidate.receipt().stats().live_bytes_read, 2 * 4096);
            assert_eq!(candidate.receipt().stats().overlay_bytes_written, 2 * 4096);
            assert_eq!(
                candidate.receipt().predecessor_generation(),
                first.memory_generation()
            );
            assert_eq!(std::fs::read(files.ram.as_path()).unwrap(), expected);
            assert_eq!(
                candidate.receipt().identity_dirty_pages(),
                if anchored { 4 } else { 64 }
            );
            let second = adopt_identity(&mut memory, key(3), candidate, &files);
            assert_eq!(
                second.identity_anchor_generation(),
                initial_anchor_generation
            );
            retained.clear();
            retained.push(files);
            memory.reopen(key(3)).unwrap();

            write_page(&memory, 32, 0x63);
            expected[2 * 65536..2 * 65536 + 4096].fill(0x63);
            stop(&mut memory, key(4));
            let identity = match initial_anchor {
                RamIdentityAnchor::Identified { stream } => {
                    RamIdentityPolicy::SinceAnchor { stream }
                }
                RamIdentityAnchor::Unknown => RamIdentityPolicy::Full,
            };
            let (candidate, files) = capture_identity(&mut memory, key(4), identity);
            assert_eq!(candidate.receipt().mode(), RamCaptureMode::Incremental);
            assert_eq!(
                candidate.receipt().predecessor_generation(),
                second.memory_generation()
            );
            let stats = candidate.receipt().stats();
            let selected_bytes = if anchored { 3 * 65536 } else { 4 * 65536 };
            if stats.seed_method == RamSeedMethod::Clone {
                assert_eq!(stats.live_bytes_read, selected_bytes);
                assert_eq!(stats.baseline_bytes_read, 0);
                assert_eq!(stats.baseline_hole_bytes, 0);
            } else {
                assert_eq!(stats.live_bytes_read, 4096);
            }
            assert_eq!(candidate.receipt().stats().overlay_bytes_written, 4096);
            assert_eq!(candidate.receipt().materialization_dirty_pages(), 1);
            assert_eq!(
                candidate.receipt().identity_dirty_pages(),
                if anchored { 5 } else { 64 }
            );
            let changes = read_test_changes(files.changes.as_file());
            assert_eq!(
                changes.keys().copied().collect::<Vec<_>>(),
                if anchored {
                    vec![0, 1, 2]
                } else {
                    vec![0, 1, 2, 3]
                }
            );
            assert_eq!(
                candidate.receipt().stats().identity_bytes_hashed,
                if anchored { 3 * 65536 } else { 4 * 65536 }
            );
            for (index, digest) in changes {
                units[index as usize] = digest;
            }
            assert_eq!(std::fs::read(files.ram.as_path()).unwrap(), expected);
            assert_eq!(units, independent_units(&expected));
            assert_eq!(
                stream_root(&units, expected.len() as u64),
                stream_root(&independent_units(&expected), expected.len() as u64)
            );
            assert_eq!(
                candidate.receipt().identity_anchor_generation(),
                initial_anchor_generation
            );
            let accepted = adopt_identity(&mut memory, key(4), candidate, &files);
            let crate::vmm::memory::image::RamIdentityGeneration::Identified { generation } =
                accepted.identity_anchor_generation()
            else {
                panic!("identified acceptance must advance its anchor epoch")
            };
            assert_eq!(generation.get(), accepted.memory_generation());
            assert_eq!(memory.identity_dirty.as_ref().unwrap().count(), 0);
            assert_eq!(memory.pending_dirty_count(), 0);
        }
    }

    #[test]
    fn fork_abandon_failure_and_rejected_acceptance_never_lose_coverage() {
        let mut memory = four_unit_coordinator();
        write_page(&memory, 0, 0x11);
        stop(&mut memory, key(1));
        let (candidate, initial) = capture_identity(&mut memory, key(1), RamIdentityPolicy::Full);
        let initial_token = adopt_identity(&mut memory, key(1), candidate, &initial);
        let RamIdentityAnchor::Identified {
            stream: initial_root,
        } = initial_token.identity_anchor()
        else {
            panic!("initial snapshot must be identified")
        };
        memory.reopen(key(1)).unwrap();
        write_page(&memory, 0, 0x42);
        stop(&mut memory, key(2));
        let request = RamCaptureRequest::Incremental {
            baseline: Some(&initial_token),
            crossover: DirtyCrossoverPercent::default(),
        };
        let id = memory
            .begin_attempt(
                key(2),
                request,
                RamIdentityPolicy::None,
                binding(key(2)),
                layout(&memory),
            )
            .unwrap();
        let failed = Outputs::new();
        assert!(
            memory
                .write_attempt(key(2), &id, failed.owned(), Instant::now())
                .is_err()
        );
        memory.abandon_attempt(key(2), &id).unwrap();
        assert_eq!(memory.baseline_token(), Some(initial_token.clone()));
        assert_eq!(memory.pending_dirty_count(), 1);
        assert_eq!(memory.identity_dirty.as_ref().unwrap().count(), 1);
        let (candidate, abandoned) = capture_identity(&mut memory, key(2), RamIdentityPolicy::None);
        let id = candidate.id.clone();
        memory.abandon_attempt(key(2), &id).unwrap();
        assert_eq!(memory.baseline_token(), Some(initial_token));
        assert_eq!(memory.pending_dirty_count(), 1);
        drop(abandoned);
        let (candidate, accepted) = capture_identity(&mut memory, key(2), RamIdentityPolicy::None);
        let id = candidate.id.clone();
        let adopted = adopt_identity(&mut memory, key(2), candidate, &accepted);
        assert!(memory.abandon_attempt(key(2), &id).is_err());
        assert_eq!(memory.baseline_token(), Some(adopted.clone()));
        assert_eq!(memory.pending_dirty_count(), 0);
        assert_eq!(memory.identity_dirty.as_ref().unwrap().count(), 1);
        memory.reopen(key(2)).unwrap();
        write_page(&memory, 16, 0x53);
        stop(&mut memory, key(3));
        assert!(
            memory
                .begin_attempt(
                    key(3),
                    RamCaptureRequest::Incremental {
                        baseline: Some(&adopted),
                        crossover: DirtyCrossoverPercent::default(),
                    },
                    RamIdentityPolicy::SinceAnchor { stream: [0x99; 32] },
                    binding(key(3)),
                    layout(&memory)
                )
                .is_err()
        );
        assert!(!memory.has_attempt());
        let (candidate, files) = capture_identity(&mut memory, key(3), RamIdentityPolicy::None);
        let wrong = candidate
            .seal(
                File::open(files.ram.as_path()).unwrap(),
                File::open(files.layout.as_path()).unwrap(),
                RamInputAuthority::OwnedLocalCut {
                    state: binding(key(3)),
                    materialization_generation: candidate.memory_generation() + 1,
                },
            )
            .unwrap();
        assert!(
            memory
                .accept_attempt(key(3), candidate.clone(), wrong)
                .is_err()
        );
        assert_eq!(memory.baseline_token(), Some(adopted));
        assert_eq!(memory.pending_dirty_count(), 1);
        memory.abandon_attempt(key(3), &candidate.id).unwrap();
        let (candidate, files) = capture_identity(
            &mut memory,
            key(3),
            RamIdentityPolicy::SinceAnchor {
                stream: initial_root,
            },
        );
        assert_eq!(candidate.receipt().identity_dirty_pages(), 2);
        assert_eq!(candidate.receipt().materialization_dirty_pages(), 1);
        assert_eq!(candidate.receipt().stats().overlay_bytes_written, 4096);
        memory.abandon_attempt(key(3), &candidate.id).unwrap();
        assert_eq!(memory.identity_dirty.as_ref().unwrap().count(), 2);
        assert_eq!(memory.pending_dirty_count(), 1);
        drop(files);
        let (candidate, files) = capture_identity(
            &mut memory,
            key(3),
            RamIdentityPolicy::SinceAnchor {
                stream: initial_root,
            },
        );
        adopt_identity(&mut memory, key(3), candidate, &files);
        assert_eq!(memory.identity_dirty.as_ref().unwrap().count(), 0);
        assert_eq!(memory.pending_dirty_count(), 0);
    }

    #[test]
    fn owned_child_seed_preserves_bytes_but_never_inherits_source_identity() {
        let mut source = coordinator();
        write_page(&source, 1, 0x64);
        stop(&mut source, key(1));
        let (candidate, files) = capture_identity(&mut source, key(1), RamIdentityPolicy::None);
        let generation = candidate.memory_generation();
        let image = candidate
            .seal(
                File::open(files.ram.as_path()).unwrap(),
                File::open(files.layout.as_path()).unwrap(),
                RamInputAuthority::OwnedLocalCut {
                    state: binding(key(1)),
                    materialization_generation: generation,
                },
            )
            .unwrap();
        source
            .accept_attempt(key(1), candidate, image.clone())
            .unwrap();
        let mut child = coordinator_with_backing(BackingKind::RestoredPrivate);
        child.seed_restored(image).unwrap();
        let token = child.baseline_token().unwrap();
        assert_eq!(token.identity_anchor(), RamIdentityAnchor::Unknown);
        assert_eq!(token.memory_generation(), generation);
        write_page(&child, 1, 0x65);
        stop(&mut child, key(2));
        let (candidate, files) = capture_identity(&mut child, key(2), RamIdentityPolicy::Full);
        assert_eq!(candidate.receipt().mode(), RamCaptureMode::Incremental);
        assert_eq!(candidate.receipt().stats().overlay_bytes_written, 4096);
        assert_eq!(candidate.receipt().stats().identity_bytes_hashed, 10 * 4096);
        assert_eq!(
            candidate.receipt().identity_anchor(),
            RamIdentityAnchor::Unknown
        );
        let token = adopt_identity(&mut child, key(2), candidate, &files);
        assert_eq!(
            token.identity_anchor(),
            RamIdentityAnchor::Identified {
                stream: stream_root(
                    &independent_units(&std::fs::read(files.ram.as_path()).unwrap()),
                    10 * 4096
                ),
            }
        );
    }

    #[test]
    fn snapshot_after_zero_fork_emits_tombstone_without_rewriting_or_hashing_zero_bytes() {
        use crate::vmm::memory::image::changes::read_test_changes;
        let mut memory = four_unit_coordinator();
        write_page(&memory, 0, 0x51);
        stop(&mut memory, key(1));
        let (snapshot, initial) = capture_identity(&mut memory, key(1), RamIdentityPolicy::Full);
        let token = adopt_identity(&mut memory, key(1), snapshot, &initial);
        let RamIdentityAnchor::Identified { stream } = token.identity_anchor() else {
            panic!("identified snapshot required")
        };
        memory.reopen(key(1)).unwrap();
        write_page(&memory, 0, 0);
        write_page(&memory, 0, 0);
        stop(&mut memory, key(2));
        let (fork, files) = capture_identity(&mut memory, key(2), RamIdentityPolicy::None);
        assert_unhashed(&fork, &files);
        assert_eq!(fork.receipt().stats().zero_run_bytes_covered, 4096);
        adopt_identity(&mut memory, key(2), fork, &files);
        assert_eq!(memory.identity_dirty.as_ref().unwrap().count(), 1);
        let (snapshot, zero) = capture_identity(
            &mut memory,
            key(2),
            RamIdentityPolicy::SinceAnchor { stream },
        );
        assert_eq!(
            snapshot.receipt().stats().live_bytes_read
                + snapshot.receipt().stats().known_zero_bytes_skipped,
            if snapshot.receipt().stats().seed_method == RamSeedMethod::Clone {
                65536
            } else {
                0
            }
        );
        assert_eq!(snapshot.receipt().stats().overlay_bytes_written, 0);
        assert_eq!(snapshot.receipt().stats().identity_bytes_hashed, 0);
        let changes = read_test_changes(zero.changes.as_file());
        assert_eq!(changes.into_iter().collect::<Vec<_>>(), vec![(0, None)]);
        let bytes = std::fs::read(zero.ram.as_path()).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
        let root = stream_root(&independent_units(&bytes), bytes.len() as u64);
        assert_ne!(root, stream);
        let token = adopt_identity(&mut memory, key(2), snapshot, &zero);
        assert_eq!(
            token.identity_anchor(),
            RamIdentityAnchor::Identified { stream: root }
        );
    }

    #[test]
    fn coverage_loss_fork_repairs_byte_baseline_but_invalidates_identified_anchor() {
        let mut memory = four_unit_coordinator();
        write_page(&memory, 0, 0x51);
        stop(&mut memory, key(1));
        let (snapshot, initial) = capture_identity(&mut memory, key(1), RamIdentityPolicy::Full);
        let token = adopt_identity(&mut memory, key(1), snapshot, &initial);
        let RamIdentityAnchor::Identified { stream } = token.identity_anchor() else {
            panic!("identified snapshot required")
        };
        memory.control.domain().invalidate_coverage();
        assert_eq!(
            memory.baseline_token().unwrap().identity_anchor(),
            RamIdentityAnchor::Unknown
        );
        let (fork, files) = capture_identity(&mut memory, key(1), RamIdentityPolicy::None);
        assert_eq!(fork.full_reason(), Some(FullCaptureReason::CoverageLost));
        assert_unhashed(&fork, &files);
        let token = adopt_identity(&mut memory, key(1), fork, &files);
        assert!(memory.control.domain().coverage_valid());
        assert_eq!(token.identity_anchor(), RamIdentityAnchor::Unknown);
        assert!(
            memory
                .begin_attempt(
                    key(1),
                    RamCaptureRequest::Incremental {
                        baseline: Some(&token),
                        crossover: DirtyCrossoverPercent::default(),
                    },
                    RamIdentityPolicy::SinceAnchor { stream },
                    binding(key(1)),
                    layout(&memory)
                )
                .is_err()
        );
        let (snapshot, files) = capture_identity(&mut memory, key(1), RamIdentityPolicy::Full);
        assert_eq!(snapshot.receipt().mode(), RamCaptureMode::Incremental);
        let cloned = snapshot.receipt().stats().seed_method == RamSeedMethod::Clone;
        assert_eq!(
            snapshot.receipt().stats().live_bytes_read,
            if cloned { 4096 } else { 0 }
        );
        assert_eq!(
            snapshot.receipt().stats().known_zero_bytes_skipped,
            if cloned { 4 * 65536 - 4096 } else { 3 * 65536 }
        );
        assert_eq!(snapshot.receipt().stats().overlay_bytes_written, 0);
        assert_eq!(snapshot.receipt().stats().identity_bytes_hashed, 65536);
        let token = adopt_identity(&mut memory, key(1), snapshot, &files);
        assert_eq!(
            token.identity_anchor(),
            RamIdentityAnchor::Identified { stream }
        );
    }
}
