#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(all(feature = "native-device-probe", not(target_os = "macos")))]
use std::sync::atomic::Ordering;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicI32, Ordering};
use std::task::Poll;
#[cfg(feature = "native-device-probe")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use arch::guest_memory::GuestRange;
use arch::guest_memory::{BackingKind, MemoryDomain, TrackingMode};
#[cfg(target_os = "macos")]
use hvf::reclaim::{ReclaimState, ReleaseOutcome};
#[cfg(target_os = "macos")]
use hvf::remap::HostMemoryRemapper;
use polly::event_manager::{BarrierKey, BarrierRequest};
use utils::eventfd::EventFd;
use utils::state::{Reader, Writer};

pub(crate) const BALLOON_STATE_MAGIC: &[u8; 8] = b"KRUNBALL";
pub(crate) const BALLOON_STATE_SCHEMA: u16 = 1;
#[cfg(any(target_os = "macos", feature = "native-device-probe"))]
use vm_memory::Address;
use vm_memory::ByteValued;

use crate::virtio::InterruptTransport;
#[cfg(any(target_os = "macos", feature = "native-device-probe"))]
use crate::virtio::balloon::ReclaimReason;
use crate::virtio::balloon::{
    BalloonMemoryPolicy, ReclaimObserver, ReclaimStatus, defs, defs::uapi,
};
#[cfg(feature = "native-device-probe")]
use crate::virtio::balloon::{ReportDescriptor, ReportIdentity, ReportWitness, ReportWitnessState};
use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::lifecycle::{
    CallbackState, DormantDeviceContext, ProviderBeginError, ProviderFault, QuiesceCompletion,
    RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
};
#[cfg(feature = "native-device-probe")]
use crate::virtio::queue::DescriptorChain;
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
use crate::virtio::{
    ActivateError, ActivateResult, BalloonError, DeviceQueue, DeviceState, QueueConfig,
    RuntimeGuestMemory, VirtioDevice,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::DiscardVirtualMemory;

// Inflate queue.
pub(crate) const IFQ_INDEX: usize = 0;
// Deflate queue.
pub(crate) const DFQ_INDEX: usize = 1;
// Stats queue.
pub(crate) const STQ_INDEX: usize = 2;
// Page-hinting queue.
pub(crate) const PHQ_INDEX: usize = 3;
// Free page reporting queue.
pub(crate) const FRQ_INDEX: usize = 4;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_STATS_VQ as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_REPORTING as u64);

fn reporting_features(enabled: bool) -> u64 {
    if enabled {
        AVAIL_FEATURES
    } else {
        AVAIL_FEATURES & !(1 << uapi::VIRTIO_BALLOON_F_REPORTING)
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioBalloonConfig {
    /* Number of pages host wants Guest to give up. */
    num_pages: u32,
    /* Number of pages we've actually got in balloon. */
    actual: u32,
    /* Free page report command id, readonly by guest */
    free_page_report_cmd_id: u32,
    /* Stores PAGE_POISON if page poisoning is in use */
    poison_val: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

#[cfg(feature = "native-device-probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportingQueueObservation {
    pub reporting_negotiated: bool,
    pub ready: bool,
    pub next_used: Option<u16>,
    pub used_ring: Option<u64>,
}

#[cfg(feature = "native-device-probe")]
enum ReportAction {
    Source { seed: u8 },
    Child { source_seed: u8, seed: u8 },
}

#[cfg(feature = "native-device-probe")]
struct ReportHold {
    active: bool,
    deadline: Instant,
    action: Option<ReportAction>,
    witness: ReportWitness,
}

#[cfg(feature = "native-device-probe")]
impl ReportHold {
    fn new() -> Self {
        Self {
            active: false,
            deadline: Instant::now(),
            action: None,
            witness: ReportWitness {
                state: ReportWitnessState::Idle,
                report: None,
                seed: None,
                verified_bytes: 0,
                used_after: None,
                barrier: None,
                parked_cpus: 0,
                failure: None,
            },
        }
    }

    fn fail(&mut self, error: String) {
        self.witness.state = ReportWitnessState::Failed;
        self.witness.failure.get_or_insert(error);
    }
}

pub struct Balloon {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioBalloonConfig,
    pub(crate) callbacks: CallbackState,
    host_reclaim_enabled: bool,
    memory_policy: Option<BalloonMemoryPolicy>,
    restored_offer: bool,
    reclaim_observer: ReclaimObserver,
    #[cfg(feature = "native-device-probe")]
    report_hold: ReportHold,
    descriptors: DescriptorChainSnapshot,
    #[cfg(target_os = "macos")]
    host_memory_remapper: Option<Arc<HostMemoryRemapper>>,
    #[cfg(target_os = "macos")]
    failure_signal: Option<(EventFd, Arc<AtomicI32>)>,
}

impl Balloon {
    pub fn new() -> crate::virtio::balloon::Result<Balloon> {
        Ok(Balloon {
            queues: None,
            avail_features: reporting_features(!cfg!(target_os = "macos")),
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(BalloonError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioBalloonConfig::default(),
            callbacks: CallbackState::new(),
            host_reclaim_enabled: true,
            memory_policy: None,
            restored_offer: false,
            reclaim_observer: ReclaimObserver::new(),
            #[cfg(feature = "native-device-probe")]
            report_hold: ReportHold::new(),
            descriptors: DescriptorChainSnapshot::new(defs::QUEUE_SIZE),
            #[cfg(target_os = "macos")]
            host_memory_remapper: None,
            #[cfg(target_os = "macos")]
            failure_signal: None,
        })
    }

    /// Binds the exact source offer without granting destructive reclaim on
    /// destination RAM, including when reporting was negotiated on the source.
    pub fn new_restore_binding(avail_features: u64) -> crate::virtio::balloon::Result<Balloon> {
        if avail_features != reporting_features(true) && avail_features != reporting_features(false)
        {
            return Err(BalloonError::UnsupportedRestoreFeatures(avail_features));
        }
        let mut balloon = Self::new()?;
        balloon.avail_features = avail_features;
        balloon.host_reclaim_enabled = false;
        balloon.restored_offer = true;
        Ok(balloon)
    }

    pub fn finalize_memory_policy(
        &mut self,
        policy: BalloonMemoryPolicy,
    ) -> crate::virtio::balloon::Result<()> {
        if self.memory_policy.is_some()
            || self.is_activated()
            || self.acked_features != 0
            || (self.restored_offer && !matches!(policy, BalloonMemoryPolicy::RestoredPrivate))
        {
            return Err(BalloonError::InvalidMemoryPolicy);
        }
        self.memory_policy = Some(policy);
        self.host_reclaim_enabled =
            policy == BalloonMemoryPolicy::Untracked && !self.restored_offer;
        if !self.restored_offer {
            #[cfg(target_os = "macos")]
            let reporting = policy != BalloonMemoryPolicy::Untracked
                || self
                    .reclaim_observer
                    .0
                    .backend
                    .get()
                    .is_some_and(|state| state.is_effective());
            #[cfg(not(target_os = "macos"))]
            let reporting = true;
            self.avail_features = reporting_features(reporting);
        }
        #[cfg(target_os = "macos")]
        if !self.host_reclaim_enabled {
            self.host_memory_remapper = None;
        }
        let reason = match policy {
            BalloonMemoryPolicy::Untracked => 0,
            BalloonMemoryPolicy::TrackedCapture => 1,
            BalloonMemoryPolicy::RestoredPrivate => 2,
        };
        let _ = self.reclaim_observer.0.facts.fetch_update(
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
            |previous| {
                Some(if previous & 32 != 0 {
                    (previous & !8)
                        | 16
                        | (u8::from(self.host_reclaim_enabled && previous & 6 == 0) << 3)
                } else {
                    u8::from(policy == BalloonMemoryPolicy::RestoredPrivate)
                        | (reason << 1)
                        | (u8::from(self.host_reclaim_enabled) << 3)
                        | 16
                })
            },
        );
        Ok(())
    }

    pub fn set_reclaim_observer(
        &mut self,
        observer: ReclaimObserver,
    ) -> crate::virtio::balloon::Result<()> {
        if self.memory_policy.is_some() || self.is_activated() || self.acked_features != 0 {
            return Err(BalloonError::InvalidMemoryPolicy);
        }
        #[cfg(target_os = "macos")]
        if let Some(state) = self.reclaim_observer.0.backend.get() {
            if observer
                .0
                .backend
                .get()
                .is_some_and(|incoming| !Arc::ptr_eq(state, incoming))
            {
                return Err(BalloonError::InvalidMemoryPolicy);
            }
            let _ = observer.0.backend.set(state.clone());
        }
        self.reclaim_observer = observer;
        Ok(())
    }

    pub fn bind_reclaim_domain(&mut self, domain: &MemoryDomain) {
        if domain.backing_kind() == BackingKind::RestoredPrivate
            || domain.tracking_mode() != Some(TrackingMode::Disabled)
        {
            self.host_reclaim_enabled = false;
            #[cfg(target_os = "macos")]
            {
                self.host_memory_remapper = None;
            }
        }
        self.reclaim_observer
            .bind(domain, self.host_reclaim_enabled, self.memory_policy);
    }

    pub fn reclaim_status(&self) -> ReclaimStatus {
        self.reclaim_observer.status()
    }

    pub fn reclaim_observer(&self) -> ReclaimObserver {
        self.reclaim_observer.clone()
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_remapper_present(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.host_memory_remapper.is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_hold_reports(&mut self) -> Result<(), String> {
        if self.report_hold.active
            || (!self.callbacks.admission_open() && self.callbacks.require_quiesced().is_err())
        {
            return Err(
                "report hold requires running or prepared device without another hold".into(),
            );
        }
        self.report_hold = ReportHold::new();
        self.report_hold.active = true;
        self.report_hold.deadline = Instant::now() + Duration::from_secs(10);
        self.report_hold.witness.state = ReportWitnessState::Holding;
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_arm_source(&mut self, seed: u8) -> Result<(), String> {
        if seed == 0
            || !self.report_hold.active
            || self.report_hold.action.is_some()
            || self.report_hold.witness.state != ReportWitnessState::Holding
        {
            return Err("source report seed requires a fresh hold and nonzero seed".into());
        }
        self.report_hold.action = Some(ReportAction::Source { seed });
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_arm_child(
        &mut self,
        expected: ReportIdentity,
        source_seed: u8,
        child_seed: u8,
    ) -> Result<(), String> {
        if source_seed == 0
            || child_seed == 0
            || source_seed == child_seed
            || !self.report_hold.active
            || self.report_hold.action.is_some()
            || self.report_hold.witness.state != ReportWitnessState::Holding
            || expected.descriptors.is_empty()
            || expected.descriptors.len() > usize::from(defs::QUEUE_SIZE)
            || !expected.gpa.is_multiple_of(4096)
        {
            return Err(
                "child completion requires a fresh hold, bounded report and distinct nonzero seeds"
                    .into(),
            );
        }
        self.report_hold.witness.report = Some(expected);
        self.report_hold.action = Some(ReportAction::Child {
            source_seed,
            seed: child_seed,
        });
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_report_parked(
        &mut self,
        key: BarrierKey,
        cpu_count: usize,
    ) -> Result<(), String> {
        if !self.report_hold.active || self.report_hold.action.is_none() {
            return Ok(());
        }
        if cpu_count == 0
            || self
                .report_hold
                .witness
                .barrier
                .is_some_and(|previous| previous != key)
            || (self.report_hold.witness.parked_cpus != 0
                && self.report_hold.witness.parked_cpus != cpu_count)
        {
            let error = "report witness received inconsistent CPU Park reconciliation".to_string();
            self.report_hold.fail(error.clone());
            return Err(error);
        }
        self.report_hold.witness.barrier = Some(key);
        self.report_hold.witness.parked_cpus = cpu_count;
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_report_witness(&mut self) -> ReportWitness {
        if self.report_hold.active && self.report_hold.witness.state == ReportWitnessState::Holding
        {
            if Instant::now() >= self.report_hold.deadline {
                self.report_hold.fail("report hold deadline expired".into());
            } else if self.callbacks.admission_open() && self.queues.is_some() {
                match self.inspect_report() {
                    Ok(Some(report)) => {
                        if self
                            .report_hold
                            .witness
                            .report
                            .as_ref()
                            .is_some_and(|old| old != &report)
                        {
                            self.report_hold.fail("held report identity changed".into());
                        } else {
                            self.report_hold.witness.report = Some(report);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => self.report_hold.fail(error),
                }
            }
        }
        self.report_hold.witness.clone()
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_release_reports(&mut self) -> Result<(), String> {
        if !self.report_hold.active {
            return Err("no report hold to release".into());
        }
        self.report_hold.active = false;
        self.report_hold.action = None;
        if self.callbacks.admission_open() {
            self.process_and_notify();
            self.callbacks
                .preflight(&self.queues)
                .map_err(|error| format!("report hold drain failed: {error:?}"))?;
        }
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    fn inspect_report(&mut self) -> Result<Option<ReportIdentity>, String> {
        if !self.reporting_negotiated() || !self.callbacks.admission_open() {
            return Err(
                "report inspection requires negotiated reporting and open admission".into(),
            );
        }
        let DeviceState::Activated(memory, _) = &self.device_state else {
            return Err("report inspection requires activated memory".into());
        };
        let queues = self
            .queues
            .as_ref()
            .ok_or("report queues are not available")?;
        let queue = &queues
            .get(FRQ_INDEX)
            .ok_or("missing reporting queue")?
            .queue;
        queue.capture_state().map_err(|error| error.to_string())?;
        if !queue.ready || queue.actual_size() == 0 {
            return Ok(None);
        }
        let avail_idx = queue
            .avail_idx(memory, Ordering::Acquire)
            .map_err(|error| error.to_string())?
            .0;
        let available = avail_idx.wrapping_sub(queue.next_avail.0);
        if available == 0 {
            return Ok(None);
        }
        if available > queue.actual_size() {
            return Err("report availability exceeds queue capacity".into());
        }
        let slot = queue
            .avail_ring
            .checked_add(4 + 2 * u64::from(queue.next_avail.0 % queue.actual_size()))
            .ok_or("report avail address overflow")?;
        std::sync::atomic::fence(Ordering::Acquire);
        let head: u16 = memory.read_obj(slot).map_err(|error| error.to_string())?;
        let chain =
            DescriptorChain::checked_new(memory, queue.desc_table, queue.actual_size(), head)
                .ok_or("invalid held report head")?;
        let snapshot = self
            .descriptors
            .read(chain)
            .map_err(|error| error.to_string())?;
        let mut gpa = None;
        for descriptor in snapshot.descriptors() {
            if descriptor.flags & VIRTQ_DESC_F_WRITE == 0 {
                return Err("held report is not device-writable".into());
            }
            let end = descriptor
                .addr
                .checked_add(u64::from(descriptor.len))
                .ok_or("held report payload overflow")?;
            for other in queues.iter().filter(|other| other.queue.ready) {
                let other = &other.queue;
                let size = u64::from(other.actual_size());
                for (start, length) in [
                    (other.desc_table.0, 16 * size),
                    (other.avail_ring.0, 6 + 2 * size),
                    (other.used_ring.0, 6 + 8 * size),
                ] {
                    let metadata_end =
                        start.checked_add(length).ok_or("queue metadata overflow")?;
                    if descriptor.addr < metadata_end && start < end {
                        return Err("held report overlaps queue metadata".into());
                    }
                }
            }
            let aligned = descriptor
                .addr
                .checked_add(4095)
                .map(|address| address & !4095)
                .ok_or("held report page alignment overflow")?;
            if gpa.is_none()
                && aligned
                    .checked_add(4096)
                    .is_some_and(|page_end| page_end <= end)
            {
                memory
                    .validate_range(vm_memory::GuestAddress(aligned), 4096)
                    .map_err(|error| error.to_string())?;
                gpa = Some(aligned);
            }
        }
        let used_idx: u16 = memory
            .load(
                queue
                    .used_ring
                    .checked_add(2)
                    .ok_or("used index overflow")?,
                Ordering::Acquire,
            )
            .map_err(|error| error.to_string())?;
        if used_idx != queue.next_used.0 {
            return Err("held report used index disagrees with device state".into());
        }
        Ok(Some(ReportIdentity {
            head,
            next_avail: queue.next_avail.0,
            next_used: queue.next_used.0,
            avail_idx,
            used_idx,
            gpa: gpa.ok_or("held report has no complete aligned page")?,
            desc_table: queue.desc_table.0,
            avail_ring: queue.avail_ring.0,
            used_ring: queue.used_ring.0,
            descriptors: snapshot
                .descriptors()
                .iter()
                .map(|descriptor| ReportDescriptor {
                    addr: descriptor.addr,
                    len: descriptor.len,
                    flags: descriptor.flags,
                    next: descriptor.next,
                })
                .collect(),
        }))
    }

    #[cfg(feature = "native-device-probe")]
    fn report_at_quiesce(&mut self, request: BarrierRequest) -> Result<(), String> {
        if self.report_hold.active && self.report_hold.witness.state == ReportWitnessState::Failed {
            return Err("report witness retains an unresolved failure".into());
        }
        if !self.report_hold.active || self.report_hold.action.is_none() {
            return Ok(());
        }
        if self.report_hold.witness.state != ReportWitnessState::Holding
            || self.report_hold.witness.barrier != Some(request.key)
            || self.report_hold.witness.parked_cpus == 0
            || Instant::now() >= self.report_hold.deadline
            || Instant::now() >= request.deadline
        {
            return Err(
                "report witness lacks current all-CPU Park reconciliation or expired".into(),
            );
        }
        self.callbacks
            .preflight(&self.queues)
            .map_err(|error| format!("{error:?}"))?;
        let report = self
            .inspect_report()?
            .ok_or("no genuine available report at quiesce")?;
        if self
            .report_hold
            .witness
            .report
            .as_ref()
            .is_some_and(|expected| expected != &report)
        {
            return Err("held report head, GPA, descriptors or queue state changed".into());
        }
        let memory = match &self.device_state {
            DeviceState::Activated(memory, _) => memory.clone(),
            _ => return Err("report witness has no activated memory".into()),
        };
        let action = self
            .report_hold
            .action
            .take()
            .ok_or("missing report action")?;
        let (seed, child) = match action {
            ReportAction::Source { seed } => {
                if memory.domain().backing_kind() != BackingKind::Boot
                    || memory.domain().tracking_mode() != Some(TrackingMode::Capture)
                {
                    return Err("source report seed requires capture-tracked boot memory".into());
                }
                (seed, false)
            }
            ReportAction::Child { source_seed, seed } => {
                if self.reclaim_status().reason != ReclaimReason::RestoredPrivateMapping
                    || memory.domain().backing_kind() != BackingKind::RestoredPrivate
                    || self.pressure_remapper_present()
                {
                    return Err(
                        "child report witness requires inhibited private memory without remapper"
                            .into(),
                    );
                }
                let mut before = [0; 4096];
                memory
                    .read_slice(&mut before, vm_memory::GuestAddress(report.gpa))
                    .map_err(|error| error.to_string())?;
                if before != [source_seed; 4096] {
                    return Err(
                        "child inherited report page differs from complete source seed".into(),
                    );
                }
                (seed, true)
            }
        };
        memory
            .write_slice(&[seed; 4096], vm_memory::GuestAddress(report.gpa))
            .map_err(|error| error.to_string())?;
        self.report_hold.witness.report = Some(report.clone());
        self.report_hold.witness.seed = Some(seed);
        if child {
            self.report_hold.active = false;
            self.process_and_notify();
            self.report_hold.active = true;
            self.callbacks
                .preflight(&self.queues)
                .map_err(|error| format!("report publication failed: {error:?}"))?;
            let queue = &self
                .queues
                .as_ref()
                .ok_or("missing queues after report completion")?
                .get(FRQ_INDEX)
                .ok_or("missing report queue after completion")?
                .queue;
            let used_after: u16 = memory
                .load(
                    vm_memory::GuestAddress(report.used_ring)
                        .checked_add(2)
                        .ok_or("used index overflow")?,
                    Ordering::Acquire,
                )
                .map_err(|error| error.to_string())?;
            let delta = used_after.wrapping_sub(report.used_idx);
            if delta == 0 || delta > queue.actual_size() || used_after != queue.next_used.0 {
                return Err("report completion did not publish a bounded real used delta".into());
            }
            let entry = vm_memory::GuestAddress(report.used_ring)
                .checked_add(4 + 8 * u64::from(report.next_used % queue.actual_size()))
                .ok_or("used entry overflow")?;
            let used_head: u32 = memory.read_obj(entry).map_err(|error| error.to_string())?;
            let used_len: u32 = memory
                .read_obj(entry.checked_add(4).ok_or("used length overflow")?)
                .map_err(|error| error.to_string())?;
            if used_head != u32::from(report.head) || used_len != 0 {
                return Err("real used entry does not acknowledge the held report head".into());
            }
            self.report_hold.witness.used_after = Some(used_after);
        }
        let mut after = [0; 4096];
        memory
            .read_slice(&mut after, vm_memory::GuestAddress(report.gpa))
            .map_err(|error| error.to_string())?;
        if after != [seed; 4096] {
            return Err("complete report page changed after seed or used publication".into());
        }
        self.report_hold.witness.verified_bytes = after.len();
        self.report_hold.witness.state = if child {
            ReportWitnessState::ChildCompleted
        } else {
            ReportWitnessState::SourceSeeded
        };
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_reporting_queue(&self) -> ReportingQueueObservation {
        let queue = self
            .queues
            .as_ref()
            .and_then(|queues| queues.get(FRQ_INDEX))
            .map(|queue| &queue.queue)
            .filter(|queue| queue.ready);
        ReportingQueueObservation {
            reporting_negotiated: self.acked_features & (1 << uapi::VIRTIO_BALLOON_F_REPORTING)
                != 0,
            ready: queue.is_some(),
            next_used: queue.map(|queue| queue.next_used.0),
            used_ring: queue.map(|queue| queue.used_ring.0),
        }
    }

    #[cfg(target_os = "macos")]
    pub fn set_reclaim_state(&mut self, state: Arc<ReclaimState>) {
        let state = self.reclaim_observer.0.backend.get_or_init(|| state);
        if self.memory_policy.is_none() && self.host_reclaim_enabled && !self.restored_offer {
            self.avail_features = reporting_features(state.is_effective());
        }
    }

    #[cfg(target_os = "macos")]
    pub fn set_host_memory_remapper(&mut self, remapper: Option<Arc<HostMemoryRemapper>>) {
        self.host_memory_remapper = if self.host_reclaim_enabled
            && self.reclaim_status().reason == ReclaimReason::None
            && self
                .reclaim_observer
                .0
                .backend
                .get()
                .is_some_and(|state| state.inhibition().is_none())
        {
            remapper
        } else {
            None
        };
    }

    #[cfg(target_os = "macos")]
    pub fn set_failure_signal(&mut self, event: EventFd, exit_code: Arc<AtomicI32>) {
        self.failure_signal = Some((event, exit_code));
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn fail_vm(&self, reason: &str) {
        error!("balloon: fatal free-page reporting error: {reason}");
        if let Some((event, exit_code)) = &self.failure_signal {
            exit_code.store(1, Ordering::SeqCst);
            if let Err(error) = event.write(1) {
                error!("balloon: failed to signal fatal VM exit: {error}");
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub(crate) fn fail_vm(&self, reason: &str) {
        error!("balloon: fatal free-page reporting error: {reason}");
    }

    pub fn id(&self) -> &str {
        defs::BALLOON_DEV_ID
    }

    fn reporting_negotiated(&self) -> bool {
        self.acked_features & (1 << uapi::VIRTIO_BALLOON_F_REPORTING as u64) != 0
    }

    pub fn process_frq(&mut self) -> Result<bool, String> {
        #[cfg(feature = "native-device-probe")]
        if self.report_hold.active {
            return Ok(false);
        }
        if !self.callbacks.admission_open() {
            return Ok(false);
        }
        if self.callbacks.preflight(&self.queues).is_err() {
            return Err("retained reporting terminality fault".into());
        }
        #[cfg(target_os = "macos")]
        let backend_failures = self
            .reclaim_observer
            .0
            .backend
            .get()
            .map(|state| state.stats().failed_operations);
        let result = self.process_reports();
        if result.is_err() {
            #[cfg(target_os = "macos")]
            let backend_recorded = self
                .reclaim_observer
                .0
                .backend
                .get()
                .map(|state| state.stats().failed_operations)
                != backend_failures;
            #[cfg(not(target_os = "macos"))]
            let backend_recorded = false;
            if !backend_recorded {
                self.reclaim_observer.record_failure();
            }
            self.callbacks.retain_fault(ProviderFault::DeviceState);
            if let Some(queue) = self
                .queues
                .as_mut()
                .and_then(|queues| queues.get_mut(FRQ_INDEX))
            {
                queue.queue.record_processing_failure();
            }
        }
        result
    }

    fn process_reports(&mut self) -> Result<bool, String> {
        let reporting_enabled = self.reporting_negotiated() && self.host_reclaim_enabled;
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return Ok(false);
        };
        let reporting_enabled = reporting_enabled
            && mem.domain().backing_kind() == BackingKind::Boot
            && mem.domain().tracking_mode() == Some(TrackingMode::Disabled);
        let Some(queue) = self
            .queues
            .as_mut()
            .and_then(|queues| queues.get_mut(FRQ_INDEX))
        else {
            return Err("missing free-page reporting queue".into());
        };
        if !queue.queue.ready {
            return Ok(false);
        }
        let mut have_used = false;
        #[cfg(target_os = "macos")]
        let mut prepared = false;
        #[cfg(target_os = "linux")]
        // nix's sysconf/mman modules are not enabled in this crate.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|size| *size != 0)
            .ok_or_else(|| "invalid host page granule".to_string())?;
        while let Some(head) = queue.queue.pop(mem) {
            let index = head.index;
            let snapshot = self
                .descriptors
                .read(head)
                .map_err(|error| format!("invalid free-page report chain: {error}"))?;
            if snapshot
                .descriptors()
                .iter()
                .any(|descriptor| descriptor.flags & VIRTQ_DESC_F_WRITE == 0)
            {
                return Err("free-page report is not device-writable".into());
            }

            if reporting_enabled {
                #[cfg(not(target_os = "macos"))]
                for descriptor in snapshot.descriptors() {
                    mem.try_read_access(
                        descriptor.len as usize,
                        vm_memory::GuestAddress(descriptor.addr),
                        |_, len, _, slice| {
                            #[cfg(target_os = "linux")]
                            if !len.is_multiple_of(page_size)
                                || !(slice.as_ptr() as usize).is_multiple_of(page_size)
                            {
                                return Err(vm_memory::GuestMemoryError::IOError(
                                    std::io::Error::other(
                                        "reported range is not host-page aligned",
                                    ),
                                ));
                            }
                            #[cfg(not(target_os = "linux"))]
                            let _ = slice;
                            Ok(len)
                        },
                    )
                    .map_err(|error| format!("invalid reported range: {error}"))?;
                }

                #[cfg(target_os = "macos")]
                if let Some(state) = self.reclaim_observer.0.backend.get() {
                    if !prepared && let Some(remapper) = &self.host_memory_remapper {
                        // The callback owner retains registered RAM throughout normalization.
                        unsafe { remapper.before_reports() }.map_err(|error| error.to_string())?;
                        prepared = true;
                    }
                    for range in
                        coalesce_free_page_ranges(snapshot.descriptors().iter().map(|descriptor| {
                            (vm_memory::GuestAddress(descriptor.addr), descriptor.len)
                        }))
                    {
                        let len = usize::try_from(range.byte_len())
                            .map_err(|_| "reported range exceeds host address space".to_string())?;
                        let _write = mem
                            .write(vm_memory::GuestAddress(range.start()), len)
                            .map_err(|error| format!("invalid reported range: {error}"))?;
                        match state.release_report(range) {
                            Ok(ReleaseOutcome::Released | ReleaseOutcome::Skipped) => {}
                            Err(error) => return Err(error.to_string()),
                        }
                    }
                }

                #[cfg(not(target_os = "macos"))]
                for descriptor in snapshot.descriptors() {
                    mem.try_write_access(
                        descriptor.len as usize,
                        vm_memory::GuestAddress(descriptor.addr),
                        |_, len, _, slice| {
                            let host = slice.as_mut_ptr();
                            #[cfg(target_os = "linux")]
                            {
                                // nix::sys::mman is not enabled in this crate's existing feature set.
                                let result =
                                    unsafe { libc::madvise(host.cast(), len, libc::MADV_DONTNEED) };
                                if result != 0 {
                                    return Err(vm_memory::GuestMemoryError::IOError(
                                        std::io::Error::last_os_error(),
                                    ));
                                }
                            }
                            #[cfg(target_os = "windows")]
                            {
                                let result = unsafe { DiscardVirtualMemory(host.cast(), len) };
                                if result != 0 {
                                    return Err(vm_memory::GuestMemoryError::IOError(
                                        std::io::Error::from_raw_os_error(result as i32),
                                    ));
                                }
                            }
                            self.reclaim_observer.record_release(len);
                            Ok(len)
                        },
                    )
                    .map_err(|error| format!("failed report discard: {error}"))?;
                }
            }
            queue
                .queue
                .add_used(mem, index, 0)
                .map_err(|error| format!("failed to publish used report: {error}"))?;
            if !reporting_enabled {
                self.reclaim_observer.record_skip();
            }
            have_used = true;
        }
        queue
            .queue
            .capture_state()
            .map_err(|error| format!("invalid reporting queue state: {error}"))?;
        Ok(have_used)
    }

    pub(crate) fn process_and_notify(&mut self) {
        let result = self.process_frq();
        match result {
            Ok(true) => {
                let result = match (&self.device_state, self.queues.as_mut()) {
                    (DeviceState::Activated(memory, interrupt), Some(queues)) => queues[FRQ_INDEX]
                        .queue
                        .needs_notification(memory)
                        .map_err(|_| ProviderFault::QueueState)
                        .and_then(|needed| {
                            if needed {
                                interrupt
                                    .try_signal_used_queue()
                                    .map_err(|_| ProviderFault::Notification)
                            } else {
                                Ok(())
                            }
                        }),
                    _ => Err(ProviderFault::DeviceState),
                };
                if let Err(fault) = result {
                    self.callbacks.retain_fault(fault);
                    self.fail_vm("free-page report notification failed");
                }
            }
            Ok(false) => {}
            Err(error) => self.fail_vm(&error),
        }
    }

    pub fn restore_queue_config() -> &'static [crate::virtio::QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    pub fn inspect_restore_payload(payload: &[u8], available: u64) -> Result<(), ProviderFault> {
        if available != reporting_features(true) && available != reporting_features(false) {
            return Err(ProviderFault::Unsupported);
        }
        Self::decode_payload_features(payload, available).map(|_| ())
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<(u64, VirtioBalloonConfig), ProviderFault> {
        Self::decode_payload_features(payload, self.avail_features)
    }

    fn decode_payload_features(
        payload: &[u8],
        available: u64,
    ) -> Result<(u64, VirtioBalloonConfig), ProviderFault> {
        let mut reader = Reader::new(payload);
        let decoded = (|| {
            reader.header(BALLOON_STATE_MAGIC, BALLOON_STATE_SCHEMA)?;
            if reader.u16()? != 1
                || reader.u32()? != uapi::VIRTIO_ID_BALLOON
                || reader.u64()? != available
            {
                return Err(utils::state::Error::Invalid("balloon profile"));
            }
            let acked = reader.u64()?;
            if acked & !available != 0 {
                return Err(utils::state::Error::Invalid("balloon features"));
            }
            let config = VirtioBalloonConfig {
                num_pages: reader.u32()?,
                actual: reader.u32()?,
                free_page_report_cmd_id: reader.u32()?,
                poison_val: reader.u32()?,
            };
            reader.finish()?;
            Ok((acked, config))
        })();
        decoded.map_err(ProviderFault::from)
    }
}

/// Merges the descriptors of one free-page report into maximal contiguous
/// guest ranges, dropping descriptors that are empty or overflow.
#[cfg(target_os = "macos")]
fn coalesce_free_page_ranges(
    descriptors: impl IntoIterator<Item = (vm_memory::GuestAddress, u32)>,
) -> Vec<GuestRange> {
    let mut spans: Vec<(u64, u64)> = descriptors
        .into_iter()
        .filter_map(|(address, len)| {
            let start = address.raw_value();
            let end = start.checked_add(u64::from(len))?;
            (end > start).then_some((start, end))
        })
        .collect();
    spans.sort_unstable();
    let mut runs: Vec<GuestRange> = Vec::with_capacity(spans.len());
    let mut current: Option<(u64, u64)> = None;
    for (start, end) in spans {
        match current {
            Some((run_start, run_end)) if start <= run_end => {
                current = Some((run_start, run_end.max(end)));
            }
            Some((run_start, run_end)) => {
                runs.extend(GuestRange::new(run_start, run_end - run_start).ok());
                current = Some((start, end));
            }
            None => current = Some((start, end)),
        }
    }
    if let Some((run_start, run_end)) = current {
        runs.extend(GuestRange::new(run_start, run_end - run_start).ok());
    }
    runs
}

impl VirtioDevice for Balloon {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_BALLOON
    }

    fn device_name(&self) -> &str {
        "balloon"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        let count = data.len().min(config_slice.len() - offset as usize);
        data[..count].copy_from_slice(&config_slice[offset as usize..offset as usize + count]);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "balloon: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.bind_reclaim_domain(mem.domain());
        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn state_provider(&self) -> Option<&dyn VirtioStateProvider> {
        Some(self)
    }

    fn state_provider_mut(&mut self) -> Option<&mut dyn VirtioStateProvider> {
        Some(self)
    }
}

impl VirtioStateProvider for Balloon {
    fn preflight(&self) -> Result<(), ProviderFault> {
        self.callbacks.preflight(&self.queues)?;
        if self.is_activated()
            && self
                .queues
                .as_ref()
                .is_some_and(|queues| queues.len() != defs::NUM_QUEUES)
        {
            return Err(ProviderFault::QueueCount);
        }
        Ok(())
    }

    fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError> {
        #[cfg(feature = "native-device-probe")]
        if let Err(error) = self.report_at_quiesce(request) {
            self.report_hold.fail(error);
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::DeviceState,
            });
        }
        self.callbacks.begin_quiesce(request, &mut self.queues)
    }

    fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.callbacks.poll_quiesce(key, &mut self.queues)
    }
    fn validate_terminal_drain(&self, key: BarrierKey) -> Result<(), ProviderFault> {
        self.callbacks.validate_terminal_drain(key, &self.queues)?;
        self.preflight()
    }

    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance {
        let count = if self.is_activated() {
            defs::NUM_QUEUES
        } else {
            0
        };
        let acceptance = self
            .callbacks
            .begin_resume(request, queues, &mut self.queues, count);
        if !matches!(acceptance, ResumeAcceptance::Accepted) {
            return acceptance;
        }
        if self.is_activated() {
            if self.activate_evt.write(1).is_err() {
                self.callbacks.retain_fault(ProviderFault::Notification);
                return ResumeAcceptance::AcceptedWithFailure(ProviderFault::Notification);
            }
            self.process_and_notify();
            if let Err(fault) = self.callbacks.preflight(&self.queues) {
                self.callbacks.retain_fault(fault);
                return ResumeAcceptance::AcceptedWithFailure(fault);
            }
        }
        ResumeAcceptance::Accepted
    }

    fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        self.callbacks.preflight(&self.queues)?;
        self.callbacks.poll_resume(key)
    }

    fn state_limit(&self) -> u32 {
        4096
    }

    fn capture_payload(&self, key: BarrierKey) -> Result<Vec<u8>, ProviderFault> {
        self.callbacks.require_cut(key)?;
        let mut writer = Writer::new(self.state_limit() as usize);
        writer
            .header(BALLOON_STATE_MAGIC, BALLOON_STATE_SCHEMA)
            .map_err(ProviderFault::from)?;
        writer
            .u16(1)
            .and_then(|()| writer.u32(uapi::VIRTIO_ID_BALLOON))
            .and_then(|()| writer.u64(self.avail_features))
            .and_then(|()| writer.u64(self.acked_features))
            .and_then(|()| writer.u32(self.config.num_pages))
            .and_then(|()| writer.u32(self.config.actual))
            .and_then(|()| writer.u32(self.config.free_page_report_cmd_id))
            .and_then(|()| writer.u32(self.config.poison_val))
            .map_err(|_| ProviderFault::DeviceState)?;
        Ok(writer.finish())
    }

    fn validate_payload(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.decode_payload(payload).map(|_| ())
    }

    fn validate_restore(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        if self.is_activated() || self.queues.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.validate_payload(payload)
    }

    fn apply_payload(&mut self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.callbacks.require_quiesced()?;
        let (acked, config) = self.decode_payload(payload)?;
        self.acked_features = acked;
        self.config = config;
        Ok(())
    }

    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        let (acked, config) = self.decode_payload(payload)?;
        self.callbacks.prepare_restore(request)?;
        match context.reclaim_policy {
            RestoredReclaimPolicy::Disabled => self.host_reclaim_enabled = false,
        }
        self.acked_features = acked;
        self.bind_reclaim_domain(context.memory.domain());
        self.config = config;
        self.device_state = if context.activated {
            DeviceState::Activated(context.memory, context.interrupt)
        } else {
            DeviceState::Inactive
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::VirtioDevice;
    use crate::virtio::balloon::defs::uapi;
    use crate::virtio::balloon::device::Balloon;

    #[cfg(target_os = "macos")]
    #[test]
    fn free_page_ranges_coalesce_adjacent_descriptors_in_any_order() {
        use vm_memory::GuestAddress;

        use crate::virtio::balloon::device::coalesce_free_page_ranges;

        let mib = 2 * 1024 * 1024;
        let runs = coalesce_free_page_ranges([
            (GuestAddress(4 * mib), mib as u32),
            (GuestAddress(0), mib as u32),
            (GuestAddress(mib), mib as u32),
            (GuestAddress(8 * mib), 0),
            (GuestAddress(u64::MAX - 1), 16),
            (GuestAddress(5 * mib), mib as u32),
        ]);
        let spans: Vec<(u64, u64)> = runs
            .iter()
            .map(|range| (range.start(), range.byte_len()))
            .collect();
        assert_eq!(spans, vec![(0, 2 * mib), (4 * mib, 2 * mib)]);
    }

    #[test]
    fn reporting_selection_preserves_unrelated_features() {
        use crate::virtio::balloon::device::{AVAIL_FEATURES, reporting_features};
        let reporting = 1 << uapi::VIRTIO_BALLOON_F_REPORTING;
        assert_eq!(reporting_features(true), AVAIL_FEATURES);
        assert_eq!(reporting_features(false), AVAIL_FEATURES & !reporting);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unqualified_balloon_does_not_advertise_reporting() {
        use hvf::reclaim::ReclaimState;
        use std::sync::Arc;
        let mut balloon = Balloon::new().unwrap();
        let reporting = 1 << uapi::VIRTIO_BALLOON_F_REPORTING;
        assert_eq!(balloon.avail_features() & reporting, 0);
        let state = Arc::new(ReclaimState::new());
        state.set_policy_enabled(true);
        balloon.set_reclaim_state(state);
        assert_eq!(balloon.avail_features() & reporting, 0);
        assert_ne!(
            balloon.avail_features() & (1 << uapi::VIRTIO_BALLOON_F_STATS_VQ),
            0
        );
    }

    #[test]
    fn free_page_reporting_requires_feature_negotiation() {
        let mut balloon = Balloon::new().unwrap();
        assert!(!balloon.reporting_negotiated());

        balloon.set_acked_features(1 << uapi::VIRTIO_BALLOON_F_REPORTING);
        assert!(balloon.reporting_negotiated());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fatal_reporting_error_signals_vm_exit() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicI32, Ordering};

        use utils::eventfd::{EFD_NONBLOCK, EventFd};

        let mut balloon = Balloon::new().unwrap();
        let event = EventFd::new(EFD_NONBLOCK).unwrap();
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        balloon.set_failure_signal(event.try_clone().unwrap(), exit_code.clone());

        balloon.fail_vm("test failure");

        assert_eq!(exit_code.load(Ordering::SeqCst), 1);
        assert_eq!(event.read().unwrap(), 1);
    }

    fn request(operation: u64) -> polly::event_manager::BarrierRequest {
        use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
        use std::time::{Duration, Instant};
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(11),
            },
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    #[test]
    fn provider_balloon_config_codec_is_exact_and_bounded() {
        use crate::virtio::lifecycle::VirtioStateProvider;
        use std::task::Poll;
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon.config.num_pages = 17;
        balloon.config.actual = 13;
        balloon.config.free_page_report_cmd_id = 0x12345678;
        balloon.config.poison_val = 0x87654321;
        balloon.begin_quiesce(request(1)).unwrap();
        assert!(matches!(
            balloon.poll_quiesce(request(1).key).unwrap(),
            Poll::Ready(_)
        ));
        let payload = balloon.capture_payload(request(1).key).unwrap();
        use crate::virtio::lifecycle::ProviderFault;
        use utils::state::StateHeaderError;
        assert_eq!(&payload[..10], b"KRUNBALL\x01\x00");
        let mut wrong_magic = payload.clone();
        wrong_magic[0] ^= 1;
        assert!(matches!(
            balloon.validate_payload(&wrong_magic),
            Err(ProviderFault::StateHeader(StateHeaderError::Magic { .. }))
        ));
        let mut wrong_schema = payload.clone();
        wrong_schema[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            balloon.validate_payload(&wrong_schema),
            Err(ProviderFault::StateHeader(StateHeaderError::Schema { expected: 1, found: 2 }))
        );
        balloon.validate_payload(&payload).unwrap();
        let (acked, decoded) = balloon.decode_payload(&payload).unwrap();
        assert_eq!(acked, balloon.acked_features());
        assert_eq!(
            [
                decoded.num_pages,
                decoded.actual,
                decoded.free_page_report_cmd_id,
                decoded.poison_val,
            ],
            [17, 13, 0x12345678, 0x87654321]
        );
        assert_eq!(payload.len(), 48);
        let mut config = [0; 16];
        balloon.read_config(0, &mut config);
        assert_eq!(&payload[32..], &config);
        for length in 0..payload.len() {
            assert!(balloon.validate_payload(&payload[..length]).is_err());
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(balloon.validate_payload(&trailing).is_err());
        let mut wrong_features = payload.clone();
        wrong_features[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(balloon.validate_payload(&wrong_features).is_err());
        assert!(balloon.capture_payload(request(2).key).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_real_report_cut_keeps_stats_and_restored_reclaim_disabled() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::{FRQ_INDEX, STQ_INDEX};
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
        };
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use std::task::Poll;
        use utils::eventfd::{EFD_NONBLOCK, EventFd};
        use vm_memory::GuestAddress;

        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let child_report_address = GuestAddress((10 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        rings[STQ_INDEX].dtable[0].set(0x9000, 16, 0, 0);
        rings[STQ_INDEX].avail.ring[0].set(0);
        rings[STQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let interrupt = || {
            InterruptTransport::new(
                DummyIrqChip::new().into(),
                "balloon-provider-test".into(),
                None,
            )
            .unwrap()
        };
        let mut source = Balloon::new().unwrap();
        source.set_acked_features(source.avail_features());
        source
            .activate(
                memory.clone(),
                interrupt(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(
                            ring.create_queue(),
                            Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                        )
                    })
                    .collect(),
            )
            .unwrap();
        assert!(source.process_frq().unwrap());
        let mut contents = vec![1u8; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
        source.begin_quiesce(request(1)).unwrap();
        let Poll::Ready(completion) = source.poll_quiesce(request(1).key).unwrap() else {
            panic!("missing callback queues")
        };
        assert_eq!(completion.queues.len(), 5);
        assert!(completion.fault.is_none());
        assert_eq!(
            completion.queues[FRQ_INDEX]
                .queue
                .capture_state()
                .unwrap()
                .next_used,
            1
        );
        assert_eq!(
            completion.queues[STQ_INDEX]
                .queue
                .capture_state()
                .unwrap()
                .next_avail,
            0
        );
        assert_eq!(rings[STQ_INDEX].used.idx.get(), 0);
        let payload = source.capture_payload(request(1).key).unwrap();

        let child_memory =
            RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let child_rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &child_memory, 8))
            .collect();
        let mut cut = vec![0u8; 16 * page_size];
        memory.read_slice(&mut cut, GuestAddress(0)).unwrap();
        child_memory.write_slice(&cut, GuestAddress(0)).unwrap();
        child_memory
            .write_slice(&vec![0xa5; page_size], child_report_address)
            .unwrap();
        child_rings[FRQ_INDEX].dtable[1].set(child_report_address.0, page_size as u32, 2, 0);
        child_rings[FRQ_INDEX].avail.ring[1].set(1);
        child_rings[FRQ_INDEX].avail.idx.set(2);
        let mut destination = Balloon::new().unwrap();
        destination
            .prepare_restore(
                request(1),
                &payload,
                DormantDeviceContext {
                    memory: child_memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert_eq!(destination.avail_features(), source.avail_features());
        assert_eq!(destination.acked_features(), source.acked_features());
        assert!(!destination.host_reclaim_enabled);
        assert_eq!(
            destination.activate_evt.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!destination.process_frq().unwrap());
        assert_eq!(child_rings[FRQ_INDEX].used.idx.get(), 1);
        let child_queues = completion
            .queues
            .iter()
            .zip(&child_rings)
            .map(|(saved, ring)| {
                let mut queue = ring.create_queue();
                queue.apply_state(&saved.queue.capture_state().unwrap());
                DeviceQueue::new(queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
            })
            .collect();
        assert!(matches!(
            destination.begin_resume(request(2), child_queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(child_rings[FRQ_INDEX].used.idx.get(), 2);
        child_memory
            .read_slice(&mut contents, child_report_address)
            .unwrap();
        assert_eq!(contents, vec![0xa5; page_size]);
        assert_eq!(child_rings[STQ_INDEX].used.idx.get(), 0);
        assert!(matches!(
            source.begin_resume(request(2), completion.queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            source.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_report_effect_with_failed_used_publication_stays_faulted() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut queues: Vec<_> = rings
            .iter()
            .map(|ring| DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap())))
            .collect();
        queues[FRQ_INDEX].queue.used_ring = GuestAddress((32 * page_size) as u64);
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-fault-test".into(),
                    None,
                )
                .unwrap(),
                queues,
            )
            .unwrap();
        assert!(balloon.process_frq().is_err());
        let mut contents = vec![1u8; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0; page_size]);
        assert!(balloon.preflight().is_err());
        let queue = &balloon.queues.as_ref().unwrap()[FRQ_INDEX].queue;
        assert_eq!(queue.next_avail.0, 1);
        assert_eq!(queue.next_used.0, 0);
        assert!(queue.capture_state().is_err());
        assert!(!balloon.process_frq().unwrap());
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        balloon.begin_quiesce(request(1)).unwrap();
        let std::task::Poll::Ready(completion) = balloon.poll_quiesce(request(1).key).unwrap()
        else {
            panic!("fault cleanup lost queues");
        };
        assert!(completion.fault.is_some());
        assert_eq!(completion.queues.len(), 5);
        assert!(completion.queues[FRQ_INDEX].queue.capture_state().is_err());
        assert!(balloon.capture_payload(request(1).key).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_short_report_never_discards_bytes_outside_its_range() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32 - 1, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-range-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            )
            .unwrap();
        assert!(balloon.process_frq().is_err());
        let mut contents = vec![0; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0x5a; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        assert!(balloon.preflight().is_err());
    }

    #[test]
    fn provider_balloon_restore_binding_preserves_offer_without_reclaim_grant() {
        use crate::virtio::balloon::device::reporting_features;
        for reporting in [false, true] {
            let features = reporting_features(reporting);
            let mut balloon = Balloon::new_restore_binding(features).unwrap();
            assert_eq!(balloon.avail_features(), features);
            balloon
                .finalize_memory_policy(
                    crate::virtio::balloon::BalloonMemoryPolicy::RestoredPrivate,
                )
                .unwrap();
            assert_eq!(balloon.avail_features(), features);
            assert!(
                balloon
                    .finalize_memory_policy(crate::virtio::balloon::BalloonMemoryPolicy::Untracked,)
                    .is_err()
            );
            assert!(!balloon.host_reclaim_enabled);
            balloon.set_acked_features(features);
            assert_eq!(balloon.acked_features(), features);
            #[cfg(target_os = "macos")]
            {
                use hvf::reclaim::ReclaimState;
                use std::sync::Arc;
                balloon.set_reclaim_state(Arc::new(ReclaimState::new()));
                assert_eq!(balloon.avail_features(), features);
                assert!(!balloon.host_reclaim_enabled);
            }
        }
        assert!(Balloon::new_restore_binding(u64::MAX).is_err());
    }

    #[test]
    fn memory_policy_finalization_is_one_shot_and_precedes_negotiation() {
        use crate::virtio::balloon::BalloonMemoryPolicy;
        for policy in [
            BalloonMemoryPolicy::TrackedCapture,
            BalloonMemoryPolicy::RestoredPrivate,
        ] {
            let mut balloon = Balloon::new().unwrap();
            balloon.finalize_memory_policy(policy).unwrap();
            assert!(!balloon.host_reclaim_enabled);
            assert_ne!(
                balloon.avail_features() & (1 << uapi::VIRTIO_BALLOON_F_REPORTING),
                0
            );
            assert!(
                balloon
                    .finalize_memory_policy(BalloonMemoryPolicy::Untracked)
                    .is_err()
            );
            assert!(!balloon.host_reclaim_enabled);
        }
        let mut ordinary = Balloon::new().unwrap();
        ordinary
            .finalize_memory_policy(BalloonMemoryPolicy::Untracked)
            .unwrap();
        assert!(ordinary.host_reclaim_enabled);
        let mut negotiated = Balloon::new().unwrap();
        negotiated.set_acked_features(negotiated.avail_features());
        assert!(
            negotiated
                .finalize_memory_policy(BalloonMemoryPolicy::TrackedCapture)
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_file_reports_acknowledge_without_resurrecting_baseline_bytes() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::BalloonMemoryPolicy;
        use crate::virtio::balloon::device::{FRQ_INDEX, reporting_features};
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use arch::guest_memory::{BackingKind, MemoryDomain};
        use nix::fcntl::{FcntlArg, SealFlag, fcntl};
        use nix::sys::memfd::{MFdFlags, memfd_create};
        use std::fs::File;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::{FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

        for restore_binding in [false, true] {
            let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
            let len = 16 * page_size;
            let report_address = GuestAddress((8 * page_size) as u64);
            let file = File::from(
                memfd_create(
                    "balloon-private-baseline",
                    MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
                )
                .unwrap(),
            );
            file.set_len(len as u64).unwrap();
            file.write_all_at(&vec![0x6b; page_size], report_address.0)
                .unwrap();
            fcntl(
                &file,
                FcntlArg::F_ADD_SEALS(
                    SealFlag::F_SEAL_WRITE
                        | SealFlag::F_SEAL_GROW
                        | SealFlag::F_SEAL_SHRINK
                        | SealFlag::F_SEAL_SEAL,
                ),
            )
            .unwrap();
            let baseline =
                Arc::new(File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap());
            let sibling = GuestMemoryMmap::from_regions(vec![
                GuestRegionMmap::new(
                    MmapRegion::<()>::build(
                        Some(FileOffset::from_arc(baseline.clone(), 0)),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE,
                    )
                    .unwrap(),
                    GuestAddress(0),
                )
                .unwrap(),
            ])
            .unwrap();
            let mapping = MmapRegion::build(
                Some(FileOffset::from_arc(baseline.clone(), 0)),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
            )
            .unwrap();
            let raw = GuestMemoryMmap::from_regions(vec![
                GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap(),
            ])
            .unwrap();
            let (domain, authority, mut control) =
                MemoryDomain::construct(raw, page_size as u32, BackingKind::RestoredPrivate)
                    .unwrap();
            let epoch = authority.issue_epoch(1).unwrap();
            control.finish_tracked(authority, epoch).unwrap();
            let memory = RuntimeGuestMemory::new(domain);
            let rings: Vec<_> = (0..5)
                .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
                .collect();
            rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 2, 0);
            rings[FRQ_INDEX].avail.ring[0].set(0);
            rings[FRQ_INDEX].avail.idx.set(1);
            memory
                .write_slice(&vec![0xa5; page_size], report_address)
                .unwrap();
            let mut balloon = if restore_binding {
                let mut balloon = Balloon::new_restore_binding(reporting_features(true)).unwrap();
                balloon
                    .finalize_memory_policy(BalloonMemoryPolicy::RestoredPrivate)
                    .unwrap();
                balloon
            } else {
                let mut balloon = Balloon::new().unwrap();
                balloon
                    .finalize_memory_policy(BalloonMemoryPolicy::Untracked)
                    .unwrap();
                assert!(balloon.host_reclaim_enabled);
                balloon
            };
            balloon.set_acked_features(balloon.avail_features());
            balloon
                .activate(
                    memory.clone(),
                    InterruptTransport::new(
                        DummyIrqChip::new().into(),
                        "balloon-private-test".into(),
                        None,
                    )
                    .unwrap(),
                    rings
                        .iter()
                        .map(|ring| {
                            DeviceQueue::new(
                                ring.create_queue(),
                                Arc::new(EventFd::new(0).unwrap()),
                            )
                        })
                        .collect(),
                )
                .unwrap();
            let observer = balloon.reclaim_observer();
            assert!(balloon.process_frq().unwrap());
            assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
            let mut contents = vec![0; page_size];
            memory.read_slice(&mut contents, report_address).unwrap();
            assert_eq!(contents, vec![0xa5; page_size]);
            baseline
                .read_exact_at(&mut contents, report_address.0)
                .unwrap();
            assert_eq!(contents, vec![0x6b; page_size]);
            memory
                .write_slice(&vec![0x3c; page_size], report_address)
                .unwrap();
            rings[FRQ_INDEX].avail.ring[1].set(0);
            rings[FRQ_INDEX].avail.idx.set(2);
            assert!(balloon.process_frq().unwrap());
            assert_eq!(rings[FRQ_INDEX].used.idx.get(), 2);
            memory.read_slice(&mut contents, report_address).unwrap();
            assert_eq!(contents, vec![0x3c; page_size]);
            use vm_memory::Bytes;
            sibling.read_slice(&mut contents, report_address).unwrap();
            assert_eq!(contents, vec![0x6b; page_size]);
            baseline
                .read_exact_at(&mut contents, report_address.0)
                .unwrap();
            assert_eq!(contents, vec![0x6b; page_size]);
            let status = observer.status();
            assert_eq!(
                status.backing,
                crate::virtio::balloon::ReclaimBacking::RestoredPrivate
            );
            assert_eq!(
                status.reason,
                crate::virtio::balloon::ReclaimReason::RestoredPrivateMapping
            );
            assert_eq!(
                status.qualification,
                crate::virtio::balloon::ReclaimQualification::NotRun
            );
            assert!(!status.requested);
            assert!(!status.effective);
            assert_eq!(status.released_bytes, 0);
            assert_eq!(status.released_extents, 0);
            assert_eq!(status.skipped_reports, 2);
            assert_eq!(status.failed_operations, 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tracked_source_reports_keep_bytes_and_dirty_only_queue_completion() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::BalloonMemoryPolicy;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use arch::guest_memory::{BackingKind, DirtyPageMap, MemoryDomain, PageIndex};
        use std::sync::Arc;
        use std::task::Poll;
        use utils::eventfd::EventFd;
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, page_size as u32, BackingKind::Boot).unwrap();
        let memory = RuntimeGuestMemory::new(domain.clone());
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        let report_address = GuestAddress((8 * page_size) as u64);
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 3, 1);
        rings[FRQ_INDEX].dtable[1].set(report_address.0 + page_size as u64, page_size as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let epoch = authority.issue_epoch(1).unwrap();
        control.finish_tracked(authority, epoch).unwrap();
        let mut balloon = Balloon::new().unwrap();
        #[cfg(feature = "native-device-probe")]
        {
            let observed = balloon.pressure_reporting_queue();
            assert!(!observed.reporting_negotiated);
            assert!(!observed.ready);
            assert_eq!(observed.next_used, None);
            assert_eq!(observed.used_ring, None);
        }
        balloon
            .finalize_memory_policy(BalloonMemoryPolicy::TrackedCapture)
            .unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-tracked-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            )
            .unwrap();
        #[cfg(feature = "native-device-probe")]
        {
            let observed = balloon.pressure_reporting_queue();
            assert!(observed.reporting_negotiated);
            assert!(observed.ready);
            assert_eq!(observed.next_used, Some(0));
            assert!(observed.used_ring.is_some());
        }
        assert!(balloon.process_frq().unwrap());
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
        #[cfg(feature = "native-device-probe")]
        {
            let observed = balloon.pressure_reporting_queue();
            assert!(observed.reporting_negotiated);
            assert!(observed.ready);
            assert_eq!(observed.next_used, Some(rings[FRQ_INDEX].used.idx.get()));
        }
        let mut contents = vec![0; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0x5a; page_size]);
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("report completion retained a writer");
        };
        let cut = control.seal(&drained).unwrap();
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 1);
        assert!(dirty.contains(PageIndex::new(0x4000 / page_size)));
        assert!(!dirty.contains(PageIndex::new(8)));
        let status = balloon.reclaim_status();
        assert_eq!(status.backing, crate::virtio::balloon::ReclaimBacking::Boot);
        assert_eq!(
            status.reason,
            crate::virtio::balloon::ReclaimReason::TrackedCapture
        );
        assert!(!status.requested);
        assert!(!status.effective);
        assert_eq!(status.skipped_reports, 1);
        assert_eq!(status.released_bytes, 0);
        assert_eq!(status.released_extents, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_unready_saved_report_queue_never_discards_or_publishes() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
        };
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use std::task::Poll;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut queues: Vec<_> = rings
            .iter()
            .map(|ring| DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap())))
            .collect();
        queues[FRQ_INDEX].queue.ready = false;
        let saved = queues[FRQ_INDEX].queue.capture_state().unwrap();
        let interrupt = || {
            InterruptTransport::new(
                DummyIrqChip::new().into(),
                "balloon-unready-test".into(),
                None,
            )
            .unwrap()
        };
        let mut source = Balloon::new().unwrap();
        source.set_acked_features(source.avail_features());
        source
            .activate(memory.clone(), interrupt(), queues)
            .unwrap();
        assert!(!source.process_frq().unwrap());
        source.begin_quiesce(request(1)).unwrap();
        let Poll::Ready(completion) = source.poll_quiesce(request(1).key).unwrap() else {
            panic!("unready queue was lost");
        };
        let payload = source.capture_payload(request(1).key).unwrap();
        let mut destination = Balloon::new_restore_binding(source.avail_features()).unwrap();
        destination
            .prepare_restore(
                request(1),
                &payload,
                DormantDeviceContext {
                    memory: memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        let fresh = completion
            .queues
            .iter()
            .zip(&rings)
            .map(|(queue, ring)| {
                let mut fresh = ring.create_queue();
                fresh.apply_state(&queue.queue.capture_state().unwrap());
                DeviceQueue::new(fresh, Arc::new(EventFd::new(0).unwrap()))
            })
            .collect();
        assert!(matches!(
            destination.begin_resume(request(2), fresh),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert!(!destination.process_frq().unwrap());
        assert_eq!(
            destination.queues.as_ref().unwrap()[FRQ_INDEX]
                .queue
                .capture_state()
                .unwrap(),
            saved
        );
        let mut contents = vec![0; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0x5a; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        destination.preflight().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_snapshot_rejects_tail_cycle_before_any_discard() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 3, 1);
        rings[FRQ_INDEX].dtable[1].set(report_address.0, page_size as u32, 3, 1);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-cycle-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            )
            .unwrap();
        assert!(balloon.process_frq().is_err());
        let mut contents = vec![0; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0x5a; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        assert!(balloon.preflight().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_report_spanning_adjacent_regions_discards_both_before_used() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[
            (GuestAddress(0), 9 * page_size),
            (GuestAddress((9 * page_size) as u64), 7 * page_size),
        ])
        .unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, (2 * page_size) as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; 2 * page_size], report_address)
            .unwrap();
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-regions-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            )
            .unwrap();
        assert!(balloon.process_frq().unwrap());
        let mut contents = vec![1; 2 * page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0; 2 * page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
        balloon.preflight().unwrap();
        assert!(!balloon.process_frq().unwrap());
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn provider_balloon_activation_registers_all_real_queue_subscribers() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use polly::event_manager::{EventManager, Subscriber};
        use std::os::unix::io::AsRawFd;
        use std::sync::{Arc, Mutex};
        use utils::epoll::{EpollEvent, EventSet};
        use utils::eventfd::{EFD_NONBLOCK, EventFd};
        use vm_memory::GuestAddress;
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        let events: Vec<_> = (0..5)
            .map(|_| Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
            .collect();
        let source = Arc::new(Mutex::new(Balloon::new().unwrap()));
        let subscriber: Arc<Mutex<dyn Subscriber>> = source.clone();
        let mut manager = EventManager::new().unwrap();
        manager.add_subscriber(subscriber.clone()).unwrap();
        let existing_fd = events[0].as_raw_fd();
        manager
            .register(
                existing_fd,
                EpollEvent::new(EventSet::IN, existing_fd as u64),
                subscriber.clone(),
            )
            .unwrap();
        let mut balloon = match source.lock() {
            Ok(device) => device,
            Err(error) => panic!("balloon lock poisoned: {error}"),
        };
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-registration-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .zip(&events)
                    .map(|(ring, event)| DeviceQueue::new(ring.create_queue(), event.clone()))
                    .collect(),
            )
            .unwrap();
        let activation_fd = balloon.activate_evt.as_raw_fd();
        balloon.process(
            &EpollEvent::new(EventSet::IN, activation_fd as u64),
            &mut manager,
        );
        for event in events {
            assert!(Arc::ptr_eq(
                &manager.subscriber(event.as_raw_fd()).unwrap(),
                &subscriber
            ));
        }
        assert!(manager.subscriber(activation_fd).is_err());
        balloon.preflight().unwrap();
    }

    #[cfg(target_os = "linux")]
    fn activate_report_fixture(
        balloon: &mut Balloon,
        memory: &crate::virtio::RuntimeGuestMemory,
        queues: Vec<crate::virtio::DeviceQueue>,
    ) {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::InterruptTransport;
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-report-test".into(),
                    None,
                )
                .unwrap(),
                queues,
            )
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn anonymous_reports_preserve_real_advice_and_count_repeated_ranges() {
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::balloon::{BalloonMemoryPolicy, ReclaimQualification, ReclaimReason};
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|i| VirtQueue::new(GuestAddress(i * 0x1000), &memory, 8))
            .collect();
        let address = GuestAddress((8 * page) as u64);
        rings[FRQ_INDEX].dtable[0].set(address.0, page as u32, 2, 0);
        let mut balloon = Balloon::new().unwrap();
        balloon
            .finalize_memory_policy(BalloonMemoryPolicy::Untracked)
            .unwrap();
        activate_report_fixture(
            &mut balloon,
            &memory,
            rings
                .iter()
                .map(|ring| {
                    DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                })
                .collect(),
        );
        let observer = balloon.reclaim_observer();
        for (slot, value) in [0xa5, 0x3c].into_iter().enumerate() {
            memory.write_slice(&vec![value; page], address).unwrap();
            rings[FRQ_INDEX].avail.ring[slot].set(0);
            rings[FRQ_INDEX].avail.idx.set(slot as u16 + 1);
            assert!(balloon.process_frq().unwrap());
            assert_eq!(rings[FRQ_INDEX].used.idx.get(), slot as u16 + 1);
            let mut payload = vec![0xff; page];
            memory.read_slice(&mut payload, address).unwrap();
            assert_eq!(payload, vec![0; page]);
            let status = observer.status();
            assert!(status.requested);
            assert!(status.effective);
            assert_eq!(status.reason, ReclaimReason::None);
            assert_eq!(status.qualification, ReclaimQualification::NotRun);
            assert_eq!(status.released_extents, slot as u64 + 1);
            assert_eq!(status.released_bytes, (slot as u64 + 1) * page as u64);
            assert_eq!(status.skipped_reports, 0);
            assert_eq!(status.failed_operations, 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_ranges_and_failed_used_publication_never_invent_success() {
        use crate::virtio::balloon::BalloonMemoryPolicy;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        // Nonwritable, unaligned actual discard, advice then failed publication,
        // and inhibited processing with failed publication are distinct failures.
        for case in 0..7 {
            let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page)]).unwrap();
            let rings: Vec<_> = (0..5)
                .map(|i| VirtQueue::new(GuestAddress(i * 0x1000), &memory, 8))
                .collect();
            let address = GuestAddress((8 * page) as u64);
            rings[FRQ_INDEX].dtable[0].set(
                address.0,
                page as u32 + u32::from(case == 1),
                if case == 0 {
                    0
                } else if case == 6 {
                    3
                } else {
                    2
                },
                0,
            );
            rings[FRQ_INDEX].avail.ring[0].set(if case == 4 { 8 } else { 0 });
            rings[FRQ_INDEX]
                .avail
                .idx
                .set(if case == 5 { 9 } else { 1 });
            memory.write_slice(&vec![0xa5; page], address).unwrap();
            let mut balloon = Balloon::new().unwrap();
            balloon
                .finalize_memory_policy(if case == 3 {
                    BalloonMemoryPolicy::TrackedCapture
                } else {
                    BalloonMemoryPolicy::Untracked
                })
                .unwrap();
            activate_report_fixture(
                &mut balloon,
                &memory,
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            );
            if (2..=3).contains(&case) {
                balloon.queues.as_mut().unwrap()[FRQ_INDEX].queue.used_ring =
                    GuestAddress((32 * page) as u64);
            }
            assert!(balloon.process_frq().is_err());
            let status = balloon.reclaim_status();
            assert_eq!(status.failed_operations, 1, "case {case}");
            assert_eq!(status.skipped_reports, 0, "case {case}");
            assert_eq!(
                status.released_bytes,
                if case == 2 { page as u64 } else { 0 },
                "case {case}"
            );
            assert_eq!(status.released_extents, u64::from(case == 2), "case {case}");
            assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
            let mut payload = vec![0; page];
            memory.read_slice(&mut payload, address).unwrap();
            assert_eq!(payload, vec![if case == 2 { 0 } else { 0xa5 }; page]);
            // Retained failure is not another attempted syscall or publication.
            let _ = balloon.process_frq();
            assert_eq!(balloon.reclaim_status().failed_operations, 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn advice_error_retains_successful_prefix_accounting() {
        use crate::virtio::balloon::BalloonMemoryPolicy;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|i| VirtQueue::new(GuestAddress(i * 0x1000), &memory, 8))
            .collect();
        let first = GuestAddress((8 * page) as u64);
        let locked = GuestAddress((9 * page) as u64);
        rings[FRQ_INDEX].dtable[0].set(first.0, page as u32, 3, 1);
        rings[FRQ_INDEX].dtable[1].set(locked.0, page as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory.write_slice(&vec![0xa5; 2 * page], first).unwrap();
        // nix's mman module is not enabled in this crate. Linux rejects
        // DONTNEED on a locked page after successfully advising the prefix.
        memory
            .try_read_access(page, locked, |_, len, _, slice| {
                assert_eq!(unsafe { libc::mlock(slice.as_ptr().cast(), len) }, 0);
                Ok(len)
            })
            .unwrap();
        let mut balloon = Balloon::new().unwrap();
        balloon
            .finalize_memory_policy(BalloonMemoryPolicy::Untracked)
            .unwrap();
        activate_report_fixture(
            &mut balloon,
            &memory,
            rings
                .iter()
                .map(|ring| {
                    DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                })
                .collect(),
        );
        let result = balloon.process_frq();
        memory
            .try_read_access(page, locked, |_, len, _, slice| {
                assert_eq!(unsafe { libc::munlock(slice.as_ptr().cast(), len) }, 0);
                Ok(len)
            })
            .unwrap();
        assert!(result.unwrap_err().contains("failed report discard"));
        let status = balloon.reclaim_status();
        assert_eq!(status.released_bytes, page as u64);
        assert_eq!(status.released_extents, 1);
        assert_eq!(status.failed_operations, 1);
        assert_eq!(status.skipped_reports, 0);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        let mut bytes = vec![0xff; 2 * page];
        memory.read_slice(&mut bytes, first).unwrap();
        assert_eq!(&bytes[..page], vec![0; page]);
        assert_eq!(&bytes[page..], vec![0xa5; page]);
    }

    #[cfg(all(target_os = "linux", feature = "native-device-probe"))]
    fn tracked_report_memory(
        raw: vm_memory::GuestMemoryMmap,
        backing: arch::guest_memory::BackingKind,
    ) -> (
        crate::virtio::RuntimeGuestMemory,
        arch::guest_memory::DomainControl,
    ) {
        use arch::guest_memory::MemoryDomain;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
        let (domain, authority, mut control) = MemoryDomain::construct(raw, page, backing).unwrap();
        let epoch = authority.issue_epoch(1).unwrap();
        control.finish_tracked(authority, epoch).unwrap();
        (crate::virtio::RuntimeGuestMemory::new(domain), control)
    }

    #[cfg(all(target_os = "linux", feature = "native-device-probe"))]
    #[test]
    fn offered_report_hold_consumes_event_but_preserves_unpopped_capture_and_explicit_drain() {
        use crate::virtio::DeviceQueue;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::balloon::{BalloonMemoryPolicy, ReportWitnessState};
        use crate::virtio::queue::tests::VirtQueue;
        use arch::guest_memory::BackingKind;
        use polly::event_manager::{EventManager, Subscriber};
        use std::os::fd::AsRawFd;
        use std::sync::Arc;
        use utils::epoll::{EpollEvent, EventSet};
        use utils::eventfd::{EFD_NONBLOCK, EventFd};
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let (memory, _control) = tracked_report_memory(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
            BackingKind::Boot,
        );
        let rings: Vec<_> = (0..5)
            .map(|i| VirtQueue::new(GuestAddress(i * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(0x8000, 4096, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut balloon = Balloon::new().unwrap();
        balloon
            .finalize_memory_policy(BalloonMemoryPolicy::TrackedCapture)
            .unwrap();
        activate_report_fixture(
            &mut balloon,
            &memory,
            rings
                .iter()
                .enumerate()
                .map(|(i, ring)| {
                    DeviceQueue::new(
                        ring.create_queue(),
                        if i == FRQ_INDEX {
                            event.clone()
                        } else {
                            Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())
                        },
                    )
                })
                .collect(),
        );
        balloon.pressure_hold_reports().unwrap();
        let before = balloon.queues.as_ref().unwrap()[FRQ_INDEX]
            .queue
            .capture_state()
            .unwrap();
        let mut descriptor_before = [0; 16];
        memory
            .read_slice(&mut descriptor_before, GuestAddress(before.desc_table))
            .unwrap();
        event.write(1).unwrap();
        balloon.process(
            &EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64),
            &mut EventManager::new().unwrap(),
        );
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let witness = balloon.pressure_report_witness();
        assert_eq!(witness.state, ReportWitnessState::Holding);
        assert_eq!(witness.report.as_ref().unwrap().head, 0);
        assert_eq!(witness.report.as_ref().unwrap().gpa, 0x8000);
        assert_eq!(
            balloon.queues.as_ref().unwrap()[FRQ_INDEX]
                .queue
                .capture_state()
                .unwrap(),
            before
        );
        let mut descriptor_after = [0; 16];
        memory
            .read_slice(&mut descriptor_after, GuestAddress(before.desc_table))
            .unwrap();
        assert_eq!(descriptor_before, descriptor_after);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        balloon.pressure_release_reports().unwrap();
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
        assert_eq!(rings[FRQ_INDEX].used.ring[0].get().id, 0);
        assert_eq!(balloon.reclaim_status().skipped_reports, 1);
        // A late hold cannot undo a consumed head or claim another report.
        balloon.pressure_hold_reports().unwrap();
        assert!(balloon.pressure_report_witness().report.is_none());
        assert_eq!(
            balloon.queues.as_ref().unwrap()[FRQ_INDEX]
                .queue
                .next_avail
                .0,
            1
        );
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
        balloon.pressure_release_reports().unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "native-device-probe"))]
    #[test]
    fn held_report_refuses_malformed_metadata_stale_identity_and_missing_park_without_writes() {
        use crate::virtio::DeviceQueue;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::balloon::{BalloonMemoryPolicy, ReportWitnessState};
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use arch::guest_memory::BackingKind;
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        // Readonly, own metadata overlap, too-short page, availability overflow,
        // changed head, wrong Park key, no Park, and deadline expiration.
        for case in 0..8 {
            let (memory, _control) = tracked_report_memory(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
                BackingKind::Boot,
            );
            let rings: Vec<_> = (0..5)
                .map(|i| VirtQueue::new(GuestAddress(i * 0x1000), &memory, 8))
                .collect();
            let address = if case == 1 { 0x4000 } else { 0x8000 };
            rings[FRQ_INDEX].dtable[0].set(
                address,
                if case == 2 { 4095 } else { 4096 },
                if case == 0 { 0 } else { 2 },
                0,
            );
            rings[FRQ_INDEX].dtable[1].set(0x9000, 4096, 2, 0);
            rings[FRQ_INDEX].avail.ring[0].set(0);
            rings[FRQ_INDEX]
                .avail
                .idx
                .set(if case == 3 { 9 } else { 1 });
            let mut balloon = Balloon::new().unwrap();
            balloon
                .finalize_memory_policy(BalloonMemoryPolicy::TrackedCapture)
                .unwrap();
            activate_report_fixture(
                &mut balloon,
                &memory,
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            );
            balloon.pressure_hold_reports().unwrap();
            balloon.pressure_arm_source(0xa5).unwrap();
            if case <= 3 {
                assert_eq!(
                    balloon.pressure_report_witness().state,
                    ReportWitnessState::Failed,
                    "case {case}"
                );
            } else {
                assert!(balloon.pressure_report_witness().report.is_some());
                if case == 4 {
                    rings[FRQ_INDEX].avail.ring[0].set(1);
                }
                if case != 6 {
                    balloon
                        .pressure_report_parked(request(if case == 5 { 2 } else { 1 }).key, 2)
                        .unwrap();
                }
                if case == 7 {
                    balloon.report_hold.deadline = std::time::Instant::now();
                }
            }
            assert!(balloon.begin_quiesce(request(1)).is_err(), "case {case}");
            assert_eq!(
                balloon.pressure_report_witness().state,
                ReportWitnessState::Failed
            );
            assert!(!balloon.process_frq().unwrap());
            assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
            assert_eq!(
                balloon.queues.as_ref().unwrap()[FRQ_INDEX]
                    .queue
                    .next_avail
                    .0,
                0
            );
            let mut payload = [0xff; 4096];
            memory
                .read_slice(&mut payload, GuestAddress(0x8000))
                .unwrap();
            assert_eq!(payload, [0; 4096], "case {case}");
            assert_eq!(balloon.reclaim_status().skipped_reports, 0);
            assert_eq!(balloon.reclaim_status().released_bytes, 0);
        }
    }

    #[cfg(all(target_os = "linux", feature = "native-device-probe"))]
    #[test]
    fn quiesce_report_witness_seeds_source_and_completes_prepared_private_child_after_used() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::balloon::{BalloonMemoryPolicy, ReportWitnessState};
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
        };
        use crate::virtio::queue::{Queue, tests::VirtQueue};
        use crate::virtio::{DeviceQueue, InterruptTransport};
        use arch::guest_memory::{BackingKind, DirtyPageMap, PageIndex};
        use nix::fcntl::{FcntlArg, SealFlag, fcntl};
        use nix::sys::memfd::{MFdFlags, memfd_create};
        use std::fs::File;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;
        use std::sync::Arc;
        use std::task::Poll;
        use utils::eventfd::EventFd;
        use vm_memory::{FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

        let (source_memory, _source_control) = tracked_report_memory(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
            BackingKind::Boot,
        );
        let rings: Vec<_> = (0..5)
            .map(|i| VirtQueue::new(GuestAddress(i * 0x1000), &source_memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(0x8000, 4096, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        let mut source = Balloon::new().unwrap();
        source
            .finalize_memory_policy(BalloonMemoryPolicy::TrackedCapture)
            .unwrap();
        activate_report_fixture(
            &mut source,
            &source_memory,
            rings
                .iter()
                .map(|ring| {
                    DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                })
                .collect(),
        );
        source.pressure_hold_reports().unwrap();
        assert!(source.pressure_arm_source(0).is_err());
        source.pressure_arm_source(0xa5).unwrap();
        let held = source.pressure_report_witness().report.unwrap();
        source.pressure_report_parked(request(1).key, 2).unwrap();
        source.pressure_report_parked(request(1).key, 2).unwrap();
        source.begin_quiesce(request(1)).unwrap();
        let Poll::Ready(completion) = source.poll_quiesce(request(1).key).unwrap() else {
            panic!("source did not quiesce");
        };
        assert!(completion.fault.is_none());
        let source_witness = source.pressure_report_witness();
        assert_eq!(source_witness.state, ReportWitnessState::SourceSeeded);
        assert_eq!(source_witness.report, Some(held.clone()));
        assert_eq!(source_witness.verified_bytes, 4096);
        assert_eq!(source_witness.used_after, None);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        let states: Vec<_> = completion
            .queues
            .iter()
            .map(|queue| queue.queue.capture_state().unwrap())
            .collect();
        let payload = source.capture_payload(request(1).key).unwrap();
        assert!(source.pressure_arm_source(0x3c).is_err());
        let mut image = vec![0; 0x10000];
        source_memory
            .read_slice(&mut image, GuestAddress(0))
            .unwrap();
        let file = File::from(
            memfd_create(
                "held-report-private-image",
                MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
            )
            .unwrap(),
        );
        file.set_len(image.len() as u64).unwrap();
        file.write_all_at(&image, 0).unwrap();
        fcntl(
            &file,
            FcntlArg::F_ADD_SEALS(
                SealFlag::F_SEAL_WRITE
                    | SealFlag::F_SEAL_GROW
                    | SealFlag::F_SEAL_SHRINK
                    | SealFlag::F_SEAL_SEAL,
            ),
        )
        .unwrap();
        let baseline = Arc::new(File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap());
        let private = || {
            let mapping = MmapRegion::build(
                Some(FileOffset::from_arc(baseline.clone(), 0)),
                image.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
            )
            .unwrap();
            tracked_report_memory(
                GuestMemoryMmap::from_regions(vec![
                    GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap(),
                ])
                .unwrap(),
                BackingKind::RestoredPrivate,
            )
        };
        let prepared = |memory: &crate::virtio::RuntimeGuestMemory| {
            let mut child = Balloon::new_restore_binding(source.avail_features()).unwrap();
            child
                .finalize_memory_policy(BalloonMemoryPolicy::RestoredPrivate)
                .unwrap();
            child
                .prepare_restore(
                    request(1),
                    &payload,
                    DormantDeviceContext {
                        memory: memory.clone(),
                        interrupt: InterruptTransport::new(
                            DummyIrqChip::new().into(),
                            "prepared-report-child".into(),
                            None,
                        )
                        .unwrap(),
                        activated: true,
                        reclaim_policy: RestoredReclaimPolicy::Disabled,
                    },
                )
                .unwrap();
            child
        };
        let fresh_queues = || {
            states
                .iter()
                .map(|state| {
                    let mut queue = Queue::new(state.max_size);
                    queue.apply_state(state);
                    DeviceQueue::new(queue, Arc::new(EventFd::new(0).unwrap()))
                })
                .collect()
        };
        for wrong_identity in [true, false] {
            let (memory, _control) = private();
            let mut invalid = prepared(&memory);
            invalid.pressure_hold_reports().unwrap();
            let mut expected = held.clone();
            if wrong_identity {
                expected.gpa += 4096;
            }
            invalid.pressure_arm_child(expected, 0xa5, 0x3c).unwrap();
            assert!(matches!(
                invalid.begin_resume(request(2), fresh_queues()),
                ResumeAcceptance::Accepted
            ));
            assert!(matches!(
                invalid.poll_resume(request(2).key).unwrap(),
                Poll::Ready(())
            ));
            if !wrong_identity {
                // Check the last byte as well as the beginning of inherited A.
                memory
                    .write_slice(&[0], GuestAddress(held.gpa + 4095))
                    .unwrap();
            }
            invalid.pressure_report_parked(request(3).key, 2).unwrap();
            assert!(invalid.begin_quiesce(request(3)).is_err());
            assert_eq!(
                invalid.pressure_report_witness().state,
                ReportWitnessState::Failed
            );
            assert_eq!(
                invalid.queues.as_ref().unwrap()[FRQ_INDEX]
                    .queue
                    .next_avail
                    .0,
                0
            );
            let used: u16 = memory.read_obj(GuestAddress(held.used_ring + 2)).unwrap();
            assert_eq!(used, 0);
            let mut retained = [0; 4096];
            memory
                .read_slice(&mut retained, GuestAddress(held.gpa))
                .unwrap();
            let mut expected = [0xa5; 4096];
            if !wrong_identity {
                expected[4095] = 0;
            }
            assert_eq!(retained, expected);
            assert_eq!(invalid.reclaim_status().skipped_reports, 0);
            assert_eq!(invalid.reclaim_status().released_bytes, 0);
        }
        let (child_memory, mut child_control) = private();
        let (sibling_memory, _sibling_control) = private();
        let mut child = prepared(&child_memory);
        // There are no installed child queues yet. Arming must precede resume.
        child.pressure_hold_reports().unwrap();
        assert!(child.pressure_arm_child(held.clone(), 0xa5, 0xa5).is_err());
        child.pressure_arm_child(held.clone(), 0xa5, 0x3c).unwrap();
        assert!(matches!(
            child.begin_resume(request(2), fresh_queues()),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            child.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(
            child.queues.as_ref().unwrap()[FRQ_INDEX].queue.next_avail.0,
            0
        );
        let mut page = [0; 4096];
        child_memory
            .read_slice(&mut page, GuestAddress(held.gpa))
            .unwrap();
        assert_eq!(page, [0xa5; 4096]);
        child.pressure_report_parked(request(3).key, 2).unwrap();
        child.begin_quiesce(request(3)).unwrap();
        let Poll::Ready(completion) = child.poll_quiesce(request(3).key).unwrap() else {
            panic!("child did not quiesce");
        };
        assert!(completion.fault.is_none());
        let result = child.pressure_report_witness();
        assert_eq!(result.state, ReportWitnessState::ChildCompleted);
        assert_eq!(result.report, Some(held.clone()));
        assert_eq!(result.verified_bytes, 4096);
        assert_eq!(result.seed, Some(0x3c));
        assert_eq!(result.used_after, Some(1));
        assert_eq!(result.barrier, Some(request(3).key));
        assert_eq!(result.parked_cpus, 2);
        child_memory
            .read_slice(&mut page, GuestAddress(held.gpa))
            .unwrap();
        assert_eq!(page, [0x3c; 4096]);
        sibling_memory
            .read_slice(&mut page, GuestAddress(held.gpa))
            .unwrap();
        assert_eq!(page, [0xa5; 4096]);
        baseline.read_exact_at(&mut page, held.gpa).unwrap();
        assert_eq!(page, [0xa5; 4096]);
        let status = child.reclaim_status();
        assert_eq!(status.released_bytes, 0);
        assert_eq!(status.released_extents, 0);
        assert_eq!(status.skipped_reports, 1);
        assert!(!child.pressure_remapper_present());
        let closing = child_control.close().unwrap();
        let Poll::Ready(Ok(drained)) = child_control.poll_drained(&closing) else {
            panic!("witness retained a memory writer");
        };
        let cut = child_control.seal(&drained).unwrap();
        let mut dirty = DirtyPageMap::new(child_memory.domain().layout());
        child_control.drain_host_dirty(&cut, &mut dirty).unwrap();
        let granule = child_memory.domain().layout().granule() as usize;
        assert!(dirty.contains(PageIndex::new(held.gpa as usize / granule)));
        assert!(dirty.contains(PageIndex::new(held.used_ring as usize / granule)));
        child.pressure_release_reports().unwrap();
        assert!(child.pressure_release_reports().is_err());
        source.pressure_release_reports().unwrap();
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn balloon_observer_retains_live_hvf_authority_across_construction_binding() {
        use crate::virtio::balloon::{ReclaimObserver, ReclaimQualification};
        use hvf::reclaim::ReclaimState;
        use std::sync::Arc;

        let state = Arc::new(ReclaimState::new());
        state.set_policy_enabled(true);
        let mut balloon = Balloon::new().unwrap();
        balloon.set_reclaim_state(state.clone());
        let observer = ReclaimObserver::new();
        balloon.set_reclaim_observer(observer.clone()).unwrap();
        balloon.set_reclaim_state(state.clone());
        assert!(observer.status().requested);
        assert!(!observer.status().effective);
        assert_eq!(
            observer.status().qualification,
            ReclaimQualification::NotRun
        );
        state.set_policy_enabled(false);
        assert!(!observer.status().requested);
        state.set_policy_enabled(true);
        assert!(observer.status().requested);
        let conflicting = ReclaimObserver::new();
        conflicting
            .0
            .backend
            .set(Arc::new(ReclaimState::new()))
            .unwrap();
        assert!(balloon.set_reclaim_observer(conflicting).is_err());
        state.set_policy_enabled(false);
        assert!(!balloon.reclaim_status().requested);
        assert!(!observer.status().requested);
    }
}
