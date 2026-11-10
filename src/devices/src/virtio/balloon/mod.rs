#[cfg(not(feature = "tee"))]
pub(crate) mod device;
#[cfg(not(feature = "tee"))]
mod event_handler;

#[cfg(not(feature = "tee"))]
pub use self::defs::uapi::VIRTIO_ID_BALLOON as TYPE_BALLOON;
#[cfg(not(feature = "tee"))]
pub use self::device::Balloon;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BalloonMemoryPolicy {
    Untracked,
    TrackedCapture,
    RestoredPrivate,
}

use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use arch::guest_memory::{BackingKind, MemoryDomain, TrackingMode};
#[cfg(target_os = "macos")]
use hvf::reclaim::{ReclaimInhibition, ReclaimState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimBacking {
    Boot,
    RestoredPrivate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimReason {
    None,
    TrackedCapture,
    RestoredPrivateMapping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimQualification {
    NotRun,
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclaimStatus {
    pub backing: ReclaimBacking,
    pub reason: ReclaimReason,
    pub requested: bool,
    pub qualification: ReclaimQualification,
    /// Linux advice needs no HVF qualification; this is actual host permission.
    pub effective: bool,
    pub released_bytes: u64,
    pub released_extents: u64,
    pub retried_faults: u64,
    /// Skipped operations, including backend range skips, not physical pages.
    pub skipped_reports: u64,
    pub failed_operations: u64,
}

struct ReclaimObservation {
    // One publication keeps structural inhibition coherent in concurrent samples.
    facts: AtomicU8,
    released_bytes: AtomicU64,
    released_extents: AtomicU64,
    skipped_reports: AtomicU64,
    failed_operations: AtomicU64,
    #[cfg(target_os = "macos")]
    backend: OnceLock<Arc<ReclaimState>>,
}

#[derive(Clone)]
pub struct ReclaimObserver(Arc<ReclaimObservation>);

#[cfg(not(feature = "tee"))]
pub(crate) fn saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
        Some(previous.saturating_add(value))
    });
}

impl ReclaimObserver {
    fn new() -> Self {
        Self(Arc::new(ReclaimObservation {
            facts: AtomicU8::new(0),
            released_bytes: AtomicU64::new(0),
            released_extents: AtomicU64::new(0),
            skipped_reports: AtomicU64::new(0),
            failed_operations: AtomicU64::new(0),
            #[cfg(target_os = "macos")]
            backend: OnceLock::new(),
        }))
    }

    pub fn for_domain(
        domain: &MemoryDomain,
        #[cfg(target_os = "macos")] state: Arc<ReclaimState>,
    ) -> Self {
        let observer = Self::new();
        #[cfg(target_os = "macos")]
        let _ = observer.0.backend.set(state);
        observer.bind(domain, false, None);
        observer
    }

    fn bind(&self, domain: &MemoryDomain, enabled: bool, policy: Option<BalloonMemoryPolicy>) {
        let restored = domain.backing_kind() == BackingKind::RestoredPrivate;
        let reason = if restored {
            2
        } else if domain.tracking_mode() != Some(TrackingMode::Disabled) {
            1
        } else {
            0
        };
        self.0.facts.store(
            u8::from(restored)
                | (reason << 1)
                | (u8::from(enabled && reason == 0) << 3)
                | (u8::from(policy.is_some()) << 4)
                | 32,
            Ordering::Release,
        );
    }

    pub fn status(&self) -> ReclaimStatus {
        let facts = self.0.facts.load(Ordering::Acquire);
        let mut status = ReclaimStatus {
            backing: if facts & 1 != 0 {
                ReclaimBacking::RestoredPrivate
            } else {
                ReclaimBacking::Boot
            },
            reason: match (facts >> 1) & 3 {
                1 => ReclaimReason::TrackedCapture,
                2 => ReclaimReason::RestoredPrivateMapping,
                _ => ReclaimReason::None,
            },
            requested: !cfg!(target_os = "macos") && facts & 8 != 0,
            qualification: ReclaimQualification::NotRun,
            effective: !cfg!(target_os = "macos") && facts & 8 != 0,
            released_bytes: self.0.released_bytes.load(Ordering::Relaxed),
            released_extents: self.0.released_extents.load(Ordering::Relaxed),
            retried_faults: 0,
            skipped_reports: self.0.skipped_reports.load(Ordering::Relaxed),
            failed_operations: self.0.failed_operations.load(Ordering::Relaxed),
        };
        #[cfg(target_os = "macos")]
        if let Some(state) = self.0.backend.get() {
            use hvf::reclaim::ReclaimQualification as Qualification;
            if status.reason == ReclaimReason::None
                && let Some(reason) = state.inhibition()
            {
                status.reason = match reason {
                    ReclaimInhibition::TrackedCapture => ReclaimReason::TrackedCapture,
                    ReclaimInhibition::RestoredPrivateMapping => {
                        ReclaimReason::RestoredPrivateMapping
                    }
                };
            }
            status.requested = status.reason == ReclaimReason::None && state.policy_enabled();
            status.qualification = if status.reason == ReclaimReason::None {
                match state.qualification() {
                    Qualification::NotRun => ReclaimQualification::NotRun,
                    Qualification::Passed => ReclaimQualification::Passed,
                    Qualification::Failed => ReclaimQualification::Failed,
                    Qualification::Inconclusive => ReclaimQualification::Inconclusive,
                }
            } else {
                ReclaimQualification::NotRun
            };
            status.effective = status.reason == ReclaimReason::None
                && state.is_effective()
                && (facts & 16 == 0 || facts & 8 != 0);
            let stats = state.stats();
            status.released_bytes = stats.released_bytes;
            status.released_extents = stats.released_extents;
            status.retried_faults = stats.retried_faults;
            status.skipped_reports = status.skipped_reports.saturating_add(stats.skipped_reports);
            status.failed_operations = status
                .failed_operations
                .saturating_add(stats.failed_operations);
        }
        if status.reason != ReclaimReason::None {
            status.requested = false;
            status.qualification = ReclaimQualification::NotRun;
            status.effective = false;
        }
        status
    }

    #[cfg(all(not(feature = "tee"), not(target_os = "macos")))]
    pub(crate) fn record_release(&self, bytes: usize) {
        saturating_add(&self.0.released_bytes, bytes as u64);
        saturating_add(&self.0.released_extents, 1);
    }

    #[cfg(not(feature = "tee"))]
    pub(crate) fn record_skip(&self) {
        saturating_add(&self.0.skipped_reports, 1);
    }

    #[cfg(not(feature = "tee"))]
    pub(crate) fn record_failure(&self) {
        saturating_add(&self.0.failed_operations, 1);
    }
}

#[cfg(all(feature = "native-device-probe", not(feature = "tee")))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportDescriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[cfg(all(feature = "native-device-probe", not(feature = "tee")))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportIdentity {
    pub head: u16,
    pub next_avail: u16,
    pub next_used: u16,
    pub avail_idx: u16,
    pub used_idx: u16,
    pub gpa: u64,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring: u64,
    pub descriptors: Vec<ReportDescriptor>,
}

#[cfg(all(feature = "native-device-probe", not(feature = "tee")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportWitnessState {
    Idle,
    Holding,
    SourceSeeded,
    ChildCompleted,
    Failed,
}

#[cfg(all(feature = "native-device-probe", not(feature = "tee")))]
#[derive(Clone, Debug)]
pub struct ReportWitness {
    pub state: ReportWitnessState,
    pub report: Option<ReportIdentity>,
    pub seed: Option<u8>,
    pub verified_bytes: usize,
    pub used_after: Option<u16>,
    pub barrier: Option<polly::event_manager::BarrierKey>,
    pub parked_cpus: usize,
    pub failure: Option<String>,
}

#[cfg(not(feature = "tee"))]
mod defs {
    use crate::virtio::QueueConfig;

    pub const BALLOON_DEV_ID: &str = "virtio_balloon";
    pub const NUM_QUEUES: usize = 5;
    pub const QUEUE_SIZE: u16 = 256;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_BALLOON: u32 = 5;
        pub const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1;
        pub const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u32 = 3;
        pub const VIRTIO_BALLOON_F_REPORTING: u32 = 5;
    }
}

#[cfg(not(feature = "tee"))]
#[derive(Debug)]
pub enum BalloonError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    UnsupportedRestoreFeatures(u64),
    InvalidMemoryPolicy,
}

#[cfg(not(feature = "tee"))]
type Result<T> = std::result::Result<T, BalloonError>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arch::guest_memory::{BackingKind, MemoryDomain};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::virtio::balloon::{
        ReclaimBacking, ReclaimObserver, ReclaimQualification, ReclaimReason,
    };

    fn domain(backing: BackingKind, tracked: bool) -> Arc<MemoryDomain> {
        let granule = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
        let raw =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 16 * granule as usize)]).unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, granule, backing).unwrap();
        if tracked {
            let epoch = authority.issue_epoch(1).unwrap();
            control.finish_tracked(authority, epoch).unwrap();
        } else {
            control.finish_untracked(authority).unwrap();
        }
        domain
    }

    #[test]
    fn no_balloon_observation_uses_actual_domain_and_never_invents_advice() {
        for (backing, tracked, expected_backing, expected_reason) in [
            (
                BackingKind::Boot,
                false,
                ReclaimBacking::Boot,
                ReclaimReason::None,
            ),
            (
                BackingKind::Boot,
                true,
                ReclaimBacking::Boot,
                ReclaimReason::TrackedCapture,
            ),
            (
                BackingKind::RestoredPrivate,
                true,
                ReclaimBacking::RestoredPrivate,
                ReclaimReason::RestoredPrivateMapping,
            ),
        ] {
            let domain = domain(backing, tracked);
            #[cfg(target_os = "macos")]
            let backend = Arc::new(hvf::reclaim::ReclaimState::new());
            let observer = ReclaimObserver::for_domain(
                &domain,
                #[cfg(target_os = "macos")]
                backend.clone(),
            );
            let status = observer.status();
            assert_eq!(status.backing, expected_backing);
            assert_eq!(status.reason, expected_reason);
            assert!(!status.requested);
            assert!(!status.effective);
            assert_eq!(status.qualification, ReclaimQualification::NotRun);
            assert_eq!(status.released_bytes, 0);
            assert_eq!(status.released_extents, 0);
            assert_eq!(status.skipped_reports, 0);
            assert_eq!(status.failed_operations, 0);
            #[cfg(target_os = "macos")]
            {
                backend.set_policy_enabled(true);
                assert_eq!(observer.status().requested, !tracked);
                backend.set_policy_enabled(false);
                assert!(!observer.status().requested);
            }
            #[cfg(not(feature = "tee"))]
            {
                use crate::virtio::balloon::{Balloon, BalloonMemoryPolicy};
                let mut balloon = Balloon::new().unwrap();
                balloon.set_reclaim_observer(observer.clone()).unwrap();
                balloon
                    .finalize_memory_policy(BalloonMemoryPolicy::Untracked)
                    .unwrap();
                // Publishing a permissive local policy cannot transiently erase
                // immutable inhibition already installed by the actual domain.
                assert_eq!(observer.status().backing, expected_backing);
                assert_eq!(observer.status().reason, expected_reason);
                balloon.bind_reclaim_domain(&domain);
                let bound = observer.status();
                assert_eq!(bound.backing, expected_backing);
                assert_eq!(bound.reason, expected_reason);
                #[cfg(target_os = "linux")]
                {
                    assert_eq!(bound.requested, !tracked);
                    assert_eq!(bound.effective, !tracked);
                }
                assert!(
                    balloon
                        .finalize_memory_policy(BalloonMemoryPolicy::RestoredPrivate)
                        .is_err()
                );
                assert_eq!(observer.status(), bound);
            }
        }
    }

    #[cfg(all(not(feature = "tee"), target_os = "linux"))]
    #[test]
    fn advice_observation_is_shared_saturating_and_process_local() {
        let domain = domain(BackingKind::Boot, false);
        let observer = ReclaimObserver::for_domain(&domain);
        let clone = observer.clone();
        observer
            .0
            .released_bytes
            .store(u64::MAX - 1, std::sync::atomic::Ordering::Relaxed);
        observer
            .0
            .released_extents
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
        observer.record_release(4096);
        observer.record_skip();
        observer.record_failure();
        assert_eq!(clone.status().released_bytes, u64::MAX);
        assert_eq!(clone.status().released_extents, u64::MAX);
        assert_eq!(clone.status().skipped_reports, 1);
        assert_eq!(clone.status().failed_operations, 1);
        let fresh = ReclaimObserver::for_domain(&domain).status();
        assert_eq!(fresh.released_bytes, 0);
        assert_eq!(fresh.released_extents, 0);
        assert_eq!(fresh.skipped_reports, 0);
        assert_eq!(fresh.failed_operations, 0);
    }
}
