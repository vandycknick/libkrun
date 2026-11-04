//! Host mapping maintenance, independent of balloon attachment and reporting qualification.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use crate::reclaim::{ReclaimState, ReclaimStateError};

const PERIOD: Duration = Duration::from_secs(30);
const REPORT_THROTTLE: Duration = Duration::from_millis(250);

struct Schedule {
    last_success: Instant,
    deadline: Instant,
}

impl Schedule {
    fn new(now: Instant) -> Self {
        Self {
            last_success: now,
            deadline: now + PERIOD,
        }
    }

    fn before_reports(&mut self, now: Instant) -> bool {
        let earliest = self.last_success + REPORT_THROTTLE;
        if now >= earliest {
            true
        } else {
            self.deadline = self.deadline.min(earliest);
            false
        }
    }

    fn succeeded(&mut self, started: Instant) {
        self.last_success = started;
        self.deadline = started + PERIOD;
    }

    fn timeout_millis(&self, now: Instant) -> i32 {
        let millis = self
            .deadline
            .saturating_duration_since(now)
            .as_nanos()
            .div_ceil(1_000_000);
        i32::try_from(millis).unwrap_or(i32::MAX)
    }
}

pub struct HostMemoryRemapper {
    ram: Arc<ReclaimState>,
    schedule: Mutex<Schedule>,
    admission_closed: AtomicBool,
}

impl HostMemoryRemapper {
    pub fn new(ram: Arc<ReclaimState>) -> Option<Self> {
        ram.is_eligible().then(|| Self {
            ram,
            schedule: Mutex::new(Schedule::new(Instant::now())),
            admission_closed: AtomicBool::new(false),
        })
    }

    // Barrier identities and transition ownership belong to the VMM journal.
    pub fn close_admission(&self) {
        self.admission_closed.store(true, Ordering::Release);
    }

    pub fn poll_quiesced(&self) -> Result<bool, ReclaimStateError> {
        match self.schedule.try_lock() {
            Ok(_schedule) => Ok(self.admission_closed.load(Ordering::Acquire)),
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Poisoned(_)) => Err(ReclaimStateError::RemapperLockPoisoned),
        }
    }

    pub fn reopen_admission(&self) {
        self.admission_closed.store(false, Ordering::Release);
    }

    pub fn timeout_millis(&self) -> Result<i32, ReclaimStateError> {
        if self.admission_closed.load(Ordering::Acquire) {
            return Ok(i32::MAX);
        }
        let schedule = self
            .schedule
            .lock()
            .map_err(|_| ReclaimStateError::RemapperLockPoisoned)?;
        Ok(schedule.timeout_millis(Instant::now()))
    }

    /// # Safety
    /// The owning VMM must retain every registered RAM allocation for this call.
    pub unsafe fn before_reports(&self) -> Result<(), ReclaimStateError> {
        let mut schedule = self
            .schedule
            .lock()
            .map_err(|_| ReclaimStateError::RemapperLockPoisoned)?;
        if self.admission_closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let started = Instant::now();
        if schedule.before_reports(started) {
            unsafe { self.ram.normalize_host_mappings()? };
            schedule.succeeded(started);
        }
        Ok(())
    }

    /// # Safety
    /// The owning VMM must retain every registered RAM allocation for this call.
    pub unsafe fn poll(&self) -> Result<(), ReclaimStateError> {
        let mut schedule = self
            .schedule
            .lock()
            .map_err(|_| ReclaimStateError::RemapperLockPoisoned)?;
        if self.admission_closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let started = Instant::now();
        if started >= schedule.deadline {
            unsafe { self.ram.normalize_host_mappings()? };
            schedule.succeeded(started);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::remap::{PERIOD, REPORT_THROTTLE, Schedule};
    use std::time::{Duration, Instant};

    #[test]
    fn construction_inhibition_refuses_remapper_without_affecting_ordinary_eligibility() {
        use crate::reclaim::{ReclaimInhibition, ReclaimState};
        use crate::remap::HostMemoryRemapper;
        use arch::guest_memory::{RamLayout, RamPermissions, RamRegion};
        use std::sync::Arc;

        let granule = crate::discard::native_page_size().unwrap() as u64;
        for reason in [
            ReclaimInhibition::TrackedCapture,
            ReclaimInhibition::RestoredPrivateMapping,
        ] {
            let ram = Arc::new(ReclaimState::new());
            ram.initialize_inhibited(granule, reason).unwrap();
            ram.set_policy_enabled(true);
            assert!(HostMemoryRemapper::new(ram).is_none());
        }
        let ordinary = Arc::new(ReclaimState::new());
        let mut layout = RamLayout::new(granule).unwrap();
        layout
            .register_region(
                RamRegion::new(
                    granule,
                    granule * 2,
                    granule,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        ordinary.initialize(layout).unwrap();
        assert!(!ordinary.is_effective());
        assert!(HostMemoryRemapper::new(ordinary).is_some());
    }

    #[test]
    fn periodic_deadline_exists_without_reports() {
        let now = Instant::now();
        let schedule = Schedule::new(now);
        assert_eq!(schedule.timeout_millis(now), 30_000);
        assert_eq!(schedule.timeout_millis(now + PERIOD), 0);
        assert_eq!(
            schedule.timeout_millis(now + PERIOD - Duration::from_nanos(1)),
            1
        );
    }

    #[test]
    fn reports_bring_deadline_forward_without_postponing_it() {
        let now = Instant::now();
        let mut schedule = Schedule::new(now);
        assert!(!schedule.before_reports(now + Duration::from_millis(10)));
        assert_eq!(schedule.deadline, now + REPORT_THROTTLE);
        assert!(!schedule.before_reports(now + Duration::from_millis(200)));
        assert_eq!(schedule.deadline, now + REPORT_THROTTLE);
        assert!(schedule.before_reports(now + REPORT_THROTTLE));
        // Only successful operations advance the schedule.
        assert_eq!(schedule.last_success, now);
        schedule.succeeded(now + REPORT_THROTTLE);
        assert_eq!(schedule.deadline, now + REPORT_THROTTLE + PERIOD);
        assert!(!schedule.before_reports(now + Duration::from_millis(300)));
        assert_eq!(schedule.deadline, now + Duration::from_millis(500));
    }

    #[test]
    fn maintenance_admission_drains_real_lock_ownership_and_preserves_schedule() {
        use crate::reclaim::ReclaimState;
        use crate::remap::HostMemoryRemapper;
        use crossbeam_channel::bounded;
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex};

        let now = Instant::now();
        let remapper = Arc::new(HostMemoryRemapper {
            ram: Arc::new(ReclaimState::new()),
            schedule: Mutex::new(Schedule::new(now)),
            admission_closed: AtomicBool::new(false),
        });
        let (entered_tx, entered_rx) = bounded(1);
        let (finish_tx, finish_rx) = bounded(1);
        let worker_remapper = Arc::clone(&remapper);
        let worker = std::thread::spawn(move || {
            let Ok(_owned) = worker_remapper.schedule.lock() else {
                panic!("maintenance schedule lock poisoned");
            };
            entered_tx.send(()).unwrap();
            finish_rx.recv().unwrap();
        });
        entered_rx.recv().unwrap();
        remapper.close_admission();
        assert!(!remapper.poll_quiesced().unwrap());
        assert_eq!(remapper.timeout_millis().unwrap(), i32::MAX);
        finish_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(remapper.poll_quiesced().unwrap());
        unsafe { remapper.before_reports() }.unwrap();
        unsafe { remapper.poll() }.unwrap();
        assert_eq!(
            remapper
                .schedule
                .lock()
                .map(|schedule| schedule.deadline)
                .unwrap(),
            now + PERIOD,
        );
        remapper.reopen_admission();
        assert!(!remapper.poll_quiesced().unwrap());
        assert_eq!(
            remapper
                .schedule
                .lock()
                .map(|schedule| schedule.deadline)
                .unwrap(),
            now + PERIOD,
        );
    }
}
