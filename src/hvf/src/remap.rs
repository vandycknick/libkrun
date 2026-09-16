//! Host mapping maintenance, independent of balloon attachment and reporting qualification.

use std::sync::{Arc, Mutex};
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
}

impl HostMemoryRemapper {
    pub fn new(ram: Arc<ReclaimState>) -> Option<Self> {
        ram.is_eligible().then(|| Self {
            ram,
            schedule: Mutex::new(Schedule::new(Instant::now())),
        })
    }

    pub fn timeout_millis(&self) -> Result<i32, ReclaimStateError> {
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
}
