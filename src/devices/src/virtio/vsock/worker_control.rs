use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
#[cfg(target_os = "macos")]
use std::time::Duration;

use utils::eventfd::{EFD_NONBLOCK, EventFd};

#[derive(Clone, Copy)]
pub(crate) enum Owner {
    Mux = 1,
    Reaper = 2,
    #[cfg(target_os = "macos")]
    Timesync = 4,
}

#[cfg(feature = "native-device-probe")]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WorkerCounters {
    pub host_connects: u64,
    pub guest_requests: u64,
    pub admitted: u64,
    pub rejected: u64,
    pub credit_queued: u64,
    pub credit_delivered: u64,
    pub reaps: u64,
    pub overflowed: bool,
}

#[cfg(feature = "native-device-probe")]
pub(crate) enum WorkerCounter {
    HostConnect,
    GuestRequest,
    Admitted,
    Rejected,
    CreditQueued,
    CreditDelivered,
    Reap,
}

#[cfg(feature = "native-device-probe")]
pub(crate) struct WorkerObservation {
    pub expected: u8,
    pub started: u8,
    pub parked: u8,
    pub exited: u8,
    pub reconciled: u8,
    pub paused: bool,
    pub activation_fenced: bool,
    pub transport_ready: bool,
    pub counters: WorkerCounters,
}

struct State {
    pause: bool,
    stop: bool,
    parked: u8,
    started: u8,
    reconciled: u8,
    expected: u8,
    exited: u8,
    epoch: u64,
    service: Option<u32>,
    activation_fenced: bool,
    transport_ready: bool,
    #[cfg(feature = "native-device-probe")]
    counters: WorkerCounters,
    release_pending: bool,
}

pub(crate) struct WorkerControl {
    state: Mutex<State>,
    failed: AtomicBool,
    pub reaper_wake: crossbeam_channel::Receiver<()>,
    reaper_wake_sender: crossbeam_channel::Sender<()>,
    changed: Condvar,
    pub wake: EventFd,
}

impl WorkerControl {
    pub fn new() -> io::Result<Arc<Self>> {
        let (reaper_wake_sender, reaper_wake) = crossbeam_channel::bounded(1);
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                pause: false,
                stop: false,
                parked: 0,
                started: 0,
                reconciled: 0,
                expected: 0,
                exited: 0,
                epoch: 0,
                service: None,
                activation_fenced: false,
                transport_ready: true,
                release_pending: false,
                #[cfg(feature = "native-device-probe")]
                counters: WorkerCounters::default(),
            }),
            failed: AtomicBool::new(false),
            changed: Condvar::new(),
            wake: EventFd::new(EFD_NONBLOCK)?,
            reaper_wake,
            reaper_wake_sender,
        }))
    }

    pub fn pause(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("vsock worker control poisoned"))?;
        state.pause = true;
        state.epoch = state.epoch.wrapping_add(1);
        state.reconciled = 0;
        let _ = self.reaper_wake_sender.try_send(());
        drop(state);
        self.changed.notify_all();
        self.wake.write(1)
    }

    pub fn resume(&self) -> io::Result<()> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("vsock worker control poisoned"))?
            .pause = false;
        self.changed.notify_all();
        let _ = self.reaper_wake_sender.try_send(());
        self.wake.write(1)
    }

    pub fn epoch(&self) -> u64 {
        self.state.lock().map_or(u64::MAX, |state| state.epoch)
    }

    pub fn activation_fenced(&self) -> bool {
        self.state
            .lock()
            .map_or(true, |state| state.activation_fenced)
    }

    pub fn bind_activation(&self, service: u32) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("vsock worker control poisoned"))?;
        state.service = Some(service);
        state.activation_fenced = true;
        state.transport_ready = false;
        Ok(())
    }

    pub fn admits(&self, service: u32) -> bool {
        self.state.lock().is_ok_and(|state| {
            state.transport_ready && (!state.activation_fenced || state.service == Some(service))
        })
    }

    pub fn transport_ready(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.transport_ready)
    }

    pub fn transport_reset_completed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.transport_ready = true;
        }
        let _ = self.wake.write(1);
    }

    pub fn release_activation(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("vsock worker control poisoned"))?;
        if !state.transport_ready {
            return Err(io::Error::other("vsock reset is still pending"));
        }
        state.release_pending = true;
        state.reconciled &= !(Owner::Mux as u8);
        state.epoch = state.epoch.wrapping_add(1);
        Ok(())
    }

    pub fn release_pending(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.release_pending)
    }

    pub fn complete_activation_release(&self, epoch: u64) {
        if let Ok(mut state) = self.state.lock()
            && state.epoch == epoch
            && state.release_pending
            && !self.failed.load(Ordering::Acquire)
        {
            state.activation_fenced = false;
            state.release_pending = false;
        }
    }

    pub fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }

    pub fn failed(&self) -> bool {
        self.retained_fault().is_some()
    }

    /// Sticky owner failure and poisoning remain observable without gate admission.
    pub fn retained_fault(&self) -> Option<crate::virtio::lifecycle::ProviderFault> {
        if self.state.is_poisoned() {
            Some(crate::virtio::lifecycle::ProviderFault::DeviceLock)
        } else if self.failed.load(Ordering::Acquire) {
            Some(crate::virtio::lifecycle::ProviderFault::Worker)
        } else {
            None
        }
    }

    pub fn parked(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.pause && (state.parked | state.exited) == state.expected)
    }

    fn running_state(&self, state: &State) -> bool {
        !state.pause
            && !state.stop
            && !self.failed.load(Ordering::Acquire)
            && !state.release_pending
            && state.parked == 0
            && state.expected == Self::owners()
            && state.exited == 0
            && state.started == state.expected
            && state.reconciled == state.expected
    }

    pub fn poll_running(&self) -> Result<bool, crate::virtio::lifecycle::ProviderFault> {
        use crate::virtio::lifecycle::ProviderFault;
        let state = self.state.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                self.retained_fault().unwrap_or(ProviderFault::LockBusy)
            }
            std::sync::TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
        })?;
        if self.failed.load(Ordering::Acquire) {
            return Err(ProviderFault::Worker);
        }
        Ok(self.running_state(&state))
    }

    /// Inspect owner admission without waiting on an active acquisition.
    pub fn preflight(
        &self,
        require_inventory: bool,
    ) -> Result<(), crate::virtio::lifecycle::ProviderFault> {
        use crate::virtio::lifecycle::ProviderFault;
        let state = self.state.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                self.retained_fault().unwrap_or(ProviderFault::LockBusy)
            }
            std::sync::TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
        })?;
        if self.failed.load(Ordering::Acquire)
            || require_inventory
                && (state.expected != Self::owners() || state.exited != 0 || state.stop)
        {
            return Err(ProviderFault::Worker);
        }
        Ok(())
    }

    pub fn admit<T>(&self, acquire: impl FnOnce() -> T) -> Option<T> {
        let Ok(state) = self.state.lock() else {
            return None;
        };
        if state.pause || state.stop || self.failed.load(Ordering::Acquire) {
            return None;
        }
        Some(acquire())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn record(&self, counter: WorkerCounter) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let count = match counter {
            WorkerCounter::HostConnect => &mut state.counters.host_connects,
            WorkerCounter::GuestRequest => &mut state.counters.guest_requests,
            WorkerCounter::Admitted => &mut state.counters.admitted,
            WorkerCounter::Rejected => &mut state.counters.rejected,
            WorkerCounter::CreditQueued => &mut state.counters.credit_queued,
            WorkerCounter::CreditDelivered => &mut state.counters.credit_delivered,
            WorkerCounter::Reap => &mut state.counters.reaps,
        };
        if let Some(next) = count.checked_add(1) {
            *count = next;
        } else {
            state.counters.overflowed = true;
        }
    }

    #[cfg(feature = "native-device-probe")]
    pub fn observation(
        &self,
    ) -> Result<WorkerObservation, crate::virtio::lifecycle::ProviderFault> {
        let state = self.state.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                crate::virtio::lifecycle::ProviderFault::LockBusy
            }
            std::sync::TryLockError::Poisoned(_) => {
                crate::virtio::lifecycle::ProviderFault::DeviceLock
            }
        })?;
        Ok(WorkerObservation {
            expected: state.expected,
            started: state.started,
            parked: state.parked,
            exited: state.exited,
            reconciled: state.reconciled,
            paused: state.pause,
            activation_fenced: state.activation_fenced,
            transport_ready: state.transport_ready,
            counters: state.counters,
        })
    }

    const fn owners() -> u8 {
        if cfg!(target_os = "macos") { 7 } else { 3 }
    }

    pub fn expect_owner(&self, owner: Owner) {
        if let Ok(mut state) = self.state.lock() {
            state.expected |= owner as u8;
        }
    }

    pub fn exited(&self, owner: Owner) {
        if let Ok(mut state) = self.state.lock() {
            state.exited |= owner as u8;
        }
    }

    pub fn boundary(&self, owner: Owner) -> bool {
        self.boundary_releasing(owner, || {})
    }

    pub fn boundary_releasing(&self, owner: Owner, release: impl FnOnce()) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.started |= owner as u8;
        if state.pause || state.stop {
            drop(state);
            release();
            let Ok(next) = self.state.lock() else {
                return false;
            };
            state = next;
        }
        while state.pause && !state.stop {
            state.parked |= owner as u8;
            // Only lifecycle changes wake owners. Broadcasting each parked
            // wait would make paused owners continually wake one another.
            let Ok(next) = self.changed.wait(state) else {
                return false;
            };
            state = next;
        }
        state.parked &= !(owner as u8);
        !state.stop
    }

    pub fn reconciled(&self, owner: Owner, epoch: u64) {
        if let Ok(mut state) = self.state.lock()
            && !state.pause
            && state.epoch == epoch
        {
            state.reconciled |= owner as u8;
        }
    }

    #[cfg(target_os = "macos")]
    pub fn wait(&self, timeout: Duration) {
        if let Ok(state) = self.state.lock() {
            let _ = self
                .changed
                .wait_timeout_while(state, timeout, |state| !state.pause && !state.stop);
        }
    }

    pub fn stop(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.stop = true;
        }
        self.changed.notify_all();
        let _ = self.wake.write(1);
        let _ = self.reaper_wake_sender.try_send(());
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::lifecycle::ProviderFault;
    use crate::virtio::vsock::worker_control::WorkerControl;

    #[test]
    #[cfg(feature = "native-device-probe")]
    fn pressure_observation_vsock_actual_owner_lock_distinguishes_busy_and_poison() {
        let control = WorkerControl::new().unwrap();
        let held = control.state.lock().expect("hold the actual owner gate");
        assert!(matches!(
            control.observation(),
            Err(ProviderFault::LockBusy)
        ));
        drop(held);
        let observed = control.observation().unwrap();
        assert_eq!(observed.expected, 0);
        assert_eq!(observed.started, 0);
        let poisoned = control.clone();
        assert!(
            std::thread::spawn(move || {
                let _held = poisoned.state.lock().expect("poison the actual owner gate");
                panic!("poison the actual owner gate");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            control.observation(),
            Err(ProviderFault::DeviceLock)
        ));
    }

    #[test]
    fn provider_vsock_preflight_distinguishes_active_owner_lock_from_fault() {
        let control = WorkerControl::new().unwrap();
        let held = control.state.lock().expect("actual owner gate");
        assert_eq!(control.preflight(false), Err(ProviderFault::LockBusy));
        assert_eq!(control.poll_running(), Err(ProviderFault::LockBusy));
        drop(held);
        assert_eq!(control.preflight(false), Ok(()));
        assert_eq!(control.poll_running(), Ok(false));
        assert_eq!(control.preflight(true), Err(ProviderFault::Worker));
        control.fail();
        assert_eq!(control.preflight(false), Err(ProviderFault::Worker));
        assert_eq!(control.poll_running(), Err(ProviderFault::Worker));
    }

    #[test]
    fn provider_vsock_preflight_owner_lock_poison_is_not_transient_busy() {
        let control = WorkerControl::new().unwrap();
        let poisoned = control.clone();
        assert!(
            std::thread::spawn(move || {
                let _held = poisoned.state.lock().expect("actual owner gate");
                panic!("poison the actual owner gate");
            })
            .join()
            .is_err()
        );
        assert_eq!(control.preflight(false), Err(ProviderFault::DeviceLock));
        assert_eq!(control.poll_running(), Err(ProviderFault::DeviceLock));
        assert_eq!(control.retained_fault(), Some(ProviderFault::DeviceLock));
    }

    #[test]
    fn provider_vsock_sticky_worker_failure_does_not_wait_for_owner_gate() {
        let control = WorkerControl::new().unwrap();
        let held = control.state.lock().expect("actual owner gate");
        let failed = control.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let owner = std::thread::spawn(move || {
            failed.fail();
            sender.send(()).unwrap();
        });
        let completed = receiver.recv_timeout(std::time::Duration::from_secs(1));
        let fault = control.retained_fault();
        let running = control.poll_running();
        drop(held);
        owner.join().unwrap();
        assert!(completed.is_ok());
        assert_eq!(fault, Some(ProviderFault::Worker));
        assert_eq!(running, Err(ProviderFault::Worker));
    }
}
