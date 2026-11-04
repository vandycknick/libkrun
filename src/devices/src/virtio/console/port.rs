use polly::event_manager::BarrierKey;
use std::borrow::Cow;
use std::sync::{Arc, Mutex, TryLockError};
use std::task::Poll;
use std::thread::{self, JoinHandle};
use utils::eventfd::{EFD_NONBLOCK, EventFd};

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::lifecycle::ProviderFault;
use crate::virtio::port_io::PortTerminalProperties;
use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};

pub struct PortDescription {
    pub name: Cow<'static, str>,
    pub input: Option<Box<dyn PortInput + Send>>,
    pub output: Option<Box<dyn PortOutput + Send>>,
    pub terminal: Option<Box<dyn PortTerminalProperties>>,
}

impl PortDescription {
    pub fn console(
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
        terminal: Box<dyn PortTerminalProperties>,
    ) -> Self {
        Self {
            name: "".into(),
            input,
            output,
            terminal: Some(terminal),
        }
    }

    pub fn output_pipe(
        name: impl Into<Cow<'static, str>>,
        output: Box<dyn PortOutput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: None,
            output: Some(output),
            terminal: None,
        }
    }

    pub fn input_pipe(
        name: impl Into<Cow<'static, str>>,
        input: Box<dyn PortInput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: Some(input),
            output: None,
            terminal: None,
        }
    }
}

#[cfg(feature = "native-device-probe")]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConsoleOutputObservation {
    pub port_id: u32,
    pub worker_handle_retained: bool,
    pub worker_finished: bool,
    pub admission_closed: bool,
    pub blocked_head: Option<u16>,
    pub bytes_written: u32,
    pub write_remaining: usize,
}

pub(crate) struct Direction {
    pub queue: Option<DeviceQueue>,
    pub closed: bool,
    pub terminal: bool,
    pub started: bool,
    pub eof: bool,
    pub fault: Option<ProviderFault>,
    #[cfg(feature = "native-device-probe")]
    pub blocked_output: Option<(u16, u32, usize)>,
}

impl Direction {
    pub fn fail(&mut self, fault: ProviderFault) {
        self.fault.get_or_insert(fault);
        if let Some(queue) = &mut self.queue {
            queue.queue.record_processing_failure();
        }
    }
}

struct Worker {
    owner: Arc<Mutex<Direction>>,
    thread: Option<JoinHandle<()>>,
    terminal_wake_attempted: bool,
    terminal_fault: Option<ProviderFault>,
}

impl Worker {
    fn new(queue: DeviceQueue, eof: bool) -> Self {
        Self {
            owner: Arc::new(Mutex::new(Direction {
                queue: Some(queue),
                closed: false,
                terminal: false,
                started: false,
                eof,
                fault: None,
                #[cfg(feature = "native-device-probe")]
                blocked_output: None,
            })),
            thread: None,
            terminal_wake_attempted: false,
            terminal_fault: None,
        }
    }

    fn notify(&self) {
        if let Some(handle) = &self.thread {
            handle.thread().unpark();
        }
    }

    fn close(&self, key: BarrierKey) -> Result<(), ProviderFault> {
        let mut owner = self.owner.lock().map_err(|_| ProviderFault::DeviceLock)?;
        owner.closed = true;
        let result = owner.queue.as_mut().map_or(Ok(()), |queue| {
            queue
                .queue
                .close_admission(key)
                .map_err(|_| ProviderFault::QueueState)
        });
        drop(owner);
        self.notify();
        result
    }

    fn collect(&mut self) -> Result<bool, ProviderFault> {
        if self
            .thread
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
        {
            return Ok(false);
        }
        if let Some(handle) = self.thread.take()
            && handle.join().is_err()
        {
            self.owner
                .lock()
                .map_err(|_| ProviderFault::DeviceLock)?
                .fail(ProviderFault::Worker);
        }
        Ok(true)
    }

    fn poll_terminal_stop(
        &mut self,
        stopfd: Option<&Arc<EventFd>>,
    ) -> Poll<Result<(), ProviderFault>> {
        let mut owner = match self.owner.try_lock() {
            Ok(owner) => owner,
            Err(TryLockError::WouldBlock) => return Poll::Pending,
            Err(TryLockError::Poisoned(_)) => {
                self.terminal_fault.get_or_insert(ProviderFault::DeviceLock);
                return Poll::Ready(Err(ProviderFault::DeviceLock));
            }
        };
        owner.closed = true;
        owner.terminal = true;
        if let Some(fault) = owner.fault {
            self.terminal_fault.get_or_insert(fault);
        }
        drop(owner);
        if !self.terminal_wake_attempted {
            self.terminal_wake_attempted = true;
            if self.thread.is_some() && stopfd.is_none_or(|stopfd| stopfd.write(1).is_err()) {
                self.terminal_fault
                    .get_or_insert(ProviderFault::Notification);
            }
            self.notify();
        }
        if let Some(fault) = self.terminal_fault {
            return Poll::Ready(Err(fault));
        }
        if self
            .thread
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
        {
            return Poll::Pending;
        }
        if let Some(handle) = self.thread.take()
            && handle.join().is_err()
        {
            self.terminal_fault = Some(ProviderFault::Worker);
            return Poll::Ready(Err(ProviderFault::Worker));
        }
        match self.owner.try_lock() {
            Ok(owner) => {
                if let Some(fault) = owner.fault {
                    self.terminal_fault.get_or_insert(fault);
                    Poll::Ready(Err(fault))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Err(TryLockError::WouldBlock) => Poll::Pending,
            Err(TryLockError::Poisoned(_)) => {
                self.terminal_fault = Some(ProviderFault::DeviceLock);
                Poll::Ready(Err(ProviderFault::DeviceLock))
            }
        }
    }
}

pub(crate) struct PortQueues {
    pub rx: DeviceQueue,
    pub tx: DeviceQueue,
    pub fault: Option<ProviderFault>,
}

pub(crate) struct Port {
    pub(crate) port_id: u32,
    name: Cow<'static, str>,
    input: Option<Arc<Mutex<Box<dyn PortInput + Send>>>>,
    output: Option<Arc<Mutex<Box<dyn PortOutput + Send>>>>,
    terminal: Option<Box<dyn PortTerminalProperties>>,
    stopfd: Option<Arc<EventFd>>,
    terminal_stopfd: Option<Arc<EventFd>>,
    rx: Option<Worker>,
    tx: Option<Worker>,
    pub(crate) opened: bool,
    pub(crate) ready: bool,
    pub(crate) eof: bool,
    pub(crate) engaged: bool,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        Self {
            port_id,
            name: description.name,
            input: description.input.map(|input| Arc::new(Mutex::new(input))),
            output: description
                .output
                .map(|output| Arc::new(Mutex::new(output))),
            terminal: description.terminal,
            stopfd: None,
            terminal_stopfd: None,
            rx: None,
            tx: None,
            opened: false,
            ready: false,
            eof: false,
            engaged: false,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn terminal(&self) -> Option<&dyn PortTerminalProperties> {
        self.terminal.as_deref()
    }
    pub(crate) fn shape(&self) -> u8 {
        u8::from(self.input.is_some())
            | (u8::from(self.output.is_some()) << 1)
            | (u8::from(self.terminal.is_some()) << 2)
    }
    pub(crate) fn running(&self) -> bool {
        self.rx.is_some() || self.tx.is_some()
    }
    pub fn notify_rx(&self) {
        if let Some(worker) = &self.rx {
            worker.notify();
        }
    }
    pub fn notify_tx(&self) {
        if let Some(worker) = &self.tx {
            worker.notify();
        }
    }

    #[cfg(feature = "native-device-probe")]
    pub(crate) fn output_observation(&self) -> Result<ConsoleOutputObservation, ProviderFault> {
        let mut observation = ConsoleOutputObservation {
            port_id: self.port_id,
            ..Default::default()
        };
        if let Some(worker) = &self.tx {
            let owner = worker.owner.try_lock().map_err(|error| match error {
                TryLockError::WouldBlock => ProviderFault::LockBusy,
                TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
            })?;
            if let Some(fault) = owner.fault {
                return Err(fault);
            }
            observation.worker_handle_retained = worker.thread.is_some();
            observation.worker_finished = worker.thread.as_ref().is_some_and(|h| h.is_finished());
            observation.admission_closed = owner.closed;
            if let Some((head, written, remaining)) = owner.blocked_output {
                observation.blocked_head = Some(head);
                observation.bytes_written = written;
                observation.write_remaining = remaining;
            }
        }
        Ok(observation)
    }

    pub fn start(
        &mut self,
        mem: RuntimeGuestMemory,
        rx_queue: DeviceQueue,
        tx_queue: DeviceQueue,
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
    ) -> Result<(), ProviderFault> {
        if self.running() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.rx = Some(Worker::new(rx_queue, self.eof));
        self.tx = Some(Worker::new(tx_queue, false));
        self.engaged = true;
        let stopfd = Arc::new(EventFd::new(EFD_NONBLOCK).map_err(|_| ProviderFault::Worker)?);
        let terminal_stopfd =
            Arc::new(EventFd::new(EFD_NONBLOCK).map_err(|_| ProviderFault::Worker)?);
        self.stopfd = Some(stopfd.clone());
        self.terminal_stopfd = Some(terminal_stopfd.clone());
        if let (Some(input), Some(worker)) = (&self.input, &mut self.rx)
            && !self.eof
        {
            let (input, owner, memory, irq) = (
                input.clone(),
                worker.owner.clone(),
                mem.clone(),
                interrupt.clone(),
            );
            let port_id = self.port_id;
            worker.thread = Some(
                thread::Builder::new()
                    .name("console rx".into())
                    .spawn(move || process_rx(memory, owner, irq, input, control, port_id, stopfd))
                    .map_err(|_| ProviderFault::Worker)?,
            );
        }
        if let (Some(output), Some(worker)) = (&self.output, &mut self.tx) {
            let (output, owner) = (output.clone(), worker.owner.clone());
            worker.thread = Some(
                thread::Builder::new()
                    .name("console tx".into())
                    .spawn(move || process_tx(mem, owner, interrupt, output, terminal_stopfd))
                    .map_err(|_| ProviderFault::Worker)?,
            );
        }
        Ok(())
    }

    pub(crate) fn close(&self, key: BarrierKey) -> Result<(), ProviderFault> {
        let mut fault = None;
        for worker in [&self.rx, &self.tx].into_iter().flatten() {
            if let Err(error) = worker.close(key) {
                fault.get_or_insert(error);
            }
        }
        if let Some(stopfd) = &self.stopfd
            && stopfd.write(1).is_err()
        {
            fault.get_or_insert(ProviderFault::Notification);
        }
        fault.map_or(Ok(()), Err)
    }

    pub(crate) fn poll_queues(&mut self) -> Result<Option<PortQueues>, ProviderFault> {
        let (Some(rx), Some(tx)) = (&mut self.rx, &mut self.tx) else {
            return Ok(None);
        };
        let rx_done = rx.collect()?;
        let tx_done = tx.collect()?;
        if !rx_done || !tx_done {
            return Ok(None);
        }
        let mut rx_owner = rx.owner.lock().map_err(|_| ProviderFault::DeviceLock)?;
        let mut tx_owner = tx.owner.lock().map_err(|_| ProviderFault::DeviceLock)?;
        let fault = rx_owner.fault.or(tx_owner.fault);
        self.eof = rx_owner.eof;
        if rx_owner.queue.is_none() || tx_owner.queue.is_none() {
            return Err(ProviderFault::QueueCount);
        }
        let rx_queue = rx_owner.queue.take().ok_or(ProviderFault::QueueCount)?;
        let tx_queue = tx_owner.queue.take().ok_or(ProviderFault::QueueCount)?;
        drop(rx_owner);
        drop(tx_owner);
        self.rx = None;
        self.tx = None;
        self.stopfd = None;
        self.terminal_stopfd = None;
        Ok(Some(PortQueues {
            rx: rx_queue,
            tx: tx_queue,
            fault,
        }))
    }

    pub(crate) fn started(&self) -> Result<bool, ProviderFault> {
        for worker in [&self.rx, &self.tx].into_iter().flatten() {
            let owner = worker.owner.lock().map_err(|_| ProviderFault::DeviceLock)?;
            if let Some(fault) = owner.fault {
                return Err(fault);
            }
            if worker.thread.is_some() && !owner.started {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn preflight(&self) -> Result<(), ProviderFault> {
        let mut busy = false;
        let mut fault = None;
        for worker in [&self.rx, &self.tx].into_iter().flatten() {
            match worker.owner.try_lock() {
                Ok(owner) => {
                    if let Some(error) = owner.fault {
                        fault.get_or_insert(error);
                    }
                }
                Err(TryLockError::WouldBlock) => busy = true,
                Err(TryLockError::Poisoned(_)) => {
                    fault.get_or_insert(ProviderFault::DeviceLock);
                }
            }
        }
        match fault {
            Some(fault) => Err(fault),
            None if busy => Err(ProviderFault::LockBusy),
            None => Ok(()),
        }
    }

    pub(crate) fn poll_terminal_stop(&mut self) -> Poll<Result<(), ProviderFault>> {
        let mut pending = false;
        let mut fault = None;
        for (worker, stopfd) in [
            (&mut self.rx, &self.stopfd),
            (&mut self.tx, &self.terminal_stopfd),
        ] {
            if let Some(worker) = worker {
                match worker.poll_terminal_stop(stopfd.as_ref()) {
                    Poll::Pending => pending = true,
                    Poll::Ready(Err(error)) => {
                        fault.get_or_insert(error);
                    }
                    Poll::Ready(Ok(())) => {}
                }
            }
        }
        match fault {
            Some(fault) => Poll::Ready(Err(fault)),
            None if pending => Poll::Pending,
            None => Poll::Ready(Ok(())),
        }
    }

    pub fn shutdown(&mut self) -> Result<(), ProviderFault> {
        // Terminal wake is separate from close: accepted output must survive a failed pause.
        for (worker, stopfd) in [(&self.rx, &self.stopfd), (&self.tx, &self.terminal_stopfd)] {
            if worker
                .as_ref()
                .is_some_and(|worker| worker.thread.is_some())
                && stopfd.is_none()
            {
                return Err(ProviderFault::Notification);
            }
        }
        for worker in [&self.rx, &self.tx].into_iter().flatten() {
            let mut owner = worker.owner.lock().map_err(|_| ProviderFault::DeviceLock)?;
            owner.closed = true;
            owner.terminal = true;
        }
        for stopfd in [&self.stopfd, &self.terminal_stopfd].into_iter().flatten() {
            stopfd.write(1).map_err(|_| ProviderFault::Notification)?;
        }
        let mut fault = None;
        for worker in [&mut self.rx, &mut self.tx].into_iter().flatten() {
            worker.notify();
            if let Some(handle) = worker.thread.take()
                && handle.join().is_err()
            {
                fault.get_or_insert(ProviderFault::Worker);
            }
            if worker.owner.lock().is_err() {
                fault = Some(ProviderFault::DeviceLock);
            }
        }
        if let Some(fault) = fault {
            return Err(fault);
        }
        self.rx = None;
        self.tx = None;
        self.stopfd = None;
        self.terminal_stopfd = None;
        self.opened = false;
        self.ready = false;
        self.eof = false;
        self.engaged = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::console::port::{Port, PortDescription, Worker};
    use crate::virtio::lifecycle::{ProviderFault, VirtioStateProvider};
    use crate::virtio::{Console, DeviceQueue, Queue};
    use std::borrow::Cow;
    use std::sync::Arc;
    use utils::eventfd::{EFD_NONBLOCK, EventFd};

    #[test]
    fn console_provider_port_preflight_distinguishes_contention_poison_and_effect_fault() {
        let mut port = Port::new(
            0,
            PortDescription {
                name: Cow::Borrowed("input"),
                input: None,
                output: None,
                terminal: None,
            },
        );
        let worker = Worker::new(
            DeviceQueue {
                queue: Queue::new(32),
                event: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            },
            false,
        );
        let owner = worker.owner.clone();
        port.rx = Some(worker);
        let mut state = owner.lock().unwrap();
        assert_eq!(port.preflight(), Err(ProviderFault::LockBusy));
        state.fault = Some(ProviderFault::Worker);
        drop(state);
        assert_eq!(port.preflight(), Err(ProviderFault::Worker));
        assert!(
            std::thread::spawn(move || {
                let _guard = owner.lock().unwrap();
                panic!("poison the actual port owner mutex");
            })
            .join()
            .is_err()
        );
        assert_eq!(port.preflight(), Err(ProviderFault::DeviceLock));
    }

    fn pending_worker() -> Worker {
        Worker::new(
            DeviceQueue {
                queue: Queue::new(32),
                event: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            },
            false,
        )
    }

    fn empty_description() -> PortDescription {
        PortDescription {
            name: Cow::Borrowed("port"),
            input: None,
            output: None,
            terminal: None,
        }
    }

    #[test]
    fn console_terminal_shutdown_retains_worker_when_wake_is_missing() {
        let mut port = Port::new(0, empty_description());
        let mut worker = pending_worker();
        worker.thread = Some(std::thread::spawn(|| {}));
        port.tx = Some(worker);
        assert_eq!(port.shutdown(), Err(ProviderFault::Notification));
        let worker = port.tx.as_mut().unwrap();
        let Ok(owner) = worker.owner.lock() else {
            panic!("terminal owner unexpectedly poisoned");
        };
        assert!(!owner.terminal);
        drop(owner);
        worker.thread.take().unwrap().join().unwrap();
    }

    #[test]
    fn console_terminal_shutdown_retains_poisoned_worker_handle() {
        let mut port = Port::new(0, empty_description());
        let mut worker = pending_worker();
        let owner = worker.owner.clone();
        std::thread::spawn(move || {
            let Ok(_guard) = owner.lock() else {
                panic!("terminal owner unexpectedly poisoned");
            };
            panic!("poison the terminal owner");
        })
        .join()
        .unwrap_err();
        worker.thread = Some(std::thread::spawn(|| {}));
        port.tx = Some(worker);
        port.terminal_stopfd = Some(Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()));
        assert_eq!(port.shutdown(), Err(ProviderFault::DeviceLock));
        port.tx
            .as_mut()
            .unwrap()
            .thread
            .take()
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn console_terminal_shutdown_retains_worker_when_wake_fails() {
        let mut port = Port::new(0, empty_description());
        let mut worker = pending_worker();
        worker.thread = Some(std::thread::spawn(|| {}));
        port.tx = Some(worker);
        let stopfd = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        stopfd.write(u64::MAX - 1).unwrap();
        port.terminal_stopfd = Some(stopfd);
        assert_eq!(port.shutdown(), Err(ProviderFault::Notification));
        port.tx
            .as_mut()
            .unwrap()
            .thread
            .take()
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn console_terminal_shutdown_reports_worker_panic_after_join() {
        let mut port = Port::new(0, empty_description());
        let mut worker = pending_worker();
        worker.thread = Some(std::thread::spawn(|| panic!("terminal worker failed")));
        port.tx = Some(worker);
        port.terminal_stopfd = Some(Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()));
        assert_eq!(port.shutdown(), Err(ProviderFault::Worker));
        assert!(port.tx.as_ref().unwrap().thread.is_none());
        assert!(port.running());
    }

    #[test]
    fn console_provider_busy_rx_does_not_mask_tx_effect_fault_or_poison() {
        let mut port = Port::new(0, empty_description());
        let rx = pending_worker();
        let tx = pending_worker();
        let rx_owner = rx.owner.clone();
        let tx_owner = tx.owner.clone();
        port.rx = Some(rx);
        port.tx = Some(tx);
        let Ok(_rx_guard) = rx_owner.lock() else {
            panic!("RX owner unexpectedly poisoned");
        };
        assert_eq!(port.preflight(), Err(ProviderFault::LockBusy));
        {
            let Ok(mut tx) = tx_owner.lock() else {
                panic!("TX owner unexpectedly poisoned");
            };
            tx.fail(ProviderFault::Notification);
        }
        assert_eq!(port.preflight(), Err(ProviderFault::Notification));
        assert!(
            std::thread::spawn(move || {
                let Ok(_guard) = tx_owner.lock() else {
                    panic!("TX owner unexpectedly poisoned");
                };
                panic!("poison the actual TX owner while RX remains contended");
            })
            .join()
            .is_err()
        );
        assert_eq!(port.preflight(), Err(ProviderFault::DeviceLock));
    }

    #[test]
    fn console_provider_busy_port_does_not_mask_later_port_or_control_fault() {
        for control_fault in [false, true] {
            let mut console = Console::new(vec![empty_description(), empty_description()]).unwrap();
            let earlier = pending_worker();
            let earlier_owner = earlier.owner.clone();
            console.ports[0].rx = Some(earlier);
            let Ok(_earlier_guard) = earlier_owner.lock() else {
                panic!("earlier owner unexpectedly poisoned");
            };
            assert_eq!(console.preflight(), Err(ProviderFault::LockBusy));
            let expected = if control_fault {
                console.control.freeze(true).unwrap();
                assert_eq!(console.control.port_add(1), Err(ProviderFault::DeviceState));
                ProviderFault::DeviceState
            } else {
                let later = pending_worker();
                {
                    let Ok(mut owner) = later.owner.lock() else {
                        panic!("later owner unexpectedly poisoned");
                    };
                    owner.fail(ProviderFault::Worker);
                }
                console.ports[1].tx = Some(later);
                ProviderFault::Worker
            };
            assert_eq!(console.preflight(), Err(expected));
        }
    }

    #[test]
    fn console_terminal_poll_retains_contended_owner_and_closes_peer() {
        use std::task::Poll;
        let mut port = Port::new(0, empty_description());
        let rx = pending_worker();
        let rx_owner = Arc::clone(&rx.owner);
        port.rx = Some(rx);
        port.tx = Some(pending_worker());
        let guard = rx_owner.lock().expect("actual RX direction owner");
        assert_eq!(port.poll_terminal_stop(), Poll::Pending);
        assert!(
            port.tx
                .as_ref()
                .unwrap()
                .owner
                .lock()
                .expect("actual TX owner")
                .terminal
        );
        assert!(port.rx.as_ref().unwrap().owner.try_lock().is_err());
        drop(guard);
        assert_eq!(port.poll_terminal_stop(), Poll::Ready(Ok(())));
        assert!(
            port.rx
                .as_ref()
                .unwrap()
                .owner
                .lock()
                .expect("retained RX")
                .queue
                .is_some()
        );
        assert!(
            port.tx
                .as_ref()
                .unwrap()
                .owner
                .lock()
                .expect("retained TX")
                .queue
                .is_some()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn console_terminal_poll_wake_failure_retains_handle_and_cannot_retry_into_success() {
        use std::task::Poll;
        for missing in [false, true] {
            let mut port = Port::new(0, empty_description());
            let mut worker = pending_worker();
            worker.thread = Some(std::thread::spawn(|| {}));
            port.tx = Some(worker);
            if !missing {
                let stopfd = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
                stopfd.write(u64::MAX - 1).unwrap();
                port.terminal_stopfd = Some(stopfd);
            }
            assert_eq!(
                port.poll_terminal_stop(),
                Poll::Ready(Err(ProviderFault::Notification))
            );
            assert!(port.tx.as_ref().unwrap().thread.is_some());
            assert!(
                port.tx
                    .as_ref()
                    .unwrap()
                    .owner
                    .lock()
                    .expect("retained TX")
                    .queue
                    .is_some()
            );
            port.terminal_stopfd = Some(Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()));
            assert_eq!(
                port.poll_terminal_stop(),
                Poll::Ready(Err(ProviderFault::Notification))
            );
            assert!(port.tx.as_ref().unwrap().thread.is_some());
            port.tx
                .as_mut()
                .unwrap()
                .thread
                .take()
                .unwrap()
                .join()
                .unwrap();
        }
    }

    #[test]
    fn console_terminal_poll_poison_retains_handle_and_does_not_hide_peer_fault() {
        use std::task::Poll;
        let mut port = Port::new(0, empty_description());
        let rx = pending_worker();
        let rx_owner = Arc::clone(&rx.owner);
        port.rx = Some(rx);
        let mut tx = pending_worker();
        tx.owner
            .lock()
            .expect("actual TX owner")
            .fail(ProviderFault::QueueState);
        tx.thread = Some(std::thread::spawn(|| {}));
        port.tx = Some(tx);
        let guard = rx_owner.lock().expect("contended actual RX owner");
        assert_eq!(
            port.poll_terminal_stop(),
            Poll::Ready(Err(ProviderFault::QueueState))
        );
        assert!(port.tx.as_ref().unwrap().thread.is_some());
        drop(guard);
        std::thread::spawn(move || {
            let _guard = rx_owner.lock().expect("poison actual RX owner");
            panic!("actual RX owner poisoned");
        })
        .join()
        .unwrap_err();
        assert_eq!(
            port.poll_terminal_stop(),
            Poll::Ready(Err(ProviderFault::DeviceLock))
        );
        assert!(port.tx.as_ref().unwrap().thread.is_some());
        port.tx
            .as_mut()
            .unwrap()
            .thread
            .take()
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn console_terminal_poll_join_panic_is_sticky_and_keeps_queue_owner() {
        use std::task::Poll;
        use std::time::{Duration, Instant};
        let mut port = Port::new(0, empty_description());
        let mut worker = pending_worker();
        worker.thread = Some(std::thread::spawn(|| {
            panic!("actual terminal worker failed")
        }));
        port.tx = Some(worker);
        port.terminal_stopfd = Some(Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match port.poll_terminal_stop() {
                Poll::Ready(result) => {
                    assert_eq!(result, Err(ProviderFault::Worker));
                    break;
                }
                Poll::Pending => {
                    assert!(Instant::now() < deadline);
                    std::thread::yield_now();
                }
            }
        }
        assert!(port.tx.as_ref().unwrap().thread.is_none());
        assert!(
            port.tx
                .as_ref()
                .unwrap()
                .owner
                .lock()
                .expect("retained TX")
                .queue
                .is_some()
        );
        assert_eq!(
            port.poll_terminal_stop(),
            Poll::Ready(Err(ProviderFault::Worker))
        );
    }
}
