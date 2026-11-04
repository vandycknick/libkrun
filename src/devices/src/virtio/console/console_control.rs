use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::{Arc, Mutex, TryLockError};

use crate::virtio::RuntimeGuestMemory;
use crate::virtio::lifecycle::ProviderFault;
use utils::eventfd::EFD_NONBLOCK;
use utils::eventfd::EventFd;
use vm_memory::ByteValued;

use crate::virtio::console::defs::control_event::{
    VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_PORT_ADD, VIRTIO_CONSOLE_PORT_NAME,
    VIRTIO_CONSOLE_PORT_OPEN, VIRTIO_CONSOLE_RESIZE,
};

pub(crate) const MAX_PENDING_BYTES: usize = 220_000;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed(4))]
pub struct VirtioConsoleControl {
    /// Port number
    pub id: u32,
    /// The kind of control event
    pub event: u16,
    /// Extra information for the event
    pub value: u16,
}

// Safe because it only has data and has no implicit padding.
// But NOTE that this relies on CPU being little endian, to have correct semantics
unsafe impl ByteValued for VirtioConsoleControl {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleResize {
    // NOTE: the order of these fields in older Linux kernels and in the spec were swapped.
    // Linux changed it in commit 5326ab737a47 to match the specs.
    pub cols: u16,
    pub rows: u16,
}

// Safe because it only has data and has no implicit padding.
// but NOTE, that we rely on CPU being little endian, for the values to be correct
unsafe impl ByteValued for VirtioConsoleResize {}

pub enum Payload {
    ConsoleControl(VirtioConsoleControl),
    Bytes(Vec<u8>),
}

impl Deref for Payload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Payload::ConsoleControl(b) => b.as_slice(),
            Payload::Bytes(b) => b.as_slice(),
        }
    }
}

struct ControlState {
    queue: VecDeque<Payload>,
    frozen: bool,
    fault: Option<ProviderFault>,
    bytes: usize,
}

pub struct ConsoleControl {
    state: Mutex<ControlState>,
    queue_evt: EventFd,
}

impl ConsoleControl {
    pub fn new() -> std::io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            state: Mutex::new(ControlState {
                queue: VecDeque::new(),
                frozen: false,
                fault: None,
                bytes: 0,
            }),
            queue_evt: EventFd::new(EFD_NONBLOCK)?,
        }))
    }

    pub fn mark_console_port(
        &self,
        _mem: &RuntimeGuestMemory,
        port_id: u32,
    ) -> Result<(), ProviderFault> {
        self.push_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_CONSOLE_PORT,
            value: 1,
        })
    }

    pub fn console_resize(
        &self,
        port_id: u32,
        new_size: VirtioConsoleResize,
    ) -> Result<(), ProviderFault> {
        let mut buf = Vec::with_capacity(12);
        buf.extend(
            VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_RESIZE,
                value: 0,
            }
            .as_slice(),
        );
        buf.extend(new_size.as_slice());
        self.push_vec(buf)
    }

    /// Adds another port with the specified port_id
    pub fn port_add(&self, port_id: u32) -> Result<(), ProviderFault> {
        self.push_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_PORT_ADD,
            value: 0,
        })
    }

    pub fn port_open(&self, port_id: u32, open: bool) -> Result<(), ProviderFault> {
        self.push_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_PORT_OPEN,
            value: open as u16,
        })
    }

    pub fn port_name(&self, port_id: u32, name: &str) -> Result<(), ProviderFault> {
        let mut buf = Vec::with_capacity(8 + name.len());

        buf.extend_from_slice(
            VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_PORT_NAME,
                value: 1, // Unspecified/unused in the spec, lets use the same value as QEMU.
            }
            .as_slice(),
        );

        // The spec says the name shouldn't be NUL terminated.
        buf.extend(name.as_bytes());
        self.push_vec(buf)
    }

    pub fn deliver_front(
        &self,
        deliver: impl FnOnce(&[u8]) -> Result<bool, ProviderFault>,
    ) -> Result<bool, ProviderFault> {
        let mut state = self.state.lock().map_err(|_| ProviderFault::DeviceLock)?;
        let Some(message) = state.queue.front() else {
            return Ok(false);
        };
        if !deliver(message)? {
            return Ok(false);
        }
        let length = message.len();
        state.bytes -= length;
        state.queue.pop_front();
        Ok(true)
    }

    pub(crate) fn freeze(&self, frozen: bool) -> Result<(), ProviderFault> {
        self.state
            .lock()
            .map_err(|_| ProviderFault::DeviceLock)?
            .frozen = frozen;
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Result<Vec<Vec<u8>>, ProviderFault> {
        let state = self.state.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => ProviderFault::LockBusy,
            TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
        })?;
        if let Some(fault) = state.fault {
            return Err(fault);
        }
        Ok(state.queue.iter().map(|payload| payload.to_vec()).collect())
    }

    pub(crate) fn install(&self, messages: Vec<Vec<u8>>) -> Result<(), ProviderFault> {
        let mut state = self.state.lock().map_err(|_| ProviderFault::DeviceLock)?;
        state.bytes = messages.iter().map(Vec::len).sum();
        state.queue = messages.into_iter().map(Payload::Bytes).collect();
        state.frozen = true;
        Ok(())
    }

    pub(crate) fn reset(&self) -> Result<(), ProviderFault> {
        let mut state = self.state.lock().map_err(|_| ProviderFault::DeviceLock)?;
        state.queue.clear();
        state.bytes = 0;
        state.frozen = false;
        state.fault = None;
        match self.queue_evt.read() {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(_) => Err(ProviderFault::Notification),
        }
    }

    pub fn queue_evt(&self) -> &EventFd {
        &self.queue_evt
    }

    pub(crate) fn check(&self) -> Result<(), ProviderFault> {
        let state = self.state.lock().map_err(|_| ProviderFault::DeviceLock)?;
        state.fault.map_or(Ok(()), Err)
    }

    pub(crate) fn preflight(&self) -> Result<(), ProviderFault> {
        let state = self.state.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => ProviderFault::LockBusy,
            TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
        })?;
        state.fault.map_or(Ok(()), Err)
    }

    fn push_msg(&self, msg: VirtioConsoleControl) -> Result<(), ProviderFault> {
        self.push(Payload::ConsoleControl(msg))
    }

    fn push_vec(&self, buf: Vec<u8>) -> Result<(), ProviderFault> {
        self.push(Payload::Bytes(buf))
    }

    fn push(&self, payload: Payload) -> Result<(), ProviderFault> {
        let mut state = self.state.lock().map_err(|_| ProviderFault::DeviceLock)?;
        if let Some(fault) = state.fault {
            return Err(fault);
        }
        if state.frozen
            || state.queue.len() >= 4096
            || state.bytes + payload.len() > MAX_PENDING_BYTES
        {
            state.fault = Some(ProviderFault::DeviceState);
            return Err(ProviderFault::DeviceState);
        }
        state.bytes += payload.len();
        state.queue.push_back(payload);
        if self.queue_evt.write(1).is_err() {
            state.fault = Some(ProviderFault::Notification);
            return Err(ProviderFault::Notification);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::console::console_control::ConsoleControl;
    use crate::virtio::lifecycle::ProviderFault;

    #[test]
    fn console_provider_control_preflight_distinguishes_contention_poison_and_effect_fault() {
        let control = ConsoleControl::new().unwrap();
        let mut state = control.state.lock().unwrap();
        assert_eq!(control.preflight(), Err(ProviderFault::LockBusy));
        state.fault = Some(ProviderFault::Notification);
        drop(state);
        assert_eq!(control.preflight(), Err(ProviderFault::Notification));
        let poison = control.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = poison.state.lock().unwrap();
                panic!("poison the actual control queue mutex");
            })
            .join()
            .is_err()
        );
        assert_eq!(control.preflight(), Err(ProviderFault::DeviceLock));
    }

    #[test]
    fn console_provider_capture_preserves_lock_busy_poison_and_control_fault() {
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::{Console, PortDescription};
        use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
        use std::time::{Duration, Instant};

        let mut console = Console::new(vec![PortDescription {
            name: "port".into(),
            input: None,
            output: None,
            terminal: None,
        }])
        .unwrap();
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(5),
        };
        console.begin_quiesce(request).unwrap();
        assert!(console.poll_quiesce(request.key).unwrap().is_ready());
        let original = console.capture_payload(request.key).unwrap();
        let control = console.control.clone();
        let Ok(guard) = control.state.lock() else {
            panic!("control mutex unexpectedly poisoned");
        };
        assert_eq!(
            console.capture_payload(request.key),
            Err(ProviderFault::LockBusy)
        );
        drop(guard);
        assert_eq!(console.capture_payload(request.key).unwrap(), original);
        {
            let Ok(mut state) = control.state.lock() else {
                panic!("control mutex unexpectedly poisoned");
            };
            state.fault = Some(ProviderFault::Notification);
        }
        assert_eq!(
            console.capture_payload(request.key),
            Err(ProviderFault::Notification)
        );
        assert!(
            std::thread::spawn(move || {
                let Ok(_guard) = control.state.lock() else {
                    panic!("control mutex unexpectedly poisoned");
                };
                panic!("poison the actual retained control mutex");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            console.capture_payload(request.key),
            Err(ProviderFault::DeviceLock)
        );
    }
}
