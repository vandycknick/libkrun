use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::defs::QUEUE_SIZE;
use crate::virtio::console::port::Direction;
use crate::virtio::console::port_io::PortInput;
use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::lifecycle::ProviderFault;
use crate::virtio::{InterruptTransport, RuntimeGuestMemory};
use std::sync::{Arc, Mutex};
use std::{io, thread};
use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, GuestMemoryError};

pub(crate) fn process_rx(
    mem: RuntimeGuestMemory,
    owner: Arc<Mutex<Direction>>,
    interrupt: InterruptTransport,
    input: Arc<Mutex<Box<dyn PortInput + Send>>>,
    control: Arc<ConsoleControl>,
    port_id: u32,
    stopfd: Arc<EventFd>,
) {
    let mut snapshot = DescriptorChainSnapshot::new(QUEUE_SIZE);
    loop {
        let head = {
            let Ok(mut state) = owner.lock() else {
                return;
            };
            state.started = true;
            if state.closed || state.eof || state.fault.is_some() {
                return;
            }
            let Some(queue) = state.queue.as_mut() else {
                return;
            };
            if !queue.queue.ready {
                drop(state);
                thread::park();
                continue;
            }
            match queue.queue.pop(&mem) {
                Some(head) => head,
                None => {
                    if queue.queue.capture_state().is_err() {
                        state.fail(ProviderFault::QueueState);
                        return;
                    }
                    drop(state);
                    thread::park();
                    continue;
                }
            }
        };
        let head_index = head.index;
        let chain = match snapshot.read(head) {
            Ok(chain) => chain,
            Err(_) => {
                if let Ok(mut state) = owner.lock() {
                    state.fail(ProviderFault::QueueState);
                }
                return;
            }
        };
        if chain
            .descriptors()
            .iter()
            .any(|descriptor| descriptor.flags & 2 == 0)
        {
            if let Ok(mut state) = owner.lock() {
                state.fail(ProviderFault::QueueState);
            }
            return;
        }
        let mut bytes_read = 0u32;
        let mut eof = false;
        let mut blocked = false;
        let mut failed = false;
        let mut capacity = false;
        for desc in chain.descriptors() {
            capacity |= desc.len != 0;
            let Ok(mut input) = input.lock() else {
                failed = true;
                break;
            };
            let result = mem.try_access(
                desc.len as usize,
                GuestAddress(desc.addr),
                |_, len, _, mut target| {
                    loop {
                        match input.read_volatile(&mut target) {
                            Ok(n) if n <= len => {
                                eof = n == 0;
                                bytes_read = bytes_read
                                    .checked_add(n as u32)
                                    .ok_or(GuestMemoryError::InvalidBackendAddress)?;
                                return Ok(n);
                            }
                            Ok(_) => return Err(GuestMemoryError::InvalidBackendAddress),
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                blocked = true;
                                return Ok(0);
                            }
                            Err(error) => return Err(GuestMemoryError::IOError(error)),
                        }
                    }
                },
            );
            if result.is_err() {
                failed = true;
                break;
            }
            if eof || blocked {
                break;
            }
        }
        let Ok(mut state) = owner.lock() else {
            return;
        };
        if failed {
            state.fail(ProviderFault::Worker);
            return;
        }
        state.eof = eof;
        let Some(queue) = state.queue.as_mut() else {
            state.fail(ProviderFault::QueueCount);
            return;
        };
        if bytes_read == 0 && !eof && capacity {
            if queue.queue.undo_pop(head_index).is_err() {
                state.fail(ProviderFault::QueueState);
                return;
            }
        } else {
            if queue.queue.add_used(&mem, head_index, bytes_read).is_err() {
                state.fail(ProviderFault::QueueState);
                return;
            }
            match queue.queue.needs_notification(&mem) {
                Ok(true) if interrupt.try_signal_used_queue().is_err() => {
                    state.fail(ProviderFault::Notification);
                    return;
                }
                Err(_) => {
                    state.fail(ProviderFault::QueueState);
                    return;
                }
                _ => {}
            }
        }
        if eof {
            if let Err(fault) = control.port_open(port_id, false) {
                state.fail(fault);
            }
            return;
        }
        let closed = state.closed;
        drop(state);
        if closed {
            return;
        }
        if blocked || (bytes_read == 0 && capacity) {
            let wait = input
                .lock()
                .map_err(|_| ProviderFault::DeviceLock)
                .and_then(|input| {
                    input
                        .wait_until_readable(Some(&stopfd))
                        .map_err(|_| ProviderFault::Worker)
                });
            if let Err(fault) = wait {
                if let Ok(mut state) = owner.lock() {
                    state.fail(fault);
                }
                return;
            }
        }
    }
}
