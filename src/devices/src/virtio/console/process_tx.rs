use crate::virtio::console::defs::QUEUE_SIZE;
use crate::virtio::console::port::Direction;
use crate::virtio::console::port_io::PortOutput;
use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::lifecycle::ProviderFault;
use crate::virtio::{InterruptTransport, RuntimeGuestMemory};
use std::sync::{Arc, Mutex};
use std::{io, thread};
use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, GuestMemoryError};

pub(crate) fn process_tx(
    mem: RuntimeGuestMemory,
    owner: Arc<Mutex<Direction>>,
    interrupt: InterruptTransport,
    output: Arc<Mutex<Box<dyn PortOutput + Send>>>,
    terminal_stopfd: Arc<EventFd>,
) {
    let mut snapshot = DescriptorChainSnapshot::new(QUEUE_SIZE);
    loop {
        let head = {
            let Ok(mut state) = owner.lock() else {
                return;
            };
            state.started = true;
            if state.closed || state.fault.is_some() {
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
            .any(|descriptor| descriptor.flags & 2 != 0)
        {
            if let Ok(mut state) = owner.lock() {
                state.fail(ProviderFault::QueueState);
            }
            return;
        }
        let mut bytes_written = 0u32;
        let mut failed = false;
        let mut cancelled = false;
        for desc in chain.descriptors() {
            let Ok(mut output) = output.lock() else {
                failed = true;
                break;
            };
            let result = mem.try_read_access(
                desc.len as usize,
                GuestAddress(desc.addr),
                |_, len, _, src| {
                    loop {
                        match output.write_volatile(src) {
                            Ok(n) if n > 0 && n <= len => {
                                bytes_written = bytes_written
                                    .checked_add(n as u32)
                                    .ok_or(GuestMemoryError::InvalidBackendAddress)?;
                                return Ok(n);
                            }
                            Ok(_) => {
                                return Err(GuestMemoryError::IOError(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "console output made no progress",
                                )));
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                #[cfg(feature = "native-device-probe")]
                                {
                                    owner
                                        .lock()
                                        .map_err(|_| GuestMemoryError::InvalidBackendAddress)?
                                        .blocked_output = Some((head_index, bytes_written, len));
                                }
                                let result = output.wait_until_writable(&terminal_stopfd);
                                #[cfg(feature = "native-device-probe")]
                                {
                                    owner
                                        .lock()
                                        .map_err(|_| GuestMemoryError::InvalidBackendAddress)?
                                        .blocked_output = None;
                                }
                                result.map_err(GuestMemoryError::IOError)?;
                                if owner
                                    .lock()
                                    .map_err(|_| GuestMemoryError::InvalidBackendAddress)?
                                    .terminal
                                {
                                    cancelled = true;
                                    return Err(GuestMemoryError::InvalidBackendAddress);
                                }
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
        }
        let Ok(mut state) = owner.lock() else {
            return;
        };
        if cancelled {
            return;
        }
        if failed {
            state.fail(ProviderFault::Worker);
            return;
        }
        // Destructive shutdown abandons the accepted head without publishing a completion.
        // Reversible close never sets terminal and must finish the entire accepted write.
        if state.terminal {
            return;
        }
        let Some(queue) = state.queue.as_mut() else {
            state.fail(ProviderFault::QueueCount);
            return;
        };
        if queue
            .queue
            .add_used(&mem, head_index, bytes_written)
            .is_err()
        {
            state.fail(ProviderFault::QueueState);
            return;
        }
        let notification = queue.queue.needs_notification(&mem);
        match notification {
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
}
