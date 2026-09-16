use std::collections::HashMap;
#[cfg(unix)]
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
#[cfg(unix)]
use std::time::Instant;
#[cfg(windows)]
use utils::windows::RawFd;

use super::super::Queue as VirtQueue;
use super::muxer::{ProxyMap, push_proxy_credit};
use super::muxer_rxq::MuxerRxQ;
use super::proxy::{NewProxyType, Proxy, ProxyRemoval, ProxyUpdate};
use super::tsi_stream::TsiStreamProxy;
#[cfg(unix)]
use crate::virtio::vsock::control_proxy::{ControlHandle, ControlProxy, Incoming};

use crate::virtio::InterruptTransport;
use crate::virtio::RuntimeGuestMemory;
use crate::virtio::vsock::defs;
use crate::virtio::vsock::unix_proxy::{UnixAcceptorProxy, UnixProxy};
use crossbeam_channel::Sender;
use rand::{RngExt, rng, rngs::ThreadRng};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

#[cfg(unix)]
struct SourcePortAllocator {
    start: u32,
    end: u32,
    next: u32,
}

#[cfg(unix)]
impl SourcePortAllocator {
    fn new(start: u32, end: u32) -> Self {
        Self {
            start,
            end,
            next: start,
        }
    }

    fn allocate(&mut self, live_proxy_ids: impl IntoIterator<Item = u64>) -> Option<u32> {
        let live_source_ports: HashSet<u32> = live_proxy_ids
            .into_iter()
            .map(|proxy_id| proxy_id as u32)
            .collect();
        for _ in self.start..self.end {
            let port = self.next;
            self.next = if port + 1 == self.end {
                self.start
            } else {
                port + 1
            };
            if !live_source_ports.contains(&port) {
                return Some(port);
            }
        }
        None
    }
}

pub struct MuxerThread {
    cid: u64,
    pub epoll: Epoll,
    rxq: Arc<Mutex<MuxerRxQ>>,
    proxy_map: ProxyMap,
    mem: RuntimeGuestMemory,
    queue: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    reaper_sender: Sender<u64>,
    unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
    #[cfg(unix)]
    control: Option<ControlProxy>,
    #[cfg(unix)]
    control_handle: Option<Arc<ControlHandle>>,
    #[cfg(unix)]
    source_ports: SourcePortAllocator,
}

impl MuxerThread {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cid: u64,
        epoll: Epoll,
        rxq: Arc<Mutex<MuxerRxQ>>,
        proxy_map: ProxyMap,
        mem: RuntimeGuestMemory,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        reaper_sender: Sender<u64>,
        unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
        #[cfg(unix)] control: Option<ControlProxy>,
        #[cfg(unix)] control_handle: Option<Arc<ControlHandle>>,
    ) -> Self {
        MuxerThread {
            cid,
            epoll,
            rxq,
            proxy_map,
            mem,
            queue,
            interrupt,
            reaper_sender,
            unix_ipc_port_map,
            #[cfg(unix)]
            control,
            #[cfg(unix)]
            control_handle,
            #[cfg(unix)]
            source_ports: SourcePortAllocator::new(1 << 30, 1 << 31),
        }
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("vsock muxer".into())
            .spawn(|| self.work())
            .unwrap();
    }

    pub fn update_polling(&self, id: u64, fd: RawFd, evset: EventSet) {
        debug!("update_polling id={id} fd={fd:?} evset={evset:?}");
        #[cfg(unix)]
        {
            let _ = self
                .epoll
                .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
            if !evset.is_empty() {
                let _ = self
                    .epoll
                    .ctl(ControlOperation::Add, fd, &EpollEvent::new(evset, id));
            }
        }
        #[cfg(windows)]
        {
            let sock = fd as windows_sys::Win32::Networking::WinSock::SOCKET;
            let _ = self
                .epoll
                .ctl_socket(ControlOperation::Delete, sock, &EpollEvent::default());
            if !evset.is_empty() {
                let _ =
                    self.epoll
                        .ctl_socket(ControlOperation::Add, sock, &EpollEvent::new(evset, id));
            }
        }
    }

    fn process_proxy_update(&self, id: u64, mut update: ProxyUpdate, thread_rng: &mut ThreadRng) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        let keep_proxy = matches!(&update.remove_proxy, ProxyRemoval::Keep);
        if !keep_proxy && let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().disable_deferred_credit();
        }

        let mut credit_used_queue = false;
        if keep_proxy && let Some(credit_rx) = update.push_credit_req.take() {
            debug!("send_credit_request");
            credit_used_queue = push_proxy_credit(
                self.cid,
                id,
                credit_rx,
                &self.proxy_map,
                &self.queue,
                &self.mem,
            );
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                debug!("immediately removing proxy: {id}");
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                debug!("deferring proxy removal: {id}");
                if self.reaper_sender.send(id).is_err() {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }

        let mut should_signal = update.signal_queue || credit_used_queue;

        if let Some((peer_port, accept_fd, family, proxy_type)) = update.new_proxy {
            let local_port: u32 = thread_rng.random_range(1024..u32::MAX);
            let new_id: u64 = ((peer_port as u64) << 32) | (local_port as u64);
            let new_proxy: Box<dyn Proxy> = match proxy_type {
                NewProxyType::Tcp => Box::new(TsiStreamProxy::new_reverse(
                    new_id,
                    self.cid,
                    id,
                    family,
                    local_port,
                    peer_port,
                    accept_fd,
                    self.mem.clone(),
                    self.queue.clone(),
                    self.rxq.clone(),
                )),
                NewProxyType::Unix => Box::new(UnixProxy::new_reverse(
                    new_id,
                    self.cid,
                    local_port,
                    peer_port,
                    accept_fd,
                    self.mem.clone(),
                    self.queue.clone(),
                    self.rxq.clone(),
                )),
            };
            self.proxy_map
                .write()
                .unwrap()
                .insert(new_id, Mutex::new(new_proxy));
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&new_id) {
                proxy.lock().unwrap().push_op_request();
            };
            should_signal = true;
        }

        if should_signal {
            debug!("signal IRQ");
            self.interrupt.signal_used_queue();
        }
    }

    fn create_listening_ipc_sockets(&self) {
        for (port, (path, do_listen)) in &self.unix_ipc_port_map {
            if !do_listen {
                continue;
            }
            let id = ((*port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            let proxy = match UnixAcceptorProxy::new(id, path, *port) {
                Ok(proxy) => proxy,
                Err(e) => {
                    warn!("Failed to create listening proxy at {path:?}: {e:?}");
                    continue;
                }
            };
            self.proxy_map
                .write()
                .unwrap()
                .insert(id, Mutex::new(Box::new(proxy)));
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                self.update_polling(id, proxy.lock().unwrap().as_raw_fd(), EventSet::IN);
            };
        }
    }

    #[cfg(unix)]
    fn update_control_polling(&self) {
        const CONTROL_EVENT: u64 = u64::MAX;
        let Some(control) = &self.control else {
            return;
        };
        let Some(fd) = control.as_raw_fd() else {
            return;
        };
        let mut events = EventSet::IN;
        if self
            .control_handle
            .as_ref()
            .is_some_and(|handle| handle.wants_write())
        {
            events |= EventSet::OUT;
        }
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
        let _ = self.epoll.ctl(
            ControlOperation::Add,
            fd,
            &EpollEvent::new(events, CONTROL_EVENT),
        );
    }

    #[cfg(unix)]
    fn process_control_message(&mut self, message: Incoming) {
        match message {
            Incoming::Connect { port, fd } => {
                let inserted_id = match self.proxy_map.write() {
                    Ok(mut proxy_map) => {
                        let Some(local_port) =
                            self.source_ports.allocate(proxy_map.keys().copied())
                        else {
                            warn!("vsock mux source-port range is exhausted");
                            return;
                        };
                        let id = ((port as u64) << 32) | local_port as u64;
                        let proxy = UnixProxy::new_mux_reverse(
                            id,
                            self.cid,
                            local_port,
                            port,
                            fd,
                            self.mem.clone(),
                            self.queue.clone(),
                            self.rxq.clone(),
                        );
                        proxy_map.insert(id, Mutex::new(Box::new(proxy)));
                        Ok(id)
                    }
                    Err(_) => Err(()),
                };
                let id = match inserted_id {
                    Ok(id) => id,
                    Err(()) => {
                        self.fail_mux_transport(
                            "proxy map is poisoned while accepting host CONNECT",
                        );
                        return;
                    }
                };
                let pushed = match self.proxy_map.read() {
                    Ok(proxy_map) => proxy_map.get(&id).is_some_and(|proxy| match proxy.lock() {
                        Ok(proxy) => {
                            proxy.push_op_request();
                            true
                        }
                        Err(_) => false,
                    }),
                    Err(_) => false,
                };
                if !pushed {
                    self.fail_mux_transport("proxy state is poisoned while accepting host CONNECT");
                    return;
                }
                self.interrupt.signal_used_queue();
            }
            Incoming::Admit(request_id) => self.finish_guest_request(request_id, true),
            Incoming::Reject(request_id) => self.finish_guest_request(request_id, false),
        }
    }

    #[cfg(unix)]
    fn finish_guest_request(&mut self, request_id: u32, admit: bool) {
        let Some(handle) = &self.control_handle else {
            return;
        };
        let Some(proxy_id) = handle.take_pending(request_id) else {
            debug!("ignoring late vsock mux reply for request {request_id}");
            return;
        };
        let (update, poisoned) = match self.proxy_map.read() {
            Ok(proxy_map) => match proxy_map.get(&proxy_id) {
                Some(proxy) => match proxy.lock() {
                    Ok(mut proxy) => (
                        if admit {
                            proxy.admit_mux()
                        } else {
                            proxy.fail_mux()
                        },
                        false,
                    ),
                    Err(_) => (None, true),
                },
                None => (None, false),
            },
            Err(_) => (None, true),
        };
        if poisoned {
            self.fail_mux_transport("proxy state is poisoned while resolving guest request");
            return;
        }
        if let Some(update) = update {
            self.process_proxy_update(proxy_id, update, &mut rng());
        }
    }

    #[cfg(unix)]
    fn fail_mux_transport(&mut self, reason: &str) {
        warn!("vsock mux transport failed: {reason}");
        let pending = self
            .control
            .as_mut()
            .map_or_else(Vec::new, ControlProxy::close);
        let proxy_map = match self.proxy_map.read() {
            Ok(proxy_map) => proxy_map,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut ids: Vec<u64> = proxy_map
            .iter()
            .filter_map(|(id, proxy)| {
                let proxy = match proxy.lock() {
                    Ok(proxy) => proxy,
                    Err(poisoned) => poisoned.into_inner(),
                };
                proxy.is_mux().then_some(*id)
            })
            .collect();
        drop(proxy_map);
        ids.extend(pending);
        ids.sort_unstable();
        ids.dedup();
        for id in &ids {
            let proxy_map = match self.proxy_map.read() {
                Ok(proxy_map) => proxy_map,
                Err(poisoned) => poisoned.into_inner(),
            };
            let update = proxy_map.get(id).and_then(|proxy| {
                let mut proxy = match proxy.lock() {
                    Ok(proxy) => proxy,
                    Err(poisoned) => poisoned.into_inner(),
                };
                proxy.fail_mux()
            });
            drop(proxy_map);
            if let Some(update) = update {
                if let Some((poll_id, fd, events)) = update.polling {
                    self.update_polling(poll_id, fd, events);
                }
                if update.signal_queue {
                    self.interrupt.signal_used_queue();
                }
            }
        }
        let mut proxy_map = match self.proxy_map.write() {
            Ok(proxy_map) => proxy_map,
            Err(poisoned) => poisoned.into_inner(),
        };
        for id in ids {
            proxy_map.remove(&id);
        }
    }

    #[cfg(unix)]
    fn service_control(&mut self, evset: EventSet) {
        let result = if let Some(control) = &mut self.control {
            let messages =
                if evset.intersects(EventSet::IN | EventSet::READ_HANG_UP | EventSet::HANG_UP) {
                    control.read_messages()
                } else {
                    Ok(Vec::new())
                };
            messages.and_then(|messages| {
                if evset.contains(EventSet::OUT) {
                    control.flush()?;
                }
                Ok(messages)
            })
        } else {
            return;
        };
        match result {
            Ok(messages) => {
                for message in messages {
                    self.process_control_message(message);
                }
                self.update_control_polling();
            }
            Err(error) => self.fail_mux_transport(&error),
        }
    }

    #[cfg(unix)]
    fn fail_pending_proxy(&self, proxy_id: u64) -> Result<Option<ProxyUpdate>, ()> {
        let proxy_map = self.proxy_map.read().map_err(|_| ())?;
        let Some(proxy) = proxy_map.get(&proxy_id) else {
            return Ok(None);
        };
        let mut proxy = proxy.lock().map_err(|_| ())?;
        Ok(proxy.fail_mux())
    }

    fn work(mut self) {
        #[cfg(unix)]
        const CONTROL_EVENT: u64 = u64::MAX;
        #[cfg(unix)]
        const CONTROL_WAKE_EVENT: u64 = u64::MAX - 1;
        let mut thread_rng = rng();
        self.create_listening_ipc_sockets();
        #[cfg(unix)]
        if let Some(control) = &self.control
            && let Some(fd) = control.as_raw_fd()
            && let Err(error) = self.epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::IN, CONTROL_EVENT),
            )
        {
            self.fail_mux_transport(&format!("failed to register control fd: {error}"));
        }
        #[cfg(unix)]
        if let Some(handle) = &self.control_handle {
            let _ = self.epoll.ctl(
                ControlOperation::Add,
                handle.wake_fd(),
                &EpollEvent::new(EventSet::IN, CONTROL_WAKE_EVENT),
            );
        }
        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            #[cfg(unix)]
            {
                let now = Instant::now();
                if self
                    .control
                    .as_ref()
                    .is_some_and(|control| control.partial_expired(now))
                {
                    self.fail_mux_transport("partial control frame exceeded its deadline");
                }
                if let Some(handle) = &self.control_handle {
                    let (expired, partial) = handle.expire();
                    for proxy_id in expired {
                        match self.fail_pending_proxy(proxy_id) {
                            Ok(Some(update)) => {
                                self.process_proxy_update(proxy_id, update, &mut thread_rng);
                            }
                            Ok(None) => {}
                            Err(()) => {
                                self.fail_mux_transport(
                                    "proxy state is poisoned while expiring guest request",
                                );
                                break;
                            }
                        }
                    }
                    if partial {
                        self.fail_mux_transport("partially sent frame exceeded its deadline");
                    }
                }
            }
            #[cfg(unix)]
            let queue_timeout = self
                .control_handle
                .as_ref()
                .map_or(-1, |handle| handle.next_timeout_ms());
            #[cfg(unix)]
            let partial_timeout = self
                .control
                .as_ref()
                .and_then(|control| control.partial_timeout_ms(Instant::now()))
                .unwrap_or(-1);
            #[cfg(unix)]
            let timeout = match (queue_timeout, partial_timeout) {
                (-1, timeout) | (timeout, -1) => timeout,
                (queue, partial) => queue.min(partial),
            };
            #[cfg(windows)]
            let timeout = -1;
            match self
                .epoll
                .wait(epoll_events.len(), timeout, epoll_events.as_mut_slice())
            {
                Ok(ev_cnt) => {
                    for ev in &epoll_events[0..ev_cnt] {
                        debug!("Event: ev.data={} ev.fd={}", ev.data(), ev.fd());
                        let evset = EventSet::from_bits(ev.events).unwrap();
                        let id = ev.data();

                        #[cfg(unix)]
                        if id == CONTROL_EVENT {
                            self.service_control(evset);
                            continue;
                        }
                        #[cfg(unix)]
                        if id == CONTROL_WAKE_EVENT {
                            if let Some(handle) = &self.control_handle {
                                handle.drain_wake();
                                if !handle.is_active() {
                                    self.fail_mux_transport("request id space is exhausted");
                                    continue;
                                }
                            }
                            self.service_control(EventSet::OUT);
                            continue;
                        }

                        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy_lock| {
                            let mut proxy = proxy_lock.lock().unwrap();
                            proxy.process_event(evset)
                        });

                        if let Some(update) = update {
                            self.process_proxy_update(id, update, &mut thread_rng);
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;
    use std::os::fd::OwnedFd;
    use std::sync::{Arc, Mutex, RwLock};

    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::virtio::vsock::muxer::ProxyMap;
    use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
    use crate::virtio::vsock::muxer_thread::SourcePortAllocator;
    use crate::virtio::vsock::unix_proxy::UnixProxy;
    use crate::virtio::{Queue, RuntimeGuestMemory};

    fn insert_host_proxy(proxy_map: &ProxyMap, guest_port: u32, source_port: u32) -> OwnedFd {
        let (fd, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let id = ((guest_port as u64) << 32) | source_port as u64;
        let memory = RuntimeGuestMemory::passthrough(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap(),
        );
        let proxy = UnixProxy::new_mux_reverse(
            id,
            3,
            source_port,
            guest_port,
            fd,
            memory,
            Arc::new(Mutex::new(Queue::new(256))),
            Arc::new(Mutex::new(MuxerRxQ::new())),
        );
        proxy_map
            .write()
            .unwrap()
            .insert(id, Mutex::new(Box::new(proxy)));
        peer
    }

    fn allocate(allocator: &mut SourcePortAllocator, proxy_map: &ProxyMap) -> Option<u32> {
        allocator.allocate(proxy_map.read().unwrap().keys().copied())
    }

    #[test]
    fn host_source_ports_are_global_and_freed_ports_can_be_reused() {
        let mut allocator = SourcePortAllocator::new(10, 12);
        let proxy_map: ProxyMap = Arc::new(RwLock::new(HashMap::new()));

        let first = allocate(&mut allocator, &proxy_map).unwrap();
        let _first_peer = insert_host_proxy(&proxy_map, 100, first);
        let second = allocate(&mut allocator, &proxy_map).unwrap();
        let _second_peer = insert_host_proxy(&proxy_map, 200, second);

        assert_ne!(first, second);
        assert_eq!(allocate(&mut allocator, &proxy_map), None);

        let first_id = (100u64 << 32) | first as u64;
        proxy_map.write().unwrap().remove(&first_id).unwrap();
        assert_eq!(allocate(&mut allocator, &proxy_map), Some(first));
        assert!(
            proxy_map
                .read()
                .unwrap()
                .keys()
                .all(|id| *id as u32 != first)
        );
    }
}
