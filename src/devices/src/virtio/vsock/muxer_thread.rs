use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(windows)]
use utils::windows::RawFd;

#[cfg(unix)]
use crate::virtio::vsock::control_proxy::{ControlHandle, ControlProxy, Incoming};
use crate::virtio::vsock::muxer::{ProxyMap, push_proxy_credit};
use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
use crate::virtio::vsock::packet::PacketQueue as VirtQueue;
use crate::virtio::vsock::proxy::{NewProxyType, Proxy, ProxyRemoval, ProxyUpdate};
use crate::virtio::vsock::tsi_stream::TsiStreamProxy;

use crate::virtio::InterruptTransport;
use crate::virtio::RuntimeGuestMemory;
use crate::virtio::vsock::defs;
use crate::virtio::vsock::reaper::{RetiredProxy, defer_proxy};
use crate::virtio::vsock::unix_proxy::{UnixAcceptorProxy, UnixProxy};
use crate::virtio::vsock::worker_control::{Owner, WorkerControl};
use crossbeam_channel::Sender;
use rand::{RngExt, rng, rngs::ThreadRng};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
#[cfg(windows)]
use utils::windows::AsRawFd;

/// Upper bound on one fenced-listener backoff; the exposure commit wakes it early.
const FENCED_LISTENER_BACKOFF: Duration = Duration::from_millis(10);

pub(crate) const SOURCE_PORT_START: u32 = 1 << 30;
pub(crate) const SOURCE_PORT_END: u32 = 1 << 31;

/// Guest socket state can outlive a removed host proxy. Never reuse its tuple,
/// including after worker restart or execution restore.
pub(crate) struct SourcePortAllocator {
    end: u32,
    next: AtomicU32,
}

impl SourcePortAllocator {
    pub(crate) fn new(next: u32, end: u32) -> Self {
        Self {
            end,
            next: AtomicU32::new(next),
        }
    }

    pub(crate) fn next(&self) -> u32 {
        self.next.load(Ordering::Acquire)
    }

    fn allocate(&self, live_proxy_ids: impl IntoIterator<Item = u64> + Clone) -> Option<u32> {
        while let Ok(port) = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                (next < self.end).then(|| next + 1)
            })
        {
            if !live_proxy_ids
                .clone()
                .into_iter()
                .any(|id| id as u32 == port)
            {
                return Some(port);
            }
        }
        None
    }
}

pub(crate) struct MuxerThread {
    cid: u64,
    pub epoll: Epoll,
    rxq: Arc<Mutex<MuxerRxQ>>,
    proxy_map: ProxyMap,
    mem: RuntimeGuestMemory,
    queue: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    reaper_sender: Sender<RetiredProxy>,
    unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
    #[cfg(unix)]
    control: Option<ControlProxy>,
    #[cfg(unix)]
    control_registered: bool,
    #[cfg(unix)]
    control_handle: Option<Arc<ControlHandle>>,
    #[cfg(unix)]
    source_ports: Arc<SourcePortAllocator>,
    worker_control: Arc<WorkerControl>,
    retired_ports: Vec<u32>,
    initialized: bool,
    /// This thread's registration; activation preparation is bound to it.
    instance: u64,
}

impl MuxerThread {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cid: u64,
        epoll: Epoll,
        rxq: Arc<Mutex<MuxerRxQ>>,
        proxy_map: ProxyMap,
        mem: RuntimeGuestMemory,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        reaper_sender: Sender<RetiredProxy>,
        unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
        #[cfg(unix)] control: Option<ControlProxy>,
        #[cfg(unix)] control_handle: Option<Arc<ControlHandle>>,
        worker_control: Arc<WorkerControl>,
        retired_ports: Vec<u32>,
        #[cfg(unix)] source_ports: Arc<SourcePortAllocator>,
        instance: u64,
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
            control_registered: false,
            #[cfg(unix)]
            control_handle,
            #[cfg(unix)]
            source_ports,
            retired_ports,
            worker_control,
            initialized: false,
            instance,
        }
    }

    pub fn run(self) -> std::io::Result<thread::JoinHandle<()>> {
        thread::Builder::new()
            .name("vsock muxer".into())
            .spawn(|| self.work())
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
                if defer_proxy(&self.reaper_sender, id, &self.proxy_map).is_err() {
                    self.worker_control.fail();
                }
            }
        }

        let mut should_signal = update.signal_queue || credit_used_queue;

        if let Some((peer_port, accept_fd, family, proxy_type)) = update.new_proxy {
            let local_port: u32 = thread_rng.random_range(1024..u32::MAX);
            let new_id: u64 = ((peer_port as u64) << 32) | (local_port as u64);
            let new_proxy: Arc<Mutex<dyn Proxy>> = match proxy_type {
                NewProxyType::Tcp => Arc::new(Mutex::new(TsiStreamProxy::new_reverse(
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
                ))),
                NewProxyType::Unix => Arc::new(Mutex::new(UnixProxy::new_reverse(
                    new_id,
                    self.cid,
                    local_port,
                    peer_port,
                    accept_fd,
                    self.mem.clone(),
                    self.queue.clone(),
                    self.rxq.clone(),
                ))),
            };
            self.proxy_map.write().unwrap().insert(new_id, new_proxy);
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

    /// Host listeners stay owned and registered but never accept while the
    /// effective activation fence, including an uncommitted exposure, holds.
    fn fenced_listener(&self, id: u64) -> bool {
        id as u32 == defs::TSI_PROXY_PORT
            && self
                .unix_ipc_port_map
                .get(&((id >> 32) as u32))
                .is_some_and(|(_, listen)| *listen)
            && self.worker_control.activation_fenced()
    }

    fn create_listening_ipc_sockets(&self) -> std::io::Result<()> {
        let mut map = self
            .proxy_map
            .write()
            .map_err(|_| std::io::Error::other("vsock proxy map poisoned"))?;
        for (port, (path, listen)) in &self.unix_ipc_port_map {
            if !listen {
                continue;
            }
            let id = (u64::from(*port) << 32) | u64::from(defs::TSI_PROXY_PORT);
            if let std::collections::hash_map::Entry::Vacant(entry) = map.entry(id) {
                let proxy = UnixAcceptorProxy::new(id, path, *port)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                entry.insert(Arc::new(Mutex::new(proxy)));
            }
            let proxy = map
                .get(&id)
                .ok_or_else(|| std::io::Error::other("missing vsock listener"))?;
            let proxy = proxy
                .lock()
                .map_err(|_| std::io::Error::other("vsock listener poisoned"))?;
            #[cfg(unix)]
            self.epoll.ctl(
                ControlOperation::Add,
                proxy.as_raw_fd(),
                &EpollEvent::new(EventSet::IN, id),
            )?;
            #[cfg(windows)]
            self.update_polling(id, proxy.as_raw_fd(), EventSet::IN);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn update_control_polling(&mut self) {
        const CONTROL_EVENT: u64 = u64::MAX;
        let Some(control) = &self.control else {
            return;
        };
        let Some(fd) = control.as_raw_fd() else {
            return;
        };
        if self.control_registered {
            if let Err(error) = self
                .epoll
                .ctl(ControlOperation::Delete, fd, &EpollEvent::default())
            {
                self.fail_mux_transport(&format!("failed to suspend control fd: {error}"));
                return;
            }
            self.control_registered = false;
        }
        // Keep the first request and its SCM_RIGHTS descriptor in the socket
        // until the admitted Linux guest has retired the transport reset.
        if !self.worker_control.transport_ready() {
            return;
        }
        let mut events = EventSet::IN;
        if self
            .control_handle
            .as_ref()
            .is_some_and(|handle| handle.wants_write())
        {
            events |= EventSet::OUT;
        }
        if let Err(error) = self.epoll.ctl(
            ControlOperation::Add,
            fd,
            &EpollEvent::new(events, CONTROL_EVENT),
        ) {
            self.fail_mux_transport(&format!("failed to register control fd: {error}"));
        } else {
            self.control_registered = true;
        }
    }

    #[cfg(unix)]
    fn process_control_message(&mut self, message: Incoming) {
        match message {
            Incoming::Connect { port, fd } => {
                if !self.worker_control.admits(port) {
                    return;
                }
                let inserted_id = match self.proxy_map.write() {
                    Ok(mut proxy_map) => {
                        let Some(local_port) = self.source_ports.allocate(
                            proxy_map
                                .keys()
                                .copied()
                                .chain(self.retired_ports.iter().copied().map(u64::from)),
                        ) else {
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
                        proxy_map.insert(id, Arc::new(Mutex::new(proxy)));
                        Ok(id)
                    }
                    Err(_) => Err(()),
                };
                #[cfg(feature = "native-device-probe")]
                if inserted_id.is_ok() {
                    self.worker_control
                        .record(crate::virtio::vsock::worker_control::WorkerCounter::HostConnect);
                }
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
            #[cfg(feature = "native-device-probe")]
            self.worker_control.record(if admit {
                crate::virtio::vsock::worker_control::WorkerCounter::Admitted
            } else {
                crate::virtio::vsock::worker_control::WorkerCounter::Rejected
            });
            self.process_proxy_update(proxy_id, update, &mut rng());
        }
    }

    #[cfg(unix)]
    fn fail_mux_transport(&mut self, reason: &str) {
        self.worker_control.fail();
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
        if !self.worker_control.transport_ready() {
            self.update_control_polling();
            return;
        }
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

    fn prepare_activation_listeners(&mut self, epoch: u64) -> std::io::Result<()> {
        let release_pending = self.worker_control.release_pending();
        if !self.initialized && (!self.worker_control.activation_fenced() || release_pending) {
            self.create_listening_ipc_sockets()?;
            self.initialized = true;
        }
        // Epoch changes invalidate an acknowledgement, not these retained
        // listener registrations. Retry until this same mux is acknowledged.
        if self.initialized && release_pending {
            self.worker_control
                .complete_activation_release(epoch, self.instance);
        }
        Ok(())
    }

    fn work(mut self) {
        #[cfg(unix)]
        const CONTROL_EVENT: u64 = u64::MAX;
        #[cfg(unix)]
        const CONTROL_WAKE_EVENT: u64 = u64::MAX - 1;
        const OWNER_WAKE_EVENT: u64 = u64::MAX - 2;
        let mut thread_rng = rng();
        if !self.worker_control.boundary(Owner::Mux) {
            return;
        }
        if !self.initialized && !self.worker_control.activation_fenced() {
            if self.create_listening_ipc_sockets().is_err() {
                self.worker_control.fail();
                return;
            }
            self.initialized = true;
        }
        if self
            .epoll
            .ctl(
                ControlOperation::Add,
                self.worker_control.wake.as_raw_fd(),
                &EpollEvent::new(EventSet::IN, OWNER_WAKE_EVENT),
            )
            .is_err()
        {
            self.worker_control.fail();
            return;
        }
        #[cfg(unix)]
        self.update_control_polling();
        #[cfg(unix)]
        if let Some(handle) = &self.control_handle
            && self
                .epoll
                .ctl(
                    ControlOperation::Add,
                    handle.wake_fd(),
                    &EpollEvent::new(EventSet::IN, CONTROL_WAKE_EVENT),
                )
                .is_err()
        {
            self.worker_control.fail();
            return;
        }
        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        let mut ready_proxies: [Option<Arc<Mutex<dyn Proxy>>>; 32] = std::array::from_fn(|_| None);
        'work: loop {
            if !self.worker_control.boundary(Owner::Mux) {
                return;
            }
            let epoch = self.worker_control.epoch();
            if self.prepare_activation_listeners(epoch).is_err() {
                self.worker_control.fail();
                return;
            }
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
            self.worker_control.reconciled(Owner::Mux, epoch);
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
                    {
                        let Ok(map) = self.proxy_map.read() else {
                            self.worker_control.fail();
                            return;
                        };
                        for (slot, event) in ready_proxies.iter_mut().zip(&epoll_events[..ev_cnt]) {
                            *slot = map.get(&event.data()).cloned();
                        }
                    }
                    let mut fenced_listener = false;
                    for (index, ev) in epoll_events[..ev_cnt].iter().enumerate() {
                        if !self
                            .worker_control
                            .boundary_releasing(Owner::Mux, || ready_proxies.fill_with(|| None))
                        {
                            return;
                        }
                        if self.worker_control.epoch() != epoch {
                            ready_proxies.fill_with(|| None);
                            continue 'work;
                        }
                        let ready_proxy = ready_proxies[index].take();
                        if ev.data() == OWNER_WAKE_EVENT {
                            while self.worker_control.wake.read().is_ok() {}
                            #[cfg(unix)]
                            self.update_control_polling();
                            continue;
                        }
                        debug!("Event: ev.data={} ev.fd={}", ev.data(), ev.fd());
                        let evset = EventSet::from_bits_truncate(ev.events);
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

                        if self.fenced_listener(id) {
                            fenced_listener = true;
                            continue;
                        }
                        if !self.worker_control.admits((id >> 32) as u32) {
                            continue;
                        }
                        let update = ready_proxy.and_then(|proxy| {
                            match process_ready_proxy(&self.proxy_map, id, &proxy, evset) {
                                Ok(update) => update,
                                Err(()) => {
                                    self.worker_control.fail();
                                    None
                                }
                            }
                        });

                        if let Some(update) = update {
                            self.process_proxy_update(id, update, &mut thread_rng);
                        }
                    }
                    if fenced_listener {
                        self.worker_control.await_exposure(FENCED_LISTENER_BACKOFF);
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }
}

fn process_ready_proxy(
    proxies: &ProxyMap,
    id: u64,
    ready: &Arc<Mutex<dyn Proxy>>,
    events: EventSet,
) -> Result<Option<ProxyUpdate>, ()> {
    let map = proxies.read().map_err(|_| ())?;
    if map
        .get(&id)
        .is_none_or(|current| !Arc::ptr_eq(current, ready))
    {
        return Ok(None);
    }
    let mut proxy = ready.lock().map_err(|_| ())?;
    Ok(Some(proxy.process_event(events)))
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;
    use std::os::fd::OwnedFd;
    use std::sync::{Arc, Mutex, RwLock};

    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use vm_memory::GuestAddress;

    use crate::virtio::vsock::muxer::ProxyMap;
    use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
    use crate::virtio::vsock::muxer_thread::{SourcePortAllocator, process_ready_proxy};
    use crate::virtio::vsock::unix_proxy::UnixProxy;
    use crate::virtio::{Queue, RuntimeGuestMemory};
    use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

    fn insert_host_proxy(proxy_map: &ProxyMap, guest_port: u32, source_port: u32) -> OwnedFd {
        let (fd, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let id = ((guest_port as u64) << 32) | source_port as u64;
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap();
        let proxy = UnixProxy::new_mux_reverse(
            id,
            3,
            source_port,
            guest_port,
            fd,
            memory,
            Arc::new(Mutex::new(
                crate::virtio::vsock::packet::PacketQueue::from_queue(Queue::new(256)),
            )),
            Arc::new(Mutex::new(MuxerRxQ::new())),
        );
        proxy_map
            .write()
            .unwrap()
            .insert(id, Arc::new(Mutex::new(proxy)));
        peer
    }

    fn allocate(allocator: &mut SourcePortAllocator, proxy_map: &ProxyMap) -> Option<u32> {
        allocator.allocate(proxy_map.read().unwrap().keys().copied())
    }

    #[test]
    fn host_source_ports_are_global_and_closed_tuples_are_not_reused() {
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
        assert_eq!(allocate(&mut allocator, &proxy_map), None);
    }

    #[test]
    fn provider_vsock_cached_ready_event_cannot_target_reused_session_id() {
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::new()));
        let port = 1027;
        let source = 1 << 30;
        let id = (u64::from(port) << 32) | u64::from(source);
        let original_peer = insert_host_proxy(&map, port, source);
        let original = map.read().expect("proxy map").get(&id).unwrap().clone();
        let mut epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                original.lock().expect("original proxy").as_raw_fd(),
                &EpollEvent::new(EventSet::IN, id),
            )
            .unwrap();
        nix::unistd::write(&original_peer, b"old").unwrap();
        let mut events = [EpollEvent::default(); 1];
        assert_eq!(epoll.wait(1, 1000, &mut events).unwrap(), 1);
        let replacement_peer = insert_host_proxy(&map, port, source);
        nix::unistd::write(&replacement_peer, b"new").unwrap();
        assert!(
            process_ready_proxy(&map, events[0].data(), &original, events[0].event_set())
                .unwrap_or_else(|_| panic!("proxy dispatch failed"))
                .is_none()
        );
        let replacement = map.read().expect("proxy map").get(&id).unwrap().clone();
        let mut bytes = [0u8; 3];
        assert_eq!(
            nix::sys::socket::recv(
                replacement.lock().expect("replacement proxy").as_raw_fd(),
                &mut bytes,
                nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT
            )
            .unwrap(),
            3
        );
        assert_eq!(&bytes, b"new");
    }

    #[test]
    fn provider_vsock_listener_preparation_retries_a_stale_epoch_without_rebinding() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::InterruptTransport;
        use crate::virtio::lifecycle::ActivationExposure;
        use crate::virtio::vsock::muxer_thread::MuxerThread;
        use crate::virtio::vsock::packet::PacketQueue;
        use crate::virtio::vsock::worker_control::WorkerControl;

        let path = utils::tempfile::TempFile::new().unwrap();
        std::fs::remove_file(path.as_path()).unwrap();
        let control = WorkerControl::new().unwrap();
        control.bind_activation(1024).unwrap();
        control.transport_reset_completed();
        let instance = control.bind_mux().unwrap();
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let mut mux = MuxerThread::new(
            3,
            Epoll::new().unwrap(),
            Arc::new(Mutex::new(MuxerRxQ::new())),
            Arc::new(RwLock::new(HashMap::new())),
            RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap(),
            Arc::new(Mutex::new(PacketQueue::from_queue(Queue::new(256)))),
            InterruptTransport::new(DummyIrqChip::new().into(), "vsock-epoch".into(), None)
                .unwrap(),
            sender,
            HashMap::from([(1027, (path.as_path().to_path_buf(), true))]),
            None,
            None,
            control.clone(),
            Vec::new(),
            Arc::new(SourcePortAllocator::new(1 << 30, 1 << 31)),
            instance,
        );
        let stale_epoch = control.epoch();
        let exposure = ActivationExposure::new();
        control.release_activation(&exposure).unwrap();
        mux.prepare_activation_listeners(stale_epoch).unwrap();
        assert!(mux.initialized);
        assert!(control.release_pending());
        assert!(control.activation_fenced());
        // Re-registering the retained listener would fail with EEXIST.
        mux.prepare_activation_listeners(control.epoch()).unwrap();
        assert!(!control.release_pending());
        assert!(
            control.activation_fenced(),
            "shared commit must still fence traffic"
        );
        assert!(!exposure.is_open());
    }
}
