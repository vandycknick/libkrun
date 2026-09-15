use std::collections::HashMap;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
#[cfg(windows)]
use utils::windows::RawFd;

use super::super::Queue as VirtQueue;
use super::TsiFlags;
use super::VsockError;
use super::defs;
use super::defs::uapi;
use super::muxer_rxq::{MuxerRxQ, rx_to_pkt};
use super::muxer_thread::MuxerThread;
use super::packet::{TsiConnectReq, TsiGetnameRsp, VsockPacket};
use super::reaper::ReaperThread;
#[cfg(target_os = "macos")]
use super::timesync::TimesyncThread;
use super::tsi_dgram::TsiDgramProxy;
use super::tsi_stream::TsiStreamProxy;
use super::unix_proxy::UnixProxy;
#[cfg(unix)]
use crate::virtio::vsock::control_proxy::{
    ControlHandle, ControlProxy, UnixSocketIdentity, prepare_stream,
};
use crate::virtio::vsock::proxy::{Proxy, ProxyRemoval, ProxyStatus, ProxyUpdate};
use crossbeam_channel::{Sender, unbounded};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use crate::virtio::{InterruptTransport, RuntimeGuestMemory};
use std::net::{Ipv4Addr, SocketAddrV4};

#[cfg(windows)]
use defs::{LINUX_AF_INET as AF_INET, LINUX_AF_INET6 as AF_INET6, LINUX_AF_UNIX as AF_UNIX};
#[cfg(unix)]
use libc::{AF_INET, AF_INET6, AF_UNIX};

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
    Reset {
        local_port: u32,
        peer_port: u32,
    },
    Shutdown {
        local_port: u32,
        peer_port: u32,
        flags: u32,
    },
    GetnameResponse {
        local_port: u32,
        peer_port: u32,
        data: TsiGetnameRsp,
    },
    ConnResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    OpRequest {
        local_port: u32,
        peer_port: u32,
    },
    OpResponse {
        local_port: u32,
        peer_port: u32,
    },
    CreditRequest {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    CreditUpdate {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    ListenResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    AcceptResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PushPacketOutcome {
    UsedQueue,
    Buffered,
}

pub(crate) fn try_push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &RuntimeGuestMemory,
) -> Result<PushPacketOutcome, Box<MuxerRx>> {
    let rx = match try_push_virtqueue(cid, rx, queue_mutex, mem) {
        Ok(()) => return Ok(PushPacketOutcome::UsedQueue),
        Err(rx) => rx,
    };

    rxq_mutex
        .lock()
        .unwrap()
        .push(*rx)
        .map(|()| PushPacketOutcome::Buffered)
}

fn try_push_virtqueue(
    cid: u64,
    rx: MuxerRx,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &RuntimeGuestMemory,
) -> Result<(), Box<MuxerRx>> {
    let mut queue = queue_mutex.lock().unwrap();
    if let Some(head) = queue.pop(mem) {
        if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
            rx_to_pkt(cid, rx, &mut pkt);
            if let Err(e) = queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len()) {
                error!("failed to add used elements to the queue: {e:?}");
            }
            return Ok(());
        }
        return Ok(());
    }

    Err(Box::new(rx))
}

fn flush_proxy_credit(
    cid: u64,
    id: u64,
    proxy: &mut dyn Proxy,
    queue: &Arc<Mutex<VirtQueue>>,
    mem: &RuntimeGuestMemory,
) -> bool {
    let mut used_queue = false;
    while let Some(credit) = proxy.pop_deferred_credit() {
        match try_push_virtqueue(cid, *credit, queue, mem) {
            Ok(()) => used_queue = true,
            Err(credit) => {
                if proxy.defer_credit(credit).is_err() {
                    error!("proxy {id} rejected a deferred credit packet");
                }
                break;
            }
        }
    }
    used_queue
}

pub(crate) fn push_proxy_credit(
    cid: u64,
    id: u64,
    credit: MuxerRx,
    proxy_map: &ProxyMap,
    queue: &Arc<Mutex<VirtQueue>>,
    mem: &RuntimeGuestMemory,
) -> bool {
    let proxy_map = proxy_map.read().unwrap();
    let Some(proxy) = proxy_map.get(&id) else {
        return false;
    };
    let mut proxy = proxy.lock().unwrap();
    if !proxy.deferred_credit_enabled() {
        return false;
    }
    if proxy.defer_credit(Box::new(credit)).is_err() {
        return false;
    }
    flush_proxy_credit(cid, id, proxy.as_mut(), queue, mem)
}

pub fn push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &RuntimeGuestMemory,
) {
    if try_push_packet(cid, rx, rxq_mutex, queue_mutex, mem).is_err() {
        error!("couldn't preserve packet because the bounded RX queue is full");
    }
}

pub struct VsockMuxer {
    cid: u64,
    host_port_map: Option<HashMap<u16, u16>>,
    queue: Option<Arc<Mutex<VirtQueue>>>,
    mem: Option<RuntimeGuestMemory>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    epoll: Epoll,
    interrupt: Option<InterruptTransport>,
    proxy_map: ProxyMap,
    reaper_sender: Option<Sender<u64>>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    tsi_flags: TsiFlags,
    #[cfg(unix)]
    control: Option<ControlProxy>,
    #[cfg(unix)]
    control_handle: Option<Arc<ControlHandle>>,
    #[cfg(unix)]
    protected_identities: Vec<UnixSocketIdentity>,
}

impl VsockMuxer {
    #[cfg(unix)]
    fn fence_control(&self, reason: &str) {
        warn!("fencing vsock mux transport: {reason}");
        if let Some(control) = &self.control_handle {
            control.fence();
        }
    }

    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
    ) -> Self {
        VsockMuxer {
            cid,
            host_port_map,
            queue: None,
            mem: None,
            rxq: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll: Epoll::new().unwrap(),
            interrupt: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            reaper_sender: None,
            unix_ipc_port_map,
            tsi_flags,
            #[cfg(unix)]
            control: None,
            #[cfg(unix)]
            control_handle: None,
            #[cfg(unix)]
            protected_identities: Vec::new(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn set_unix_mux_fd(&mut self, fd: OwnedFd) -> std::io::Result<()> {
        let (control, handle) = ControlProxy::new(fd, self.protected_identities.drain(..))?;
        self.control = Some(control);
        self.control_handle = Some(handle);
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn add_unix_mux_protected_identity(&mut self, identity: UnixSocketIdentity) {
        if let Some(control) = &mut self.control {
            control.add_protected_identity(identity);
        } else {
            self.protected_identities.push(identity);
        }
    }

    pub(crate) fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
    ) {
        self.queue = Some(queue.clone());
        self.mem = Some(mem.clone());
        self.interrupt = Some(interrupt.clone());

        #[cfg(target_os = "macos")]
        {
            let timesync =
                TimesyncThread::new(self.cid, mem.clone(), queue.clone(), interrupt.clone());
            timesync.run();
        }

        let (sender, receiver) = unbounded();

        let thread = MuxerThread::new(
            self.cid,
            self.epoll.clone(),
            self.rxq.clone(),
            self.proxy_map.clone(),
            mem,
            queue,
            interrupt.clone(),
            sender.clone(),
            self.unix_ipc_port_map.clone().unwrap_or_default(),
            #[cfg(unix)]
            self.control.take(),
            #[cfg(unix)]
            self.control_handle.clone(),
        );
        thread.run();

        self.reaper_sender = Some(sender);
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        reaper.run();
    }

    pub(crate) fn has_pending_rx(&self) -> bool {
        !self.rxq.lock().unwrap().is_empty()
    }

    pub(crate) fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("recv_stream_pkt");
        if self.rxq.lock().unwrap().is_empty() {
            return Err(VsockError::NoData);
        }

        if let Some(rx) = self.rxq.lock().unwrap().pop() {
            rx_to_pkt(self.cid, rx, pkt);
        }

        Ok(())
    }

    pub(crate) fn retry_deferred_credit(&self) -> bool {
        let (Some(queue), Some(mem)) = (&self.queue, &self.mem) else {
            return false;
        };
        let proxy_map = self.proxy_map.read().unwrap();
        let mut used_queue = false;
        for proxy in proxy_map.values() {
            let mut proxy = proxy.lock().unwrap();
            used_queue |= flush_proxy_credit(self.cid, proxy.id(), proxy.as_mut(), queue, mem);
        }
        used_queue
    }

    fn push_packet(&self, rx: MuxerRx) {
        let mem = match self.mem.as_ref() {
            Some(m) => m,
            None => {
                error!("proxy creation without mem");
                return;
            }
        };
        let queue_mutex = match self.queue.as_ref() {
            Some(q) => q,
            None => {
                error!("stream proxy creation without stream queue");
                return;
            }
        };

        push_packet(self.cid, rx, &self.rxq, queue_mutex, mem);
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

    fn process_proxy_update(&self, id: u64, mut update: ProxyUpdate) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        let keep_proxy = matches!(&update.remove_proxy, ProxyRemoval::Keep);
        if !keep_proxy && let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().disable_deferred_credit();
        }

        let mut credit_used_queue = false;
        if keep_proxy
            && let Some(credit) = update.push_credit_req.take()
            && let (Some(queue), Some(mem)) = (&self.queue, &self.mem)
        {
            credit_used_queue =
                push_proxy_credit(self.cid, id, credit, &self.proxy_map, queue, mem);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                info!("immediately removing proxy: {id}");
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                info!("deferring proxy removal: {id}");
                if let Some(reaper_sender) = &self.reaper_sender
                    && reaper_sender.send(id).is_err()
                {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }

        if (update.signal_queue || credit_used_queue)
            && let Some(interrupt) = &self.interrupt
        {
            interrupt.signal_used_queue();
        }
    }

    fn process_proxy_create(&self, pkt: &VsockPacket) {
        debug!("proxy create request");
        if let Some(req) = pkt.read_proxy_create() {
            debug!(
                "proxy create request: peer_port={}, type={}",
                req.peer_port, req._type
            );
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    error!("proxy creation without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    error!("stream proxy creation without stream queue");
                    return;
                }
            };
            match req._type {
                defs::SOCK_STREAM => {
                    debug!("proxy create stream");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family == AF_UNIX as u16
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting stream unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family == AF_INET as u16 || req.family == AF_INET6 as u16)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting stream inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiStreamProxy::new(
                        id,
                        self.cid,
                        req.family,
                        defs::TSI_PROXY_PORT,
                        req.peer_port,
                        pkt.src_port(),
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating tcp proxy: {e}"),
                    }
                }
                defs::SOCK_DGRAM => {
                    debug!("proxy create dgram");
                    let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
                    if req.family == AF_UNIX as u16
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_UNIX)
                    {
                        warn!("rejecting dgram unix proxy because HIJACK_UNIX is disabled");
                        return;
                    }
                    if (req.family == AF_INET as u16 || req.family == AF_INET6 as u16)
                        && !self.tsi_flags.contains(TsiFlags::HIJACK_INET)
                    {
                        warn!("rejecting dgram inet proxy because HIJACK_INET is disabled");
                        return;
                    }
                    match TsiDgramProxy::new(
                        id,
                        self.cid,
                        req.family,
                        req.peer_port,
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating udp proxy: {e}"),
                    }
                }
                _ => debug!("unknown type on connection request"),
            };
        }
    }

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("proxy connect request");
        if let Some(req) = pkt.read_connect_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("proxy connect request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => {
                    self.process_proxy_update(id, proxy.lock().unwrap().connect(pkt, req));
                }
                None => self.push_packet(MuxerRx::ConnResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::ECONNREFUSED,
                }),
            }
        }
    }

    fn process_getname(&self, pkt: &VsockPacket) {
        debug!("new getname request");
        if let Some(req) = pkt.read_getname_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "new getname request: id={}, peer_port={}, local_port={}",
                id, req.peer_port, req.local_port
            );

            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => proxy.lock().unwrap().getpeername(pkt),
                None => self.push_packet(MuxerRx::GetnameResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    data: TsiGetnameRsp {
                        result: -libc::EINVAL,
                        addr_len: 0,
                        addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
                    },
                }),
            }
        }
    }

    fn process_sendto_addr(&self, pkt: &VsockPacket) {
        debug!("new DGRAM sendto addr: src={}", pkt.src_port());
        if let Some(req) = pkt.read_sendto_addr() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("new DGRAM sendto addr: id={id}");
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().sendto_addr(req));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_sendto_data(&self, pkt: &VsockPacket) {
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
        debug!("DGRAM sendto data: id={} src={}", id, pkt.src_port());
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().sendto_data(pkt);
        }
    }

    fn process_listen_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM listen request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_listen_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM listen request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(
                    id,
                    proxy.lock().unwrap().listen(pkt, req, &self.host_port_map),
                ),
                None => self.push_packet(MuxerRx::ListenResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EPERM,
                }),
            };
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("DGRAM accept request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_accept_req() {
            let id = ((req.peer_port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            debug!("DGRAM accept request: id={id}");
            match self.proxy_map.read().unwrap().get(&id) {
                Some(proxy) => self.process_proxy_update(id, proxy.lock().unwrap().accept(req)),
                None => self.push_packet(MuxerRx::AcceptResponse {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                    result: -libc::EINVAL,
                }),
            }
        }
    }

    fn process_proxy_release(&self, pkt: &VsockPacket) {
        debug!("DGRAM release request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_release_req() {
            let id = ((req.peer_port as u64) << 32) | (req.local_port as u64);
            debug!(
                "DGRAM release request: id={} local_port={} peer_port={}",
                id, req.local_port, req.peer_port
            );
            let update = if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                Some(proxy.lock().unwrap().release())
            } else {
                debug!(
                    "release without proxy: id={}, proxies={}",
                    id,
                    self.proxy_map.read().unwrap().len()
                );
                None
            };

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
        debug!(
            "DGRAM release request: proxies={}",
            self.proxy_map.read().unwrap().len()
        );
    }

    fn process_dgram_rw(&self, pkt: &VsockPacket) {
        debug!("DGRAM OP_RW");
        let id = ((pkt.src_port() as u64) << 32) | (defs::TSI_PROXY_PORT as u64);

        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!("DGRAM allowing OP_RW for {}", pkt.src_port());
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.sendmsg(pkt);
            self.process_proxy_update(id, update);
        } else {
            debug!("DGRAM ignoring OP_RW for {}", pkt.src_port());
        }
    }

    pub(crate) fn send_dgram_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_dgram_pkt: src_port={} dst_port={}",
            pkt.src_port(),
            pkt.dst_port()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        match pkt.dst_port() {
            defs::TSI_PROXY_CREATE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_create(pkt)
            }
            defs::TSI_CONNECT if self.tsi_flags.tsi_enabled() => self.process_connect(pkt),
            defs::TSI_GETNAME if self.tsi_flags.tsi_enabled() => self.process_getname(pkt),
            defs::TSI_SENDTO_ADDR if self.tsi_flags.tsi_enabled() => self.process_sendto_addr(pkt),
            defs::TSI_SENDTO_DATA if self.tsi_flags.tsi_enabled() => self.process_sendto_data(pkt),
            defs::TSI_LISTEN if self.tsi_flags.tsi_enabled() => self.process_listen_request(pkt),
            defs::TSI_ACCEPT if self.tsi_flags.tsi_enabled() => self.process_accept_request(pkt),
            defs::TSI_PROXY_RELEASE if self.tsi_flags.tsi_enabled() => {
                self.process_proxy_release(pkt)
            }
            _ => {
                if pkt.op() == uapi::VSOCK_OP_RW {
                    self.process_dgram_rw(pkt);
                } else {
                    error!("unexpected dgram pkt: {}", pkt.op());
                }
            }
        }

        Ok(())
    }

    fn process_op_request(&mut self, pkt: &VsockPacket) {
        debug!("OP_REQUEST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let proxy_map = match self.proxy_map.read() {
            Ok(proxy_map) => proxy_map,
            Err(_) => {
                #[cfg(unix)]
                self.fence_control("proxy map is poisoned during OP_REQUEST");
                return;
            }
        };
        let existing = if let Some(proxy) = proxy_map.get(&id) {
            let mut proxy = match proxy.lock() {
                Ok(proxy) => proxy,
                Err(_) => {
                    #[cfg(unix)]
                    self.fence_control("proxy is poisoned during OP_REQUEST");
                    return;
                }
            };
            Some(if proxy.status() == ProxyStatus::WaitingOnHost {
                None
            } else {
                proxy.confirm_connect(pkt)
            })
        } else {
            None
        };
        drop(proxy_map);
        if let Some(update) = existing {
            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
            return;
        }
        if let Some(ipc_map) = &self.unix_ipc_port_map
            && let Some((path, listen)) = ipc_map.get(&pkt.dst_port())
        {
            let (Some(mem), Some(queue)) = (self.mem.as_ref(), self.queue.as_ref()) else {
                warn!("Unix port request before vsock activation");
                return;
            };
            if *listen {
                warn!("Attempting to connect a socket that is listening, sending rst");
                let rx = MuxerRx::Reset {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                };
                push_packet(self.cid, rx, &self.rxq, queue, mem);
                return;
            }
            let rxq = self.rxq.clone();

            let mut unix = match UnixProxy::new(
                id,
                self.cid,
                pkt.dst_port(),
                pkt.src_port(),
                mem.clone(),
                queue.clone(),
                rxq,
                path.to_path_buf(),
            ) {
                Ok(unix) => unix,
                Err(error) => {
                    warn!("failed to create Unix port proxy: {error}");
                    return;
                }
            };
            let tsi = TsiConnectReq {
                peer_port: 0,
                addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into(),
            };
            let update = unix.connect(pkt, tsi);
            unix.confirm_connect(pkt);
            match self.proxy_map.write() {
                Ok(mut proxy_map) => {
                    proxy_map.insert(id, Mutex::new(Box::new(unix)));
                }
                Err(_) => {
                    #[cfg(unix)]
                    self.fence_control("proxy map is poisoned while adding Unix port proxy");
                    return;
                }
            }
            self.process_proxy_update(id, update);
            return;
        }

        #[cfg(unix)]
        self.process_mux_request(pkt, id);
    }

    #[cfg(unix)]
    fn process_mux_request(&self, pkt: &VsockPacket, proxy_id: u64) {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

        let Some(control) = &self.control_handle else {
            return;
        };
        let pair = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        );
        let (proxy_fd, passed_fd) = match pair {
            Ok(pair) => pair,
            Err(error) => {
                warn!("failed to create mux data socketpair: {error}");
                self.push_packet(MuxerRx::Reset {
                    local_port: pkt.dst_port(),
                    peer_port: pkt.src_port(),
                });
                return;
            }
        };
        if let Err(error) = prepare_stream(&proxy_fd).and_then(|()| prepare_stream(&passed_fd)) {
            warn!("failed to configure mux data socketpair: {error}");
            self.push_packet(MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            });
            return;
        }
        let (Some(mem), Some(queue)) = (self.mem.as_ref(), self.queue.as_ref()) else {
            self.fence_control("guest mux request arrived before activation");
            return;
        };
        let mut proxy = UnixProxy::new_waiting_on_host(
            proxy_id,
            self.cid,
            pkt.dst_port(),
            pkt.src_port(),
            proxy_fd,
            mem.clone(),
            queue.clone(),
            self.rxq.clone(),
        );
        proxy.peer_buf_alloc = pkt.buf_alloc();
        proxy.peer_fwd_cnt = std::num::Wrapping(pkt.fwd_cnt());
        let mut proxy_map = match self.proxy_map.write() {
            Ok(proxy_map) => proxy_map,
            Err(_) => {
                self.fence_control("proxy map is poisoned while adding guest mux request");
                return;
            }
        };
        if let std::collections::hash_map::Entry::Vacant(entry) = proxy_map.entry(proxy_id) {
            entry.insert(Mutex::new(Box::new(proxy)));
        } else {
            debug!("ignoring duplicate pending guest request: id={proxy_id}");
            return;
        }
        drop(proxy_map);
        if control
            .enqueue_connect(pkt.dst_port(), pkt.src_port(), proxy_id, passed_fd)
            .is_err()
        {
            match self.proxy_map.write() {
                Ok(mut proxy_map) => {
                    proxy_map.remove(&proxy_id);
                }
                Err(_) => {
                    self.fence_control("proxy map is poisoned while cancelling guest mux request")
                }
            }
            self.push_packet(MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            });
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("OP_RESPONSE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().process_op_response(pkt));
        update
            .as_ref()
            .and_then(|u| u.push_accept)
            .and_then(|(_id, parent_id)| {
                self.proxy_map
                    .read()
                    .unwrap()
                    .get(&parent_id)
                    .map(|proxy| proxy.lock().unwrap().enqueue_accept())
            });

        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_shutdown(&self, pkt: &VsockPacket) {
        debug!("OP_SHUTDOWN");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().shutdown(pkt);
        }
    }

    fn process_op_credit_update(&self, pkt: &VsockPacket) {
        debug!("OP_CREDIT_UPDATE");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().update_peer_credit(pkt));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_stream_rw(&self, pkt: &VsockPacket) {
        debug!("OP_RW");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let proxy_map = match self.proxy_map.read() {
            Ok(proxy_map) => proxy_map,
            Err(_) => {
                #[cfg(unix)]
                self.fence_control("proxy map is poisoned during stream write");
                return;
            }
        };
        let update = proxy_map.get(&id).and_then(|proxy_lock| {
            debug!(
                "allowing OP_RW: src={} dst={}",
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = match proxy_lock.lock() {
                Ok(proxy) => proxy,
                Err(_) => {
                    #[cfg(unix)]
                    self.fence_control("proxy is poisoned during stream write");
                    return None;
                }
            };
            #[cfg(unix)]
            if proxy.status() == ProxyStatus::WaitingOnHost
                && let Some(control) = &self.control_handle
            {
                control.cancel_proxy(id);
            }
            Some(proxy.sendmsg(pkt))
        });
        drop(proxy_map);
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        } else {
            debug!("invalid OP_RW for {}, sending reset", pkt.src_port());
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    warn!("OP_RW without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    warn!("OP_RW without queue");
                    return;
                }
            };

            // This response goes to the connection.
            let rx = MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            };
            push_packet(self.cid, rx, &self.rxq, queue, mem);
        }
    }

    fn process_stream_rst(&self, pkt: &VsockPacket) {
        debug!("OP_RST");
        let id: u64 = ((pkt.src_port() as u64) << 32) | (pkt.dst_port() as u64);
        let proxy_map = match self.proxy_map.read() {
            Ok(proxy_map) => proxy_map,
            Err(_) => {
                #[cfg(unix)]
                self.fence_control("proxy map is poisoned during stream reset");
                return;
            }
        };
        let update = if let Some(proxy_lock) = proxy_map.get(&id) {
            debug!(
                "allowing OP_RST: id={} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = match proxy_lock.lock() {
                Ok(proxy) => proxy,
                Err(_) => {
                    #[cfg(unix)]
                    self.fence_control("proxy is poisoned during stream reset");
                    return;
                }
            };
            #[cfg(unix)]
            if proxy.status() == ProxyStatus::WaitingOnHost
                && let Some(control) = &self.control_handle
            {
                control.cancel_proxy(id);
            }
            proxy.disable_deferred_credit();
            Some(proxy.release())
        } else {
            debug!("invalid OP_RST for {}", pkt.src_port());
            None
        };
        drop(proxy_map);

        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    pub(crate) fn send_stream_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "send_pkt: src_port={} dst_port={}, op={}",
            pkt.src_port(),
            pkt.dst_port(),
            pkt.op()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!("dropping guest packet for unknown CID: {:?}", pkt.hdr());
            return Ok(());
        }

        match pkt.op() {
            uapi::VSOCK_OP_REQUEST => self.process_op_request(pkt),
            uapi::VSOCK_OP_RESPONSE => self.process_op_response(pkt),
            uapi::VSOCK_OP_SHUTDOWN => self.process_op_shutdown(pkt),
            uapi::VSOCK_OP_CREDIT_UPDATE => self.process_op_credit_update(pkt),
            uapi::VSOCK_OP_RW => self.process_stream_rw(pkt),
            uapi::VSOCK_OP_RST => self.process_stream_rst(pkt),
            _ => warn!("stream: unhandled op={}", pkt.op()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use crossbeam_channel::unbounded;
    #[cfg(unix)]
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use std::num::Wrapping;
    use std::sync::{Arc, Mutex};

    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::TsiFlags;
    use crate::virtio::vsock::defs::{self, uapi};
    use crate::virtio::vsock::muxer::{MuxerRx, VsockMuxer};
    use crate::virtio::vsock::packet::{VSOCK_PKT_HDR_SIZE, VsockPacket};
    use crate::virtio::vsock::proxy::{ProxyStatus, ProxyUpdate};
    #[cfg(unix)]
    use crate::virtio::vsock::unix_proxy::UnixProxy;
    use crate::virtio::{DescriptorChain, RuntimeGuestMemory};

    #[cfg(unix)]
    #[test]
    fn guest_send_credit_update_reaches_the_receive_virtqueue() {
        let mem = RuntimeGuestMemory::passthrough(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap(),
        );
        let queue = VirtQueue::new(GuestAddress(0), &mem, 8);
        queue.dtable[0].set(0x1000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        queue.dtable[1].set(0x1100, 4, 2, 0);
        queue.avail.ring[0].set(0);
        queue.avail.idx.set(1);
        let queue_mutex = Arc::new(Mutex::new(queue.create_queue()));
        let mut muxer = VsockMuxer::new(3, None, None, TsiFlags::empty());
        muxer.queue = Some(queue_mutex.clone());
        muxer.mem = Some(mem.clone());
        let (fd, _peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let id = (9_u64 << 32) | 7;
        let mut proxy = UnixProxy::new_mux_reverse(
            id,
            3,
            7,
            9,
            fd,
            mem.clone(),
            queue_mutex,
            muxer.rxq.clone(),
        );
        proxy.tx_cnt = Wrapping(65536);
        muxer
            .proxy_map
            .write()
            .unwrap()
            .insert(id, Mutex::new(Box::new(proxy)));

        muxer.process_proxy_update(
            id,
            ProxyUpdate {
                push_credit_req: Some(MuxerRx::CreditUpdate {
                    local_port: 7,
                    peer_port: 9,
                    fwd_cnt: 65536,
                }),
                ..Default::default()
            },
        );

        assert_eq!(muxer.queue.as_ref().unwrap().lock().unwrap().next_used.0, 1);
        let head = DescriptorChain::checked_new(&mem, GuestAddress(0), 8, 0).unwrap();
        let packet = VsockPacket::from_rx_virtq_head(&head).unwrap();
        assert_eq!(packet.op(), uapi::VSOCK_OP_CREDIT_UPDATE);
        assert_eq!(packet.src_port(), 7);
        assert_eq!(packet.dst_port(), 9);
        assert_eq!(packet.fwd_cnt(), 65536);
    }

    #[cfg(unix)]
    #[test]
    fn newer_credit_dispatch_cannot_bypass_deferred_credit_after_rx_refill() {
        let mem = RuntimeGuestMemory::passthrough(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap(),
        );
        let queue = VirtQueue::new(GuestAddress(0), &mem, 8);
        let queue_mutex = Arc::new(Mutex::new(queue.create_queue()));
        let mut muxer = VsockMuxer::new(3, None, None, TsiFlags::empty());
        muxer.queue = Some(queue_mutex.clone());
        muxer.mem = Some(mem.clone());
        for port in 0..defs::MUXER_RXQ_SIZE as u32 {
            muxer
                .rxq
                .lock()
                .unwrap()
                .push(MuxerRx::Reset {
                    local_port: port,
                    peer_port: port,
                })
                .unwrap();
        }

        let (fd, _peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let id = (9_u64 << 32) | 7;
        let mut proxy = UnixProxy::new_mux_reverse(
            id,
            3,
            7,
            9,
            fd,
            mem.clone(),
            queue_mutex.clone(),
            muxer.rxq.clone(),
        );
        proxy.status = ProxyStatus::WaitingCreditUpdate;
        proxy.tx_cnt = Wrapping(u32::MAX - 1);
        proxy.last_tx_cnt_sent = proxy.tx_cnt;
        muxer
            .proxy_map
            .write()
            .unwrap()
            .insert(id, Mutex::new(Box::new(proxy)));

        muxer.process_proxy_update(
            id,
            ProxyUpdate {
                push_credit_req: Some(MuxerRx::CreditRequest {
                    local_port: 7,
                    peer_port: 9,
                    fwd_cnt: 17,
                }),
                ..Default::default()
            },
        );
        muxer.process_proxy_update(
            id,
            ProxyUpdate {
                push_credit_req: Some(MuxerRx::CreditUpdate {
                    local_port: 7,
                    peer_port: 9,
                    fwd_cnt: u32::MAX - 1,
                }),
                ..Default::default()
            },
        );
        assert_eq!(muxer.rxq.lock().unwrap().len(), defs::MUXER_RXQ_SIZE);

        // Refill RX, then dispatch a newer producer update before the RX event
        // retries the old debt. The guest write advances tx_cnt across wrap.
        queue.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        queue.dtable[1].set(0x4100, 4, 2, 0);
        queue.dtable[2].set(0x4200, VSOCK_PKT_HDR_SIZE as u32, 3, 3);
        queue.dtable[3].set(0x4300, 4, 2, 0);
        queue.avail.ring[0].set(0);
        queue.avail.ring[1].set(2);
        queue.avail.idx.set(2);

        queue.dtable[6].set(0x6000, VSOCK_PKT_HDR_SIZE as u32, 3, 7);
        queue.dtable[7].set(0x6100, 4, 2, 0);
        mem.write_slice(b"wrap", GuestAddress(0x6100)).unwrap();
        let write_head = DescriptorChain::checked_new(&mem, GuestAddress(0), 8, 6).unwrap();
        let mut guest_write = VsockPacket::from_rx_virtq_head(&write_head).unwrap();
        guest_write
            .set_src_cid(3)
            .set_dst_cid(uapi::VSOCK_HOST_CID)
            .set_src_port(9)
            .set_dst_port(7)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_op(uapi::VSOCK_OP_RW)
            .set_len(4);
        muxer.send_stream_pkt(&guest_write).unwrap();
        assert!(!muxer.retry_deferred_credit());

        assert_eq!(queue_mutex.lock().unwrap().next_used.0, 2);
        let request_head = DescriptorChain::checked_new(&mem, GuestAddress(0), 8, 0).unwrap();
        let request = VsockPacket::from_rx_virtq_head(&request_head).unwrap();
        assert_eq!(request.op(), uapi::VSOCK_OP_CREDIT_REQUEST);
        assert_eq!(request.fwd_cnt(), 2);
        let update_head = DescriptorChain::checked_new(&mem, GuestAddress(0), 8, 2).unwrap();
        let update = VsockPacket::from_rx_virtq_head(&update_head).unwrap();
        assert_eq!(update.op(), uapi::VSOCK_OP_CREDIT_UPDATE);
        assert_eq!(update.fwd_cnt(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn guest_reset_discards_deferred_credit_before_deferred_removal_and_rx_refill() {
        let mem = RuntimeGuestMemory::passthrough(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap(),
        );
        let queue = VirtQueue::new(GuestAddress(0), &mem, 8);
        let queue_mutex = Arc::new(Mutex::new(queue.create_queue()));
        let mut muxer = VsockMuxer::new(3, None, None, TsiFlags::empty());
        muxer.queue = Some(queue_mutex.clone());
        muxer.mem = Some(mem.clone());
        for port in 0..defs::MUXER_RXQ_SIZE as u32 {
            muxer
                .rxq
                .lock()
                .unwrap()
                .push(MuxerRx::Reset {
                    local_port: port,
                    peer_port: port,
                })
                .unwrap();
        }

        let (fd, _peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        let id = (9_u64 << 32) | 7;
        let mut proxy = UnixProxy::new_mux_reverse(
            id,
            3,
            7,
            9,
            fd,
            mem.clone(),
            queue_mutex.clone(),
            muxer.rxq.clone(),
        );
        proxy.status = ProxyStatus::Connected;
        muxer
            .proxy_map
            .write()
            .unwrap()
            .insert(id, Mutex::new(Box::new(proxy)));
        let (reaper_sender, reaper_receiver) = unbounded();
        muxer.reaper_sender = Some(reaper_sender);
        muxer.process_proxy_update(
            id,
            ProxyUpdate {
                push_credit_req: Some(MuxerRx::CreditRequest {
                    local_port: 7,
                    peer_port: 9,
                    fwd_cnt: 1,
                }),
                ..Default::default()
            },
        );

        queue.dtable[4].set(0x5000, VSOCK_PKT_HDR_SIZE as u32, 3, 5);
        queue.dtable[5].set(0x5100, 4, 2, 0);
        let reset_head = DescriptorChain::checked_new(&mem, GuestAddress(0), 8, 4).unwrap();
        let mut reset = VsockPacket::from_rx_virtq_head(&reset_head).unwrap();
        reset
            .set_src_cid(3)
            .set_dst_cid(uapi::VSOCK_HOST_CID)
            .set_src_port(9)
            .set_dst_port(7)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_op(uapi::VSOCK_OP_RST)
            .set_len(0);
        muxer.send_stream_pkt(&reset).unwrap();
        assert_eq!(reaper_receiver.try_recv().unwrap(), id);
        assert!(muxer.proxy_map.read().unwrap().get(&id).is_some());

        // A racing producer after the reset must not recreate deferred debt.
        muxer.process_proxy_update(
            id,
            ProxyUpdate {
                push_credit_req: Some(MuxerRx::CreditUpdate {
                    local_port: 7,
                    peer_port: 9,
                    fwd_cnt: 2,
                }),
                ..Default::default()
            },
        );

        queue.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        queue.dtable[1].set(0x4100, 4, 2, 0);
        queue.avail.ring[0].set(0);
        queue.avail.idx.set(1);
        assert!(!muxer.retry_deferred_credit());
        assert_eq!(queue_mutex.lock().unwrap().next_used.0, 0);
    }
}
