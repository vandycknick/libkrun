use std::collections::HashMap;
#[cfg(unix)]
use std::collections::VecDeque;
use std::num::Wrapping;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::super::Queue as VirtQueue;
use super::defs;
use super::defs::uapi;
use super::muxer::{MuxerRx, push_packet};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};

#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

use super::proxy::{DeferredCredit, Proxy, ProxyError, ProxyStatus, ProxyUpdate, RecvPkt};

use crate::virtio::RuntimeGuestMemory;
use utils::epoll::EventSet;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

// Fields are marked pub(crate) so the OS submodules can access them
pub struct UnixProxy {
    pub(crate) id: u64,
    pub(crate) cid: u64,
    pub(crate) fd: OwnedFd,
    pub status: ProxyStatus,
    pub(crate) mem: RuntimeGuestMemory,
    pub(crate) queue: Arc<Mutex<VirtQueue>>,
    pub(crate) rxq: Arc<Mutex<MuxerRxQ>>,
    pub(crate) path: PathBuf,
    pub(crate) peer_port: u32,
    pub(crate) local_port: u32,
    pub(crate) control_port: u32,
    pub(crate) peer_fwd_cnt: Wrapping<u32>,
    pub(crate) peer_buf_alloc: u32,
    pub(crate) tx_cnt: Wrapping<u32>,
    pub(crate) last_tx_cnt_sent: Wrapping<u32>,
    pub(crate) push_cnt: Wrapping<u32>,
    pub(crate) rx_cnt: Wrapping<u32>,
    pub(crate) deferred_credit: DeferredCredit,
    #[cfg(unix)]
    pub(crate) mux_transport: bool,
    #[cfg(unix)]
    pub(crate) connect_response: Option<(Vec<u8>, usize)>,
    #[cfg(unix)]
    pub(crate) pending_tx: VecDeque<Vec<u8>>,
    #[cfg(unix)]
    pub(crate) pending_tx_offset: usize,
    #[cfg(unix)]
    pub(crate) pending_tx_bytes: usize,
}

impl UnixProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        cid: u64,
        local_port: u32,
        control_port: u32,
        mem: RuntimeGuestMemory,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        path: PathBuf,
    ) -> Result<Self, ProxyError> {
        let fd = sys::create_socket(id)?;
        Ok(UnixProxy {
            id,
            cid,
            fd,
            status: ProxyStatus::Idle,
            mem,
            queue,
            rxq,
            path,
            peer_port: 0,
            local_port,
            control_port,
            peer_fwd_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            push_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            deferred_credit: DeferredCredit::default(),
            #[cfg(unix)]
            mux_transport: false,
            #[cfg(unix)]
            connect_response: None,
            #[cfg(unix)]
            pending_tx: VecDeque::new(),
            #[cfg(unix)]
            pending_tx_offset: 0,
            #[cfg(unix)]
            pending_tx_bytes: 0,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_reverse(
        id: u64,
        cid: u64,
        local_port: u32,
        peer_port: u32,
        fd: OwnedFd,
        mem: RuntimeGuestMemory,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Self {
        debug!("new_reverse: id={id} local_port={local_port} peer_port={peer_port}");
        UnixProxy {
            id,
            cid,
            local_port,
            peer_port,
            control_port: 0,
            fd,
            status: ProxyStatus::ReverseInit,
            mem,
            queue,
            rxq,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            last_tx_cnt_sent: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            push_cnt: Wrapping(0),
            deferred_credit: DeferredCredit::default(),
            path: Default::default(),
            #[cfg(unix)]
            mux_transport: false,
            #[cfg(unix)]
            connect_response: None,
            #[cfg(unix)]
            pending_tx: VecDeque::new(),
            #[cfg(unix)]
            pending_tx_offset: 0,
            #[cfg(unix)]
            pending_tx_bytes: 0,
        }
    }

    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_mux_reverse(
        id: u64,
        cid: u64,
        local_port: u32,
        peer_port: u32,
        fd: OwnedFd,
        mem: RuntimeGuestMemory,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Self {
        let mut proxy = Self::new_reverse(id, cid, local_port, peer_port, fd, mem, queue, rxq);
        proxy.mux_transport = true;
        proxy
    }

    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_waiting_on_host(
        id: u64,
        cid: u64,
        local_port: u32,
        peer_port: u32,
        fd: OwnedFd,
        mem: RuntimeGuestMemory,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Self {
        let mut proxy = Self::new_mux_reverse(id, cid, local_port, peer_port, fd, mem, queue, rxq);
        proxy.status = ProxyStatus::WaitingOnHost;
        proxy
    }

    pub(crate) fn push_reset(&self) {
        debug!(
            "push_reset: id: {}, peer_port: {}, local_port: {}",
            self.id, self.peer_port, self.local_port
        );

        let rx = MuxerRx::Reset {
            local_port: self.local_port,
            peer_port: self.peer_port,
        };

        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    pub(crate) fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    pub fn recv_pkt(&mut self) -> (bool, bool) {
        let mut have_used = false;
        let mut wait_credit = false;
        let mut queue = self.queue.lock().unwrap();

        while let Some(head) = queue.pop(&self.mem) {
            let len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => match sys::recv_to_pkt(self, &mut pkt) {
                    RecvPkt::WaitForCredit => {
                        wait_credit = true;
                        0
                    }
                    RecvPkt::Read(cnt) => {
                        self.rx_cnt += Wrapping(cnt as u32);
                        self.init_data_pkt(&mut pkt);
                        pkt.set_len(cnt as u32);
                        pkt.hdr().len() + cnt
                    }
                    RecvPkt::Close => {
                        #[cfg(unix)]
                        {
                            self.status = if self.mux_transport {
                                ProxyStatus::PeerHalfClosed
                            } else {
                                ProxyStatus::Closed
                            };
                        }
                        #[cfg(windows)]
                        {
                            self.status = ProxyStatus::Closed;
                        }
                        0
                    }
                    RecvPkt::Error => 0,
                },
                Err(e) => {
                    debug!("recv_pkt: RX queue error: {e:?}");
                    0
                }
            };

            if len == 0 {
                queue.undo_pop();
                break;
            } else {
                have_used = true;
                self.push_cnt += Wrapping(len as u32);
                debug!(
                    "recv_pkt: pushing packet with {} bytes, push_cnt={}",
                    len, self.push_cnt
                );
                if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                    error!("failed to add used elements to the queue: {e:?}");
                }
            }
        }

        debug!("recv_pkt: have_used={have_used}");
        (have_used, wait_credit)
    }

    pub(crate) fn init_data_pkt(&self, pkt: &mut VsockPacket) {
        debug!(
            "init_data_pkt: id={}, local_port={}, peer_port={}",
            self.id, self.local_port, self.peer_port
        );

        pkt.set_op(uapi::VSOCK_OP_RW)
            .set_src_cid(uapi::VSOCK_HOST_CID)
            .set_dst_cid(self.cid)
            .set_src_port(self.local_port)
            .set_dst_port(self.peer_port)
            .set_type(uapi::VSOCK_TYPE_STREAM)
            .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
            .set_fwd_cnt(self.tx_cnt.0);
    }

    #[cfg(unix)]
    pub(crate) fn push_shutdown(&self) {
        push_packet(
            self.cid,
            MuxerRx::Shutdown {
                local_port: self.local_port,
                peer_port: self.peer_port,
                flags: uapi::VSOCK_FLAGS_SHUTDOWN_SEND,
            },
            &self.rxq,
            &self.queue,
            &self.mem,
        );
    }
}

impl Proxy for UnixProxy {
    fn id(&self) -> u64 {
        self.id
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn defer_credit(&mut self, credit: Box<MuxerRx>) -> Result<(), Box<MuxerRx>> {
        self.deferred_credit.push(credit, self.tx_cnt.0)
    }

    fn pop_deferred_credit(&mut self) -> Option<Box<MuxerRx>> {
        self.deferred_credit.pop(self.tx_cnt.0)
    }

    fn disable_deferred_credit(&mut self) {
        self.deferred_credit.disable();
    }

    fn deferred_credit_enabled(&self) -> bool {
        self.deferred_credit.is_enabled()
    }

    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate {
        sys::do_connect(self, pkt, req)
    }

    fn confirm_connect(&mut self, pkt: &VsockPacket) -> Option<ProxyUpdate> {
        sys::confirm_connect(self, pkt)
    }

    fn getpeername(&mut self, _pkt: &VsockPacket) {
        todo!();
    }

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        sys::sendmsg(self, pkt)
    }

    fn sendto_addr(&mut self, _req: TsiSendtoAddr) -> ProxyUpdate {
        todo!();
    }

    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        todo!();
    }

    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        todo!();
    }

    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        sys::update_peer_credit(self, pkt)
    }

    fn push_op_request(&self) {
        sys::push_op_request(self)
    }

    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        sys::process_op_response(self, pkt)
    }

    fn enqueue_accept(&mut self) {
        todo!();
    }

    fn shutdown(&mut self, pkt: &VsockPacket) {
        sys::do_shutdown(self, pkt)
    }

    fn release(&mut self) -> ProxyUpdate {
        sys::release(self)
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        sys::process_event(self, evset)
    }

    #[cfg(unix)]
    fn admit_mux(&mut self) -> Option<ProxyUpdate> {
        sys::admit_mux(self)
    }

    #[cfg(unix)]
    fn fail_mux(&mut self) -> Option<ProxyUpdate> {
        sys::fail_mux(self)
    }

    #[cfg(unix)]
    fn is_mux(&self) -> bool {
        self.mux_transport
    }
}

impl AsRawFd for UnixProxy {
    fn as_raw_fd(&self) -> RawFd {
        sys::as_raw_fd(self)
    }
}

pub struct UnixAcceptorProxy {
    id: u64,
    fd: OwnedFd,
    peer_port: u32,
}

impl UnixAcceptorProxy {
    pub fn new(id: u64, path: &PathBuf, peer_port: u32) -> Result<Self, ProxyError> {
        sys::new_acceptor_proxy(id, path, peer_port)
    }
}

impl Proxy for UnixAcceptorProxy {
    fn id(&self) -> u64 {
        self.id
    }
    fn status(&self) -> ProxyStatus {
        ProxyStatus::WaitingOnAccept
    }
    fn connect(&mut self, _: &VsockPacket, _: TsiConnectReq) -> ProxyUpdate {
        unreachable!()
    }
    fn getpeername(&mut self, _: &VsockPacket) {
        unreachable!()
    }
    fn sendmsg(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn sendto_addr(&mut self, _: TsiSendtoAddr) -> ProxyUpdate {
        unreachable!()
    }
    fn listen(
        &mut self,
        _: &VsockPacket,
        _: TsiListenReq,
        _: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        unreachable!()
    }
    fn accept(&mut self, _: TsiAcceptReq) -> ProxyUpdate {
        unreachable!()
    }
    fn update_peer_credit(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn process_op_response(&mut self, _: &VsockPacket) -> ProxyUpdate {
        unreachable!()
    }
    fn release(&mut self) -> ProxyUpdate {
        unreachable!()
    }
    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        sys::process_acceptor_event(self, evset)
    }
}

impl AsRawFd for UnixAcceptorProxy {
    fn as_raw_fd(&self) -> RawFd {
        sys::as_raw_acceptor_fd(self)
    }
}
