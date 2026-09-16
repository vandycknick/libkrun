use std::num::Wrapping;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, Shutdown, SockFlag, SockType, UnixAddr, accept, bind,
    connect, listen, recv, send, shutdown, socket,
};

#[cfg(target_os = "macos")]
use super::super::super::linux_errno::linux_errno_raw;
use super::super::muxer::{MuxerRx, push_packet};
use super::super::packet::{TsiConnectReq, VsockPacket};
use super::super::proxy::{
    NewProxyType, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt,
};
use utils::epoll::EventSet;

pub type PlatformHandle = OwnedFd;

pub(crate) fn create_socket(id: u64) -> Result<PlatformHandle, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;

    // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
    match fcntl(&fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                    warn!("error switching to non-blocking: id={id}, err={e}");
                }
            }
            None => error!("invalid fd flags id={id}"),
        },
        Err(e) => error!("couldn't obtain fd flags id={id}, err={e}"),
    };

    #[cfg(target_os = "macos")]
    {
        // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
        let option_value: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &option_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&option_value) as libc::socklen_t,
            )
        };
    }

    Ok(fd)
}

pub(crate) fn switch_to_connected(proxy: &mut super::UnixProxy) {
    proxy.status = ProxyStatus::Connected;
    if proxy.mux_transport {
        return;
    }
    match fcntl(&proxy.fd, FcntlArg::F_GETFL) {
        Ok(flags) => match OFlag::from_bits(flags) {
            Some(flags) => {
                if let Err(e) = fcntl(&proxy.fd, FcntlArg::F_SETFL(flags & !OFlag::O_NONBLOCK)) {
                    warn!("error switching to blocking: id={}, err={}", proxy.id, e);
                }
            }
            None => error!("invalid fd flags id={}", proxy.id),
        },
        Err(e) => error!("couldn't obtain fd flags id={}, err={}", proxy.id, e),
    };
}

fn push_connect_rsp(proxy: &super::UnixProxy, result: i32) {
    debug!(
        "push_connect_rsp: id: {}, control_port: {}, result: {}",
        proxy.id, proxy.control_port, result
    );

    // This response goes to the control port (DGRAM).
    let rx = MuxerRx::ConnResponse {
        local_port: 1025,
        peer_port: proxy.control_port,
        result,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn recv_to_pkt(proxy: &super::UnixProxy, pkt: &mut VsockPacket) -> RecvPkt {
    if let Some(buf) = pkt.buf_mut() {
        let peer_credit = proxy.peer_avail_credit();
        let max_len = std::cmp::min(buf.len(), peer_credit);

        debug!(
            "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
            proxy.peer_avail_credit(),
            buf.len(),
            max_len
        );

        if max_len == 0 {
            return RecvPkt::WaitForCredit;
        }

        match recv(
            proxy.fd.as_raw_fd(),
            &mut buf[..max_len],
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(cnt) => {
                debug!("recv cnt={cnt}");
                if cnt > 0 {
                    debug!("recv rx_cnt={}", proxy.rx_cnt);
                    RecvPkt::Read(cnt)
                } else {
                    RecvPkt::Close
                }
            }
            Err(e) => {
                debug!("recv_pkt: recv error: {e:?}");
                RecvPkt::Error
            }
        }
    } else {
        debug!("recv_pkt: pkt without buf");
        RecvPkt::Error
    }
}

pub(crate) fn do_connect(
    proxy: &mut super::UnixProxy,
    _pkt: &VsockPacket,
    _req: TsiConnectReq,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    let addr = UnixAddr::new(&proxy.path).unwrap();

    let result = match connect(proxy.fd.as_raw_fd(), &addr) {
        Ok(()) => {
            debug!("connect: Connected");
            switch_to_connected(proxy);
            0
        }
        Err(nix::errno::Errno::EINPROGRESS) => {
            debug!("connect: Connecting");
            proxy.status = ProxyStatus::Connecting;
            0
        }
        Err(e) => {
            debug!("Error connecting: {e}");
            #[cfg(target_os = "macos")]
            let errno = -linux_errno_raw(Errno::last_raw());
            #[cfg(target_os = "linux")]
            let errno = -Errno::last_raw();
            errno
        }
    };

    if proxy.status == ProxyStatus::Connecting {
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN | EventSet::OUT));
    } else {
        if proxy.status == ProxyStatus::Connected {
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        }
        push_connect_rsp(proxy, result);
    }
    update
}

pub(crate) fn confirm_connect(
    proxy: &mut super::UnixProxy,
    pkt: &VsockPacket,
) -> Option<ProxyUpdate> {
    debug!(
        "confirm_connect: local_port={} peer_port={}, src_port={}, dst_port={}",
        pkt.dst_port(),
        pkt.src_port(),
        proxy.local_port,
        proxy.peer_port,
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    proxy.local_port = pkt.dst_port();
    proxy.peer_port = pkt.src_port();

    // This response goes to the connection.
    let rx = MuxerRx::OpResponse {
        local_port: pkt.dst_port(),
        peer_port: pkt.src_port(),
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);

    None
}

pub(crate) fn sendmsg(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    if proxy.mux_transport {
        return sendmsg_mux(proxy, pkt);
    }
    let mut update = ProxyUpdate::default();

    let ret = if let Some(buf) = pkt.buf() {
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::empty();

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_NOSIGNAL;

        match send(proxy.fd.as_raw_fd(), buf, flags) {
            Ok(sent) => {
                if sent != buf.len() {
                    error!("couldn't set everything: buf={}, sent={}", buf.len(), sent);
                }
                proxy.tx_cnt += Wrapping(sent as u32);
                sent as i32
            }
            Err(err) => {
                #[cfg(target_os = "macos")]
                let errno = -linux_errno_raw(err as i32);

                #[cfg(target_os = "linux")]
                let errno = -(err as i32);
                errno
            }
        }
    } else {
        -libc::EINVAL
    };

    if ret > 0 && (proxy.tx_cnt - proxy.last_tx_cnt_sent).0 >= proxy.peer_buf_alloc / 2 {
        debug!(
            "sending credit update: id={}, tx_cnt={}, last_tx_cnt={}",
            proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
        );
        proxy.last_tx_cnt_sent = proxy.tx_cnt;

        update.push_credit_req = Some(MuxerRx::CreditUpdate {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            fwd_cnt: proxy.tx_cnt.0,
        });
    }

    debug!("sendmsg ret={ret}");

    update
}

fn sendmsg_mux(
    proxy: &mut crate::virtio::vsock::unix_proxy::UnixProxy,
    pkt: &VsockPacket,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();
    if proxy.status == ProxyStatus::WaitingOnHost {
        return fail_waiting_on_host(proxy);
    }
    if !matches!(
        proxy.status,
        ProxyStatus::Connected | ProxyStatus::WaitingCreditUpdate | ProxyStatus::PeerHalfClosed
    ) {
        return update;
    }
    let Some(buf) = pkt.buf() else {
        return update;
    };
    if proxy.pending_tx_bytes + buf.len() > crate::virtio::vsock::defs::CONN_TX_BUF_SIZE {
        proxy.push_reset();
        proxy.status = ProxyStatus::Closed;
        update.remove_proxy = ProxyRemoval::Immediate;
        update.signal_queue = true;
        return update;
    }
    proxy.pending_tx_bytes += buf.len();
    proxy.pending_tx.push_back(buf.to_vec());
    flush_pending_tx(proxy, &mut update);
    update
}

fn fail_waiting_on_host(proxy: &mut crate::virtio::vsock::unix_proxy::UnixProxy) -> ProxyUpdate {
    proxy.push_reset();
    let _ = shutdown(proxy.fd.as_raw_fd(), Shutdown::Both);
    proxy.status = ProxyStatus::Closed;
    ProxyUpdate {
        remove_proxy: ProxyRemoval::Immediate,
        signal_queue: true,
        ..Default::default()
    }
}

fn mux_data_events(proxy: &crate::virtio::vsock::unix_proxy::UnixProxy) -> EventSet {
    let mut events = match proxy.status {
        ProxyStatus::Connected => EventSet::IN,
        ProxyStatus::WaitingCreditUpdate | ProxyStatus::PeerHalfClosed => EventSet::empty(),
        _ => return EventSet::empty(),
    };
    if !proxy.pending_tx.is_empty() {
        events |= EventSet::OUT;
    }
    events
}

fn flush_pending_tx(
    proxy: &mut crate::virtio::vsock::unix_proxy::UnixProxy,
    update: &mut ProxyUpdate,
) {
    while let Some(front) = proxy.pending_tx.front() {
        let flags = {
            #[cfg(target_os = "linux")]
            {
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL
            }
            #[cfg(target_os = "macos")]
            {
                MsgFlags::MSG_DONTWAIT
            }
        };
        match send(
            proxy.fd.as_raw_fd(),
            &front[proxy.pending_tx_offset..],
            flags,
        ) {
            Ok(0) => {
                proxy.status = ProxyStatus::Closed;
                update.remove_proxy = ProxyRemoval::Immediate;
                break;
            }
            Ok(sent) => {
                proxy.pending_tx_offset += sent;
                proxy.pending_tx_bytes -= sent;
                proxy.tx_cnt += Wrapping(sent as u32);
                if proxy.pending_tx_offset == front.len() {
                    proxy.pending_tx.pop_front();
                    proxy.pending_tx_offset = 0;
                }
            }
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => break,
            Err(error) => {
                debug!("mux data send failed: id={}, error={error}", proxy.id);
                proxy.status = ProxyStatus::Closed;
                update.remove_proxy = ProxyRemoval::Immediate;
                break;
            }
        }
    }
    update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), mux_data_events(proxy)));
    if (proxy.tx_cnt - proxy.last_tx_cnt_sent).0 >= proxy.peer_buf_alloc / 2 {
        proxy.last_tx_cnt_sent = proxy.tx_cnt;
        update.push_credit_req = Some(MuxerRx::CreditUpdate {
            local_port: proxy.local_port,
            peer_port: proxy.peer_port,
            fwd_cnt: proxy.tx_cnt.0,
        });
    }
}

pub(crate) fn update_peer_credit(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    debug!(
        "update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
        pkt.buf_alloc(),
        proxy.rx_cnt,
        pkt.fwd_cnt()
    );
    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    if proxy.mux_transport {
        if proxy.status == ProxyStatus::WaitingCreditUpdate && proxy.peer_avail_credit() > 0 {
            proxy.status = ProxyStatus::Connected;
        }
        let polling = match proxy.status {
            ProxyStatus::Connected
            | ProxyStatus::WaitingCreditUpdate
            | ProxyStatus::PeerHalfClosed => {
                Some((proxy.id, proxy.fd.as_raw_fd(), mux_data_events(proxy)))
            }
            _ => None,
        };
        return ProxyUpdate {
            polling,
            ..Default::default()
        };
    }

    proxy.status = ProxyStatus::Connected;

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

pub(crate) fn push_op_request(proxy: &super::UnixProxy) {
    debug!(
        "push_op_request: id={}, local_port={} peer_port={}",
        proxy.id, proxy.local_port, proxy.peer_port
    );

    // This packet goes to the connection.
    let rx = MuxerRx::OpRequest {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
}

pub(crate) fn process_op_response(proxy: &mut super::UnixProxy, pkt: &VsockPacket) -> ProxyUpdate {
    debug!(
        "process_op_response: id={} src_port={} dst_port={}",
        proxy.id,
        pkt.src_port(),
        pkt.dst_port()
    );

    proxy.peer_buf_alloc = pkt.buf_alloc();
    proxy.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

    if proxy.mux_transport && proxy.status == ProxyStatus::ReverseInit {
        proxy.connect_response = Some((format!("OK {}\n", proxy.local_port).into_bytes(), 0));
        return flush_connect_response(proxy);
    }

    switch_to_connected(proxy);

    ProxyUpdate {
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    }
}

fn flush_connect_response(proxy: &mut crate::virtio::vsock::unix_proxy::UnixProxy) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();
    let Some((bytes, offset)) = &mut proxy.connect_response else {
        return update;
    };
    let flags = {
        #[cfg(target_os = "linux")]
        {
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL
        }
        #[cfg(target_os = "macos")]
        {
            MsgFlags::MSG_DONTWAIT
        }
    };
    match send(proxy.fd.as_raw_fd(), &bytes[*offset..], flags) {
        Ok(0) => {
            proxy.status = ProxyStatus::Closed;
            update.remove_proxy = ProxyRemoval::Immediate;
        }
        Ok(sent) => {
            *offset += sent;
            if *offset == bytes.len() {
                proxy.connect_response = None;
                switch_to_connected(proxy);
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
            } else {
                proxy.status = ProxyStatus::SendingConnectResponse;
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::OUT));
            }
        }
        Err(Errno::EAGAIN) | Err(Errno::EINTR) => {
            proxy.status = ProxyStatus::SendingConnectResponse;
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::OUT));
        }
        Err(error) => {
            debug!(
                "mux connect response failed: id={}, error={error}",
                proxy.id
            );
            proxy.status = ProxyStatus::Closed;
            update.remove_proxy = ProxyRemoval::Immediate;
        }
    }
    update
}

pub(crate) fn admit_mux(
    proxy: &mut crate::virtio::vsock::unix_proxy::UnixProxy,
) -> Option<ProxyUpdate> {
    if !proxy.mux_transport || proxy.status != ProxyStatus::WaitingOnHost {
        return None;
    }
    proxy.status = ProxyStatus::Connected;
    let rx = MuxerRx::OpResponse {
        local_port: proxy.local_port,
        peer_port: proxy.peer_port,
    };
    push_packet(proxy.cid, rx, &proxy.rxq, &proxy.queue, &proxy.mem);
    Some(ProxyUpdate {
        signal_queue: true,
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN)),
        ..Default::default()
    })
}

pub(crate) fn fail_mux(
    proxy: &mut crate::virtio::vsock::unix_proxy::UnixProxy,
) -> Option<ProxyUpdate> {
    if !proxy.mux_transport {
        return None;
    }
    proxy.push_reset();
    let _ = shutdown(proxy.fd.as_raw_fd(), Shutdown::Both);
    proxy.status = ProxyStatus::Closed;
    Some(ProxyUpdate {
        signal_queue: true,
        polling: Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty())),
        remove_proxy: ProxyRemoval::Immediate,
        ..Default::default()
    })
}

pub(crate) fn do_shutdown(proxy: &mut super::UnixProxy, pkt: &VsockPacket) {
    let recv_off = pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_RCV != 0;
    let send_off = pkt.flags() & super::uapi::VSOCK_FLAGS_SHUTDOWN_SEND != 0;

    let how = if recv_off && send_off {
        Shutdown::Both
    } else if recv_off {
        Shutdown::Read
    } else {
        Shutdown::Write
    };

    if let Err(e) = shutdown_socket(proxy.fd.as_raw_fd(), how) {
        warn!("error sending shutdown to socket: {e}");
    }
}

fn shutdown_socket(fd: RawFd, how: Shutdown) -> Result<(), Errno> {
    match shutdown(fd, how) {
        // The peer can disconnect before the guest's shutdown reaches the proxy.
        Ok(()) | Err(Errno::ENOTCONN) => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn release(proxy: &mut super::UnixProxy) -> ProxyUpdate {
    debug!(
        "release: id={}, tx_cnt={}, last_tx_cnt={}",
        proxy.id, proxy.tx_cnt, proxy.last_tx_cnt_sent
    );

    // A connection that never reached Connected carries no data and is not
    // registered for polling yet, so there is nothing to reserve its id for.
    // Keeping it would leave the accepted host socket open, and its peer
    // blocked, until the reaper reclaims the proxy.
    let remove_proxy = match proxy.status {
        ProxyStatus::ReverseInit
        | ProxyStatus::Connecting
        | ProxyStatus::WaitingOnHost
        | ProxyStatus::SendingConnectResponse => ProxyRemoval::Immediate,
        _ => ProxyRemoval::Deferred,
    };

    ProxyUpdate {
        remove_proxy,
        ..Default::default()
    }
}

pub(crate) fn process_event(proxy: &mut super::UnixProxy, evset: EventSet) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        debug!("process_event: HANG_UP");

        if proxy.status == ProxyStatus::Connecting {
            push_connect_rsp(proxy, -libc::ECONNREFUSED);
        } else {
            proxy.push_reset();
        }

        proxy.status = ProxyStatus::Closed;
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;

        return update;
    }

    if evset.contains(EventSet::IN) {
        debug!("process_event: IN");
        if proxy.status == ProxyStatus::Connected {
            let (signal_queue, wait_credit) = proxy.recv_pkt();
            update.signal_queue = signal_queue;

            if wait_credit && proxy.status != ProxyStatus::WaitingCreditUpdate {
                proxy.status = ProxyStatus::WaitingCreditUpdate;
                let rx = MuxerRx::CreditRequest {
                    local_port: proxy.local_port,
                    peer_port: proxy.peer_port,
                    fwd_cnt: proxy.tx_cnt.0,
                };
                update.push_credit_req = Some(rx);
            }

            if proxy.status == ProxyStatus::PeerHalfClosed {
                debug!("process_event: endpoint half-closed: id={}", proxy.id);
                proxy.push_shutdown();
                update.signal_queue = true;
                let events = if proxy.pending_tx.is_empty() {
                    EventSet::empty()
                } else {
                    EventSet::OUT
                };
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), events));
                return update;
            } else if proxy.status == ProxyStatus::Closed {
                debug!(
                    "process_event: endpoint closed, sending reset: id={}",
                    proxy.id
                );

                proxy.push_reset();
                update.signal_queue = true;
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
                return update;
            } else if proxy.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: WaitingCreditUpdate");
                update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), mux_data_events(proxy)));
            }
        } else {
            debug!("EventSet::IN while not connected: {:?}", proxy.status);
        }
    }

    if evset.contains(EventSet::OUT) {
        debug!("process_event: OUT");
        if proxy.status == ProxyStatus::SendingConnectResponse {
            return flush_connect_response(proxy);
        } else if proxy.mux_transport
            && (proxy.status == ProxyStatus::Connected
                || proxy.status == ProxyStatus::WaitingCreditUpdate
                || proxy.status == ProxyStatus::PeerHalfClosed)
            && !proxy.pending_tx.is_empty()
        {
            flush_pending_tx(proxy, &mut update);
        } else if proxy.status == ProxyStatus::Connecting {
            switch_to_connected(proxy);
            push_connect_rsp(proxy, 0);
            update.signal_queue = true;
            update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::IN));
        } else {
            error!("EventSet::OUT while not connecting");
        }
    }

    update
}

pub(crate) fn as_raw_fd(proxy: &super::UnixProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}

pub(crate) fn new_acceptor_proxy(
    id: u64,
    path: &PathBuf,
    peer_port: u32,
) -> Result<super::UnixAcceptorProxy, ProxyError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    bind(
        fd.as_raw_fd(),
        &UnixAddr::new(path)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    listen(
        &fd,
        Backlog::new(5)
            .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?,
    )
    .map_err(|e| ProxyError::CreatingSocket(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(super::UnixAcceptorProxy { id, fd, peer_port })
}

pub(crate) fn process_acceptor_event(
    proxy: &mut super::UnixAcceptorProxy,
    evset: EventSet,
) -> ProxyUpdate {
    let mut update = ProxyUpdate::default();

    if evset.contains(EventSet::HANG_UP) {
        debug!("process_event: HANG_UP");
        update.polling = Some((proxy.id, proxy.fd.as_raw_fd(), EventSet::empty()));
        update.signal_queue = true;
        update.remove_proxy = ProxyRemoval::Deferred;
        return update;
    }
    if evset.contains(EventSet::IN) {
        match accept(proxy.fd.as_raw_fd()) {
            Ok(accept_fd) => {
                // Safe because we've just obtained the FD from the `accept` call above.
                let new_fd = unsafe { OwnedFd::from_raw_fd(accept_fd) };
                update.new_proxy = Some((
                    proxy.peer_port,
                    new_fd,
                    AddressFamily::Unix,
                    NewProxyType::Unix,
                ));
            }
            Err(e) => warn!("error accepting connection: id={}, err={}", proxy.id, e),
        };
        update.signal_queue = true;
    }
    update
}

pub(crate) fn as_raw_acceptor_fd(proxy: &super::UnixAcceptorProxy) -> RawFd {
    proxy.fd.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;
    use std::sync::{Arc, Mutex};

    use nix::sys::socket::{
        AddressFamily, MsgFlags, Shutdown, SockFlag, SockType, recv, send, shutdown, socketpair,
    };
    use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::control_proxy::prepare_stream;
    use crate::virtio::vsock::defs::uapi;
    use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
    use crate::virtio::vsock::packet::{VSOCK_PKT_HDR_SIZE, VsockPacket};
    use crate::virtio::vsock::unix_proxy::unix::*;
    use crate::virtio::{Descriptor, DescriptorChain, Queue, RuntimeGuestMemory};

    #[test]
    fn socket_shutdown_is_idempotent() {
        let (fd, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        shutdown_socket(fd.as_raw_fd(), Shutdown::Write).unwrap();
        let mut buffer = [0; 1];
        assert_eq!(
            recv(peer.as_raw_fd(), &mut buffer, MsgFlags::empty()).unwrap(),
            0
        );
        send(peer.as_raw_fd(), b"x", MsgFlags::empty()).unwrap();
        assert_eq!(
            recv(fd.as_raw_fd(), &mut buffer, MsgFlags::empty()).unwrap(),
            1
        );
        assert_eq!(buffer, *b"x");
        shutdown_socket(fd.as_raw_fd(), Shutdown::Both).unwrap();
        shutdown_socket(fd.as_raw_fd(), Shutdown::Both).unwrap();
        drop(peer);
        shutdown_socket(fd.as_raw_fd(), Shutdown::Both).unwrap();
    }

    #[test]
    fn socket_shutdown_accepts_disconnected_socket() {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        assert_eq!(
            shutdown(fd.as_raw_fd(), Shutdown::Both),
            Err(Errno::ENOTCONN)
        );
        shutdown_socket(fd.as_raw_fd(), Shutdown::Both).unwrap();
    }

    #[test]
    fn socket_shutdown_preserves_unexpected_errors() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            shutdown_socket(file.as_raw_fd(), Shutdown::Both),
            Err(Errno::ENOTSOCK)
        );
    }

    const QUEUE_SIZE: u16 = 32;
    const CREDIT_PACKET_DESC: GuestAddress = GuestAddress(0x3000);
    const CREDIT_PACKET_HDR: GuestAddress = GuestAddress(0x3100);

    fn credit_packet(mem: &RuntimeGuestMemory, buf_alloc: u32, fwd_cnt: u32) -> VsockPacket {
        mem.write_obj(
            Descriptor {
                addr: CREDIT_PACKET_HDR.raw_value(),
                len: VSOCK_PKT_HDR_SIZE as u32,
                flags: 0,
                next: 0,
            },
            CREDIT_PACKET_DESC,
        )
        .unwrap();
        mem.write_slice(&[0; VSOCK_PKT_HDR_SIZE], CREDIT_PACKET_HDR)
            .unwrap();
        let chain = DescriptorChain::checked_new(mem, CREDIT_PACKET_DESC, 1, 0).unwrap();
        let mut packet = VsockPacket::from_tx_virtq_head(&chain).unwrap();
        packet.set_buf_alloc(buf_alloc).set_fwd_cnt(fwd_cnt);
        packet
    }

    fn socketpair_proxy_with_rx_buffers(
        buffer_count: usize,
        buffer_size: usize,
    ) -> (
        crate::virtio::vsock::unix_proxy::UnixProxy,
        OwnedFd,
        RuntimeGuestMemory,
        Vec<GuestAddress>,
    ) {
        assert!(buffer_count * 2 <= QUEUE_SIZE as usize);
        let (fd, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        prepare_stream(&fd).unwrap();
        prepare_stream(&peer).unwrap();
        let mem = RuntimeGuestMemory::passthrough(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap(),
        );
        let virt_queue = VirtQueue::new(GuestAddress(0), &mem, QUEUE_SIZE);
        let mut data_addresses = Vec::with_capacity(buffer_count);
        for index in 0..buffer_count {
            let head = index * 2;
            let header_address = 0x4000 + (index as u64 * 0x100);
            let data_address = GuestAddress(header_address + VSOCK_PKT_HDR_SIZE as u64);
            virt_queue.dtable[head].set(
                header_address,
                VSOCK_PKT_HDR_SIZE as u32,
                0x1 | 0x2,
                (head + 1) as u16,
            );
            virt_queue.dtable[head + 1].set(data_address.raw_value(), buffer_size as u32, 0x2, 0);
            virt_queue.avail.ring[index].set(head as u16);
            data_addresses.push(data_address);
        }
        virt_queue.avail.idx.set(buffer_count as u16);
        let queue = Arc::new(Mutex::new(virt_queue.create_queue()));
        let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
        let mut proxy = crate::virtio::vsock::unix_proxy::UnixProxy::new_waiting_on_host(
            (7u64 << 32) | 9,
            3,
            9,
            7,
            fd,
            mem.clone(),
            queue,
            rxq,
        );
        proxy.status = ProxyStatus::Connected;
        (proxy, peer, mem, data_addresses)
    }

    fn send_all(fd: RawFd, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let sent = send(fd, bytes, MsgFlags::empty()).unwrap();
            assert!(sent > 0);
            bytes = &bytes[sent..];
        }
    }

    fn event_set(update: &ProxyUpdate) -> Option<EventSet> {
        update.polling.map(|(_, _, events)| events)
    }

    fn waiting_proxy() -> (
        crate::virtio::vsock::unix_proxy::UnixProxy,
        OwnedFd,
        Arc<Mutex<MuxerRxQ>>,
    ) {
        let (fd, peer) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        prepare_stream(&fd).unwrap();
        prepare_stream(&peer).unwrap();
        let memory = RuntimeGuestMemory::passthrough(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap(),
        );
        let rxq = Arc::new(Mutex::new(MuxerRxQ::new()));
        let proxy = crate::virtio::vsock::unix_proxy::UnixProxy::new_waiting_on_host(
            (7u64 << 32) | 9,
            3,
            9,
            7,
            fd,
            memory,
            Arc::new(Mutex::new(Queue::new(256))),
            rxq.clone(),
        );
        (proxy, peer, rxq)
    }

    #[test]
    fn waiting_proxy_publishes_nothing_until_admitted() {
        let (mut proxy, peer, rxq) = waiting_proxy();
        let mut byte = [0u8; 1];
        assert_eq!(
            recv(peer.as_raw_fd(), &mut byte, MsgFlags::MSG_DONTWAIT),
            Err(Errno::EAGAIN)
        );
        nix::unistd::write(&peer, b"payload").unwrap();
        assert!(rxq.lock().unwrap().is_empty());

        let update = admit_mux(&mut proxy).unwrap();
        assert_eq!(proxy.status, ProxyStatus::Connected);
        assert!(update.signal_queue);
        assert!(matches!(
            rxq.lock().unwrap().pop(),
            Some(MuxerRx::OpResponse { .. })
        ));
        let mut payload = [0u8; 7];
        assert_eq!(
            recv(proxy.fd.as_raw_fd(), &mut payload, MsgFlags::MSG_DONTWAIT).unwrap(),
            payload.len()
        );
        assert_eq!(&payload, b"payload");
    }

    #[test]
    fn rejection_violation_and_established_control_failure_close_real_endpoint() {
        for established in [false, true] {
            let (mut proxy, peer, rxq) = waiting_proxy();
            if established {
                proxy.status = ProxyStatus::Connected;
            }
            let update = if established {
                fail_mux(&mut proxy).unwrap()
            } else {
                fail_waiting_on_host(&mut proxy)
            };
            assert!(matches!(update.remove_proxy, ProxyRemoval::Immediate));
            assert!(matches!(
                rxq.lock().unwrap().pop(),
                Some(MuxerRx::Reset { .. })
            ));
            let mut byte = [0u8; 1];
            assert_eq!(
                recv(peer.as_raw_fd(), &mut byte, MsgFlags::empty()).unwrap(),
                0
            );
        }
    }

    #[test]
    fn mux_bulk_receive_restarts_after_each_credit_window_and_delivers_eof() {
        const BUFFER_SIZE: usize = 32;
        const CREDIT_WINDOW: u32 = 64;
        const PAYLOAD_SIZE: usize = 256;

        let packet_count = PAYLOAD_SIZE / BUFFER_SIZE;
        let (mut proxy, peer, mem, data_addresses) =
            socketpair_proxy_with_rx_buffers(packet_count + 1, BUFFER_SIZE);
        proxy.peer_buf_alloc = CREDIT_WINDOW;
        let payload: Vec<u8> = (0..PAYLOAD_SIZE)
            .map(|index| index.wrapping_mul(31) as u8)
            .collect();
        send_all(peer.as_raw_fd(), &payload);
        shutdown(peer.as_raw_fd(), Shutdown::Write).unwrap();

        for window in 1..=4 {
            let update = process_event(&mut proxy, EventSet::IN);
            assert!(update.signal_queue);
            assert_eq!(proxy.status, ProxyStatus::WaitingCreditUpdate);
            assert!(matches!(
                update.push_credit_req,
                Some(MuxerRx::CreditRequest { .. })
            ));
            assert_eq!(event_set(&update), Some(EventSet::empty()));

            let packet = credit_packet(&mem, CREDIT_WINDOW, window * CREDIT_WINDOW);
            let update = update_peer_credit(&mut proxy, &packet);
            assert_eq!(proxy.status, ProxyStatus::Connected);
            assert_eq!(event_set(&update), Some(EventSet::IN));
        }

        let update = process_event(&mut proxy, EventSet::IN);
        assert!(update.signal_queue);
        assert_eq!(proxy.status, ProxyStatus::PeerHalfClosed);
        assert_eq!(
            event_set(&update_peer_credit(
                &mut proxy,
                &credit_packet(&mem, CREDIT_WINDOW, PAYLOAD_SIZE as u32),
            )),
            Some(EventSet::empty())
        );
        assert_eq!(proxy.status, ProxyStatus::PeerHalfClosed);
        let shutdown_chain = DescriptorChain::checked_new(
            &mem,
            GuestAddress(0),
            QUEUE_SIZE,
            (packet_count * 2) as u16,
        )
        .unwrap();
        let shutdown_packet = VsockPacket::from_rx_virtq_head(&shutdown_chain).unwrap();
        assert_eq!(shutdown_packet.op(), uapi::VSOCK_OP_SHUTDOWN);
        assert_eq!(shutdown_packet.flags(), uapi::VSOCK_FLAGS_SHUTDOWN_SEND);

        let mut received = Vec::with_capacity(PAYLOAD_SIZE);
        for address in data_addresses.iter().take(packet_count) {
            let mut buffer = [0; BUFFER_SIZE];
            mem.read_slice(&mut buffer, *address).unwrap();
            received.extend_from_slice(&buffer);
        }
        let checksum = |bytes: &[u8]| bytes.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        assert_eq!(checksum(&received), checksum(&payload));
        assert_eq!(received, payload);
        assert_eq!(proxy.rx_cnt, Wrapping(PAYLOAD_SIZE as u32));
        assert_eq!(
            proxy.queue.lock().unwrap().next_used.0,
            packet_count as u16 + 1
        );
    }

    #[test]
    fn mux_credit_updates_preserve_state_and_write_interest() {
        let (mut proxy, peer, mem, _) = socketpair_proxy_with_rx_buffers(1, 16);
        proxy.pending_tx.push_back(vec![1]);
        proxy.pending_tx_bytes = 1;
        send_all(peer.as_raw_fd(), b"x");

        let update = process_event(&mut proxy, EventSet::IN);
        assert_eq!(proxy.status, ProxyStatus::WaitingCreditUpdate);
        assert!(matches!(
            update.push_credit_req,
            Some(MuxerRx::CreditRequest { .. })
        ));
        assert_eq!(event_set(&update), Some(EventSet::OUT));

        let update = update_peer_credit(&mut proxy, &credit_packet(&mem, 0, 0));
        assert_eq!(proxy.status, ProxyStatus::WaitingCreditUpdate);
        assert_eq!(event_set(&update), Some(EventSet::OUT));

        let update = update_peer_credit(&mut proxy, &credit_packet(&mem, 1, 0));
        assert_eq!(proxy.status, ProxyStatus::Connected);
        assert_eq!(event_set(&update), Some(EventSet::IN | EventSet::OUT));

        for status in [
            ProxyStatus::WaitingOnHost,
            ProxyStatus::ReverseInit,
            ProxyStatus::Closed,
            ProxyStatus::PeerHalfClosed,
        ] {
            proxy.status = status;
            let update = update_peer_credit(&mut proxy, &credit_packet(&mem, 64, 0));
            assert_eq!(proxy.status, status);
            if status == ProxyStatus::PeerHalfClosed {
                assert_eq!(event_set(&update), Some(EventSet::OUT));
            } else {
                assert_eq!(event_set(&update), None);
            }
        }
    }

    #[test]
    fn mux_credit_blocked_reads_do_not_drop_guest_writes() {
        let (mut proxy, peer, mem, _) = socketpair_proxy_with_rx_buffers(1, 16);
        proxy.status = ProxyStatus::WaitingCreditUpdate;
        let payload = b"independent direction";
        mem.write_obj(
            Descriptor {
                addr: 0x3300,
                len: VSOCK_PKT_HDR_SIZE as u32,
                flags: 1,
                next: 1,
            },
            GuestAddress(0x3200),
        )
        .unwrap();
        mem.write_obj(
            Descriptor {
                addr: 0x3400,
                len: payload.len() as u32,
                flags: 0,
                next: 0,
            },
            GuestAddress(0x3210),
        )
        .unwrap();
        mem.write_slice(payload, GuestAddress(0x3400)).unwrap();
        mem.write_obj((payload.len() as u32).to_le(), GuestAddress(0x3318))
            .unwrap();
        let head = DescriptorChain::checked_new(&mem, GuestAddress(0x3200), 2, 0).unwrap();
        let packet = VsockPacket::from_tx_virtq_head(&head).unwrap();

        let update = sendmsg_mux(&mut proxy, &packet);
        let mut received = [0; 64];
        let count = recv(peer.as_raw_fd(), &mut received, MsgFlags::MSG_DONTWAIT).unwrap();
        assert_eq!(&received[..count], payload);
        assert_eq!(proxy.status, ProxyStatus::WaitingCreditUpdate);
        assert_eq!(event_set(&update), Some(EventSet::empty()));
    }

    #[test]
    fn mux_credit_resume_uses_wrapping_counters() {
        let (mut proxy, _peer, mem, _) = socketpair_proxy_with_rx_buffers(1, 16);
        proxy.status = ProxyStatus::WaitingCreditUpdate;
        proxy.rx_cnt = Wrapping(u32::MAX - 15);
        proxy.peer_buf_alloc = 16;
        proxy.peer_fwd_cnt = Wrapping(u32::MAX - 31);
        assert_eq!(proxy.peer_avail_credit(), 0);

        let update = update_peer_credit(&mut proxy, &credit_packet(&mem, 16, u32::MAX - 15));
        assert_eq!(proxy.peer_avail_credit(), 16);
        assert_eq!(proxy.status, ProxyStatus::Connected);
        assert_eq!(event_set(&update), Some(EventSet::IN));
    }
}
