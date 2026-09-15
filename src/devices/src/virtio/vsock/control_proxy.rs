use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{IoSlice, IoSliceMut};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::socket::{
    ControlMessage, MsgFlags, SockType, getsockname, getsockopt, sendmsg, sockopt,
};
use nix::sys::stat::fstat;
use utils::eventfd::{EFD_NONBLOCK, EventFd};

const MAX_LINE_BYTES: usize = 64;
const MAX_FRAMES: usize = 2048;
const MAX_QUEUED_BYTES: usize = 128 * 1024;
const MAX_QUEUED_FDS: usize = 1024;
const MAX_PENDING: usize = 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
// A readiness turn consumes at most 32 complete frames or 2048 bytes. Level
// readiness schedules the remaining stream data on the next muxer turn.
const RECEIVE_FRAME_BUDGET: usize = 32;
const RECEIVE_BYTE_BUDGET: usize = 2048;
// macOS installs rights that do not fit in the ancillary buffer without
// exposing their descriptor numbers. Size this above the entire session quota
// so every protocol-reachable descriptor can always be closed explicitly.
const RECEIVED_FD_CAPACITY: usize = MAX_QUEUED_FDS + 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UnixSocketIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

pub fn unix_socket_identity(fd: BorrowedFd<'_>) -> std::io::Result<UnixSocketIdentity> {
    let stat = fstat(fd)?;
    Ok(UnixSocketIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[derive(Debug)]
pub(crate) enum Incoming {
    Connect { port: u32, fd: OwnedFd },
    Admit(u32),
    Reject(u32),
}

struct OutboundFrame {
    bytes: Vec<u8>,
    offset: usize,
    fd: Option<OwnedFd>,
    request_id: u32,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct PendingRequest {
    proxy_id: u64,
    deadline: Instant,
}

struct Shared {
    active: bool,
    next_request_id: u32,
    frames: VecDeque<OutboundFrame>,
    queued_bytes: usize,
    queued_fds: usize,
    pending: HashMap<u32, PendingRequest>,
}

pub(crate) struct ControlHandle {
    shared: Mutex<Shared>,
    wake: EventFd,
    fenced: AtomicBool,
}

impl ControlHandle {
    fn new() -> std::io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            shared: Mutex::new(Shared {
                active: true,
                next_request_id: 1,
                frames: VecDeque::new(),
                queued_bytes: 0,
                queued_fds: 0,
                pending: HashMap::new(),
            }),
            wake: EventFd::new(EFD_NONBLOCK)?,
            fenced: AtomicBool::new(false),
        }))
    }

    fn lock_shared(&self) -> Result<MutexGuard<'_, Shared>, String> {
        match self.shared.lock() {
            Ok(shared) => {
                if self.fenced.load(Ordering::Acquire) {
                    Err("control session is fenced".into())
                } else {
                    Ok(shared)
                }
            }
            Err(poisoned) => {
                self.fenced.store(true, Ordering::Release);
                let mut shared = poisoned.into_inner();
                shared.active = false;
                shared.frames.clear();
                shared.pending.clear();
                shared.queued_bytes = 0;
                shared.queued_fds = 0;
                drop(shared);
                let _ = self.wake.write(1);
                Err("control queue mutex is poisoned".into())
            }
        }
    }

    pub(crate) fn fence(&self) {
        self.fenced.store(true, Ordering::Release);
        match self.shared.lock() {
            Ok(mut shared) => {
                shared.active = false;
                shared.frames.clear();
                shared.pending.clear();
                shared.queued_bytes = 0;
                shared.queued_fds = 0;
            }
            Err(poisoned) => {
                let mut shared = poisoned.into_inner();
                shared.active = false;
                shared.frames.clear();
                shared.pending.clear();
                shared.queued_bytes = 0;
                shared.queued_fds = 0;
            }
        }
        let _ = self.wake.write(1);
    }

    pub(crate) fn wake_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    pub(crate) fn drain_wake(&self) {
        while self.wake.read().is_ok() {}
    }

    pub(crate) fn enqueue_connect(
        &self,
        host_port: u32,
        guest_port: u32,
        proxy_id: u64,
        fd: OwnedFd,
    ) -> Result<u32, OwnedFd> {
        let mut shared = match self.lock_shared() {
            Ok(shared) => shared,
            Err(_) => return Err(fd),
        };
        let request_id = shared.next_request_id;
        let line = format!("CONNECT {request_id} {host_port} {guest_port}\n").into_bytes();
        if request_id == 0 {
            shared.active = false;
            drop(shared);
            let _ = self.wake.write(1);
            return Err(fd);
        }
        if !shared.active
            || shared
                .pending
                .values()
                .any(|pending| pending.proxy_id == proxy_id)
            || shared.pending.len() >= MAX_PENDING
            || shared.frames.len() >= MAX_FRAMES
            || shared.queued_bytes + line.len() > MAX_QUEUED_BYTES
            || shared.queued_fds >= MAX_QUEUED_FDS
        {
            return Err(fd);
        }
        shared.next_request_id = request_id.checked_add(1).unwrap_or(0);
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        shared.queued_bytes += line.len();
        shared.queued_fds += 1;
        shared.frames.push_back(OutboundFrame {
            bytes: line,
            offset: 0,
            fd: Some(fd),
            request_id,
            deadline,
        });
        shared
            .pending
            .insert(request_id, PendingRequest { proxy_id, deadline });
        drop(shared);
        let _ = self.wake.write(1);
        Ok(request_id)
    }

    pub(crate) fn take_pending(&self, request_id: u32) -> Option<u64> {
        self.lock_shared()
            .ok()?
            .pending
            .remove(&request_id)
            .map(|pending| pending.proxy_id)
    }

    pub(crate) fn cancel_proxy(&self, proxy_id: u64) {
        let Ok(mut shared) = self.lock_shared() else {
            return;
        };
        let Some(request_id) = shared
            .pending
            .iter()
            .find_map(|(id, pending)| (pending.proxy_id == proxy_id).then_some(*id))
        else {
            return;
        };
        shared.pending.remove(&request_id);
        if let Some(position) = shared
            .frames
            .iter()
            .position(|frame| frame.request_id == request_id)
        {
            if shared.frames[position].offset != 0 {
                shared.active = false;
                drop(shared);
                let _ = self.wake.write(1);
                return;
            }
            if let Some(frame) = shared.frames.remove(position) {
                shared.queued_bytes -= frame.bytes.len();
                shared.queued_fds -= usize::from(frame.fd.is_some());
            }
        }
    }

    pub(crate) fn next_timeout_ms(&self) -> i32 {
        let Ok(shared) = self.lock_shared() else {
            return 0;
        };
        let now = Instant::now();
        shared
            .pending
            .values()
            .map(|pending| pending.deadline.saturating_duration_since(now))
            .chain(
                shared
                    .frames
                    .front()
                    .map(|frame| frame.deadline.saturating_duration_since(now)),
            )
            .min()
            .map_or(-1, |duration| {
                duration.as_millis().min(i32::MAX as u128) as i32
            })
    }

    pub(crate) fn expire(&self) -> (Vec<u64>, bool) {
        let now = Instant::now();
        let Ok(mut shared) = self.lock_shared() else {
            return (Vec::new(), true);
        };
        let expired_ids: Vec<u32> = shared
            .pending
            .iter()
            .filter_map(|(id, pending)| (pending.deadline <= now).then_some(*id))
            .collect();
        let mut failed = false;
        let mut proxies = Vec::with_capacity(expired_ids.len());
        for request_id in expired_ids {
            if let Some(position) = shared
                .frames
                .iter()
                .position(|frame| frame.request_id == request_id)
            {
                if shared.frames[position].offset != 0 {
                    failed = true;
                    break;
                }
                if let Some(frame) = shared.frames.remove(position) {
                    shared.queued_bytes -= frame.bytes.len();
                    shared.queued_fds -= usize::from(frame.fd.is_some());
                }
            }
            if let Some(pending) = shared.pending.remove(&request_id) {
                proxies.push(pending.proxy_id);
            }
        }
        (proxies, failed)
    }

    pub(crate) fn wants_write(&self) -> bool {
        self.lock_shared()
            .map(|shared| !shared.frames.is_empty())
            .unwrap_or(false)
    }

    pub(crate) fn is_active(&self) -> bool {
        !self.fenced.load(Ordering::Acquire)
            && self
                .lock_shared()
                .map(|shared| shared.active)
                .unwrap_or(false)
    }

    fn fail(&self) -> Vec<u64> {
        self.fenced.store(true, Ordering::Release);
        let mut shared = match self.shared.lock() {
            Ok(shared) => shared,
            Err(poisoned) => poisoned.into_inner(),
        };
        shared.active = false;
        shared.frames.clear();
        shared.queued_bytes = 0;
        shared.queued_fds = 0;
        shared
            .pending
            .drain()
            .map(|(_, pending)| pending.proxy_id)
            .collect()
    }
}

pub(crate) struct ControlProxy {
    fd: Option<OwnedFd>,
    handle: Arc<ControlHandle>,
    line: Vec<u8>,
    line_fd: Option<OwnedFd>,
    protected_identities: HashSet<UnixSocketIdentity>,
    line_deadline: Option<Instant>,
    ancillary: Vec<u8>,
}

impl ControlProxy {
    pub(crate) fn new(
        fd: OwnedFd,
        protected_identities: impl IntoIterator<Item = UnixSocketIdentity>,
    ) -> std::io::Result<(Self, Arc<ControlHandle>)> {
        validate_stream(&fd)?;
        set_fd_flags(&fd)?;
        let mut protected_identities: HashSet<_> = protected_identities.into_iter().collect();
        protected_identities.insert(unix_socket_identity(fd.as_fd())?);
        let handle = ControlHandle::new()?;
        Ok((
            Self {
                fd: Some(fd),
                handle: handle.clone(),
                line: Vec::new(),
                line_fd: None,
                protected_identities,
                line_deadline: None,
                ancillary: vec![
                    0u8;
                    unsafe {
                        libc::CMSG_SPACE(
                            (RECEIVED_FD_CAPACITY * mem::size_of::<RawFd>()) as libc::c_uint,
                        ) as usize
                    }
                ],
            },
            handle,
        ))
    }

    pub(crate) fn as_raw_fd(&self) -> Option<RawFd> {
        self.fd.as_ref().map(AsRawFd::as_raw_fd)
    }

    pub(crate) fn add_protected_identity(&mut self, identity: UnixSocketIdentity) {
        self.protected_identities.insert(identity);
    }

    pub(crate) fn read_messages(&mut self) -> Result<Vec<Incoming>, String> {
        self.read_messages_at(Instant::now())
    }

    fn read_messages_at(&mut self, now: Instant) -> Result<Vec<Incoming>, String> {
        let mut messages = Vec::new();
        let mut bytes_read = 0;
        while bytes_read < RECEIVE_BYTE_BUDGET && messages.len() < RECEIVE_FRAME_BUDGET {
            let Some((byte, mut fds)) = self.read_byte()? else {
                break;
            };
            bytes_read += 1;
            let first = self.line.is_empty();
            if first {
                self.line_deadline = Some(now + REQUEST_TIMEOUT);
            }
            if (!first && !fds.is_empty()) || fds.len() > 1 {
                return Err("ancillary fd is not exactly one on the first byte".into());
            }
            if first && fds.len() == 1 {
                self.line_fd = fds.pop();
            }
            if !byte.is_ascii() || self.line.len() == MAX_LINE_BYTES {
                return Err("oversized or non-ASCII control frame".into());
            }
            self.line.push(byte);
            if byte == b'\n' {
                let line = mem::take(&mut self.line);
                let fd = self.line_fd.take();
                self.line_deadline = None;
                messages.push(parse_line(&line, fd)?);
            }
        }
        Ok(messages)
    }

    pub(crate) fn partial_timeout_ms(&self, now: Instant) -> Option<i32> {
        self.line_deadline.map(|deadline| {
            deadline
                .saturating_duration_since(now)
                .as_millis()
                .min(i32::MAX as u128) as i32
        })
    }

    pub(crate) fn partial_expired(&self, now: Instant) -> bool {
        self.line_deadline.is_some_and(|deadline| deadline <= now)
    }

    fn read_byte(&mut self) -> Result<Option<(u8, Vec<OwnedFd>)>, String> {
        let fd = self.fd.as_ref().ok_or("control channel is closed")?;
        let mut byte = 0u8;
        let mut iov = [IoSliceMut::new(std::slice::from_mut(&mut byte))];
        let mut header: libc::msghdr = unsafe { mem::zeroed() };
        header.msg_iov = iov.as_mut_ptr().cast();
        header.msg_iovlen = iov.len() as _;
        header.msg_control = self.ancillary.as_mut_ptr().cast();
        header.msg_controllen = self.ancillary.len() as _;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
        #[cfg(target_os = "macos")]
        let flags = libc::MSG_DONTWAIT;
        // nix refuses to expose cmsgs after MSG_CTRUNC, which would leak every
        // descriptor the kernel installed. Raw recvmsg is required for cleanup.
        let result = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut header, flags) };
        if result < 0 {
            let error = Errno::last();
            return match error {
                Errno::EAGAIN | Errno::EINTR => Ok(None),
                _ => Err(format!("recvmsg failed: {error}")),
            };
        }
        if result == 0 {
            return Err("control channel reached EOF".into());
        }

        let mut received = Vec::new();
        let mut unknown = false;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&header) };
        while !cmsg.is_null() {
            let current = unsafe { &*cmsg };
            if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
                let header_len = unsafe { libc::CMSG_LEN(0) as usize };
                let message_len = current.cmsg_len as usize;
                if message_len < header_len {
                    unknown = true;
                    break;
                }
                let count = (message_len - header_len) / mem::size_of::<RawFd>();
                let data = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>() };
                for index in 0..count {
                    let raw = unsafe { *data.add(index) };
                    received.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            } else {
                unknown = true;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&header, cmsg) };
        }
        validate_received_fds(
            header.msg_flags,
            unknown,
            &received,
            &self.protected_identities,
        )?;
        Ok(Some((byte, received)))
    }

    pub(crate) fn flush(&mut self) -> Result<bool, String> {
        self.flush_limited(usize::MAX)
    }

    fn flush_limited(&mut self, mut byte_budget: usize) -> Result<bool, String> {
        let fd = self.fd.as_ref().ok_or("control channel is closed")?;
        loop {
            let mut shared = self.handle.lock_shared()?;
            let Some(frame) = shared.frames.front_mut() else {
                return Ok(true);
            };
            if byte_budget == 0 {
                return Ok(false);
            }
            let send_len = (frame.bytes.len() - frame.offset).min(byte_budget);
            let iov = [IoSlice::new(
                &frame.bytes[frame.offset..frame.offset + send_len],
            )];
            let raw_fds = frame.fd.as_ref().map(|fd| [fd.as_raw_fd()]);
            let cmsgs = raw_fds
                .as_ref()
                .map_or_else(Vec::new, |fds| vec![ControlMessage::ScmRights(fds)]);
            #[cfg(target_os = "linux")]
            let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
            #[cfg(target_os = "macos")]
            let flags = MsgFlags::MSG_DONTWAIT;
            match sendmsg::<()>(fd.as_raw_fd(), &iov, &cmsgs, flags, None) {
                Ok(0) => return Err("sendmsg made no progress".into()),
                Ok(written) => {
                    byte_budget -= written;
                    let transferred_fd = frame.fd.take().is_some();
                    let complete = {
                        frame.offset += written;
                        frame.offset == frame.bytes.len()
                    };
                    if transferred_fd {
                        shared.queued_fds -= 1;
                    }
                    if complete {
                        let Some(frame) = shared.frames.pop_front() else {
                            drop(shared);
                            self.handle.fence();
                            return Err("control queue lost its active frame".into());
                        };
                        shared.queued_bytes -= frame.bytes.len();
                    }
                }
                Err(Errno::EAGAIN) | Err(Errno::EINTR) => return Ok(false),
                Err(error) => return Err(format!("sendmsg failed: {error}")),
            }
        }
    }

    pub(crate) fn close(&mut self) -> Vec<u64> {
        self.fd.take();
        self.line.clear();
        self.line_fd.take();
        self.line_deadline = None;
        self.handle.fail()
    }
}

fn validate_received_fds(
    message_flags: libc::c_int,
    unknown: bool,
    received: &[OwnedFd],
    protected_identities: &HashSet<UnixSocketIdentity>,
) -> Result<(), String> {
    if message_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 || unknown {
        return Err("truncated or unknown ancillary data".into());
    }
    for received_fd in received {
        set_fd_flags(received_fd).map_err(|error| error.to_string())?;
        validate_stream(received_fd).map_err(|error| error.to_string())?;
        let identity =
            unix_socket_identity(received_fd.as_fd()).map_err(|error| error.to_string())?;
        if protected_identities.contains(&identity) {
            return Err("received fd aliases a protected socket endpoint".into());
        }
    }
    Ok(())
}

fn parse_u32(value: &[u8]) -> Result<u32, String> {
    if value.is_empty()
        || (value.len() > 1 && value[0] == b'0')
        || !value.iter().all(u8::is_ascii_digit)
    {
        return Err("non-canonical decimal field".into());
    }
    std::str::from_utf8(value)
        .map_err(|_| "non-ASCII decimal field".to_string())?
        .parse()
        .map_err(|_| "decimal field is outside u32".into())
}

fn parse_line(line: &[u8], fd: Option<OwnedFd>) -> Result<Incoming, String> {
    if line.last() != Some(&b'\n') {
        return Err("unterminated control frame".into());
    }
    let fields: Vec<&[u8]> = line[..line.len() - 1].split(|byte| *byte == b' ').collect();
    match fields.as_slice() {
        [b"CONNECT", port] => Ok(Incoming::Connect {
            port: parse_u32(port)?,
            fd: fd.ok_or("CONNECT is missing its fd")?,
        }),
        [b"OK", request_id] if fd.is_none() => Ok(Incoming::Admit(parse_u32(request_id)?)),
        [b"REJECT", request_id] if fd.is_none() => Ok(Incoming::Reject(parse_u32(request_id)?)),
        _ => Err("invalid control frame".into()),
    }
}

pub(crate) fn prepare_stream(fd: &OwnedFd) -> std::io::Result<()> {
    validate_stream(fd)?;
    set_fd_flags(fd)
}

fn set_fd_flags(fd: &OwnedFd) -> std::io::Result<()> {
    let status = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(status | OFlag::O_NONBLOCK))?;
    let descriptor = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD)?);
    fcntl(fd, FcntlArg::F_SETFD(descriptor | FdFlag::FD_CLOEXEC))?;
    #[cfg(target_os = "macos")]
    {
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&enabled as *const libc::c_int).cast(),
                mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn validate_stream(fd: impl AsFd) -> std::io::Result<()> {
    let fd = fd.as_fd();
    if getsockopt(&fd, sockopt::SockType)? != SockType::Stream {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mux descriptor is not a stream socket",
        ));
    }
    getsockname::<nix::sys::socket::UnixAddr>(fd.as_raw_fd()).map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::virtio::vsock::control_proxy::*;
    use nix::sys::socket::{AddressFamily, SockFlag, socketpair};
    use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

    fn pair() -> (OwnedFd, OwnedFd) {
        let pair = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();
        prepare_stream(&pair.0).unwrap();
        prepare_stream(&pair.1).unwrap();
        pair
    }

    #[test]
    fn macos_socket_identity_distinguishes_endpoints_and_matches_aliases() {
        let (one, other) = pair();
        let alias = nix::unistd::dup(&one).unwrap();
        assert_eq!(
            unix_socket_identity(one.as_fd()).unwrap(),
            unix_socket_identity(alias.as_fd()).unwrap()
        );
        assert_ne!(
            unix_socket_identity(one.as_fd()).unwrap(),
            unix_socket_identity(other.as_fd()).unwrap()
        );
    }

    #[test]
    fn parser_requires_canonical_frames_and_rights() {
        assert!(parse_line(b"OK 0\n", None).is_ok());
        assert!(parse_line(b"OK 01\n", None).is_err());
        assert!(parse_line(b"CONNECT 4\n", None).is_err());
        let (fd, _peer) = pair();
        assert!(matches!(
            parse_line(b"CONNECT 4\n", Some(fd)),
            Ok(Incoming::Connect { port: 4, .. })
        ));
    }

    #[test]
    fn fragmented_real_socket_frame_keeps_first_byte_fd() {
        let (local, peer) = pair();
        let (passed, _passed_peer) = pair();
        let (mut control, _) = ControlProxy::new(local, []).unwrap();
        let first = [IoSlice::new(b"C")];
        sendmsg::<()>(
            peer.as_raw_fd(),
            &first,
            &[ControlMessage::ScmRights(&[passed.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        nix::unistd::write(&peer, b"ONNECT 42\n").unwrap();
        let messages = control.read_messages().unwrap();
        let [Incoming::Connect { port, fd }] = messages.as_slice() else {
            panic!("expected one CONNECT frame");
        };
        assert_eq!(*port, 42);
        let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).unwrap());
        assert!(flags.contains(FdFlag::FD_CLOEXEC));
    }

    #[test]
    fn split_frame_progress_transfers_rights_once_and_preserves_alignment() {
        let (local, peer) = pair();
        let (passed, _passed_peer) = pair();
        let (mut control, handle) = ControlProxy::new(local, []).unwrap();
        handle.enqueue_connect(9, 7, 1, passed).unwrap();
        assert!(!control.flush_limited(1).unwrap());
        let mut byte = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        let mut cmsg = nix::cmsg_space!([RawFd; 2]);
        let rights: usize = {
            let message = nix::sys::socket::recvmsg::<()>(
                peer.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::empty(),
            )
            .unwrap();
            message
                .cmsgs()
                .unwrap()
                .map(|cmsg| match cmsg {
                    nix::sys::socket::ControlMessageOwned::ScmRights(fds) => fds.len(),
                    _ => 0,
                })
                .sum()
        };
        assert_eq!(rights, 1);
        assert_eq!(byte, [b'C']);

        assert!(control.flush().unwrap());
        let mut remainder = [0u8; MAX_LINE_BYTES];
        let mut iov = [IoSliceMut::new(&mut remainder)];
        let mut cmsg = nix::cmsg_space!([RawFd; 2]);
        let (bytes, rights) = {
            let message = nix::sys::socket::recvmsg::<()>(
                peer.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::empty(),
            )
            .unwrap();
            (message.bytes, message.cmsgs().unwrap().count())
        };
        assert_eq!(bytes, b"ONNECT 1 9 7\n".len());
        assert_eq!(rights, 0);
        assert_eq!(&remainder[..bytes], b"ONNECT 1 9 7\n");
    }

    #[test]
    fn protected_socket_alias_is_rejected_and_received_copy_is_closed() {
        let (local, peer) = pair();
        let (protected, protected_peer) = pair();
        let identity = unix_socket_identity(protected.as_fd()).unwrap();
        let (mut control, _) = ControlProxy::new(local, [identity]).unwrap();
        sendmsg::<()>(
            peer.as_raw_fd(),
            &[IoSlice::new(b"C")],
            &[ControlMessage::ScmRights(&[protected.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert!(control.read_messages().is_err());
        drop(protected);
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&protected_peer, &mut byte).unwrap(), 0);
    }

    #[test]
    fn truncated_ancillary_rejects_and_drops_every_exposed_right() {
        let (received, peer) = pair();
        let received = vec![received];
        assert!(
            validate_received_fds(libc::MSG_CTRUNC, false, &received, &HashSet::new()).is_err()
        );
        drop(received);
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&peer, &mut byte).unwrap(), 0);
    }

    #[test]
    fn adjacent_frames_assign_rights_to_the_correct_first_byte() {
        let (local, peer) = pair();
        let (passed, _passed_peer) = pair();
        let (mut control, _) = ControlProxy::new(local, []).unwrap();
        sendmsg::<()>(
            peer.as_raw_fd(),
            &[IoSlice::new(b"C")],
            &[ControlMessage::ScmRights(&[passed.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        nix::unistd::write(&peer, b"ONNECT 8\nOK 19\n").unwrap();
        let messages = control.read_messages().unwrap();
        assert!(matches!(messages[0], Incoming::Connect { port: 8, .. }));
        assert!(matches!(messages[1], Incoming::Admit(19)));
    }

    #[test]
    fn missing_and_excess_rights_are_fatal() {
        let (local, peer) = pair();
        let (mut control, _) = ControlProxy::new(local, []).unwrap();
        nix::unistd::write(&peer, b"CONNECT 8\n").unwrap();
        assert!(control.read_messages().is_err());

        let (local, peer) = pair();
        let (one, one_peer) = pair();
        let (two, two_peer) = pair();
        let (mut control, _) = ControlProxy::new(local, []).unwrap();
        sendmsg::<()>(
            peer.as_raw_fd(),
            &[IoSlice::new(b"CONNECT 8\n")],
            &[ControlMessage::ScmRights(&[
                one.as_raw_fd(),
                two.as_raw_fd(),
            ])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert!(control.read_messages().is_err());
        drop(one);
        drop(two);
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&one_peer, &mut byte).unwrap(), 0);
        assert_eq!(nix::unistd::read(&two_peer, &mut byte).unwrap(), 0);
    }

    #[test]
    fn cancelled_and_partial_expired_frames_have_distinct_outcomes() {
        let (local, _peer) = pair();
        let (passed, _passed_peer) = pair();
        let (_control, handle) = ControlProxy::new(local, []).unwrap();
        let request_id = handle.enqueue_connect(9, 7, 44, passed).unwrap();
        {
            let mut shared = handle.shared.lock().unwrap();
            shared.pending.get_mut(&request_id).unwrap().deadline = Instant::now();
            shared.frames.front_mut().unwrap().deadline = Instant::now();
        }
        assert_eq!(handle.expire(), (vec![44], false));

        let (passed, _passed_peer) = pair();
        let request_id = handle.enqueue_connect(9, 7, 45, passed).unwrap();
        {
            let mut shared = handle.shared.lock().unwrap();
            shared.pending.get_mut(&request_id).unwrap().deadline = Instant::now();
            let frame = shared.frames.front_mut().unwrap();
            frame.deadline = Instant::now();
            frame.offset = 1;
        }
        assert_eq!(handle.expire(), (Vec::new(), true));
    }

    #[test]
    fn cancellation_drops_unsent_frame_and_fences_partial_frame() {
        let (local, _peer) = pair();
        let (passed, _passed_peer) = pair();
        let (_control, handle) = ControlProxy::new(local, []).unwrap();
        handle.enqueue_connect(9, 7, 66, passed).unwrap();
        handle.cancel_proxy(66);
        assert!(!handle.wants_write());
        assert!(handle.is_active());

        let (passed, _passed_peer) = pair();
        handle.enqueue_connect(9, 7, 67, passed).unwrap();
        handle.shared.lock().unwrap().frames[0].offset = 1;
        handle.cancel_proxy(67);
        assert!(!handle.is_active());
    }

    #[test]
    fn duplicate_pending_proxy_preserves_original_endpoint_and_request_id() {
        let (local, _peer) = pair();
        let (original, original_peer) = pair();
        let (duplicate, duplicate_peer) = pair();
        let (other, _other_peer) = pair();
        let (_control, handle) = ControlProxy::new(local, []).unwrap();
        assert_eq!(handle.enqueue_connect(9, 7, 88, original).unwrap(), 1);
        let duplicate = handle.enqueue_connect(9, 7, 88, duplicate).unwrap_err();
        assert_eq!(handle.enqueue_connect(10, 8, 89, other).unwrap(), 2);
        assert_eq!(handle.take_pending(1), Some(88));
        drop(duplicate);
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&duplicate_peer, &mut byte).unwrap(), 0);
        assert_eq!(
            nix::unistd::read(&original_peer, &mut byte).unwrap_err(),
            Errno::EAGAIN
        );
    }

    #[test]
    fn duplicate_reply_is_late_and_control_half_close_is_failure() {
        let (local, peer) = pair();
        let (passed, _passed_peer) = pair();
        let (mut control, handle) = ControlProxy::new(local, []).unwrap();
        let request_id = handle.enqueue_connect(9, 7, 55, passed).unwrap();
        assert_eq!(handle.take_pending(request_id), Some(55));
        assert_eq!(handle.take_pending(request_id), None);
        nix::sys::socket::shutdown(peer.as_raw_fd(), nix::sys::socket::Shutdown::Write).unwrap();
        assert!(control.read_messages().is_err());
    }

    #[test]
    fn stopped_reader_does_not_block_outbound_progress() {
        let (local, _peer) = pair();
        let (mut control, handle) = ControlProxy::new(local, []).unwrap();
        for proxy_id in 0..MAX_PENDING as u64 {
            let (passed, _passed_peer) = pair();
            handle.enqueue_connect(9, 7, proxy_id, passed).unwrap();
        }
        let (excess, _excess_peer) = pair();
        assert!(
            handle
                .enqueue_connect(9, 7, MAX_PENDING as u64, excess)
                .is_err()
        );
        let start = Instant::now();
        assert!(!control.flush().unwrap());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(handle.wants_write());
    }

    #[test]
    fn queue_waker_and_deadline_drive_real_readiness_waits() {
        let (local, _peer) = pair();
        let (passed, _passed_peer) = pair();
        let (_control, handle) = ControlProxy::new(local, []).unwrap();
        let mut epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                handle.wake_fd(),
                &EpollEvent::new(EventSet::IN, 17),
            )
            .unwrap();
        let request_id = handle.enqueue_connect(9, 7, 90, passed).unwrap();
        let mut events = [EpollEvent::default(); 1];
        assert_eq!(epoll.wait(1, 100, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 17);
        handle.drain_wake();

        {
            let deadline = Instant::now() + Duration::from_millis(20);
            let mut shared = handle.shared.lock().unwrap();
            shared.pending.get_mut(&request_id).unwrap().deadline = deadline;
            shared.frames.front_mut().unwrap().deadline = deadline;
        }
        let timeout = handle.next_timeout_ms().max(1);
        let started = Instant::now();
        assert_eq!(epoll.wait(1, timeout, &mut events).unwrap(), 0);
        assert!(started.elapsed() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(handle.expire(), (vec![90], false));
    }

    #[test]
    fn partial_frame_deadline_starts_with_first_byte_and_does_not_renew() {
        let (local, peer) = pair();
        let (passed, passed_peer) = pair();
        let (mut control, _) = ControlProxy::new(local, []).unwrap();
        let started = Instant::now();
        sendmsg::<()>(
            peer.as_raw_fd(),
            &[IoSlice::new(b"C")],
            &[ControlMessage::ScmRights(&[passed.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert!(control.read_messages_at(started).unwrap().is_empty());
        nix::unistd::write(&peer, b"ON").unwrap();
        assert!(
            control
                .read_messages_at(started + Duration::from_secs(4))
                .unwrap()
                .is_empty()
        );
        assert!(control.partial_expired(started + REQUEST_TIMEOUT));
        control.close();
        drop(passed);
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&passed_peer, &mut byte).unwrap(), 0);
    }

    #[test]
    fn receive_flood_is_bounded_and_leaves_readiness_for_outbound_progress() {
        let (local, peer) = pair();
        let (passed, _passed_peer) = pair();
        let (mut control, handle) = ControlProxy::new(local, []).unwrap();
        let flood = b"OK 1\n".repeat(RECEIVE_FRAME_BUDGET * 2);
        nix::unistd::write(&peer, &flood).unwrap();
        handle.enqueue_connect(9, 7, 91, passed).unwrap();

        let messages = control.read_messages().unwrap();
        assert_eq!(messages.len(), RECEIVE_FRAME_BUDGET);
        assert!(control.flush().unwrap());

        let mut epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                control.as_raw_fd().unwrap(),
                &EpollEvent::new(EventSet::IN, 23),
            )
            .unwrap();
        let mut events = [EpollEvent::default(); 1];
        assert_eq!(epoll.wait(1, 0, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 23);

        let mut byte = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        let mut cmsg = nix::cmsg_space!([RawFd; 1]);
        let message = nix::sys::socket::recvmsg::<()>(
            peer.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::empty(),
        )
        .unwrap();
        assert_eq!(message.bytes, 1);
        assert_eq!(message.cmsgs().unwrap().count(), 1);
    }

    #[test]
    fn mutex_poison_fences_wakes_and_drops_queued_rights() {
        let (local, peer) = pair();
        let (passed, passed_peer) = pair();
        let (mut control, handle) = ControlProxy::new(local, []).unwrap();
        handle.enqueue_connect(9, 7, 92, passed).unwrap();
        let poison_handle = handle.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = poison_handle.shared.lock().unwrap();
                panic!("poison control queue for teardown test");
            })
            .join()
            .is_err()
        );
        assert!(!handle.is_active());

        let mut epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                handle.wake_fd(),
                &EpollEvent::new(EventSet::IN, 29),
            )
            .unwrap();
        let mut events = [EpollEvent::default(); 1];
        assert_eq!(epoll.wait(1, 100, &mut events).unwrap(), 1);
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&passed_peer, &mut byte).unwrap(), 0);
        control.close();
        assert_eq!(nix::unistd::read(&peer, &mut byte).unwrap(), 0);
    }

    #[test]
    fn closing_control_cancels_queued_fds_and_pending_requests() {
        let (local, peer) = pair();
        let (passed, passed_peer) = pair();
        let (mut control, handle) = ControlProxy::new(local, []).unwrap();
        handle.enqueue_connect(9, 7, 77, passed).unwrap();
        assert_eq!(control.close(), vec![77]);
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&passed_peer, &mut byte).unwrap(), 0);
        assert_eq!(nix::unistd::read(&peer, &mut byte).unwrap(), 0);
    }

    #[test]
    fn data_socket_half_close_preserves_the_opposite_direction() {
        let (local, peer) = pair();
        nix::unistd::write(&peer, b"request").unwrap();
        nix::sys::socket::shutdown(peer.as_raw_fd(), nix::sys::socket::Shutdown::Write).unwrap();
        let mut request = [0u8; 7];
        assert_eq!(nix::unistd::read(&local, &mut request).unwrap(), 7);
        assert_eq!(&request, b"request");
        let mut eof = [0u8; 1];
        assert_eq!(nix::unistd::read(&local, &mut eof).unwrap(), 0);
        nix::unistd::write(&local, b"response").unwrap();
        let mut response = [0u8; 8];
        assert_eq!(nix::unistd::read(&peer, &mut response).unwrap(), 8);
        assert_eq!(&response, b"response");
    }
}
