// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "macos")]
use std::net::{Ipv6Addr, SocketAddrV6};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

#[cfg(windows)]
use crate::virtio::vsock::windows::sockaddr_storage::SockaddrStorage;
use arch::guest_memory::{HostReadGuard, HostWriteGuard, ReadView, WriteView};
#[cfg(target_os = "linux")]
use nix::sys::socket::{AddressFamily, sockaddr};
#[cfg(unix)]
use nix::sys::socket::{SockaddrLike, SockaddrStorage};
use utils::byte_order;
use vm_memory::{Address, GuestAddress};

use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
use crate::virtio::vsock::worker_control::WorkerControl;
use crate::virtio::vsock::{Result, VsockError, defs};
use crate::virtio::{DescriptorChain, Queue, RuntimeGuestMemory};

pub const VSOCK_PKT_HDR_SIZE: usize = 44;
const HDROFF_SRC_CID: usize = 0;
const HDROFF_DST_CID: usize = 8;
const HDROFF_SRC_PORT: usize = 16;
const HDROFF_DST_PORT: usize = 20;
const HDROFF_LEN: usize = 24;
const HDROFF_TYPE: usize = 28;
const HDROFF_OP: usize = 30;
const HDROFF_FLAGS: usize = 32;
const HDROFF_BUF_ALLOC: usize = 36;
const HDROFF_FWD_CNT: usize = 40;

#[repr(C)]
pub struct TsiProxyCreate {
    pub peer_port: u32,
    pub family: u16,
    pub _type: u16,
}
#[repr(C)]
pub struct TsiConnectReq {
    pub peer_port: u32,
    pub addr: SockaddrStorage,
}
#[repr(C)]
pub struct TsiConnectRsp {
    pub result: i32,
}
#[repr(C)]
pub struct TsiGetnameReq {
    pub peer_port: u32,
    pub local_port: u32,
    pub peer: u32,
}
#[repr(C)]
#[derive(Debug)]
pub struct TsiGetnameRsp {
    pub result: i32,
    pub addr_len: u32,
    pub addr: SockaddrStorage,
}
impl TsiGetnameRsp {
    pub(crate) fn payload_len(&self) -> Option<usize> {
        let length = self.addr_len as usize;
        if length > 128 || length > self.addr.len() as usize {
            return None;
        }
        length.checked_add(8)
    }
}
impl Default for TsiGetnameRsp {
    fn default() -> Self {
        let addr: SockaddrStorage = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
        Self {
            result: -1,
            addr_len: 16,
            addr,
        }
    }
}
#[repr(C)]
#[derive(Debug)]
pub struct TsiSendtoAddr {
    pub peer_port: u32,
    pub addr: SockaddrStorage,
}
#[repr(C)]
#[derive(Debug)]
pub struct TsiListenReq {
    pub peer_port: u32,
    pub vm_port: u32,
    pub backlog: i32,
    pub addr: SockaddrStorage,
}
#[repr(C)]
#[derive(Debug)]
pub struct TsiListenRsp {
    pub result: i32,
}
#[repr(C)]
#[derive(Debug)]
pub struct TsiAcceptReq {
    pub peer_port: u32,
    pub flags: u32,
}
#[repr(C)]
#[derive(Debug)]
pub struct TsiAcceptRsp {
    pub result: i32,
}
#[repr(C)]
pub struct TsiReleaseReq {
    pub peer_port: u32,
    pub local_port: u32,
}

pub(crate) struct PacketQueue {
    pub queue: Queue,
    pub snapshot: DescriptorChainSnapshot,
    admission: Option<Arc<WorkerControl>>,
}
impl PacketQueue {
    pub fn from_queue(queue: Queue) -> Self {
        let snapshot = DescriptorChainSnapshot::new(queue.get_max_size());
        Self {
            queue,
            snapshot,
            admission: None,
        }
    }
    pub fn bind_admission(&mut self, control: Arc<WorkerControl>) {
        self.admission = Some(control);
    }
    pub fn pop<'m>(&mut self, memory: &'m RuntimeGuestMemory) -> Option<DescriptorChain<'m>> {
        let queue = &mut self.queue;
        match &self.admission {
            Some(control) => control.admit(|| queue.pop(memory)).flatten(),
            None => queue.pop(memory),
        }
    }
    #[cfg(feature = "native-device-probe")]
    pub fn record_counter(&self, counter: crate::virtio::vsock::worker_control::WorkerCounter) {
        if let Some(control) = &self.admission {
            control.record(counter);
        }
    }
}
impl Deref for PacketQueue {
    type Target = Queue;
    fn deref(&self) -> &Queue {
        &self.queue
    }
}
impl DerefMut for PacketQueue {
    fn deref_mut(&mut self) -> &mut Queue {
        &mut self.queue
    }
}

/// A captured TX header and a read-only payload. Direct payloads stay in guest RAM.
///
/// Payload views expose const pointers and volatile reads only. A const pointer
/// must not be cast to a writable destination, even while the packet is alive.
pub struct TxPacket<'a> {
    header: [u8; VSOCK_PKT_HDR_SIZE],
    payload: TxPayload<'a>,
}
enum TxPayload<'a> {
    Guest(HostReadGuard),
    Scratch(&'a [u8]),
    Empty,
}

/// RX owns both writer obligations until the packet, including any receive, is complete.
pub struct RxPacket {
    _header: HostWriteGuard,
    header_ptr: *mut u8,
    body: Option<HostWriteGuard>,
}

struct Header<'a>(&'a [u8]);
impl Header<'_> {
    fn u16(&self, offset: usize) -> u16 {
        byte_order::read_le_u16(&self.0[offset..])
    }
    fn u32(&self, offset: usize) -> u32 {
        byte_order::read_le_u32(&self.0[offset..])
    }
    fn u64(&self, offset: usize) -> u64 {
        byte_order::read_le_u64(&self.0[offset..])
    }
}

impl<'a> TxPacket<'a> {
    pub(crate) fn from_tx_virtq_head(
        head: &DescriptorChain,
        snapshot: &mut DescriptorChainSnapshot,
        scratch: Option<&'a mut [u8]>,
    ) -> Result<Self> {
        let chain = snapshot
            .read(head.clone())
            .map_err(|_| VsockError::InvalidDescriptorChain)?;
        let descriptors = chain.descriptors();
        if descriptors
            .iter()
            .any(|descriptor| descriptor.flags & VIRTQ_DESC_F_WRITE != 0)
        {
            return Err(VsockError::UnreadableDescriptor);
        }
        let header = descriptors.first().ok_or(VsockError::BufDescMissing)?;
        if header.len < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(VsockError::HdrDescTooSmall(header.len));
        }
        let mut captured = [0; VSOCK_PKT_HDR_SIZE];
        head.mem
            .read_slice(&mut captured, GuestAddress(header.addr))
            .map_err(VsockError::GuestMemoryMmap)?;
        let mut packet = Self {
            header: captured,
            payload: TxPayload::Empty,
        };
        let length = packet.len() as usize;
        if length > defs::MAX_PKT_BUF_SIZE {
            return Err(VsockError::InvalidPktLen(packet.len()));
        }
        if length == 0 {
            return Ok(packet);
        }
        let inline = header.len as usize - VSOCK_PKT_HDR_SIZE;
        let direct = if descriptors.len() == 1 && inline >= length {
            Some(
                GuestAddress(header.addr)
                    .checked_add(VSOCK_PKT_HDR_SIZE as u64)
                    .ok_or(VsockError::GuestMemoryBounds)?,
            )
        } else if descriptors.len() == 2 && inline == 0 && descriptors[1].len as usize >= length {
            Some(GuestAddress(descriptors[1].addr))
        } else {
            None
        };
        if let Some(address) = direct {
            let guard = head
                .mem
                .read(address, length)
                .map_err(VsockError::GuestMemoryMmap)?;
            // A direct syscall needs one mapping. Adjacent mappings use the existing scratch path.
            if guard.read_view(0, length).is_ok() {
                packet.payload = TxPayload::Guest(guard);
                return Ok(packet);
            }
        }
        let buffer = scratch
            .and_then(|buffer| buffer.get_mut(..length))
            .ok_or(VsockError::BufDescTooSmall)?;
        let mut written = 0;
        for (index, descriptor) in descriptors.iter().enumerate() {
            let skip = if index == 0 { VSOCK_PKT_HDR_SIZE } else { 0 };
            let count = (descriptor.len as usize - skip).min(length - written);
            if count != 0 {
                let address = GuestAddress(descriptor.addr)
                    .checked_add(skip as u64)
                    .ok_or(VsockError::GuestMemoryBounds)?;
                head.mem
                    .read_slice(&mut buffer[written..written + count], address)
                    .map_err(VsockError::GuestMemoryMmap)?;
                written += count;
            }
            if written == length {
                break;
            }
        }
        if written != length {
            return Err(VsockError::BufDescTooSmall);
        }
        packet.payload = TxPayload::Scratch(buffer);
        Ok(packet)
    }
    pub fn hdr(&self) -> &[u8] {
        &self.header
    }
    pub fn buf(&self) -> Option<ReadView<'_>> {
        match &self.payload {
            TxPayload::Guest(guard) => guard.read_view(0, guard.len()).ok(),
            TxPayload::Scratch(bytes) => Some(ReadView::from_slice(bytes)),
            TxPayload::Empty => None,
        }
    }
    pub fn src_cid(&self) -> u64 {
        Header(self.hdr()).u64(HDROFF_SRC_CID)
    }
    pub fn dst_cid(&self) -> u64 {
        Header(self.hdr()).u64(HDROFF_DST_CID)
    }
    pub fn src_port(&self) -> u32 {
        Header(self.hdr()).u32(HDROFF_SRC_PORT)
    }
    pub fn dst_port(&self) -> u32 {
        Header(self.hdr()).u32(HDROFF_DST_PORT)
    }
    pub fn len(&self) -> u32 {
        Header(self.hdr()).u32(HDROFF_LEN)
    }
    pub fn type_(&self) -> u16 {
        Header(self.hdr()).u16(HDROFF_TYPE)
    }
    pub fn op(&self) -> u16 {
        Header(self.hdr()).u16(HDROFF_OP)
    }
    pub fn flags(&self) -> u32 {
        Header(self.hdr()).u32(HDROFF_FLAGS)
    }
    pub fn buf_alloc(&self) -> u32 {
        Header(self.hdr()).u32(HDROFF_BUF_ALLOC)
    }
    pub fn fwd_cnt(&self) -> u32 {
        Header(self.hdr()).u32(HDROFF_FWD_CNT)
    }
    fn payload_bytes<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let view = self.buf()?;
        let view = view.subslice(offset, N).ok()?;
        let mut bytes = [0; N];
        view.read_slice(&mut bytes, 0).ok()?;
        Some(bytes)
    }
    #[cfg(target_os = "linux")]
    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        if addr_len as usize > buf.len() || addr_len < 2 {
            return None;
        }
        // from_raw copies into aligned storage; family-specific wire bounds remain ours.
        let address =
            unsafe { SockaddrStorage::from_raw(buf.as_ptr().cast::<sockaddr>(), Some(addr_len))? };
        match address.family() {
            Some(AddressFamily::Inet) if addr_len >= 16 => Some(address),
            Some(AddressFamily::Inet6) if addr_len >= 28 => Some(address),
            Some(AddressFamily::Unix)
                if addr_len as usize <= std::mem::size_of::<libc::sockaddr_un>() =>
            {
                Some(address)
            }
            _ => None,
        }
    }
    #[cfg(target_os = "macos")]
    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        let buf = buf.get(..addr_len as usize)?;
        let family = u16::from_le_bytes(buf.get(..2)?.try_into().ok()?);
        match family {
            defs::LINUX_AF_INET => {
                buf.get(..16)?;
                let port = u16::from_be_bytes(buf.get(2..4)?.try_into().ok()?);
                let addr: [u8; 4] = buf.get(4..8)?.try_into().ok()?;
                Some(SocketAddrV4::new(Ipv4Addr::from(addr), port).into())
            }
            defs::LINUX_AF_INET6 => {
                let port = u16::from_be_bytes(buf.get(2..4)?.try_into().ok()?);
                let flow = u32::from_be_bytes(buf.get(4..8)?.try_into().ok()?);
                let addr: [u8; 16] = buf.get(8..24)?.try_into().ok()?;
                let scope = u32::from_le_bytes(buf.get(24..28)?.try_into().ok()?);
                Some(SocketAddrV6::new(Ipv6Addr::from(addr), port, flow, scope).into())
            }
            _ => None,
        }
    }
    #[cfg(target_os = "windows")]
    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        SockaddrStorage::from_linux_bytes(buf.get(..addr_len as usize)?, addr_len)
    }
    fn address(&self, offset: usize, length: u32) -> Option<SockaddrStorage> {
        let length = length as usize;
        let mut bytes = [0; 128];
        let destination = bytes.get_mut(..length)?;
        self.buf()?
            .subslice(offset, length)
            .ok()?
            .read_slice(destination, 0)
            .ok()?;
        Self::parse_address(destination, length as u32)
    }
    pub fn read_proxy_create(&self) -> Option<TsiProxyCreate> {
        let bytes: [u8; 8] = self.payload_bytes(0)?;
        Some(TsiProxyCreate {
            peer_port: byte_order::read_le_u32(&bytes),
            family: byte_order::read_le_u16(&bytes[4..]),
            _type: byte_order::read_le_u16(&bytes[6..]),
        })
    }
    pub fn read_connect_req(&self) -> Option<TsiConnectReq> {
        let bytes: [u8; 8] = self.payload_bytes(0)?;
        Some(TsiConnectReq {
            peer_port: byte_order::read_le_u32(&bytes),
            addr: self.address(8, byte_order::read_le_u32(&bytes[4..]))?,
        })
    }
    pub fn read_getname_req(&self) -> Option<TsiGetnameReq> {
        let bytes: [u8; 12] = self.payload_bytes(0)?;
        Some(TsiGetnameReq {
            peer_port: byte_order::read_le_u32(&bytes),
            local_port: byte_order::read_le_u32(&bytes[4..]),
            peer: byte_order::read_le_u32(&bytes[8..]),
        })
    }
    pub fn read_sendto_addr(&self) -> Option<TsiSendtoAddr> {
        let req = self.read_connect_req()?;
        Some(TsiSendtoAddr {
            peer_port: req.peer_port,
            addr: req.addr,
        })
    }
    pub fn read_listen_req(&self) -> Option<TsiListenReq> {
        let bytes: [u8; 16] = self.payload_bytes(0)?;
        Some(TsiListenReq {
            peer_port: byte_order::read_le_u32(&bytes),
            vm_port: byte_order::read_le_u32(&bytes[4..]),
            backlog: byte_order::read_le_u32(&bytes[8..]) as i32,
            addr: self.address(16, byte_order::read_le_u32(&bytes[12..]))?,
        })
    }
    pub fn read_accept_req(&self) -> Option<TsiAcceptReq> {
        let bytes: [u8; 8] = self.payload_bytes(0)?;
        Some(TsiAcceptReq {
            peer_port: byte_order::read_le_u32(&bytes),
            flags: byte_order::read_le_u32(&bytes[4..]),
        })
    }
    pub fn read_release_req(&self) -> Option<TsiReleaseReq> {
        let bytes: [u8; 8] = self.payload_bytes(0)?;
        Some(TsiReleaseReq {
            peer_port: byte_order::read_le_u32(&bytes),
            local_port: byte_order::read_le_u32(&bytes[4..]),
        })
    }
}

impl RxPacket {
    pub(crate) fn from_rx_virtq_head(
        head: &DescriptorChain,
        snapshot: &mut DescriptorChainSnapshot,
    ) -> Result<Self> {
        let chain = snapshot
            .read(head.clone())
            .map_err(|_| VsockError::InvalidDescriptorChain)?;
        let descriptors = chain.descriptors();
        if descriptors
            .iter()
            .any(|descriptor| descriptor.flags & VIRTQ_DESC_F_WRITE == 0)
        {
            return Err(VsockError::UnwritableDescriptor);
        }
        let first = descriptors.first().ok_or(VsockError::BufDescMissing)?;
        if first.len < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(VsockError::HdrDescTooSmall(first.len));
        }
        let inline = first.len as usize - VSOCK_PKT_HDR_SIZE;
        let body_range = if inline != 0 {
            Some((
                GuestAddress(first.addr)
                    .checked_add(VSOCK_PKT_HDR_SIZE as u64)
                    .ok_or(VsockError::GuestMemoryBounds)?,
                inline,
            ))
        } else {
            descriptors[1..]
                .iter()
                .find(|descriptor| descriptor.len != 0)
                .map(|descriptor| (GuestAddress(descriptor.addr), descriptor.len as usize))
                .or_else(|| (descriptors.len() > 1).then_some((GuestAddress(0), 0)))
        };
        let header = head
            .mem
            .write(GuestAddress(first.addr), VSOCK_PKT_HDR_SIZE)
            .map_err(VsockError::GuestMemoryMmap)?;
        let header_ptr = header
            .write_view(0, VSOCK_PKT_HDR_SIZE)
            .map_err(VsockError::GuestMemoryMmap)?
            .as_mut_ptr();
        let body = if let Some((address, capacity)) = body_range {
            let guard = head
                .mem
                .write(address, capacity.min(defs::MAX_PKT_BUF_SIZE))
                .map_err(VsockError::GuestMemoryMmap)?;
            guard
                .write_view(0, guard.len())
                .map_err(VsockError::GuestMemoryMmap)?;
            Some(guard)
        } else {
            None
        };
        Ok(Self {
            _header: header,
            header_ptr,
            body,
        })
    }
    fn header_bytes<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut bytes = [0; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            // Only fixed-size getters use offsets inside the retained header.
            *byte = unsafe { self.header_ptr.add(offset + index).read_volatile() };
        }
        bytes
    }
    pub fn buf(&self) -> Option<ReadView<'_>> {
        self.body
            .as_ref()
            .and_then(|guard| guard.read_view(0, guard.len()).ok())
    }
    pub fn buf_mut(&mut self) -> Option<WriteView<'_>> {
        self.body
            .as_ref()
            .and_then(|guard| guard.write_view(0, guard.len()).ok())
    }
    fn set_header(&mut self, offset: usize, bytes: &[u8]) -> &mut Self {
        for (index, byte) in bytes.iter().enumerate() {
            // Only fixed-size field setters call this with offsets inside the retained header.
            unsafe {
                self.header_ptr.add(offset + index).write_volatile(*byte);
            }
        }
        self
    }
    pub fn len(&self) -> u32 {
        u32::from_le_bytes(self.header_bytes(HDROFF_LEN))
    }
    pub fn op(&self) -> u16 {
        u16::from_le_bytes(self.header_bytes(HDROFF_OP))
    }
    pub fn flags(&self) -> u32 {
        u32::from_le_bytes(self.header_bytes(HDROFF_FLAGS))
    }
    pub fn src_port(&self) -> u32 {
        u32::from_le_bytes(self.header_bytes(HDROFF_SRC_PORT))
    }
    pub fn dst_port(&self) -> u32 {
        u32::from_le_bytes(self.header_bytes(HDROFF_DST_PORT))
    }
    pub fn fwd_cnt(&self) -> u32 {
        u32::from_le_bytes(self.header_bytes(HDROFF_FWD_CNT))
    }
    pub fn set_src_cid(&mut self, value: u64) -> &mut Self {
        self.set_header(HDROFF_SRC_CID, &value.to_le_bytes())
    }
    pub fn set_dst_cid(&mut self, value: u64) -> &mut Self {
        self.set_header(HDROFF_DST_CID, &value.to_le_bytes())
    }
    pub fn set_src_port(&mut self, value: u32) -> &mut Self {
        self.set_header(HDROFF_SRC_PORT, &value.to_le_bytes())
    }
    pub fn set_dst_port(&mut self, value: u32) -> &mut Self {
        self.set_header(HDROFF_DST_PORT, &value.to_le_bytes())
    }
    pub fn set_len(&mut self, value: u32) -> &mut Self {
        self.set_header(HDROFF_LEN, &value.to_le_bytes())
    }
    pub fn set_type(&mut self, value: u16) -> &mut Self {
        self.set_header(HDROFF_TYPE, &value.to_le_bytes())
    }
    pub fn set_op(&mut self, value: u16) -> &mut Self {
        self.set_header(HDROFF_OP, &value.to_le_bytes())
    }
    pub fn set_flags(&mut self, value: u32) -> &mut Self {
        self.set_header(HDROFF_FLAGS, &value.to_le_bytes())
    }
    pub fn set_flag(&mut self, value: u32) -> &mut Self {
        self.set_flags(self.flags() | value)
    }
    pub fn set_buf_alloc(&mut self, value: u32) -> &mut Self {
        self.set_header(HDROFF_BUF_ALLOC, &value.to_le_bytes())
    }
    pub fn set_fwd_cnt(&mut self, value: u32) -> &mut Self {
        self.set_header(HDROFF_FWD_CNT, &value.to_le_bytes())
    }
    pub fn write_connect_rsp(&mut self, rsp: TsiConnectRsp) {
        self.write_body(&rsp.result.to_le_bytes());
    }
    pub fn write_listen_rsp(&mut self, rsp: TsiListenRsp) {
        self.write_body(&rsp.result.to_le_bytes());
    }
    pub fn write_accept_rsp(&mut self, rsp: TsiAcceptRsp) {
        self.write_body(&rsp.result.to_le_bytes());
    }
    pub fn write_time_sync(&mut self, time: u64) {
        self.write_body(&time.to_le_bytes());
    }
    fn write_body(&mut self, bytes: &[u8]) {
        if let Some(view) = self.buf_mut()
            && bytes.len() <= view.len()
        {
            for (index, byte) in bytes.iter().enumerate() {
                // The bounded view borrows the retained, premarked writer obligation.
                unsafe {
                    view.as_mut_ptr().add(index).write_volatile(*byte);
                }
            }
        }
    }
    pub fn write_getname_rsp(&mut self, rsp: TsiGetnameRsp) {
        let Some(payload_len) = rsp.payload_len() else {
            return;
        };
        let length = payload_len - 8;
        let mut bytes = [0; 136];
        bytes[..4].copy_from_slice(&rsp.result.to_le_bytes());
        bytes[4..8].copy_from_slice(&rsp.addr_len.to_le_bytes());
        let address = unsafe { std::slice::from_raw_parts(rsp.addr.as_ptr().cast::<u8>(), length) };
        bytes[8..8 + length].copy_from_slice(address);
        #[cfg(target_os = "macos")]
        {
            let family = match bytes[9] as i32 {
                libc::AF_INET => defs::LINUX_AF_INET,
                libc::AF_INET6 => defs::LINUX_AF_INET6,
                _ => 0,
            };
            bytes[8..10].copy_from_slice(&family.to_le_bytes());
        }
        self.write_body(&bytes[..payload_len]);
    }
}

// nix socket APIs require Rust slices, which cannot represent concurrently mutable
// guest RAM. These adapters retain the bounded view through the raw syscall.
#[cfg(unix)]
pub(crate) fn recv_into(
    fd: std::os::fd::RawFd,
    view: WriteView<'_>,
    count: usize,
    flags: nix::sys::socket::MsgFlags,
) -> nix::Result<usize> {
    if count > view.len() {
        return Err(nix::errno::Errno::EINVAL);
    }
    let result = unsafe { libc::recv(fd, view.as_mut_ptr().cast(), count, flags.bits()) };
    nix::errno::Errno::result(result).map(|count| count as usize)
}

#[cfg(unix)]
pub(crate) fn send_from(
    fd: std::os::fd::RawFd,
    view: ReadView<'_>,
    flags: nix::sys::socket::MsgFlags,
) -> nix::Result<usize> {
    let result = unsafe { libc::send(fd, view.as_ptr().cast(), view.len(), flags.bits()) };
    nix::errno::Errno::result(result).map(|count| count as usize)
}

#[cfg(unix)]
pub(crate) fn send_to(
    fd: std::os::fd::RawFd,
    view: ReadView<'_>,
    address: &SockaddrStorage,
    flags: nix::sys::socket::MsgFlags,
) -> nix::Result<usize> {
    let result = unsafe {
        libc::sendto(
            fd,
            view.as_ptr().cast(),
            view.len(),
            flags.bits(),
            address.as_ptr(),
            address.len(),
        )
    };
    nix::errno::Errno::result(result).map(|count| count as usize)
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use arch::guest_memory::{BackingKind, DirtyPageMap, DomainControl, MemoryDomain};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::packet::{
        PacketQueue, RxPacket, TxPacket, TxPayload, VSOCK_PKT_HDR_SIZE,
    };
    use crate::virtio::{DescriptorChain, Queue, RuntimeGuestMemory};

    fn tracked_packet(rx: bool) -> (RuntimeGuestMemory, DomainControl, Queue) {
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
        let memory = RuntimeGuestMemory::new(domain);
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x2000, VSOCK_PKT_HDR_SIZE as u32, if rx { 3 } else { 1 }, 1);
        ring.dtable[1].set(0x3ff0, 32, if rx { 2 } else { 0 }, 0);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        memory
            .write_slice(&[0; VSOCK_PKT_HDR_SIZE], GuestAddress(0x2000))
            .unwrap();
        memory
            .write_obj(32u32.to_le(), GuestAddress(0x2018))
            .unwrap();
        memory
            .write_slice(&[0xa5; 32], GuestAddress(0x3ff0))
            .unwrap();
        let queue = ring.create_queue();
        let epoch = authority.issue_epoch(1).unwrap();
        control.finish_tracked(authority, epoch).unwrap();
        (memory, control, queue)
    }

    #[test]
    fn provider_vsock_tx_direct_read_does_not_mark_or_hold_writers() {
        let (memory, mut control, mut queue) = tracked_packet(false);
        let head = queue.pop(&memory).unwrap();
        let packet =
            TxPacket::from_tx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8), None)
                .unwrap();
        assert!(matches!(packet.payload, TxPayload::Guest(_)));
        let view = packet.buf().unwrap();
        let _: *const u8 = view.as_ptr();
        let mut bytes = [0; 32];
        view.read_slice(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [0xa5; 32]);
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("TX retained a writer");
        };
        let cut = control.seal(&drained).unwrap();
        let mut dirty = DirtyPageMap::new(control.domain().layout());
        control.drain_host_dirty(&cut, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 0);
        assert_eq!(packet.len(), 32);
    }

    #[cfg(unix)]
    #[test]
    fn provider_vsock_rx_receive_short_error_and_completion_retain_marked_writers() {
        use crate::virtio::vsock::packet::recv_into;
        use arch::guest_memory::PageIndex;
        use nix::errno::Errno;
        use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, send, socketpair};
        use std::os::fd::AsRawFd;

        let (memory, mut control, mut queue) = tracked_packet(true);
        let head = queue.pop(&memory).unwrap();
        let mut packet =
            RxPacket::from_rx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8)).unwrap();
        let (receiver, sender) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::SOCK_NONBLOCK,
        )
        .unwrap();
        send(sender.as_raw_fd(), b"received", MsgFlags::empty()).unwrap();
        assert_eq!(
            recv_into(
                receiver.as_raw_fd(),
                packet.buf_mut().unwrap(),
                32,
                MsgFlags::empty()
            )
            .unwrap(),
            8
        );
        assert_eq!(
            recv_into(-1, packet.buf_mut().unwrap(), 32, MsgFlags::empty()),
            Err(Errno::EBADF)
        );
        assert_eq!(
            recv_into(
                receiver.as_raw_fd(),
                packet.buf_mut().unwrap(),
                33,
                MsgFlags::empty()
            ),
            Err(Errno::EINVAL)
        );
        packet
            .set_len(8)
            .set_op(5)
            .write_time_sync(0x0102030405060708);
        queue
            .add_used(
                &memory,
                head.index,
                VSOCK_PKT_HDR_SIZE as u32 + packet.len(),
            )
            .unwrap();
        let closing = control.close().unwrap();
        assert!(control.poll_drained(&closing).is_pending());
        assert!(memory.write_slice(b"x", GuestAddress(0x5000)).is_err());
        // An admitted destination remains writable even after new writer admission closes.
        packet.write_connect_rsp(crate::virtio::vsock::packet::TsiConnectRsp { result: -7 });
        assert_eq!(packet.len(), 8);
        let mut bytes = [0; 32];
        packet.buf().unwrap().read_slice(&mut bytes, 0).unwrap();
        assert_eq!(&bytes[..4], &(-7i32).to_le_bytes());
        assert_eq!(&bytes[8..], &[0xa5; 24]);
        drop(packet);
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("RX writer did not drain");
        };
        let cut = control.seal(&drained).unwrap();
        let mut dirty = DirtyPageMap::new(control.domain().layout());
        control.drain_host_dirty(&cut, &mut dirty).unwrap();
        assert!(dirty.contains(PageIndex::new(2)));
        assert!(dirty.contains(PageIndex::new(3)));
        assert!(dirty.contains(PageIndex::new(4)));
        assert!(!dirty.contains(PageIndex::new(5)));
    }

    #[test]
    fn provider_vsock_packet_full_tail_rejects_ttl_and_direction_before_dma() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        ring.dtable[1].set(0x5000, 8, 3, 1);
        memory
            .write_slice(&[0x5a; VSOCK_PKT_HDR_SIZE], GuestAddress(0x4000))
            .unwrap();
        let mut snapshot = DescriptorChainSnapshot::new(8);
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        assert!(RxPacket::from_rx_virtq_head(&head, &mut snapshot).is_err());
        let mut header = [0; VSOCK_PKT_HDR_SIZE];
        memory
            .read_slice(&mut header, GuestAddress(0x4000))
            .unwrap();
        assert_eq!(header, [0x5a; VSOCK_PKT_HDR_SIZE]);
        ring.dtable[1].set(0x5000, 8, 1, 2);
        ring.dtable[2].set(0x6000, 8, 2, 0);
        assert!(RxPacket::from_rx_virtq_head(&head, &mut snapshot).is_err());
        ring.dtable[1].set(0x5000, 8, 2, 0);
        assert!(RxPacket::from_rx_virtq_head(&head, &mut snapshot).is_ok());
        assert!(TxPacket::from_tx_virtq_head(&head, &mut snapshot, None).is_err());
    }

    #[test]
    fn provider_vsock_packet_tx_metadata_is_frozen_and_scatter_copy_is_bounded() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 1, 1);
        ring.dtable[1].set(0x5000, 3, 1, 2);
        ring.dtable[2].set(0x6000, 128, 0, 0);
        memory
            .write_obj(4u32.to_le(), GuestAddress(0x4018))
            .unwrap();
        memory
            .write_obj(1027u32.to_le(), GuestAddress(0x4014))
            .unwrap();
        memory.write_slice(b"abc", GuestAddress(0x5000)).unwrap();
        memory.write_slice(b"defgh", GuestAddress(0x6000)).unwrap();
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut snapshot = DescriptorChainSnapshot::new(8);
        let mut scratch = [0xa5; 64];
        let packet =
            TxPacket::from_tx_virtq_head(&head, &mut snapshot, Some(&mut scratch)).unwrap();
        memory
            .write_obj(42u32.to_le(), GuestAddress(0x4014))
            .unwrap();
        assert_eq!(packet.dst_port(), 1027);
        let mut bytes = [0; 4];
        packet.buf().unwrap().read_slice(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"abcd");
        drop(packet);
        assert_eq!(scratch[4..], [0xa5; 60]);
        let mut too_small = [0; 3];
        assert!(TxPacket::from_tx_virtq_head(&head, &mut snapshot, Some(&mut too_small)).is_err());
    }

    #[test]
    fn provider_vsock_tx_adjacent_mapping_payload_uses_bounded_scratch() {
        let memory = RuntimeGuestMemory::from_ranges(&[
            (GuestAddress(0), 0x5000),
            (GuestAddress(0x5000), 0x1000),
        ])
        .unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 1, 1);
        ring.dtable[1].set(0x4ffe, 4, 0, 0);
        memory
            .write_obj(4u32.to_le(), GuestAddress(0x4018))
            .unwrap();
        memory.write_slice(b"abcd", GuestAddress(0x4ffe)).unwrap();
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut scratch = [0xa5; 8];
        let packet = TxPacket::from_tx_virtq_head(
            &head,
            &mut DescriptorChainSnapshot::new(8),
            Some(&mut scratch),
        )
        .unwrap();
        assert!(matches!(packet.payload, TxPayload::Scratch(_)));
        let mut bytes = [0; 4];
        packet.buf().unwrap().read_slice(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"abcd");
        drop(packet);
        assert_eq!(&scratch[4..], &[0xa5; 4]);
    }

    #[test]
    fn provider_vsock_rx_zero_body_never_dereferences_arbitrary_address() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        ring.dtable[1].set(u64::MAX, 0, 2, 0);
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut packet =
            RxPacket::from_rx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8)).unwrap();
        assert!(packet.buf_mut().unwrap().is_empty());
        packet.set_len(0).write_time_sync(42);
        assert_eq!(packet.len(), 0);
    }

    #[test]
    fn provider_vsock_rx_getname_response_copies_declared_address_only() {
        use crate::virtio::vsock::packet::TsiGetnameRsp;

        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        ring.dtable[1].set(0x5000, 132, 2, 0);
        memory
            .write_slice(&[0xa5; 132], GuestAddress(0x5000))
            .unwrap();
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut packet =
            RxPacket::from_rx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8)).unwrap();
        packet.write_getname_rsp(TsiGetnameRsp::default());
        let mut bytes = [0; 132];
        packet.buf().unwrap().read_slice(&mut bytes, 0).unwrap();
        assert_eq!(&bytes[..4], &(-1i32).to_le_bytes());
        assert_eq!(&bytes[4..8], &16u32.to_le_bytes());
        assert_eq!(&bytes[24..], &[0xa5; 108]);
    }

    #[test]
    fn provider_vsock_packet_zero_length_tx_still_validates_complete_tail() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 1, 1);
        ring.dtable[1].set(0x5000, 8, 1, 1);
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        assert!(
            TxPacket::from_tx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8), None)
                .is_err()
        );
    }

    #[test]
    fn provider_vsock_tx_header_and_payload_length_bounds_are_checked() {
        use crate::virtio::vsock::VsockError;

        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32 - 1, 0, 0);
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut snapshot = DescriptorChainSnapshot::new(8);
        assert!(matches!(
            TxPacket::from_tx_virtq_head(&head, &mut snapshot, None),
            Err(VsockError::HdrDescTooSmall(_))
        ));
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 0, 0);
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        memory
            .write_obj(u32::MAX.to_le(), GuestAddress(0x4018))
            .unwrap();
        assert!(matches!(
            TxPacket::from_tx_virtq_head(&head, &mut snapshot, None),
            Err(VsockError::InvalidPktLen(u32::MAX))
        ));
        memory.write_obj(0u32, GuestAddress(0x4018)).unwrap();
        let packet = TxPacket::from_tx_virtq_head(&head, &mut snapshot, None).unwrap();
        assert!(matches!(packet.payload, TxPayload::Empty));
        assert!(packet.buf().is_none());
    }

    #[test]
    fn provider_vsock_control_decoding_rejects_truncated_and_oversized_fields() {
        for length in 0..8 {
            let bytes = [0; 8];
            let packet = TxPacket {
                header: [0; VSOCK_PKT_HDR_SIZE],
                payload: TxPayload::Scratch(&bytes[..length]),
            };
            assert!(packet.read_proxy_create().is_none());
            assert!(packet.read_connect_req().is_none());
            assert!(packet.read_sendto_addr().is_none());
            assert!(packet.read_accept_req().is_none());
            assert!(packet.read_release_req().is_none());
        }
        for length in 0..16 {
            let bytes = [0; 16];
            let packet = TxPacket {
                header: [0; VSOCK_PKT_HDR_SIZE],
                payload: TxPayload::Scratch(&bytes[..length]),
            };
            assert!(packet.read_listen_req().is_none());
            if length < 12 {
                assert!(packet.read_getname_req().is_none());
            }
        }
        let mut bytes = [0; 16];
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let packet = TxPacket {
            header: [0; VSOCK_PKT_HDR_SIZE],
            payload: TxPayload::Scratch(&bytes),
        };
        assert!(packet.read_connect_req().is_none());
        assert!(packet.read_sendto_addr().is_none());
        assert!(packet.read_listen_req().is_none());
    }

    #[test]
    fn provider_vsock_packet_admission_closes_between_real_owned_heads() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, 44, 2, 0);
        ring.dtable[1].set(0x5000, 44, 2, 0);
        ring.avail.ring[0].set(0);
        ring.avail.ring[1].set(1);
        ring.avail.idx.set(2);
        let control = crate::virtio::vsock::worker_control::WorkerControl::new().unwrap();
        let mut queue = PacketQueue::from_queue(ring.create_queue());
        queue.bind_admission(control.clone());
        let first = queue.pop(&memory).unwrap();
        control.pause().unwrap();
        assert!(queue.pop(&memory).is_none());
        queue.add_used(&memory, first.index, 0).unwrap();
        assert_eq!(queue.capture_state().unwrap().next_avail, 1);
        assert_eq!(queue.capture_state().unwrap().next_used, 1);
        control.resume().unwrap();
        assert_eq!(queue.pop(&memory).unwrap().index, 1);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn provider_vsock_macos_address_bounds_and_ipv6_scope_roundtrip() {
        use crate::virtio::vsock::defs;
        use crate::virtio::vsock::packet::TsiGetnameRsp;

        let mut ipv4 = [0; 16];
        ipv4[..2].copy_from_slice(&defs::LINUX_AF_INET.to_le_bytes());
        for length in 0..16 {
            assert!(TxPacket::parse_address(&ipv4[..length], length as u32).is_none());
        }
        assert!(TxPacket::parse_address(&ipv4, 16).is_some());
        let mut request = [0; 36];
        request[..4].copy_from_slice(&7u32.to_le_bytes());
        request[4..8].copy_from_slice(&28u32.to_le_bytes());
        request[8..10].copy_from_slice(&defs::LINUX_AF_INET6.to_le_bytes());
        request[10..12].copy_from_slice(&443u16.to_be_bytes());
        request[12..16].copy_from_slice(&0x01020304u32.to_be_bytes());
        request[16..32].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        request[32..36].copy_from_slice(&0x12345678u32.to_le_bytes());
        let tx = TxPacket {
            header: [0; VSOCK_PKT_HDR_SIZE],
            payload: TxPayload::Scratch(&request),
        };
        let decoded = tx.read_connect_req().unwrap();
        let address = decoded.addr.as_sockaddr_in6().unwrap();
        assert_eq!(address.port(), 443);
        assert_eq!(address.flowinfo(), 0x01020304);
        assert_eq!(address.scope_id(), 0x12345678);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        ring.dtable[1].set(0x5000, 36, 2, 0);
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut rx =
            RxPacket::from_rx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8)).unwrap();
        rx.write_getname_rsp(TsiGetnameRsp {
            result: 0,
            addr_len: 28,
            addr: decoded.addr,
        });
        let mut response = [0; 36];
        rx.buf().unwrap().read_slice(&mut response, 0).unwrap();
        assert_eq!(&response[8..10], &defs::LINUX_AF_INET6.to_le_bytes());
        assert_eq!(&response[32..36], &0x12345678u32.to_le_bytes());
    }
}
