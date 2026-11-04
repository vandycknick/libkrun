// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

use crate::virtio::Queue;
use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
use crate::virtio::vsock::worker_control::WorkerControl;
/// `VsockPacket` provides a thin wrapper over the buffers exchanged via virtio queues.
/// There are two components to a vsock packet, each using its own descriptor in a
/// virtio queue:
/// - the packet header; and
/// - the packet data/buffer.
///
/// There is a 1:1 relation between descriptor chains and packets: the first (chain head) holds
/// the header, and an optional second descriptor holds the data. The second descriptor is only
/// present for data packets (VSOCK_OP_RW).
///
/// `VsockPacket` wraps these two buffers and provides direct access to the data stored
/// in guest memory. This is done to avoid unnecessarily copying data from guest memory
/// to temporary buffers, before passing it on to the vsock backend.
use std::convert::TryInto;
use std::ffi::CStr;
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "macos")]
use std::net::{Ipv6Addr, SocketAddrV6};
use std::ops::{Deref, DerefMut};
use std::os::raw::c_char;
use std::result;
use std::sync::Arc;

#[cfg(windows)]
use crate::virtio::vsock::windows::sockaddr_storage::SockaddrStorage;
#[cfg(target_os = "linux")]
use nix::sys::socket::{AddressFamily, sockaddr};
#[cfg(unix)]
use nix::sys::socket::{SockaddrLike, SockaddrStorage};
use utils::byte_order;
use vm_memory::{self, Address, GuestAddress, GuestMemoryError};

use crate::virtio::vsock::defs;
use crate::virtio::vsock::{Result, VsockError};
use crate::virtio::{DescriptorChain, LeasedHostAddress, RuntimeGuestMemory};

// The vsock packet header is defined by the C struct:
//
// ```C
// struct virtio_vsock_hdr {
//     le64 src_cid;
//     le64 dst_cid;
//     le32 src_port;
//     le32 dst_port;
//     le32 len;
//     le16 type;
//     le16 op;
//     le32 flags;
//     le32 buf_alloc;
//     le32 fwd_cnt;
// };
// ```
//
// This structed will occupy the buffer pointed to by the head descriptor. We'll be accessing it
// as a byte slice. To that end, we define below the offsets for each field struct, as well as the
// packed struct size, as a bunch of `usize` consts.
// Note that these offsets are only used privately by the `VsockPacket` struct, the public interface
// consisting of getter and setter methods, for each struct field, that will also handle the correct
// endianess.

/// The vsock packet header struct size (when packed).
pub const VSOCK_PKT_HDR_SIZE: usize = 44;

// Source CID.
const HDROFF_SRC_CID: usize = 0;

// Destination CID.
const HDROFF_DST_CID: usize = 8;

// Source port.
const HDROFF_SRC_PORT: usize = 16;

// Destination port.
const HDROFF_DST_PORT: usize = 20;

// Data length (in bytes) - may be 0, if there is no data buffer.
const HDROFF_LEN: usize = 24;

// Socket type. Currently, only connection-oriented streams are defined by the vsock protocol.
const HDROFF_TYPE: usize = 28;

// Operation ID - one of the VSOCK_OP_* values; e.g.
// - VSOCK_OP_RW: a data packet;
// - VSOCK_OP_REQUEST: connection request;
// - VSOCK_OP_RST: forcefull connection termination;
// etc (see `super::defs::uapi` for the full list).
const HDROFF_OP: usize = 30;

// Additional options (flags) associated with the current operation (`op`).
// Currently, only used with shutdown requests (VSOCK_OP_SHUTDOWN).
const HDROFF_FLAGS: usize = 32;

// Size (in bytes) of the packet sender receive buffer (for the connection to which this packet
// belongs).
const HDROFF_BUF_ALLOC: usize = 36;

// Number of bytes the sender has received and consumed (for the connection to which this packet
// belongs). For instance, for our Unix backend, this counter would be the total number of bytes
// we have successfully written to a backing Unix socket.
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

impl Default for TsiGetnameRsp {
    fn default() -> Self {
        let addr: SockaddrStorage = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0).into();
        TsiGetnameRsp {
            result: -1,
            // It's fine to unwrap here sice we've just created the SocketAddrV4 above.
            addr_len: addr.as_sockaddr_in().unwrap().len(),
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

enum PacketHeader {
    Captured([u8; VSOCK_PKT_HDR_SIZE]),
    Guest(LeasedHostAddress),
}

/// The vsock packet, implemented as a wrapper over a virtq descriptor chain:
/// - the chain head, holding the packet header; and
/// - (an optional) data/buffer descriptor, only present for data packets (VSOCK_OP_RW).
pub struct VsockPacket<'a> {
    header: PacketHeader,
    buf: Option<*mut u8>,
    buf_size: usize,
    owned_buf: Option<&'a mut [u8]>,
    _buffer_lease: Option<LeasedHostAddress>,
}

fn get_host_address(
    mem: &RuntimeGuestMemory,
    guest_addr: GuestAddress,
    size: usize,
) -> result::Result<LeasedHostAddress, GuestMemoryError> {
    mem.get_host_address(guest_addr, size)
}

impl<'a> VsockPacket<'a> {
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
        let mut captured = [0u8; VSOCK_PKT_HDR_SIZE];
        head.mem
            .read_slice(&mut captured, GuestAddress(header.addr))
            .map_err(VsockError::GuestMemoryMmap)?;
        let mut packet = Self {
            header: PacketHeader::Captured(captured),
            buf: None,
            buf_size: 0,
            owned_buf: None,
            _buffer_lease: None,
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
            let lease =
                get_host_address(head.mem, address, length).map_err(VsockError::GuestMemoryMmap)?;
            packet.buf = Some(lease.as_ptr());
            packet.buf_size = length;
            packet._buffer_lease = Some(lease);
            return Ok(packet);
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
        packet.buf_size = length;
        packet.owned_buf = Some(buffer);
        Ok(packet)
    }

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
        let header = get_host_address(head.mem, GuestAddress(first.addr), VSOCK_PKT_HDR_SIZE)
            .map_err(VsockError::GuestMemoryMmap)?;
        let mut packet = Self {
            header: PacketHeader::Guest(header),
            buf: None,
            buf_size: 0,
            owned_buf: None,
            _buffer_lease: None,
        };
        let inline = first.len as usize - VSOCK_PKT_HDR_SIZE;
        let body = if inline != 0 {
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
        };
        if let Some((address, capacity)) = body {
            packet.buf_size = capacity.min(defs::MAX_PKT_BUF_SIZE);
            let lease = get_host_address(head.mem, address, packet.buf_size)
                .map_err(VsockError::GuestMemoryMmap)?;
            packet.buf = Some(lease.as_ptr());
            packet._buffer_lease = Some(lease);
        } else if descriptors.len() > 1 {
            // An explicit zero-length body remains present without leasing its
            // arbitrary guest address; a header-only control packet has none.
            packet.buf = Some(std::ptr::NonNull::<u8>::dangling().as_ptr());
        }
        Ok(packet)
    }

    /// Provides in-place, byte-slice, access to the vsock packet header.
    pub fn hdr(&self) -> &[u8] {
        match &self.header {
            PacketHeader::Captured(header) => header,
            PacketHeader::Guest(header) => unsafe {
                std::slice::from_raw_parts(header.as_ptr(), VSOCK_PKT_HDR_SIZE)
            },
        }
    }

    /// Provides in-place, byte-slice, mutable access to the vsock packet header.
    pub fn hdr_mut(&mut self) -> &mut [u8] {
        match &mut self.header {
            PacketHeader::Captured(header) => header,
            PacketHeader::Guest(header) => unsafe {
                std::slice::from_raw_parts_mut(header.as_ptr(), VSOCK_PKT_HDR_SIZE)
            },
        }
    }

    /// Provides in-place, byte-slice access to the vsock packet data buffer.
    ///
    /// Note: control packets (e.g. connection request or reset) have no data buffer associated.
    ///       For those packets, this method will return `None`.
    /// Also note: calling `len()` on the returned slice will yield the buffer size, which may be
    ///            (and often is) larger than the length of the packet data. The packet data length
    ///            is stored in the packet header, and accessible via `VsockPacket::len()`.
    pub fn buf(&self) -> Option<&[u8]> {
        if let Some(ref owned) = self.owned_buf {
            Some(owned)
        } else {
            self.buf.map(|ptr| {
                // This is safe since bound checks have already been performed when creating the
                // packet from the virtq descriptor.
                unsafe { std::slice::from_raw_parts(ptr as *const u8, self.buf_size) }
            })
        }
    }

    /// Provides in-place, byte-slice, mutable access to the vsock packet data buffer.
    ///
    /// Note: control packets (e.g. connection request or reset) have no data buffer associated.
    ///       For those packets, this method will return `None`.
    /// Also note: calling `len()` on the returned slice will yield the buffer size, which may be
    ///            (and often is) larger than the length of the packet data. The packet data length
    ///            is stored in the packet header, and accessible via `VsockPacket::len()`.
    pub fn buf_mut(&mut self) -> Option<&mut [u8]> {
        if let Some(ref mut owned) = self.owned_buf {
            Some(owned)
        } else {
            self.buf.map(|ptr| {
                // This is safe since bound checks have already been performed when creating the
                // packet from the virtq descriptor.
                unsafe { std::slice::from_raw_parts_mut(ptr, self.buf_size) }
            })
        }
    }

    pub fn src_cid(&self) -> u64 {
        byte_order::read_le_u64(&self.hdr()[HDROFF_SRC_CID..])
    }

    pub fn set_src_cid(&mut self, cid: u64) -> &mut Self {
        byte_order::write_le_u64(&mut self.hdr_mut()[HDROFF_SRC_CID..], cid);
        self
    }

    pub fn dst_cid(&self) -> u64 {
        byte_order::read_le_u64(&self.hdr()[HDROFF_DST_CID..])
    }

    pub fn set_dst_cid(&mut self, cid: u64) -> &mut Self {
        byte_order::write_le_u64(&mut self.hdr_mut()[HDROFF_DST_CID..], cid);
        self
    }

    pub fn src_port(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_SRC_PORT..])
    }

    pub fn set_src_port(&mut self, port: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_SRC_PORT..], port);
        self
    }

    pub fn dst_port(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_DST_PORT..])
    }

    pub fn set_dst_port(&mut self, port: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_DST_PORT..], port);
        self
    }

    pub fn len(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_LEN..])
    }

    pub fn set_len(&mut self, len: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_LEN..], len);
        self
    }

    pub fn type_(&self) -> u16 {
        byte_order::read_le_u16(&self.hdr()[HDROFF_TYPE..])
    }

    pub fn set_type(&mut self, type_: u16) -> &mut Self {
        byte_order::write_le_u16(&mut self.hdr_mut()[HDROFF_TYPE..], type_);
        self
    }

    pub fn op(&self) -> u16 {
        byte_order::read_le_u16(&self.hdr()[HDROFF_OP..])
    }

    pub fn set_op(&mut self, op: u16) -> &mut Self {
        byte_order::write_le_u16(&mut self.hdr_mut()[HDROFF_OP..], op);
        self
    }

    pub fn flags(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_FLAGS..])
    }

    pub fn set_flags(&mut self, flags: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_FLAGS..], flags);
        self
    }

    pub fn set_flag(&mut self, flag: u32) -> &mut Self {
        self.set_flags(self.flags() | flag);
        self
    }

    pub fn buf_alloc(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_BUF_ALLOC..])
    }

    pub fn set_buf_alloc(&mut self, buf_alloc: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_BUF_ALLOC..], buf_alloc);
        self
    }

    pub fn fwd_cnt(&self) -> u32 {
        byte_order::read_le_u32(&self.hdr()[HDROFF_FWD_CNT..])
    }

    pub fn set_fwd_cnt(&mut self, fwd_cnt: u32) -> &mut Self {
        byte_order::write_le_u32(&mut self.hdr_mut()[HDROFF_FWD_CNT..], fwd_cnt);
        self
    }

    pub fn sa_family(&self) -> Option<u16> {
        if self.buf_size >= 2 {
            Some(byte_order::read_le_u16(&self.buf().unwrap()[0..]))
        } else {
            None
        }
    }

    pub fn inet_port(&self) -> Option<u16> {
        if self.buf_size >= 4 {
            Some(byte_order::read_be_u16(&self.buf().unwrap()[2..]))
        } else {
            None
        }
    }

    pub fn inet_addr(&self) -> Option<[u8; 4]> {
        if self.buf_size >= 8 {
            let ptr = &self.buf().unwrap()[4];
            let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, 4) };
            slice[0..4].try_into().ok()
        } else {
            None
        }
    }

    pub fn unix_path(&self) -> Option<&str> {
        if self.buf_size >= 108 {
            let cstr =
                unsafe { CStr::from_ptr(&self.buf().unwrap()[2] as *const _ as *const c_char) };
            cstr.to_str().ok()
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        let sockaddr: SockaddrStorage = unsafe {
            SockaddrStorage::from_raw(&buf[0] as *const _ as *const sockaddr, Some(addr_len))?
        };

        match sockaddr.family() {
            Some(AddressFamily::Inet) => debug!("parse_address: AF_INET"),
            Some(AddressFamily::Inet6) => debug!("parse_address: AF_INET6"),
            Some(AddressFamily::Unix) => debug!("parse_address: AF_UNIX"),
            _ => {
                if let Some(family) = sockaddr.family() {
                    warn!("parse_address: unsupported family {family:?}");
                } else {
                    warn!("parse_address: error parsing family");
                }
                return None;
            }
        }

        Some(sockaddr)
    }

    #[cfg(target_os = "macos")]
    fn parse_address(buf: &[u8], _addr_len: u32) -> Option<SockaddrStorage> {
        let family: u16 = byte_order::read_le_u16(&buf[0..2]);

        match family {
            defs::LINUX_AF_INET => {
                debug!("parse_address: AF_INET");
                let in_port: u16 = byte_order::read_be_u16(&buf[2..4]);
                let in_addr = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                Some(SocketAddrV4::new(in_addr, in_port).into())
            }
            defs::LINUX_AF_INET6 => {
                debug!("parse_address: AF_INET6");
                let in_port: u16 = byte_order::read_be_u16(&buf[2..4]);
                let flowinfo: u32 = byte_order::read_be_u32(&buf[4..8]);
                let in6_addr = Ipv6Addr::new(
                    byte_order::read_be_u16(&buf[8..10]),
                    byte_order::read_be_u16(&buf[10..12]),
                    byte_order::read_be_u16(&buf[12..14]),
                    byte_order::read_be_u16(&buf[14..16]),
                    byte_order::read_be_u16(&buf[16..18]),
                    byte_order::read_be_u16(&buf[18..20]),
                    byte_order::read_be_u16(&buf[20..22]),
                    byte_order::read_be_u16(&buf[22..24]),
                );
                let scope_id: u32 = byte_order::read_be_u32(&buf[24..28]);
                Some(SocketAddrV6::new(in6_addr, in_port, flowinfo, scope_id).into())
            }
            defs::LINUX_AF_UNIX => {
                // On macOS, SockaddrStorage doesn't implement `from_raw` for
                // Unix sockets, nor a way to cast an UnixPath to it.
                error!("AF_UNIX sockets aren't yet supported on macOS");
                None
            }
            _ => None,
        }
    }

    #[cfg(target_os = "windows")]
    fn parse_address(buf: &[u8], addr_len: u32) -> Option<SockaddrStorage> {
        SockaddrStorage::from_linux_bytes(buf, addr_len)
    }

    pub fn read_proxy_create(&self) -> Option<TsiProxyCreate> {
        if self.buf_size >= 6 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let family: u16 = byte_order::read_le_u16(&self.buf().unwrap()[4..]);
            let _type: u16 = byte_order::read_le_u16(&self.buf().unwrap()[6..]);

            Some(TsiProxyCreate {
                peer_port,
                family,
                _type,
            })
        } else {
            None
        }
    }

    pub fn read_connect_req(&self) -> Option<TsiConnectReq> {
        if self.buf_size >= 4 {
            let buf = self.buf().unwrap();
            let peer_port: u32 = byte_order::read_le_u32(&buf[0..]);
            let addr_len: u32 = byte_order::read_le_u32(&buf[4..]);
            let addr = Self::parse_address(&buf[8..], addr_len)?;

            Some(TsiConnectReq { peer_port, addr })
        } else {
            None
        }
    }

    pub fn write_connect_rsp(&mut self, rsp: TsiConnectRsp) {
        if self.buf_size >= 4
            && let Some(buf) = self.buf_mut()
        {
            byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
        }
    }

    pub fn read_getname_req(&self) -> Option<TsiGetnameReq> {
        if self.buf_size >= 12 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let local_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[4..]);
            let peer: u32 = byte_order::read_le_u32(&self.buf().unwrap()[8..]);
            Some(TsiGetnameReq {
                peer_port,
                local_port,
                peer,
            })
        } else {
            None
        }
    }

    pub fn write_getname_rsp(&mut self, rsp: TsiGetnameRsp) {
        if self.buf_size >= 132
            && let Some(buf) = self.buf_mut()
        {
            byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
            byte_order::write_le_u32(&mut buf[4..], rsp.addr_len);
            let addr_ptr = rsp.addr.as_ptr();
            let slice = unsafe {
                std::slice::from_raw_parts(addr_ptr as *const u8, rsp.addr.len() as usize)
            };
            buf[8..(rsp.addr.len() + 8) as usize].copy_from_slice(slice);

            // On macOS, convert BSD sockaddr (u8 sa_len + u8 sa_family) to
            // Linux wire format (u16 sa_family). Also translate macOS AF_*
            // values to their Linux equivalents (e.g. AF_INET6: 30 → 10).
            #[cfg(target_os = "macos")]
            {
                let bsd_family = buf[9];
                let linux_family: u16 = match bsd_family as i32 {
                    libc::AF_INET => defs::LINUX_AF_INET,
                    libc::AF_INET6 => defs::LINUX_AF_INET6,
                    _ => 0, // AF_UNSPEC
                };
                byte_order::write_le_u16(&mut buf[8..], linux_family);
            }
        }
    }

    pub fn read_sendto_addr(&self) -> Option<TsiSendtoAddr> {
        if self.buf_size >= 4 {
            let buf = self.buf().unwrap();
            let peer_port: u32 = byte_order::read_le_u32(&buf[0..]);
            let addr_len: u32 = byte_order::read_le_u32(&buf[4..]);
            let addr = Self::parse_address(&buf[8..], addr_len)?;

            Some(TsiSendtoAddr { peer_port, addr })
        } else {
            None
        }
    }

    pub fn read_listen_req(&self) -> Option<TsiListenReq> {
        if self.buf_size >= 12 {
            let buf = self.buf().unwrap();
            let peer_port: u32 = byte_order::read_le_u32(&buf[0..]);
            let vm_port: u32 = byte_order::read_le_u32(&buf[4..]);
            let backlog: u32 = byte_order::read_le_u32(&buf[8..]);
            let addr_len: u32 = byte_order::read_le_u32(&buf[12..]);
            let addr = Self::parse_address(&buf[16..], addr_len)?;

            Some(TsiListenReq {
                peer_port,
                vm_port,
                backlog: backlog as i32,
                addr,
            })
        } else {
            None
        }
    }

    pub fn write_listen_rsp(&mut self, rsp: TsiListenRsp) {
        if self.buf_size >= 4
            && let Some(buf) = self.buf_mut()
        {
            byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
        }
    }

    pub fn read_accept_req(&self) -> Option<TsiAcceptReq> {
        if self.buf_size >= 8 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let flags: u32 = byte_order::read_le_u32(&self.buf().unwrap()[4..]);

            Some(TsiAcceptReq { peer_port, flags })
        } else {
            None
        }
    }

    pub fn write_accept_rsp(&mut self, rsp: TsiAcceptRsp) {
        if self.buf_size >= 4
            && let Some(buf) = self.buf_mut()
        {
            byte_order::write_le_u32(&mut buf[0..], rsp.result as u32);
        }
    }

    pub fn read_release_req(&self) -> Option<TsiReleaseReq> {
        if self.buf_size >= 8 {
            let peer_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[0..]);
            let local_port: u32 = byte_order::read_le_u32(&self.buf().unwrap()[4..]);
            Some(TsiReleaseReq {
                peer_port,
                local_port,
            })
        } else {
            None
        }
    }

    pub fn write_time_sync(&mut self, time: u64) {
        if self.buf_size >= 8
            && let Some(buf) = self.buf_mut()
        {
            byte_order::write_le_u64(&mut buf[0..], time);
        }
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;

    use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::packet::{VSOCK_PKT_HDR_SIZE, VsockPacket};
    use crate::virtio::{DescriptorChain, RuntimeGuestMemory};

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
        assert!(VsockPacket::from_rx_virtq_head(&head, &mut snapshot).is_err());
        let mut header = [0u8; VSOCK_PKT_HDR_SIZE];
        memory
            .read_slice(&mut header, GuestAddress(0x4000))
            .unwrap();
        assert_eq!(header, [0x5a; VSOCK_PKT_HDR_SIZE]);
        ring.dtable[1].set(0x5000, 8, 1, 2);
        ring.dtable[2].set(0x6000, 8, 2, 0);
        assert!(VsockPacket::from_rx_virtq_head(&head, &mut snapshot).is_err());
        ring.dtable[1].set(0x5000, 8, 2, 0);
        assert!(VsockPacket::from_rx_virtq_head(&head, &mut snapshot).is_ok());
    }

    #[test]
    fn provider_vsock_packet_tx_metadata_is_frozen_and_scatter_copy_is_bounded() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 1, 1);
        ring.dtable[1].set(0x5000, 3, 1, 2);
        ring.dtable[2].set(0x6000, 128, 0, 0);
        memory.write_obj(4u32, GuestAddress(0x4018)).unwrap();
        memory.write_obj(1027u32, GuestAddress(0x4014)).unwrap();
        memory.write_slice(b"abc", GuestAddress(0x5000)).unwrap();
        memory.write_slice(b"defgh", GuestAddress(0x6000)).unwrap();
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut snapshot = DescriptorChainSnapshot::new(8);
        let mut scratch = [0xa5; 64];
        let packet =
            VsockPacket::from_tx_virtq_head(&head, &mut snapshot, Some(&mut scratch)).unwrap();
        memory.write_obj(42u32, GuestAddress(0x4014)).unwrap();
        assert_eq!(packet.dst_port(), 1027);
        assert_eq!(packet.buf().unwrap(), b"abcd");
        drop(packet);
        assert_eq!(scratch[4..], [0xa5; 60]);
    }

    #[test]
    fn provider_vsock_packet_zero_length_tx_still_validates_complete_tail() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 1, 1);
        ring.dtable[1].set(0x5000, 8, 1, 1);
        let head = DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut snapshot = DescriptorChainSnapshot::new(8);
        assert!(VsockPacket::from_tx_virtq_head(&head, &mut snapshot, None).is_err());
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
        let mut queue = crate::virtio::vsock::packet::PacketQueue::from_queue(ring.create_queue());
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
}
