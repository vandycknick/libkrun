use libc::{
    IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUN_F_UFO, c_char, c_int,
    ifreq,
};
use nix::fcntl::{FcntlArg, OFlag, fcntl, open};
use nix::sys::stat::Mode;
use nix::unistd::{read, write};
use nix::{ioctl_write_int, ioctl_write_ptr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::{io, mem, ptr};
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO,
};

use crate::virtio::net::backend::{ConnectError, NetBackend, ReadError, WriteError};

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
ioctl_write_int!(tunsetoffload, b'T', 208);
ioctl_write_ptr!(tunsetvnethdrsz, b'T', 216, c_int);

pub struct Tap {
    fd: OwnedFd,
}

impl Tap {
    /// Create an endpoint using the file descriptor of a tap device
    pub fn new(tap_name: String, vnet_features: u64) -> Result<Self, ConnectError> {
        let fd = match open("/dev/net/tun", OFlag::O_RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(err) => return Err(ConnectError::OpenNetTun(err)),
        };

        let mut req: ifreq = unsafe { mem::zeroed() };

        unsafe {
            ptr::copy_nonoverlapping(
                tap_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tap_name.len(),
            );
        }

        req.ifr_ifru.ifru_flags = IFF_TAP as i16 | IFF_NO_PI as i16 | IFF_VNET_HDR as i16;

        let mut offload_flags: u64 = 0;
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_CSUM)) != 0 {
            offload_flags |= TUN_F_CSUM as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO4)) != 0 {
            offload_flags |= TUN_F_TSO4 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO6)) != 0 {
            offload_flags |= TUN_F_TSO6 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_UFO)) != 0 {
            offload_flags |= TUN_F_UFO as u64;
        }

        unsafe {
            if let Err(err) = tunsetiff(fd.as_raw_fd(), &mut req as *mut _ as *mut _) {
                return Err(ConnectError::TunSetIff(io::Error::from(err)));
            }

            // TODO(slp): replace hardcoded vnet size with cons
            if let Err(err) = tunsetvnethdrsz(fd.as_raw_fd(), &12) {
                return Err(ConnectError::TunSetVnetHdrSz(io::Error::from(err)));
            }

            if let Err(err) = tunsetoffload(fd.as_raw_fd(), offload_flags) {
                return Err(ConnectError::TunSetOffload(io::Error::from(err)));
            }
        }

        let flags = fcntl(&fd, FcntlArg::F_GETFL).map_err(ConnectError::Configure)?;
        fcntl(
            &fd,
            FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
        )
        .map_err(ConnectError::Configure)?;

        Ok(Self { fd })
    }
}

impl NetBackend for Tap {
    /// Try to read a frame from the tap devie. If no bytes are available reports
    /// ReadError::NothingRead.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let frame_length = match read(&self.fd, buf) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead);
            }
            Err(e) => {
                return Err(ReadError::Internal(e));
            }
        };
        debug!("Read eth frame from tap: {frame_length} bytes");
        Ok(frame_length)
    }

    /// Try to write a frame to the tap device.
    fn write_frame(&mut self, _hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        let ret = match write(&self.fd, buf) {
            Ok(count) if count == buf.len() => count,
            Ok(_) => return Err(WriteError::Internal(nix::Error::EIO)),
            Err(nix::Error::EAGAIN) => return Err(WriteError::NothingWritten),
            Err(error) => return Err(WriteError::Internal(error)),
        };
        debug!("Written frame size={}, written={}", buf.len(), ret);
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        // The tap backend doesn't do partial writes.
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::net::backend::{NetBackend, WriteError};
    use crate::virtio::net::tap::Tap;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn net_provider_tap_nonblocking_write_backpressure_has_no_effect() {
        let (socket, peer) = UnixDatagram::pair().expect("real packet socket");
        socket
            .set_nonblocking(true)
            .expect("TAP nonblocking contract");
        peer.set_nonblocking(true).expect("nonblocking observation");
        let mut backend = Tap { fd: socket.into() };
        let mut frame = [0x33; 1024];
        let mut accepted = 0;
        loop {
            match backend.write_frame(0, &mut frame) {
                Ok(()) => {
                    accepted += 1;
                    assert!(accepted < 10000, "real socket must reach backpressure");
                }
                Err(WriteError::NothingWritten) => break,
                Err(error) => panic!("legitimate TAP backpressure became terminal: {error:?}"),
            }
        }
        assert!(matches!(
            backend.write_frame(0, &mut frame),
            Err(WriteError::NothingWritten)
        ));
        let mut received = [0; 2048];
        for _ in 0..accepted {
            assert_eq!(
                peer.recv(&mut received).expect("accepted packet"),
                frame.len()
            );
            assert_eq!(&received[..frame.len()], &frame);
        }
        assert_eq!(
            peer.recv(&mut received)
                .expect_err("no effect from refused packet")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut retry = [0x55; 17];
        backend
            .write_frame(0, &mut retry)
            .expect("retry after writable");
        assert_eq!(peer.recv(&mut received).expect("one retry"), retry.len());
        assert_eq!(&received[..retry.len()], &retry);
    }
}
