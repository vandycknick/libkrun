use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, connect, getsockopt, recv, send,
    setsockopt, socket, sockopt,
};
use std::{
    os::fd::{AsRawFd, OwnedFd, RawFd},
    path::PathBuf,
};

use crate::virtio::net::backend::ConnectError;

use crate::virtio::net::backend::{NetBackend, ReadError, WriteError};
use crate::virtio::net::{VNET_HDR_LEN, write_virtio_net_hdr};

/// Each frame the network proxy is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const FRAME_HEADER_LEN: usize = 4;

pub struct Unixstream {
    fd: OwnedFd,
    rx_header: [u8; FRAME_HEADER_LEN],
    rx_header_read: usize,
    rx_frame_length: usize,
    rx_body_read: usize,
    // 0 if last write is fully complete, otherwise the length that was written
    last_partial_write_length: usize,
}

impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: OwnedFd) -> Self {
        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Self {
            fd,
            rx_header: [0; FRAME_HEADER_LEN],
            rx_header_read: 0,
            rx_frame_length: 0,
            rx_body_read: 0,
            last_partial_write_length: 0,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        Ok(Self::new(fd))
    }

    fn read_available(fd: RawFd, buf: &mut [u8]) -> Result<usize, ReadError> {
        loop {
            match recv(fd, buf, MsgFlags::MSG_DONTWAIT) {
                Ok(0) => return Err(ReadError::Internal(nix::Error::ECONNRESET)),
                Ok(count) => return Ok(count),
                Err(nix::Error::EINTR) => continue,
                Err(nix::Error::EAGAIN) => return Err(ReadError::NothingRead),
                Err(error) => return Err(ReadError::Internal(error)),
            }
        }
    }

    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut bytes_send = 0;

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        while bytes_send < buf.len() {
            match send(self.fd.as_raw_fd(), &buf[bytes_send..], flags) {
                Ok(0) => return Err(WriteError::ProcessNotRunning),
                Ok(size) => bytes_send += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    if bytes_send == 0 {
                        return Err(WriteError::NothingWritten);
                    } else {
                        log::trace!(
                            "Wrote {bytes_send} bytes, but socket blocked, will need try_finish_write() to finish"
                        );

                        self.last_partial_write_length += bytes_send;
                        return Err(WriteError::PartialWrite);
                    }
                }
                Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        self.last_partial_write_length = 0;
        Ok(())
    }
}

impl NetBackend for Unixstream {
    /// Try to read a frame from the proxy. If no bytes are available reports ReadError::NothingRead
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if buf.len() < VNET_HDR_LEN {
            return Err(ReadError::Internal(nix::Error::EMSGSIZE));
        }
        while self.rx_header_read < FRAME_HEADER_LEN {
            self.rx_header_read += Self::read_available(
                self.fd.as_raw_fd(),
                &mut self.rx_header[self.rx_header_read..],
            )?;
        }
        self.rx_frame_length = u32::from_be_bytes(self.rx_header) as usize;
        let hdr_len = VNET_HDR_LEN;
        if self.rx_frame_length == 0 || self.rx_frame_length > buf.len().saturating_sub(hdr_len) {
            return Err(ReadError::Internal(nix::Error::EMSGSIZE));
        }
        write_virtio_net_hdr(buf);
        // The worker retains this receive buffer across incomplete stream frames.
        while self.rx_body_read < self.rx_frame_length {
            self.rx_body_read += Self::read_available(
                self.fd.as_raw_fd(),
                &mut buf[hdr_len + self.rx_body_read..hdr_len + self.rx_frame_length],
            )?;
        }
        let frame_length = self.rx_frame_length;
        self.rx_header_read = 0;
        self.rx_frame_length = 0;
        self.rx_body_read = 0;
        log::trace!("Read eth frame from network proxy: {frame_length} bytes");
        Ok(hdr_len + frame_length)
    }

    /// Try to write a frame to the proxy.
    /// (Will mutate and override parts of buf, with a frame header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///   (such as vnet header), that can be overwritten. Must be >= FRAME_HEADER_LEN.
    /// * `buf` - the buffer to write to the proxy, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 || hdr_len < FRAME_HEADER_LEN || buf.len() <= hdr_len
        {
            return Err(WriteError::Internal(nix::Error::EINVAL));
        }
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - FRAME_HEADER_LEN..hdr_len].copy_from_slice(
            &u32::try_from(frame_length)
                .map_err(|_| WriteError::Internal(nix::Error::EMSGSIZE))?
                .to_be_bytes(),
        );

        self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN..])?;
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length != 0
    }

    /// Try to finish a partial write
    ///
    /// If no partial write is required will do nothing and return Ok(())
    ///
    /// * `hdr_len` - must be the same value as passed to write_frame, that caused the partial write
    /// * `buf` - must be same buffer that was given to write_frame, that caused the partial write
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            let already_written = self.last_partial_write_length;
            log::trace!("Requested to finish partial write");
            let start = hdr_len
                .checked_sub(FRAME_HEADER_LEN)
                .and_then(|offset| offset.checked_add(already_written))
                .ok_or(WriteError::Internal(nix::Error::EINVAL))?;
            let remaining = buf
                .get(start..)
                .ok_or(WriteError::Internal(nix::Error::EINVAL))?;
            self.write_loop(remaining)?;
            log::debug!("Finished partial write ({already_written}bytes written before)")
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::net::VNET_HDR_LEN;
    use crate::virtio::net::backend::{NetBackend, ReadError};
    use crate::virtio::net::unixstream::Unixstream;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    #[test]
    fn net_provider_cold_stream_retains_partial_header_and_body_without_waiting() {
        let (socket, mut peer) = UnixStream::pair().expect("real stream");
        let mut backend = Unixstream::new(socket.into());
        let mut frame = [0; 128];
        peer.write_all(&[0, 0]).expect("partial header");
        assert!(matches!(
            backend.read_frame(&mut frame),
            Err(ReadError::NothingRead)
        ));
        assert_eq!(backend.rx_header_read, 2);
        peer.write_all(&[0, 8, b'a', b'b'])
            .expect("header and partial body");
        assert!(matches!(
            backend.read_frame(&mut frame),
            Err(ReadError::NothingRead)
        ));
        assert_eq!(backend.rx_body_read, 2);
        peer.write_all(b"cdefgh").expect("remaining body");
        assert_eq!(
            backend.read_frame(&mut frame).expect("one complete frame"),
            VNET_HDR_LEN + 8
        );
        assert_eq!(&frame[VNET_HDR_LEN..VNET_HDR_LEN + 8], b"abcdefgh");
        assert_eq!((backend.rx_header_read, backend.rx_body_read), (0, 0));
        drop(peer);
        assert!(matches!(
            backend.read_frame(&mut frame),
            Err(ReadError::Internal(nix::Error::ECONNRESET))
        ));
    }

    #[test]
    fn net_provider_cold_stream_refuses_oversize_frame_before_body_read() {
        let (socket, mut peer) = UnixStream::pair().expect("real stream");
        let mut backend = Unixstream::new(socket.into());
        peer.write_all(&u32::MAX.to_be_bytes())
            .expect("malformed frame length");
        let mut frame = [0; 128];
        assert!(matches!(
            backend.read_frame(&mut frame),
            Err(ReadError::Internal(nix::Error::EMSGSIZE))
        ));
    }
}
