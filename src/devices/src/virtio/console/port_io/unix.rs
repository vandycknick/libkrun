use crate::virtio::{ReadView, WriteView};
use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, TIOCGWINSZ};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::ioctl_read_bad;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::unistd::{dup, isatty};
use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use utils::eventfd::{EFD_NONBLOCK, EventFd};

use crate::virtio::console::port_io::{
    PortInput, PortInputEmpty, PortOutput, PortTerminalProperties,
};

pub fn stdin() -> Result<Box<dyn PortInput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(STDIN_FILENO)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortInputFd(fd)))
}

pub fn input_to_raw_fd_dup(fd: RawFd) -> Result<Box<dyn PortInput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(fd)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortInputFd(fd)))
}

pub fn stdout() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDOUT_FILENO)
}

pub fn stderr() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDERR_FILENO)
}

pub fn term_fd(
    term_fd: RawFd,
) -> Result<Box<dyn PortTerminalProperties + Send + Sync>, nix::Error> {
    let fd = dup_raw_fd_into_owned(term_fd)?;
    if !isatty(&fd)? {
        return Err(Errno::ENOTTY);
    }
    Ok(Box::new(PortTerminalPropertiesFd(fd)))
}

pub fn input_empty() -> Result<Box<dyn PortInput + Send>, nix::Error> {
    Ok(Box::new(PortInputEmpty {}))
}

pub fn output_file(file: File) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(file.as_raw_fd())
}

pub fn output_to_raw_fd_dup(fd: RawFd) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(fd)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortOutputFd(fd)))
}

struct PortInputFd(OwnedFd);

impl AsRawFd for PortInputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl PortInput for PortInputFd {
    fn read_volatile(&mut self, buf: WriteView<'_>) -> io::Result<usize> {
        // nix requires a Rust slice, which cannot represent concurrently accessed guest RAM.
        // The write view keeps its premarked, bounded destination alive through this call.
        let bytes_read =
            unsafe { libc::read(self.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if bytes_read < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_read as usize)
        }
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) -> io::Result<()> {
        let stop = stopfd.map(|fd| unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) });
        let mut poll_fds = [
            PollFd::new(self.0.as_fd(), PollFlags::POLLIN),
            PollFd::new(
                stop.as_ref().map_or(self.0.as_fd(), AsFd::as_fd),
                PollFlags::POLLIN,
            ),
        ];
        wait_poll(&mut poll_fds)
    }
}

impl PortInput for PortInputEmpty {
    fn read_volatile(&mut self, _buf: WriteView<'_>) -> Result<usize, io::Error> {
        Ok(0)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) -> io::Result<()> {
        if let Some(stopfd) = stopfd {
            let fd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
            wait_poll(&mut [PollFd::new(fd, PollFlags::POLLIN)])
        } else {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                "empty console input needs a wake endpoint",
            ))
        }
    }
}

struct PortOutputFd(OwnedFd);

impl AsRawFd for PortOutputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl PortOutput for PortOutputFd {
    fn write_volatile(&mut self, buf: ReadView<'_>) -> Result<usize, io::Error> {
        // nix requires a Rust slice; this read-only pointer remains view-bounded.
        let written = unsafe { libc::write(self.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }

    fn wait_until_writable(&self, terminal_stopfd: &EventFd) -> io::Result<()> {
        let stop = unsafe { BorrowedFd::borrow_raw(terminal_stopfd.as_raw_fd()) };
        wait_poll(&mut [
            PollFd::new(self.0.as_fd(), PollFlags::POLLOUT),
            PollFd::new(stop, PollFlags::POLLIN),
        ])
    }
}

fn dup_raw_fd_into_owned(raw_fd: RawFd) -> Result<OwnedFd, nix::Error> {
    // SAFETY: if raw_fd is invalid the `dup` call below will fail
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    let fd = dup(borrowed_fd)?;
    Ok(fd)
}

fn make_non_blocking(fd: &impl AsFd) -> Result<(), nix::Error> {
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

struct PortTerminalPropertiesFd(OwnedFd);

impl PortTerminalProperties for PortTerminalPropertiesFd {
    fn get_win_size(&self) -> (u16, u16) {
        let mut ws: WS = WS::default();

        if let Err(err) = unsafe { tiocgwinsz(self.0.as_raw_fd(), &mut ws) } {
            log::error!("Couldn't get terminal dimensions: {err}");
            return (0, 0);
        }
        (ws.cols, ws.rows)
    }
}

pub struct PortInputSigInt {
    sigint_evt: EventFd,
}

impl PortInputSigInt {
    pub fn new() -> Self {
        PortInputSigInt {
            sigint_evt: EventFd::new(EFD_NONBLOCK)
                .expect("Failed to create EventFd for SIGINT signaling"),
        }
    }

    pub fn sigint_evt(&self) -> &EventFd {
        &self.sigint_evt
    }
}

impl Default for PortInputSigInt {
    fn default() -> Self {
        Self::new()
    }
}

impl PortInput for PortInputSigInt {
    fn read_volatile(&mut self, buf: WriteView<'_>) -> Result<usize, io::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.sigint_evt.read()?;
        log::trace!("SIGINT received");
        buf.write_slice(&[3u8], 0).map_err(io::Error::other)?;
        Ok(1)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) -> io::Result<()> {
        let sigint = unsafe { BorrowedFd::borrow_raw(self.sigint_evt.as_raw_fd()) };
        let stop = stopfd.map(|fd| unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) });
        let mut fds = [
            PollFd::new(sigint, PollFlags::POLLIN),
            PollFd::new(stop.as_ref().map_or(sigint, AsFd::as_fd), PollFlags::POLLIN),
        ];
        wait_poll(&mut fds)
    }
}

fn wait_poll(fds: &mut [PollFd<'_>]) -> io::Result<()> {
    loop {
        match poll(fds, PollTimeout::NONE) {
            Ok(_) => {
                if fds.iter().any(|fd| {
                    fd.revents()
                        .is_some_and(|events| events.contains(PollFlags::POLLNVAL))
                }) {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "invalid console endpoint",
                    ));
                }
                return Ok(());
            }
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct WS {
    rows: u16,
    cols: u16,
    xpixel: u16,
    ypixel: u16,
}

ioctl_read_bad!(tiocgwinsz, TIOCGWINSZ, WS);

#[cfg(test)]
mod tests {
    use crate::virtio::console::port_io::unix::{PortInputFd, PortOutputFd, make_non_blocking};
    use crate::virtio::console::port_io::{PortInput, PortInputSigInt, PortOutput};
    use crate::virtio::{ReadView, RuntimeGuestMemory};
    use nix::unistd::{pipe, read, write};
    use std::io::ErrorKind;
    use vm_memory::GuestAddress;

    #[test]
    fn console_port_views_real_pipe_clipping_and_backing_lifetime() {
        let (input_fd, producer) = pipe().unwrap();
        make_non_blocking(&input_fd).unwrap();
        assert_eq!(write(&producer, b"abcdef").unwrap(), 6);
        let mut input = PortInputFd(input_fd);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        memory.write_slice(&[0x77; 8], GuestAddress(0x100)).unwrap();
        let destination = memory.write(GuestAddress(0x100), 8).unwrap();
        drop(memory);
        assert_eq!(
            input
                .read_volatile(destination.write_view(0, 3).unwrap())
                .unwrap(),
            3
        );
        let mut actual = [0; 8];
        destination
            .read_view(0, 8)
            .unwrap()
            .read_slice(&mut actual, 0)
            .unwrap();
        assert_eq!(&actual[..3], b"abc");
        assert_eq!(&actual[3..], &[0x77; 5]);

        let (consumer, output_fd) = pipe().unwrap();
        let mut output = PortOutputFd(output_fd);
        assert_eq!(
            output
                .write_volatile(destination.read_view(0, 3).unwrap())
                .unwrap(),
            3
        );
        let mut copied = [0; 8];
        assert_eq!(read(&consumer, &mut copied).unwrap(), 3);
        assert_eq!(&copied[..3], b"abc");
        assert_eq!(
            output
                .write_volatile(ReadView::from_slice(b"host"))
                .unwrap(),
            4
        );
        assert_eq!(read(&consumer, &mut copied).unwrap(), 4);
        assert_eq!(&copied[..4], b"host");

        assert_eq!(
            input
                .read_volatile(destination.write_view(3, 5).unwrap())
                .unwrap(),
            3
        );
        assert_eq!(
            input
                .read_volatile(destination.write_view(6, 2).unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::WouldBlock
        );
        destination
            .read_view(0, 8)
            .unwrap()
            .read_slice(&mut actual, 0)
            .unwrap();
        assert_eq!(&actual[..6], b"abcdef");
        assert_eq!(&actual[6..], &[0x77; 2]);
    }

    #[test]
    fn console_port_views_empty_ctrl_c_does_not_consume_signal() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        let guard = memory.write(GuestAddress(0x100), 1).unwrap();
        let mut input = PortInputSigInt::new();
        input.sigint_evt().write(1).unwrap();
        assert_eq!(
            input
                .read_volatile(guard.write_view(0, 0).unwrap())
                .unwrap(),
            0
        );
        assert_eq!(
            input
                .read_volatile(guard.write_view(0, 1).unwrap())
                .unwrap(),
            1
        );
        assert_eq!(guard.read_view(0, 1).unwrap().read_obj::<u8>(0).unwrap(), 3);
    }
}
