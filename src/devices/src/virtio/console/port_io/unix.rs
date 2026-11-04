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
use vm_memory::bitmap::Bitmap;
use vm_memory::{VolatileMemoryError, VolatileSlice, WriteVolatile};

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
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        // nix::read requires a Rust byte slice; guest memory is volatile and
        // cannot be reborrowed as an ordinary mutable slice.

        let fd = self.as_raw_fd();
        let guard = buf.ptr_guard_mut();

        let dst = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
        // valid for writes of length `buf.len() by the invariants upheld by the constructor
        // of `VolatileSlice`.
        let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

        if bytes_read < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::WouldBlock {
                // We don't know if a partial read might have happened, so mark everything as dirty
                buf.bitmap().mark_dirty(0, buf.len());
            }

            Err(err)
        } else {
            let bytes_read = bytes_read as usize;
            buf.bitmap().mark_dirty(0, bytes_read);
            Ok(bytes_read)
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
    fn read_volatile(&mut self, _buf: &mut VolatileSlice) -> Result<usize, io::Error> {
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
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.0.write_volatile(buf).map_err(|e| match e {
            VolatileMemoryError::IOError(e) => e,
            e => {
                log::error!("Unsuported error from write_volatile: {e:?}");
                io::Error::other(e)
            }
        })
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
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        self.sigint_evt.read()?;
        log::trace!("SIGINT received");
        buf.copy_from(&[3u8]); //ASCII 'ETX' -> generates SIGINIT in a terminal
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
