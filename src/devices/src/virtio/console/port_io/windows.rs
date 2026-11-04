use crate::virtio::{ReadView, WriteView};
use std::fs::File;
use std::io::{self, ErrorKind, IsTerminal};
use std::mem::MaybeUninit;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle, RawHandle};
use utils::eventfd::EventFd;
use utils::windows::AsRawFd;
use windows_sys::Win32::{
    Foundation::FALSE,
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        Console::{CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo},
        Threading::{INFINITE, WaitForMultipleObjects, WaitForSingleObject},
    },
};

use crate::virtio::console::port_io::{
    PortInput, PortInputEmpty, PortOutput, PortTerminalProperties,
};

pub fn input_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortInput + Send>> {
    Ok(Box::new(PortInputHandle(dup_handle(handle)?)))
}

pub fn term_handle(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortTerminalProperties + Send + Sync>> {
    assert!(
        unsafe { BorrowedHandle::borrow_raw(handle).is_terminal() },
        "Expected handle {handle:?}, to be a tty, to query the window size!"
    );
    let handle = dup_handle(handle)?;
    Ok(Box::new(PortTerminalPropertiesHandle(handle)))
}

pub fn input_empty() -> Result<Box<dyn PortInput + Send>, io::Error> {
    Ok(Box::new(PortInputEmpty {}))
}

pub fn output_file(file: File) -> Result<Box<dyn PortOutput + Send>, io::Error> {
    output_to_handle_dup(file.as_raw_handle())
}

pub fn output_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> Result<Box<dyn PortOutput + Send>, io::Error> {
    // We skip make_non_blocking() on Windows and rely on the background
    // tx_thread to safely execute a blocking write.
    let owned_handle = dup_handle(handle)?;
    Ok(Box::new(PortOutputHandle(owned_handle)))
}

struct PortInputHandle(OwnedHandle);

impl AsRawHandle for PortInputHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }
}

impl PortInput for PortInputHandle {
    fn read_volatile(&mut self, buf: WriteView<'_>) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX")
        })?;
        let mut bytes_read: u32 = 0;
        let ret = unsafe {
            ReadFile(
                self.as_raw_handle(),
                buf.as_mut_ptr(),
                len,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::BrokenPipe {
                return Ok(0);
            }
            Err(err)
        } else {
            let n = bytes_read as usize;
            Ok(n)
        }
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) -> io::Result<()> {
        let handles = [
            self.as_raw_handle(),
            stopfd.map_or(self.as_raw_handle(), AsRawFd::as_raw_fd),
        ];
        wait_for_handles(&handles)
    }
}

impl PortInput for PortInputEmpty {
    fn read_volatile(&mut self, _buf: WriteView<'_>) -> Result<usize, io::Error> {
        Ok(0)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) -> io::Result<()> {
        let stop = stopfd.ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "empty console input needs a wake endpoint",
            )
        })?;
        wait_for_handles(&[stop.as_raw_fd()])
    }
}

struct PortOutputHandle(OwnedHandle);

impl AsRawHandle for PortOutputHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }
}

impl PortOutput for PortOutputHandle {
    fn write_volatile(&mut self, buf: ReadView<'_>) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX")
        })?;
        let mut bytes_written: u32 = 0;
        let ret = unsafe {
            WriteFile(
                self.as_raw_handle(),
                buf.as_ptr(),
                len,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_written as usize)
        }
    }

    fn wait_until_writable(&self, _terminal_stopfd: &EventFd) -> io::Result<()> {
        Ok(())
    }
}

struct PortTerminalPropertiesHandle(OwnedHandle);

impl PortTerminalProperties for PortTerminalPropertiesHandle {
    fn get_win_size(&self) -> (u16, u16) {
        let mut info = MaybeUninit::<CONSOLE_SCREEN_BUFFER_INFO>::uninit();
        let ret = unsafe { GetConsoleScreenBufferInfo(self.0.as_raw_handle(), info.as_mut_ptr()) };
        if ret == 0 {
            log::error!(
                "GetConsoleScreenBufferInfo failed: {}",
                io::Error::last_os_error()
            );
            return (0, 0);
        }
        let info = unsafe { info.assume_init() };

        let cols = (info.srWindow.Right - info.srWindow.Left + 1) as u16;
        let rows = (info.srWindow.Bottom - info.srWindow.Top + 1) as u16;
        (cols, rows)
    }
}

fn dup_handle(raw: *mut core::ffi::c_void) -> Result<OwnedHandle, io::Error> {
    let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
    borrowed.try_clone_to_owned()
}

/// Block until at least one of the given Windows HANDLEs becomes signaled.
fn wait_for_handles(handles: &[*mut core::ffi::c_void]) -> io::Result<()> {
    let result = match handles {
        [handle] => unsafe { WaitForSingleObject(*handle, INFINITE) },
        _ => unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, INFINITE)
        },
    };
    if result == u32::MAX {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
