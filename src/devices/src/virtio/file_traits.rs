// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::AsRawFd;

#[cfg(feature = "blk")]
use imago::io_buffers::{IoVector, IoVectorMut};

use crate::virtio::bindings::{off64_t, pread64, preadv64, pwrite64, pwritev64};
#[cfg(feature = "blk")]
use crate::virtio::block::device::DiskProperties;
use crate::virtio::{ReadView, WriteView};

const IO_BATCH_SIZE: usize = 64;

pub trait FileSetLen {
    fn set_len(&self, len: u64) -> Result<()>;
}

impl FileSetLen for File {
    fn set_len(&self, len: u64) -> Result<()> {
        File::set_len(self, len)
    }
}

fn check_completion(completed: usize, supplied: usize) -> Result<usize> {
    if completed > supplied {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "I/O completion exceeds supplied memory",
        ));
    }
    Ok(completed)
}

fn checked_offset(offset: u64, count: usize) -> Result<u64> {
    offset
        .checked_add(count as u64)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "file offset overflow"))
}

/// File reads mutate guest destinations; file writes only borrow guest sources.
///
/// A guest source cannot be supplied to a syscall destination:
/// ```compile_fail
/// use krun_devices::virtio::{ReadView, file_traits::FileReadWriteVolatile};
/// fn receive(file: &mut std::fs::File, source: ReadView<'_>) {
///     file.read_volatile(source);
/// }
/// ```
///
/// Writable views cannot escape their owning obligation:
/// ```compile_fail
/// use krun_devices::virtio::{HostWriteGuard, WriteView};
/// fn escape(guard: HostWriteGuard) -> WriteView<'static> {
///     guard.write_view(0, guard.len()).unwrap()
/// }
/// ```
pub trait FileReadWriteVolatile {
    fn read_volatile(&mut self, destination: WriteView<'_>) -> Result<usize>;

    fn read_vectored_volatile(&mut self, destinations: &[WriteView<'_>]) -> Result<usize> {
        match destinations.iter().find(|view| !view.is_empty()) {
            Some(view) => self
                .read_volatile(*view)
                .and_then(|n| check_completion(n, view.len())),
            None => Ok(0),
        }
    }

    fn read_exact_volatile(&mut self, mut destination: WriteView<'_>) -> Result<()> {
        while !destination.is_empty() {
            match self.read_volatile(destination) {
                Ok(0) => return Err(Error::from(ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    check_completion(n, destination.len())?;
                    destination = destination
                        .subslice(n, destination.len() - n)
                        .map_err(Error::other)?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn write_volatile(&mut self, source: ReadView<'_>) -> Result<usize>;

    fn write_vectored_volatile(&mut self, sources: &[ReadView<'_>]) -> Result<usize> {
        match sources.iter().find(|view| !view.is_empty()) {
            Some(view) => self
                .write_volatile(*view)
                .and_then(|n| check_completion(n, view.len())),
            None => Ok(0),
        }
    }

    fn write_all_volatile(&mut self, mut source: ReadView<'_>) -> Result<()> {
        while !source.is_empty() {
            match self.write_volatile(source) {
                Ok(0) => return Err(Error::from(ErrorKind::WriteZero)),
                Ok(n) => {
                    check_completion(n, source.len())?;
                    source = source.subslice(n, source.len() - n).map_err(Error::other)?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl<T: FileReadWriteVolatile + ?Sized> FileReadWriteVolatile for &mut T {
    fn read_volatile(&mut self, destination: WriteView<'_>) -> Result<usize> {
        (**self).read_volatile(destination)
    }

    fn read_vectored_volatile(&mut self, destinations: &[WriteView<'_>]) -> Result<usize> {
        (**self).read_vectored_volatile(destinations)
    }

    fn read_exact_volatile(&mut self, destination: WriteView<'_>) -> Result<()> {
        (**self).read_exact_volatile(destination)
    }

    fn write_volatile(&mut self, source: ReadView<'_>) -> Result<usize> {
        (**self).write_volatile(source)
    }

    fn write_vectored_volatile(&mut self, sources: &[ReadView<'_>]) -> Result<usize> {
        (**self).write_vectored_volatile(sources)
    }

    fn write_all_volatile(&mut self, source: ReadView<'_>) -> Result<()> {
        (**self).write_all_volatile(source)
    }
}

pub trait FileReadWriteAtVolatile {
    fn read_at_volatile(&self, destination: WriteView<'_>, offset: u64) -> Result<usize>;

    fn read_vectored_at_volatile(
        &self,
        destinations: &[WriteView<'_>],
        offset: u64,
    ) -> Result<usize> {
        match destinations.iter().find(|view| !view.is_empty()) {
            Some(view) => self
                .read_at_volatile(*view, offset)
                .and_then(|n| check_completion(n, view.len())),
            None => Ok(0),
        }
    }

    fn read_exact_at_volatile(
        &self,
        mut destination: WriteView<'_>,
        mut offset: u64,
    ) -> Result<()> {
        while !destination.is_empty() {
            match self.read_at_volatile(destination, offset) {
                Ok(0) => return Err(Error::from(ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    check_completion(n, destination.len())?;
                    destination = destination
                        .subslice(n, destination.len() - n)
                        .map_err(Error::other)?;
                    offset = checked_offset(offset, n)?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn write_at_volatile(&self, source: ReadView<'_>, offset: u64) -> Result<usize>;

    fn write_vectored_at_volatile(&self, sources: &[ReadView<'_>], offset: u64) -> Result<usize> {
        match sources.iter().find(|view| !view.is_empty()) {
            Some(view) => self
                .write_at_volatile(*view, offset)
                .and_then(|n| check_completion(n, view.len())),
            None => Ok(0),
        }
    }

    fn write_all_at_volatile(&self, mut source: ReadView<'_>, mut offset: u64) -> Result<()> {
        while !source.is_empty() {
            match self.write_at_volatile(source, offset) {
                Ok(0) => return Err(Error::from(ErrorKind::WriteZero)),
                Ok(n) => {
                    check_completion(n, source.len())?;
                    source = source.subslice(n, source.len() - n).map_err(Error::other)?;
                    offset = checked_offset(offset, n)?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl<T: FileReadWriteAtVolatile + ?Sized> FileReadWriteAtVolatile for &T {
    fn read_at_volatile(&self, destination: WriteView<'_>, offset: u64) -> Result<usize> {
        (**self).read_at_volatile(destination, offset)
    }

    fn read_vectored_at_volatile(
        &self,
        destinations: &[WriteView<'_>],
        offset: u64,
    ) -> Result<usize> {
        (**self).read_vectored_at_volatile(destinations, offset)
    }

    fn read_exact_at_volatile(&self, destination: WriteView<'_>, offset: u64) -> Result<()> {
        (**self).read_exact_at_volatile(destination, offset)
    }

    fn write_at_volatile(&self, source: ReadView<'_>, offset: u64) -> Result<usize> {
        (**self).write_at_volatile(source, offset)
    }

    fn write_vectored_at_volatile(&self, sources: &[ReadView<'_>], offset: u64) -> Result<usize> {
        (**self).write_vectored_at_volatile(sources, offset)
    }

    fn write_all_at_volatile(&self, source: ReadView<'_>, offset: u64) -> Result<()> {
        (**self).write_all_at_volatile(source, offset)
    }
}

fn native_offset(offset: u64) -> Result<off64_t> {
    offset
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "file offset exceeds native range"))
}

fn syscall_result(result: isize, supplied: usize) -> Result<usize> {
    if result < 0 {
        Err(Error::last_os_error())
    } else {
        check_completion(result as usize, supplied)
    }
}

// nix's I/O interfaces require Rust slices. Guest RAM must remain volatile, so
// these narrowly bounded adapters pass raw pointers instead of inventing &mut [u8].
impl FileReadWriteVolatile for File {
    fn read_volatile(&mut self, destination: WriteView<'_>) -> Result<usize> {
        let result = unsafe {
            libc::read(
                self.as_raw_fd(),
                destination.as_mut_ptr().cast(),
                destination.len(),
            )
        };
        syscall_result(result, destination.len())
    }

    fn read_vectored_volatile(&mut self, destinations: &[WriteView<'_>]) -> Result<usize> {
        destination_iovecs(destinations, |iovecs, supplied| {
            let result = unsafe {
                libc::readv(
                    self.as_raw_fd(),
                    iovecs.as_ptr(),
                    iovecs.len() as libc::c_int,
                )
            };
            syscall_result(result, supplied)
        })
    }

    fn write_volatile(&mut self, source: ReadView<'_>) -> Result<usize> {
        let result = unsafe { libc::write(self.as_raw_fd(), source.as_ptr().cast(), source.len()) };
        syscall_result(result, source.len())
    }

    fn write_vectored_volatile(&mut self, sources: &[ReadView<'_>]) -> Result<usize> {
        source_iovecs(sources, |iovecs, supplied| {
            let result = unsafe {
                libc::writev(
                    self.as_raw_fd(),
                    iovecs.as_ptr(),
                    iovecs.len() as libc::c_int,
                )
            };
            syscall_result(result, supplied)
        })
    }
}

impl FileReadWriteAtVolatile for File {
    fn read_at_volatile(&self, destination: WriteView<'_>, offset: u64) -> Result<usize> {
        let offset = native_offset(offset)?;
        let result = unsafe {
            pread64(
                self.as_raw_fd(),
                destination.as_mut_ptr().cast(),
                destination.len(),
                offset,
            )
        };
        syscall_result(result, destination.len())
    }

    fn read_vectored_at_volatile(
        &self,
        destinations: &[WriteView<'_>],
        offset: u64,
    ) -> Result<usize> {
        let offset = native_offset(offset)?;
        destination_iovecs(destinations, |iovecs, supplied| {
            let result = unsafe {
                preadv64(
                    self.as_raw_fd(),
                    iovecs.as_ptr(),
                    iovecs.len() as libc::c_int,
                    offset,
                )
            };
            syscall_result(result, supplied)
        })
    }

    fn write_at_volatile(&self, source: ReadView<'_>, offset: u64) -> Result<usize> {
        let offset = native_offset(offset)?;
        let result = unsafe {
            pwrite64(
                self.as_raw_fd(),
                source.as_ptr().cast(),
                source.len(),
                offset,
            )
        };
        syscall_result(result, source.len())
    }

    fn write_vectored_at_volatile(&self, sources: &[ReadView<'_>], offset: u64) -> Result<usize> {
        let offset = native_offset(offset)?;
        source_iovecs(sources, |iovecs, supplied| {
            let result = unsafe {
                pwritev64(
                    self.as_raw_fd(),
                    iovecs.as_ptr(),
                    iovecs.len() as libc::c_int,
                    offset,
                )
            };
            syscall_result(result, supplied)
        })
    }
}

fn destination_iovecs(
    destinations: &[WriteView<'_>],
    call: impl FnOnce(&[libc::iovec], usize) -> Result<usize>,
) -> Result<usize> {
    let mut scratch = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; IO_BATCH_SIZE];
    let count = destinations.len().min(IO_BATCH_SIZE);
    let mut supplied = 0_usize;
    for (slot, view) in scratch.iter_mut().zip(destinations).take(count) {
        *slot = libc::iovec {
            iov_base: view.as_mut_ptr().cast(),
            iov_len: view.len(),
        };
        supplied = supplied
            .checked_add(view.len())
            .ok_or_else(|| Error::from(ErrorKind::InvalidInput))?;
    }
    if count == 0 {
        Ok(0)
    } else {
        call(&scratch[..count], supplied)
    }
}

fn source_iovecs(
    sources: &[ReadView<'_>],
    call: impl FnOnce(&[libc::iovec], usize) -> Result<usize>,
) -> Result<usize> {
    let mut scratch = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; IO_BATCH_SIZE];
    let count = sources.len().min(IO_BATCH_SIZE);
    let mut supplied = 0_usize;
    for (slot, view) in scratch.iter_mut().zip(sources).take(count) {
        // iovec uses a mutable pointer even for writev's read-only sources.
        *slot = libc::iovec {
            iov_base: view.as_ptr().cast_mut().cast(),
            iov_len: view.len(),
        };
        supplied = supplied
            .checked_add(view.len())
            .ok_or_else(|| Error::from(ErrorKind::InvalidInput))?;
    }
    if count == 0 {
        Ok(0)
    } else {
        call(&scratch[..count], supplied)
    }
}

#[cfg(feature = "blk")]
impl FileReadWriteAtVolatile for DiskProperties {
    fn read_at_volatile(&self, destination: WriteView<'_>, offset: u64) -> Result<usize> {
        self.read_vectored_at_volatile(&[destination], offset)
    }

    fn read_vectored_at_volatile(
        &self,
        destinations: &[WriteView<'_>],
        offset: u64,
    ) -> Result<usize> {
        let mut scratch = [const { std::mem::MaybeUninit::<vm_memory::VolatileSlice<'_>>::uninit() };
            IO_BATCH_SIZE];
        let count = destinations.len().min(IO_BATCH_SIZE);
        if count == 0 {
            return Ok(0);
        }
        for (slot, view) in scratch.iter_mut().zip(destinations).take(count) {
            // Private imago adapter only: destination guards are marked and stay alive
            // throughout readv, including backend errors. No mutable Rust slice escapes.
            slot.write(unsafe { vm_memory::VolatileSlice::new(view.as_mut_ptr(), view.len()) });
        }
        let slices = unsafe {
            std::slice::from_raw_parts(
                scratch.as_ptr().cast::<vm_memory::VolatileSlice<'_>>(),
                count,
            )
        };
        let (iovec, pointer_guards) = IoVectorMut::from_volatile_slice(slices);
        let length = iovec
            .len()
            .try_into()
            .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
        let result = self
            .file
            .lock()
            .map_err(|_| Error::other("block backend lock poisoned"))?
            .readv(iovec, offset);
        drop(pointer_guards);
        result?;
        Ok(length)
    }

    fn write_at_volatile(&self, source: ReadView<'_>, offset: u64) -> Result<usize> {
        self.write_vectored_at_volatile(&[source], offset)
    }

    fn write_vectored_at_volatile(&self, sources: &[ReadView<'_>], offset: u64) -> Result<usize> {
        let mut scratch = [const { std::mem::MaybeUninit::<vm_memory::VolatileSlice<'_>>::uninit() };
            IO_BATCH_SIZE];
        let count = sources.len().min(IO_BATCH_SIZE);
        if count == 0 {
            return Ok(0);
        }
        for (slot, view) in scratch.iter_mut().zip(sources).take(count) {
            // imago's source adapter only takes const pointer guards. Its legacy
            // VolatileSlice representation is confined here, never returned to callers.
            slot.write(unsafe {
                vm_memory::VolatileSlice::new(view.as_ptr().cast_mut(), view.len())
            });
        }
        let slices = unsafe {
            std::slice::from_raw_parts(
                scratch.as_ptr().cast::<vm_memory::VolatileSlice<'_>>(),
                count,
            )
        };
        let (iovec, pointer_guards) = IoVector::from_volatile_slice(slices);
        let length = iovec
            .len()
            .try_into()
            .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
        let result = self
            .file
            .lock()
            .map_err(|_| Error::other("block backend lock poisoned"))?
            .writev(iovec, offset);
        drop(pointer_guards);
        result?;
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::file_traits::{FileReadWriteAtVolatile, FileReadWriteVolatile};
    use crate::virtio::{ReadView, RuntimeGuestMemory};
    use std::fs::{File, OpenOptions};
    use std::io::ErrorKind;
    use std::os::unix::fs::FileExt;
    use utils::tempfile::TempFile;
    use vm_memory::GuestAddress;

    #[test]
    fn file_views_exact_read_eof_keeps_written_prefix_and_guard_ownership() {
        let file = TempFile::new().unwrap();
        file.as_file().write_all_at(b"short", 0).unwrap();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        memory.write_slice(&[0x77; 8], GuestAddress(0x100)).unwrap();
        let guard = memory.write(GuestAddress(0x100), 8).unwrap();
        drop(memory);
        let error = file
            .as_file()
            .read_exact_at_volatile(guard.write_view(0, 8).unwrap(), 0)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        let mut actual = [0; 8];
        guard
            .read_view(0, 8)
            .unwrap()
            .read_slice(&mut actual, 0)
            .unwrap();
        assert_eq!(&actual[..5], b"short");
        assert_eq!(&actual[5..], &[0x77; 3]);
    }

    #[test]
    fn file_views_zero_length_and_native_offset_boundaries() {
        let file = TempFile::new().unwrap();
        let mut output = file.as_file().try_clone().unwrap();
        assert_eq!(output.write_volatile(ReadView::from_slice(&[])).unwrap(), 0);
        assert_eq!(
            file.as_file().write_vectored_at_volatile(&[], 0).unwrap(),
            0
        );
        let error = file
            .as_file()
            .write_at_volatile(ReadView::from_slice(b"x"), u64::MAX)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(file.as_file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn file_views_real_access_mode_errors_leave_destination_owned() {
        let file = TempFile::new().unwrap();
        file.as_file().write_all_at(b"source", 0).unwrap();
        let mut read_only = File::open(file.as_path()).unwrap();
        let mut write_only = OpenOptions::new().write(true).open(file.as_path()).unwrap();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        memory
            .write_slice(b"unchanged", GuestAddress(0x100))
            .unwrap();
        let guard = memory.write(GuestAddress(0x100), 9).unwrap();
        assert_eq!(
            write_only
                .read_volatile(guard.write_view(0, 9).unwrap())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(
            read_only
                .write_volatile(ReadView::from_slice(b"bad"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
        let mut actual = [0; 9];
        guard
            .read_view(0, 9)
            .unwrap()
            .read_slice(&mut actual, 0)
            .unwrap();
        assert_eq!(&actual, b"unchanged");
        assert_eq!(
            file.as_file()
                .read_at_volatile(guard.write_view(0, 3).unwrap(), 0)
                .unwrap(),
            3
        );
        guard
            .read_view(0, 9)
            .unwrap()
            .read_slice(&mut actual, 0)
            .unwrap();
        assert_eq!(&actual, b"souhanged");
    }
}
