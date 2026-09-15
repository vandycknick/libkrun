// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use arch::guest_memory::{GuestRange, HostMemoryAccess, HostMemoryLease};
use vm_memory::{
    Address, AtomicAccess, ByteValued, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryError,
    GuestMemoryMmap, GuestMemoryRegion, VolatileMemoryError, VolatileSlice,
};

#[derive(Clone)]
pub struct RuntimeGuestMemory {
    memory: GuestMemoryMmap,
    access: Option<Arc<dyn HostMemoryAccess>>,
}

impl RuntimeGuestMemory {
    #[cfg(test)]
    pub fn from_ranges(
        ranges: &[(GuestAddress, usize)],
    ) -> Result<Self, vm_memory::mmap::FromRangesError> {
        GuestMemoryMmap::from_ranges(ranges).map(Self::passthrough)
    }

    pub fn new(memory: GuestMemoryMmap, access: Arc<dyn HostMemoryAccess>) -> Self {
        Self {
            memory,
            access: Some(access),
        }
    }

    pub fn passthrough(memory: GuestMemoryMmap) -> Self {
        Self {
            memory,
            access: None,
        }
    }

    fn lease(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<Option<Arc<dyn HostMemoryLease>>, GuestMemoryError> {
        if len == 0 {
            return Ok(None);
        }
        let Some(access) = &self.access else {
            return Ok(None);
        };
        let len = u64::try_from(len).map_err(|_| GuestMemoryError::InvalidBackendAddress)?;
        let range = GuestRange::new(address.raw_value(), len).map_err(|error| {
            GuestMemoryError::IOError(io::Error::new(io::ErrorKind::InvalidInput, error))
        })?;
        Arc::clone(access)
            .access(range)
            .map(Some)
            .map_err(|error| GuestMemoryError::IOError(io::Error::other(error)))
    }

    pub fn allows_external_mapping(&self) -> bool {
        self.access
            .as_ref()
            .is_none_or(|access| access.allows_external_mapping())
    }

    #[cfg(feature = "vhost-user")]
    pub(crate) fn with_external_mapping<T>(
        &self,
        operation: impl for<'a> FnOnce(&'a GuestMemoryMmap) -> T,
    ) -> Result<T, GuestMemoryError> {
        if !self.allows_external_mapping() {
            return Err(GuestMemoryError::IOError(io::Error::new(
                io::ErrorKind::Unsupported,
                "reclaimable guest RAM cannot be exported as a long-lived mapping",
            )));
        }
        Ok(operation(&self.memory))
    }

    #[cfg(feature = "vhost-user")]
    pub(crate) fn external_host_address(
        &self,
        address: GuestAddress,
    ) -> Result<*mut u8, GuestMemoryError> {
        self.with_external_mapping(|memory| memory.get_host_address(address))?
    }

    pub fn checked_offset(&self, base: GuestAddress, offset: usize) -> Option<GuestAddress> {
        self.memory.checked_offset(base, offset)
    }

    pub fn address_in_range(&self, address: GuestAddress) -> bool {
        self.memory.address_in_range(address)
    }

    pub fn read_obj<T: ByteValued>(&self, address: GuestAddress) -> Result<T, GuestMemoryError> {
        let _lease = self.lease(address, size_of::<T>())?;
        self.memory.read_obj(address)
    }

    pub fn write_obj<T: ByteValued>(
        &self,
        value: T,
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        let _lease = self.lease(address, size_of::<T>())?;
        self.memory.write_obj(value, address)
    }

    pub fn read_slice(
        &self,
        buffer: &mut [u8],
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        let _lease = self.lease(address, buffer.len())?;
        self.memory.read_slice(buffer, address)
    }

    pub fn write_slice(
        &self,
        buffer: &[u8],
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        let _lease = self.lease(address, buffer.len())?;
        self.memory.write_slice(buffer, address)
    }

    pub fn load<T: AtomicAccess>(
        &self,
        address: GuestAddress,
        order: Ordering,
    ) -> Result<T, GuestMemoryError> {
        let _lease = self.lease(address, size_of::<T>())?;
        self.memory.load(address, order)
    }

    pub fn store<T: AtomicAccess>(
        &self,
        value: T,
        address: GuestAddress,
        order: Ordering,
    ) -> Result<(), GuestMemoryError> {
        let _lease = self.lease(address, size_of::<T>())?;
        self.memory.store(value, address, order)
    }

    pub fn get_slice(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<LeasedVolatileSlice<'_>, GuestMemoryError> {
        let lease = self.lease(address, len)?;
        let slice = self.memory.get_slice(address, len)?;
        Ok(LeasedVolatileSlice { slice, lease })
    }

    pub fn get_host_address(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<LeasedHostAddress, GuestMemoryError> {
        let lease = self.lease(address, len)?;
        let pointer = if len == 0 {
            self.memory.get_host_address(address)?
        } else {
            self.memory
                .get_slice(address, len)?
                .ptr_guard_mut()
                .as_ptr()
        };
        Ok(LeasedHostAddress {
            pointer,
            lease,
            _memory: self.memory.clone(),
        })
    }

    pub fn try_access<F>(
        &self,
        count: usize,
        address: GuestAddress,
        mut callback: F,
    ) -> Result<usize, GuestMemoryError>
    where
        F: for<'a> FnMut(usize, usize, usize, VolatileSlice<'a>) -> Result<usize, GuestMemoryError>,
    {
        let mut completed = 0;
        while completed < count {
            let current = address
                .checked_add(completed as u64)
                .ok_or(GuestMemoryError::InvalidBackendAddress)?;
            let region = self
                .memory
                .find_region(current)
                .ok_or(GuestMemoryError::InvalidGuestAddress(current))?;
            let region_offset = current.raw_value() - region.start_addr().raw_value();
            let len = (count - completed).min((region.len() - region_offset) as usize);
            let leased = self.get_slice(current, len)?;
            let done = callback(completed, len, region_offset as usize, leased.slice)?;
            if done == 0 {
                break;
            }
            if done > len {
                return Err(GuestMemoryError::IOError(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest memory callback exceeded its leased range",
                )));
            }
            completed = completed
                .checked_add(done)
                .ok_or(GuestMemoryError::InvalidBackendAddress)?;
        }
        Ok(completed)
    }
}

impl From<GuestMemoryMmap> for RuntimeGuestMemory {
    fn from(memory: GuestMemoryMmap) -> Self {
        Self::passthrough(memory)
    }
}

#[derive(Clone)]
pub struct LeasedVolatileSlice<'a> {
    slice: VolatileSlice<'a>,
    lease: Option<Arc<dyn HostMemoryLease>>,
}

impl<'a> LeasedVolatileSlice<'a> {
    /// Reborrows this slice without allowing safe code to outlive its lease guard.
    ///
    /// ```compile_fail
    /// use krun_devices::virtio::LeasedVolatileSlice;
    /// use vm_memory::VolatileSlice;
    ///
    /// fn detach<'backing>(guard: &LeasedVolatileSlice<'backing>) -> VolatileSlice<'backing> {
    ///     guard.slice()
    /// }
    /// ```
    pub fn slice(&self) -> VolatileSlice<'_> {
        self.slice
    }

    pub fn offset(&self, count: usize) -> Result<Self, VolatileMemoryError> {
        Ok(Self {
            slice: self.slice.offset(count)?,
            lease: self.lease.clone(),
        })
    }

    pub fn len(&self) -> usize {
        self.slice.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }

    pub fn lease(&self) -> Option<Arc<dyn HostMemoryLease>> {
        self.lease.clone()
    }
}

pub struct LeasedHostAddress {
    pointer: *mut u8,
    lease: Option<Arc<dyn HostMemoryLease>>,
    _memory: GuestMemoryMmap,
}

unsafe impl Send for LeasedHostAddress {}
unsafe impl Sync for LeasedHostAddress {}

impl LeasedHostAddress {
    /// Returns the guest-memory pointer protected by this guard.
    ///
    /// Dereferencing the pointer remains unsafe. The pointer must not be used
    /// after this guard and all clones of its lease have been dropped.
    pub fn as_ptr(&self) -> *mut u8 {
        self.pointer
    }

    pub fn lease(&self) -> Option<Arc<dyn HostMemoryLease>> {
        self.lease.clone()
    }
}

use std::mem::size_of;

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::sync_channel;

    use arch::guest_memory::{
        GuestRange, HostMemoryAccess, HostMemoryAccessError, HostMemoryLease,
    };
    use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

    use crate::virtio::RuntimeGuestMemory;
    use crate::virtio::descriptor_utils::{
        DescriptorType, Reader, Writer, create_descriptor_chain,
    };
    use crate::virtio::vsock::packet::{VSOCK_PKT_HDR_SIZE, VsockPacket};

    struct CountingAccess {
        active: Arc<AtomicUsize>,
        peak: AtomicUsize,
        limit: usize,
    }

    struct CountingLease(Arc<AtomicUsize>);

    impl Drop for CountingLease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    impl HostMemoryLease for CountingLease {}

    impl HostMemoryAccess for CountingAccess {
        fn access(
            self: Arc<Self>,
            _range: GuestRange,
        ) -> Result<Arc<dyn HostMemoryLease>, HostMemoryAccessError> {
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            if active > self.limit {
                self.active.fetch_sub(1, Ordering::AcqRel);
                return Err(HostMemoryAccessError::new("lease capacity exhausted"));
            }
            self.peak.fetch_max(active, Ordering::AcqRel);
            Ok(Arc::new(CountingLease(Arc::clone(&self.active))))
        }

        fn allows_external_mapping(&self) -> bool {
            false
        }
    }

    fn memory(limit: usize) -> (RuntimeGuestMemory, Arc<CountingAccess>) {
        let access = Arc::new(CountingAccess {
            active: Arc::new(AtomicUsize::new(0)),
            peak: AtomicUsize::new(0),
            limit,
        });
        let provider: Arc<dyn HostMemoryAccess> = access.clone();
        let memory = RuntimeGuestMemory::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap(),
            provider,
        );
        (memory, access)
    }

    fn temporary_file() -> File {
        let path = std::env::temp_dir().join(format!(
            "libkrun-runtime-memory-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file
    }

    #[test]
    fn raw_and_volatile_views_retain_leases_until_last_guard_drops() {
        let (memory, access) = memory(4);
        let raw = memory.get_host_address(GuestAddress(0x1000), 8).unwrap();
        assert_eq!(access.active.load(Ordering::Acquire), 1);
        unsafe { raw.as_ptr().write(0x5a) };

        let volatile = memory.get_slice(GuestAddress(0x2000), 8).unwrap();
        let clone = volatile.clone();
        let subslice = clone.offset(4).unwrap();
        subslice.slice().write_slice(&[1, 2, 3, 4], 0).unwrap();
        assert_eq!(access.active.load(Ordering::Acquire), 2);
        drop(volatile);
        assert_eq!(access.active.load(Ordering::Acquire), 2);
        drop(clone);
        assert_eq!(access.active.load(Ordering::Acquire), 2);
        drop(subslice);
        drop(raw);
        assert_eq!(access.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn zero_length_operations_preserve_memory_behavior_without_leases() {
        let (memory, access) = memory(0);
        let address = GuestAddress(0x1000);

        memory.read_slice(&mut [], address).unwrap();
        memory.write_slice(&[], address).unwrap();
        assert!(memory.get_slice(address, 0).unwrap().is_empty());
        let raw = memory.get_host_address(address, 0).unwrap();
        assert_eq!(
            raw.as_ptr(),
            memory.memory.get_host_address(address).unwrap()
        );
        let mut called = false;
        assert_eq!(
            memory
                .try_access(0, address, |_, _, _, _| {
                    called = true;
                    Ok(0)
                })
                .unwrap(),
            0
        );
        assert!(!called);
        assert_eq!(access.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn empty_descriptor_consumers_and_vsock_rx_do_not_lease_empty_ranges() {
        let (memory, access) = memory(2);
        let reader_chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            GuestAddress(0x1000),
            vec![(DescriptorType::Readable, 0)],
            0,
        )
        .unwrap();
        let mut reader = Reader::new(&memory, reader_chain).unwrap();
        assert_eq!(reader.available_bytes(), 0);
        assert_eq!(reader.read(&mut []).unwrap(), 0);

        let writer_chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x100),
            GuestAddress(0x2000),
            vec![(DescriptorType::Writable, 0)],
            0,
        )
        .unwrap();
        let mut writer = Writer::new(&memory, writer_chain).unwrap();
        assert_eq!(writer.available_bytes(), 0);
        assert_eq!(writer.write(&[]).unwrap(), 0);
        assert_eq!(access.active.load(Ordering::Acquire), 0);

        let packet_chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x200),
            GuestAddress(0x3000),
            vec![
                (DescriptorType::Writable, VSOCK_PKT_HDR_SIZE as u32),
                (DescriptorType::Writable, 0),
            ],
            0,
        )
        .unwrap();
        let packet = VsockPacket::from_rx_virtq_head(&packet_chain).unwrap();
        assert!(packet.buf().unwrap().is_empty());
        assert_eq!(access.active.load(Ordering::Acquire), 1);
        drop(packet);
        assert_eq!(access.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn raw_buffer_lease_survives_async_real_socket_operation() {
        let (memory, access) = memory(2);
        memory.write_slice(b"async", GuestAddress(0x1000)).unwrap();
        let buffer = memory.get_host_address(GuestAddress(0x1000), 5).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let (ready_sender, ready_receiver) = sync_channel(0);
        let (go_sender, go_receiver) = sync_channel(0);
        let worker = std::thread::spawn(move || {
            ready_sender.send(()).unwrap();
            go_receiver.recv().unwrap();
            let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), 5) };
            sender.write_all(bytes).unwrap();
        });

        ready_receiver.recv().unwrap();
        assert_eq!(access.active.load(Ordering::Acquire), 1);
        go_sender.send(()).unwrap();
        let mut received = [0; 5];
        receiver.read_exact(&mut received).unwrap();
        worker.join().unwrap();
        assert_eq!(&received, b"async");
        assert_eq!(access.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn synchronous_access_releases_before_return_and_capacity_is_bounded() {
        let (memory, access) = memory(1);
        memory
            .write_slice(&[1, 2, 3], GuestAddress(0x1000))
            .unwrap();
        assert_eq!(access.active.load(Ordering::Acquire), 0);

        let first = memory.get_slice(GuestAddress(0x1000), 8).unwrap();
        assert!(memory.get_slice(GuestAddress(0x2000), 8).is_err());
        drop(first);
        assert!(memory.get_slice(GuestAddress(0x2000), 8).is_ok());
        assert_eq!(access.peak.load(Ordering::Acquire), 1);
    }

    #[test]
    fn descriptor_reader_keeps_lease_during_real_file_io_and_cancel_cleans_up() {
        let (memory, access) = memory(16);
        memory.write_slice(b"socket", GuestAddress(0x1000)).unwrap();
        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            GuestAddress(0x1000),
            vec![(DescriptorType::Readable, 6)],
            0,
        )
        .unwrap();
        let mut reader = Reader::new(&memory, chain).unwrap();
        assert!(access.active.load(Ordering::Acquire) > 0);

        let mut file = temporary_file();
        reader.read_to(&mut file, 6).unwrap();
        file.rewind().unwrap();
        let mut received = [0; 6];
        file.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"socket");
        assert_eq!(access.active.load(Ordering::Acquire), 0);
        drop(reader);
        assert_eq!(access.active.load(Ordering::Acquire), 0);

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            GuestAddress(0x2000),
            vec![(DescriptorType::Readable, 8)],
            0,
        )
        .unwrap();
        let reader = Reader::new(&memory, chain).unwrap();
        drop(reader);
        assert_eq!(access.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn descriptor_writer_keeps_lease_during_real_file_io_and_error_cleanup() {
        let (memory, access) = memory(16);
        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            GuestAddress(0x3000),
            vec![(DescriptorType::Writable, 4)],
            0,
        )
        .unwrap();
        let mut writer = Writer::new(&memory, chain).unwrap();
        assert!(access.active.load(Ordering::Acquire) > 0);

        let mut file = temporary_file();
        file.write_all(b"file").unwrap();
        writer.write_from_at(&file, 4, 0).unwrap();
        assert_eq!(access.active.load(Ordering::Acquire), 0);
        drop(writer);
        assert_eq!(access.active.load(Ordering::Acquire), 0);

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            GuestAddress(0x4000),
            vec![(DescriptorType::Writable, 4)],
            0,
        )
        .unwrap();
        let mut writer = Writer::new(&memory, chain).unwrap();
        let path = std::env::temp_dir().join(format!(
            "libkrun-runtime-memory-write-only-{}",
            std::process::id()
        ));
        let write_only = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(writer.write_from_at(&write_only, 4, 0).is_err());
        assert!(access.active.load(Ordering::Acquire) > 0);
        drop(writer);
        assert_eq!(access.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn raw_addresses_validate_the_full_range_in_guarded_and_passthrough_modes() {
        let backing = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap();
        let (guarded, _) = memory(4);
        let passthrough = RuntimeGuestMemory::passthrough(backing);

        for memory in [&guarded, &passthrough] {
            assert!(memory.get_host_address(GuestAddress(0xffff), 1).is_ok());
            assert!(memory.get_host_address(GuestAddress(0xffff), 2).is_err());
            assert!(memory.get_host_address(GuestAddress(u64::MAX), 2).is_err());

            let chain = create_descriptor_chain(
                memory,
                GuestAddress(0),
                GuestAddress(0x10_000 - VSOCK_PKT_HDR_SIZE as u64 + 1),
                vec![(DescriptorType::Writable, VSOCK_PKT_HDR_SIZE as u32)],
                0,
            )
            .unwrap();
            assert!(VsockPacket::from_rx_virtq_head(&chain).is_err());
        }
    }

    #[test]
    fn raw_address_guard_keeps_guest_memory_backing_alive() {
        let raw = {
            let (memory, _) = memory(1);
            memory.write_slice(&[0x5a], GuestAddress(0x1000)).unwrap();
            memory.get_host_address(GuestAddress(0x1000), 1).unwrap()
        };

        assert_eq!(unsafe { raw.as_ptr().read() }, 0x5a);
    }
}
