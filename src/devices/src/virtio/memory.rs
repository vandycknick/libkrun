// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use arch::guest_memory::{
    HostReadGuard, HostWriteGuard, MemoryDomain, MemoryError, ReadView, WriteView,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use vm_memory::{Address, AtomicAccess, ByteValued, GuestAddress, GuestMemoryError};

#[derive(Clone)]
pub struct RuntimeGuestMemory {
    domain: Arc<MemoryDomain>,
}
impl RuntimeGuestMemory {
    pub fn new(domain: Arc<MemoryDomain>) -> Self {
        Self { domain }
    }
    pub fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub fn read_only(&self) -> arch::guest_memory::ReadGuestMemory<'_> {
        self.domain.read_only()
    }
    #[cfg(test)]
    pub fn from_ranges(ranges: &[(GuestAddress, usize)]) -> Result<Self, GuestMemoryError> {
        use arch::guest_memory::BackingKind;
        let memory = vm_memory::GuestMemoryMmap::from_ranges(ranges)
            .map_err(|error| GuestMemoryError::IOError(std::io::Error::other(error)))?;
        let (domain, authority, mut control) =
            MemoryDomain::construct(memory, 4096, BackingKind::Boot)?;
        control.finish_untracked(authority)?;
        Ok(Self::new(domain))
    }
    pub fn allows_external_mapping(&self) -> bool {
        self.domain.allows_external_mapping()
    }
    #[cfg(feature = "vhost-user")]
    pub(crate) fn with_external_mapping<T>(
        &self,
        operation: impl FnOnce(&vm_memory::GuestMemoryMmap) -> T,
    ) -> Result<T, GuestMemoryError> {
        self.domain.with_external_mapping(operation)
    }
    #[cfg(feature = "vhost-user")]
    pub(crate) fn external_host_address(
        &self,
        address: GuestAddress,
    ) -> Result<*mut u8, GuestMemoryError> {
        use vm_memory::GuestMemoryBackend;
        self.with_external_mapping(|memory| memory.get_host_address(address))?
    }
    pub fn checked_offset(&self, base: GuestAddress, offset: usize) -> Option<GuestAddress> {
        self.domain.checked_offset(base, offset)
    }
    pub fn address_in_range(&self, address: GuestAddress) -> bool {
        self.domain.address_in_range(address)
    }
    pub fn validate_range(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        self.domain.validate_range(address, len)
    }
    pub fn region_remaining(&self, address: GuestAddress) -> Result<usize, GuestMemoryError> {
        self.domain.region_remaining(address)
    }
    pub fn read(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<HostReadGuard, GuestMemoryError> {
        self.domain.read(address, len)
    }
    pub fn write(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<HostWriteGuard, GuestMemoryError> {
        self.domain.write(address, len)
    }
    pub fn read_at_most(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<Option<HostReadGuard>, GuestMemoryError> {
        if len == 0 {
            return Ok(None);
        }
        self.read(address, len.min(self.region_remaining(address)?))
            .map(Some)
    }
    pub fn write_at_most(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<Option<HostWriteGuard>, GuestMemoryError> {
        if len == 0 {
            return Ok(None);
        }
        self.write(address, len.min(self.region_remaining(address)?))
            .map(Some)
    }
    pub fn read_obj<T: ByteValued>(&self, address: GuestAddress) -> Result<T, GuestMemoryError> {
        self.domain.read_obj(address)
    }
    pub fn write_obj<T: ByteValued>(
        &self,
        value: T,
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        self.write_slice(value.as_slice(), address)
    }
    pub fn read_slice(
        &self,
        buffer: &mut [u8],
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        self.domain.read_slice(buffer, address)
    }
    pub fn write_slice(
        &self,
        buffer: &[u8],
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        self.try_write_access(buffer.len(), address, |completed, len, _, view| {
            view.write_slice(&buffer[completed..completed + len], 0)
                .map_err(GuestMemoryError::from)?;
            Ok(len)
        })?;
        Ok(())
    }
    pub fn load<T: AtomicAccess>(
        &self,
        address: GuestAddress,
        order: Ordering,
    ) -> Result<T, GuestMemoryError> {
        self.domain.load(address, order)
    }
    pub fn store<T: AtomicAccess>(
        &self,
        value: T,
        address: GuestAddress,
        order: Ordering,
    ) -> Result<(), GuestMemoryError> {
        let guard = self.write(address, size_of::<T>())?;
        guard
            .write_view(0, size_of::<T>())?
            .store(value, 0, order)
            .map_err(GuestMemoryError::from)
    }
    fn span(
        &self,
        address: GuestAddress,
        remaining: usize,
    ) -> Result<(usize, usize), GuestMemoryError> {
        let len = remaining.min(self.region_remaining(address)?);
        let region = self
            .domain
            .layout()
            .regions()
            .iter()
            .find(|region| region.guest_range().contains_address(address.raw_value()))
            .ok_or(MemoryError::Bounds)?;
        let offset = usize::try_from(address.raw_value() - region.guest_range().start())
            .map_err(|_| MemoryError::Overflow)?;
        Ok((len, offset))
    }
    pub fn try_read_access<F>(
        &self,
        count: usize,
        address: GuestAddress,
        mut callback: F,
    ) -> Result<usize, GuestMemoryError>
    where
        F: for<'a> FnMut(usize, usize, usize, ReadView<'a>) -> Result<usize, GuestMemoryError>,
    {
        let guard = self.read(address, count)?;
        let mut completed = 0;
        while completed < count {
            let current = address
                .checked_add(completed as u64)
                .ok_or(MemoryError::Overflow)?;
            let (len, offset) = self.span(current, count - completed)?;
            let done = callback(completed, len, offset, guard.read_view(completed, len)?)?;
            if done > len {
                return Err(MemoryError::Bounds.into());
            }
            if done == 0 {
                break;
            }
            completed += done;
        }
        Ok(completed)
    }
    pub fn try_write_access<F>(
        &self,
        count: usize,
        address: GuestAddress,
        mut callback: F,
    ) -> Result<usize, GuestMemoryError>
    where
        F: for<'a> FnMut(usize, usize, usize, WriteView<'a>) -> Result<usize, GuestMemoryError>,
    {
        let guard = self.write(address, count)?;
        let mut completed = 0;
        while completed < count {
            let current = address
                .checked_add(completed as u64)
                .ok_or(MemoryError::Overflow)?;
            let (len, offset) = self.span(current, count - completed)?;
            let done = callback(completed, len, offset, guard.write_view(completed, len)?)?;
            if done > len {
                return Err(MemoryError::Bounds.into());
            }
            if done == 0 {
                break;
            }
            completed += done;
        }
        Ok(completed)
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::memory::RuntimeGuestMemory;
    use arch::guest_memory::{BackingKind, DirtyPageMap, MemoryDomain, PageIndex};
    use std::task::Poll;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn writes_mark_adjacent_regions_and_reject_holes_before_mutation() {
        let raw = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 4096),
            (GuestAddress(4096), 4096),
            (GuestAddress(16384), 4096),
        ])
        .unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
        let epoch = authority.issue_epoch(1).unwrap();
        control.finish_tracked(authority, epoch).unwrap();
        let memory = RuntimeGuestMemory::new(domain.clone());
        memory.write_slice(&[1, 2], GuestAddress(4095)).unwrap();
        assert!(memory.write_slice(&[9; 8192], GuestAddress(4096)).is_err());
        let mut bytes = [0; 2];
        memory.read_slice(&mut bytes, GuestAddress(4095)).unwrap();
        assert_eq!(bytes, [1, 2]);
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("writers not drained")
        };
        let cut = control.seal(&drained).unwrap();
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 2);
        assert!(dirty.contains(PageIndex::new(0)));
        assert!(dirty.contains(PageIndex::new(1)));
        assert!(!dirty.contains(PageIndex::new(2)));
    }

    #[test]
    fn partial_callback_failure_keeps_entire_exposed_destination_dirty() {
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 8192)]).unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
        let epoch = authority.issue_epoch(1).unwrap();
        control.finish_tracked(authority, epoch).unwrap();
        let memory = RuntimeGuestMemory::new(domain.clone());
        assert!(
            memory
                .try_write_access(8192, GuestAddress(0), |_, _, _, view| {
                    view.write_slice(&[7], 0)?;
                    Err(vm_memory::GuestMemoryError::InvalidBackendAddress)
                })
                .is_err()
        );
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("writers not drained")
        };
        let cut = control.seal(&drained).unwrap();
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 2);
    }
}
