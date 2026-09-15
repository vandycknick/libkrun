// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Guest RAM layout description for host reclaim.
//!
//! This module contains no hypervisor or host-memory operations. It records
//! which guest-physical ranges are private anonymous RAM, translates guest
//! ranges to their host addresses, and validates the alignment a backend needs
//! before it releases a range to the host.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

/// Optional guard for host access to guest memory.
///
/// Devices route guest memory access through `RuntimeGuestMemory`, which
/// consults an implementation only when one is installed. The macOS reclaim
/// path installs none: the host mapping stays valid across a release, so host
/// access needs no lease and pays no synchronization cost.
pub trait HostMemoryAccess: Send + Sync {
    fn access(
        self: Arc<Self>,
        range: GuestRange,
    ) -> Result<Arc<dyn HostMemoryLease>, HostMemoryAccessError>;

    /// Long-lived mappings handed to another process or library.
    fn allows_external_mapping(&self) -> bool;
}

pub trait HostMemoryLease: Send + Sync {}

#[derive(Debug, Eq, PartialEq)]
pub struct HostMemoryAccessError(String);

impl HostMemoryAccessError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for HostMemoryAccessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for HostMemoryAccessError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamPermissions(u8);

impl RamPermissions {
    pub const READ: u8 = 0b001;
    pub const WRITE: u8 = 0b010;
    pub const EXECUTE: u8 = 0b100;
    pub const READ_WRITE_EXECUTE: Self = Self(0b111);

    pub const fn bits(self) -> u8 {
        self.0
    }

    fn is_valid(self) -> bool {
        self.0 != 0 && self.0 & !0b111 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestRange {
    start: u64,
    end: u64,
}

impl GuestRange {
    pub fn new(start: u64, len: u64) -> Result<Self, ReclaimError> {
        if len == 0 {
            return Err(ReclaimError::EmptyRange);
        }
        let end = start
            .checked_add(len)
            .ok_or(ReclaimError::AddressOverflow)?;
        Ok(Self { start, end })
    }

    pub fn start(self) -> u64 {
        self.start
    }

    /// Exclusive end address.
    pub fn end(self) -> u64 {
        self.end
    }

    pub fn byte_len(self) -> u64 {
        self.end - self.start
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    pub fn contains_address(self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostRange {
    guest: GuestRange,
    host_start: u64,
    permissions: RamPermissions,
}

impl HostRange {
    pub fn guest_range(self) -> GuestRange {
        self.guest
    }

    pub fn host_start(self) -> u64 {
        self.host_start
    }

    pub fn byte_len(self) -> u64 {
        self.guest.byte_len()
    }

    pub fn permissions(self) -> RamPermissions {
        self.permissions
    }
}

/// One contiguous private anonymous RAM region with identical guest and host
/// alignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamRegion {
    range: HostRange,
}

impl RamRegion {
    pub fn new(
        guest_start: u64,
        host_start: u64,
        len: u64,
        permissions: RamPermissions,
    ) -> Result<Self, ReclaimError> {
        if !permissions.is_valid() {
            return Err(ReclaimError::InvalidPermissions);
        }
        let guest = GuestRange::new(guest_start, len)?;
        host_start
            .checked_add(len)
            .ok_or(ReclaimError::AddressOverflow)?;
        Ok(Self {
            range: HostRange {
                guest,
                host_start,
                permissions,
            },
        })
    }

    pub fn host_range(self) -> HostRange {
        self.range
    }

    pub fn contains_address(self, guest_address: u64) -> bool {
        self.range.guest.contains_address(guest_address)
    }

    /// Shrinks `requested` to the largest `alignment`-aligned sub-range inside
    /// this region and translates it to host addresses. Returns `Ok(None)`
    /// when nothing aligned remains.
    pub fn aligned_subrange(
        self,
        requested: GuestRange,
        alignment: u64,
    ) -> Result<Option<HostRange>, ReclaimError> {
        if !alignment.is_power_of_two() {
            return Err(ReclaimError::InvalidAlignment);
        }
        if !self.range.guest.contains(requested) {
            return Err(ReclaimError::NotRam);
        }

        let aligned_start = requested
            .start
            .checked_add(alignment - 1)
            .ok_or(ReclaimError::AddressOverflow)?
            & !(alignment - 1);
        let aligned_end = requested.end & !(alignment - 1);
        if aligned_start >= aligned_end {
            return Ok(None);
        }

        let offset = aligned_start - self.range.guest.start;
        let host_start = self
            .range
            .host_start
            .checked_add(offset)
            .ok_or(ReclaimError::AddressOverflow)?;
        if host_start & (alignment - 1) != 0 {
            return Err(ReclaimError::MisalignedHostTranslation);
        }

        Ok(Some(HostRange {
            guest: GuestRange {
                start: aligned_start,
                end: aligned_end,
            },
            host_start,
            permissions: self.range.permissions,
        }))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReclaimError {
    AddressOverflow,
    EmptyRange,
    InvalidAlignment,
    InvalidPermissions,
    MisalignedHostTranslation,
    NotRam,
    OverlappingRegion,
}

impl Display for ReclaimError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::AddressOverflow => "address range overflowed",
                Self::EmptyRange => "range is empty",
                Self::InvalidAlignment => "alignment is not a nonzero power of two",
                Self::InvalidPermissions => "RAM permissions are invalid",
                Self::MisalignedHostTranslation => "guest and host RAM alignment do not match",
                Self::NotRam => "range is not wholly contained in registered RAM",
                Self::OverlappingRegion => "RAM region overlaps an existing guest or host mapping",
            }
        )
    }
}

impl Error for ReclaimError {}

/// The set of guest RAM regions a backend may release to the host, plus the
/// host page granule every release must be aligned to.
#[derive(Clone, Debug)]
pub struct RamLayout {
    granule: u64,
    regions: Vec<RamRegion>,
}

impl RamLayout {
    pub fn new(granule: u64) -> Result<Self, ReclaimError> {
        if !granule.is_power_of_two() {
            return Err(ReclaimError::InvalidAlignment);
        }
        Ok(Self {
            granule,
            regions: Vec::new(),
        })
    }

    pub fn register_region(&mut self, region: RamRegion) -> Result<(), ReclaimError> {
        let host = region.host_range();
        if host.guest.start & (self.granule - 1) != 0
            || host.host_start & (self.granule - 1) != 0
            || host.byte_len() & (self.granule - 1) != 0
        {
            return Err(ReclaimError::InvalidAlignment);
        }
        if self.regions.iter().any(|existing| {
            let existing = existing.host_range();
            existing.guest.overlaps(host.guest)
                || numeric_ranges_overlap(
                    existing.host_start,
                    existing.byte_len(),
                    host.host_start,
                    host.byte_len(),
                )
        }) {
            return Err(ReclaimError::OverlappingRegion);
        }
        self.regions.push(region);
        self.regions.sort_by_key(|entry| entry.range.guest.start);
        Ok(())
    }

    pub fn granule(&self) -> u64 {
        self.granule
    }

    pub fn regions(&self) -> &[RamRegion] {
        &self.regions
    }

    pub fn has_registered_regions(&self) -> bool {
        !self.regions.is_empty()
    }

    pub fn region_containing(&self, guest_address: u64) -> Option<RamRegion> {
        self.regions
            .iter()
            .copied()
            .find(|region| region.contains_address(guest_address))
    }

    /// Translates `range` to the granule-aligned host range inside the RAM
    /// region that wholly contains it. `Ok(None)` means nothing aligned is
    /// left to release.
    pub fn resolve(&self, range: GuestRange) -> Result<Option<HostRange>, ReclaimError> {
        let region = self
            .region_containing(range.start)
            .ok_or(ReclaimError::NotRam)?;
        region.aligned_subrange(range, self.granule)
    }
}

fn numeric_ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    let a_end = a_start.saturating_add(a_len);
    let b_end = b_start.saturating_add(b_len);
    a_start < b_end && b_start < a_end
}

#[cfg(test)]
mod tests {
    use super::{GuestRange, RamLayout, RamPermissions, RamRegion, ReclaimError};

    fn layout() -> RamLayout {
        let mut layout = RamLayout::new(0x4000).unwrap();
        layout
            .register_region(
                RamRegion::new(
                    0x4000_0000,
                    0x1_0000_0000,
                    0x40_0000,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        layout
    }

    #[test]
    fn layout_requires_power_of_two_granule_and_aligned_regions() {
        assert_eq!(
            RamLayout::new(0x3000).err(),
            Some(ReclaimError::InvalidAlignment)
        );
        let mut layout = RamLayout::new(0x4000).unwrap();
        let misaligned = RamRegion::new(
            0x4000_1000,
            0x1_0000_0000,
            0x4000,
            RamPermissions::READ_WRITE_EXECUTE,
        )
        .unwrap();
        assert_eq!(
            layout.register_region(misaligned).err(),
            Some(ReclaimError::InvalidAlignment)
        );
        assert!(!layout.has_registered_regions());
    }

    #[test]
    fn layout_rejects_overlapping_guest_or_host_ranges() {
        let mut layout = layout();
        let guest_overlap = RamRegion::new(
            0x4020_0000,
            0x2_0000_0000,
            0x4000,
            RamPermissions::READ_WRITE_EXECUTE,
        )
        .unwrap();
        assert_eq!(
            layout.register_region(guest_overlap).err(),
            Some(ReclaimError::OverlappingRegion)
        );
        let host_overlap = RamRegion::new(
            0x8000_0000,
            0x1_0020_0000,
            0x4000,
            RamPermissions::READ_WRITE_EXECUTE,
        )
        .unwrap();
        assert_eq!(
            layout.register_region(host_overlap).err(),
            Some(ReclaimError::OverlappingRegion)
        );
        assert_eq!(layout.regions().len(), 1);
    }

    #[test]
    fn resolve_translates_and_aligns_inside_ram_only() {
        let layout = layout();
        let range = GuestRange::new(0x4000_1000, 0x2_2000).unwrap();
        let host = layout.resolve(range).unwrap().expect("aligned sub-range");
        assert_eq!(host.guest_range().start(), 0x4000_4000);
        assert_eq!(host.guest_range().end(), 0x4002_0000);
        assert_eq!(host.host_start(), 0x1_0000_4000);
        assert_eq!(host.permissions(), RamPermissions::READ_WRITE_EXECUTE);

        let tiny = GuestRange::new(0x4000_1000, 0x1000).unwrap();
        assert_eq!(layout.resolve(tiny).unwrap(), None);

        let outside = GuestRange::new(0x3fff_c000, 0x8000).unwrap();
        assert_eq!(layout.resolve(outside).err(), Some(ReclaimError::NotRam));
        let straddling = GuestRange::new(0x403f_c000, 0x8000).unwrap();
        assert_eq!(layout.resolve(straddling).err(), Some(ReclaimError::NotRam));
    }

    #[test]
    fn region_lookup_uses_half_open_bounds() {
        let layout = layout();
        assert!(layout.region_containing(0x4000_0000).is_some());
        assert!(layout.region_containing(0x403f_ffff).is_some());
        assert!(layout.region_containing(0x4040_0000).is_none());
        assert!(layout.region_containing(0x3fff_ffff).is_none());
    }

    #[test]
    fn guest_range_rejects_empty_and_overflowing_ranges() {
        assert_eq!(GuestRange::new(0, 0).err(), Some(ReclaimError::EmptyRange));
        assert_eq!(
            GuestRange::new(u64::MAX, 2).err(),
            Some(ReclaimError::AddressOverflow)
        );
        assert_eq!(
            RamRegion::new(0, 0, 0x4000, RamPermissions(0)).err(),
            Some(ReclaimError::InvalidPermissions)
        );
    }
}
