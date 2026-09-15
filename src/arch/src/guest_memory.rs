// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Checked bookkeeping for host reclaim of guest RAM.
//!
//! This module deliberately contains no hypervisor or host-memory operations. A
//! caller first reserves a release or restore transition, performs the OS
//! operation, then commits or aborts the exact token. Reservations exclude
//! overlapping transitions and leases without holding this ledger's lock across
//! I/O. Generations and token IDs are checked and never reused, so exhaustion
//! disables further transitions rather than allowing wrapping ABA.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

/// Keeps a checked guest RAM range mapped and host-accounted while userspace
/// can dereference it. Implementations must restore before returning a lease.
pub trait HostMemoryAccess: Send + Sync {
    fn access(
        self: Arc<Self>,
        range: GuestRange,
    ) -> Result<Arc<dyn HostMemoryLease>, HostMemoryAccessError>;

    /// Long-lived mappings handed to another process or library cannot be
    /// reclaimed until that integration owns durable leases.
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
    pub const READ_WRITE_EXECUTE: Self = Self(0b111);

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

    pub fn byte_len(self) -> u64 {
        self.end - self.start
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
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

    fn aligned_subrange(
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MappingGeneration(u64);

impl MappingGeneration {
    pub const INITIAL: Self = Self(0);

    pub fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LeaseId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasePlan {
    token: u64,
    range: HostRange,
    generation: MappingGeneration,
}

impl ReleasePlan {
    pub fn range(self) -> HostRange {
        self.range
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePlan {
    token: u64,
    access: GuestRange,
    ranges: Vec<HostRange>,
    generation: MappingGeneration,
    lease: LeaseId,
}

impl RestorePlan {
    pub fn ranges(&self) -> &[HostRange] {
        &self.ranges
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessPlan {
    Leased(LeaseId),
    Restore(RestorePlan),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MappingRun {
    range: GuestRange,
    generation: MappingGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleasedExtent {
    range: HostRange,
    generation: MappingGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingKind {
    Release,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingTransition {
    range: GuestRange,
    kind: PendingKind,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReclaimError {
    ActiveLease,
    AddressOverflow,
    Busy,
    EmptyRange,
    GenerationExhausted,
    InvalidAlignment,
    InvalidPermissions,
    InvalidTransition,
    LeaseExhausted,
    MetadataLimit,
    MisalignedHostTranslation,
    NotRam,
    OverlappingRegion,
    Released,
    TokenExhausted,
    UnknownLease,
}

impl Display for ReclaimError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::ActiveLease => "range has an active host-access lease",
                Self::AddressOverflow => "address range overflowed",
                Self::Busy => "range has a pending mapping transition",
                Self::EmptyRange => "range is empty",
                Self::GenerationExhausted => "mapping generation space is exhausted",
                Self::InvalidAlignment => "alignment is not a nonzero power of two",
                Self::InvalidPermissions => "RAM permissions are invalid",
                Self::InvalidTransition => "mapping transition token is stale or invalid",
                Self::LeaseExhausted => "host-access lease space is exhausted",
                Self::MetadataLimit => "RAM-granule metadata bound was exceeded",
                Self::MisalignedHostTranslation => "guest and host RAM alignment do not match",
                Self::NotRam => "range is not wholly contained in registered RAM",
                Self::OverlappingRegion => "RAM region overlaps an existing guest or host mapping",
                Self::Released => "range intersects released RAM and must be restored",
                Self::TokenExhausted => "transition token space is exhausted",
                Self::UnknownLease => "host-access lease does not exist",
            }
        )
    }
}

impl Error for ReclaimError {}

#[derive(Debug)]
pub struct ReclaimLedger {
    granule: u64,
    regions: Vec<RamRegion>,
    released: BTreeMap<u64, ReleasedExtent>,
    leases: BTreeMap<LeaseId, GuestRange>,
    reserved_leases: BTreeMap<LeaseId, GuestRange>,
    pending: BTreeMap<u64, Vec<PendingTransition>>,
    mapping_runs: Vec<MappingRun>,
    granule_limit: usize,
    next_generation: u64,
    next_lease: u64,
    next_token: u64,
}

impl ReclaimLedger {
    pub fn new(granule: u64) -> Result<Self, ReclaimError> {
        if !granule.is_power_of_two() {
            return Err(ReclaimError::InvalidAlignment);
        }
        Ok(Self {
            granule,
            regions: Vec::new(),
            released: BTreeMap::new(),
            leases: BTreeMap::new(),
            reserved_leases: BTreeMap::new(),
            pending: BTreeMap::new(),
            mapping_runs: Vec::new(),
            granule_limit: 0,
            next_generation: 1,
            next_lease: 1,
            next_token: 1,
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

        let granules = usize::try_from(host.byte_len() / self.granule)
            .map_err(|_| ReclaimError::MetadataLimit)?;
        self.granule_limit = self
            .granule_limit
            .checked_add(granules)
            .ok_or(ReclaimError::MetadataLimit)?;
        self.regions.push(region);
        self.regions.sort_by_key(|entry| entry.range.guest.start);
        self.mapping_runs.push(MappingRun {
            range: host.guest,
            generation: MappingGeneration::INITIAL,
        });
        self.coalesce_mapping_runs();
        Ok(())
    }

    pub fn granule(&self) -> u64 {
        self.granule
    }

    pub fn has_registered_regions(&self) -> bool {
        !self.regions.is_empty()
    }

    pub fn prepare_release(
        &mut self,
        requested: GuestRange,
        host_alignment: u64,
    ) -> Result<Option<ReleasePlan>, ReclaimError> {
        let region = self.region_containing(requested)?;
        let Some(range) = region.aligned_subrange(requested, host_alignment)? else {
            return Ok(None);
        };
        self.ensure_available(range.guest)?;
        if self
            .leases
            .values()
            .any(|lease| lease.overlaps(range.guest))
        {
            return Err(ReclaimError::ActiveLease);
        }

        let token = self.allocate_token()?;
        let generation = self.allocate_generation()?;
        self.pending.insert(
            token,
            vec![PendingTransition {
                range: range.guest,
                kind: PendingKind::Release,
            }],
        );
        Ok(Some(ReleasePlan {
            token,
            range,
            generation,
        }))
    }

    pub fn validate_release(
        &self,
        requested: GuestRange,
        host_alignment: u64,
    ) -> Result<bool, ReclaimError> {
        let region = self.region_containing(requested)?;
        Ok(region
            .aligned_subrange(requested, host_alignment)?
            .is_some())
    }

    pub fn commit_release(&mut self, plan: ReleasePlan) -> Result<(), ReclaimError> {
        self.take_pending(plan.token, plan.range.guest, PendingKind::Release)?;
        if self
            .released
            .values()
            .any(|extent| extent.range.guest.overlaps(plan.range.guest))
        {
            return Err(ReclaimError::InvalidTransition);
        }
        self.remove_mapping_range(plan.range.guest)?;
        self.released.insert(
            plan.range.guest.start,
            ReleasedExtent {
                range: plan.range,
                generation: plan.generation,
            },
        );
        self.check_metadata_bound()
    }

    pub fn abort_release(&mut self, plan: ReleasePlan) -> Result<(), ReclaimError> {
        self.take_pending(plan.token, plan.range.guest, PendingKind::Release)
    }

    pub fn prepare_access(&mut self, range: GuestRange) -> Result<AccessPlan, ReclaimError> {
        self.region_containing(range)?;
        if self
            .pending
            .values()
            .flatten()
            .any(|pending| pending.range.overlaps(range))
        {
            return Err(ReclaimError::Busy);
        }

        let released: Vec<HostRange> = self
            .released
            .values()
            .filter(|extent| extent.range.guest.overlaps(range))
            .map(|extent| extent.range)
            .collect();
        if released.is_empty() {
            let lease = self.allocate_lease_id(range, false)?;
            self.leases.insert(lease, range);
            return Ok(AccessPlan::Leased(lease));
        }

        let token = self.allocate_token()?;
        let generation = self.allocate_generation()?;
        let lease = self.allocate_lease_id(range, true)?;
        self.pending.insert(
            token,
            released
                .iter()
                .map(|released_range| PendingTransition {
                    range: released_range.guest,
                    kind: PendingKind::Restore,
                })
                .collect(),
        );
        Ok(AccessPlan::Restore(RestorePlan {
            token,
            access: range,
            ranges: released,
            generation,
            lease,
        }))
    }

    pub fn commit_restore(&mut self, plan: RestorePlan) -> Result<LeaseId, ReclaimError> {
        self.validate_restore_pending(&plan)?;
        self.pending.remove(&plan.token);
        for range in &plan.ranges {
            match self.released.remove(&range.guest.start) {
                Some(current) if current.range == *range => {}
                _ => return Err(ReclaimError::InvalidTransition),
            }
            self.insert_mapping_run(range.guest, plan.generation)?;
        }
        self.reserved_leases.remove(&plan.lease);
        self.leases.insert(plan.lease, plan.access);
        Ok(plan.lease)
    }

    pub fn abort_restore(&mut self, plan: RestorePlan) -> Result<(), ReclaimError> {
        self.validate_restore_pending(&plan)?;
        self.pending.remove(&plan.token);
        self.reserved_leases.remove(&plan.lease);
        Ok(())
    }

    pub fn release_lease(&mut self, lease: LeaseId) -> Result<(), ReclaimError> {
        self.leases
            .remove(&lease)
            .map(|_| ())
            .ok_or(ReclaimError::UnknownLease)
    }

    pub fn generation_at(
        &self,
        guest_address: u64,
    ) -> Result<Option<MappingGeneration>, ReclaimError> {
        let range = GuestRange::new(guest_address, 1)?;
        self.region_containing(range)?;
        Ok(self
            .mapping_runs
            .iter()
            .find(|run| run.range.contains(range))
            .map(|run| run.generation))
    }

    pub fn active_lease_count(&self) -> usize {
        self.leases.len()
    }

    pub fn released_extent_count(&self) -> usize {
        self.released.len()
    }

    pub fn current_generation(&self) -> MappingGeneration {
        MappingGeneration(self.next_generation - 1)
    }

    pub fn released_generation_at(
        &self,
        guest_address: u64,
    ) -> Result<Option<MappingGeneration>, ReclaimError> {
        let range = GuestRange::new(guest_address, 1)?;
        self.region_containing(range)?;
        Ok(self
            .released
            .values()
            .find(|extent| extent.range.guest.contains(range))
            .map(|extent| extent.generation))
    }

    pub fn mapping_run_count(&self) -> usize {
        self.mapping_runs.len()
    }

    fn region_containing(&self, range: GuestRange) -> Result<RamRegion, ReclaimError> {
        self.regions
            .iter()
            .copied()
            .find(|region| region.range.guest.contains(range))
            .ok_or(ReclaimError::NotRam)
    }

    fn ensure_available(&self, range: GuestRange) -> Result<(), ReclaimError> {
        if self
            .released
            .values()
            .any(|extent| extent.range.guest.overlaps(range))
        {
            return Err(ReclaimError::Released);
        }
        if self
            .pending
            .values()
            .flatten()
            .any(|pending| pending.range.overlaps(range))
        {
            return Err(ReclaimError::Busy);
        }
        Ok(())
    }

    fn allocate_generation(&mut self) -> Result<MappingGeneration, ReclaimError> {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ReclaimError::GenerationExhausted)?;
        Ok(MappingGeneration(generation))
    }

    fn allocate_token(&mut self) -> Result<u64, ReclaimError> {
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or(ReclaimError::TokenExhausted)?;
        Ok(token)
    }

    fn allocate_lease_id(
        &mut self,
        range: GuestRange,
        reserve: bool,
    ) -> Result<LeaseId, ReclaimError> {
        if self.leases.len().saturating_add(self.reserved_leases.len()) >= self.granule_limit {
            return Err(ReclaimError::LeaseExhausted);
        }
        let id = LeaseId(self.next_lease);
        self.next_lease = self
            .next_lease
            .checked_add(1)
            .ok_or(ReclaimError::LeaseExhausted)?;
        if reserve {
            self.reserved_leases.insert(id, range);
        }
        Ok(id)
    }

    fn take_pending(
        &mut self,
        token: u64,
        range: GuestRange,
        kind: PendingKind,
    ) -> Result<(), ReclaimError> {
        match self.pending.remove(&token) {
            Some(pending) if pending.as_slice() == [PendingTransition { range, kind }] => Ok(()),
            Some(pending) => {
                self.pending.insert(token, pending);
                Err(ReclaimError::InvalidTransition)
            }
            None => Err(ReclaimError::InvalidTransition),
        }
    }

    fn validate_restore_pending(&self, plan: &RestorePlan) -> Result<(), ReclaimError> {
        let expected: Vec<PendingTransition> = plan
            .ranges
            .iter()
            .map(|range| PendingTransition {
                range: range.guest,
                kind: PendingKind::Restore,
            })
            .collect();
        if self.pending.get(&plan.token) != Some(&expected) {
            return Err(ReclaimError::InvalidTransition);
        }
        if self.reserved_leases.get(&plan.lease) != Some(&plan.access) {
            return Err(ReclaimError::InvalidTransition);
        }
        for range in &plan.ranges {
            if self
                .released
                .get(&range.guest.start)
                .map(|extent| extent.range)
                != Some(*range)
            {
                return Err(ReclaimError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn remove_mapping_range(&mut self, range: GuestRange) -> Result<(), ReclaimError> {
        let covered = self.mapping_runs.iter().try_fold(0_u64, |total, run| {
            let start = run.range.start.max(range.start);
            let end = run.range.end.min(range.end);
            total
                .checked_add(end.saturating_sub(start))
                .ok_or(ReclaimError::MetadataLimit)
        })?;
        if covered != range.byte_len() {
            return Err(ReclaimError::InvalidTransition);
        }

        let mut runs = Vec::with_capacity(self.mapping_runs.len().saturating_add(1));
        for run in self.mapping_runs.drain(..) {
            if !run.range.overlaps(range) {
                runs.push(run);
                continue;
            }
            if run.range.start < range.start {
                runs.push(MappingRun {
                    range: GuestRange {
                        start: run.range.start,
                        end: range.start,
                    },
                    generation: run.generation,
                });
            }
            if range.end < run.range.end {
                runs.push(MappingRun {
                    range: GuestRange {
                        start: range.end,
                        end: run.range.end,
                    },
                    generation: run.generation,
                });
            }
        }
        self.mapping_runs = runs;
        self.check_metadata_bound()
    }

    fn insert_mapping_run(
        &mut self,
        range: GuestRange,
        generation: MappingGeneration,
    ) -> Result<(), ReclaimError> {
        if self
            .mapping_runs
            .iter()
            .any(|run| run.range.overlaps(range))
        {
            return Err(ReclaimError::InvalidTransition);
        }
        self.mapping_runs.push(MappingRun { range, generation });
        self.coalesce_mapping_runs();
        self.check_metadata_bound()
    }

    fn coalesce_mapping_runs(&mut self) {
        self.mapping_runs.sort_by_key(|run| run.range.start);
        let mut coalesced: Vec<MappingRun> = Vec::with_capacity(self.mapping_runs.len());
        for run in self.mapping_runs.drain(..) {
            if let Some(previous) = coalesced.last_mut()
                && previous.range.end == run.range.start
                && previous.generation == run.generation
            {
                previous.range.end = run.range.end;
            } else {
                coalesced.push(run);
            }
        }
        self.mapping_runs = coalesced;
    }

    fn check_metadata_bound(&self) -> Result<(), ReclaimError> {
        if self.released.len() > self.granule_limit
            || self.pending.values().map(Vec::len).sum::<usize>() > self.granule_limit
            || self.mapping_runs.len() > self.granule_limit
            || self.leases.len().saturating_add(self.reserved_leases.len()) > self.granule_limit
        {
            Err(ReclaimError::MetadataLimit)
        } else {
            Ok(())
        }
    }
}

fn numeric_ranges_overlap(first: u64, first_len: u64, second: u64, second_len: u64) -> bool {
    let first_end = first.saturating_add(first_len);
    let second_end = second.saturating_add(second_len);
    first < second_end && second < first_end
}

#[cfg(test)]
mod tests {
    use crate::guest_memory::{
        AccessPlan, GuestRange, MappingGeneration, RamPermissions, RamRegion, ReclaimError,
        ReclaimLedger,
    };

    const GRANULE: u64 = 0x1000;
    const HOST_ALIGNMENT: u64 = 0x4000;

    fn ledger() -> ReclaimLedger {
        let mut ledger = ReclaimLedger::new(GRANULE).unwrap();
        ledger
            .register_region(
                RamRegion::new(
                    0x8000_0000,
                    0x1_0000_0000,
                    8 * HOST_ALIGNMENT,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        ledger
    }

    #[test]
    fn rejects_overflow_holes_mmio_and_overlapping_regions() {
        assert_eq!(
            GuestRange::new(u64::MAX, 2),
            Err(ReclaimError::AddressOverflow)
        );
        assert_eq!(
            RamRegion::new(0, u64::MAX, 2, RamPermissions::READ_WRITE_EXECUTE),
            Err(ReclaimError::AddressOverflow)
        );

        let mut ledger = ledger();
        let hole = GuestRange::new(0x9000_0000, GRANULE).unwrap();
        assert_eq!(ledger.prepare_access(hole), Err(ReclaimError::NotRam));
        assert_eq!(
            ledger.register_region(
                RamRegion::new(
                    0x8000_1000,
                    0x2_0000_0000,
                    GRANULE,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap()
            ),
            Err(ReclaimError::OverlappingRegion)
        );
        assert_eq!(
            ledger.register_region(
                RamRegion::new(
                    0xa000_0000,
                    0x1_0000_1000,
                    GRANULE,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap()
            ),
            Err(ReclaimError::OverlappingRegion)
        );
    }

    #[test]
    fn workload_ram_layout_rejects_adjacent_shm_gpa() {
        let mut ledger = ReclaimLedger::new(HOST_ALIGNMENT).unwrap();
        ledger
            .register_region(
                RamRegion::new(
                    0x8000_0000,
                    0x1_0000_0000,
                    2 * HOST_ALIGNMENT,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();

        let shm = GuestRange::new(0x8000_0000 + 2 * HOST_ALIGNMENT, HOST_ALIGNMENT).unwrap();
        assert_eq!(ledger.prepare_access(shm), Err(ReclaimError::NotRam));
    }

    #[test]
    fn aligns_inward_with_matching_host_offset() {
        let mut ledger = ledger();
        let requested = GuestRange::new(0x8000_1000, 0x9fff).unwrap();
        let plan = ledger
            .prepare_release(requested, HOST_ALIGNMENT)
            .unwrap()
            .unwrap();
        assert_eq!(plan.range().guest_range().start(), 0x8000_4000);
        assert_eq!(plan.range().byte_len(), 0x4000);
        assert_eq!(plan.range().host_start(), 0x1_0000_4000);
        ledger.abort_release(plan).unwrap();

        let empty = GuestRange::new(0x8000_1000, 0x2000).unwrap();
        assert_eq!(ledger.prepare_release(empty, HOST_ALIGNMENT).unwrap(), None);
    }

    #[test]
    fn release_validation_is_non_mutating() {
        let mut ledger = ledger();
        let range = GuestRange::new(0x8000_1000, 0x9fff).unwrap();
        assert!(ledger.validate_release(range, HOST_ALIGNMENT).unwrap());
        assert_eq!(ledger.released_extent_count(), 0);
        assert_eq!(ledger.active_lease_count(), 0);

        let plan = ledger
            .prepare_release(range, HOST_ALIGNMENT)
            .unwrap()
            .unwrap();
        ledger.abort_release(plan).unwrap();

        let empty = GuestRange::new(0x8000_1000, 0x2000).unwrap();
        assert!(!ledger.validate_release(empty, HOST_ALIGNMENT).unwrap());
        let outside_ram = GuestRange::new(0x7000_0000, HOST_ALIGNMENT).unwrap();
        assert_eq!(
            ledger.validate_release(outside_ram, HOST_ALIGNMENT),
            Err(ReclaimError::NotRam)
        );
    }

    #[test]
    fn rejects_misaligned_host_translation() {
        let mut ledger = ReclaimLedger::new(GRANULE).unwrap();
        ledger
            .register_region(
                RamRegion::new(
                    0x8000_0000,
                    0x1_0000_1000,
                    HOST_ALIGNMENT,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        let range = GuestRange::new(0x8000_0000, HOST_ALIGNMENT).unwrap();
        assert_eq!(
            ledger.prepare_release(range, HOST_ALIGNMENT),
            Err(ReclaimError::MisalignedHostTranslation)
        );
    }

    #[test]
    fn release_commit_abort_and_overlap_are_exact() {
        let mut ledger = ledger();
        let range = GuestRange::new(0x8000_0000, HOST_ALIGNMENT).unwrap();
        let aborted = ledger
            .prepare_release(range, HOST_ALIGNMENT)
            .unwrap()
            .unwrap();
        assert_eq!(ledger.prepare_access(range), Err(ReclaimError::Busy));
        ledger.abort_release(aborted).unwrap();

        let committed = ledger
            .prepare_release(range, HOST_ALIGNMENT)
            .unwrap()
            .unwrap();
        ledger.commit_release(committed).unwrap();
        assert_eq!(ledger.released_extent_count(), 1);
        assert_eq!(
            ledger.prepare_release(range, HOST_ALIGNMENT),
            Err(ReclaimError::Released)
        );
        assert_eq!(
            ledger.commit_release(committed),
            Err(ReclaimError::InvalidTransition)
        );
    }

    #[test]
    fn lease_blocks_release_and_cleanup_is_bounded() {
        let mut ledger = ledger();
        let range = GuestRange::new(0x8000_0000, HOST_ALIGNMENT).unwrap();
        let lease = match ledger.prepare_access(range).unwrap() {
            AccessPlan::Leased(lease) => lease,
            AccessPlan::Restore(_) => panic!("mapped RAM unexpectedly required restore"),
        };
        assert_eq!(ledger.active_lease_count(), 1);
        assert_eq!(
            ledger.prepare_release(range, HOST_ALIGNMENT),
            Err(ReclaimError::ActiveLease)
        );
        ledger.release_lease(lease).unwrap();
        assert_eq!(ledger.active_lease_count(), 0);
        assert_eq!(ledger.release_lease(lease), Err(ReclaimError::UnknownLease));
    }

    #[test]
    fn restore_commits_mapping_generation_before_lease() {
        let mut ledger = ledger();
        let range = GuestRange::new(0x8000_0000, HOST_ALIGNMENT).unwrap();
        let release = ledger
            .prepare_release(range, HOST_ALIGNMENT)
            .unwrap()
            .unwrap();
        ledger.commit_release(release).unwrap();
        assert_eq!(ledger.generation_at(range.start()).unwrap(), None);
        assert!(
            ledger
                .released_generation_at(range.start())
                .unwrap()
                .unwrap()
                .value()
                > 0
        );

        let restore = match ledger.prepare_access(range).unwrap() {
            AccessPlan::Restore(restore) => restore,
            AccessPlan::Leased(_) => panic!("released RAM was leased without restoration"),
        };
        assert_eq!(restore.ranges().len(), 1);
        let lease = ledger.commit_restore(restore).unwrap();
        assert!(
            ledger
                .generation_at(range.start())
                .unwrap()
                .unwrap()
                .value()
                > 0
        );
        assert_eq!(ledger.released_extent_count(), 0);
        ledger.release_lease(lease).unwrap();
    }

    #[test]
    fn restore_abort_preserves_released_state() {
        let mut ledger = ledger();
        let range = GuestRange::new(0x8000_0000, HOST_ALIGNMENT).unwrap();
        let release = ledger
            .prepare_release(range, HOST_ALIGNMENT)
            .unwrap()
            .unwrap();
        ledger.commit_release(release).unwrap();
        let restore = match ledger.prepare_access(range).unwrap() {
            AccessPlan::Restore(restore) => restore,
            AccessPlan::Leased(_) => panic!("released RAM was leased without restoration"),
        };
        ledger.abort_restore(restore).unwrap();
        assert_eq!(ledger.released_extent_count(), 1);
        assert_eq!(ledger.generation_at(range.start()).unwrap(), None);
    }

    #[test]
    fn mapping_runs_coalesce_and_remain_granule_bounded() {
        let mut ledger = ledger();
        let first = GuestRange::new(0x8000_0000, HOST_ALIGNMENT).unwrap();
        let second = GuestRange::new(0x8000_4000, HOST_ALIGNMENT).unwrap();
        for range in [first, second] {
            let plan = ledger
                .prepare_release(range, HOST_ALIGNMENT)
                .unwrap()
                .unwrap();
            ledger.commit_release(plan).unwrap();
        }
        assert!(ledger.mapping_run_count() <= 8 * (HOST_ALIGNMENT / GRANULE) as usize);
        for range in [first, second] {
            let plan = match ledger.prepare_access(range).unwrap() {
                AccessPlan::Restore(plan) => plan,
                AccessPlan::Leased(_) => panic!("released RAM was leased without restoration"),
            };
            let lease = ledger.commit_restore(plan).unwrap();
            ledger.release_lease(lease).unwrap();
        }
        assert!(ledger.mapping_run_count() <= 3);
        assert_ne!(
            ledger.generation_at(first.start()).unwrap(),
            Some(MappingGeneration::INITIAL)
        );
    }

    #[test]
    fn generation_token_and_lease_ids_never_wrap() {
        let range = GuestRange::new(0x8000_0000, HOST_ALIGNMENT).unwrap();

        let mut generation = ledger();
        generation.next_generation = u64::MAX;
        assert_eq!(
            generation.prepare_release(range, HOST_ALIGNMENT),
            Err(ReclaimError::GenerationExhausted)
        );
        assert_eq!(
            generation.prepare_release(range, HOST_ALIGNMENT),
            Err(ReclaimError::GenerationExhausted)
        );

        let mut token = ledger();
        token.next_token = u64::MAX;
        assert_eq!(
            token.prepare_release(range, HOST_ALIGNMENT),
            Err(ReclaimError::TokenExhausted)
        );

        let mut lease = ledger();
        lease.next_lease = u64::MAX;
        assert_eq!(
            lease.prepare_access(range),
            Err(ReclaimError::LeaseExhausted)
        );
        assert_eq!(
            lease.prepare_access(range),
            Err(ReclaimError::LeaseExhausted)
        );
    }

    #[test]
    fn pending_restore_reserves_lease_capacity_before_os_work() {
        let mut ledger = ReclaimLedger::new(GRANULE).unwrap();
        ledger
            .register_region(
                RamRegion::new(
                    0x8000_0000,
                    0x1_0000_0000,
                    3 * GRANULE,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        let mapped = GuestRange::new(0x8000_0000, GRANULE).unwrap();
        let first_released = GuestRange::new(0x8000_1000, GRANULE).unwrap();
        let second_released = GuestRange::new(0x8000_2000, GRANULE).unwrap();
        for range in [first_released, second_released] {
            let release = ledger.prepare_release(range, GRANULE).unwrap().unwrap();
            ledger.commit_release(release).unwrap();
        }
        for _ in 0..2 {
            assert!(matches!(
                ledger.prepare_access(mapped).unwrap(),
                AccessPlan::Leased(_)
            ));
        }

        let reserved = match ledger.prepare_access(first_released).unwrap() {
            AccessPlan::Restore(plan) => plan,
            AccessPlan::Leased(_) => panic!("released RAM was leased without restoration"),
        };
        assert_eq!(
            ledger.prepare_access(second_released),
            Err(ReclaimError::LeaseExhausted)
        );
        ledger.abort_restore(reserved).unwrap();
        assert!(matches!(
            ledger.prepare_access(second_released).unwrap(),
            AccessPlan::Restore(_)
        ));
    }
}
