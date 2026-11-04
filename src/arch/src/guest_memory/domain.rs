use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::Poll;

use crate::guest_memory::{GuestRange, RamPermissions};
use vm_memory::{
    Address, AtomicAccess, ByteValued, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryError,
    GuestMemoryMmap, GuestMemoryRegion, VolatileMemoryError, VolatileSlice,
};

const CLOSED: usize = 1usize << (usize::BITS - 1);
const COUNT: usize = CLOSED - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionId(usize);
impl RegionId {
    pub fn index(self) -> usize {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageIndex(usize);
impl PageIndex {
    pub fn new(index: usize) -> Self {
        Self(index)
    }
    pub fn index(self) -> usize {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TopologyGeneration(u64);
impl TopologyGeneration {
    pub fn value(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackingKind {
    Boot,
    RestoredInput,
    RestoredPrivate,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackingMode {
    Disabled,
    Capture,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    Geometry,
    Bounds,
    Closed,
    Overflow,
    Authority,
    State,
    ExternalExport,
    Bitmap,
    CoverageLost,
}
impl Display for MemoryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "memory domain: {self:?}")
    }
}
impl std::error::Error for MemoryError {}
impl From<MemoryError> for GuestMemoryError {
    fn from(error: MemoryError) -> Self {
        Self::IOError(std::io::Error::other(error))
    }
}

#[derive(Debug)]
pub struct RegisteredRamRegion {
    id: RegionId,
    guest: GuestRange,
    stream_offset: u64,
    first_page: usize,
    page_count: usize,
    permissions: RamPermissions,
}
impl RegisteredRamRegion {
    pub fn id(&self) -> RegionId {
        self.id
    }
    pub fn guest_range(&self) -> GuestRange {
        self.guest
    }
    pub fn stream_offset(&self) -> u64 {
        self.stream_offset
    }
    pub fn first_page(&self) -> usize {
        self.first_page
    }
    pub fn permissions(&self) -> RamPermissions {
        self.permissions
    }
}
#[derive(Debug)]
pub struct RegisteredRamLayout {
    granule: u32,
    regions: Box<[RegisteredRamRegion]>,
    packed_len: u64,
    page_count: usize,
    aligned: bool,
}
impl RegisteredRamLayout {
    pub fn from_memory(memory: &GuestMemoryMmap, granule: u32) -> Result<Self, MemoryError> {
        if !granule.is_power_of_two() {
            return Err(MemoryError::Geometry);
        }
        let mut regions = Vec::with_capacity(memory.num_regions());
        let mut packed_len = 0u64;
        let mut page_count = 0usize;
        let mut previous_end = 0;
        let mut aligned = true;
        for region in memory.iter() {
            let start = region.start_addr().raw_value();
            let len = region.len();
            let guest = GuestRange::new(start, len).map_err(|_| MemoryError::Geometry)?;
            if start < previous_end {
                return Err(MemoryError::Geometry);
            }
            previous_end = guest.end();
            let host = region
                .get_host_address(vm_memory::MemoryRegionAddress(0))
                .map_err(|_| MemoryError::Geometry)? as usize;
            host.checked_add(usize::try_from(len).map_err(|_| MemoryError::Overflow)?)
                .ok_or(MemoryError::Overflow)?;
            for previous in memory.iter().take(regions.len()) {
                let previous_host = previous
                    .get_host_address(vm_memory::MemoryRegionAddress(0))
                    .map_err(|_| MemoryError::Geometry)?
                    as usize;
                let previous_end = previous_host
                    .checked_add(
                        usize::try_from(previous.len()).map_err(|_| MemoryError::Overflow)?,
                    )
                    .ok_or(MemoryError::Overflow)?;
                if host < previous_end && previous_host < host + len as usize {
                    return Err(MemoryError::Geometry);
                }
            }
            aligned &= start.is_multiple_of(u64::from(granule))
                && len.is_multiple_of(u64::from(granule))
                && host.is_multiple_of(granule as usize);
            let pages = usize::try_from(len.div_ceil(u64::from(granule)))
                .map_err(|_| MemoryError::Overflow)?;
            regions.push(RegisteredRamRegion {
                id: RegionId(regions.len()),
                guest,
                stream_offset: packed_len,
                first_page: page_count,
                page_count: pages,
                permissions: RamPermissions::READ_WRITE_EXECUTE,
            });
            packed_len = packed_len.checked_add(len).ok_or(MemoryError::Overflow)?;
            page_count = page_count.checked_add(pages).ok_or(MemoryError::Overflow)?;
        }
        Ok(Self {
            granule,
            regions: regions.into_boxed_slice(),
            packed_len,
            page_count,
            aligned,
        })
    }
    pub fn validate_capture(&self) -> Result<(), MemoryError> {
        if !self.aligned
            || !(4096..=65536).contains(&self.granule)
            || self.regions.is_empty()
            || self.regions.len() > 512
            || self.packed_len > (1u64 << 40)
        {
            return Err(MemoryError::Geometry);
        }
        Ok(())
    }
    pub fn granule(&self) -> u32 {
        self.granule
    }
    pub fn regions(&self) -> &[RegisteredRamRegion] {
        &self.regions
    }
    pub fn packed_len(&self) -> u64 {
        self.packed_len
    }
    pub fn page_count(&self) -> usize {
        self.page_count
    }
    pub fn page_at(&self, gpa: u64) -> Option<PageIndex> {
        self.regions
            .iter()
            .find(|region| region.guest.contains_address(gpa))
            .map(|region| {
                PageIndex(
                    region.first_page
                        + ((gpa - region.guest.start()) / u64::from(self.granule)) as usize,
                )
            })
    }
}

#[derive(Debug)]
pub struct DirtyPageMap {
    words: Box<[u64]>,
    pages: usize,
}
impl DirtyPageMap {
    pub fn new(layout: &RegisteredRamLayout) -> Self {
        Self {
            words: vec![0; layout.page_count.div_ceil(64)].into_boxed_slice(),
            pages: layout.page_count,
        }
    }
    pub fn page_count(&self) -> usize {
        self.pages
    }
    pub fn words(&self) -> &[u64] {
        &self.words
    }
    pub fn set(&mut self, page: PageIndex) -> Result<(), MemoryError> {
        if page.0 >= self.pages {
            return Err(MemoryError::Bitmap);
        }
        self.words[page.0 / 64] |= 1u64 << (page.0 % 64);
        Ok(())
    }
    pub fn contains(&self, page: PageIndex) -> bool {
        page.0 < self.pages && self.words[page.0 / 64] & (1u64 << (page.0 % 64)) != 0
    }
    pub fn count(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }
    pub fn clear(&mut self) {
        self.words.fill(0);
    }
    pub fn merge(&mut self, other: &Self) -> Result<(), MemoryError> {
        if self.pages != other.pages {
            return Err(MemoryError::Bitmap);
        }
        for (dst, src) in self.words.iter_mut().zip(other.words.iter()) {
            *dst |= src;
        }
        Ok(())
    }
    pub fn merge_region_words(
        &mut self,
        region: &RegisteredRamRegion,
        words: &[u64],
    ) -> Result<(), MemoryError> {
        self.merge_words(
            region.first_page,
            region_pages(region, self.pages, words.len())?,
            words,
        )
    }
    pub fn merge_words(
        &mut self,
        first: usize,
        pages: usize,
        words: &[u64],
    ) -> Result<(), MemoryError> {
        if first.checked_add(pages).is_none_or(|end| end > self.pages)
            || words.len() != pages.div_ceil(64)
        {
            return Err(MemoryError::Bitmap);
        }
        for (index, word) in words.iter().copied().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let local = index * 64 + bit;
                if local < pages {
                    self.set(PageIndex(first + local))?;
                }
                bits &= bits - 1;
            }
        }
        Ok(())
    }
    pub fn iter_set(&self) -> impl Iterator<Item = PageIndex> + '_ {
        self.words
            .iter()
            .copied()
            .enumerate()
            .flat_map(move |(word_index, mut word)| {
                std::iter::from_fn(move || {
                    if word == 0 {
                        return None;
                    }
                    let bit = word.trailing_zeros() as usize;
                    word &= word - 1;
                    Some(PageIndex(word_index * 64 + bit))
                })
            })
            .filter(|page| page.0 < self.pages)
    }
}
fn region_pages(
    region: &RegisteredRamRegion,
    total: usize,
    words: usize,
) -> Result<usize, MemoryError> {
    let pages = region.page_count;
    if region
        .first_page
        .checked_add(pages)
        .is_none_or(|end| end > total)
        || pages.div_ceil(64) != words
    {
        return Err(MemoryError::Bitmap);
    }
    Ok(pages)
}

pub struct AtomicDirtyPageMap {
    words: Box<[AtomicU64]>,
    pages: usize,
}
impl AtomicDirtyPageMap {
    pub fn new(layout: &RegisteredRamLayout) -> Self {
        Self {
            words: (0..layout.page_count.div_ceil(64))
                .map(|_| AtomicU64::new(0))
                .collect(),
            pages: layout.page_count,
        }
    }
    pub fn mark(&self, page: PageIndex) -> Result<(), MemoryError> {
        if page.0 >= self.pages {
            return Err(MemoryError::Bitmap);
        }
        self.words[page.0 / 64].fetch_or(1u64 << (page.0 % 64), Ordering::Relaxed);
        Ok(())
    }
    pub fn contains(&self, page: PageIndex) -> bool {
        page.0 < self.pages
            && self.words[page.0 / 64].load(Ordering::Relaxed) & (1u64 << (page.0 % 64)) != 0
    }
    pub fn merge_into(&self, pending: &mut DirtyPageMap) -> Result<(), MemoryError> {
        if self.pages != pending.pages {
            return Err(MemoryError::Bitmap);
        }
        for (dst, src) in pending.words.iter_mut().zip(self.words.iter()) {
            *dst |= src.load(Ordering::Acquire);
        }
        Ok(())
    }
    fn drain_into(&self, pending: &mut DirtyPageMap) -> Result<(), MemoryError> {
        self.merge_into(pending)?;
        for word in &self.words {
            word.store(0, Ordering::Release);
        }
        Ok(())
    }
}

pub struct MemoryDomain {
    memory: GuestMemoryMmap,
    layout: RegisteredRamLayout,
    backing: BackingKind,
    mode: AtomicU8,
    exported: AtomicBool,
    gate: AtomicUsize,
    native: AtomicUsize,
    close_generation: AtomicU64,
    sealed_generation: AtomicU64,
    host_dirty: OnceLock<AtomicDirtyPageMap>,
    coverage_lost: AtomicBool,
}
impl MemoryDomain {
    pub fn construct(
        memory: GuestMemoryMmap,
        granule: u32,
        backing: BackingKind,
    ) -> Result<(Arc<Self>, ConstructionAuthority, DomainControl), MemoryError> {
        let layout = RegisteredRamLayout::from_memory(&memory, granule)?;
        let domain = Arc::new(Self {
            memory,
            layout,
            backing,
            mode: AtomicU8::new(0),
            exported: AtomicBool::new(false),
            gate: AtomicUsize::new(0),
            native: AtomicUsize::new(0),
            close_generation: AtomicU64::new(0),
            sealed_generation: AtomicU64::new(0),
            host_dirty: OnceLock::new(),
            coverage_lost: AtomicBool::new(false),
        });
        Ok((
            domain.clone(),
            ConstructionAuthority {
                domain: domain.clone(),
            },
            DomainControl {
                domain,
                generation: 0,
                state: ControlState::Constructing,
            },
        ))
    }
    pub fn layout(&self) -> &RegisteredRamLayout {
        &self.layout
    }
    pub fn topology_generation(&self) -> TopologyGeneration {
        TopologyGeneration(0)
    }
    pub fn backing_kind(&self) -> BackingKind {
        self.backing
    }
    pub fn tracking_mode(&self) -> Option<TrackingMode> {
        match self.mode.load(Ordering::Acquire) {
            1 => Some(TrackingMode::Disabled),
            2 => Some(TrackingMode::Capture),
            _ => None,
        }
    }
    pub fn coverage_valid(&self) -> bool {
        !self.coverage_lost.load(Ordering::Acquire)
    }
    pub fn external_mapping_exported(&self) -> bool {
        self.exported.load(Ordering::Acquire) || self.mode.load(Ordering::Acquire) == 4
    }
    pub fn invalidate_coverage(&self) {
        self.coverage_lost.store(true, Ordering::Release);
    }
    pub fn read_only(&self) -> ReadGuestMemory<'_> {
        ReadGuestMemory::new(&self.memory)
    }
    pub fn host_page_dirty(&self, page: PageIndex) -> Result<bool, MemoryError> {
        if page.index() >= self.layout.page_count() {
            return Err(MemoryError::Bounds);
        }
        Ok(self
            .host_dirty
            .get()
            .ok_or(MemoryError::State)?
            .contains(page))
    }
    pub fn matches_mapping(&self, memory: &GuestMemoryMmap) -> bool {
        self.memory.num_regions() == memory.num_regions()
            && self.memory.iter().zip(memory.iter()).all(|(left, right)| {
                left.start_addr() == right.start_addr()
                    && left.len() == right.len()
                    && left
                        .get_host_address(vm_memory::MemoryRegionAddress(0))
                        .ok()
                        == right
                            .get_host_address(vm_memory::MemoryRegionAddress(0))
                            .ok()
            })
    }
    pub fn matches_region_mapping(&self, region: RegionId, host: u64) -> bool {
        self.memory
            .iter()
            .nth(region.index())
            .and_then(|mapping| {
                mapping
                    .get_host_address(vm_memory::MemoryRegionAddress(0))
                    .ok()
            })
            .is_some_and(|pointer| pointer as usize as u64 == host)
    }
    pub fn validate_range(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        if len == 0 {
            return Ok(());
        }
        let end = address
            .raw_value()
            .checked_add(u64::try_from(len).map_err(|_| MemoryError::Overflow)?)
            .ok_or(MemoryError::Overflow)?;
        let mut current = address.raw_value();
        for region in self.memory.iter() {
            if current < region.start_addr().raw_value() {
                break;
            }
            if current >= region.start_addr().raw_value()
                && current < region.start_addr().raw_value() + region.len()
            {
                current = end.min(region.start_addr().raw_value() + region.len());
                if current == end {
                    return Ok(());
                }
            }
        }
        Err(GuestMemoryError::InvalidGuestAddress(GuestAddress(current)))
    }
    pub fn region_remaining(&self, address: GuestAddress) -> Result<usize, GuestMemoryError> {
        let region = self
            .memory
            .find_region(address)
            .ok_or(GuestMemoryError::InvalidGuestAddress(address))?;
        usize::try_from(region.len() - (address.raw_value() - region.start_addr().raw_value()))
            .map_err(|_| MemoryError::Overflow.into())
    }
    pub fn read(
        self: &Arc<Self>,
        address: GuestAddress,
        len: usize,
    ) -> Result<HostReadGuard, GuestMemoryError> {
        self.validate_range(address, len)?;
        Ok(HostReadGuard {
            domain: self.clone(),
            address,
            len,
        })
    }
    pub fn write(
        self: &Arc<Self>,
        address: GuestAddress,
        len: usize,
    ) -> Result<HostWriteGuard, GuestMemoryError> {
        self.validate_range(address, len)?;
        if len != 0 {
            self.acquire(false)?;
            if let Err(error) = self.mark(address, len) {
                self.release();
                return Err(error.into());
            }
        }
        Ok(HostWriteGuard {
            domain: self.clone(),
            address,
            len,
            counted: len != 0,
        })
    }
    fn acquire(&self, existing: bool) -> Result<(), MemoryError> {
        let mut state = self.gate.load(Ordering::Acquire);
        loop {
            if (!existing && state & CLOSED != 0) || (existing && state & COUNT == 0) {
                return Err(MemoryError::Closed);
            }
            if state & COUNT == COUNT {
                return Err(MemoryError::Overflow);
            }
            match self.gate.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(next) => state = next,
            }
        }
    }
    fn release(&self) {
        self.gate.fetch_sub(1, Ordering::Release);
    }
    fn mark(&self, address: GuestAddress, len: usize) -> Result<(), MemoryError> {
        let Some(map) = self.host_dirty.get() else {
            return Ok(());
        };
        let end = address
            .raw_value()
            .checked_add(len as u64)
            .ok_or(MemoryError::Overflow)?;
        for region in self.layout.regions() {
            let start = address.raw_value().max(region.guest.start());
            let stop = end.min(region.guest.end());
            if start < stop {
                let first = (start - region.guest.start()) / u64::from(self.layout.granule);
                let last = (stop - 1 - region.guest.start()) / u64::from(self.layout.granule);
                for page in first..=last {
                    map.mark(PageIndex(region.first_page + page as usize))?;
                }
            }
        }
        Ok(())
    }
    pub fn with_external_mapping<T>(
        &self,
        operation: impl FnOnce(&GuestMemoryMmap) -> T,
    ) -> Result<T, GuestMemoryError> {
        if self.backing != BackingKind::Boot {
            return Err(MemoryError::ExternalExport.into());
        }
        let mut mode = self.mode.load(Ordering::Acquire);
        loop {
            match mode {
                2 => return Err(MemoryError::ExternalExport.into()),
                1 | 4 => break,
                0 => {
                    match self
                        .mode
                        .compare_exchange_weak(0, 4, Ordering::AcqRel, Ordering::Acquire)
                    {
                        Ok(_) => break,
                        Err(next) => mode = next,
                    }
                }
                _ => return Err(MemoryError::State.into()),
            }
        }
        self.exported.store(true, Ordering::Release);
        Ok(operation(&self.memory))
    }
    pub fn allows_external_mapping(&self) -> bool {
        self.backing == BackingKind::Boot && self.tracking_mode() != Some(TrackingMode::Capture)
    }
    pub fn checked_offset(&self, base: GuestAddress, offset: usize) -> Option<GuestAddress> {
        self.memory.checked_offset(base, offset)
    }
    pub fn address_in_range(&self, address: GuestAddress) -> bool {
        self.memory.address_in_range(address)
    }
    pub fn read_obj<T: ByteValued>(&self, address: GuestAddress) -> Result<T, GuestMemoryError> {
        self.memory.read_obj(address)
    }
    pub fn read_slice(
        &self,
        buffer: &mut [u8],
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        self.memory.read_slice(buffer, address)
    }
    pub fn load<T: AtomicAccess>(
        &self,
        address: GuestAddress,
        order: Ordering,
    ) -> Result<T, GuestMemoryError> {
        self.memory.load(address, order)
    }
}

pub struct ConstructionAuthority {
    domain: Arc<MemoryDomain>,
}
impl ConstructionAuthority {
    pub fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub fn memory(&self) -> Result<&GuestMemoryMmap, MemoryError> {
        if self.domain.tracking_mode().is_some() {
            return Err(MemoryError::State);
        }
        Ok(&self.domain.memory)
    }
    pub fn with_memory<T>(
        &self,
        operation: impl FnOnce(&GuestMemoryMmap) -> T,
    ) -> Result<T, MemoryError> {
        if self.domain.tracking_mode().is_some() {
            return Err(MemoryError::State);
        }
        Ok(operation(&self.domain.memory))
    }
    pub fn issue_epoch(&self, epoch: u64) -> Result<CpuTrackingEpoch, MemoryError> {
        if self.domain.tracking_mode().is_some() || epoch == 0 {
            return Err(MemoryError::State);
        }
        Ok(CpuTrackingEpoch {
            domain: self.domain.clone(),
            epoch,
            close_generation: 0,
        })
    }
    pub fn native_effects(&self) -> Result<NativeEffectsPermit, MemoryError> {
        if self.domain.tracking_mode().is_some() {
            return Err(MemoryError::State);
        }
        self.domain
            .native
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| MemoryError::Overflow)?;
        Ok(NativeEffectsPermit {
            domain: self.domain.clone(),
            generation: 0,
            runtime: false,
        })
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ControlState {
    Constructing,
    Open,
    Closing,
    Drained,
    Sealed,
}
pub struct DomainControl {
    domain: Arc<MemoryDomain>,
    generation: u64,
    state: ControlState,
}
pub struct ClosingMemory {
    domain: Arc<MemoryDomain>,
    generation: u64,
}
pub struct DrainedMemory {
    domain: Arc<MemoryDomain>,
    generation: u64,
}
pub struct MemoryCut {
    domain: Arc<MemoryDomain>,
    generation: u64,
}
pub struct NativeEffectsPermit {
    domain: Arc<MemoryDomain>,
    generation: u64,
    runtime: bool,
}
impl std::fmt::Debug for NativeEffectsPermit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeEffectsPermit")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub struct CpuTrackingEpoch {
    domain: Arc<MemoryDomain>,
    epoch: u64,
    close_generation: u64,
}
pub struct CpuHarvest {
    domain: Arc<MemoryDomain>,
    epoch: u64,
    generation: u64,
}
impl DomainControl {
    pub fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub fn runtime_native_effects(&mut self) -> Result<NativeEffectsPermit, MemoryError> {
        if self.state != ControlState::Open {
            return Err(MemoryError::State);
        }
        self.domain
            .native
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| MemoryError::Overflow)?;
        Ok(NativeEffectsPermit {
            domain: self.domain.clone(),
            generation: self.generation,
            runtime: true,
        })
    }
    fn check_construction(&self, authority: &ConstructionAuthority) -> Result<(), MemoryError> {
        if self.state != ControlState::Constructing
            || !Arc::ptr_eq(&self.domain, &authority.domain)
            || self.domain.native.load(Ordering::Acquire) != 0
        {
            return Err(MemoryError::Authority);
        }
        self.domain
            .gate
            .compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| MemoryError::Authority)?;
        Ok(())
    }
    pub fn finish_untracked(
        &mut self,
        authority: ConstructionAuthority,
    ) -> Result<(), MemoryError> {
        self.check_construction(&authority)?;
        if self.domain.backing != BackingKind::Boot {
            return Err(MemoryError::State);
        }
        self.domain.mode.store(1, Ordering::Release);
        self.domain.gate.store(0, Ordering::Release);
        self.state = ControlState::Open;
        Ok(())
    }
    pub fn finish_tracked(
        &mut self,
        authority: ConstructionAuthority,
        epoch: CpuTrackingEpoch,
    ) -> Result<(), MemoryError> {
        self.check_construction(&authority)?;
        epoch.validate_domain(&self.domain)?;
        self.domain.layout.validate_capture()?;
        if self.domain.exported.load(Ordering::Acquire) || epoch.close_generation != 0 {
            return Err(MemoryError::ExternalExport);
        }
        self.domain
            .host_dirty
            .set(AtomicDirtyPageMap::new(&self.domain.layout))
            .map_err(|_| MemoryError::State)?;
        self.domain
            .mode
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| MemoryError::ExternalExport)?;
        self.domain.gate.store(0, Ordering::Release);
        self.state = ControlState::Open;
        Ok(())
    }
    pub fn close(&mut self) -> Result<ClosingMemory, MemoryError> {
        if self.domain.native.load(Ordering::Acquire) != 0 {
            return Err(MemoryError::Authority);
        }
        if self.state != ControlState::Open
            || self.domain.tracking_mode() != Some(TrackingMode::Capture)
        {
            return Err(MemoryError::State);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(MemoryError::Overflow)?;
        self.domain
            .close_generation
            .store(self.generation, Ordering::Release);
        self.domain.gate.fetch_or(CLOSED, Ordering::AcqRel);
        self.state = ControlState::Closing;
        Ok(ClosingMemory {
            domain: self.domain.clone(),
            generation: self.generation,
        })
    }
    pub fn poll_drained(
        &mut self,
        closing: &ClosingMemory,
    ) -> Poll<Result<DrainedMemory, MemoryError>> {
        if self.state != ControlState::Closing
            || self.generation != closing.generation
            || !Arc::ptr_eq(&self.domain, &closing.domain)
        {
            return Poll::Ready(Err(MemoryError::Authority));
        }
        if self.domain.gate.load(Ordering::Acquire) != CLOSED {
            return Poll::Pending;
        }
        self.state = ControlState::Drained;
        Poll::Ready(Ok(DrainedMemory {
            domain: self.domain.clone(),
            generation: self.generation,
        }))
    }
    pub fn native_effects(
        &mut self,
        drained: &DrainedMemory,
    ) -> Result<NativeEffectsPermit, MemoryError> {
        if self.state != ControlState::Drained
            || self.generation != drained.generation
            || !Arc::ptr_eq(&self.domain, &drained.domain)
        {
            return Err(MemoryError::Authority);
        }
        self.domain
            .native
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| MemoryError::Overflow)?;
        Ok(NativeEffectsPermit {
            domain: self.domain.clone(),
            generation: self.generation,
            runtime: false,
        })
    }
    pub fn poll_native_drained(&self, drained: &DrainedMemory) -> Poll<Result<(), MemoryError>> {
        if self.state != ControlState::Drained
            || self.generation != drained.generation
            || !Arc::ptr_eq(&self.domain, &drained.domain)
        {
            return Poll::Ready(Err(MemoryError::Authority));
        }
        if self.domain.native.load(Ordering::Acquire) != 0
            || self.domain.gate.load(Ordering::Acquire) != CLOSED
        {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
    pub fn seal(&mut self, drained: &DrainedMemory) -> Result<MemoryCut, MemoryError> {
        if self.state != ControlState::Drained
            || self.generation != drained.generation
            || !Arc::ptr_eq(&self.domain, &drained.domain)
            || self.domain.native.load(Ordering::Acquire) != 0
            || self.domain.gate.load(Ordering::Acquire) != CLOSED
        {
            return Err(MemoryError::Authority);
        }
        self.state = ControlState::Sealed;
        self.domain
            .sealed_generation
            .store(self.generation, Ordering::Release);
        Ok(MemoryCut {
            domain: self.domain.clone(),
            generation: self.generation,
        })
    }
    pub fn drain_host_dirty(
        &mut self,
        cut: &MemoryCut,
        pending: &mut DirtyPageMap,
    ) -> Result<(), MemoryError> {
        self.validate_cut(cut)?;
        self.domain
            .host_dirty
            .get()
            .ok_or(MemoryError::State)?
            .drain_into(pending)
    }
    pub fn validate_cut(&self, cut: &MemoryCut) -> Result<(), MemoryError> {
        cut.validate_domain(&self.domain)?;
        if self.state != ControlState::Sealed || self.generation != cut.generation {
            return Err(MemoryError::Authority);
        }
        Ok(())
    }
    pub fn reopen(&mut self, cut: MemoryCut, epoch: CpuTrackingEpoch) -> Result<(), MemoryError> {
        self.validate_cut(&cut)?;
        epoch.validate_domain(&self.domain)?;
        if epoch.close_generation != cut.generation {
            return Err(MemoryError::Authority);
        }
        self.domain
            .gate
            .compare_exchange(CLOSED, 0, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| MemoryError::State)?;
        self.state = ControlState::Open;
        Ok(())
    }
}
impl MemoryCut {
    pub fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn validate_domain(&self, domain: &MemoryDomain) -> Result<(), MemoryError> {
        if !std::ptr::eq(Arc::as_ptr(&self.domain), domain)
            || self.domain.gate.load(Ordering::Acquire) != CLOSED
            || self.domain.native.load(Ordering::Acquire) != 0
            || self.domain.close_generation.load(Ordering::Acquire) != self.generation
            || self.domain.sealed_generation.load(Ordering::Acquire) != self.generation
        {
            return Err(MemoryError::Authority);
        }
        Ok(())
    }
    pub fn issue_harvest(&self, epoch: u64) -> Result<CpuHarvest, MemoryError> {
        self.validate_domain(&self.domain)?;
        Ok(CpuHarvest {
            domain: self.domain.clone(),
            epoch,
            generation: self.generation,
        })
    }
    pub fn issue_epoch(&self, epoch: u64) -> Result<CpuTrackingEpoch, MemoryError> {
        self.validate_domain(&self.domain)?;
        if epoch == 0 {
            return Err(MemoryError::State);
        }
        Ok(CpuTrackingEpoch {
            domain: self.domain.clone(),
            epoch,
            close_generation: self.generation,
        })
    }
}
impl CpuHarvest {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn validate_cut(&self, cut: &MemoryCut) -> Result<(), MemoryError> {
        cut.validate_domain(&self.domain)?;
        if self.generation != cut.generation {
            return Err(MemoryError::Authority);
        }
        Ok(())
    }
}
impl CpuTrackingEpoch {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn validate_domain(&self, domain: &MemoryDomain) -> Result<(), MemoryError> {
        if !std::ptr::eq(Arc::as_ptr(&self.domain), domain) {
            return Err(MemoryError::Authority);
        }
        Ok(())
    }
}
impl NativeEffectsPermit {
    pub fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub fn validate_domain(&self, domain: &MemoryDomain) -> Result<(), MemoryError> {
        if !std::ptr::eq(Arc::as_ptr(&self.domain), domain) {
            return Err(MemoryError::Authority);
        }
        if self.runtime {
            if self.domain.tracking_mode().is_none()
                || self.domain.gate.load(Ordering::Acquire) & CLOSED != 0
                || self.domain.close_generation.load(Ordering::Acquire) != self.generation
            {
                return Err(MemoryError::Authority);
            }
        } else if self.generation == 0 {
            if self.domain.tracking_mode().is_some() {
                return Err(MemoryError::Authority);
            }
        } else if self.domain.gate.load(Ordering::Acquire) & CLOSED == 0
            || self.domain.close_generation.load(Ordering::Acquire) != self.generation
            || self.domain.sealed_generation.load(Ordering::Acquire) == self.generation
        {
            return Err(MemoryError::Authority);
        }
        Ok(())
    }
    pub fn coverage_lost(&self) {
        self.domain.coverage_lost.store(true, Ordering::Release);
    }
    pub fn write(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<HostWriteGuard, GuestMemoryError> {
        self.validate_domain(&self.domain)?;
        self.domain.validate_range(address, len)?;
        if len != 0 {
            self.domain
                .gate
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    if state & COUNT == COUNT {
                        None
                    } else {
                        Some(state + 1)
                    }
                })
                .map_err(|_| MemoryError::Overflow)?;
            if let Err(error) = self.domain.mark(address, len) {
                self.domain.release();
                return Err(error.into());
            }
        }
        Ok(HostWriteGuard {
            domain: self.domain.clone(),
            address,
            len,
            counted: len != 0,
        })
    }
}
impl Drop for NativeEffectsPermit {
    fn drop(&mut self) {
        self.domain.native.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyEffect {
    PreEffectRefusal,
    CoverageLost,
    ProtectionUnknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyOperation {
    Bind,
    Arm,
    Collect,
    Rearm,
    Native,
    Fault,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyLocation {
    Vm,
    Slot(u32),
    Region(RegionId),
    Page(PageIndex),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirtyFailure {
    pub operation: DirtyOperation,
    pub location: DirtyLocation,
    pub native_code: i64,
    pub effect: DirtyEffect,
}
impl Display for DirtyFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dirty tracking {:?} at {:?}: {:?} ({})",
            self.operation, self.location, self.effect, self.native_code
        )
    }
}
impl std::error::Error for DirtyFailure {}

pub struct HostReadGuard {
    domain: Arc<MemoryDomain>,
    address: GuestAddress,
    len: usize,
}
pub struct HostWriteGuard {
    domain: Arc<MemoryDomain>,
    address: GuestAddress,
    len: usize,
    counted: bool,
}
fn subrange(
    address: GuestAddress,
    total: usize,
    offset: usize,
    len: usize,
) -> Result<GuestAddress, GuestMemoryError> {
    if offset.checked_add(len).is_none_or(|end| end > total) {
        return Err(MemoryError::Bounds.into());
    }
    address
        .checked_add(offset as u64)
        .ok_or_else(|| MemoryError::Overflow.into())
}
fn view(
    domain: &MemoryDomain,
    address: GuestAddress,
    len: usize,
) -> Result<VolatileSlice<'_>, GuestMemoryError> {
    if len == 0 {
        // A zero-length slice never authorizes dereferencing the dangling pointer.
        return Ok(unsafe { VolatileSlice::new(std::ptr::NonNull::<u8>::dangling().as_ptr(), 0) });
    }
    domain.memory.get_slice(address, len)
}
impl HostReadGuard {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn read_view(&self, offset: usize, len: usize) -> Result<ReadView<'_>, GuestMemoryError> {
        Ok(ReadView {
            slice: view(
                &self.domain,
                subrange(self.address, self.len, offset, len)?,
                len,
            )?,
        })
    }
    pub fn try_clone(&self) -> Result<Self, GuestMemoryError> {
        Ok(Self {
            domain: self.domain.clone(),
            address: self.address,
            len: self.len,
        })
    }
    pub fn split_at(self, offset: usize) -> Result<(Self, Self), GuestMemoryError> {
        let address = subrange(self.address, self.len, offset, 0)?;
        let right = Self {
            domain: self.domain.clone(),
            address,
            len: self.len - offset,
        };
        Ok((
            Self {
                domain: self.domain,
                address: self.address,
                len: offset,
            },
            right,
        ))
    }
}
impl HostWriteGuard {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn read_view(&self, offset: usize, len: usize) -> Result<ReadView<'_>, GuestMemoryError> {
        Ok(self.write_view(offset, len)?.as_read())
    }
    pub fn write_view(&self, offset: usize, len: usize) -> Result<WriteView<'_>, GuestMemoryError> {
        Ok(WriteView {
            slice: view(
                &self.domain,
                subrange(self.address, self.len, offset, len)?,
                len,
            )?,
        })
    }
    pub fn try_clone(&self) -> Result<Self, GuestMemoryError> {
        if self.counted {
            self.domain.acquire(true)?;
        }
        Ok(Self {
            domain: self.domain.clone(),
            address: self.address,
            len: self.len,
            counted: self.counted,
        })
    }
    pub fn split_at(mut self, offset: usize) -> Result<(Self, Self), GuestMemoryError> {
        let address = subrange(self.address, self.len, offset, 0)?;
        let right_len = self.len - offset;
        let right_counted = self.counted && right_len != 0;
        if right_counted && offset != 0 {
            self.domain.acquire(true)?;
        }
        let right = Self {
            domain: self.domain.clone(),
            address,
            len: right_len,
            counted: right_counted,
        };
        if offset == 0 {
            self.counted = false;
        }
        self.len = offset;
        Ok((self, right))
    }
}
impl Drop for HostWriteGuard {
    fn drop(&mut self) {
        if self.counted {
            self.domain.release();
        }
    }
}

/// A read-only view. Its pointer may only be read within bounds while the view's
/// owner remains alive; casting it to a writable pointer violates that contract.
///
/// ```compile_fail
/// use krun_arch::guest_memory::ReadView;
/// fn mutate(view: ReadView<'_>) { view.as_mut_ptr(); }
/// ```
#[derive(Clone, Copy)]
pub struct ReadView<'a> {
    slice: VolatileSlice<'a>,
}
/// A write view cannot outlive the counted guard, including its read projection.
///
/// ```compile_fail
/// use krun_arch::guest_memory::HostWriteGuard;
/// fn escape(guard: HostWriteGuard) {
///     let view = guard.write_view(0, 1).unwrap();
///     drop(guard);
///     view.write_obj(7u8, 0).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use krun_arch::guest_memory::HostWriteGuard;
/// fn escape_read(guard: HostWriteGuard) {
///     let view = guard.read_view(0, 1).unwrap();
///     drop(guard);
///     view.read_obj::<u8>(0).unwrap();
/// }
/// ```
#[derive(Clone, Copy)]
pub struct WriteView<'a> {
    slice: VolatileSlice<'a>,
}
impl<'a> ReadView<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self {
            slice: unsafe { VolatileSlice::new(slice.as_ptr().cast_mut(), slice.len()) },
        }
    }
    pub fn len(self) -> usize {
        self.slice.len()
    }
    pub fn is_empty(self) -> bool {
        self.slice.is_empty()
    }
    pub fn subslice(self, offset: usize, len: usize) -> Result<Self, VolatileMemoryError> {
        Ok(Self {
            slice: self.slice.subslice(offset, len)?,
        })
    }
    /// The domain uses plain mmap backing, never a foreign-mapping backend; the
    /// owning guard pins the HVA through the complete call using this pointer.
    pub fn as_ptr(self) -> *const u8 {
        self.slice.ptr_guard().as_ptr()
    }
    pub fn read_slice(self, buffer: &mut [u8], offset: usize) -> Result<(), VolatileMemoryError> {
        self.slice.read_slice(buffer, offset)
    }
    pub fn read_obj<T: ByteValued>(self, offset: usize) -> Result<T, VolatileMemoryError> {
        self.slice.read_obj(offset)
    }
    pub fn load<T: AtomicAccess>(
        self,
        offset: usize,
        order: Ordering,
    ) -> Result<T, VolatileMemoryError> {
        self.slice.load(offset, order)
    }
    pub fn copy_to(self, buffer: &mut [u8]) -> usize {
        self.slice.copy_to(buffer)
    }
}
impl<'a> WriteView<'a> {
    pub fn len(self) -> usize {
        self.slice.len()
    }
    pub fn is_empty(self) -> bool {
        self.slice.is_empty()
    }
    pub fn subslice(self, offset: usize, len: usize) -> Result<Self, VolatileMemoryError> {
        Ok(Self {
            slice: self.slice.subslice(offset, len)?,
        })
    }
    /// The owning write guard pins this plain-mmap HVA and its writer obligation
    /// through the complete syscall or native operation using this pointer.
    pub fn as_mut_ptr(self) -> *mut u8 {
        self.slice.ptr_guard_mut().as_ptr()
    }
    pub fn as_read(self) -> ReadView<'a> {
        ReadView { slice: self.slice }
    }
    pub fn read_slice(self, buffer: &mut [u8], offset: usize) -> Result<(), VolatileMemoryError> {
        self.slice.read_slice(buffer, offset)
    }
    pub fn read_obj<T: ByteValued>(self, offset: usize) -> Result<T, VolatileMemoryError> {
        self.slice.read_obj(offset)
    }
    pub fn load<T: AtomicAccess>(
        self,
        offset: usize,
        order: Ordering,
    ) -> Result<T, VolatileMemoryError> {
        self.slice.load(offset, order)
    }
    pub fn write_slice(self, buffer: &[u8], offset: usize) -> Result<(), VolatileMemoryError> {
        self.slice.write_slice(buffer, offset)
    }
    pub fn write_obj<T: ByteValued>(
        self,
        value: T,
        offset: usize,
    ) -> Result<(), VolatileMemoryError> {
        self.slice.write_obj(value, offset)
    }
    pub fn store<T: AtomicAccess>(
        self,
        value: T,
        offset: usize,
        order: Ordering,
    ) -> Result<(), VolatileMemoryError> {
        self.slice.store(value, offset, order)
    }
    pub fn copy_from(self, buffer: &[u8]) {
        self.slice.copy_from(buffer);
    }
}

pub struct ReadGuestMemory<'a> {
    memory: &'a GuestMemoryMmap,
}
impl<'a> ReadGuestMemory<'a> {
    pub fn new(memory: &'a GuestMemoryMmap) -> Self {
        Self { memory }
    }
    pub fn validate_range(
        &self,
        address: GuestAddress,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        let mut remaining = len;
        let mut current = address;
        while remaining != 0 {
            let region = self
                .memory
                .find_region(current)
                .ok_or(GuestMemoryError::InvalidGuestAddress(current))?;
            let count = remaining.min(
                (region.len() - (current.raw_value() - region.start_addr().raw_value())) as usize,
            );
            remaining -= count;
            current = current
                .checked_add(count as u64)
                .ok_or(MemoryError::Overflow)?;
        }
        Ok(())
    }
    pub fn read_obj<T: ByteValued>(&self, address: GuestAddress) -> Result<T, GuestMemoryError> {
        self.memory.read_obj(address)
    }
    pub fn read_slice(
        &self,
        buffer: &mut [u8],
        address: GuestAddress,
    ) -> Result<(), GuestMemoryError> {
        self.memory.read_slice(buffer, address)
    }
    pub fn load<T: AtomicAccess>(
        &self,
        address: GuestAddress,
        order: Ordering,
    ) -> Result<T, GuestMemoryError> {
        self.memory.load(address, order)
    }
    pub fn address_in_range(&self, address: GuestAddress) -> bool {
        self.memory.address_in_range(address)
    }
    pub fn checked_offset(&self, address: GuestAddress, offset: usize) -> Option<GuestAddress> {
        self.memory.checked_offset(address, offset)
    }
}

#[cfg(test)]
mod tests {
    use crate::guest_memory::{
        BackingKind, DirtyPageMap, DomainControl, MemoryCut, MemoryDomain, MemoryError, PageIndex,
        TrackingMode,
    };
    use std::sync::{Arc, Barrier};
    use std::task::Poll;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn tracked(ranges: &[(GuestAddress, usize)]) -> (Arc<MemoryDomain>, DomainControl) {
        let raw = GuestMemoryMmap::from_ranges(ranges).unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
        let epoch = authority.issue_epoch(1).unwrap();
        control.finish_tracked(authority, epoch).unwrap();
        (domain, control)
    }

    fn seal(control: &mut DomainControl) -> MemoryCut {
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("ordinary writers remain")
        };
        control.seal(&drained).unwrap()
    }

    #[test]
    fn registered_inventory_packs_holes_without_allocating_hole_bits() {
        let (domain, _) = tracked(&[(GuestAddress(0), 4096), (GuestAddress(0x10000), 8192)]);
        let layout = domain.layout();
        assert_eq!(layout.packed_len(), 12288);
        assert_eq!(layout.page_count(), 3);
        assert_eq!(layout.regions()[1].stream_offset(), 4096);
        assert_eq!(layout.regions()[1].first_page(), 1);
        assert_eq!(layout.page_at(0x10000), Some(PageIndex::new(1)));
        assert_eq!(layout.page_at(0x11000), Some(PageIndex::new(2)));
        assert_eq!(layout.page_at(4096), None);
        assert!(domain.validate_range(GuestAddress(4095), 2).is_err());
        assert!(domain.validate_range(GuestAddress(u64::MAX), 2).is_err());
        assert!(domain.validate_range(GuestAddress(u64::MAX), 0).is_ok());
    }

    #[test]
    fn capture_region_bound_does_not_restrict_excluded_cold_domains() {
        let ranges = (0..513)
            .map(|index| (GuestAddress(index * 8192), 4096))
            .collect::<Vec<_>>();
        let raw = GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
        assert_eq!(
            domain.layout().validate_capture(),
            Err(MemoryError::Geometry)
        );
        control.finish_untracked(authority).unwrap();
        assert_eq!(domain.tracking_mode(), Some(TrackingMode::Disabled));
        assert!(domain.write(GuestAddress(512 * 8192), 1).is_ok());
    }

    #[test]
    fn disabled_cold_domains_accept_non_capture_aligned_lengths() {
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 17)]).unwrap();
        let (domain, authority, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
        assert!(domain.layout().validate_capture().is_err());
        control.finish_untracked(authority).unwrap();
        assert!(domain.write(GuestAddress(16), 1).is_ok());
    }

    #[test]
    fn reads_and_empty_writes_do_not_mark_or_prevent_drain() {
        let (domain, mut control) = tracked(&[(GuestAddress(0), 8192)]);
        let read = domain.read(GuestAddress(0), 8192).unwrap();
        let empty = domain.write(GuestAddress(u64::MAX), 0).unwrap();
        assert!(empty.write_view(0, 0).unwrap().is_empty());
        assert!(empty.try_clone().unwrap().is_empty());
        let (left, right) = empty.split_at(0).unwrap();
        assert!(left.is_empty() && right.is_empty());
        let cut = seal(&mut control);
        let mut pending = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut pending).unwrap();
        assert_eq!(pending.count(), 0);
        assert_eq!(read.read_view(0, 1).unwrap().read_obj::<u8>(0).unwrap(), 0);
    }

    #[test]
    fn closed_guard_cloning_and_splitting_preserve_every_obligation() {
        let (domain, mut control) = tracked(&[(GuestAddress(0), 8192)]);
        let guard = domain.write(GuestAddress(0), 8192).unwrap();
        let closing = control.close().unwrap();
        assert!(domain.write(GuestAddress(0), 1).is_err());
        assert!(control.poll_drained(&closing).is_pending());
        let clone = guard.try_clone().unwrap();
        let (left, right) = guard.split_at(4096).unwrap();
        left.write_view(0, 1).unwrap().write_obj(17u8, 0).unwrap();
        right.write_view(0, 1).unwrap().write_obj(19u8, 0).unwrap();
        drop(left);
        drop(clone);
        assert!(control.poll_drained(&closing).is_pending());
        drop(right);
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("last guard did not release")
        };
        let cut = control.seal(&drained).unwrap();
        let mut pending = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut pending).unwrap();
        assert_eq!(pending.count(), 2);
        assert_eq!(domain.read_obj::<u8>(GuestAddress(4096)).unwrap(), 19);
    }

    #[test]
    fn privileged_guard_survives_permit_and_prevents_final_sealing() {
        let (domain, mut control) = tracked(&[(GuestAddress(0), 4096)]);
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("ordinary drain")
        };
        let permit = control.native_effects(&drained).unwrap();
        assert!(control.seal(&drained).is_err());
        let guard = permit.write(GuestAddress(0), 1).unwrap();
        drop(permit);
        assert!(control.poll_native_drained(&drained).is_pending());
        assert!(control.seal(&drained).is_err());
        guard.write_view(0, 1).unwrap().write_obj(23u8, 0).unwrap();
        drop(guard);
        assert!(matches!(
            control.poll_native_drained(&drained),
            Poll::Ready(Ok(()))
        ));
        let cut = control.seal(&drained).unwrap();
        assert!(control.native_effects(&drained).is_err());
        let mut pending = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut pending).unwrap();
        assert!(pending.contains(PageIndex::new(0)));
    }

    #[test]
    fn construction_permits_and_writers_block_finalization() {
        for native in [false, true] {
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
            let (domain, authority, mut control) =
                MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
            let epoch = authority.issue_epoch(1).unwrap();
            let permit = native.then(|| authority.native_effects().unwrap());
            let writer = (!native).then(|| domain.write(GuestAddress(0), 1).unwrap());
            assert_eq!(
                control.finish_tracked(authority, epoch),
                Err(MemoryError::Authority)
            );
            assert_eq!(domain.tracking_mode(), None);
            drop(writer);
            drop(permit);
        }
    }

    #[test]
    fn external_export_and_tracked_finalization_are_atomic_alternatives() {
        for _ in 0..64 {
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
            let (domain, authority, mut control) =
                MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
            let epoch = authority.issue_epoch(1).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            std::thread::scope(|scope| {
                let domain = domain.clone();
                let rendezvous = barrier.clone();
                let export = scope.spawn(move || {
                    rendezvous.wait();
                    domain
                        .with_external_mapping(|memory| memory.clone())
                        .is_ok()
                });
                barrier.wait();
                let captured = control.finish_tracked(authority, epoch).is_ok();
                let exported = export.join().unwrap();
                assert_ne!(captured, exported);
            });
        }
    }

    #[test]
    fn stale_and_foreign_cut_and_epoch_authority_is_rejected() {
        let (domain, mut control) = tracked(&[(GuestAddress(0), 4096)]);
        let (foreign, mut foreign_control) = tracked(&[(GuestAddress(0), 4096)]);
        let first = seal(&mut control);
        assert!(first.validate_domain(&foreign).is_err());
        let stale = MemoryCut {
            domain: domain.clone(),
            generation: first.generation,
        };
        let epoch = first.issue_epoch(2).unwrap();
        let old_epoch = epoch.clone();
        control.reopen(first, epoch).unwrap();
        assert!(stale.validate_domain(&domain).is_err());
        let second = seal(&mut control);
        assert!(stale.issue_harvest(2).is_err());
        assert!(stale.issue_epoch(3).is_err());
        let foreign_cut = seal(&mut foreign_control);
        assert!(foreign_cut.validate_domain(&domain).is_err());
        assert_eq!(
            control.reopen(second, old_epoch),
            Err(MemoryError::Authority)
        );
    }

    #[test]
    fn host_dirty_drain_retains_union_and_detects_same_page_in_next_epoch() {
        let (domain, mut control) = tracked(&[(GuestAddress(0), 8192)]);
        drop(domain.write(GuestAddress(0), 1).unwrap());
        assert!(domain.host_page_dirty(PageIndex::new(0)).unwrap());
        let cut = seal(&mut control);
        let mut pending = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut pending).unwrap();
        assert!(!domain.host_page_dirty(PageIndex::new(0)).unwrap());
        assert_eq!(pending.count(), 1);
        let epoch = cut.issue_epoch(2).unwrap();
        control.reopen(cut, epoch).unwrap();
        drop(domain.write(GuestAddress(0), 1).unwrap());
        drop(domain.write(GuestAddress(4096), 1).unwrap());
        assert!(domain.host_page_dirty(PageIndex::new(0)).unwrap());
        let cut = seal(&mut control);
        control.drain_host_dirty(&cut, &mut pending).unwrap();
        assert_eq!(pending.count(), 2);
    }

    #[test]
    fn region_bitmap_merge_handles_dense_unaligned_start_and_tail_padding() {
        let (domain, _) = tracked(&[(GuestAddress(0), 4096), (GuestAddress(8192), 65 * 4096)]);
        let mut pending = DirtyPageMap::new(domain.layout());
        pending
            .merge_region_words(&domain.layout().regions()[1], &[1 << 63, u64::MAX])
            .unwrap();
        assert_eq!(pending.count(), 2);
        assert!(pending.contains(PageIndex::new(64)));
        assert!(pending.contains(PageIndex::new(65)));
        assert!(!pending.contains(PageIndex::new(0)));
        assert!(pending.merge_words(65, 2, &[1]).is_err());
        assert!(pending.merge_words(0, 65, &[1]).is_err());
    }

    #[test]
    fn restored_inputs_require_tracking_and_never_export_raw_mapping() {
        for backing in [BackingKind::RestoredInput, BackingKind::RestoredPrivate] {
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
            let (domain, authority, mut control) =
                MemoryDomain::construct(raw, 4096, backing).unwrap();
            assert!(domain.with_external_mapping(|_| ()).is_err());
            assert!(control.finish_untracked(authority).is_err());
        }
    }
    #[test]
    fn concurrent_construction_writer_cannot_cross_finalization_unmarked() {
        for _ in 0..64 {
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
            let (domain, authority, mut control) =
                MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
            let epoch = authority.issue_epoch(1).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let (done, completed) = std::sync::mpsc::sync_channel(1);
            std::thread::scope(|scope| {
                let writer_domain = domain.clone();
                let rendezvous = barrier.clone();
                let writer = scope.spawn(move || {
                    rendezvous.wait();
                    let Ok(guard) = writer_domain.write(GuestAddress(0), 1) else {
                        return false;
                    };
                    completed.recv().unwrap();
                    guard.write_view(0, 1).unwrap().write_obj(37u8, 0).unwrap();
                    true
                });
                barrier.wait();
                let finalized = control.finish_tracked(authority, epoch).is_ok();
                let _ = done.send(());
                if finalized && writer.join().unwrap() {
                    assert!(domain.host_page_dirty(PageIndex::new(0)).unwrap());
                }
            });
        }
    }

    #[test]
    fn runtime_native_authority_blocks_close_and_is_retired_before_next_cut() {
        let (domain, mut control) = tracked(&[(GuestAddress(0), 4096)]);
        let permit = control.runtime_native_effects().unwrap();
        assert!(control.close().is_err());
        drop(permit.write(GuestAddress(0), 1).unwrap());
        drop(permit);
        let cut = seal(&mut control);
        assert!(domain.host_page_dirty(PageIndex::new(0)).unwrap());
        let epoch = cut.issue_epoch(2).unwrap();
        control.reopen(cut, epoch).unwrap();
        let permit = control.runtime_native_effects().unwrap();
        assert!(permit.validate_domain(&domain).is_ok());
    }
}
