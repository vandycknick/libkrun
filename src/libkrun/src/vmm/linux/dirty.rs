use std::sync::Arc;

use crate::vmm::linux::vstate::VmFdOwner;
use arch::guest_memory::{
    ConstructionAuthority, CpuHarvest, CpuTrackingEpoch, DirtyEffect, DirtyFailure, DirtyLocation,
    DirtyOperation, DirtyPageMap, MemoryCut, MemoryDomain, NativeEffectsPermit, RegionId,
    RegisteredRamRegion, TrackingMode,
};
use kvm_bindings::{
    KVM_MEM_LOG_DIRTY_PAGES, KVMIO, kvm_dirty_log, kvm_dirty_log__bindgen_ty_1,
    kvm_userspace_memory_region,
};
use kvm_ioctls::VmFd;
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

ioctl_iow_nr!(get_dirty_log_into, KVMIO, 0x42, kvm_dirty_log);

fn failure(
    operation: DirtyOperation,
    slot: Option<u32>,
    effect: DirtyEffect,
    code: i64,
) -> DirtyFailure {
    DirtyFailure {
        operation,
        location: slot.map_or(DirtyLocation::Vm, DirtyLocation::Slot),
        native_code: code,
        effect,
    }
}

struct KvmSlotBitmap {
    pages: usize,
    words: Box<[u64]>,
}

impl KvmSlotBitmap {
    fn new(bytes: u64, granule: u32) -> Result<Self, DirtyFailure> {
        let pages = slot_pages(bytes, granule)?;
        let count = pages.div_ceil(64);
        let mut words = Vec::new();
        words
            .try_reserve_exact(count)
            .map_err(|_| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))?;
        words.resize(count, 0);
        Ok(Self {
            pages,
            words: words.into_boxed_slice(),
        })
    }

    fn validate(&self, bytes: u64, granule: u32) -> Result<(), DirtyFailure> {
        let pages = slot_pages(bytes, granule)?;
        if pages != self.pages || self.words.len() != pages.div_ceil(64) {
            return Err(failure(
                DirtyOperation::Collect,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        Ok(())
    }

    fn mask_tail(&mut self) {
        let tail = self.pages % 64;
        if tail != 0
            && let Some(last) = self.words.last_mut()
        {
            *last &= (1u64 << tail) - 1;
        }
    }
}

fn slot_pages(bytes: u64, granule: u32) -> Result<usize, DirtyFailure> {
    if !(4096..=65536).contains(&granule)
        || !granule.is_power_of_two()
        || bytes == 0
        || !bytes.is_multiple_of(u64::from(granule))
    {
        return Err(failure(
            DirtyOperation::Arm,
            None,
            DirtyEffect::PreEffectRefusal,
            0,
        ));
    }
    usize::try_from(bytes / u64::from(granule))
        .map_err(|_| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))
}

struct RegisteredKvmSlot {
    region: Option<RegionId>,
    installed: kvm_userspace_memory_region,
    original_flags: u32,
    dirty: Option<KvmSlotBitmap>,
}

impl RegisteredKvmSlot {
    fn new(installed: kvm_userspace_memory_region) -> Self {
        Self {
            region: None,
            original_flags: installed.flags,
            installed,
            dirty: None,
        }
    }

    fn logging_registration(&self) -> kvm_userspace_memory_region {
        kvm_userspace_memory_region {
            flags: self.original_flags | KVM_MEM_LOG_DIRTY_PAGES,
            ..self.installed
        }
    }

    fn matches_region(&self, region: &RegisteredRamRegion, host: u64) -> bool {
        self.installed.guest_phys_addr == region.guest_range().start()
            && self.installed.memory_size == region.guest_range().byte_len()
            && self.installed.userspace_addr == host
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrackingState {
    Constructing,
    Bound,
    Armed(u64),
    Harvested { epoch: u64, cut: u64 },
    Failed,
}

pub(crate) struct KvmMemory {
    slots: Vec<RegisteredKvmSlot>,
    backing: Option<Arc<GuestMemoryMmap>>,
    domain: Option<Arc<MemoryDomain>>,
    state: TrackingState,
}

impl KvmMemory {
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            backing: None,
            domain: None,
            state: TrackingState::Constructing,
        }
    }

    pub(crate) fn domain(&self) -> Option<&Arc<MemoryDomain>> {
        self.domain.as_ref()
    }

    pub(crate) fn backing(&self) -> Option<&Arc<GuestMemoryMmap>> {
        self.backing.as_ref()
    }

    pub(crate) fn validate_native(&self, permit: &NativeEffectsPermit) -> Result<(), String> {
        let domain = self
            .domain
            .as_ref()
            .ok_or("kvm/native/memory-domain-unbound")?;
        permit
            .validate_domain(domain)
            .map_err(|e| format!("kvm/native/authority: {e:?}"))?;
        if !matches!(self.state, TrackingState::Armed(_))
            || domain.tracking_mode() != Some(TrackingMode::Capture)
        {
            return Err("kvm/native/dirty-tracking-not-armed".into());
        }
        Ok(())
    }

    pub(crate) fn prepare_registration(
        &mut self,
        memory: &GuestMemoryMmap,
    ) -> Result<(), DirtyFailure> {
        if self.state != TrackingState::Constructing || self.backing.is_some() {
            return Err(failure(
                DirtyOperation::Bind,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        self.slots
            .try_reserve_exact(memory.num_regions())
            .map_err(|_| failure(DirtyOperation::Bind, None, DirtyEffect::PreEffectRefusal, 0))?;
        self.backing = Some(Arc::new(memory.clone()));
        Ok(())
    }

    fn prepare_tracked(
        &mut self,
        domain: &Arc<MemoryDomain>,
        authority: &ConstructionAuthority,
    ) -> Result<(CpuTrackingEpoch, Vec<RegisteredKvmSlot>), DirtyFailure> {
        if !Arc::ptr_eq(domain, authority.domain()) || self.domain.is_some() {
            return Err(failure(
                DirtyOperation::Arm,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        domain
            .layout()
            .validate_capture()
            .map_err(|_| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))?;
        let epoch = authority
            .issue_epoch(1)
            .map_err(|_| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))?;
        let slots = authority
            .with_memory(|memory| -> Result<Vec<RegisteredKvmSlot>, DirtyFailure> {
                self.prepare_registration(memory)?;
                let mut slots = Vec::new();
                slots.try_reserve_exact(memory.num_regions()).map_err(|_| {
                    failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0)
                })?;
                for (mapping, region) in memory.iter().zip(domain.layout().regions()) {
                    let slot = u32::try_from(region.id().index()).map_err(|_| {
                        failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0)
                    })?;
                    let mut record = RegisteredKvmSlot::new(kvm_userspace_memory_region {
                        slot,
                        guest_phys_addr: mapping.start_addr().raw_value(),
                        memory_size: mapping.len(),
                        userspace_addr: mapping.as_ptr() as u64,
                        flags: 0,
                    });
                    record.region = Some(region.id());
                    record.dirty = Some(KvmSlotBitmap::new(
                        mapping.len(),
                        domain.layout().granule(),
                    )?);
                    record.installed = record.logging_registration();
                    slots.push(record);
                }
                Ok(slots)
            })
            .map_err(|_| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))??;
        Ok((epoch, slots))
    }

    pub(crate) fn initialize_tracked(
        &mut self,
        fd: &VmFdOwner,
        domain: Arc<MemoryDomain>,
        authority: &ConstructionAuthority,
    ) -> Result<CpuTrackingEpoch, DirtyFailure> {
        let (epoch, slots) = self.prepare_tracked(&domain, authority)?;
        fd.retain_backing(self.backing.as_ref().ok_or_else(|| {
            failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0)
        })?)?;
        fd.bind_domain(Arc::clone(&domain))?;
        self.domain = Some(domain);
        for record in slots {
            if let Err(error) = unsafe { fd.set_user_memory_region(record.installed) } {
                self.state = TrackingState::Failed;
                authority.domain().invalidate_coverage();
                return Err(failure(
                    DirtyOperation::Arm,
                    Some(record.installed.slot),
                    DirtyEffect::CoverageLost,
                    i64::from(error.errno()),
                ));
            }
            self.slots.push(record);
        }
        self.state = TrackingState::Armed(1);
        Ok(epoch)
    }

    pub(crate) fn register(
        &mut self,
        fd: &VmFd,
        registration: kvm_userspace_memory_region,
    ) -> Result<(), kvm_ioctls::Error> {
        if self.state != TrackingState::Constructing
            || self.backing.is_none()
            || self.slots.len() == self.slots.capacity()
        {
            return Err(kvm_ioctls::Error::new(nix::errno::Errno::EINVAL as i32));
        }
        // Capacity and backing ownership are established before the first registration.
        unsafe { fd.set_user_memory_region(registration) }?;
        self.slots.push(RegisteredKvmSlot::new(registration));
        Ok(())
    }

    pub(crate) fn bind(&mut self, domain: Arc<MemoryDomain>) -> Result<(), DirtyFailure> {
        if self.state != TrackingState::Constructing || self.domain.is_some() {
            return Err(failure(
                DirtyOperation::Bind,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        let layout = domain.layout();
        let backing = self
            .backing
            .as_ref()
            .ok_or_else(|| failure(DirtyOperation::Bind, None, DirtyEffect::PreEffectRefusal, 0))?;
        if layout.regions().len() != self.slots.len() || !domain.matches_mapping(backing) {
            return Err(failure(
                DirtyOperation::Bind,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        for ((slot, region), mapping) in self.slots.iter().zip(layout.regions()).zip(backing.iter())
        {
            let host = mapping.as_ptr() as u64;
            if !slot.matches_region(region, host)
                || mapping.start_addr().raw_value() != region.guest_range().start()
                || mapping.len() != region.guest_range().byte_len()
            {
                return Err(failure(
                    DirtyOperation::Bind,
                    Some(slot.installed.slot),
                    DirtyEffect::PreEffectRefusal,
                    0,
                ));
            }
        }
        for (slot, region) in self.slots.iter_mut().zip(layout.regions()) {
            slot.region = Some(region.id());
        }
        self.domain = Some(domain);
        self.state = TrackingState::Bound;
        Ok(())
    }

    pub(crate) fn arm(
        &mut self,
        fd: &VmFd,
        authority: &ConstructionAuthority,
    ) -> Result<CpuTrackingEpoch, DirtyFailure> {
        let domain = self
            .domain
            .as_ref()
            .ok_or_else(|| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))?;
        if self.state != TrackingState::Bound || !Arc::ptr_eq(domain, authority.domain()) {
            return Err(failure(
                DirtyOperation::Arm,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        domain
            .layout()
            .validate_capture()
            .map_err(|_| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))?;
        let epoch = authority
            .issue_epoch(1)
            .map_err(|_| failure(DirtyOperation::Arm, None, DirtyEffect::PreEffectRefusal, 0))?;
        // Every buffer is ready before any slot flags are changed.
        for slot in &mut self.slots {
            slot.dirty = Some(KvmSlotBitmap::new(
                slot.installed.memory_size,
                domain.layout().granule(),
            )?);
        }
        for slot in &mut self.slots {
            let registration = slot.logging_registration();
            if let Err(error) = unsafe { fd.set_user_memory_region(registration) } {
                self.state = TrackingState::Failed;
                domain.invalidate_coverage();
                return Err(failure(
                    DirtyOperation::Arm,
                    Some(registration.slot),
                    DirtyEffect::CoverageLost,
                    i64::from(error.errno()),
                ));
            }
            slot.installed = registration;
        }
        self.state = TrackingState::Armed(1);
        Ok(epoch)
    }

    pub(crate) fn collect(
        &mut self,
        fd: &VmFd,
        cut: &MemoryCut,
        retained: &mut DirtyPageMap,
    ) -> Result<CpuHarvest, DirtyFailure> {
        let domain = self.domain.as_ref().ok_or_else(|| {
            failure(
                DirtyOperation::Collect,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        cut.validate_domain(domain).map_err(|_| {
            failure(
                DirtyOperation::Collect,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        let TrackingState::Armed(current) = self.state else {
            return Err(failure(
                DirtyOperation::Collect,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        };
        let next = current.checked_add(1).ok_or_else(|| {
            failure(
                DirtyOperation::Collect,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        let harvest = cut.issue_harvest(next).map_err(|_| {
            failure(
                DirtyOperation::Collect,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        if retained.page_count() != domain.layout().page_count()
            || self.slots.len() != domain.layout().regions().len()
        {
            return Err(failure(
                DirtyOperation::Collect,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        // Validate the complete retained inventory before the first destructive GET.
        for (slot, region) in self.slots.iter().zip(domain.layout().regions()) {
            if slot.region != Some(region.id())
                || slot.installed.flags != (slot.original_flags | KVM_MEM_LOG_DIRTY_PAGES)
            {
                return Err(failure(
                    DirtyOperation::Collect,
                    Some(slot.installed.slot),
                    DirtyEffect::PreEffectRefusal,
                    0,
                ));
            }
            slot.dirty
                .as_ref()
                .ok_or_else(|| {
                    failure(
                        DirtyOperation::Collect,
                        Some(slot.installed.slot),
                        DirtyEffect::PreEffectRefusal,
                        0,
                    )
                })?
                .validate(slot.installed.memory_size, domain.layout().granule())
                .map_err(|_| {
                    failure(
                        DirtyOperation::Collect,
                        Some(slot.installed.slot),
                        DirtyEffect::PreEffectRefusal,
                        0,
                    )
                })?;
        }
        for (slot, region) in self.slots.iter_mut().zip(domain.layout().regions()) {
            if let Err(error) = harvest_slot_into(fd, slot, region, retained) {
                self.state = TrackingState::Failed;
                domain.invalidate_coverage();
                return Err(error);
            }
        }
        self.state = TrackingState::Harvested {
            epoch: next,
            cut: cut.generation(),
        };
        Ok(harvest)
    }

    pub(crate) fn rearm(
        &mut self,
        cut: &MemoryCut,
        harvested: CpuHarvest,
    ) -> Result<CpuTrackingEpoch, DirtyFailure> {
        harvested.validate_cut(cut).map_err(|_| {
            failure(
                DirtyOperation::Rearm,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        let domain = self.domain.as_ref().ok_or_else(|| {
            failure(
                DirtyOperation::Rearm,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        cut.validate_domain(domain).map_err(|_| {
            failure(
                DirtyOperation::Rearm,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        let expected = TrackingState::Harvested {
            epoch: harvested.epoch(),
            cut: cut.generation(),
        };
        if self.state != expected {
            return Err(failure(
                DirtyOperation::Rearm,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            ));
        }
        let epoch = cut.issue_epoch(harvested.epoch()).map_err(|_| {
            failure(
                DirtyOperation::Rearm,
                None,
                DirtyEffect::PreEffectRefusal,
                0,
            )
        })?;
        // Ordinary GET has already reprotected the slots; the witness consumes that success.
        self.state = TrackingState::Armed(harvested.epoch());
        Ok(epoch)
    }
}

fn harvest_slot_into(
    fd: &VmFd,
    slot: &mut RegisteredKvmSlot,
    region: &RegisteredRamRegion,
    retained: &mut DirtyPageMap,
) -> Result<(), DirtyFailure> {
    let bitmap = slot.dirty.as_mut().ok_or_else(|| {
        failure(
            DirtyOperation::Collect,
            Some(slot.installed.slot),
            DirtyEffect::PreEffectRefusal,
            0,
        )
    })?;
    bitmap.words.fill(0);
    let log = kvm_dirty_log {
        slot: slot.installed.slot,
        padding1: 0,
        __bindgen_anon_1: kvm_dirty_log__bindgen_ty_1 {
            dirty_bitmap: bitmap.words.as_mut_ptr().cast(),
        },
    };
    // The exact retained registration determines the kernel's copy size, checked before entry.
    let result = unsafe { ioctl_with_ref(fd, get_dirty_log_into(), &log) };
    let result = match result {
        0 => Ok(()),
        value if value < 0 => Err(i64::from(nix::errno::Errno::last_raw())),
        value => Err(i64::from(value)),
    };
    retain_slot_result(bitmap, region, retained, slot.installed.slot, result)
}

fn retain_slot_result(
    bitmap: &mut KvmSlotBitmap,
    region: &RegisteredRamRegion,
    retained: &mut DirtyPageMap,
    slot: u32,
    result: Result<(), i64>,
) -> Result<(), DirtyFailure> {
    let code = match result {
        Ok(()) => 0,
        Err(code) => code,
    };
    bitmap.mask_tail();
    // A failing copy can still have delivered a prefix. Keep all known bits, without retrying GET.
    retained
        .merge_region_words(region, &bitmap.words)
        .map_err(|_| {
            failure(
                DirtyOperation::Collect,
                Some(slot),
                DirtyEffect::CoverageLost,
                code,
            )
        })?;
    if result.is_err() {
        return Err(failure(
            DirtyOperation::Collect,
            Some(slot),
            DirtyEffect::CoverageLost,
            code,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::task::Poll;

    use arch::guest_memory::{
        BackingKind, DirtyEffect, DirtyLocation, DirtyPageMap, DomainControl, MemoryCut,
        MemoryDomain, PageIndex, RegisteredRamLayout,
    };
    use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY, kvm_userspace_memory_region};
    use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};

    use crate::vmm::linux::dirty::{
        KvmMemory, KvmSlotBitmap, RegisteredKvmSlot, TrackingState, retain_slot_result, slot_pages,
    };

    fn sealed_domain() -> (Arc<MemoryDomain>, DomainControl, MemoryCut) {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 8192)]).unwrap();
        let (domain, construction, mut control) =
            MemoryDomain::construct(memory, 4096, BackingKind::Boot).unwrap();
        let epoch = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, epoch).unwrap();
        let cut = seal(&mut control);
        (domain, control, cut)
    }

    fn seal(control: &mut DomainControl) -> MemoryCut {
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("unused domain must drain");
        };
        control.seal(&drained).unwrap()
    }

    #[test]
    fn rearm_consumes_only_exact_harvest_once_and_never_clears_retained_union() {
        let (domain, mut control, cut) = sealed_domain();
        let mut retained = DirtyPageMap::new(domain.layout());
        retained.set(PageIndex::new(1)).unwrap();
        let before = retained.words().to_vec();
        let mut tracking = KvmMemory::new();
        tracking.domain = Some(Arc::clone(&domain));
        tracking.state = TrackingState::Harvested {
            epoch: 2,
            cut: cut.generation(),
        };
        let stale = cut.issue_harvest(2).unwrap();
        let epoch = tracking.rearm(&cut, cut.issue_harvest(2).unwrap()).unwrap();
        assert_eq!(epoch.epoch(), 2);
        assert_eq!(tracking.state, TrackingState::Armed(2));
        assert!(tracking.rearm(&cut, cut.issue_harvest(2).unwrap()).is_err());
        assert_eq!(retained.words(), before);
        control.reopen(cut, epoch).unwrap();
        let newer = seal(&mut control);
        tracking.state = TrackingState::Harvested {
            epoch: 3,
            cut: newer.generation(),
        };
        assert!(tracking.rearm(&newer, stale).is_err());
        assert_eq!(
            tracking.state,
            TrackingState::Harvested {
                epoch: 3,
                cut: newer.generation()
            }
        );
        let epoch = tracking
            .rearm(&newer, newer.issue_harvest(3).unwrap())
            .unwrap();
        assert_eq!(epoch.epoch(), 3);
        assert_eq!(retained.words(), before);
    }

    #[test]
    fn rearm_refuses_foreign_cut_wrong_epoch_armed_and_failed_states() {
        let (domain, _, cut) = sealed_domain();
        let (_, _, foreign) = sealed_domain();
        let mut tracking = KvmMemory::new();
        tracking.domain = Some(Arc::clone(&domain));
        tracking.state = TrackingState::Harvested {
            epoch: 2,
            cut: cut.generation(),
        };
        assert!(
            tracking
                .rearm(&foreign, foreign.issue_harvest(2).unwrap())
                .is_err()
        );
        assert!(tracking.rearm(&cut, cut.issue_harvest(3).unwrap()).is_err());
        tracking.state = TrackingState::Armed(2);
        assert!(tracking.rearm(&cut, cut.issue_harvest(2).unwrap()).is_err());
        tracking.state = TrackingState::Failed;
        domain.invalidate_coverage();
        assert!(tracking.rearm(&cut, cut.issue_harvest(2).unwrap()).is_err());
        assert_eq!(tracking.state, TrackingState::Failed);
        assert!(!domain.coverage_valid());
    }

    #[test]
    fn slot_bitmap_uses_exact_native_granule_and_word_tail() {
        for granule in [4096, 16384, 65536] {
            for pages in [1, 63, 64, 65, 127, 128, 129] {
                let mut bitmap = KvmSlotBitmap::new(pages * u64::from(granule), granule).unwrap();
                assert_eq!(bitmap.pages, pages as usize);
                assert_eq!(bitmap.words.len(), (pages as usize).div_ceil(64));
                bitmap.words.fill(u64::MAX);
                bitmap.mask_tail();
                assert_eq!(
                    bitmap
                        .words
                        .iter()
                        .map(|word| word.count_ones() as usize)
                        .sum::<usize>(),
                    pages as usize
                );
                assert!(bitmap.validate(pages * u64::from(granule), granule).is_ok());
                assert!(
                    bitmap
                        .validate((pages + 1) * u64::from(granule), granule)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn slot_bitmap_refuses_empty_unaligned_and_invalid_granules() {
        for (bytes, granule) in [
            (0, 4096),
            (4097, 4096),
            (4096, 0),
            (4096, 8193),
            (4096, 131072),
        ] {
            let error = slot_pages(bytes, granule).unwrap_err();
            assert_eq!(error.effect, DirtyEffect::PreEffectRefusal);
        }
        let mut bitmap = KvmSlotBitmap::new(65 * 4096, 4096).unwrap();
        bitmap.words = vec![0].into_boxed_slice();
        assert!(bitmap.validate(65 * 4096, 4096).is_err());
    }

    #[test]
    fn logging_preserves_actual_address_space_slot_and_nonlogging_flags() {
        let installed = kvm_userspace_memory_region {
            slot: 0x0003_0017,
            flags: KVM_MEM_READONLY,
            guest_phys_addr: 0x24000,
            memory_size: 65 * 4096,
            userspace_addr: 0x10_0000,
        };
        let slot = RegisteredKvmSlot::new(installed);
        let logging = slot.logging_registration();
        assert_eq!(logging.slot, installed.slot);
        assert_eq!(logging.guest_phys_addr, installed.guest_phys_addr);
        assert_eq!(logging.memory_size, installed.memory_size);
        assert_eq!(logging.userspace_addr, installed.userspace_addr);
        assert_eq!(logging.flags, KVM_MEM_READONLY | KVM_MEM_LOG_DIRTY_PAGES);
        assert_eq!(slot.original_flags, KVM_MEM_READONLY);
    }

    #[test]
    fn slot_results_merge_non_word_aligned_regions_and_mask_padding() {
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 3 * 4096),
            (GuestAddress(0x10_0000), 65 * 4096),
            (GuestAddress(0x20_0000), 4096),
        ])
        .unwrap();
        let layout = RegisteredRamLayout::from_memory(&memory, 4096).unwrap();
        let mut retained = DirtyPageMap::new(&layout);
        retained.set(PageIndex::new(0)).unwrap();
        let mut bitmap = KvmSlotBitmap::new(65 * 4096, 4096).unwrap();
        bitmap.words[0] = 1 | (1 << 60) | (1 << 61) | (1 << 63);
        bitmap.words[1] = u64::MAX;
        retain_slot_result(
            &mut bitmap,
            &layout.regions()[1],
            &mut retained,
            0x20017,
            Ok(()),
        )
        .unwrap();
        assert_eq!(bitmap.words[1], 1);
        assert_eq!(
            retained
                .iter_set()
                .map(|page| page.index())
                .collect::<Vec<_>>(),
            [0, 3, 63, 64, 66, 67]
        );
        assert!(!retained.contains(PageIndex::new(68)));
        assert_eq!(layout.page_at(0x8000), None);
    }

    #[test]
    fn failed_slot_retains_successful_prefix_and_delivered_bits_without_acceptance() {
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 3 * 4096),
            (GuestAddress(0x10_0000), 65 * 4096),
        ])
        .unwrap();
        let layout = RegisteredRamLayout::from_memory(&memory, 4096).unwrap();
        let mut retained = DirtyPageMap::new(&layout);
        let mut first = KvmSlotBitmap::new(3 * 4096, 4096).unwrap();
        first.words[0] = 1 << 2;
        retain_slot_result(&mut first, &layout.regions()[0], &mut retained, 7, Ok(())).unwrap();
        let mut second = KvmSlotBitmap::new(65 * 4096, 4096).unwrap();
        second.words[0] = 1 << 63;
        second.words[1] = u64::MAX;
        let error = retain_slot_result(
            &mut second,
            &layout.regions()[1],
            &mut retained,
            0x30011,
            Err(14),
        )
        .unwrap_err();
        assert_eq!(error.effect, DirtyEffect::CoverageLost);
        assert_eq!(error.location, DirtyLocation::Slot(0x30011));
        assert_eq!(error.native_code, 14);
        assert_eq!(
            retained
                .iter_set()
                .map(|page| page.index())
                .collect::<Vec<_>>(),
            [2, 66, 67]
        );
        second.words.fill(0);
        retain_slot_result(
            &mut second,
            &layout.regions()[1],
            &mut retained,
            0x30011,
            Ok(()),
        )
        .unwrap();
        assert_eq!(
            retained
                .iter_set()
                .map(|page| page.index())
                .collect::<Vec<_>>(),
            [2, 66, 67]
        );
    }

    #[test]
    fn registration_reserves_inventory_and_retains_backing_once() {
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 4096),
            (GuestAddress(0x20_0000), 4096),
        ])
        .unwrap();
        let mut tracking = KvmMemory::new();
        tracking.prepare_registration(&memory).unwrap();
        assert!(tracking.slots.capacity() >= memory.num_regions());
        assert!(tracking.backing.is_some());
        assert!(tracking.prepare_registration(&memory).is_err());
        assert!(tracking.slots.is_empty());
    }

    #[test]
    fn tracked_restore_prepares_every_logging_registration_before_effects() {
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 3 * 4096),
            (GuestAddress(0x10_0000), 65 * 4096),
        ])
        .unwrap();
        let (domain, authority, _) =
            MemoryDomain::construct(memory.clone(), 4096, BackingKind::Boot).unwrap();
        let mut tracking = KvmMemory::new();
        let (epoch, planned) = tracking.prepare_tracked(&domain, &authority).unwrap();
        assert_eq!(epoch.epoch(), 1);
        assert_eq!(planned.len(), 2);
        assert!(tracking.slots.is_empty());
        assert!(tracking.slots.capacity() >= planned.len());
        assert!(tracking.backing.is_some());
        for ((slot, region), mapping) in planned
            .iter()
            .zip(domain.layout().regions())
            .zip(memory.iter())
        {
            assert_eq!(slot.installed.slot as usize, region.id().index());
            assert_eq!(slot.original_flags, 0);
            assert_eq!(slot.installed.flags, KVM_MEM_LOG_DIRTY_PAGES);
            assert_eq!(slot.region, Some(region.id()));
            assert!(slot.matches_region(region, mapping.as_ptr() as u64));
            let bitmap = slot.dirty.as_ref().unwrap();
            bitmap.validate(mapping.len(), 4096).unwrap();
            assert!(bitmap.words.iter().all(|word| *word == 0));
        }
    }

    #[test]
    fn tracked_restore_refuses_foreign_authority_before_preparing_records() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        let (domain, _, _) =
            MemoryDomain::construct(memory.clone(), 4096, BackingKind::Boot).unwrap();
        let (_, foreign, _) = MemoryDomain::construct(memory, 4096, BackingKind::Boot).unwrap();
        assert!(!Arc::ptr_eq(&domain, foreign.domain()));
        let mut tracking = KvmMemory::new();
        let error = tracking.prepare_tracked(&domain, &foreign).err().unwrap();
        assert_eq!(error.effect, DirtyEffect::PreEffectRefusal);
        assert!(tracking.backing.is_none());
        assert!(tracking.slots.is_empty());
    }
}
