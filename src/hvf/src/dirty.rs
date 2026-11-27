// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! The sole stage-two permission owner for capture RAM. Reclaim and external
//! mapping changes are excluded before this owner can arm a CPU epoch.

use std::sync::{Arc, Mutex, MutexGuard};

use arch::guest_memory::{
    ConstructionAuthority, CpuHarvest, CpuTrackingEpoch, DirtyEffect, DirtyFailure, DirtyLocation,
    DirtyOperation, DirtyPageMap, MemoryCut, MemoryDomain, PageIndex, RamPermissions, RegionId,
    TrackingMode,
};

use crate::bindings::{
    HV_SUCCESS, hv_vcpu_exit_exception_t, hv_vcpu_t, hv_vm_map, hv_vm_protect, hv_vm_unmap,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Unarmed,
    Disabled,
    Armed(u64),
    Failed,
}

impl Lifecycle {
    fn next_epoch(self, harvested: u64) -> Option<u64> {
        if self == Self::Armed(harvested) {
            harvested.checked_add(1)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
struct Mapping {
    region: Option<RegionId>,
    host: u64,
    guest: u64,
    len: u64,
    permissions: RamPermissions,
}

impl Mapping {
    fn recovery_permissions(&self) -> Option<u8> {
        let permissions = self.permissions.bits();
        (permissions & RamPermissions::WRITE != 0).then_some(permissions & !RamPermissions::WRITE)
    }
}

struct EpochPages {
    dirty: DirtyPageMap,
    writable: DirtyPageMap,
}

struct ProtectionInner {
    domain: Option<Arc<MemoryDomain>>,
    mappings: Vec<Mapping>,
    lifecycle: Lifecycle,
    pages: Option<EpochPages>,
    epoch: Option<CpuTrackingEpoch>,
    last_issued_epoch: u64,
}

pub struct HvfRamProtection {
    inner: Mutex<ProtectionInner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyFaultResolution {
    NotHandled,
    Retry,
}

fn failure(
    operation: DirtyOperation,
    location: DirtyLocation,
    effect: DirtyEffect,
    native_code: i64,
) -> DirtyFailure {
    DirtyFailure {
        operation,
        location,
        effect,
        native_code,
    }
}

fn refused(operation: DirtyOperation) -> DirtyFailure {
    failure(
        operation,
        DirtyLocation::Vm,
        DirtyEffect::PreEffectRefusal,
        0,
    )
}

impl Default for HvfRamProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl HvfRamProtection {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ProtectionInner {
                domain: None,
                mappings: Vec::new(),
                lifecycle: Lifecycle::Unarmed,
                pages: None,
                epoch: None,
                last_issued_epoch: 0,
            }),
        }
    }

    fn lock(
        &self,
        operation: DirtyOperation,
    ) -> Result<MutexGuard<'_, ProtectionInner>, DirtyFailure> {
        match self.inner.lock() {
            Ok(inner) => Ok(inner),
            Err(poison) => {
                poison.into_inner().fail();
                Err(failure(
                    operation,
                    DirtyLocation::Vm,
                    DirtyEffect::ProtectionUnknown,
                    0,
                ))
            }
        }
    }

    pub fn bind(&self, domain: Arc<MemoryDomain>) -> Result<(), DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Bind)?;
        if inner.domain.is_some() || inner.lifecycle != Lifecycle::Unarmed {
            return Err(refused(DirtyOperation::Bind));
        }
        let layout = domain.layout();
        if inner.mappings.len() != layout.regions().len() {
            return Err(refused(DirtyOperation::Bind));
        }
        for (mapping, region) in inner.mappings.iter_mut().zip(layout.regions()) {
            if mapping.guest != region.guest_range().start()
                || mapping.len != region.guest_range().byte_len()
                || mapping.permissions != region.permissions()
                || mapping.host.checked_add(mapping.len).is_none()
                || !domain.matches_region_mapping(region.id(), mapping.host)
            {
                return Err(refused(DirtyOperation::Bind));
            }
            mapping.region = Some(region.id());
        }
        inner.domain = Some(domain);
        Ok(())
    }

    pub fn check_mapping_mutation(&self) -> Result<(), DirtyFailure> {
        let inner = self.lock(DirtyOperation::Bind)?;
        inner.allow_mapping_mutation()
    }

    pub fn reserve_mappings(&self, count: usize) -> Result<(), DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Bind)?;
        if inner.domain.is_some() || inner.lifecycle != Lifecycle::Unarmed {
            return Err(refused(DirtyOperation::Bind));
        }
        inner
            .mappings
            .try_reserve(count)
            .map_err(|_| refused(DirtyOperation::Bind))
    }

    pub(crate) fn map_memory(
        &self,
        host: u64,
        guest: u64,
        len: u64,
        permissions: RamPermissions,
    ) -> Result<(), crate::Error> {
        let mut inner = self
            .lock(DirtyOperation::Bind)
            .map_err(crate::Error::DirtyTracking)?;
        inner
            .allow_mapping_mutation()
            .map_err(crate::Error::DirtyTracking)?;
        let size = len.try_into().map_err(|_| crate::Error::MemorySize)?;
        if len == 0 || guest.checked_add(len).is_none() || host.checked_add(len).is_none() {
            return Err(crate::Error::MemorySize);
        }
        let retain_registration = inner.lifecycle == Lifecycle::Unarmed;
        if retain_registration {
            inner
                .mappings
                .try_reserve(1)
                .map_err(|_| crate::Error::MemorySize)?;
        }
        let result = unsafe {
            hv_vm_map(
                host as *mut core::ffi::c_void,
                guest,
                size,
                permissions.bits().into(),
            )
        };
        if result != HV_SUCCESS {
            return Err(crate::Error::MemoryMap);
        }
        if retain_registration {
            inner.mappings.push(Mapping {
                region: None,
                host,
                guest,
                len,
                permissions,
            });
        }
        Ok(())
    }

    pub(crate) fn unmap_memory(&self, guest: u64, len: u64) -> Result<(), crate::Error> {
        let mut inner = self
            .lock(DirtyOperation::Bind)
            .map_err(crate::Error::DirtyTracking)?;
        inner
            .allow_mapping_mutation()
            .map_err(crate::Error::DirtyTracking)?;
        let size = len.try_into().map_err(|_| crate::Error::MemorySize)?;
        let result = unsafe { hv_vm_unmap(guest, size) };
        if result != HV_SUCCESS {
            return Err(crate::Error::MemoryUnmap);
        }
        inner
            .mappings
            .retain(|mapping| mapping.guest != guest || mapping.len != len);
        Ok(())
    }

    pub fn arm_initial(
        &self,
        authority: &ConstructionAuthority,
    ) -> Result<CpuTrackingEpoch, DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Arm)?;
        if inner.lifecycle != Lifecycle::Unarmed {
            return Err(refused(DirtyOperation::Arm));
        }
        let domain = inner
            .domain
            .clone()
            .ok_or_else(|| refused(DirtyOperation::Arm))?;
        let epoch = authority
            .issue_epoch(1)
            .map_err(|_| refused(DirtyOperation::Arm))?;
        epoch
            .validate_domain(&domain)
            .map_err(|_| refused(DirtyOperation::Arm))?;
        domain
            .layout()
            .validate_capture()
            .map_err(|_| refused(DirtyOperation::Arm))?;
        inner.pages = Some(EpochPages {
            dirty: DirtyPageMap::new(domain.layout()),
            writable: DirtyPageMap::new(domain.layout()),
        });
        // No partial protection pass can become an executable epoch.
        inner.lifecycle = Lifecycle::Failed;
        for mapping in &inner.mappings {
            if mapping.permissions.bits() & RamPermissions::WRITE != 0 {
                protect(
                    mapping.guest,
                    mapping.len,
                    mapping.permissions.bits() & !RamPermissions::WRITE,
                )
                .map_err(|code| {
                    domain.invalidate_coverage();
                    failure(
                        DirtyOperation::Arm,
                        mapping
                            .region
                            .map_or(DirtyLocation::Vm, DirtyLocation::Region),
                        DirtyEffect::ProtectionUnknown,
                        code,
                    )
                })?;
            }
        }
        inner.lifecycle = Lifecycle::Armed(1);
        inner.last_issued_epoch = 1;
        inner.epoch = Some(epoch.clone());
        Ok(epoch)
    }

    pub fn entered_epoch(&self, vcpu: hv_vcpu_t) -> Result<Option<CpuTrackingEpoch>, DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Fault)?;
        if let Some(domain) = &inner.domain {
            match domain.tracking_mode() {
                Some(TrackingMode::Disabled) if inner.lifecycle == Lifecycle::Unarmed => {
                    inner.lifecycle = Lifecycle::Disabled;
                    inner.mappings = Vec::new();
                }
                Some(TrackingMode::Disabled) => {}
                Some(TrackingMode::Capture) => {}
                None => return Err(refused(DirtyOperation::Fault)),
            }
        }
        match inner.lifecycle {
            Lifecycle::Disabled => Ok(None),
            Lifecycle::Armed(_) => inner
                .epoch
                .clone()
                .map(Some)
                .ok_or_else(|| refused(DirtyOperation::Fault)),
            _ => {
                inner.log_fault_rejection("entered_epoch", vcpu, None);
                Err(failure(
                    DirtyOperation::Fault,
                    DirtyLocation::Vm,
                    DirtyEffect::ProtectionUnknown,
                    0,
                ))
            }
        }
    }

    /// Standalone untracked HVF users finalize their policy with reclaim setup.
    pub(crate) fn finalize_untracked(&self) -> Result<(), DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Bind)?;
        if inner.domain.is_none() && inner.lifecycle == Lifecycle::Unarmed {
            inner.lifecycle = Lifecycle::Disabled;
            inner.mappings = Vec::new();
            Ok(())
        } else if inner
            .domain
            .as_ref()
            .is_some_and(|domain| domain.tracking_mode() == Some(TrackingMode::Disabled))
            && matches!(inner.lifecycle, Lifecycle::Unarmed | Lifecycle::Disabled)
        {
            inner.lifecycle = Lifecycle::Disabled;
            inner.mappings = Vec::new();
            Ok(())
        } else {
            Err(refused(DirtyOperation::Bind))
        }
    }

    pub fn handle_ram_write_fault(
        &self,
        vcpu: hv_vcpu_t,
        entered: &CpuTrackingEpoch,
        exception: &hv_vcpu_exit_exception_t,
    ) -> Result<DirtyFaultResolution, DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Fault)?;
        let domain = inner
            .domain
            .clone()
            .ok_or_else(|| refused(DirtyOperation::Fault))?;
        if entered.validate_domain(&domain).is_err()
            || inner.lifecycle != Lifecycle::Armed(entered.epoch())
        {
            inner.log_fault_rejection("validate_entered", vcpu, Some((entered, exception)));
            inner.fail();
            return Err(failure(
                DirtyOperation::Fault,
                DirtyLocation::Vm,
                DirtyEffect::ProtectionUnknown,
                0,
            ));
        }
        let syndrome = exception.syndrome;
        let ipa = exception.physical_address;
        let page = domain.layout().page_at(ipa);
        let mapping = inner
            .mappings
            .iter()
            .find(|mapping| ipa >= mapping.guest && ipa - mapping.guest < mapping.len)
            .copied();
        if page.is_none() && valid_mmio_translation(syndrome) {
            return Ok(DirtyFaultResolution::NotHandled);
        }
        if !qualified_ram_write(syndrome)
            || mapping.is_none_or(|mapping| mapping.permissions.bits() & RamPermissions::WRITE == 0)
        {
            inner.log_fault_rejection("handle_ram_write_fault", vcpu, Some((entered, exception)));
            inner.fail();
            return Err(failure(
                DirtyOperation::Fault,
                DirtyLocation::Vm,
                DirtyEffect::ProtectionUnknown,
                0,
            ));
        }
        let page = page.ok_or_else(|| refused(DirtyOperation::Fault))?;
        let mapping = mapping.ok_or_else(|| refused(DirtyOperation::Fault))?;
        let granule = u64::from(domain.layout().granule());
        let marked = inner
            .pages
            .as_mut()
            .ok_or_else(|| refused(DirtyOperation::Fault))?
            .dirty
            .set(page);
        if marked.is_err() {
            inner.fail();
            return Err(failure(
                DirtyOperation::Fault,
                DirtyLocation::Page(page),
                DirtyEffect::ProtectionUnknown,
                0,
            ));
        }
        if inner
            .pages
            .as_ref()
            .is_some_and(|pages| pages.writable.contains(page))
        {
            return Ok(DirtyFaultResolution::Retry);
        }
        let page_gpa = ipa & !(granule - 1);
        if let Err(code) = protect(page_gpa, granule, mapping.permissions.bits()) {
            inner.fail();
            return Err(failure(
                DirtyOperation::Fault,
                DirtyLocation::Page(page),
                DirtyEffect::ProtectionUnknown,
                code,
            ));
        }
        if inner
            .pages
            .as_mut()
            .ok_or_else(|| refused(DirtyOperation::Fault))?
            .writable
            .set(page)
            .is_err()
        {
            inner.fail();
            return Err(failure(
                DirtyOperation::Fault,
                DirtyLocation::Page(page),
                DirtyEffect::ProtectionUnknown,
                0,
            ));
        }
        Ok(DirtyFaultResolution::Retry)
    }

    pub fn reject_instruction_fault(
        &self,
        vcpu: hv_vcpu_t,
        entered: &CpuTrackingEpoch,
        exception: &hv_vcpu_exit_exception_t,
    ) -> DirtyFailure {
        match self.lock(DirtyOperation::Fault) {
            Ok(mut inner) => {
                inner.log_fault_rejection(
                    "reject_instruction_fault",
                    vcpu,
                    Some((entered, exception)),
                );
                inner.fail();
                failure(
                    DirtyOperation::Fault,
                    DirtyLocation::Vm,
                    DirtyEffect::ProtectionUnknown,
                    0,
                )
            }
            Err(error) => error,
        }
    }

    pub fn collect_cpu_dirty(
        &self,
        cut: &MemoryCut,
        retained: &mut DirtyPageMap,
    ) -> Result<CpuHarvest, DirtyFailure> {
        let inner = self.lock(DirtyOperation::Collect)?;
        let domain = inner
            .domain
            .as_ref()
            .ok_or_else(|| refused(DirtyOperation::Collect))?;
        cut.validate_domain(domain)
            .map_err(|_| refused(DirtyOperation::Collect))?;
        let pages = inner
            .pages
            .as_ref()
            .ok_or_else(|| refused(DirtyOperation::Collect))?;
        // Even a failed permission epoch retains all already-known dirties.
        retained
            .merge(&pages.dirty)
            .map_err(|_| refused(DirtyOperation::Collect))?;
        let Lifecycle::Armed(epoch) = inner.lifecycle else {
            return Err(failure(
                DirtyOperation::Collect,
                DirtyLocation::Vm,
                DirtyEffect::ProtectionUnknown,
                0,
            ));
        };
        cut.issue_harvest(epoch)
            .map_err(|_| refused(DirtyOperation::Collect))
    }

    pub fn rearm_cpu_dirty(
        &self,
        cut: &MemoryCut,
        harvested: CpuHarvest,
    ) -> Result<CpuTrackingEpoch, DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Rearm)?;
        let domain = inner
            .domain
            .clone()
            .ok_or_else(|| refused(DirtyOperation::Rearm))?;
        cut.validate_domain(&domain)
            .map_err(|_| refused(DirtyOperation::Rearm))?;
        harvested
            .validate_cut(cut)
            .map_err(|_| refused(DirtyOperation::Rearm))?;
        let next = inner
            .lifecycle
            .next_epoch(harvested.epoch())
            .ok_or_else(|| refused(DirtyOperation::Rearm))?;
        let epoch = cut
            .issue_epoch(next)
            .map_err(|_| refused(DirtyOperation::Rearm))?;
        inner.lifecycle = Lifecycle::Failed;
        {
            let pages = inner
                .pages
                .as_ref()
                .ok_or_else(|| refused(DirtyOperation::Rearm))?;
            let granule = u64::from(domain.layout().granule());
            let mut written = pages.writable.iter_set().peekable();
            for region in domain.layout().regions() {
                let end =
                    region.first_page() + (region.guest_range().byte_len() / granule) as usize;
                while let Some((first, run_end)) = next_written_run(&mut written, end) {
                    if first.index() < region.first_page() {
                        domain.invalidate_coverage();
                        return Err(failure(
                            DirtyOperation::Rearm,
                            DirtyLocation::Page(first),
                            DirtyEffect::ProtectionUnknown,
                            0,
                        ));
                    }
                    let gpa = region.guest_range().start()
                        + (first.index() - region.first_page()) as u64 * granule;
                    let len = (run_end - first.index()) as u64 * granule;
                    protect(
                        gpa,
                        len,
                        region.permissions().bits() & !RamPermissions::WRITE,
                    )
                    .map_err(|code| {
                        domain.invalidate_coverage();
                        failure(
                            DirtyOperation::Rearm,
                            DirtyLocation::Region(region.id()),
                            DirtyEffect::ProtectionUnknown,
                            code,
                        )
                    })?;
                }
            }
            if written.next().is_some() {
                domain.invalidate_coverage();
                return Err(failure(
                    DirtyOperation::Rearm,
                    DirtyLocation::Vm,
                    DirtyEffect::ProtectionUnknown,
                    0,
                ));
            }
        }
        let pages = inner
            .pages
            .as_mut()
            .ok_or_else(|| refused(DirtyOperation::Rearm))?;
        pages.dirty.clear();
        pages.writable.clear();
        inner.lifecycle = Lifecycle::Armed(next);
        inner.last_issued_epoch = next;
        inner.epoch = Some(epoch.clone());
        Ok(epoch)
    }

    pub fn reestablish_cpu_dirty(
        &self,
        cut: &MemoryCut,
        retained: &mut DirtyPageMap,
    ) -> Result<CpuTrackingEpoch, DirtyFailure> {
        let mut inner = self.lock(DirtyOperation::Reestablish)?;
        let epoch = inner.prepare_reestablishment(cut, retained)?;
        let pages = inner
            .pages
            .as_ref()
            .ok_or_else(|| refused(DirtyOperation::Reestablish))?;
        retained
            .merge(&pages.dirty)
            .map_err(|_| refused(DirtyOperation::Reestablish))?;
        for index in 0..inner.mappings.len() {
            let mapping = inner.mappings[index];
            if let Some(permissions) = mapping.recovery_permissions() {
                let result = protect(mapping.guest, mapping.len, permissions);
                inner.record_reestablishment_result(mapping, result)?;
            }
        }
        let pages = inner
            .pages
            .as_mut()
            .ok_or_else(|| refused(DirtyOperation::Reestablish))?;
        pages.dirty.clear();
        pages.writable.clear();
        inner.last_issued_epoch = epoch.epoch();
        inner.lifecycle = Lifecycle::Armed(epoch.epoch());
        inner.epoch = Some(epoch.clone());
        Ok(epoch)
    }
}

impl ProtectionInner {
    #[cold]
    fn log_fault_rejection(
        &self,
        path: &str,
        vcpu: hv_vcpu_t,
        fault: Option<(&CpuTrackingEpoch, &hv_vcpu_exit_exception_t)>,
    ) {
        let lifecycle = self.lifecycle;
        let armed_epoch = match lifecycle {
            Lifecycle::Armed(epoch) => Some(epoch),
            _ => None,
        };
        let published_epoch = self.epoch.as_ref().map(CpuTrackingEpoch::epoch);
        if let Some((entered, exception)) = fault {
            let syndrome = exception.syndrome;
            let ec = (syndrome >> 26) & 0x3f;
            let fsc = syndrome & 0x3f;
            let wnr = (syndrome >> 6) & 1;
            let s1ptw = (syndrome >> 7) & 1;
            let cm = (syndrome >> 8) & 1;
            let fnv = (syndrome >> 10) & 1;
            let ipa = exception.physical_address;
            let va = exception.virtual_address;
            let page = self
                .domain
                .as_ref()
                .and_then(|domain| domain.layout().page_at(ipa))
                .map(PageIndex::index);
            log::error!(
                "HVF dirty tracking rejected: path={path} vcpu={vcpu} ec={ec:#04x} \
                 syndrome={syndrome:#018x} fsc={fsc:#04x} wnr={wnr} s1ptw={s1ptw} cm={cm} \
                 fnv={fnv} ipa={ipa:#x} va={va:#x} tracked_ram={} page={page:?} \
                 entered_epoch={} armed_epoch={armed_epoch:?} published_epoch={published_epoch:?} \
                 lifecycle={lifecycle:?}",
                page.is_some(),
                entered.epoch(),
            );
        } else {
            // Admission failed before hv_vcpu_run; the exit record is not from this entry.
            log::error!(
                "HVF dirty tracking rejected: path={path} vcpu={vcpu} ec=None syndrome=None \
                 fsc=None wnr=None s1ptw=None cm=None fnv=None ipa=None va=None tracked_ram=None \
                 page=None entered_epoch=None armed_epoch={armed_epoch:?} \
                 published_epoch={published_epoch:?} lifecycle={lifecycle:?}"
            );
        }
    }

    fn next_reestablishment_epoch(&self) -> Result<u64, DirtyFailure> {
        if self.lifecycle != Lifecycle::Failed || self.last_issued_epoch == 0 {
            return Err(refused(DirtyOperation::Reestablish));
        }
        self.last_issued_epoch
            .checked_add(1)
            .ok_or_else(|| refused(DirtyOperation::Reestablish))
    }

    fn prepare_reestablishment(
        &self,
        cut: &MemoryCut,
        retained: &DirtyPageMap,
    ) -> Result<CpuTrackingEpoch, DirtyFailure> {
        let refusal = || refused(DirtyOperation::Reestablish);
        let next = self.next_reestablishment_epoch()?;
        let domain = self.domain.as_ref().ok_or_else(refusal)?;
        cut.validate_domain(domain).map_err(|_| refusal())?;
        let pages = self.pages.as_ref().ok_or_else(refusal)?;
        let count = domain.layout().page_count();
        if domain.tracking_mode() != Some(TrackingMode::Capture)
            || retained.page_count() != count
            || pages.dirty.page_count() != count
            || pages.writable.page_count() != count
            || self.mappings.len() != domain.layout().regions().len()
        {
            return Err(refusal());
        }
        for (mapping, region) in self.mappings.iter().zip(domain.layout().regions()) {
            if mapping.region != Some(region.id())
                || mapping.guest != region.guest_range().start()
                || mapping.len != region.guest_range().byte_len()
                || mapping.permissions != region.permissions()
                || mapping.host.checked_add(mapping.len).is_none()
                || usize::try_from(mapping.len).is_err()
                || !domain.matches_region_mapping(region.id(), mapping.host)
            {
                return Err(failure(
                    DirtyOperation::Reestablish,
                    DirtyLocation::Region(region.id()),
                    DirtyEffect::PreEffectRefusal,
                    0,
                ));
            }
        }
        cut.issue_epoch(next).map_err(|_| refusal())
    }

    fn record_reestablishment_result(
        &mut self,
        mapping: Mapping,
        result: Result<(), i64>,
    ) -> Result<(), DirtyFailure> {
        result.map_err(|code| {
            self.fail();
            failure(
                DirtyOperation::Reestablish,
                mapping
                    .region
                    .map_or(DirtyLocation::Vm, DirtyLocation::Region),
                DirtyEffect::ProtectionUnknown,
                code,
            )
        })
    }

    fn fail(&mut self) {
        self.lifecycle = Lifecycle::Failed;
        if let Some(domain) = &self.domain {
            domain.invalidate_coverage();
        }
    }

    fn allow_mapping_mutation(&self) -> Result<(), DirtyFailure> {
        if matches!(self.lifecycle, Lifecycle::Unarmed | Lifecycle::Disabled)
            && self
                .domain
                .as_ref()
                .is_none_or(|domain| domain.tracking_mode() != Some(TrackingMode::Capture))
        {
            if let Some(domain) = &self.domain {
                domain
                    .with_external_mapping(|_| ())
                    .map_err(|_| refused(DirtyOperation::Bind))?;
            }
            Ok(())
        } else {
            Err(refused(DirtyOperation::Bind))
        }
    }
}

fn next_written_run(
    written: &mut std::iter::Peekable<impl Iterator<Item = PageIndex>>,
    region_end: usize,
) -> Option<(PageIndex, usize)> {
    if written.peek().is_none_or(|page| page.index() >= region_end) {
        return None;
    }
    let first = written.next()?;
    let mut end = first.index() + 1;
    while written
        .peek()
        .is_some_and(|page| page.index() == end && page.index() < region_end)
    {
        written.next();
        end += 1;
    }
    Some((first, end))
}

fn protect(gpa: u64, len: u64, permissions: u8) -> Result<(), i64> {
    let size = len.try_into().map_err(|_| -1)?;
    let status = unsafe { hv_vm_protect(gpa, size, permissions.into()) };
    if status == HV_SUCCESS {
        Ok(())
    } else {
        Err(i64::from(status))
    }
}

/// A guest data write that stage 2 refused. HVF reports the first write to a
/// write-protected page it has not populated yet as a translation fault and
/// later ones as permission faults. When the host has cleared the access flag
/// of that stage 2 entry (page aging under memory pressure) the same write
/// arrives as an access flag fault, which the architecture ranks above a
/// permission fault. All three mean the same thing for a tracked RAM page.
/// Whether the address is RAM is decided by the caller, not the syndrome.
fn qualified_ram_write(syndrome: u64) -> bool {
    matches!((syndrome >> 26) & 0x3f, 0x24 | 0x25)
        && matches!(syndrome & 0x3f, 0x04..=0x0f)
        && syndrome & (1 << 6) != 0
        && syndrome & ((1 << 7) | (1 << 8) | (1 << 10)) == 0
}

fn valid_mmio_translation(syndrome: u64) -> bool {
    matches!((syndrome >> 26) & 0x3f, 0x24 | 0x25)
        && matches!(syndrome & 0x3f, 0x04..=0x07)
        && syndrome & (1 << 24) != 0
        && syndrome & ((1 << 7) | (1 << 8) | (1 << 10)) == 0
}

#[cfg(test)]
mod tests {
    use arch::guest_memory::{
        BackingKind, DirtyEffect, DirtyLocation, DirtyOperation, MemoryDomain,
    };

    use crate::bindings::hv_vcpu_exit_exception_t;
    use crate::dirty::{
        DirtyFaultResolution, HvfRamProtection, Lifecycle, qualified_ram_write,
        valid_mmio_translation,
    };

    #[test]
    fn ram_write_classifier_does_not_require_scalar_emulation_syndrome() {
        for ec in [0x24, 0x25] {
            for level in 0x04..=0x0f {
                let syndrome = (ec << 26) | (1 << 6) | level;
                assert!(qualified_ram_write(syndrome));
                assert!(qualified_ram_write(syndrome | (1 << 24)));
                for unsupported in [1 << 7, 1 << 8, 1 << 10] {
                    assert!(!qualified_ram_write(syndrome | unsupported));
                }
                assert!(!qualified_ram_write(syndrome & !(1 << 6)));
            }
        }
        for ec in [0x20, 0x21, 0, 0x3f] {
            for flags in [0, 1 << 6, 1 << 7] {
                assert!(!qualified_ram_write((ec << 26) | flags | 0x0f));
            }
        }
        for status in [0, 3, 16, 63] {
            assert!(!qualified_ram_write((0x24 << 26) | (1 << 6) | status));
        }
    }

    #[test]
    fn write_to_a_protected_page_whose_access_flag_was_cleared_is_a_ram_write() {
        // Observed on M5 under host load right after a resume: level 3 access
        // flag fault, WnR set, on a tracked page; the other vCPU reported the
        // same page as a level 3 permission fault.
        for (syndrome, write) in [
            (0x93df_804b, true),
            (0x93df_804f, true),
            (0x93df_800b, false),
            (0x93df_808b, false),
        ] {
            assert_eq!(qualified_ram_write(syndrome), write, "{syndrome:#x}");
        }
    }

    #[test]
    fn first_write_to_an_unpopulated_protected_page_is_a_ram_write() {
        // The first scalar store observed on M5 gives a level 3 translation
        // fault with WnR and no valid ISS. DC ZVA also uses WnR, not CM.
        for (syndrome, write) in [
            (0x9200_0047, true),
            (0x9200_004f, true),
            (0x9200_0147, false),
            (0x9200_0087, false),
            (0x9200_0487, false),
        ] {
            assert_eq!(qualified_ram_write(syndrome), write, "{syndrome:#x}");
            assert!(!valid_mmio_translation(syndrome), "{syndrome:#x}");
        }
    }

    #[test]
    fn mmio_translation_requires_a_decoded_access() {
        for status in 0..64 {
            let syndrome = (0x24 << 26) | (1 << 24) | (1 << 6) | status;
            assert_eq!(valid_mmio_translation(syndrome), (4..=7).contains(&status));
            assert!(!valid_mmio_translation(syndrome & !(1 << 24)));
            assert!(!valid_mmio_translation(syndrome | (1 << 7)));
        }
    }

    #[test]
    fn epoch_identity_does_not_admit_duplicates_from_previous_epochs() {
        let abort = hv_vcpu_exit_exception_t {
            // A decoded MMIO fault would otherwise be passed through.
            syndrome: 0x9300_0047,
            virtual_address: 0x8000,
            physical_address: 0x4000,
        };
        for (lifecycle, entered) in [
            (Lifecycle::Armed(2), 1),
            (Lifecycle::Unarmed, 2),
            (Lifecycle::Disabled, 2),
            (Lifecycle::Failed, 2),
        ] {
            let (domain, authority, _) =
                MemoryDomain::construct(Default::default(), 16384, BackingKind::Boot).unwrap();
            let current = authority.issue_epoch(2).unwrap();
            let entered = authority.issue_epoch(entered).unwrap();
            let protection = HvfRamProtection::new();
            protection.bind(domain.clone()).unwrap();
            {
                let mut inner = protection.lock(DirtyOperation::Fault).unwrap();
                inner.lifecycle = lifecycle;
                inner.epoch = Some(current.clone());
            }
            if lifecycle == Lifecycle::Armed(2) {
                for _ in 0..2 {
                    assert_eq!(
                        protection.handle_ram_write_fault(0, &current, &abort),
                        Ok(DirtyFaultResolution::NotHandled)
                    );
                }
            }
            let error = protection
                .handle_ram_write_fault(0, &entered, &abort)
                .unwrap_err();
            assert_eq!(error.operation, DirtyOperation::Fault);
            assert_eq!(error.location, DirtyLocation::Vm);
            assert_eq!(error.effect, DirtyEffect::ProtectionUnknown);
            assert_eq!(error.native_code, 0);
            assert_eq!(
                protection.lock(DirtyOperation::Fault).unwrap().lifecycle,
                Lifecycle::Failed
            );
            assert!(!domain.coverage_valid());
        }
    }

    #[test]
    fn instruction_abort_while_armed_still_invalidates_coverage() {
        for syndrome in [0x8200_000f, 0x8200_008f] {
            let (domain, authority, _) =
                MemoryDomain::construct(Default::default(), 16384, BackingKind::Boot).unwrap();
            let epoch = authority.issue_epoch(1).unwrap();
            let protection = HvfRamProtection::new();
            protection.bind(domain.clone()).unwrap();
            {
                let mut inner = protection.lock(DirtyOperation::Fault).unwrap();
                inner.lifecycle = Lifecycle::Armed(1);
                inner.epoch = Some(epoch.clone());
            }
            let error = protection.reject_instruction_fault(
                0,
                &epoch,
                &hv_vcpu_exit_exception_t {
                    syndrome,
                    virtual_address: 0x8000,
                    physical_address: 0x4000,
                },
            );
            assert_eq!(error.effect, DirtyEffect::ProtectionUnknown);
            assert!(!domain.coverage_valid());
            assert_eq!(
                protection.lock(DirtyOperation::Fault).unwrap().lifecycle,
                Lifecycle::Failed
            );
        }
    }

    #[test]
    fn rearm_requires_the_exact_epoch_and_never_wraps() {
        assert_eq!(Lifecycle::Armed(1).next_epoch(1), Some(2));
        assert_eq!(Lifecycle::Armed(2).next_epoch(1), None);
        assert_eq!(Lifecycle::Armed(u64::MAX).next_epoch(u64::MAX), None);
        for state in [Lifecycle::Unarmed, Lifecycle::Disabled, Lifecycle::Failed] {
            assert_eq!(state.next_epoch(1), None);
        }
    }

    #[test]
    fn written_runs_cross_bitmap_words_but_never_region_boundaries() {
        use crate::dirty::next_written_run;
        use arch::guest_memory::PageIndex;

        let mut written = [0, 62, 63, 64, 65, 127, 128, 130]
            .map(PageIndex::new)
            .into_iter()
            .peekable();
        assert_eq!(
            next_written_run(&mut written, 64),
            Some((PageIndex::new(0), 1))
        );
        assert_eq!(
            next_written_run(&mut written, 64),
            Some((PageIndex::new(62), 64))
        );
        assert_eq!(next_written_run(&mut written, 64), None);
        assert_eq!(
            next_written_run(&mut written, 131),
            Some((PageIndex::new(64), 66))
        );
        assert_eq!(
            next_written_run(&mut written, 131),
            Some((PageIndex::new(127), 129))
        );
        assert_eq!(
            next_written_run(&mut written, 131),
            Some((PageIndex::new(130), 131))
        );
        assert_eq!(next_written_run(&mut written, 131), None);
        let mut empty = std::iter::empty().peekable();
        assert_eq!(next_written_run(&mut empty, usize::MAX), None);
    }

    #[test]
    fn construction_and_failed_owners_cannot_enter_or_fall_back_to_untracked() {
        let protection = HvfRamProtection::new();
        assert!(protection.entered_epoch(0).is_err());
        assert!(protection.check_mapping_mutation().is_ok());
        match protection.lock(DirtyOperation::Fault) {
            Ok(mut inner) => inner.fail(),
            Err(error) => panic!("new protection owner unexpectedly failed: {error:?}"),
        }
        assert!(protection.entered_epoch(0).is_err());
        assert!(protection.finalize_untracked().is_err());
        assert!(protection.check_mapping_mutation().is_err());
        assert!(matches!(
            protection
                .entered_epoch(0)
                .err()
                .map(|failure| failure.effect),
            Some(DirtyEffect::ProtectionUnknown)
        ));
    }

    #[test]
    fn recovery_counter_survives_failure_and_refuses_unissued_or_exhausted_epochs() {
        use crate::dirty::HvfRamProtection;
        use arch::guest_memory::DirtyOperation;

        let protection = HvfRamProtection::new();
        let mut inner = protection.lock(DirtyOperation::Reestablish).unwrap();
        inner.lifecycle = Lifecycle::Armed(7);
        inner.last_issued_epoch = 7;
        assert!(inner.next_reestablishment_epoch().is_err());
        inner.fail();
        assert_eq!(inner.last_issued_epoch, 7);
        assert_eq!(inner.next_reestablishment_epoch().unwrap(), 8);
        assert_eq!(inner.next_reestablishment_epoch().unwrap(), 8);
        assert_eq!(inner.lifecycle, Lifecycle::Failed);
        assert!(inner.epoch.is_none());
        for last in [0, u64::MAX] {
            inner.last_issued_epoch = last;
            assert!(inner.next_reestablishment_epoch().is_err());
            assert_eq!(inner.last_issued_epoch, last);
        }
    }

    #[test]
    fn recovery_protection_result_never_publishes_an_epoch_or_unfences_a_prefix() {
        use crate::dirty::{HvfRamProtection, Mapping};
        use arch::guest_memory::{DirtyEffect, DirtyLocation, DirtyOperation, RamPermissions};

        let protection = HvfRamProtection::new();
        let mut inner = protection.lock(DirtyOperation::Reestablish).unwrap();
        inner.lifecycle = Lifecycle::Failed;
        inner.last_issued_epoch = 11;
        let mapping = Mapping {
            region: None,
            host: 0x10_0000,
            guest: 0x20_0000,
            len: 4096,
            permissions: RamPermissions::READ_WRITE_EXECUTE,
        };
        inner
            .record_reestablishment_result(mapping, Ok(()))
            .unwrap();
        assert_eq!(inner.lifecycle, Lifecycle::Failed);
        assert_eq!(inner.last_issued_epoch, 11);
        assert!(inner.epoch.is_none());
        let error = inner
            .record_reestablishment_result(mapping, Err(0x1234))
            .unwrap_err();
        assert_eq!(error.operation, DirtyOperation::Reestablish);
        assert_eq!(error.effect, DirtyEffect::ProtectionUnknown);
        assert_eq!(error.location, DirtyLocation::Vm);
        assert_eq!(error.native_code, 0x1234);
        assert_eq!(inner.lifecycle, Lifecycle::Failed);
        assert_eq!(inner.last_issued_epoch, 11);
        assert!(inner.allow_mapping_mutation().is_err());
        assert!(inner.epoch.is_none());
    }

    #[test]
    fn recovery_permissions_preserve_original_read_and_execute_for_every_mapping() {
        use crate::dirty::Mapping;
        use arch::guest_memory::RamPermissions;

        let mappings = [0, 0x10_0000, 0x20_0000].map(|guest| Mapping {
            region: None,
            host: guest + 0x100_0000,
            guest,
            len: 4096,
            permissions: RamPermissions::READ_WRITE_EXECUTE,
        });
        let permissions = mappings
            .iter()
            .map(|mapping| mapping.recovery_permissions().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            permissions,
            [RamPermissions::READ | RamPermissions::EXECUTE; 3]
        );
        assert!(mappings.iter().all(|mapping| {
            mapping.permissions.bits() == RamPermissions::READ_WRITE_EXECUTE.bits()
        }));
    }
}
