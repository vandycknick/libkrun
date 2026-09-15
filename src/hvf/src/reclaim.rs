// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use arch::guest_memory::{
    AccessPlan, GuestRange, HostMemoryAccess, HostMemoryAccessError, HostMemoryLease, LeaseId,
    MappingGeneration, RamPermissions, ReclaimError, ReclaimLedger, ReleasePlan, RestorePlan,
};

use crate::HVF;
use crate::bindings::{
    HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, HV_SUCCESS, hv_ipa_t, hv_memory_flags_t,
    hv_return_t,
};

const MADV_FREE_REUSABLE: i32 = 7;
const MADV_FREE_REUSE: i32 = 8;

// nix does not expose Darwin's reusable-memory advice operations.
unsafe extern "C" {
    #[cfg(test)]
    fn getpagesize() -> i32;
    fn madvise(address: *mut c_void, size: usize, advice: i32) -> i32;
}

#[derive(Debug)]
pub enum ReclaimStateError {
    AlreadyInitialized,
    Disabled,
    Ledger(ReclaimError),
    PolicyDisabled,
    Poisoned,
    ReusableAdvice(std::io::Error),
    ReuseAdvice(std::io::Error),
    RecoveryFailed(String),
    RestoreMap,
    ReleaseUnmap,
    HypervisorApi(libloading::Error),
    Uninitialized,
}

impl Display for ReclaimStateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "guest RAM reclaim state is already initialized"),
            Self::Disabled => write!(f, "guest RAM reclaim state is disabled"),
            Self::Ledger(error) => write!(f, "guest RAM reclaim state error: {error}"),
            Self::PolicyDisabled => write!(f, "guest RAM reclaim policy is disabled"),
            Self::Poisoned => write!(f, "guest RAM reclaim state lock is poisoned"),
            Self::ReusableAdvice(error) => {
                write!(f, "failed to mark released guest RAM reusable: {error}")
            }
            Self::ReuseAdvice(error) => {
                write!(
                    f,
                    "failed to restore reusable guest RAM accounting: {error}"
                )
            }
            Self::RecoveryFailed(error) => write!(f, "guest RAM recovery failed: {error}"),
            Self::RestoreMap => write!(f, "failed to restore guest RAM mapping in HVF"),
            Self::ReleaseUnmap => write!(f, "failed to release guest RAM mapping from HVF"),
            Self::HypervisorApi(error) => write!(f, "failed to load HVF memory API: {error}"),
            Self::Uninitialized => write!(f, "guest RAM reclaim state is not initialized"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome {
    Released,
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultResolution {
    Restored,
    Stale,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum ReclaimQualification {
    NotRun = 0,
    Passed = 1,
    Failed = 2,
    Inconclusive = 3,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimStats {
    pub released_extents: u64,
    pub released_bytes: u64,
    pub restored_extents: u64,
    pub restored_bytes: u64,
    pub skipped_reports: u64,
    pub failed_operations: u64,
}

impl Error for ReclaimStateError {}

impl From<ReclaimError> for ReclaimStateError {
    fn from(value: ReclaimError) -> Self {
        Self::Ledger(value)
    }
}

#[derive(Debug)]
pub struct ReclaimState {
    ledger: Mutex<Option<ReclaimLedger>>,
    disabled: AtomicBool,
    eligible: AtomicBool,
    policy_enabled: AtomicBool,
    qualification: AtomicU64,
    released_extents: AtomicU64,
    released_bytes: AtomicU64,
    restored_extents: AtomicU64,
    restored_bytes: AtomicU64,
    skipped_reports: AtomicU64,
    failed_operations: AtomicU64,
}

impl ReclaimState {
    pub fn new() -> Self {
        Self {
            ledger: Mutex::new(None),
            disabled: AtomicBool::new(false),
            eligible: AtomicBool::new(false),
            policy_enabled: AtomicBool::new(false),
            qualification: AtomicU64::new(ReclaimQualification::NotRun as u64),
            released_extents: AtomicU64::new(0),
            released_bytes: AtomicU64::new(0),
            restored_extents: AtomicU64::new(0),
            restored_bytes: AtomicU64::new(0),
            skipped_reports: AtomicU64::new(0),
            failed_operations: AtomicU64::new(0),
        }
    }

    pub fn runtime_access_enabled(&self) -> bool {
        !self.disabled.load(Ordering::Acquire)
            && self.eligible.load(Ordering::Acquire)
            && self.policy_enabled.load(Ordering::Acquire)
            && self.qualification() == ReclaimQualification::Passed
    }

    pub(crate) fn is_eligible(&self) -> bool {
        self.eligible.load(Ordering::Acquire)
    }

    fn effective_state(&self) -> Result<bool, ReclaimStateError> {
        if self.disabled.load(Ordering::Acquire) {
            return Err(ReclaimStateError::Disabled);
        }
        let effective = self.eligible.load(Ordering::Acquire)
            && self.policy_enabled.load(Ordering::Acquire)
            && self.qualification() == ReclaimQualification::Passed;
        if self.disabled.load(Ordering::Acquire) {
            return Err(ReclaimStateError::Disabled);
        }
        Ok(effective)
    }

    pub fn set_policy_enabled(&self, enabled: bool) {
        self.policy_enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.qualification
                .store(ReclaimQualification::NotRun as u64, Ordering::Release);
        }
    }

    pub fn qualification(&self) -> ReclaimQualification {
        match self.qualification.load(Ordering::Acquire) {
            1 => ReclaimQualification::Passed,
            2 => ReclaimQualification::Failed,
            3 => ReclaimQualification::Inconclusive,
            _ => ReclaimQualification::NotRun,
        }
    }

    pub(crate) fn record_qualification(&self, result: ReclaimQualification, detail: &str) {
        let result = if result == ReclaimQualification::Passed
            && (!self.eligible.load(Ordering::Acquire)
                || !self.policy_enabled.load(Ordering::Acquire))
        {
            ReclaimQualification::Inconclusive
        } else {
            result
        };
        self.qualification.store(result as u64, Ordering::Release);
        match result {
            ReclaimQualification::Passed => {
                log::info!("guest RAM reclaim qualification passed: {detail}")
            }
            ReclaimQualification::Failed | ReclaimQualification::Inconclusive => {
                log::warn!(
                    "guest RAM reclaim qualification {result:?}; using passthrough memory: {detail}"
                )
            }
            ReclaimQualification::NotRun => {}
        }
    }

    pub fn stats(&self) -> ReclaimStats {
        ReclaimStats {
            released_extents: self.released_extents.load(Ordering::Relaxed),
            released_bytes: self.released_bytes.load(Ordering::Relaxed),
            restored_extents: self.restored_extents.load(Ordering::Relaxed),
            restored_bytes: self.restored_bytes.load(Ordering::Relaxed),
            skipped_reports: self.skipped_reports.load(Ordering::Relaxed),
            failed_operations: self.failed_operations.load(Ordering::Relaxed),
        }
    }

    pub fn vcpu_run_generation(&self) -> Result<Option<MappingGeneration>, ReclaimStateError> {
        if !self.effective_state()? {
            return Ok(None);
        }
        Ok(Some(self.lock_ledger()?.get()?.current_generation()))
    }

    pub fn contains_ram(&self, guest_address: u64) -> Result<bool, ReclaimStateError> {
        let ledger = self.lock_ledger()?;
        match ledger.get()?.generation_at(guest_address) {
            Ok(_) => Ok(true),
            Err(ReclaimError::NotRam) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn release_report(
        self: &Arc<Self>,
        range: GuestRange,
    ) -> Result<ReleaseOutcome, ReclaimStateError> {
        if !self.effective_state()? {
            saturating_increment(&self.skipped_reports, 1);
            return Ok(ReleaseOutcome::Skipped);
        }
        let transaction = match self.begin_release(range) {
            Ok(Some(transaction)) => transaction,
            Ok(None) => {
                saturating_increment(&self.skipped_reports, 1);
                return Ok(ReleaseOutcome::Skipped);
            }
            Err(ReclaimStateError::Ledger(
                ReclaimError::ActiveLease
                | ReclaimError::AddressOverflow
                | ReclaimError::Busy
                | ReclaimError::EmptyRange
                | ReclaimError::InvalidAlignment
                | ReclaimError::MisalignedHostTranslation
                | ReclaimError::NotRam
                | ReclaimError::Released,
            )) => {
                saturating_increment(&self.skipped_reports, 1);
                return Ok(ReleaseOutcome::Skipped);
            }
            Err(error) => {
                saturating_increment(&self.failed_operations, 1);
                self.disable(&format!("failed to prepare RAM release: {error}"));
                return Err(error);
            }
        };
        let host = match transaction.range() {
            Ok(host) => host,
            Err(error) => {
                saturating_increment(&self.failed_operations, 1);
                self.disable(&format!("failed to read prepared RAM release: {error}"));
                return Err(error);
            }
        };
        let size = usize::try_from(host.byte_len()).map_err(|_| ReclaimStateError::ReleaseUnmap)?;
        if let Err(error) = checked_hvf_unmap(host.guest_range().start(), size) {
            saturating_increment(&self.failed_operations, 1);
            self.disable("HVF rejected a guest RAM release");
            return Err(error);
        }

        let advice_result =
            unsafe { madvise(host.host_start() as *mut c_void, size, MADV_FREE_REUSABLE) };
        if let Err(error) = transaction.commit() {
            saturating_increment(&self.failed_operations, 1);
            let recovery = recover_failed_release(host, size);
            self.disable(&format!("failed to commit RAM release tracking: {error}"));
            return match recovery {
                Ok(()) => Err(error),
                Err(recovery_error) => Err(ReclaimStateError::RecoveryFailed(format!(
                    "release commit failed: {error}; {recovery_error}"
                ))),
            };
        }
        if advice_result != 0 {
            let error = ReclaimStateError::ReusableAdvice(std::io::Error::last_os_error());
            if let Err(restore_error) = self.restore_without_lease(range) {
                self.disable(&format!(
                    "{error}; safe restore also failed: {restore_error}"
                ));
                return Err(restore_error);
            }
            self.disable(&error.to_string());
            saturating_increment(&self.failed_operations, 1);
            return Err(error);
        }
        saturating_increment(&self.released_extents, 1);
        saturating_increment(&self.released_bytes, host.byte_len());
        Ok(ReleaseOutcome::Released)
    }

    pub fn validate_report(&self, range: GuestRange) -> Result<bool, ReclaimStateError> {
        if !self.effective_state()? {
            return Ok(false);
        }
        let ledger = self.lock_ledger()?;
        let granule = ledger.get()?.granule();
        match ledger.get()?.validate_release(range, granule) {
            Ok(releasable) => Ok(releasable),
            Err(
                ReclaimError::AddressOverflow
                | ReclaimError::EmptyRange
                | ReclaimError::InvalidAlignment
                | ReclaimError::MisalignedHostTranslation
                | ReclaimError::NotRam,
            ) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn resolve_translation_fault(
        self: &Arc<Self>,
        guest_address: u64,
        entered_generation: MappingGeneration,
    ) -> Result<FaultResolution, ReclaimStateError> {
        if !self.effective_state()? {
            return Ok(FaultResolution::Invalid);
        }
        let range = GuestRange::new(guest_address, 1)?;
        {
            let ledger = self.lock_ledger()?;
            match ledger.get()?.generation_at(guest_address) {
                Err(ReclaimError::NotRam) => return Ok(FaultResolution::Invalid),
                Err(error) => return Err(error.into()),
                Ok(Some(generation)) => {
                    return Ok(if generation > entered_generation {
                        FaultResolution::Stale
                    } else {
                        FaultResolution::Invalid
                    });
                }
                Ok(None) => {}
            }
        }
        match self.begin_access(range)? {
            PreparedAccess::Restore(transaction) => {
                drop(transaction.restore_os()?);
                Ok(FaultResolution::Restored)
            }
            PreparedAccess::Leased(lease) => {
                drop(lease);
                let generation = self
                    .lock_ledger()?
                    .get()?
                    .generation_at(guest_address)?
                    .ok_or(ReclaimStateError::Ledger(ReclaimError::InvalidTransition))?;
                Ok(if generation > entered_generation {
                    FaultResolution::Stale
                } else {
                    FaultResolution::Invalid
                })
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn enable_policy_for_test(&self) {
        self.policy_enabled.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn qualify_for_test(&self) {
        if self.eligible.load(Ordering::Acquire) && self.policy_enabled.load(Ordering::Acquire) {
            self.qualification
                .store(ReclaimQualification::Passed as u64, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub(crate) fn test_ledger_counts(&self) -> (usize, usize) {
        let ledger = self.lock_ledger().expect("test reclaim ledger");
        let ledger = ledger.get().expect("initialized test reclaim ledger");
        (ledger.released_extent_count(), ledger.active_lease_count())
    }

    pub(crate) fn begin_initialization(
        &self,
        ledger: ReclaimLedger,
    ) -> Result<InitializationReservation<'_>, ReclaimStateError> {
        let slot = self.lock_slot()?;
        if slot.is_some() {
            return Err(ReclaimStateError::AlreadyInitialized);
        }
        Ok(InitializationReservation {
            state: self,
            slot,
            ledger: Some(ledger),
        })
    }

    fn disable(&self, reason: &str) {
        if !self.disabled.swap(true, Ordering::AcqRel) {
            log::error!("disabling guest RAM reclaim state: {reason}");
        }
    }

    fn lock_slot(&self) -> Result<MutexGuard<'_, Option<ReclaimLedger>>, ReclaimStateError> {
        if self.disabled.load(Ordering::Acquire) {
            return Err(ReclaimStateError::Disabled);
        }
        self.lock_enabled_slot()
    }

    fn lock_enabled_slot(
        &self,
    ) -> Result<MutexGuard<'_, Option<ReclaimLedger>>, ReclaimStateError> {
        let slot = self.ledger.lock().map_err(|_| {
            self.disable("state lock is poisoned");
            ReclaimStateError::Poisoned
        })?;
        if self.disabled.load(Ordering::Acquire) {
            return Err(ReclaimStateError::Disabled);
        }
        Ok(slot)
    }

    fn lock_ledger(&self) -> Result<LedgerGuard<'_>, ReclaimStateError> {
        let slot = self.lock_slot()?;
        if slot.is_none() {
            return Err(ReclaimStateError::Uninitialized);
        }
        Ok(LedgerGuard { slot })
    }

    pub(crate) fn begin_release(
        &self,
        range: GuestRange,
    ) -> Result<Option<ReleaseTransaction<'_>>, ReclaimStateError> {
        let mut ledger = self.lock_ledger()?;
        let granule = ledger.get()?.granule();
        let Some(plan) = ledger.get_mut()?.prepare_release(range, granule)? else {
            return Ok(None);
        };
        Ok(Some(ReleaseTransaction {
            state: self,
            ledger,
            plan: Some(plan),
        }))
    }

    fn begin_access(
        self: &Arc<Self>,
        range: GuestRange,
    ) -> Result<PreparedAccess<'_>, ReclaimStateError> {
        let mut ledger = self.lock_ledger()?;
        match ledger.get_mut()?.prepare_access(range)? {
            AccessPlan::Leased(id) => Ok(PreparedAccess::Leased(ReclaimLease {
                state: Arc::clone(self),
                id: Some(id),
            })),
            AccessPlan::Restore(plan) => Ok(PreparedAccess::Restore(RestoreTransaction {
                state: self,
                ledger,
                plan: Some(plan),
            })),
        }
    }

    fn restore_without_lease(self: &Arc<Self>, range: GuestRange) -> Result<(), ReclaimStateError> {
        match self.begin_access(range)? {
            PreparedAccess::Leased(lease) => {
                drop(lease);
                Ok(())
            }
            PreparedAccess::Restore(transaction) => transaction.restore_os().map(drop),
        }
    }
}

impl HostMemoryAccess for ReclaimState {
    fn access(
        self: Arc<Self>,
        range: GuestRange,
    ) -> Result<Arc<dyn HostMemoryLease>, HostMemoryAccessError> {
        match self.effective_state() {
            Err(error) => return Err(HostMemoryAccessError::new(error.to_string())),
            Ok(true) => {}
            Ok(false) => {
                return Err(HostMemoryAccessError::new(
                    ReclaimStateError::PolicyDisabled.to_string(),
                ));
            }
        }
        match self
            .begin_access(range)
            .map_err(|error| HostMemoryAccessError::new(error.to_string()))?
        {
            PreparedAccess::Leased(lease) => Ok(Arc::new(lease)),
            PreparedAccess::Restore(transaction) => transaction
                .restore_os()
                .map(|lease| Arc::new(lease) as Arc<dyn HostMemoryLease>)
                .map_err(|error| HostMemoryAccessError::new(error.to_string())),
        }
    }

    fn allows_external_mapping(&self) -> bool {
        false
    }
}

pub struct InitializationReservation<'a> {
    state: &'a ReclaimState,
    slot: MutexGuard<'a, Option<ReclaimLedger>>,
    ledger: Option<ReclaimLedger>,
}

impl InitializationReservation<'_> {
    pub fn commit(mut self) {
        if let Some(ledger) = self.ledger.take() {
            let eligible = ledger.has_registered_regions();
            *self.slot = Some(ledger);
            self.state.eligible.store(eligible, Ordering::Release);
        }
    }

    pub fn cancel(mut self) {
        self.ledger = None;
    }

    pub fn fail_closed(mut self, reason: &str) {
        self.ledger = None;
        self.state.disable(reason);
    }
}

impl Default for ReclaimState {
    fn default() -> Self {
        Self::new()
    }
}

struct LedgerGuard<'a> {
    slot: MutexGuard<'a, Option<ReclaimLedger>>,
}

impl LedgerGuard<'_> {
    fn get(&self) -> Result<&ReclaimLedger, ReclaimStateError> {
        self.slot.as_ref().ok_or(ReclaimStateError::Uninitialized)
    }

    fn get_mut(&mut self) -> Result<&mut ReclaimLedger, ReclaimStateError> {
        self.slot.as_mut().ok_or(ReclaimStateError::Uninitialized)
    }
}

pub(crate) struct ReleaseTransaction<'a> {
    state: &'a ReclaimState,
    ledger: LedgerGuard<'a>,
    plan: Option<ReleasePlan>,
}

impl ReleaseTransaction<'_> {
    pub(crate) fn range(&self) -> Result<arch::guest_memory::HostRange, ReclaimStateError> {
        self.plan
            .map(ReleasePlan::range)
            .ok_or(ReclaimStateError::Ledger(ReclaimError::InvalidTransition))
    }

    pub(crate) fn commit(mut self) -> Result<(), ReclaimStateError> {
        let plan = self
            .plan
            .as_ref()
            .copied()
            .ok_or(ReclaimStateError::Ledger(ReclaimError::InvalidTransition))?;
        let result = self
            .ledger
            .get_mut()?
            .commit_release(plan)
            .map_err(Into::into);
        if result.is_ok() {
            self.plan = None;
        }
        result
    }
}

impl Drop for ReleaseTransaction<'_> {
    fn drop(&mut self) {
        if let Some(plan) = self.plan.take() {
            let result = self
                .ledger
                .get_mut()
                .and_then(|ledger| ledger.abort_release(plan).map_err(Into::into));
            if let Err(error) = result {
                self.state
                    .disable(&format!("failed to abort RAM release transaction: {error}"));
            }
        }
    }
}

pub(crate) enum PreparedAccess<'a> {
    Leased(ReclaimLease),
    Restore(RestoreTransaction<'a>),
}

pub(crate) struct RestoreTransaction<'a> {
    state: &'a Arc<ReclaimState>,
    ledger: LedgerGuard<'a>,
    plan: Option<RestorePlan>,
}

impl RestoreTransaction<'_> {
    pub(crate) fn ranges(&self) -> &[arch::guest_memory::HostRange] {
        match &self.plan {
            Some(plan) => plan.ranges(),
            None => &[],
        }
    }

    pub(crate) fn commit(mut self) -> Result<ReclaimLease, ReclaimStateError> {
        let plan = self
            .plan
            .as_ref()
            .cloned()
            .ok_or(ReclaimStateError::Ledger(ReclaimError::InvalidTransition))?;
        let id = self.ledger.get_mut()?.commit_restore(plan)?;
        self.plan = None;
        Ok(ReclaimLease {
            state: Arc::clone(self.state),
            id: Some(id),
        })
    }

    fn restore_os(self) -> Result<ReclaimLease, ReclaimStateError> {
        let ranges = self.ranges().to_vec();
        let prepared: Result<Vec<_>, ReclaimStateError> = ranges
            .iter()
            .map(|range| {
                let size =
                    usize::try_from(range.byte_len()).map_err(|_| ReclaimStateError::RestoreMap)?;
                let flags = hvf_permissions(range.permissions())?;
                Ok((*range, size, flags))
            })
            .collect();
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                saturating_increment(&self.state.failed_operations, 1);
                self.state
                    .disable(&format!("failed to prepare RAM restore: {error}"));
                return Err(error);
            }
        };
        let mut accounting_error = None;
        for (range, size, _) in &prepared {
            if unsafe { madvise(range.host_start() as *mut c_void, *size, MADV_FREE_REUSE) } != 0
                && accounting_error.is_none()
            {
                accounting_error = Some(ReclaimStateError::ReuseAdvice(
                    std::io::Error::last_os_error(),
                ));
            }
        }

        let mut mapped: Vec<arch::guest_memory::HostRange> = Vec::new();
        for (range, size, flags) in &prepared {
            if let Err(map_error) = checked_hvf_map(
                range.host_start() as *mut c_void,
                range.guest_range().start(),
                *size,
                *flags,
            ) {
                let rollback = rollback_mappings(&mapped);
                saturating_increment(&self.state.failed_operations, 1);
                self.state.disable("failed to restore guest RAM mapping");
                return match rollback {
                    Ok(()) => Err(map_error),
                    Err(rollback_error) => Err(ReclaimStateError::RecoveryFailed(format!(
                        "restore map failed: {map_error}; {rollback_error}"
                    ))),
                };
            }
            mapped.push(*range);
        }

        let state = Arc::clone(self.state);
        let lease = match self.commit() {
            Ok(lease) => lease,
            Err(error) => {
                let rollback = rollback_mappings(&mapped);
                saturating_increment(&state.failed_operations, 1);
                state.disable(&format!("failed to commit RAM restore tracking: {error}"));
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(ReclaimStateError::RecoveryFailed(format!(
                        "restore commit failed: {error}; {rollback_error}"
                    ))),
                };
            }
        };
        saturating_increment(&state.restored_extents, ranges.len() as u64);
        let restored_bytes = ranges
            .iter()
            .fold(0_u64, |total, range| total.saturating_add(range.byte_len()));
        saturating_increment(&state.restored_bytes, restored_bytes);
        if let Some(error) = accounting_error {
            drop(lease);
            saturating_increment(&state.failed_operations, 1);
            state.disable(&error.to_string());
            return Err(error);
        }
        Ok(lease)
    }
}

fn hvf_map(
    address: *mut c_void,
    guest_address: hv_ipa_t,
    size: usize,
    flags: hv_memory_flags_t,
) -> Result<hv_return_t, ReclaimStateError> {
    type Map = unsafe extern "C" fn(*mut c_void, hv_ipa_t, usize, hv_memory_flags_t) -> hv_return_t;
    let map: libloading::Symbol<'_, Map> =
        unsafe { HVF.get(b"hv_vm_map") }.map_err(ReclaimStateError::HypervisorApi)?;
    Ok(unsafe { map(address, guest_address, size, flags) })
}

fn hvf_unmap(guest_address: hv_ipa_t, size: usize) -> Result<hv_return_t, ReclaimStateError> {
    type Unmap = unsafe extern "C" fn(hv_ipa_t, usize) -> hv_return_t;
    let unmap: libloading::Symbol<'_, Unmap> =
        unsafe { HVF.get(b"hv_vm_unmap") }.map_err(ReclaimStateError::HypervisorApi)?;
    Ok(unsafe { unmap(guest_address, size) })
}

fn checked_hvf_map(
    address: *mut c_void,
    guest_address: hv_ipa_t,
    size: usize,
    flags: hv_memory_flags_t,
) -> Result<(), ReclaimStateError> {
    check_hvf_status(
        hvf_map(address, guest_address, size, flags)?,
        ReclaimStateError::RestoreMap,
    )
}

fn checked_hvf_unmap(guest_address: hv_ipa_t, size: usize) -> Result<(), ReclaimStateError> {
    check_hvf_status(
        hvf_unmap(guest_address, size)?,
        ReclaimStateError::ReleaseUnmap,
    )
}

fn check_hvf_status(
    status: hv_return_t,
    error: ReclaimStateError,
) -> Result<(), ReclaimStateError> {
    if status == HV_SUCCESS {
        Ok(())
    } else {
        Err(error)
    }
}

fn hvf_permissions(permissions: RamPermissions) -> Result<hv_memory_flags_t, ReclaimStateError> {
    match permissions {
        RamPermissions::READ_WRITE_EXECUTE => {
            Ok((HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC).into())
        }
        _ => Err(ReclaimStateError::RestoreMap),
    }
}

fn recover_failed_release(
    range: arch::guest_memory::HostRange,
    size: usize,
) -> Result<(), ReclaimStateError> {
    let mut failures = Vec::new();
    if unsafe { madvise(range.host_start() as *mut c_void, size, MADV_FREE_REUSE) } != 0 {
        failures.push(format!(
            "MADV_FREE_REUSE: {}",
            std::io::Error::last_os_error()
        ));
    }
    if let Err(error) = hvf_permissions(range.permissions()).and_then(|flags| {
        checked_hvf_map(
            range.host_start() as *mut c_void,
            range.guest_range().start(),
            size,
            flags,
        )
    }) {
        failures.push(format!("HVF map: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ReclaimStateError::RecoveryFailed(format!(
            "release rollback failures: {}",
            failures.join(", ")
        )))
    }
}

fn rollback_mappings(ranges: &[arch::guest_memory::HostRange]) -> Result<(), ReclaimStateError> {
    let mut failures = Vec::new();
    for range in ranges.iter().rev() {
        let result = usize::try_from(range.byte_len())
            .map_err(|_| ReclaimStateError::ReleaseUnmap)
            .and_then(|size| checked_hvf_unmap(range.guest_range().start(), size));
        if let Err(error) = result {
            failures.push(format!(
                "gpa={:#x} len={:#x}: {error}",
                range.guest_range().start(),
                range.byte_len()
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ReclaimStateError::RecoveryFailed(format!(
            "restore rollback unmap failures: {}",
            failures.join(", ")
        )))
    }
}

fn saturating_increment(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

impl Drop for RestoreTransaction<'_> {
    fn drop(&mut self) {
        if let Some(plan) = self.plan.take() {
            let result = self
                .ledger
                .get_mut()
                .and_then(|ledger| ledger.abort_restore(plan).map_err(Into::into));
            if let Err(error) = result {
                self.state
                    .disable(&format!("failed to abort RAM restore transaction: {error}"));
            }
        }
    }
}

pub(crate) struct ReclaimLease {
    state: Arc<ReclaimState>,
    id: Option<LeaseId>,
}

impl HostMemoryLease for ReclaimLease {}

impl Drop for ReclaimLease {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let result = self
            .state
            .lock_ledger()
            .and_then(|mut ledger| ledger.get_mut()?.release_lease(id).map_err(Into::into));
        if let Err(error) = result {
            self.state
                .disable(&format!("failed to release host-access lease: {error}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::sync_channel;

    use arch::guest_memory::{
        GuestRange, HostMemoryAccess, RamPermissions, RamRegion, ReclaimLedger,
    };

    use crate::reclaim::{PreparedAccess, ReclaimState, ReclaimStateError};

    fn ledger() -> ReclaimLedger {
        let mut ledger = ReclaimLedger::new(0x1000).unwrap();
        ledger
            .register_region(
                RamRegion::new(
                    0x8000_0000,
                    0x1_0000_0000,
                    0x4000,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        ledger
    }

    fn state() -> Arc<ReclaimState> {
        let state = Arc::new(ReclaimState::new());
        state.begin_initialization(ledger()).unwrap().commit();
        state.enable_policy_for_test();
        state.qualify_for_test();
        state
    }

    #[test]
    fn duplicate_initialization_is_rejected_after_commit() {
        let state = ReclaimState::new();
        state.begin_initialization(ledger()).unwrap().commit();
        assert!(!state.runtime_access_enabled());
        state.qualify_for_test();
        assert!(!state.runtime_access_enabled());
        state.enable_policy_for_test();
        assert!(!state.runtime_access_enabled());
        state.qualify_for_test();
        assert!(state.runtime_access_enabled());

        assert!(matches!(
            state.begin_initialization(ledger()),
            Err(ReclaimStateError::AlreadyInitialized)
        ));
    }

    #[test]
    fn empty_ledger_never_qualifies_for_runtime_access() {
        let state = ReclaimState::new();
        state
            .begin_initialization(ReclaimLedger::new(0x1000).unwrap())
            .unwrap()
            .commit();

        state.enable_policy_for_test();
        state.qualify_for_test();
        assert!(!state.runtime_access_enabled());
    }

    #[test]
    fn failed_or_inconclusive_probe_never_enables_runtime_access() {
        let state = ReclaimState::new();
        state.begin_initialization(ledger()).unwrap().commit();
        state.enable_policy_for_test();

        state.record_qualification(crate::reclaim::ReclaimQualification::Failed, "test failure");
        assert_eq!(
            state.qualification(),
            crate::reclaim::ReclaimQualification::Failed
        );
        assert!(!state.runtime_access_enabled());
        state.record_qualification(
            crate::reclaim::ReclaimQualification::Inconclusive,
            "test noise",
        );
        assert_eq!(
            state.qualification(),
            crate::reclaim::ReclaimQualification::Inconclusive
        );
        assert!(!state.runtime_access_enabled());
    }

    #[test]
    fn initialized_state_rejects_runtime_access_while_policy_is_disabled() {
        let state = Arc::new(ReclaimState::new());
        state.begin_initialization(ledger()).unwrap().commit();
        assert_eq!(state.vcpu_run_generation().unwrap(), None);
        let range = GuestRange::new(0x8000_0000, 0x1000).unwrap();
        let provider: Arc<dyn HostMemoryAccess> = state;

        let error = match provider.access(range) {
            Ok(_) => panic!("default-disabled reclaim policy issued a lease"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "guest RAM reclaim policy is disabled");
    }

    #[test]
    fn canceled_initialization_releases_reservation_without_installing() {
        let state = ReclaimState::new();
        let reservation = state.begin_initialization(ledger()).unwrap();
        assert!(state.ledger.try_lock().is_err());
        reservation.cancel();

        state.begin_initialization(ledger()).unwrap().commit();
        assert!(state.lock_ledger().is_ok());
    }

    #[test]
    fn waiter_cannot_initialize_after_reservation_fails_closed() {
        let state = Arc::new(ReclaimState::new());
        let reservation = state.begin_initialization(ledger()).unwrap();
        let waiter_state = Arc::clone(&state);
        let (checked_sender, checked_receiver) = sync_channel(0);
        let (result_sender, result_receiver) = sync_channel(0);
        let waiter = std::thread::spawn(move || {
            checked_sender.send(()).unwrap();
            let result = waiter_state.lock_enabled_slot().map(drop);
            result_sender.send(result).unwrap();
        });

        checked_receiver.recv().unwrap();
        reservation.fail_closed("initialization rollback failed in test");

        assert!(matches!(
            result_receiver.recv().unwrap(),
            Err(ReclaimStateError::Disabled)
        ));
        waiter.join().unwrap();
    }

    #[test]
    fn lease_guard_releases_without_holding_state_lock() {
        let state = state();
        let range = GuestRange::new(0x8000_0000, 0x1000).unwrap();
        let lease = match state.begin_access(range).unwrap() {
            PreparedAccess::Leased(lease) => lease,
            PreparedAccess::Restore(_) => panic!("mapped RAM unexpectedly required restore"),
        };

        assert_eq!(
            state
                .lock_ledger()
                .unwrap()
                .get()
                .unwrap()
                .active_lease_count(),
            1
        );
        drop(lease);
        assert_eq!(
            state
                .lock_ledger()
                .unwrap()
                .get()
                .unwrap()
                .active_lease_count(),
            0
        );
    }

    #[test]
    fn runtime_restore_os_failure_is_not_reported_as_success() {
        let state = state();
        let range = GuestRange::new(0x8000_0000, 0x1000).unwrap();
        state
            .begin_release(range)
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        let provider: Arc<dyn HostMemoryAccess> = state.clone();

        let error = match provider.access(range) {
            Ok(_) => panic!("released RAM was exposed without OS restore"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "failed to restore guest RAM mapping in HVF"
        );
        assert!(state.disabled.load(Ordering::Acquire));
        assert!(!state.runtime_access_enabled());
        assert!(matches!(
            state.vcpu_run_generation(),
            Err(ReclaimStateError::Disabled)
        ));
        assert!(matches!(
            state.contains_ram(0x8000_0000),
            Err(ReclaimStateError::Disabled)
        ));
        assert_eq!(
            state
                .ledger
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .released_extent_count(),
            1
        );
    }

    #[test]
    fn release_transaction_holds_lock_and_aborts_on_drop() {
        let state = state();
        let range = GuestRange::new(0x8000_0000, 0x1000).unwrap();
        let transaction = state.begin_release(range).unwrap().unwrap();
        assert_eq!(transaction.range().unwrap().guest_range(), range);
        assert!(state.ledger.try_lock().is_err());
        drop(transaction);

        assert!(state.begin_release(range).unwrap().is_some());
    }

    #[test]
    fn two_vcpus_classify_the_same_completed_restore_as_stale_once() {
        let state = state();
        let range = GuestRange::new(0x8000_0000, 0x1000).unwrap();
        let entered_a = state.vcpu_run_generation().unwrap().unwrap();
        let entered_b = state.vcpu_run_generation().unwrap().unwrap();
        state
            .begin_release(range)
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        let restore = match state.begin_access(range).unwrap() {
            PreparedAccess::Restore(restore) => restore,
            PreparedAccess::Leased(_) => panic!("released RAM did not require restore"),
        };
        drop(restore.commit().unwrap());

        assert_eq!(
            state
                .resolve_translation_fault(range.start(), entered_a)
                .unwrap(),
            crate::reclaim::FaultResolution::Stale
        );
        assert_eq!(
            state
                .resolve_translation_fault(range.start(), entered_b)
                .unwrap(),
            crate::reclaim::FaultResolution::Stale
        );
        let retried = state.vcpu_run_generation().unwrap().unwrap();
        assert_eq!(
            state
                .resolve_translation_fault(range.start(), retried)
                .unwrap(),
            crate::reclaim::FaultResolution::Invalid
        );
    }

    #[test]
    fn enabled_fault_classification_preserves_mmio_and_rejects_mapped_ram() {
        let state = state();
        let entered = state.vcpu_run_generation().unwrap().unwrap();

        assert_eq!(
            state.resolve_translation_fault(0x1000, entered).unwrap(),
            crate::reclaim::FaultResolution::Invalid
        );
        assert!(!state.contains_ram(0x1000).unwrap());

        for _ in 0..2 {
            assert_eq!(
                state
                    .resolve_translation_fault(0x8000_0000, entered)
                    .unwrap(),
                crate::reclaim::FaultResolution::Invalid
            );
            assert!(state.contains_ram(0x8000_0000).unwrap());
        }
        assert_eq!(
            state
                .ledger
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .active_lease_count(),
            0
        );
    }

    #[test]
    fn real_hvf_release_and_host_first_restore_preserve_writes() {
        use std::alloc::{Layout, alloc_zeroed, dealloc};

        use crate::HVF;
        use crate::bindings::{
            HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, HV_SUCCESS, hv_return_t,
            hv_vm_config_t,
        };
        use crate::reclaim::{checked_hvf_map, checked_hvf_unmap, getpagesize};

        type ConfigCreate = unsafe extern "C" fn() -> hv_vm_config_t;
        type Create = unsafe extern "C" fn(hv_vm_config_t) -> hv_return_t;
        type Destroy = unsafe extern "C" fn() -> hv_return_t;
        let config_create: libloading::Symbol<'_, ConfigCreate> =
            unsafe { HVF.get(b"hv_vm_config_create") }.unwrap();
        let create: libloading::Symbol<'_, Create> = unsafe { HVF.get(b"hv_vm_create") }.unwrap();
        let destroy: libloading::Symbol<'_, Destroy> =
            unsafe { HVF.get(b"hv_vm_destroy") }.unwrap();
        let page_size = usize::try_from(unsafe { getpagesize() }).unwrap();
        let layout = Layout::from_size_align(page_size, page_size).unwrap();
        let host = unsafe { alloc_zeroed(layout) };
        assert!(!host.is_null());
        let config = unsafe { config_create() };
        assert_eq!(unsafe { create(config) }, HV_SUCCESS);

        let guest_start = 0x4000_0000;
        checked_hvf_map(
            host.cast(),
            guest_start,
            page_size,
            (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC).into(),
        )
        .unwrap();
        let mut ledger = ReclaimLedger::new(page_size as u64).unwrap();
        ledger
            .register_region(
                RamRegion::new(
                    guest_start,
                    host as u64,
                    page_size as u64,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        let state = Arc::new(ReclaimState::new());
        state.begin_initialization(ledger).unwrap().commit();
        state.enable_policy_for_test();
        state.qualify_for_test();
        let range = GuestRange::new(guest_start, page_size as u64).unwrap();

        assert_eq!(
            state.release_report(range).unwrap(),
            crate::reclaim::ReleaseOutcome::Released
        );
        assert_eq!(
            state
                .ledger
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .released_extent_count(),
            1
        );
        let lease = state.clone().access(range).unwrap();
        let bytes = unsafe { std::slice::from_raw_parts_mut(host, page_size) };
        bytes.fill(0xa5);
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
        assert_eq!(
            state.stats(),
            crate::reclaim::ReclaimStats {
                released_extents: 1,
                released_bytes: page_size as u64,
                restored_extents: 1,
                restored_bytes: page_size as u64,
                skipped_reports: 0,
                failed_operations: 0,
            }
        );
        assert_eq!(
            state
                .ledger
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .released_extent_count(),
            0
        );
        drop(lease);

        checked_hvf_unmap(guest_start, page_size).unwrap();
        assert_eq!(unsafe { destroy() }, HV_SUCCESS);
        unsafe { dealloc(host, layout) };
    }

    #[test]
    fn non_success_hvf_status_is_an_error() {
        assert!(matches!(
            crate::reclaim::check_hvf_status(
                crate::bindings::HV_SUCCESS + 1,
                ReclaimStateError::RestoreMap
            ),
            Err(ReclaimStateError::RestoreMap)
        ));
    }

    #[test]
    fn poisoned_lease_cleanup_disables_state() {
        let state = state();
        let range = GuestRange::new(0x8000_0000, 0x1000).unwrap();
        let lease = match state.begin_access(range).unwrap() {
            PreparedAccess::Leased(lease) => lease,
            PreparedAccess::Restore(_) => panic!("mapped RAM unexpectedly required restore"),
        };
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = state.ledger.lock().unwrap();
            panic!("poison reclaim state for cleanup test");
        }));
        assert!(poisoned.is_err());

        drop(lease);
        assert!(state.disabled.load(Ordering::Acquire));
        assert!(matches!(
            state.lock_slot(),
            Err(ReclaimStateError::Disabled)
        ));
    }
}
