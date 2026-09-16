// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Host reclaim of guest RAM that the guest reported free.
//!
//! Each release is `hv_vm_unmap → page-wise MADV_FREE → hv_vm_map`.
//! Advice must use native host pages even when HV mappings are coalesced.
//! The host may retain clean contents until pressure discards them; an unmap's
//! footprint drop alone is not evidence that backing was freed. Immediate
//! remapping lets the kernel handle subsequent guest refaults.
//!
//! Host device access to guest memory is never guarded. The host mapping stays
//! valid throughout the cycle, and the free-page-reporting protocol guarantees
//! that the guest does not hand a reported page to a device before the report
//! is acknowledged. The only shared state is one atomic per RAM extent so that
//! a vCPU faulting inside the unmap window waits for the remap and retries
//! instead of being treated as an invalid memory access. A global lease ledger
//! here would put a mutex and extent scan on every device descriptor/payload
//! access, even though report ownership already excludes use of those pages.
//!
//! See `docs/macos-host-reclaim.md` for qualification, failure invariants and
//! the distinction between discard eligibility, footprint and physical discard.

use std::error::Error;
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::hint;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use arch::guest_memory::{
    GuestRange, HostRange, RamLayout, RamPermissions, RamRegion, ReclaimError,
};

use crate::bindings::{
    HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, HV_SUCCESS, hv_memory_flags_t, hv_vm_map,
    hv_vm_unmap,
};
use crate::discard::{advise_free, native_page_size};

/// Transition bookkeeping granularity. Linux reports free pages in
/// `pageblock_order` blocks, which is 2 MiB on the guests libkrun runs, so one
/// state byte per 2 MiB keeps the map small without splitting reports.
pub const EXTENT_BYTES: u64 = 2 * 1024 * 1024;

const EXTENT_MAPPED: u8 = 0;
const EXTENT_TRANSITIONING: u8 = 1;
/// A release cycle could not restore the stage-2 mapping. The extent is gone
/// and any vCPU touching it must fail instead of waiting for a remap that will
/// never come.
const EXTENT_LOST: u8 = 2;
/// A release cycle takes tens of microseconds; anything near this bound means
/// the hypervisor is wedged and the vCPU must fail rather than spin forever.
const TRANSITION_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const SPINS_BEFORE_YIELD: u32 = 64;

// nix does not expose Mach's content-preserving remapping API.
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_vm_remap(
        task: u32,
        destination: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        source_task: u32,
        source: u64,
        copy: i32,
        current: *mut i32,
        maximum: *mut i32,
        inheritance: i32,
    ) -> i32;
}

#[derive(Debug)]
pub enum ReclaimStateError {
    AlreadyInitialized,
    Layout(ReclaimError),
    DiscardAdvice(std::io::Error),
    ReleaseUnmap,
    RestoreMap,
    NormalizeMapping(i32),
    RemapperLockPoisoned,
    TransitionTimeout,
    ExtentLost,
}

impl Display for ReclaimStateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "guest RAM reclaim state is already initialized"),
            Self::Layout(error) => write!(f, "guest RAM layout error: {error}"),
            Self::DiscardAdvice(error) => {
                write!(f, "failed to advise reported guest RAM free: {error}")
            }
            Self::ReleaseUnmap => write!(f, "failed to release guest RAM mapping from HVF"),
            Self::RestoreMap => write!(f, "failed to restore guest RAM mapping in HVF"),
            Self::NormalizeMapping(code) => {
                write!(
                    f,
                    "failed to normalize host RAM mappings: Mach error {code}"
                )
            }
            Self::RemapperLockPoisoned => write!(f, "host memory remapper lock poisoned"),
            Self::TransitionTimeout => {
                write!(
                    f,
                    "guest RAM release did not complete before the vCPU wait deadline"
                )
            }
            Self::ExtentLost => write!(
                f,
                "guest RAM extent was left unmapped by a failed release cycle"
            ),
        }
    }
}

impl Error for ReclaimStateError {}

impl From<ReclaimError> for ReclaimStateError {
    fn from(value: ReclaimError) -> Self {
        Self::Layout(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome {
    Released,
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultResolution {
    /// The fault raced a release cycle; the vCPU must re-execute the access.
    Retry,
    /// Not RAM, or RAM with no release in flight: handle as MMIO or an error.
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
    /// Successfully advised ranges, not necessarily distinct extents.
    pub released_extents: u64,
    /// Cumulative successfully advised bytes, not measured host-memory savings.
    pub released_bytes: u64,
    pub retried_faults: u64,
    pub skipped_reports: u64,
    pub failed_operations: u64,
}

struct RegionExtents {
    region: RamRegion,
    states: Box<[AtomicU8]>,
}

impl RegionExtents {
    fn new(region: RamRegion) -> Self {
        let count = region.host_range().byte_len().div_ceil(EXTENT_BYTES);
        let states = (0..count).map(|_| AtomicU8::new(EXTENT_MAPPED)).collect();
        Self { region, states }
    }

    fn index(&self, guest_address: u64) -> usize {
        let offset = guest_address - self.region.host_range().guest_range().start();
        usize::try_from(offset / EXTENT_BYTES).expect("extent index fits usize")
    }

    fn state(&self, guest_address: u64) -> &AtomicU8 {
        &self.states[self.index(guest_address)]
    }

    fn extent_indexes(&self, range: GuestRange) -> std::ops::RangeInclusive<usize> {
        self.index(range.start())..=self.index(range.end() - 1)
    }
}

struct ExtentMap {
    layout: RamLayout,
    regions: Vec<RegionExtents>,
}

impl ExtentMap {
    fn new(layout: RamLayout) -> Self {
        let regions = layout
            .regions()
            .iter()
            .copied()
            .map(RegionExtents::new)
            .collect();
        Self { layout, regions }
    }

    fn region_for(&self, guest_address: u64) -> Option<&RegionExtents> {
        self.regions
            .iter()
            .find(|entry| entry.region.contains_address(guest_address))
    }
}

enum CycleFailure {
    /// Guest memory is intact and mapped; reclaim is disabled from here on.
    Recoverable(ReclaimStateError),
    /// The stage-2 mapping could not be restored; the VM cannot continue.
    Fatal(ReclaimStateError),
}

pub struct ReclaimState {
    map: OnceLock<ExtentMap>,
    disabled: AtomicBool,
    policy_enabled: AtomicBool,
    qualification: AtomicU64,
    /// Incremented when a release cycle starts and again when it ends. A vCPU
    /// samples it before running; a translation fault on RAM with an unchanged
    /// value is a real fault, while a changed value means the fault raced a
    /// cycle and the access must simply be retried.
    transition_generation: AtomicU64,
    released_extents: AtomicU64,
    released_bytes: AtomicU64,
    retried_faults: AtomicU64,
    skipped_reports: AtomicU64,
    failed_operations: AtomicU64,
    #[cfg(test)]
    transition_hook: std::sync::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for ReclaimState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReclaimState")
            .field("map", &self.map.get())
            .field("disabled", &self.disabled.load(Ordering::Relaxed))
            .field(
                "policy_enabled",
                &self.policy_enabled.load(Ordering::Relaxed),
            )
            .field("qualification", &self.qualification())
            .field(
                "transition_generation",
                &self.transition_generation.load(Ordering::Relaxed),
            )
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExtentMap {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtentMap")
            .field("granule", &self.layout.granule())
            .field("regions", &self.layout.regions().len())
            .finish()
    }
}

impl ReclaimState {
    pub fn new() -> Self {
        Self {
            map: OnceLock::new(),
            disabled: AtomicBool::new(false),
            policy_enabled: AtomicBool::new(false),
            qualification: AtomicU64::new(ReclaimQualification::NotRun as u64),
            transition_generation: AtomicU64::new(0),
            released_extents: AtomicU64::new(0),
            released_bytes: AtomicU64::new(0),
            retried_faults: AtomicU64::new(0),
            skipped_reports: AtomicU64::new(0),
            failed_operations: AtomicU64::new(0),
            #[cfg(test)]
            transition_hook: std::sync::Mutex::new(None),
        }
    }

    /// Installs the RAM layout once all of it is mapped into the VM.
    pub fn initialize(&self, layout: RamLayout) -> Result<(), ReclaimStateError> {
        let page_size = native_page_size().map_err(|_| ReclaimError::InvalidAlignment)?;
        if layout.granule() != page_size as u64 {
            return Err(ReclaimError::InvalidAlignment.into());
        }
        self.map
            .set(ExtentMap::new(layout))
            .map_err(|_| ReclaimStateError::AlreadyInitialized)
    }

    /// Removes host PTEs and their accounting without replacing backing or
    /// replaying free-page reports. Guest mappings and live contents survive.
    /// Device I/O can populate host translations whose footprint charge remains
    /// after page-wise advice. Sharing the same VM object removes that charge
    /// without assuming previously reported pages are still free. Clean backing
    /// may remain resident, so this is not evidence of physical discard.
    ///
    /// # Safety
    /// The caller must keep every registered RAM allocation alive throughout
    /// this call. A retained ReclaimState alone does not own those allocations.
    pub unsafe fn normalize_host_mappings(&self) -> Result<(), ReclaimStateError> {
        if !self.is_eligible() {
            return Ok(());
        }
        let Some(map) = self.map.get() else {
            return Ok(());
        };
        for region in map.layout.regions() {
            let host = region.host_range();
            let source = host.host_start();
            let mut destination = source;
            let mut current = 0;
            let mut maximum = 0;
            // FIXED | OVERWRITE, copy=false shares the existing VM object.
            // This is not MAP_FIXED anonymous replacement or a discard.
            let result = unsafe {
                mach_vm_remap(
                    mach_task_self_,
                    &mut destination,
                    host.byte_len(),
                    0,
                    0x4000,
                    mach_task_self_,
                    source,
                    0,
                    &mut current,
                    &mut maximum,
                    2, // VM_INHERIT_NONE
                )
            };
            if result != 0 {
                return Err(ReclaimStateError::NormalizeMapping(result));
            }
            if destination != source {
                return Err(ReclaimStateError::NormalizeMapping(1)); // KERN_INVALID_ADDRESS
            }
        }
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.map.get().is_some()
    }

    pub(crate) fn is_eligible(&self) -> bool {
        self.map
            .get()
            .is_some_and(|map| map.layout.has_registered_regions())
    }

    /// Whether new reports may be advised free. HostMemoryRemapper is independent.
    /// Fault classification remains active for registered RAM even when false:
    /// earlier transitions still need recovery or detection of lost mappings.
    pub fn is_effective(&self) -> bool {
        !self.disabled.load(Ordering::Acquire)
            && self.is_eligible()
            && self.policy_enabled.load(Ordering::Acquire)
            && self.qualification() == ReclaimQualification::Passed
    }

    pub fn policy_enabled(&self) -> bool {
        self.policy_enabled.load(Ordering::Acquire)
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
            && (!self.is_eligible() || !self.policy_enabled.load(Ordering::Acquire))
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
            retried_faults: self.retried_faults.load(Ordering::Relaxed),
            skipped_reports: self.skipped_reports.load(Ordering::Relaxed),
            failed_operations: self.failed_operations.load(Ordering::Relaxed),
        }
    }

    /// Keep classifying registered RAM even after reclaim is disabled: an
    /// earlier cycle may still be transitioning or may have lost its mapping.
    pub fn vcpu_run_generation(&self) -> Option<u64> {
        if !self.is_eligible() {
            return None;
        }
        Some(self.transition_generation.load(Ordering::SeqCst))
    }

    pub fn contains_ram(&self, guest_address: u64) -> bool {
        self.map
            .get()
            .is_some_and(|map| map.layout.region_containing(guest_address).is_some())
    }

    /// Releases one free-page report to the host.
    ///
    /// Returns `Skipped` when reclaim is not effective, the range is not
    /// releasable RAM, or the range overlaps a cycle already in flight. Returns
    /// an error only when guest RAM could not be remapped, which is fatal for
    /// the VM. Any other failure disables further reclaim and is reported
    /// through `stats().failed_operations` and the log.
    pub fn release_report(&self, range: GuestRange) -> Result<ReleaseOutcome, ReclaimStateError> {
        if !self.is_effective() {
            return Ok(self.skip());
        }
        let Some(map) = self.map.get() else {
            return Ok(self.skip());
        };
        let host = match map.layout.resolve(range) {
            Ok(Some(host)) => host,
            Ok(None) | Err(_) => return Ok(self.skip()),
        };
        let Some(region) = map.region_for(host.guest_range().start()) else {
            return Ok(self.skip());
        };
        let indexes = region.extent_indexes(host.guest_range());
        for index in indexes.clone() {
            let claimed = region.states[index].compare_exchange(
                EXTENT_MAPPED,
                EXTENT_TRANSITIONING,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            if claimed.is_err() {
                for undo in *indexes.start()..index {
                    region.states[undo].store(EXTENT_MAPPED, Ordering::SeqCst);
                }
                return Ok(self.skip());
            }
        }
        self.transition_generation.fetch_add(1, Ordering::SeqCst);

        let outcome = self.cycle(host, map.layout.granule());

        // Publish completion before the extent state. A vCPU that entered
        // during the cycle and waited on the extent must observe a changed
        // generation as soon as it sees the extent leave `Transitioning`;
        // the other order lets it read "mapped, unchanged generation" and
        // wrongly classify its fault as invalid. A failed remap leaves the
        // extent `Lost` so waiters fail instead of retrying a missing mapping.
        self.transition_generation.fetch_add(1, Ordering::SeqCst);
        let final_state = if matches!(outcome, Err(CycleFailure::Fatal(_))) {
            EXTENT_LOST
        } else {
            EXTENT_MAPPED
        };
        for index in indexes {
            region.states[index].store(final_state, Ordering::SeqCst);
        }

        match outcome {
            Ok(()) => {
                saturating_increment(&self.released_extents, 1);
                saturating_increment(&self.released_bytes, host.byte_len());
                Ok(ReleaseOutcome::Released)
            }
            Err(CycleFailure::Recoverable(error)) => {
                saturating_increment(&self.failed_operations, 1);
                self.disable(&format!("release cycle failed: {error}"));
                Ok(ReleaseOutcome::Skipped)
            }
            Err(CycleFailure::Fatal(error)) => {
                saturating_increment(&self.failed_operations, 1);
                self.disable(&format!("release cycle left guest RAM unmapped: {error}"));
                Err(error)
            }
        }
    }

    /// Classifies a stage-2 translation fault at `guest_address` taken by a
    /// vCPU that entered the guest at `entered_generation`.
    ///
    /// If the address lies in an extent whose release cycle is in flight, this
    /// waits for the remap. A fault on RAM that raced any cycle is `Retry`; a
    /// fault on RAM with no cycle since the vCPU entered, or on an address that
    /// is not RAM, is `Invalid`.
    pub fn resolve_translation_fault(
        &self,
        guest_address: u64,
        entered_generation: u64,
    ) -> Result<FaultResolution, ReclaimStateError> {
        let Some(map) = self.map.get() else {
            return Ok(FaultResolution::Invalid);
        };
        let Some(region) = map.region_for(guest_address) else {
            return Ok(FaultResolution::Invalid);
        };
        let waited = wait_for_extent(region.state(guest_address))?;
        if !waited && self.transition_generation.load(Ordering::SeqCst) == entered_generation {
            return Ok(FaultResolution::Invalid);
        }
        saturating_increment(&self.retried_faults, 1);
        Ok(FaultResolution::Retry)
    }

    fn cycle(&self, host: HostRange, granule: u64) -> Result<(), CycleFailure> {
        let size = usize::try_from(host.byte_len())
            .map_err(|_| CycleFailure::Recoverable(ReclaimStateError::ReleaseUnmap))?;
        let page_size = usize::try_from(granule)
            .map_err(|_| CycleFailure::Recoverable(ReclaimStateError::ReleaseUnmap))?;
        let guest_address = host.guest_range().start();
        let address = host.host_start() as *mut c_void;
        let flags = hvf_permissions(host.permissions());

        if unsafe { hv_vm_unmap(guest_address, size) } != HV_SUCCESS {
            return Err(CycleFailure::Recoverable(ReclaimStateError::ReleaseUnmap));
        }
        let advice = unsafe { advise_free(address, size, page_size) }
            .map_err(ReclaimStateError::DiscardAdvice);
        #[cfg(test)]
        self.run_transition_hook();
        if unsafe { hv_vm_map(address, guest_address, size, flags) } != HV_SUCCESS {
            return Err(CycleFailure::Fatal(ReclaimStateError::RestoreMap));
        }
        advice.map_err(CycleFailure::Recoverable)
    }

    fn skip(&self) -> ReleaseOutcome {
        saturating_increment(&self.skipped_reports, 1);
        ReleaseOutcome::Skipped
    }

    fn disable(&self, reason: &str) {
        if !self.disabled.swap(true, Ordering::AcqRel) {
            log::error!("disabling guest RAM reclaim: {reason}");
        }
    }

    #[cfg(test)]
    pub(crate) fn enable_policy_for_test(&self) {
        self.policy_enabled.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn qualify_for_test(&self) {
        if self.is_eligible() && self.policy_enabled.load(Ordering::Acquire) {
            self.qualification
                .store(ReclaimQualification::Passed as u64, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub(crate) fn mark_extent_lost_for_test(&self, guest_address: u64) {
        let map = self.map.get().expect("initialized map");
        let region = map.region_for(guest_address).expect("RAM extent");
        region
            .state(guest_address)
            .store(EXTENT_LOST, Ordering::SeqCst);
    }

    /// Runs `hook` after the unmap and advice of every cycle, before the remap.
    #[cfg(test)]
    pub(crate) fn set_transition_hook(&self, hook: Box<dyn Fn() + Send + Sync>) {
        *self.transition_hook.lock().expect("transition hook lock") = Some(hook);
    }

    #[cfg(test)]
    fn run_transition_hook(&self) {
        if let Some(hook) = self
            .transition_hook
            .lock()
            .expect("transition hook lock")
            .as_ref()
        {
            hook();
        }
    }
}

impl Default for ReclaimState {
    fn default() -> Self {
        Self::new()
    }
}

/// Waits until the extent is no longer in transition. Returns whether it had
/// to wait, which by itself proves a cycle was in flight for this extent.
fn wait_for_extent(state: &AtomicU8) -> Result<bool, ReclaimStateError> {
    match state.load(Ordering::SeqCst) {
        EXTENT_MAPPED => return Ok(false),
        EXTENT_LOST => return Err(ReclaimStateError::ExtentLost),
        _ => {}
    }
    let deadline = Instant::now() + TRANSITION_WAIT_TIMEOUT;
    let mut spins = 0;
    loop {
        match state.load(Ordering::SeqCst) {
            EXTENT_MAPPED => return Ok(true),
            EXTENT_LOST => return Err(ReclaimStateError::ExtentLost),
            _ => {}
        }
        if spins < SPINS_BEFORE_YIELD {
            spins += 1;
            hint::spin_loop();
            continue;
        }
        if Instant::now() >= deadline {
            return Err(ReclaimStateError::TransitionTimeout);
        }
        thread::yield_now();
    }
}

fn hvf_permissions(permissions: RamPermissions) -> hv_memory_flags_t {
    let bits = permissions.bits();
    let mut flags = 0;
    if bits & RamPermissions::READ != 0 {
        flags |= HV_MEMORY_READ;
    }
    if bits & RamPermissions::WRITE != 0 {
        flags |= HV_MEMORY_WRITE;
    }
    if bits & RamPermissions::EXECUTE != 0 {
        flags |= HV_MEMORY_EXEC;
    }
    flags.into()
}

fn saturating_increment(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

#[cfg(test)]
mod tests {
    use arch::guest_memory::{GuestRange, RamLayout, RamPermissions, RamRegion};

    use crate::reclaim::{
        EXTENT_BYTES, FaultResolution, ReclaimQualification, ReclaimState, ReclaimStateError,
        ReleaseOutcome,
    };

    const RAM_START: u64 = 0x4000_0000;
    const RAM_LEN: u64 = 8 * EXTENT_BYTES;

    fn layout() -> RamLayout {
        let mut layout = RamLayout::new(0x4000).unwrap();
        layout
            .register_region(
                RamRegion::new(
                    RAM_START,
                    0x1_0000_0000,
                    RAM_LEN,
                    RamPermissions::READ_WRITE_EXECUTE,
                )
                .unwrap(),
            )
            .unwrap();
        layout
    }

    fn effective_state() -> ReclaimState {
        let state = ReclaimState::new();
        state.initialize(layout()).unwrap();
        state.enable_policy_for_test();
        state.qualify_for_test();
        assert!(state.is_effective());
        state
    }

    #[test]
    fn initialization_happens_once() {
        let state = ReclaimState::new();
        assert!(!state.is_initialized());
        assert!(!state.is_eligible());
        state.initialize(layout()).unwrap();
        assert!(state.is_initialized());
        assert!(state.is_eligible());
        assert!(matches!(
            state.initialize(layout()),
            Err(ReclaimStateError::AlreadyInitialized)
        ));
    }

    #[test]
    fn initialization_rejects_non_native_granules() {
        let page_size = crate::discard::native_page_size().unwrap() as u64;
        let state = ReclaimState::new();
        assert!(matches!(
            state.initialize(RamLayout::new(page_size * 2).unwrap()),
            Err(ReclaimStateError::Layout(_))
        ));
        assert!(!state.is_initialized());
    }

    #[test]
    fn empty_layout_never_qualifies() {
        let state = ReclaimState::new();
        state.initialize(RamLayout::new(0x4000).unwrap()).unwrap();
        state.enable_policy_for_test();
        state.record_qualification(ReclaimQualification::Passed, "test");
        assert_eq!(state.qualification(), ReclaimQualification::Inconclusive);
        assert!(!state.is_effective());
        assert_eq!(state.vcpu_run_generation(), None);
    }

    #[test]
    fn disabled_policy_resets_qualification() {
        let state = effective_state();
        state.set_policy_enabled(false);
        assert_eq!(state.qualification(), ReclaimQualification::NotRun);
        assert!(!state.is_effective());
        let range = GuestRange::new(RAM_START, EXTENT_BYTES).unwrap();
        assert_eq!(
            state.release_report(range).unwrap(),
            ReleaseOutcome::Skipped
        );
        assert_eq!(state.stats().skipped_reports, 1);
    }

    #[test]
    fn ineffective_state_skips_reports_without_touching_memory() {
        let state = ReclaimState::new();
        state.initialize(layout()).unwrap();
        let range = GuestRange::new(RAM_START, EXTENT_BYTES).unwrap();
        assert_eq!(
            state.release_report(range).unwrap(),
            ReleaseOutcome::Skipped
        );
        assert_eq!(state.stats().skipped_reports, 1);
        assert_eq!(state.stats().released_extents, 0);
    }

    #[test]
    fn faults_outside_ram_or_without_a_cycle_are_invalid() {
        let state = effective_state();
        let generation = state.vcpu_run_generation().unwrap();
        assert_eq!(
            state.resolve_translation_fault(0x1000, generation).unwrap(),
            FaultResolution::Invalid
        );
        assert_eq!(
            state
                .resolve_translation_fault(RAM_START + 0x100, generation)
                .unwrap(),
            FaultResolution::Invalid
        );
        assert!(state.contains_ram(RAM_START));
        assert!(!state.contains_ram(RAM_START + RAM_LEN));
        assert_eq!(state.stats().retried_faults, 0);
    }

    #[test]
    fn fault_after_a_generation_change_retries() {
        let state = effective_state();
        let generation = state.vcpu_run_generation().unwrap();
        state
            .transition_generation
            .fetch_add(2, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            state
                .resolve_translation_fault(RAM_START + EXTENT_BYTES, generation)
                .unwrap(),
            FaultResolution::Retry
        );
        assert_eq!(state.stats().retried_faults, 1);
    }

    #[test]
    fn fault_in_a_lost_extent_is_an_error_not_a_retry() {
        let state = effective_state();
        let generation = state.vcpu_run_generation().unwrap();
        state.mark_extent_lost_for_test(RAM_START + 3 * EXTENT_BYTES);
        assert!(matches!(
            state.resolve_translation_fault(RAM_START + 3 * EXTENT_BYTES + 0x800, generation),
            Err(ReclaimStateError::ExtentLost)
        ));
        // Neighbouring extents are unaffected.
        assert_eq!(
            state
                .resolve_translation_fault(RAM_START + 2 * EXTENT_BYTES, generation)
                .unwrap(),
            FaultResolution::Invalid
        );
    }

    #[test]
    fn disabling_reclaim_preserves_fault_recovery_and_lost_extent_errors() {
        let state = effective_state();
        let entered = state.vcpu_run_generation().unwrap();
        state
            .transition_generation
            .fetch_add(2, std::sync::atomic::Ordering::SeqCst);
        state.disable("test completed-cycle failure");
        state.set_policy_enabled(false);
        assert!(!state.is_effective());
        assert_eq!(state.vcpu_run_generation(), Some(entered + 2));
        assert_eq!(
            state.resolve_translation_fault(RAM_START, entered).unwrap(),
            FaultResolution::Retry
        );
        state.mark_extent_lost_for_test(RAM_START);
        assert!(matches!(
            state.resolve_translation_fault(RAM_START, entered),
            Err(ReclaimStateError::ExtentLost)
        ));
    }

    #[test]
    fn unaligned_or_foreign_reports_are_skipped() {
        let state = effective_state();
        let tiny = GuestRange::new(RAM_START + 0x1000, 0x1000).unwrap();
        assert_eq!(state.release_report(tiny).unwrap(), ReleaseOutcome::Skipped);
        let foreign = GuestRange::new(0x1000, 0x4000).unwrap();
        assert_eq!(
            state.release_report(foreign).unwrap(),
            ReleaseOutcome::Skipped
        );
        let straddling = GuestRange::new(RAM_START + RAM_LEN - 0x4000, 0x8000).unwrap();
        assert_eq!(
            state.release_report(straddling).unwrap(),
            ReleaseOutcome::Skipped
        );
        assert_eq!(state.stats().skipped_reports, 3);
        assert_eq!(state.stats().released_extents, 0);
    }

    #[test]
    fn extent_indexes_cover_partial_extents() {
        let map = crate::reclaim::ExtentMap::new(layout());
        let region = map.region_for(RAM_START).unwrap();
        assert_eq!(region.states.len(), 8);
        let range = GuestRange::new(RAM_START + EXTENT_BYTES - 0x4000, 0x8000).unwrap();
        assert_eq!(region.extent_indexes(range), 0..=1);
        let whole = GuestRange::new(RAM_START, RAM_LEN).unwrap();
        assert_eq!(region.extent_indexes(whole), 0..=7);
        assert!(map.region_for(RAM_START + RAM_LEN).is_none());
    }
}
