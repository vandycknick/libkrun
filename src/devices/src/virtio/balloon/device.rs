use std::cmp;
use std::io::Write;
#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(target_os = "macos")]
use arch::guest_memory::GuestRange;
#[cfg(target_os = "macos")]
use hvf::reclaim::{ReclaimState, ReleaseOutcome};
#[cfg(target_os = "macos")]
use hvf::remap::HostMemoryRemapper;
use utils::eventfd::EventFd;
#[cfg(target_os = "macos")]
use vm_memory::Address;
use vm_memory::ByteValued;

use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;
use crate::virtio::queue::VIRTQ_DESC_F_NEXT;
use crate::virtio::{
    ActivateError, ActivateResult, BalloonError, DeviceQueue, DeviceState, QueueConfig,
    RuntimeGuestMemory, VirtioDevice,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::DiscardVirtualMemory;

// Inflate queue.
pub(crate) const IFQ_INDEX: usize = 0;
// Deflate queue.
pub(crate) const DFQ_INDEX: usize = 1;
// Stats queue.
pub(crate) const STQ_INDEX: usize = 2;
// Page-hinting queue.
pub(crate) const PHQ_INDEX: usize = 3;
// Free page reporting queue.
pub(crate) const FRQ_INDEX: usize = 4;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_STATS_VQ as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_REPORTING as u64);

fn reporting_features(enabled: bool) -> u64 {
    if enabled {
        AVAIL_FEATURES
    } else {
        AVAIL_FEATURES & !(1 << uapi::VIRTIO_BALLOON_F_REPORTING)
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioBalloonConfig {
    /* Number of pages host wants Guest to give up. */
    num_pages: u32,
    /* Number of pages we've actually got in balloon. */
    actual: u32,
    /* Free page report command id, readonly by guest */
    free_page_report_cmd_id: u32,
    /* Stores PAGE_POISON if page poisoning is in use */
    poison_val: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

pub struct Balloon {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioBalloonConfig,
    #[cfg(target_os = "macos")]
    reclaim_state: Option<Arc<ReclaimState>>,
    #[cfg(target_os = "macos")]
    host_memory_remapper: Option<Arc<HostMemoryRemapper>>,
    #[cfg(target_os = "macos")]
    failure_signal: Option<(EventFd, Arc<AtomicI32>)>,
}

impl Balloon {
    pub fn new() -> super::Result<Balloon> {
        Ok(Balloon {
            queues: None,
            avail_features: reporting_features(!cfg!(target_os = "macos")),
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(BalloonError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioBalloonConfig::default(),
            #[cfg(target_os = "macos")]
            reclaim_state: None,
            #[cfg(target_os = "macos")]
            host_memory_remapper: None,
            #[cfg(target_os = "macos")]
            failure_signal: None,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn set_reclaim_state(&mut self, state: Arc<ReclaimState>) {
        self.avail_features = reporting_features(state.is_effective());
        self.reclaim_state = Some(state);
    }

    #[cfg(target_os = "macos")]
    pub fn set_host_memory_remapper(&mut self, remapper: Option<Arc<HostMemoryRemapper>>) {
        self.host_memory_remapper = remapper;
    }

    #[cfg(target_os = "macos")]
    pub fn set_failure_signal(&mut self, event: EventFd, exit_code: Arc<AtomicI32>) {
        self.failure_signal = Some((event, exit_code));
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn fail_vm(&self, reason: &str) {
        error!("balloon: fatal free-page reporting error: {reason}");
        if let Some((event, exit_code)) = &self.failure_signal {
            exit_code.store(1, Ordering::SeqCst);
            if let Err(error) = event.write(1) {
                error!("balloon: failed to signal fatal VM exit: {error}");
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub(crate) fn fail_vm(&self, reason: &str) {
        error!("balloon: fatal free-page reporting error: {reason}");
    }

    pub fn id(&self) -> &str {
        defs::BALLOON_DEV_ID
    }

    fn reporting_negotiated(&self) -> bool {
        self.acked_features & (1 << uapi::VIRTIO_BALLOON_F_REPORTING as u64) != 0
    }

    pub fn process_frq(&mut self) -> Result<bool, String> {
        debug!("balloon: process_frq()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let reporting_negotiated = self.reporting_negotiated();
        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let mut have_used = false;
        #[cfg(target_os = "macos")]
        let mut prepared = false;

        while let Some(head) = queues[FRQ_INDEX].queue.pop(mem) {
            let index = head.index;
            let mut descriptors = Vec::new();
            let mut descriptor = Some(head);
            let mut chain_valid = true;
            while let Some(current) = descriptor {
                let expects_next = current.flags & VIRTQ_DESC_F_NEXT != 0;
                let next = current.next_descriptor();
                descriptors.push((current.addr, current.len));
                if expects_next && next.is_none() {
                    chain_valid = false;
                    break;
                }
                descriptor = next;
            }

            if !chain_valid {
                debug!("balloon: safely skipping malformed free-page report chain");
                queues[FRQ_INDEX]
                    .queue
                    .add_used(mem, index, 0)
                    .map_err(|error| format!("failed to acknowledge malformed report: {error}"))?;
                have_used = true;
                continue;
            }

            if !reporting_negotiated {
                debug!("balloon: safely skipping unnegotiated free-page report");
                queues[FRQ_INDEX]
                    .queue
                    .add_used(mem, index, 0)
                    .map_err(|error| {
                        format!("failed to acknowledge unnegotiated report: {error}")
                    })?;
                have_used = true;
                continue;
            }

            #[cfg(not(target_os = "macos"))]
            let Some(host_addresses): Option<Vec<_>> = descriptors
                .iter()
                .map(|(address, len)| mem.get_host_address(*address, *len as usize).ok())
                .collect()
            else {
                debug!("balloon: safely skipping invalid free-page report chain");
                queues[FRQ_INDEX]
                    .queue
                    .add_used(mem, index, 0)
                    .map_err(|error| format!("failed to acknowledge invalid report: {error}"))?;
                have_used = true;
                continue;
            };

            // Each macOS release is an unmap/advise/remap cycle whose cost is
            // dominated by the TLB invalidation broadcast, so adjacent
            // descriptors are merged into one cycle per contiguous run.
            // Only this unacknowledged chain still owns these pages; never
            // retain its ranges for release after add_used returns them.
            #[cfg(target_os = "macos")]
            if let Some(state) = &self.reclaim_state {
                if !prepared && let Some(remapper) = &self.host_memory_remapper {
                    // The active VMM owns the registered RAM throughout this callback.
                    unsafe { remapper.before_reports() }.map_err(|error| error.to_string())?;
                    prepared = true;
                }
                for range in coalesce_free_page_ranges(&descriptors) {
                    debug!(
                        "balloon: free report guest_addr={:#x} len={}",
                        range.start(),
                        range.byte_len()
                    );
                    match state.release_report(range) {
                        Ok(ReleaseOutcome::Released | ReleaseOutcome::Skipped) => {}
                        Err(error) => return Err(error.to_string()),
                    }
                }
            }

            #[cfg(not(target_os = "macos"))]
            for (descriptor_index, (addr, len)) in descriptors.into_iter().enumerate() {
                let host_addr = &host_addresses[descriptor_index];
                debug!("balloon: free report guest_addr={:?} len={}", addr, len);
                #[cfg(target_os = "linux")]
                let advice = libc::MADV_DONTNEED;
                #[cfg(target_os = "linux")]
                unsafe {
                    libc::madvise(
                        host_addr.as_ptr() as *mut libc::c_void,
                        len as usize,
                        advice,
                    )
                };
                #[cfg(target_os = "windows")]
                unsafe {
                    DiscardVirtualMemory(host_addr.as_ptr() as *mut core::ffi::c_void, len as usize)
                };
            }

            have_used = true;
            queues[FRQ_INDEX]
                .queue
                .add_used(mem, index, 0)
                .map_err(|error| format!("failed to add used report to queue: {error}"))?;
        }

        Ok(have_used)
    }
}

/// Merges the descriptors of one free-page report into maximal contiguous
/// guest ranges, dropping descriptors that are empty or overflow.
#[cfg(target_os = "macos")]
fn coalesce_free_page_ranges(descriptors: &[(vm_memory::GuestAddress, u32)]) -> Vec<GuestRange> {
    let mut spans: Vec<(u64, u64)> = descriptors
        .iter()
        .filter_map(|(address, len)| {
            let start = address.raw_value();
            let end = start.checked_add(u64::from(*len))?;
            (end > start).then_some((start, end))
        })
        .collect();
    spans.sort_unstable();
    let mut runs: Vec<GuestRange> = Vec::with_capacity(spans.len());
    let mut current: Option<(u64, u64)> = None;
    for (start, end) in spans {
        match current {
            Some((run_start, run_end)) if start <= run_end => {
                current = Some((run_start, run_end.max(end)));
            }
            Some((run_start, run_end)) => {
                runs.extend(GuestRange::new(run_start, run_end - run_start).ok());
                current = Some((start, end));
            }
            None => current = Some((start, end)),
        }
    }
    if let Some((run_start, run_end)) = current {
        runs.extend(GuestRange::new(run_start, run_end - run_start).ok());
    }
    runs
}

impl VirtioDevice for Balloon {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_BALLOON
    }

    fn device_name(&self) -> &str {
        "balloon"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "balloon: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::VirtioDevice;
    use crate::virtio::balloon::defs::uapi;
    use crate::virtio::balloon::device::Balloon;

    #[cfg(target_os = "macos")]
    #[test]
    fn free_page_ranges_coalesce_adjacent_descriptors_in_any_order() {
        use vm_memory::GuestAddress;

        use crate::virtio::balloon::device::coalesce_free_page_ranges;

        let mib = 2 * 1024 * 1024;
        let runs = coalesce_free_page_ranges(&[
            (GuestAddress(4 * mib), mib as u32),
            (GuestAddress(0), mib as u32),
            (GuestAddress(mib), mib as u32),
            (GuestAddress(8 * mib), 0),
            (GuestAddress(u64::MAX - 1), 16),
            (GuestAddress(5 * mib), mib as u32),
        ]);
        let spans: Vec<(u64, u64)> = runs
            .iter()
            .map(|range| (range.start(), range.byte_len()))
            .collect();
        assert_eq!(spans, vec![(0, 2 * mib), (4 * mib, 2 * mib)]);
    }

    #[test]
    fn reporting_selection_preserves_unrelated_features() {
        use crate::virtio::balloon::device::{AVAIL_FEATURES, reporting_features};
        let reporting = 1 << uapi::VIRTIO_BALLOON_F_REPORTING;
        assert_eq!(reporting_features(true), AVAIL_FEATURES);
        assert_eq!(reporting_features(false), AVAIL_FEATURES & !reporting);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unqualified_balloon_does_not_advertise_reporting() {
        use hvf::reclaim::ReclaimState;
        use std::sync::Arc;
        let mut balloon = Balloon::new().unwrap();
        let reporting = 1 << uapi::VIRTIO_BALLOON_F_REPORTING;
        assert_eq!(balloon.avail_features() & reporting, 0);
        let state = Arc::new(ReclaimState::new());
        state.set_policy_enabled(true);
        balloon.set_reclaim_state(state);
        assert_eq!(balloon.avail_features() & reporting, 0);
        assert_ne!(
            balloon.avail_features() & (1 << uapi::VIRTIO_BALLOON_F_STATS_VQ),
            0
        );
    }

    #[test]
    fn free_page_reporting_requires_feature_negotiation() {
        let mut balloon = Balloon::new().unwrap();
        assert!(!balloon.reporting_negotiated());

        balloon.set_acked_features(1 << uapi::VIRTIO_BALLOON_F_REPORTING);
        assert!(balloon.reporting_negotiated());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fatal_reporting_error_signals_vm_exit() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicI32, Ordering};

        use utils::eventfd::{EFD_NONBLOCK, EventFd};

        let mut balloon = Balloon::new().unwrap();
        let event = EventFd::new(EFD_NONBLOCK).unwrap();
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        balloon.set_failure_signal(event.try_clone().unwrap(), exit_code.clone());

        balloon.fail_vm("test failure");

        assert_eq!(exit_code.load(Ordering::SeqCst), 1);
        assert_eq!(event.read().unwrap(), 1);
    }
}
