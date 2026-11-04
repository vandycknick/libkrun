#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicI32, Ordering};
use std::task::Poll;

#[cfg(target_os = "macos")]
use arch::guest_memory::GuestRange;
#[cfg(target_os = "macos")]
use hvf::reclaim::{ReclaimState, ReleaseOutcome};
#[cfg(target_os = "macos")]
use hvf::remap::HostMemoryRemapper;
use polly::event_manager::{BarrierKey, BarrierRequest};
use utils::eventfd::EventFd;
use utils::state::{Reader, Writer};
#[cfg(target_os = "macos")]
use vm_memory::Address;
use vm_memory::ByteValued;

use crate::virtio::InterruptTransport;
use crate::virtio::balloon::{defs, defs::uapi};
use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::lifecycle::{
    CallbackState, DormantDeviceContext, ProviderBeginError, ProviderFault, QuiesceCompletion,
    RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
};
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
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
    pub(crate) callbacks: CallbackState,
    host_reclaim_enabled: bool,
    descriptors: DescriptorChainSnapshot,
    #[cfg(target_os = "macos")]
    reclaim_state: Option<Arc<ReclaimState>>,
    #[cfg(target_os = "macos")]
    host_memory_remapper: Option<Arc<HostMemoryRemapper>>,
    #[cfg(target_os = "macos")]
    failure_signal: Option<(EventFd, Arc<AtomicI32>)>,
}

impl Balloon {
    pub fn new() -> crate::virtio::balloon::Result<Balloon> {
        Ok(Balloon {
            queues: None,
            avail_features: reporting_features(!cfg!(target_os = "macos")),
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(BalloonError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioBalloonConfig::default(),
            callbacks: CallbackState::new(),
            host_reclaim_enabled: true,
            descriptors: DescriptorChainSnapshot::new(defs::QUEUE_SIZE),
            #[cfg(target_os = "macos")]
            reclaim_state: None,
            #[cfg(target_os = "macos")]
            host_memory_remapper: None,
            #[cfg(target_os = "macos")]
            failure_signal: None,
        })
    }

    /// Binds the exact source offer without granting destructive reclaim on
    /// destination RAM, including when reporting was negotiated on the source.
    pub fn new_restore_binding(avail_features: u64) -> crate::virtio::balloon::Result<Balloon> {
        if avail_features != reporting_features(true) && avail_features != reporting_features(false)
        {
            return Err(BalloonError::UnsupportedRestoreFeatures(avail_features));
        }
        let mut balloon = Self::new()?;
        balloon.avail_features = avail_features;
        balloon.host_reclaim_enabled = false;
        Ok(balloon)
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_reclaim_enabled(&self) -> bool {
        self.host_reclaim_enabled
    }

    #[cfg(target_os = "macos")]
    pub fn set_reclaim_state(&mut self, state: Arc<ReclaimState>) {
        if self.host_reclaim_enabled {
            self.avail_features = reporting_features(state.is_effective());
        }
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
        if !self.callbacks.admission_open() {
            return Ok(false);
        }
        if self.callbacks.preflight(&self.queues).is_err() {
            return Err("retained reporting terminality fault".into());
        }
        let result = self.process_reports();
        if result.is_err() {
            self.callbacks.retain_fault(ProviderFault::DeviceState);
            if let Some(queue) = self
                .queues
                .as_mut()
                .and_then(|queues| queues.get_mut(FRQ_INDEX))
            {
                queue.queue.record_processing_failure();
            }
        }
        result
    }

    fn process_reports(&mut self) -> Result<bool, String> {
        let reporting_enabled = self.reporting_negotiated() && self.host_reclaim_enabled;
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return Ok(false);
        };
        let Some(queue) = self
            .queues
            .as_mut()
            .and_then(|queues| queues.get_mut(FRQ_INDEX))
        else {
            return Err("missing free-page reporting queue".into());
        };
        if !queue.queue.ready {
            return Ok(false);
        }
        let mut have_used = false;
        #[cfg(target_os = "macos")]
        let mut prepared = false;
        #[cfg(target_os = "linux")]
        // nix's sysconf/mman modules are not enabled in this crate.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|size| *size != 0)
            .ok_or_else(|| "invalid host page granule".to_string())?;
        while let Some(head) = queue.queue.pop(mem) {
            let index = head.index;
            let snapshot = self
                .descriptors
                .read(head)
                .map_err(|error| format!("invalid free-page report chain: {error}"))?;
            if snapshot
                .descriptors()
                .iter()
                .any(|descriptor| descriptor.flags & VIRTQ_DESC_F_WRITE == 0)
            {
                return Err("free-page report is not device-writable".into());
            }

            if reporting_enabled {
                #[cfg(not(target_os = "macos"))]
                for descriptor in snapshot.descriptors() {
                    mem.try_access(
                        descriptor.len as usize,
                        vm_memory::GuestAddress(descriptor.addr),
                        |_, len, _, slice| {
                            #[cfg(target_os = "linux")]
                            if !len.is_multiple_of(page_size)
                                || !(slice.ptr_guard_mut().as_ptr() as usize)
                                    .is_multiple_of(page_size)
                            {
                                return Err(vm_memory::GuestMemoryError::IOError(
                                    std::io::Error::other(
                                        "reported range is not host-page aligned",
                                    ),
                                ));
                            }
                            #[cfg(not(target_os = "linux"))]
                            let _ = slice;
                            Ok(len)
                        },
                    )
                    .map_err(|error| format!("invalid reported range: {error}"))?;
                }

                #[cfg(target_os = "macos")]
                if let Some(state) = &self.reclaim_state {
                    if !prepared && let Some(remapper) = &self.host_memory_remapper {
                        // The callback owner retains registered RAM throughout normalization.
                        unsafe { remapper.before_reports() }.map_err(|error| error.to_string())?;
                        prepared = true;
                    }
                    for range in
                        coalesce_free_page_ranges(snapshot.descriptors().iter().map(|descriptor| {
                            (vm_memory::GuestAddress(descriptor.addr), descriptor.len)
                        }))
                    {
                        match state.release_report(range) {
                            Ok(ReleaseOutcome::Released | ReleaseOutcome::Skipped) => {}
                            Err(error) => return Err(error.to_string()),
                        }
                    }
                }

                #[cfg(not(target_os = "macos"))]
                for descriptor in snapshot.descriptors() {
                    mem.try_access(
                        descriptor.len as usize,
                        vm_memory::GuestAddress(descriptor.addr),
                        |_, len, _, slice| {
                            let host = slice.ptr_guard_mut();
                            #[cfg(target_os = "linux")]
                            {
                                // nix::sys::mman is not enabled in this crate's existing feature set.
                                let result = unsafe {
                                    libc::madvise(host.as_ptr().cast(), len, libc::MADV_DONTNEED)
                                };
                                if result != 0 {
                                    return Err(vm_memory::GuestMemoryError::IOError(
                                        std::io::Error::last_os_error(),
                                    ));
                                }
                            }
                            #[cfg(target_os = "windows")]
                            {
                                let result =
                                    unsafe { DiscardVirtualMemory(host.as_ptr().cast(), len) };
                                if result != 0 {
                                    return Err(vm_memory::GuestMemoryError::IOError(
                                        std::io::Error::from_raw_os_error(result as i32),
                                    ));
                                }
                            }
                            Ok(len)
                        },
                    )
                    .map_err(|error| format!("failed report discard: {error}"))?;
                }
            }
            queue
                .queue
                .add_used(mem, index, 0)
                .map_err(|error| format!("failed to publish used report: {error}"))?;
            have_used = true;
        }
        Ok(have_used)
    }

    pub(crate) fn process_and_notify(&mut self) {
        let result = self.process_frq();
        match result {
            Ok(true) => {
                let result = match (&self.device_state, self.queues.as_mut()) {
                    (DeviceState::Activated(memory, interrupt), Some(queues)) => queues[FRQ_INDEX]
                        .queue
                        .needs_notification(memory)
                        .map_err(|_| ProviderFault::QueueState)
                        .and_then(|needed| {
                            if needed {
                                interrupt
                                    .try_signal_used_queue()
                                    .map_err(|_| ProviderFault::Notification)
                            } else {
                                Ok(())
                            }
                        }),
                    _ => Err(ProviderFault::DeviceState),
                };
                if let Err(fault) = result {
                    self.callbacks.retain_fault(fault);
                    self.fail_vm("free-page report notification failed");
                }
            }
            Ok(false) => {}
            Err(error) => self.fail_vm(&error),
        }
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<(u64, VirtioBalloonConfig), ProviderFault> {
        let mut reader = Reader::new(payload);
        let decoded = (|| {
            if reader.u16()? != 1
                || reader.u32()? != uapi::VIRTIO_ID_BALLOON
                || reader.u64()? != self.avail_features
            {
                return Err(utils::state::Error::Invalid("balloon profile"));
            }
            let acked = reader.u64()?;
            if acked & !self.avail_features != 0 {
                return Err(utils::state::Error::Invalid("balloon features"));
            }
            let config = VirtioBalloonConfig {
                num_pages: reader.u32()?,
                actual: reader.u32()?,
                free_page_report_cmd_id: reader.u32()?,
                poison_val: reader.u32()?,
            };
            reader.finish()?;
            Ok((acked, config))
        })();
        decoded.map_err(|_| ProviderFault::DeviceState)
    }
}

/// Merges the descriptors of one free-page report into maximal contiguous
/// guest ranges, dropping descriptors that are empty or overflow.
#[cfg(target_os = "macos")]
fn coalesce_free_page_ranges(
    descriptors: impl IntoIterator<Item = (vm_memory::GuestAddress, u32)>,
) -> Vec<GuestRange> {
    let mut spans: Vec<(u64, u64)> = descriptors
        .into_iter()
        .filter_map(|(address, len)| {
            let start = address.raw_value();
            let end = start.checked_add(u64::from(len))?;
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        let count = data.len().min(config_slice.len() - offset as usize);
        data[..count].copy_from_slice(&config_slice[offset as usize..offset as usize + count]);
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

    fn state_provider(&self) -> Option<&dyn VirtioStateProvider> {
        Some(self)
    }

    fn state_provider_mut(&mut self) -> Option<&mut dyn VirtioStateProvider> {
        Some(self)
    }
}

impl VirtioStateProvider for Balloon {
    fn preflight(&self) -> Result<(), ProviderFault> {
        self.callbacks.preflight(&self.queues)?;
        if self.is_activated()
            && self
                .queues
                .as_ref()
                .is_some_and(|queues| queues.len() != defs::NUM_QUEUES)
        {
            return Err(ProviderFault::QueueCount);
        }
        Ok(())
    }

    fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError> {
        self.callbacks.begin_quiesce(request, &mut self.queues)
    }

    fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.callbacks.poll_quiesce(key, &mut self.queues)
    }

    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance {
        let count = if self.is_activated() {
            defs::NUM_QUEUES
        } else {
            0
        };
        let acceptance = self
            .callbacks
            .begin_resume(request, queues, &mut self.queues, count);
        if !matches!(acceptance, ResumeAcceptance::Accepted) {
            return acceptance;
        }
        if self.is_activated() {
            if self.activate_evt.write(1).is_err() {
                self.callbacks.retain_fault(ProviderFault::Notification);
                return ResumeAcceptance::AcceptedWithFailure(ProviderFault::Notification);
            }
            self.process_and_notify();
            if let Err(fault) = self.callbacks.preflight(&self.queues) {
                self.callbacks.retain_fault(fault);
                return ResumeAcceptance::AcceptedWithFailure(fault);
            }
        }
        ResumeAcceptance::Accepted
    }

    fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        self.callbacks.preflight(&self.queues)?;
        self.callbacks.poll_resume(key)
    }

    fn state_limit(&self) -> u32 {
        4096
    }

    fn capture_payload(&self, key: BarrierKey) -> Result<Vec<u8>, ProviderFault> {
        self.callbacks.require_cut(key)?;
        let mut writer = Writer::new(self.state_limit() as usize);
        writer
            .u16(1)
            .and_then(|()| writer.u32(uapi::VIRTIO_ID_BALLOON))
            .and_then(|()| writer.u64(self.avail_features))
            .and_then(|()| writer.u64(self.acked_features))
            .and_then(|()| writer.u32(self.config.num_pages))
            .and_then(|()| writer.u32(self.config.actual))
            .and_then(|()| writer.u32(self.config.free_page_report_cmd_id))
            .and_then(|()| writer.u32(self.config.poison_val))
            .map_err(|_| ProviderFault::DeviceState)?;
        Ok(writer.finish())
    }

    fn validate_payload(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.decode_payload(payload).map(|_| ())
    }

    fn validate_restore(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        if self.is_activated() || self.queues.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.validate_payload(payload)
    }

    fn apply_payload(&mut self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.callbacks.require_quiesced()?;
        let (acked, config) = self.decode_payload(payload)?;
        self.acked_features = acked;
        self.config = config;
        Ok(())
    }

    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        let (acked, config) = self.decode_payload(payload)?;
        self.callbacks.prepare_restore(request)?;
        match context.reclaim_policy {
            RestoredReclaimPolicy::Disabled => self.host_reclaim_enabled = false,
        }
        self.acked_features = acked;
        self.config = config;
        self.device_state = if context.activated {
            DeviceState::Activated(context.memory, context.interrupt)
        } else {
            DeviceState::Inactive
        };
        Ok(())
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
        let runs = coalesce_free_page_ranges([
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

    fn request(operation: u64) -> polly::event_manager::BarrierRequest {
        use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
        use std::time::{Duration, Instant};
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(11),
            },
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    #[test]
    fn provider_balloon_config_codec_is_exact_and_bounded() {
        use crate::virtio::lifecycle::VirtioStateProvider;
        use std::task::Poll;
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon.config.num_pages = 17;
        balloon.config.actual = 13;
        balloon.config.free_page_report_cmd_id = 0x12345678;
        balloon.config.poison_val = 0x87654321;
        balloon.begin_quiesce(request(1)).unwrap();
        assert!(matches!(
            balloon.poll_quiesce(request(1).key).unwrap(),
            Poll::Ready(_)
        ));
        let payload = balloon.capture_payload(request(1).key).unwrap();
        assert_eq!(payload.len(), 38);
        let mut config = [0; 16];
        balloon.read_config(0, &mut config);
        assert_eq!(&payload[22..], &config);
        for length in 0..payload.len() {
            assert!(balloon.validate_payload(&payload[..length]).is_err());
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(balloon.validate_payload(&trailing).is_err());
        let mut wrong_features = payload.clone();
        wrong_features[14..22].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(balloon.validate_payload(&wrong_features).is_err());
        assert!(balloon.capture_payload(request(2).key).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_real_report_cut_keeps_stats_and_restored_reclaim_disabled() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::{FRQ_INDEX, STQ_INDEX};
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
        };
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use std::task::Poll;
        use utils::eventfd::{EFD_NONBLOCK, EventFd};
        use vm_memory::GuestAddress;

        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let child_report_address = GuestAddress((10 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        rings[STQ_INDEX].dtable[0].set(0x9000, 16, 0, 0);
        rings[STQ_INDEX].avail.ring[0].set(0);
        rings[STQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let interrupt = || {
            InterruptTransport::new(
                DummyIrqChip::new().into(),
                "balloon-provider-test".into(),
                None,
            )
            .unwrap()
        };
        let mut source = Balloon::new().unwrap();
        source.set_acked_features(source.avail_features());
        source
            .activate(
                memory.clone(),
                interrupt(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(
                            ring.create_queue(),
                            Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                        )
                    })
                    .collect(),
            )
            .unwrap();
        assert!(source.process_frq().unwrap());
        let mut contents = vec![1u8; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
        source.begin_quiesce(request(1)).unwrap();
        let Poll::Ready(completion) = source.poll_quiesce(request(1).key).unwrap() else {
            panic!("missing callback queues")
        };
        assert_eq!(completion.queues.len(), 5);
        assert!(completion.fault.is_none());
        assert_eq!(
            completion.queues[FRQ_INDEX]
                .queue
                .capture_state()
                .unwrap()
                .next_used,
            1
        );
        assert_eq!(
            completion.queues[STQ_INDEX]
                .queue
                .capture_state()
                .unwrap()
                .next_avail,
            0
        );
        assert_eq!(rings[STQ_INDEX].used.idx.get(), 0);
        let payload = source.capture_payload(request(1).key).unwrap();

        let child_memory =
            RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let child_rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &child_memory, 8))
            .collect();
        let mut cut = vec![0u8; 16 * page_size];
        memory.read_slice(&mut cut, GuestAddress(0)).unwrap();
        child_memory.write_slice(&cut, GuestAddress(0)).unwrap();
        child_memory
            .write_slice(&vec![0xa5; page_size], child_report_address)
            .unwrap();
        child_rings[FRQ_INDEX].dtable[1].set(child_report_address.0, page_size as u32, 2, 0);
        child_rings[FRQ_INDEX].avail.ring[1].set(1);
        child_rings[FRQ_INDEX].avail.idx.set(2);
        let mut destination = Balloon::new().unwrap();
        destination
            .prepare_restore(
                request(1),
                &payload,
                DormantDeviceContext {
                    memory: child_memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert_eq!(destination.avail_features(), source.avail_features());
        assert_eq!(destination.acked_features(), source.acked_features());
        assert!(!destination.host_reclaim_enabled);
        assert_eq!(
            destination.activate_evt.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!destination.process_frq().unwrap());
        assert_eq!(child_rings[FRQ_INDEX].used.idx.get(), 1);
        let child_queues = completion
            .queues
            .iter()
            .zip(&child_rings)
            .map(|(saved, ring)| {
                let mut queue = ring.create_queue();
                queue.apply_state(&saved.queue.capture_state().unwrap());
                DeviceQueue::new(queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
            })
            .collect();
        assert!(matches!(
            destination.begin_resume(request(2), child_queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(child_rings[FRQ_INDEX].used.idx.get(), 2);
        child_memory
            .read_slice(&mut contents, child_report_address)
            .unwrap();
        assert_eq!(contents, vec![0xa5; page_size]);
        assert_eq!(child_rings[STQ_INDEX].used.idx.get(), 0);
        assert!(matches!(
            source.begin_resume(request(2), completion.queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            source.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_report_effect_with_failed_used_publication_stays_faulted() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut queues: Vec<_> = rings
            .iter()
            .map(|ring| DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap())))
            .collect();
        queues[FRQ_INDEX].queue.used_ring = GuestAddress((32 * page_size) as u64);
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-fault-test".into(),
                    None,
                )
                .unwrap(),
                queues,
            )
            .unwrap();
        assert!(balloon.process_frq().is_err());
        let mut contents = vec![1u8; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0; page_size]);
        assert!(balloon.preflight().is_err());
        let queue = &balloon.queues.as_ref().unwrap()[FRQ_INDEX].queue;
        assert_eq!(queue.next_avail.0, 1);
        assert_eq!(queue.next_used.0, 0);
        assert!(queue.capture_state().is_err());
        assert!(!balloon.process_frq().unwrap());
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        balloon.begin_quiesce(request(1)).unwrap();
        let std::task::Poll::Ready(completion) = balloon.poll_quiesce(request(1).key).unwrap()
        else {
            panic!("fault cleanup lost queues");
        };
        assert!(completion.fault.is_some());
        assert_eq!(completion.queues.len(), 5);
        assert!(completion.queues[FRQ_INDEX].queue.capture_state().is_err());
        assert!(balloon.capture_payload(request(1).key).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_short_report_never_discards_bytes_outside_its_range() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32 - 1, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-range-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            )
            .unwrap();
        assert!(balloon.process_frq().is_err());
        let mut contents = vec![0; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0x5a; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        assert!(balloon.preflight().is_err());
    }

    #[test]
    fn provider_balloon_restore_binding_preserves_offer_without_reclaim_grant() {
        use crate::virtio::balloon::device::reporting_features;
        for reporting in [false, true] {
            let features = reporting_features(reporting);
            let mut balloon = Balloon::new_restore_binding(features).unwrap();
            assert_eq!(balloon.avail_features(), features);
            assert!(!balloon.host_reclaim_enabled);
            balloon.set_acked_features(features);
            assert_eq!(balloon.acked_features(), features);
            #[cfg(target_os = "macos")]
            {
                use hvf::reclaim::ReclaimState;
                use std::sync::Arc;
                balloon.set_reclaim_state(Arc::new(ReclaimState::new()));
                assert_eq!(balloon.avail_features(), features);
                assert!(!balloon.host_reclaim_enabled);
            }
        }
        assert!(Balloon::new_restore_binding(u64::MAX).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_unready_saved_report_queue_never_discards_or_publishes() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance, VirtioStateProvider,
        };
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use std::task::Poll;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut queues: Vec<_> = rings
            .iter()
            .map(|ring| DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap())))
            .collect();
        queues[FRQ_INDEX].queue.ready = false;
        let saved = queues[FRQ_INDEX].queue.capture_state().unwrap();
        let interrupt = || {
            InterruptTransport::new(
                DummyIrqChip::new().into(),
                "balloon-unready-test".into(),
                None,
            )
            .unwrap()
        };
        let mut source = Balloon::new().unwrap();
        source.set_acked_features(source.avail_features());
        source
            .activate(memory.clone(), interrupt(), queues)
            .unwrap();
        assert!(!source.process_frq().unwrap());
        source.begin_quiesce(request(1)).unwrap();
        let Poll::Ready(completion) = source.poll_quiesce(request(1).key).unwrap() else {
            panic!("unready queue was lost");
        };
        let payload = source.capture_payload(request(1).key).unwrap();
        let mut destination = Balloon::new_restore_binding(source.avail_features()).unwrap();
        destination
            .prepare_restore(
                request(1),
                &payload,
                DormantDeviceContext {
                    memory: memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        let fresh = completion
            .queues
            .iter()
            .zip(&rings)
            .map(|(queue, ring)| {
                let mut fresh = ring.create_queue();
                fresh.apply_state(&queue.queue.capture_state().unwrap());
                DeviceQueue::new(fresh, Arc::new(EventFd::new(0).unwrap()))
            })
            .collect();
        assert!(matches!(
            destination.begin_resume(request(2), fresh),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert!(!destination.process_frq().unwrap());
        assert_eq!(
            destination.queues.as_ref().unwrap()[FRQ_INDEX]
                .queue
                .capture_state()
                .unwrap(),
            saved
        );
        let mut contents = vec![0; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0x5a; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        destination.preflight().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_snapshot_rejects_tail_cycle_before_any_discard() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 16 * page_size)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, page_size as u32, 3, 1);
        rings[FRQ_INDEX].dtable[1].set(report_address.0, page_size as u32, 3, 1);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; page_size], report_address)
            .unwrap();
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-cycle-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            )
            .unwrap();
        assert!(balloon.process_frq().is_err());
        let mut contents = vec![0; page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0x5a; page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
        assert!(balloon.preflight().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn provider_balloon_report_spanning_adjacent_regions_discards_both_before_used() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::balloon::device::FRQ_INDEX;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let report_address = GuestAddress((8 * page_size) as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[
            (GuestAddress(0), 9 * page_size),
            (GuestAddress((9 * page_size) as u64), 7 * page_size),
        ])
        .unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        rings[FRQ_INDEX].dtable[0].set(report_address.0, (2 * page_size) as u32, 2, 0);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        memory
            .write_slice(&vec![0x5a; 2 * page_size], report_address)
            .unwrap();
        let mut balloon = Balloon::new().unwrap();
        balloon.set_acked_features(balloon.avail_features());
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-regions-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .map(|ring| {
                        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
                    })
                    .collect(),
            )
            .unwrap();
        assert!(balloon.process_frq().unwrap());
        let mut contents = vec![1; 2 * page_size];
        memory.read_slice(&mut contents, report_address).unwrap();
        assert_eq!(contents, vec![0; 2 * page_size]);
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
        balloon.preflight().unwrap();
        assert!(!balloon.process_frq().unwrap());
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn provider_balloon_activation_registers_all_real_queue_subscribers() {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use polly::event_manager::{EventManager, Subscriber};
        use std::os::unix::io::AsRawFd;
        use std::sync::{Arc, Mutex};
        use utils::epoll::{EpollEvent, EventSet};
        use utils::eventfd::{EFD_NONBLOCK, EventFd};
        use vm_memory::GuestAddress;
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rings: Vec<_> = (0..5)
            .map(|index| VirtQueue::new(GuestAddress(index * 0x1000), &memory, 8))
            .collect();
        let events: Vec<_> = (0..5)
            .map(|_| Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
            .collect();
        let source = Arc::new(Mutex::new(Balloon::new().unwrap()));
        let subscriber: Arc<Mutex<dyn Subscriber>> = source.clone();
        let mut manager = EventManager::new().unwrap();
        manager.add_subscriber(subscriber.clone()).unwrap();
        let existing_fd = events[0].as_raw_fd();
        manager
            .register(
                existing_fd,
                EpollEvent::new(EventSet::IN, existing_fd as u64),
                subscriber.clone(),
            )
            .unwrap();
        let mut balloon = match source.lock() {
            Ok(device) => device,
            Err(error) => panic!("balloon lock poisoned: {error}"),
        };
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "balloon-registration-test".into(),
                    None,
                )
                .unwrap(),
                rings
                    .iter()
                    .zip(&events)
                    .map(|(ring, event)| DeviceQueue::new(ring.create_queue(), event.clone()))
                    .collect(),
            )
            .unwrap();
        let activation_fd = balloon.activate_evt.as_raw_fd();
        balloon.process(
            &EpollEvent::new(EventSet::IN, activation_fd as u64),
            &mut manager,
        );
        for event in events {
            assert!(Arc::ptr_eq(
                &manager.subscriber(event.as_raw_fd()).unwrap(),
                &subscriber
            ));
        }
        assert!(manager.subscriber(activation_fd).is_err());
        balloon.preflight().unwrap();
    }
}
