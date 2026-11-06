use std::task::Poll;

use polly::event_manager::{BarrierKey, BarrierRequest};
use rand::{TryRng, rngs::SysRng};
use utils::eventfd::EventFd;
use utils::state::{Reader, Writer};

use vm_memory::{GuestAddress, GuestMemoryError};

use crate::virtio::InterruptTransport;
use crate::virtio::descriptor_utils::{DescriptorChainSnapshot, ValidatedDescriptorChain};
use crate::virtio::lifecycle::{
    CallbackState, DormantDeviceContext, ProviderBeginError, ProviderFault, QuiesceCompletion,
    ResumeAcceptance, VirtioStateProvider,
};
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
use crate::virtio::rng::{Result, RngError, defs, defs::uapi};
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, Queue, QueueConfig,
    RuntimeGuestMemory, VirtioDevice,
};

// Request queue.
pub(crate) const REQ_INDEX: usize = 0;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

pub struct Rng {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    pub(crate) callbacks: CallbackState,
    descriptors: DescriptorChainSnapshot,
}

impl Rng {
    pub(crate) fn queue_event(&self, idx: usize) -> Option<&std::sync::Arc<EventFd>> {
        self.queues.as_ref()?.get(idx).map(|queue| &queue.event)
    }

    pub fn new() -> Result<Rng> {
        Ok(Rng {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(RngError::EventFd)?,
            device_state: DeviceState::Inactive,
            callbacks: CallbackState::new(),
            descriptors: DescriptorChainSnapshot::new(defs::QUEUE_CONFIG[REQ_INDEX].size),
        })
    }

    pub fn id(&self) -> &str {
        defs::RNG_DEV_ID
    }

    pub fn process_req(&mut self) -> bool {
        if !self.callbacks.admission_open() || self.callbacks.preflight(&self.queues).is_err() {
            return false;
        }
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return false;
        };
        let Some(queue) = self
            .queues
            .as_mut()
            .and_then(|queues| queues.get_mut(REQ_INDEX))
        else {
            return false;
        };
        if !queue.queue.ready {
            return false;
        }
        let mut have_used = false;
        let mut random = [0u8; 4096];
        while let Some(head) = queue.queue.pop(mem) {
            let index = head.index;
            let snapshot = match self.descriptors.read(head) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    error!("rng: invalid descriptor chain: {error}");
                    queue.queue.record_processing_failure();
                    break;
                }
            };
            let completion =
                execute_validated_request(mem, &mut queue.queue, index, &snapshot, &mut random);
            have_used |= completion.published;
            if completion.failed {
                break;
            }
        }
        have_used
    }
    pub(crate) fn process_and_notify(&mut self) {
        if self.process_req() {
            let result = match (&self.device_state, self.queues.as_mut()) {
                (DeviceState::Activated(memory, interrupt), Some(queues)) => queues[REQ_INDEX]
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
            }
        }
    }

    pub fn restore_queue_config() -> &'static [crate::virtio::QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    pub fn inspect_restore_payload(payload: &[u8]) -> std::result::Result<(), ProviderFault> {
        Self::decode_payload_features(payload, AVAIL_FEATURES).map(|_| ())
    }

    fn decode_payload(&self, payload: &[u8]) -> std::result::Result<u64, ProviderFault> {
        Self::decode_payload_features(payload, self.avail_features)
    }

    fn decode_payload_features(
        payload: &[u8],
        available: u64,
    ) -> std::result::Result<u64, ProviderFault> {
        let mut reader = Reader::new(payload);
        let decoded = (|| {
            if reader.u16()? != 1
                || reader.u32()? != uapi::VIRTIO_ID_RNG
                || reader.u64()? != available
            {
                return Err(utils::state::Error::Invalid("rng profile"));
            }
            let acked = reader.u64()?;
            if acked & !available != 0 {
                return Err(utils::state::Error::Invalid("rng features"));
            }
            reader.finish()?;
            Ok(acked)
        })();
        decoded.map_err(|_| ProviderFault::DeviceState)
    }
}

struct RequestCompletion {
    published: bool,
    failed: bool,
}

fn execute_validated_request(
    memory: &RuntimeGuestMemory,
    queue: &mut Queue,
    index: u16,
    snapshot: &ValidatedDescriptorChain<'_>,
    random: &mut [u8; 4096],
) -> RequestCompletion {
    if snapshot
        .descriptors()
        .iter()
        .any(|descriptor| descriptor.flags & VIRTQ_DESC_F_WRITE == 0)
    {
        queue.record_processing_failure();
        return RequestCompletion {
            published: false,
            failed: true,
        };
    }
    let mut written = 0u32;
    let mut failed = false;
    for descriptor in snapshot.descriptors() {
        // A later admission or entropy failure cannot rewind earlier real DMA.
        let result = memory.try_write_access(
            descriptor.len as usize,
            GuestAddress(descriptor.addr),
            |_, len, _, target| {
                let count = len.min(random.len());
                let total = written
                    .checked_add(count as u32)
                    .ok_or(GuestMemoryError::InvalidBackendAddress)?;
                SysRng
                    .try_fill_bytes(&mut random[..count])
                    .map_err(|error| {
                        GuestMemoryError::IOError(std::io::Error::other(error.to_string()))
                    })?;
                target
                    .write_slice(&random[..count], 0)
                    .map_err(|error| GuestMemoryError::IOError(std::io::Error::other(error)))?;
                written = total;
                Ok(count)
            },
        );
        if result.is_err() {
            failed = true;
            break;
        }
    }
    if failed {
        queue.record_processing_failure();
    }
    let published = queue.add_used(memory, index, written).is_ok();
    RequestCompletion {
        published,
        failed: failed || !published,
    }
}

impl VirtioDevice for Rng {
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
        uapi::VIRTIO_ID_RNG
    }

    fn device_name(&self) -> &str {
        "rng"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        error!("rng: invalid request to read config space");
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "rng: guest driver attempted to write device config (offset={:x}, len={:x})",
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

    fn reset(&mut self) -> bool {
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        self.acked_features = 0;
        self.callbacks = CallbackState::new();
        true
    }
}

impl VirtioStateProvider for Rng {
    fn preflight(&self) -> std::result::Result<(), ProviderFault> {
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

    fn begin_quiesce(
        &mut self,
        request: BarrierRequest,
    ) -> std::result::Result<(), ProviderBeginError> {
        self.callbacks.begin_quiesce(request, &mut self.queues)
    }

    fn poll_quiesce(
        &mut self,
        key: BarrierKey,
    ) -> std::result::Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.callbacks.poll_quiesce(key, &mut self.queues)
    }
    fn validate_terminal_drain(&self, key: BarrierKey) -> std::result::Result<(), ProviderFault> {
        self.callbacks.validate_terminal_drain(key, &self.queues)?;
        self.preflight()
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

    fn poll_resume(&mut self, key: BarrierKey) -> std::result::Result<Poll<()>, ProviderFault> {
        self.callbacks.preflight(&self.queues)?;
        self.callbacks.poll_resume(key)
    }

    fn state_limit(&self) -> u32 {
        22
    }

    fn capture_payload(&self, key: BarrierKey) -> std::result::Result<Vec<u8>, ProviderFault> {
        self.callbacks.require_cut(key)?;
        let mut writer = Writer::new(self.state_limit() as usize);
        writer
            .u16(1)
            .and_then(|()| writer.u32(uapi::VIRTIO_ID_RNG))
            .and_then(|()| writer.u64(self.avail_features))
            .and_then(|()| writer.u64(self.acked_features))
            .map_err(|_| ProviderFault::DeviceState)?;
        Ok(writer.finish())
    }

    fn validate_payload(&self, payload: &[u8]) -> std::result::Result<(), ProviderFault> {
        self.decode_payload(payload).map(|_| ())
    }

    fn validate_restore(&self, payload: &[u8]) -> std::result::Result<(), ProviderFault> {
        if self.is_activated() || self.queues.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.validate_payload(payload)
    }

    fn apply_payload(&mut self, payload: &[u8]) -> std::result::Result<(), ProviderFault> {
        self.callbacks.require_quiesced()?;
        self.acked_features = self.decode_payload(payload)?;
        Ok(())
    }

    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> std::result::Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        let acked = self.decode_payload(payload)?;
        self.callbacks.prepare_restore(request)?;
        self.acked_features = acked;
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
    use crate::legacy::DummyIrqChip;
    use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
    use crate::virtio::lifecycle::{
        DormantDeviceContext, ProviderFault, RestoredReclaimPolicy, ResumeAcceptance,
        VirtioStateProvider,
    };
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::rng::device::{Rng, execute_validated_request};
    use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory, VirtioDevice};
    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant};
    use utils::eventfd::EventFd;
    use vm_memory::GuestAddress;

    #[test]
    fn lifecycle_rng_partial_dma_never_rewinds_published_head() {
        let validation_memory =
            RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x9000)]).unwrap();
        let validation_ring = VirtQueue::new(GuestAddress(0), &validation_memory, 8);
        validation_ring.dtable[0].set(0x1000, 16, 3, 1);
        validation_ring.dtable[1].set(0x8000, 16, 2, 0);
        validation_ring.avail.ring[0].set(0);
        validation_ring.avail.idx.set(1);
        let mut validation_queue = validation_ring.create_queue();
        let mut snapshot = DescriptorChainSnapshot::new(8);
        let validated = snapshot
            .read(validation_queue.pop(&validation_memory).unwrap())
            .unwrap();

        // A real missing tail backing exercises the production post-validation
        // DMA failure path without substituting entropy, memory writes, or used publication.
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x1000, 16, 3, 1);
        ring.dtable[1].set(0x8000, 16, 2, 0);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let mut queue = ring.create_queue();
        let index = queue.pop(&memory).unwrap().index;
        let result =
            execute_validated_request(&memory, &mut queue, index, &validated, &mut [0; 4096]);
        assert!(result.published);
        assert!(result.failed);
        assert_eq!(queue.next_avail.0, 1);
        assert_eq!(queue.next_used.0, 1);
        assert!(queue.capture_state().is_err());
        assert_eq!(ring.used.ring[0].get().len, 16);
        assert_eq!(ring.used.idx.get(), 1);
        assert!(queue.pop(&memory).is_none());
        assert_eq!(ring.used.idx.get(), 1);
    }

    fn request(operation: u64) -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(7),
            },
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    fn interrupt() -> InterruptTransport {
        InterruptTransport::new(DummyIrqChip::new().into(), "rng-provider-test".into(), None)
            .unwrap()
    }

    #[test]
    fn provider_rng_explicit_payload_retains_unpopped_work_and_restores_dormant() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x2000, 5000, 2, 0);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let event = Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        event.write(1).unwrap();
        assert_eq!(event.read().unwrap(), 1);
        let mut source = Rng::new().unwrap();
        source.set_acked_features(source.avail_features());
        source
            .activate(
                memory.clone(),
                interrupt(),
                vec![DeviceQueue::new(ring.create_queue(), event.clone())],
            )
            .unwrap();
        source.begin_quiesce(request(1)).unwrap();
        assert!(!source.process_req());
        assert_eq!(ring.used.idx.get(), 0);
        let Poll::Ready(completion) = source.poll_quiesce(request(1).key).unwrap() else {
            panic!("callback did not return queues")
        };
        assert!(completion.fault.is_none());
        assert_eq!(completion.queues.len(), 1);
        assert!(Arc::ptr_eq(&completion.queues[0].event, &event));
        let saved_queue = completion.queues[0].queue.capture_state().unwrap();
        assert_eq!(saved_queue.next_avail, 0);
        assert!(matches!(
            source.poll_quiesce(request(1).key).unwrap(),
            Poll::Pending
        ));
        let payload = source.capture_payload(request(1).key).unwrap();
        assert_eq!(payload.len(), 22);
        assert_eq!(
            source.validate_payload(&[]),
            Err(ProviderFault::DeviceState)
        );
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(source.validate_payload(&trailing).is_err());

        let destination_memory =
            RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap();
        let destination_ring = VirtQueue::new(GuestAddress(0), &destination_memory, 8);
        let mut cut = vec![0u8; 0x8000];
        memory.read_slice(&mut cut, GuestAddress(0)).unwrap();
        destination_memory
            .write_slice(&cut, GuestAddress(0))
            .unwrap();
        let mut destination = Rng::new().unwrap();
        destination
            .prepare_restore(
                request(1),
                &payload,
                DormantDeviceContext {
                    memory: destination_memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert!(destination.queues.is_none());
        assert!(!destination.process_req());
        assert_eq!(destination_ring.used.idx.get(), 0);
        assert_eq!(
            destination.activate_evt.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut fresh_queue = destination_ring.create_queue();
        fresh_queue.apply_state(&saved_queue);
        assert!(matches!(
            destination.begin_resume(
                request(2),
                vec![DeviceQueue::new(
                    fresh_queue,
                    Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap())
                )]
            ),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(destination_ring.used.idx.get(), 1);
        assert_eq!(destination_ring.used.ring[0].get().len, 5000);
        assert!(!destination.process_req());
        assert_eq!(destination_ring.used.idx.get(), 1);
        assert_eq!(ring.used.idx.get(), 0);
        assert!(matches!(
            source.begin_resume(request(2), completion.queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            source.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(ring.used.idx.get(), 1);
    }

    #[test]
    fn provider_rng_rejects_read_only_and_retains_terminal_fault() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x2000, 16, 0, 0);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        memory
            .write_slice(&[0xa5; 16], GuestAddress(0x2000))
            .unwrap();
        let mut rng = Rng::new().unwrap();
        rng.activate(
            memory.clone(),
            interrupt(),
            vec![DeviceQueue::new(
                ring.create_queue(),
                Arc::new(EventFd::new(0).unwrap()),
            )],
        )
        .unwrap();
        assert!(!rng.process_req());
        let mut bytes = [0; 16];
        memory.read_slice(&mut bytes, GuestAddress(0x2000)).unwrap();
        assert_eq!(bytes, [0xa5; 16]);
        assert_eq!(ring.used.ring[0].get().len, 0);
        assert_eq!(ring.used.idx.get(), 0);
        assert!(rng.preflight().is_err());
        rng.begin_quiesce(request(1)).unwrap();
        let Poll::Ready(completion) = rng.poll_quiesce(request(1).key).unwrap() else {
            panic!("fault cleanup lost queues");
        };
        assert_eq!(completion.fault, Some(ProviderFault::QueueState));
        assert_eq!(completion.queues.len(), 1);
        assert!(completion.queues[0].queue.capture_state().is_err());
        assert!(rng.capture_payload(request(1).key).is_err());
    }

    #[test]
    fn provider_rng_dma_region_boundary_and_prevalidated_hole_are_accounted_once() {
        for contiguous in [false, true] {
            let ranges = if contiguous {
                vec![(GuestAddress(0), 0x3000), (GuestAddress(0x3000), 0x1000)]
            } else {
                vec![(GuestAddress(0), 0x3000)]
            };
            let memory = RuntimeGuestMemory::from_ranges(&ranges).unwrap();
            let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
            ring.dtable[0].set(0x2ff0, 32, 2, 0);
            ring.avail.ring[0].set(0);
            ring.avail.idx.set(1);
            let mut rng = Rng::new().unwrap();
            rng.activate(
                memory.clone(),
                interrupt(),
                vec![DeviceQueue::new(
                    ring.create_queue(),
                    Arc::new(EventFd::new(0).unwrap()),
                )],
            )
            .unwrap();
            assert_eq!(rng.process_req(), contiguous);
            assert_eq!(ring.used.idx.get(), u16::from(contiguous));
            assert_eq!(ring.used.ring[0].get().len, if contiguous { 32 } else { 0 });
            assert_eq!(rng.preflight().is_ok(), contiguous);
            assert!(!rng.process_req());
            assert_eq!(ring.used.idx.get(), u16::from(contiguous));
        }
    }

    #[test]
    fn provider_rng_real_reset_clears_negotiation_but_pause_preserves_it() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        let mut rng = Rng::new().unwrap();
        rng.ack_features_by_page(1, 1);
        let negotiated = rng.avail_features();
        assert_eq!(rng.acked_features(), negotiated);
        rng.activate(
            memory.clone(),
            interrupt(),
            vec![DeviceQueue::new(
                ring.create_queue(),
                Arc::new(EventFd::new(0).unwrap()),
            )],
        )
        .unwrap();
        rng.begin_quiesce(request(1)).unwrap();
        let Poll::Ready(completion) = rng.poll_quiesce(request(1).key).unwrap() else {
            panic!("pause lost queues");
        };
        assert_eq!(
            &rng.capture_payload(request(1).key).unwrap()[14..22],
            &negotiated.to_le_bytes()
        );
        assert!(matches!(
            rng.begin_resume(request(2), completion.queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            rng.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(rng.acked_features(), negotiated);

        assert!(rng.reset());
        assert!(!rng.is_activated());
        assert!(rng.queues.is_none());
        assert_eq!(rng.acked_features(), 0);
        rng.begin_quiesce(request(3)).unwrap();
        let Poll::Ready(completion) = rng.poll_quiesce(request(3).key).unwrap() else {
            panic!("inactive provider did not complete");
        };
        assert!(completion.queues.is_empty());
        let payload = rng.capture_payload(request(3).key).unwrap();
        assert_eq!(payload.len(), 22);
        assert_eq!(&payload[14..22], &[0; 8]);
        assert!(matches!(
            rng.begin_resume(request(4), completion.queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            rng.poll_resume(request(4).key).unwrap(),
            Poll::Ready(())
        ));
        rng.ack_features_by_page(0, 0);
        assert_eq!(rng.acked_features(), 0);
        rng.ack_features_by_page(1, 1);
        assert_eq!(rng.acked_features(), negotiated);
    }

    #[test]
    fn provider_rng_unready_saved_queue_never_acquires_or_writes() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x2000, 16, 2, 0);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        memory
            .write_slice(&[0xa5; 16], GuestAddress(0x2000))
            .unwrap();
        let mut queue = ring.create_queue();
        queue.ready = false;
        let saved = queue.capture_state().unwrap();
        let mut source = Rng::new().unwrap();
        source
            .activate(
                memory.clone(),
                interrupt(),
                vec![DeviceQueue::new(queue, Arc::new(EventFd::new(0).unwrap()))],
            )
            .unwrap();
        assert!(!source.process_req());
        source.begin_quiesce(request(1)).unwrap();
        assert!(matches!(
            source.poll_quiesce(request(1).key).unwrap(),
            Poll::Ready(_)
        ));
        let payload = source.capture_payload(request(1).key).unwrap();
        let mut destination = Rng::new().unwrap();
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
        let mut fresh = ring.create_queue();
        fresh.apply_state(&saved);
        assert!(matches!(
            destination.begin_resume(
                request(2),
                vec![DeviceQueue::new(fresh, Arc::new(EventFd::new(0).unwrap()))]
            ),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(request(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert!(!destination.process_req());
        assert_eq!(
            destination.queues.as_ref().unwrap()[0]
                .queue
                .capture_state()
                .unwrap(),
            saved
        );
        let mut bytes = [0; 16];
        memory.read_slice(&mut bytes, GuestAddress(0x2000)).unwrap();
        assert_eq!(bytes, [0xa5; 16]);
        assert_eq!(ring.used.idx.get(), 0);
        destination.preflight().unwrap();
    }

    #[test]
    fn provider_rng_snapshot_rejects_bad_tail_before_entropy_dma() {
        for cycle in [false, true] {
            let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
            let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
            ring.dtable[0].set(0x2000, 16, 3, 1);
            ring.dtable[1].set(0x2100, 16, if cycle { 3 } else { 0 }, 1);
            ring.avail.ring[0].set(0);
            ring.avail.idx.set(1);
            memory
                .write_slice(&[0xa5; 16], GuestAddress(0x2000))
                .unwrap();
            let mut rng = Rng::new().unwrap();
            rng.activate(
                memory.clone(),
                interrupt(),
                vec![DeviceQueue::new(
                    ring.create_queue(),
                    Arc::new(EventFd::new(0).unwrap()),
                )],
            )
            .unwrap();
            assert!(!rng.process_req());
            let mut bytes = [0; 16];
            memory.read_slice(&mut bytes, GuestAddress(0x2000)).unwrap();
            assert_eq!(bytes, [0xa5; 16]);
            assert_eq!(ring.used.idx.get(), 0);
            let queue = &rng.queues.as_ref().unwrap()[0].queue;
            assert_eq!(queue.next_avail.0, 1);
            assert_eq!(queue.next_used.0, 0);
            assert!(rng.preflight().is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn provider_rng_activation_registers_missing_or_same_subscriber_without_masking_foreign() {
        use polly::event_manager::{EventManager, Subscriber};
        use std::os::unix::io::AsRawFd;
        use std::sync::Mutex;
        use utils::epoll::{EpollEvent, EventSet};
        for existing in 0..3 {
            let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
            let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
            let source = Arc::new(Mutex::new(Rng::new().unwrap()));
            let subscriber: Arc<Mutex<dyn Subscriber>> = source.clone();
            let mut manager = EventManager::new().unwrap();
            manager.add_subscriber(subscriber.clone()).unwrap();
            let event = Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
            let fd = event.as_raw_fd();
            let foreign: Arc<Mutex<dyn Subscriber>> = Arc::new(Mutex::new(Rng::new().unwrap()));
            if existing != 0 {
                manager
                    .register(
                        fd,
                        EpollEvent::new(EventSet::IN, fd as u64),
                        if existing == 1 {
                            subscriber.clone()
                        } else {
                            foreign.clone()
                        },
                    )
                    .unwrap();
            }
            let mut rng = match source.lock() {
                Ok(device) => device,
                Err(error) => panic!("rng lock poisoned: {error}"),
            };
            rng.activate(
                memory.clone(),
                interrupt(),
                vec![DeviceQueue::new(ring.create_queue(), event)],
            )
            .unwrap();
            let activation_fd = rng.activate_evt.as_raw_fd();
            rng.process(
                &EpollEvent::new(EventSet::IN, activation_fd as u64),
                &mut manager,
            );
            let actual = manager.subscriber(fd).unwrap();
            assert!(Arc::ptr_eq(
                &actual,
                if existing == 2 { &foreign } else { &subscriber }
            ));
            assert_eq!(rng.preflight().is_ok(), existing != 2);
            assert_eq!(manager.subscriber(activation_fd).is_ok(), existing == 2);
        }
    }
}
