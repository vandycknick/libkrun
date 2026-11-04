use std::sync::{Arc, Mutex};

use devices::legacy::Serial;
use devices::virtio::{MmioTransportState, VirtioDevice};
use utils::eventfd::EventFd;

use crate::vmm::device_manager::quiescence::AttachmentIdentity;
use crate::vmm::execution::StateBinding;

const DEVICE_MAGIC: &[u8; 8] = b"KRUNDEVS";
const MAX_DEVICE_BYTES: usize = 32 * 1024 * 1024;
const MAX_DEVICE_PAYLOAD: usize = 262144;

fn payload_limit(device_type: u32) -> Result<usize, utils::state::Error> {
    match device_type {
        1 => Ok(131072),
        2 | 5 => Ok(4096),
        3 => Ok(MAX_DEVICE_PAYLOAD),
        4 => Ok(22),
        19 => Ok(65536),
        devices::virtio::generation::DEVICE_TYPE => {
            Ok(devices::virtio::generation::STATE_LIMIT as usize)
        }
        _ => Err(utils::state::Error::Invalid(
            "unsupported device provider kind",
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceRecord {
    pub identity: AttachmentIdentity,
    pub state: MmioTransportState,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceEnvelope {
    pub binding: StateBinding,
    pub records: Vec<DeviceRecord>,
}

pub(crate) struct ValidatedDevices {
    envelope: DeviceEnvelope,
}

impl ValidatedDevices {
    pub(crate) fn into_envelope(self) -> DeviceEnvelope {
        self.envelope
    }

    pub fn validate(
        envelope: DeviceEnvelope,
        execution: &crate::vmm::execution::ExecutionEnvelope,
    ) -> Result<Self, utils::state::Error> {
        execution.validate()?;
        envelope.validate()?;
        if envelope.binding != execution.binding
            || envelope.records.len() != execution.attachments.len()
            || envelope
                .records
                .iter()
                .zip(&execution.attachments)
                .any(|(record, identity)| record.identity != *identity)
        {
            return Err(utils::state::Error::Invalid(
                "execution/device identity binding",
            ));
        }
        Ok(Self { envelope })
    }

    pub fn prepare(
        self,
        devices: Vec<RestoreDeviceBinding>,
        serial: Vec<(u64, Arc<Mutex<Serial>>)>,
        shutdown: Option<EventFd>,
    ) -> Result<PreparedDeviceInstall, String> {
        if devices.len() != self.envelope.records.len()
            || devices
                .iter()
                .zip(&self.envelope.records)
                .any(|(device, record)| {
                    device.identity != record.identity
                        || device.state != record.state
                        || device.payload != record.payload
                })
        {
            return Err("validated destination resource inventory mismatch".into());
        }
        PreparedDeviceInstall::validate(self.envelope.binding, devices, serial, shutdown)
    }
}

impl DeviceEnvelope {
    pub fn validate(&self) -> Result<(), utils::state::Error> {
        use utils::state::Error;
        self.binding.validate()?;
        if self.records.len() > 256 {
            return Err(Error::Limit);
        }
        let mut previous = None;
        let mut total = 0usize;
        let mut generation_seen = false;
        for record in &self.records {
            let state = &record.state;
            if state.device_type == devices::virtio::generation::DEVICE_TYPE {
                if generation_seen
                    || record.identity.configured_id != devices::virtio::generation::DEVICE_ID
                    || state.device_name != devices::virtio::generation::DEVICE_ID
                    || state.avail_features != 1 << 32
                    || state.queues.len() != 1
                    || state.queues[0].max_size != 1
                {
                    return Err(Error::Invalid("generation attachment profile"));
                }
                generation_seen = true;
            }
            if record.identity.device_type != devices::DeviceType::Virtio(state.device_type)
                || record.identity.address != state.attachment_address
                || Some(record.identity.irq) != state.irq_line
                || previous.is_some_and(|address| address >= record.identity.address)
                || record.identity.configured_id.is_empty()
                || record.identity.configured_id.len() > 256
                || state.device_name.is_empty()
                || state.device_name.len() > 256
                || state.queues.len() > 256
                || record.payload.len() > payload_limit(state.device_type)?
                || self
                    .records
                    .iter()
                    .take_while(|other| other.identity.address < record.identity.address)
                    .any(|other| {
                        other.identity.device_type == record.identity.device_type
                            && other.identity.configured_id == record.identity.configured_id
                    })
            {
                return Err(Error::Invalid("device record inventory"));
            }
            state
                .validate_payload_binding(&record.payload)
                .map_err(|_| Error::Invalid("device payload transport binding"))?;
            total = total
                .checked_add(record.payload.len())
                .ok_or(Error::Overflow)?;
            if total > MAX_DEVICE_BYTES {
                return Err(Error::Limit);
            }
            previous = Some(record.identity.address);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, utils::state::Error> {
        use utils::state::Writer;
        self.validate()?;
        let mut writer = Writer::new(MAX_DEVICE_BYTES);
        writer.fixed(DEVICE_MAGIC)?;
        writer.u16(1)?;
        self.binding.encode(&mut writer)?;
        writer.count(self.records.len(), 256)?;
        for record in &self.records {
            let state = &record.state;
            writer.bytes(record.identity.configured_id.as_bytes(), 256)?;
            writer.u32(state.device_type)?;
            writer.bytes(state.device_name.as_bytes(), 256)?;
            writer.u64(state.attachment_address)?;
            writer.u32(record.identity.irq)?;
            writer.u64(state.avail_features)?;
            writer.u64(state.acked_features)?;
            for value in [
                state.features_select,
                state.acked_features_select,
                state.queue_select,
                state.device_status,
                state.config_generation,
                state.shm_region_select,
                state.interrupt_status,
            ] {
                writer.u32(value)?;
            }
            writer.bool(state.activated)?;
            writer.count(state.queues.len(), 256)?;
            for queue in &state.queues {
                writer.u16(queue.max_size)?;
                writer.u16(queue.size)?;
                writer.bool(queue.ready)?;
                writer.u64(queue.desc_table)?;
                writer.u64(queue.avail_ring)?;
                writer.u64(queue.used_ring)?;
                writer.u16(queue.next_avail)?;
                writer.u16(queue.next_used)?;
                writer.bool(queue.event_idx_enabled)?;
                writer.u16(queue.num_added)?;
            }
            writer.bytes(&record.payload, MAX_DEVICE_PAYLOAD)?;
        }
        Ok(writer.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, utils::state::Error> {
        use utils::state::{Error, Reader};
        if bytes.len() > MAX_DEVICE_BYTES {
            return Err(Error::Limit);
        }
        let mut reader = Reader::new(bytes);
        if &reader.fixed::<8>()? != DEVICE_MAGIC || reader.u16()? != 1 {
            return Err(Error::Invalid("device envelope version"));
        }
        let binding = StateBinding::decode(&mut reader)?;
        let count = reader.count(256, 79)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let configured_id = std::str::from_utf8(reader.bytes(256)?)
                .map_err(|_| Error::Invalid("device identity UTF-8"))?
                .to_owned();
            let device_type = reader.u32()?;
            let device_name = std::str::from_utf8(reader.bytes(256)?)
                .map_err(|_| Error::Invalid("device name UTF-8"))?
                .to_owned();
            let address = reader.u64()?;
            let irq = reader.u32()?;
            let mut state = MmioTransportState {
                device_type,
                device_name,
                attachment_address: address,
                irq_line: Some(irq),
                avail_features: reader.u64()?,
                acked_features: reader.u64()?,
                features_select: reader.u32()?,
                acked_features_select: reader.u32()?,
                queue_select: reader.u32()?,
                device_status: reader.u32()?,
                config_generation: reader.u32()?,
                shm_region_select: reader.u32()?,
                interrupt_status: reader.u32()?,
                activated: reader.bool()?,
                queues: Vec::new(),
            };
            let count = reader.count(256, 36)?;
            state.queues.reserve(count);
            for _ in 0..count {
                state.queues.push(devices::virtio::QueueState {
                    max_size: reader.u16()?,
                    size: reader.u16()?,
                    ready: reader.bool()?,
                    desc_table: reader.u64()?,
                    avail_ring: reader.u64()?,
                    used_ring: reader.u64()?,
                    next_avail: reader.u16()?,
                    next_used: reader.u16()?,
                    event_idx_enabled: reader.bool()?,
                    num_added: reader.u16()?,
                });
            }
            records.push(DeviceRecord {
                identity: AttachmentIdentity {
                    device_type: devices::DeviceType::Virtio(device_type),
                    configured_id,
                    address,
                    irq,
                },
                state,
                payload: reader.bytes(payload_limit(device_type)?)?.to_vec(),
            });
        }
        reader.finish()?;
        let envelope = Self { binding, records };
        envelope.validate()?;
        Ok(envelope)
    }
}

pub(crate) struct RestoreDeviceBinding {
    pub identity: AttachmentIdentity,
    pub state: MmioTransportState,
    pub payload: Vec<u8>,
    pub resource: Arc<Mutex<dyn VirtioDevice>>,
    pub subscriber: Option<Arc<Mutex<dyn polly::event_manager::Subscriber + Send>>>,
    pub generation_binding: Option<crate::api::device_builders::GenerationBinding>,
}

pub(crate) struct PreparedDeviceInstall {
    pub binding: StateBinding,
    pub devices: Vec<RestoreDeviceBinding>,
    #[cfg(not(feature = "tee"))]
    pub balloon_bindings: Vec<crate::api::device_builders::BalloonBinding>,
    pub generation_binding: Option<crate::api::device_builders::GenerationBinding>,
    pub serial: Vec<(u64, Arc<Mutex<Serial>>)>,
    pub shutdown: Option<EventFd>,
    #[cfg(feature = "native-execution-probe")]
    pub diagnostic_buses: Option<(devices::Bus, devices::Bus)>,
    #[cfg(all(
        feature = "native-execution-probe",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub diagnostic_install_ack_hold: Option<u8>,
}

impl PreparedDeviceInstall {
    pub fn validate_memory(
        &self,
        memory: &arch::guest_memory::ReadGuestMemory<'_>,
    ) -> Result<(), String> {
        for entry in &self.devices {
            if entry.identity.device_type != devices::DeviceType::Virtio(entry.state.device_type) {
                return Err(format!("restore attachment identity {:?}", entry.identity));
            }
            entry
                .state
                .validate_payload_binding(&entry.payload)
                .map_err(|error| {
                    format!("restore payload binding {:?}: {error:?}", entry.identity)
                })?;
            let resource = entry
                .resource
                .try_lock()
                .map_err(|_| "destination device lock")?;
            if resource.device_type() != entry.state.device_type {
                return Err(format!("destination device type {:?}", entry.identity));
            }
            let provider = resource
                .state_provider()
                .ok_or_else(|| format!("missing restore provider {:?}", entry.identity))?;
            if resource.is_activated()
                || resource.device_name() != entry.state.device_name
                || resource.avail_features() != entry.state.avail_features
                || entry.payload.len() > provider.state_limit() as usize
                || (matches!(entry.state.device_type, 3 | 4 | 5 | 19)
                    && entry.subscriber.as_ref().is_none_or(|subscriber| {
                        Arc::as_ptr(subscriber) as *const ()
                            != Arc::as_ptr(&entry.resource) as *const ()
                    }))
            {
                return Err(format!("destination device profile {:?}", entry.identity));
            }
            provider
                .validate_payload(&entry.payload)
                .map_err(|error| format!("restore payload {:?}: {error:?}", entry.identity))?;
            provider
                .validate_restore(&entry.payload)
                .map_err(|error| format!("restore {:?}: {error:?}", entry.identity))?;
            let queues = resource.queue_config();
            if queues.len() != entry.state.queues.len()
                || resource.shm_region().is_some()
                || entry.state.acked_features & !entry.state.avail_features != 0
                || entry.state.interrupt_status & !3 != 0
                || !matches!(entry.state.device_status & !128, 0 | 1 | 3 | 11 | 15)
                || entry.state.device_status & !143 != 0
                || entry.state.activated != (entry.state.device_status & 4 != 0)
            {
                return Err(format!("restore transport profile {:?}", entry.identity));
            }
            for (queue, saved) in queues.iter().zip(&entry.state.queues) {
                devices::virtio::Queue::validate_restored_state(queue.size, memory, saved)
                    .map_err(|error| format!("restore queue {:?}: {error:?}", entry.identity))?;
                let event_idx =
                    entry.state.activated && entry.state.acked_features & (1 << 29) != 0;
                if saved.event_idx_enabled != event_idx {
                    return Err("restore EVENT_IDX mismatch".into());
                }
            }
        }
        Ok(())
    }

    pub fn validate(
        binding: StateBinding,
        devices: Vec<RestoreDeviceBinding>,
        serial: Vec<(u64, Arc<Mutex<Serial>>)>,
        shutdown: Option<EventFd>,
    ) -> Result<Self, String> {
        binding.validate().map_err(|error| error.to_string())?;
        if devices.len() > 256 {
            return Err("restore device count exceeds bound".into());
        }
        let mut previous = None;
        let mut generation_binding = None;
        for entry in &devices {
            if entry.state.device_type == devices::virtio::generation::DEVICE_TYPE {
                if generation_binding.is_some()
                    || entry.identity.configured_id != devices::virtio::generation::DEVICE_ID
                    || entry
                        .generation_binding
                        .as_ref()
                        .is_none_or(|binding| !binding.matches(&entry.resource))
                {
                    return Err("generation destination binding mismatch".into());
                }
                generation_binding = entry.generation_binding.clone();
            } else if entry.generation_binding.is_some() {
                return Err("generation binding on another device".into());
            }
            if previous.is_some_and(|address| address >= entry.identity.address)
                || entry.identity.configured_id.is_empty()
                || entry.identity.configured_id.len() > 256
                || entry.identity.device_type
                    != devices::DeviceType::Virtio(entry.state.device_type)
                || entry.state.attachment_address != entry.identity.address
                || entry.state.irq_line != Some(entry.identity.irq)
            {
                return Err(format!("restore attachment identity {:?}", entry.identity));
            }
            previous = Some(entry.identity.address);
            entry
                .state
                .validate_payload_binding(&entry.payload)
                .map_err(|error| {
                    format!("restore payload binding {:?}: {error:?}", entry.identity)
                })?;
            if matches!(entry.state.device_type, 3 | 4 | 5 | 19)
                && entry.subscriber.as_ref().is_none_or(|subscriber| {
                    Arc::as_ptr(subscriber) as *const ()
                        != Arc::as_ptr(&entry.resource) as *const ()
                })
            {
                return Err(format!(
                    "missing destination callback owner {:?}",
                    entry.identity
                ));
            }
            let resource = entry
                .resource
                .try_lock()
                .map_err(|_| "destination device lock")?;
            let provider = resource
                .state_provider()
                .ok_or_else(|| format!("missing restore provider {:?}", entry.identity))?;
            if resource.is_activated()
                || resource.device_type() != entry.state.device_type
                || resource.device_name() != entry.state.device_name
                || resource.avail_features() != entry.state.avail_features
                || entry.payload.len() > provider.state_limit() as usize
            {
                return Err(format!("destination device profile {:?}", entry.identity));
            }
            provider
                .validate_payload(&entry.payload)
                .map_err(|error| format!("device {:?}: {error:?}", entry.identity))?;
            provider
                .validate_restore(&entry.payload)
                .map_err(|error| format!("dormant device {:?}: {error:?}", entry.identity))?;
        }
        for (index, (address, _)) in serial.iter().enumerate() {
            if serial[..index]
                .iter()
                .any(|(previous, _)| previous == address)
            {
                return Err("duplicate destination UART binding".into());
            }
        }
        Ok(Self {
            binding,
            devices,
            #[cfg(not(feature = "tee"))]
            balloon_bindings: Vec::new(),
            generation_binding,
            serial,
            shutdown,
            #[cfg(feature = "native-execution-probe")]
            diagnostic_buses: None,
            #[cfg(all(
                feature = "native-execution-probe",
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            diagnostic_install_ack_hold: None,
        })
    }

    pub fn empty(binding: &StateBinding) -> Self {
        Self {
            binding: binding.clone(),
            #[cfg(not(feature = "tee"))]
            balloon_bindings: Vec::new(),
            generation_binding: None,
            devices: Vec::new(),
            serial: Vec::new(),
            shutdown: None,
            #[cfg(feature = "native-execution-probe")]
            diagnostic_buses: None,
            #[cfg(all(
                feature = "native-execution-probe",
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            diagnostic_install_ack_hold: None,
        }
    }

    #[cfg(all(
        feature = "native-execution-probe",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub fn hold_diagnostic_install_ack(&mut self, cpu: u8) -> Result<(), String> {
        if self.diagnostic_buses.is_none() {
            return Err("install ACK hold is diagnostic-only".into());
        }
        self.diagnostic_install_ack_hold = Some(cpu);
        Ok(())
    }

    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(crate) fn hold_device_probe_install_ack(&mut self, cpu: u8) -> Result<(), String> {
        if self.diagnostic_buses.is_some() || self.devices.is_empty() {
            return Err(
                "whole-machine install observation requires actual device providers".into(),
            );
        }
        self.diagnostic_install_ack_hold = Some(cpu);
        Ok(())
    }

    #[cfg(feature = "native-execution-probe")]
    pub fn diagnostic(
        binding: &StateBinding,
        io_bus: devices::Bus,
        mmio_bus: devices::Bus,
    ) -> Result<Self, String> {
        if !binding.native_producer.starts_with("diagnostic-only;") {
            return Err("diagnostic producer required".into());
        }
        let mut result = Self::empty(binding);
        result.diagnostic_buses = Some((io_bus, mmio_bus));
        Ok(result)
    }
}

#[cfg(all(test, not(feature = "tee")))]
mod tests {
    use crate::vmm::device_manager::quiescence::AttachmentIdentity;
    use crate::vmm::execution::StateBinding;
    use crate::vmm::execution::device_restore::{PreparedDeviceInstall, RestoreDeviceBinding};
    use devices::virtio::{MmioTransportState, Queue, VirtioDevice};
    use std::sync::{Arc, Mutex};

    fn rng_binding() -> (StateBinding, RestoreDeviceBinding) {
        let rng = devices::virtio::Rng::new().unwrap();
        let state = MmioTransportState {
            device_type: rng.device_type(),
            device_name: rng.device_name().to_owned(),
            attachment_address: 0xd0000000,
            irq_line: Some(5),
            avail_features: rng.avail_features(),
            acked_features: 0,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            device_status: 0,
            config_generation: 0,
            shm_region_select: 0,
            interrupt_status: 0,
            activated: false,
            queues: rng
                .queue_config()
                .iter()
                .map(|config| Queue::new(config.size).capture_state().unwrap())
                .collect(),
        };
        let identity = AttachmentIdentity {
            device_type: devices::DeviceType::Virtio(rng.device_type()),
            configured_id: "rng-instance-0".into(),
            address: state.attachment_address,
            irq: 5,
        };
        let binding = StateBinding {
            native_producer: "exact-native-test-producer".into(),
            silo_producer: [1; 32],
            profile: [2; 32],
            topology: [3; 32],
            ram_layout: [4; 32],
            source_run: [5; 16],
            pause_generation: 1,
            capture: [6; 16],
        };
        let mut writer = utils::state::Writer::new(22);
        writer.u16(1).unwrap();
        writer.u32(state.device_type).unwrap();
        writer.u64(state.avail_features).unwrap();
        writer.u64(state.acked_features).unwrap();
        let payload = writer.finish();
        let resource = Arc::new(Mutex::new(rng));
        (
            binding,
            RestoreDeviceBinding {
                identity,
                state,
                payload,
                resource: resource.clone(),
                subscriber: Some(resource),
                generation_binding: None,
            },
        )
    }

    fn generation_binding() -> (StateBinding, RestoreDeviceBinding) {
        use crate::api::device_builders::GenerationBinding;
        use devices::virtio::generation::{DEVICE_ID, DEVICE_TYPE, Generation};
        use devices::virtio::lifecycle::VirtioStateProvider;
        use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
        use std::time::{Duration, Instant};
        let (binding, mut record) = rng_binding();
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let mut generation = Generation::new();
        generation.begin_quiesce(request).unwrap();
        assert!(generation.poll_quiesce(request.key).unwrap().is_ready());
        record.payload = generation.capture_payload(request.key).unwrap();
        record.identity.device_type = devices::DeviceType::Virtio(DEVICE_TYPE);
        record.identity.configured_id = DEVICE_ID.into();
        record.state.device_type = DEVICE_TYPE;
        record.state.device_name = DEVICE_ID.into();
        record.state.avail_features = 1 << 32;
        record.state.queues = vec![Queue::new(1).capture_state().unwrap()];
        let resource = Arc::new(Mutex::new(Generation::new()));
        record.generation_binding = Some(GenerationBinding::new(resource.clone()));
        record.resource = resource;
        record.subscriber = None;
        (binding, record)
    }

    #[test]
    fn generation_restore_retains_exact_typed_resource_without_callback() {
        let (binding, device) = generation_binding();
        let prepared =
            PreparedDeviceInstall::validate(binding, vec![device], Vec::new(), None).unwrap();
        assert!(
            prepared
                .generation_binding
                .as_ref()
                .unwrap()
                .matches(&prepared.devices[0].resource)
        );
        assert!(prepared.devices[0].subscriber.is_none());
    }

    #[test]
    fn generation_restore_rejects_foreign_typed_binding() {
        use crate::api::device_builders::GenerationBinding;
        use devices::virtio::generation::Generation;
        let (binding, mut device) = generation_binding();
        device.generation_binding = Some(GenerationBinding::new(Arc::new(Mutex::new(
            Generation::new(),
        ))));
        assert!(PreparedDeviceInstall::validate(binding, vec![device], Vec::new(), None).is_err());
    }

    #[test]
    fn generation_payload_whitelist_and_exact_singleton_profile_are_bounded() {
        use crate::vmm::execution::device_restore::{DeviceEnvelope, DeviceRecord, payload_limit};
        use devices::virtio::generation::{DEVICE_TYPE, STATE_LIMIT};
        assert_eq!(payload_limit(DEVICE_TYPE).unwrap(), STATE_LIMIT as usize);
        assert!(payload_limit(DEVICE_TYPE + 1).is_err());
        let (binding, device) = generation_binding();
        let mut envelope = DeviceEnvelope {
            binding,
            records: vec![DeviceRecord {
                identity: device.identity,
                state: device.state,
                payload: device.payload,
            }],
        };
        assert!(envelope.validate().is_ok());
        let mut duplicate = envelope.records[0].clone();
        duplicate.identity.address += 0x1000;
        duplicate.state.attachment_address = duplicate.identity.address;
        duplicate.identity.configured_id = "another-generation".into();
        envelope.records.push(duplicate);
        assert!(envelope.validate().is_err());
        envelope.records.pop();
        envelope.records[0]
            .payload
            .resize(STATE_LIMIT as usize + 1, 0);
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn execution_restore_names_missing_real_callback_before_construction() {
        let (binding, mut device) = rng_binding();
        device.subscriber = None;
        let result = PreparedDeviceInstall::validate(binding, vec![device], Vec::new(), None);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("missing callback admitted"),
        };
        assert!(error.contains("missing destination callback owner"));
        assert!(error.contains("rng-instance-0"));
    }

    #[test]
    fn execution_restore_refuses_mismatched_outer_device_type_before_provider() {
        let (binding, mut device) = rng_binding();
        device.identity.device_type = devices::DeviceType::Virtio(device.state.device_type ^ 1);
        let mut plan = PreparedDeviceInstall::empty(&binding);
        plan.devices.push(device);
        let memory =
            vm_memory::GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0), 0x1000)])
                .unwrap();
        let error = plan
            .validate_memory(&arch::guest_memory::ReadGuestMemory::new(&memory))
            .unwrap_err();
        assert!(error.starts_with("restore attachment identity"));
        let result = PreparedDeviceInstall::validate(binding, plan.devices, Vec::new(), None);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("mismatched attachment type admitted"),
        };
        assert!(error.starts_with("restore attachment identity"));
        assert!(error.contains("rng-instance-0"));
    }

    #[test]
    fn execution_device_envelope_roundtrip_and_refuses_malformed_binding() {
        use crate::vmm::execution::device_restore::{DeviceEnvelope, DeviceRecord};
        let (binding, device) = rng_binding();
        let mut envelope = DeviceEnvelope {
            binding,
            records: vec![DeviceRecord {
                identity: device.identity,
                state: device.state,
                payload: device.payload,
            }],
        };
        let bytes = envelope.encode().unwrap();
        assert_eq!(DeviceEnvelope::decode(&bytes).unwrap(), envelope);
        for end in 0..bytes.len() {
            assert!(DeviceEnvelope::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DeviceEnvelope::decode(&trailing).is_err());
        envelope.records[0].payload[0] = 2;
        assert!(envelope.encode().is_err());
        envelope.records[0].payload[0] = 1;
        envelope.records[0].state.acked_features = 1;
        assert!(envelope.encode().is_err());
    }

    #[test]
    fn execution_device_envelope_refuses_duplicate_inventory() {
        use crate::vmm::execution::device_restore::{DeviceEnvelope, DeviceRecord};
        let (binding, device) = rng_binding();
        let record = DeviceRecord {
            identity: device.identity,
            state: device.state,
            payload: device.payload,
        };
        let envelope = DeviceEnvelope {
            binding,
            records: vec![record.clone(), record],
        };
        assert!(envelope.encode().is_err());
    }
}
