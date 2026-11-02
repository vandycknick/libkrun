use std::sync::{Arc, Mutex};

use devices::legacy::Serial;
use devices::virtio::{MmioTransportState, VirtioDevice};
use utils::eventfd::EventFd;

use crate::vmm::device_manager::quiescence::AttachmentIdentity;
use crate::vmm::execution::StateBinding;

pub(crate) struct RestoreDeviceBinding {
    pub identity: AttachmentIdentity,
    pub state: MmioTransportState,
    pub payload: Vec<u8>,
    pub resource: Arc<Mutex<dyn VirtioDevice>>,
}

pub(crate) struct PreparedDeviceInstall {
    pub binding: StateBinding,
    pub devices: Vec<RestoreDeviceBinding>,
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
    pub fn validate_memory(&self, memory: &vm_memory::GuestMemoryMmap) -> Result<(), String> {
        let memory = devices::virtio::RuntimeGuestMemory::passthrough(memory.clone());
        for entry in &self.devices {
            if entry.identity.device_type != devices::DeviceType::Virtio(entry.state.device_type) {
                return Err(format!("restore attachment identity {:?}", entry.identity));
            }
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
                devices::virtio::Queue::validate_restored_state(queue.size, &memory, saved)
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
        for entry in &devices {
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
        (
            binding,
            RestoreDeviceBinding {
                identity,
                state,
                payload: Vec::new(),
                resource: Arc::new(Mutex::new(rng)),
            },
        )
    }

    #[test]
    fn execution_restore_names_real_missing_provider_before_construction() {
        let (binding, device) = rng_binding();
        let result = PreparedDeviceInstall::validate(binding, vec![device], Vec::new(), None);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("missing provider admitted"),
        };
        assert!(error.contains("missing restore provider"));
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
        let error = plan.validate_memory(&memory).unwrap_err();
        assert!(error.starts_with("restore attachment identity"));
        let result = PreparedDeviceInstall::validate(binding, plan.devices, Vec::new(), None);
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("mismatched attachment type admitted"),
        };
        assert!(error.starts_with("restore attachment identity"));
        assert!(error.contains("rng-instance-0"));
    }
}
