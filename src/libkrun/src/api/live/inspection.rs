//! Authenticated metadata admission before allocating a restored child.
//!
//! The caller retains immutable-inode leases and verifies the full RAM stream.
//! Admission is an observation, not an install token: construction authenticates
//! its inputs again. The KVM host-profile observer creates only an empty VM and
//! one never-run vCPU, without RAM, child identity or external resources.

use std::fs::File;
use std::time::Instant;

use crate::api::capabilities::execution_state_producer;
use crate::api::live::restore::{
    RestoreAttachment, RestoreError, RestoreIdentity, RestoreRole, StateObjectIdentity,
};
use crate::api::vmm_builder::restored::{
    MAX_DEVICES_BYTES, inspect, read_object, validate_profile,
};
use crate::vmm::execution::device_restore::{DeviceEnvelope, ValidatedDevices};
use crate::vmm::execution::{
    ExecutionEnvelope, ExecutionLane, MAX_EXECUTION_BYTES, ValidatedExecution,
};
use crate::vmm::memory::image::ValidatedRamLayout;
use crate::vmm::memory::image::layout::MAX_RAM_LAYOUT_BYTES;
use devices::virtio::generation::DEVICE_TYPE;
use devices::virtio::{Balloon, Console, MmioTransportState, Rng, Vsock};

pub struct InspectionInputs<'a> {
    pub execution: &'a File,
    pub devices: &'a File,
    pub layout: &'a File,
    pub expected: &'a RestoreIdentity,
    pub layout_object: &'a StateObjectIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedDevice {
    pub configured_id: String,
    pub kind: ExpectedDeviceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedDeviceKind {
    #[cfg(feature = "blk")]
    Block {
        format: devices::virtio::block::DiskFormat,
        byte_length: u64,
        read_only: bool,
    },
    Network,
    Vsock {
        cid: u64,
    },
    Console {
        ports: Vec<(String, bool, bool, bool)>,
    },
    Rng,
    Balloon,
    Generation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmittedDeviceKind {
    #[cfg(feature = "blk")]
    Block(devices::virtio::block::RestoreBlockShape),
    Network {
        source_mac: [u8; 6],
    },
    Vsock {
        cid: u64,
    },
    Console {
        ports: Vec<(String, bool, bool, bool)>,
    },
    Rng,
    Balloon,
    Generation,
}

#[derive(Debug)]
pub struct AdmittedDevice {
    attachment: RestoreAttachment,
    kind: AdmittedDeviceKind,
    transport: MmioTransportState,
}
impl AdmittedDevice {
    pub fn attachment(&self) -> &RestoreAttachment {
        &self.attachment
    }
    pub fn kind(&self) -> &AdmittedDeviceKind {
        &self.kind
    }
    pub fn transport(&self) -> &MmioTransportState {
        &self.transport
    }
}

#[derive(Debug)]
pub struct AdmittedShape {
    execution: ValidatedExecution,
    layout: ValidatedRamLayout,
    devices: Vec<AdmittedDevice>,
}
impl AdmittedShape {
    pub fn execution(&self) -> &ExecutionEnvelope {
        self.execution.envelope()
    }
    pub fn layout(&self) -> &ValidatedRamLayout {
        &self.layout
    }
    pub fn devices(&self) -> &[AdmittedDevice] {
        &self.devices
    }
    pub fn cpu_count(&self) -> usize {
        self.execution.envelope().cpus.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InspectionError {
    #[error("inspection descriptor: {0}")]
    Descriptor(#[from] RestoreError),
    #[error("inspection {role:?} codec: {source}")]
    Codec {
        role: RestoreRole,
        source: utils::state::Error,
    },
    #[error("inspection exact state binding mismatch")]
    Binding,
    #[error("inspection exact native producer mismatch: {0}")]
    Producer(String),
    #[error("inspection backend/ISA mismatch")]
    Lane,
    #[error("inspection unsupported execution profile: {0}")]
    Profile(String),
    #[error("inspection device {configured_id}: {cause}")]
    Device {
        configured_id: String,
        cause: String,
    },
    #[error("inspection semantic device expectations mismatch")]
    Expectations,
    #[error("inspection RAM layout: {0}")]
    Layout(#[from] crate::vmm::memory::image::RamImageError),
    #[error("inspection host compatibility: {cause}")]
    Host { cause: String },
    #[error("inspection deadline expired")]
    Deadline,
}

fn check_deadline(deadline: Instant) -> Result<(), InspectionError> {
    if Instant::now() >= deadline {
        Err(InspectionError::Deadline)
    } else {
        Ok(())
    }
}

pub(crate) fn native_lane() -> ExecutionLane {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        ExecutionLane::KvmX86
    } else if cfg!(target_os = "linux") {
        ExecutionLane::KvmArm64
    } else {
        ExecutionLane::HvfArm64
    }
}

pub(crate) fn validate_execution_profile(
    execution: &ValidatedExecution,
) -> Result<(), InspectionError> {
    let saved = execution.envelope();
    if saved.lane != native_lane() {
        return Err(InspectionError::Lane);
    }
    let producer = execution_state_producer().map_err(InspectionError::Producer)?;
    if saved.binding.native_producer != producer {
        return Err(InspectionError::Producer("exact build identity".into()));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use crate::vmm::execution::{
            CpuExecutionState,
            kvm::{KvmCpuState, lapic_u32},
        };
        crate::vmm::execution::runtime::KvmCaptureProfile::from_restored_execution(execution)
            .map_err(InspectionError::Profile)?;
        let mut frequency = None;
        for cpu in &saved.cpus {
            let CpuExecutionState::Kvm(KvmCpuState::X86(cpu)) = cpu else {
                return Err(InspectionError::Lane);
            };
            if frequency.is_some_and(|rate| rate != cpu.tsc_khz) {
                return Err(InspectionError::Profile(
                    "kvm/clock/rate-disagreement".into(),
                ));
            }
            frequency = Some(cpu.tsc_khz);
            if lapic_u32(&cpu.lapic, 0x350).map_err(InspectionError::Profile)? & (7 << 8)
                == (4 << 8)
            {
                return Err(InspectionError::Profile("pit/lvt0/virtual-wire-nmi".into()));
            }
        }
    }
    Ok(())
}

fn authenticate_execution(
    file: &File,
    expected: &RestoreIdentity,
) -> Result<ValidatedExecution, InspectionError> {
    if expected.binding != expected.ram_image.state || expected.ram_image.stream == [0; 32] {
        return Err(InspectionError::Binding);
    }
    let bytes = read_object(
        file,
        RestoreRole::Execution,
        &expected.execution_object,
        MAX_EXECUTION_BYTES,
    )?;
    let envelope = ExecutionEnvelope::decode(&bytes).map_err(|source| InspectionError::Codec {
        role: RestoreRole::Execution,
        source,
    })?;
    if envelope.lane != native_lane() {
        return Err(InspectionError::Lane);
    }
    if envelope.binding != expected.binding {
        return Err(InspectionError::Binding);
    }
    let validated = ValidatedExecution::validate(envelope, &expected.binding, native_lane())
        .map_err(|source| InspectionError::Codec {
            role: RestoreRole::Execution,
            source,
        })?;
    validate_execution_profile(&validated)?;
    Ok(validated)
}

fn admits(expected: &ExpectedDeviceKind, actual: &AdmittedDeviceKind) -> bool {
    match (expected, actual) {
        #[cfg(feature = "blk")]
        (
            ExpectedDeviceKind::Block {
                format,
                byte_length,
                read_only,
            },
            AdmittedDeviceKind::Block(saved),
        ) => {
            *format == saved.format
                && *byte_length == saved.byte_length
                && *read_only == saved.read_only
        }
        (ExpectedDeviceKind::Network, AdmittedDeviceKind::Network { .. }) => true,
        (ExpectedDeviceKind::Vsock { cid: expected }, AdmittedDeviceKind::Vsock { cid }) => {
            expected == cid
        }
        (
            ExpectedDeviceKind::Console { ports: expected },
            AdmittedDeviceKind::Console { ports },
        ) => expected == ports,
        (ExpectedDeviceKind::Rng, AdmittedDeviceKind::Rng)
        | (ExpectedDeviceKind::Balloon, AdmittedDeviceKind::Balloon)
        | (ExpectedDeviceKind::Generation, AdmittedDeviceKind::Generation) => true,
        _ => false,
    }
}

fn admit_devices(
    validated: ValidatedDevices,
    expected: &[ExpectedDevice],
) -> Result<Vec<AdmittedDevice>, InspectionError> {
    let envelope = validated.into_envelope();
    validate_profile(&envelope.records)?;
    if expected.len() != envelope.records.len() || expected.len() > 256 {
        return Err(InspectionError::Expectations);
    }
    let mut devices = Vec::with_capacity(envelope.records.len());
    for record in envelope.records {
        let failure = |cause: &str| InspectionError::Device {
            configured_id: record.identity.configured_id.clone(),
            cause: cause.into(),
        };
        #[cfg(target_os = "linux")]
        crate::vmm::device_manager::mmio::MMIODeviceManager::validate_restore_position(
            record.identity.address,
            record.identity.irq,
            arch::IRQ_MAX,
        )
        .map_err(|error| failure(&format!("MMIO/IRQ routing: {error}")))?;
        let name = match record.state.device_type {
            1 => "net",
            2 => "block",
            3 => "console",
            4 => "rng",
            5 => "balloon",
            19 => "vsock",
            DEVICE_TYPE => devices::virtio::generation::DEVICE_ID,
            _ => return Err(failure("unsupported provider")),
        };
        if record.state.device_name != name {
            return Err(failure("native provider name"));
        }
        let kind = match record.state.device_type {
            #[cfg(feature = "blk")]
            2 => {
                let shape = devices::virtio::Block::inspect_restore_payload(&record.payload)
                    .map_err(|error| failure(&format!("block payload: {error:?}")))?;
                if shape.id != record.identity.configured_id {
                    return Err(failure("block ID binding"));
                }
                AdmittedDeviceKind::Block(shape)
            }
            #[cfg(feature = "net")]
            1 => AdmittedDeviceKind::Network {
                source_mac: devices::virtio::Net::inspect_restore_payload(&record.payload)
                    .map_err(|error| failure(&format!("network payload: {error:?}")))?,
            },
            19 => AdmittedDeviceKind::Vsock {
                cid: Vsock::inspect_restore_payload(&record.payload)
                    .map_err(|error| failure(&format!("vsock payload: {error:?}")))?,
            },
            3 => AdmittedDeviceKind::Console {
                ports: Console::inspect_restore_payload(&record.payload)
                    .map_err(|error| failure(&format!("console payload: {error:?}")))?,
            },
            4 => {
                Rng::inspect_restore_payload(&record.payload)
                    .map_err(|error| failure(&format!("rng payload: {error:?}")))?;
                AdmittedDeviceKind::Rng
            }
            5 => {
                Balloon::inspect_restore_payload(&record.payload, record.state.avail_features)
                    .map_err(|error| failure(&format!("balloon payload: {error:?}")))?;
                AdmittedDeviceKind::Balloon
            }
            DEVICE_TYPE => AdmittedDeviceKind::Generation,
            _ => return Err(failure("unsupported provider")),
        };
        let mut bindings = expected
            .iter()
            .filter(|item| item.configured_id == record.identity.configured_id);
        if !bindings
            .next()
            .is_some_and(|binding| admits(&binding.kind, &kind))
            || bindings.next().is_some()
        {
            return Err(InspectionError::Expectations);
        }
        devices.push(AdmittedDevice {
            attachment: RestoreAttachment {
                configured_id: record.identity.configured_id,
                address: record.identity.address,
                irq: record.identity.irq,
            },
            kind,
            transport: record.state,
        });
    }
    Ok(devices)
}

fn validate_queue_geometry(
    device: &AdmittedDevice,
    layout: &ValidatedRamLayout,
) -> Result<(), InspectionError> {
    let configs = match &device.kind {
        #[cfg(feature = "blk")]
        AdmittedDeviceKind::Block(_) => Some(&devices::virtio::block::QUEUE_CONFIG[..]),
        #[cfg(feature = "net")]
        AdmittedDeviceKind::Network { .. } => Some(&devices::virtio::net::QUEUE_CONFIG[..]),
        AdmittedDeviceKind::Vsock { .. } => Some(Vsock::restore_queue_config()),
        AdmittedDeviceKind::Rng => Some(Rng::restore_queue_config()),
        AdmittedDeviceKind::Balloon => Some(Balloon::restore_queue_config()),
        _ => None,
    };
    let (count, uniform_size) = match &device.kind {
        AdmittedDeviceKind::Console { ports } => Console::restore_queue_geometry(ports.len()),
        AdmittedDeviceKind::Generation => (1, 1),
        _ => (configs.map_or(0, |configs| configs.len()), 0),
    };
    let fault = |cause: String| InspectionError::Device {
        configured_id: device.attachment.configured_id.clone(),
        cause,
    };
    if device.transport.queues.len() != count {
        return Err(fault("destination queue count".into()));
    }
    for (index, queue) in device.transport.queues.iter().enumerate() {
        let max_size = configs.map_or(uniform_size, |configs| configs[index].size);
        devices::virtio::Queue::validate_restored_geometry(max_size, queue, |address, length| {
            let end = address
                .checked_add(length as u64)
                .ok_or(devices::virtio::QueueError::AddressOverflow)?;
            let mut cursor = address;
            for region in layout.regions() {
                let region_end = region.guest_start + region.length;
                if region.guest_start <= cursor && cursor < region_end {
                    cursor = end.min(region_end);
                    if cursor == end {
                        return Ok(());
                    }
                }
            }
            Err(devices::virtio::QueueError::InvalidChain)
        })
        .map_err(|error| fault(format!("queue/{index}: {error}")))?;
    }
    Ok(())
}

/// Authenticates bounded native metadata and probes the actual destination.
/// This never opens a RAM stream or allocates any restored-child resource.
pub fn inspect_compatibility(
    inputs: InspectionInputs<'_>,
    expected_devices: &[ExpectedDevice],
    deadline: Instant,
) -> Result<AdmittedShape, InspectionError> {
    check_deadline(deadline)?;
    let execution_inode = inspect(inputs.execution, RestoreRole::Execution, false)?;
    let devices_inode = inspect(inputs.devices, RestoreRole::Devices, false)?;
    if devices_inode == execution_inode {
        return Err(RestoreError::Descriptor {
            role: RestoreRole::Devices,
            problem: crate::api::live::restore::RestoreProblem::Alias,
        }
        .into());
    }
    let layout_inode = inspect(inputs.layout, RestoreRole::Layout, false)?;
    if layout_inode == execution_inode || layout_inode == devices_inode {
        return Err(RestoreError::Descriptor {
            role: RestoreRole::Layout,
            problem: crate::api::live::restore::RestoreProblem::Alias,
        }
        .into());
    }
    let execution = authenticate_execution(inputs.execution, inputs.expected)?;
    check_deadline(deadline)?;
    let bytes = read_object(
        inputs.devices,
        RestoreRole::Devices,
        &inputs.expected.devices_object,
        MAX_DEVICES_BYTES,
    )?;
    let devices = ValidatedDevices::validate(
        DeviceEnvelope::decode(&bytes).map_err(|source| InspectionError::Codec {
            role: RestoreRole::Devices,
            source,
        })?,
        execution.envelope(),
    )
    .map_err(|source| InspectionError::Codec {
        role: RestoreRole::Devices,
        source,
    })?;
    let devices = admit_devices(devices, expected_devices)?;
    let bytes = read_object(
        inputs.layout,
        RestoreRole::Layout,
        inputs.layout_object,
        MAX_RAM_LAYOUT_BYTES,
    )?;
    let layout = ValidatedRamLayout::decode(&bytes)?;
    layout.validate_execution(&execution)?;
    for device in &devices {
        validate_queue_geometry(device, &layout)?;
    }
    check_deadline(deadline)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    crate::vmm::linux::execution::inspect_host_execution(execution.envelope(), deadline)
        .map_err(|cause| InspectionError::Host { cause })?;
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    return Err(InspectionError::Host {
        cause: "destination CPU/register inventory probe unavailable for this unqualified lane"
            .into(),
    });
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        check_deadline(deadline)?;
        Ok(AdmittedShape {
            execution,
            layout,
            devices,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::api::live::inspection::*;
    use crate::api::live::restore::{RestoreProblem, StateObjectIdentity};
    use crate::api::vmm_builder::restored::sha256;
    use std::io::Write;
    use std::time::Duration;
    use utils::tempfile::TempFile;

    #[test]
    fn bounded_metadata_reader_rejects_empty_truncated_oversized_and_wrong_digest() {
        let temp = TempFile::new().unwrap();
        let mut writer = temp.as_file();
        writer.write_all(b"KRUNEXEC").unwrap();
        let file = File::open(temp.as_path()).unwrap();
        for expected in [
            StateObjectIdentity {
                length: 0,
                sha256: sha256(b""),
            },
            StateObjectIdentity {
                length: 9,
                sha256: sha256(b"KRUNEXECx"),
            },
            StateObjectIdentity {
                length: 8,
                sha256: [0; 32],
            },
        ] {
            assert!(
                read_object(
                    &file,
                    RestoreRole::Execution,
                    &expected,
                    MAX_EXECUTION_BYTES
                )
                .is_err()
            );
        }
        let expected = StateObjectIdentity {
            length: 8,
            sha256: sha256(b"KRUNEXEC"),
        };
        assert!(matches!(
            read_object(&file, RestoreRole::Execution, &expected, 7),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::Length,
                ..
            })
        ));
        let bytes = read_object(
            &file,
            RestoreRole::Execution,
            &expected,
            MAX_EXECUTION_BYTES,
        )
        .unwrap();
        assert!(ExecutionEnvelope::decode(&bytes).is_err());
        assert_eq!(file.metadata().unwrap().len(), 8);
    }

    #[test]
    fn semantic_expectations_do_not_admit_changed_provider_or_geometry() {
        assert!(!admits(
            &ExpectedDeviceKind::Rng,
            &AdmittedDeviceKind::Balloon
        ));
        assert!(!admits(
            &ExpectedDeviceKind::Vsock { cid: 3 },
            &AdmittedDeviceKind::Vsock { cid: 4 }
        ));
        assert!(!admits(
            &ExpectedDeviceKind::Console {
                ports: vec![("console".into(), false, true, false)]
            },
            &AdmittedDeviceKind::Console {
                ports: vec![("console".into(), true, true, false)]
            }
        ));
        assert!(admits(
            &ExpectedDeviceKind::Network,
            &AdmittedDeviceKind::Network {
                source_mac: [2, 0, 0, 0, 0, 1]
            }
        ));
        assert!(matches!(
            check_deadline(Instant::now() - Duration::from_secs(1)),
            Err(InspectionError::Deadline)
        ));
    }
    #[test]
    fn authenticated_execution_fixture_rejects_wrong_lane_or_exact_producer_without_host_probe() {
        let envelope = crate::vmm::execution::tests::envelope();
        let bytes = envelope.encode().unwrap();
        let temp = TempFile::new().unwrap();
        temp.as_file().write_all(&bytes).unwrap();
        let file = File::open(temp.as_path()).unwrap();
        let identity = StateObjectIdentity {
            length: bytes.len() as u64,
            sha256: sha256(&bytes),
        };
        let mut expected = RestoreIdentity {
            binding: envelope.binding.clone(),
            ram_image: crate::api::live::RamImageAuthentication {
                state: envelope.binding.clone(),
                stream: [1; 32],
            },
            execution_object: identity.clone(),
            devices_object: identity,
        };
        assert!(matches!(
            authenticate_execution(&file, &expected),
            Err(InspectionError::Lane | InspectionError::Producer(_))
        ));
        expected.ram_image.state.capture = [99; 16];
        assert!(matches!(
            authenticate_execution(&file, &expected),
            Err(InspectionError::Binding)
        ));
        expected.ram_image.state = expected.binding.clone();
        expected.execution_object.sha256[0] ^= 1;
        assert!(matches!(
            authenticate_execution(&file, &expected),
            Err(InspectionError::Descriptor(RestoreError::Descriptor {
                problem: RestoreProblem::Digest,
                ..
            }))
        ));
    }

    #[test]
    fn native_provider_codecs_reject_truncated_and_trailing_payloads() {
        let (_, rng) = crate::vmm::execution::device_restore::tests::rng_binding();
        Rng::inspect_restore_payload(&rng.payload).unwrap();
        for end in 0..rng.payload.len() {
            assert!(Rng::inspect_restore_payload(&rng.payload[..end]).is_err());
        }
        let mut trailing = rng.payload;
        trailing.push(0);
        assert!(Rng::inspect_restore_payload(&trailing).is_err());
        for malformed in [&[][..], &[1][..], &[0; 4097][..]] {
            assert!(Console::inspect_restore_payload(malformed).is_err());
            assert!(Vsock::inspect_restore_payload(malformed).is_err());
            assert!(Balloon::inspect_restore_payload(malformed, 0).is_err());
            #[cfg(feature = "net")]
            assert!(devices::virtio::Net::inspect_restore_payload(malformed).is_err());
            #[cfg(feature = "blk")]
            assert!(devices::virtio::Block::inspect_restore_payload(malformed).is_err());
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn admitted_queue_geometry_uses_native_queue_checks_without_ram_mapping() {
        let layout =
            ValidatedRamLayout::decode(crate::vmm::memory::image::layout::tests::X86.as_bytes())
                .unwrap();
        let (_, rng) = crate::vmm::execution::device_restore::tests::rng_binding();
        let mut device = AdmittedDevice {
            attachment: RestoreAttachment {
                configured_id: rng.identity.configured_id,
                address: rng.identity.address,
                irq: rng.identity.irq,
            },
            kind: AdmittedDeviceKind::Rng,
            transport: rng.state,
        };
        validate_queue_geometry(&device, &layout).unwrap();
        device.transport.queues[0].ready = true;
        device.transport.queues[0].size = 8;
        device.transport.queues[0].desc_table = 0;
        device.transport.queues[0].avail_ring = 128;
        device.transport.queues[0].used_ring = 256;
        validate_queue_geometry(&device, &layout).unwrap();
        device.transport.queues[0].max_size = 128;
        assert!(validate_queue_geometry(&device, &layout).is_err());
        device.transport.queues[0].max_size = 256;
        device.transport.queues[0].desc_table = 1;
        assert!(validate_queue_geometry(&device, &layout).is_err());
        device.transport.queues[0].desc_table = 12288;
        assert!(validate_queue_geometry(&device, &layout).is_err());
        device.transport.queues[0].desc_table = u64::MAX - 15;
        assert!(validate_queue_geometry(&device, &layout).is_err());
        device.transport.queues[0].desc_table = 0;
        device.transport.queues[0].size = 3;
        assert!(validate_queue_geometry(&device, &layout).is_err());
    }
}
