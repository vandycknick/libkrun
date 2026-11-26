//! Metadata admission before allocating an identified or owned-cut child.
//!
//! The caller retains immutable-inode leases and supplies explicit input authority.
//! Construction rechecks that authority; inspection is not an install token.
//! The KVM host-profile observer creates only an empty VM and
//! one never-run vCPU, without RAM, child identity or external resources.

use std::fs::File;
use std::time::Instant;

use crate::api::capabilities::{LIVE_STATE_SCHEMA, guest_architecture};
use crate::api::live::restore::{
    RestoreAttachment, RestoreError, RestoreIdentity, RestoreRole, StateObjectAuthority,
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::api::capabilities::{HvfGicSymbols, HvfSymbolGroup};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::vmm::device_manager::mmio::{MMIO_LEN, MMIODeviceManager};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::vmm::execution::{CpuExecutionState, VmExecutionState, host_page_granule};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use devices::legacy::HvfGicV3;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use hvf::framework::HvfFramework;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use hvf::state::{ClockCut, MODEL_REGISTERS, PFR0, RegisterValue};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::ops::Range;

pub struct InspectionInputs<'a> {
    pub execution: &'a File,
    pub devices: &'a File,
    pub layout: &'a File,
    pub expected: &'a RestoreIdentity,
    pub layout_object: &'a StateObjectAuthority,
}

/// Structural observation of a saved device file, not authentication or an
/// execution-admission token. Uses the same bounded codec as actual restore.
#[derive(Debug)]
pub struct SavedDeviceTransport {
    pub configured_id: String,
    pub transport: MmioTransportState,
}

pub fn decode_device_transports(
    bytes: &[u8],
) -> Result<Vec<SavedDeviceTransport>, utils::state::Error> {
    let envelope = DeviceEnvelope::decode(bytes)?;
    Ok(envelope
        .records
        .into_iter()
        .map(|record| SavedDeviceTransport {
            configured_id: record.identity.configured_id,
            transport: record.state,
        })
        .collect())
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
    #[error("inspection live state schema mismatch: expected {expected}, found {found}")]
    Schema {
        expected: &'static str,
        found: String,
    },
    #[error("inspection architecture mismatch: expected {expected}, found {found}")]
    Architecture {
        expected: &'static str,
        found: String,
    },
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[error("inspection HVF compatibility: {0}")]
    HvfHost(#[from] HvfCompatibilityError),
    #[error("inspection deadline expired")]
    Deadline,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfIpaRegion {
    Ram,
    GicDistributor,
    GicRedistributors,
    Mmio,
    LegacyMmio,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, thiserror::Error)]
pub enum HvfCompatibilityError {
    #[error("destination host query failed: {0}")]
    HostQuery(hvf::Error),
    #[error("saved CPU count {saved} exceeds destination maximum {maximum}")]
    CpuCapacity { saved: usize, maximum: u32 },
    #[error(
        "saved {region:?} at {start:#x} with length {length:#x} does not fit in destination {destination_bits}-bit IPA space"
    )]
    IpaRange {
        region: HvfIpaRegion,
        start: u64,
        length: u64,
        destination_bits: u32,
    },
    #[error("saved page granule {saved} does not match destination {destination}")]
    PageGranule { saved: u32, destination: u32 },
    #[error(
        "saved CPU {cpu} model register {register:#x} is {saved:#x}, destination is {destination:#x}"
    )]
    CpuModelRegister {
        cpu: u8,
        register: u16,
        saved: u64,
        destination: u64,
    },
    #[error("saved counter frequency {saved} Hz does not match destination {destination} Hz")]
    CounterFrequency { saved: u64, destination: u64 },
    #[error(
        "saved Mach timebase {saved:?} does not match destination {destination:?} (numerator, denominator)"
    )]
    MachTimebase {
        saved: (u32, u32),
        destination: (u32, u32),
    },
    #[error(
        "saved GIC geometry {saved:x?} does not match destination {destination:x?} (distributor base/size, redistributor base/size)"
    )]
    GicGeometry {
        saved: [u64; 4],
        destination: [u64; 4],
    },
    #[error(
        "saved {region:?} base {address:#x} does not meet destination alignment {alignment:#x}"
    )]
    GicBaseAlignment {
        region: HvfIpaRegion,
        address: u64,
        alignment: u64,
    },
    #[error("saved GIC SPI {saved} is outside the destination range {destination:?}")]
    GicTopology { saved: u32, destination: Range<u32> },
    #[error(
        "saved MMIO position {address:#x}, IRQ {irq} is outside the destination routing profile (base >= {minimum_address:#x}, alignment {alignment:#x}, IRQs {minimum_irq}..={maximum_irq})"
    )]
    MmioPlacement {
        address: u64,
        irq: u32,
        minimum_address: u64,
        alignment: u64,
        minimum_irq: u32,
        maximum_irq: u32,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<hvf::Error> for HvfCompatibilityError {
    fn from(error: hvf::Error) -> Self {
        Self::HostQuery(error)
    }
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
    if saved.binding.live_state_schema != LIVE_STATE_SCHEMA {
        return Err(InspectionError::Schema {
            expected: LIVE_STATE_SCHEMA,
            found: saved.binding.live_state_schema.clone(),
        });
    }
    if saved.binding.architecture != guest_architecture() {
        return Err(InspectionError::Architecture {
            expected: guest_architecture(),
            found: saved.binding.architecture.clone(),
        });
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
    if !expected.validate_authority() {
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn validate_hvf_layout(
    layout: ValidatedRamLayout,
    execution: &ValidatedExecution,
    destination: u32,
) -> Result<ValidatedRamLayout, InspectionError> {
    layout.validate_execution_binding(execution)?;
    if layout.granule() != destination {
        return Err(HvfCompatibilityError::PageGranule {
            saved: layout.granule(),
            destination,
        }
        .into());
    }
    Ok(layout)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg_attr(test, derive(Clone))]
struct HvfHostFacts {
    max_vcpus: u32,
    ipa_bits: u32,
    clock: ClockCut,
    model: [RegisterValue; MODEL_REGISTERS.len() - 1],
    gic_sizes: [u64; 2],
    gic_alignments: [u64; 2],
    gic_spis: Range<u32>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfHostFacts {
    fn query() -> Result<Self, hvf::Error> {
        use hvf::host;

        let framework = HvfFramework::load()?;
        let symbols = HvfGicSymbols::from_presence(framework.gic_symbols());
        for group in [symbols.blob_group(), symbols.icc_group()] {
            if let HvfSymbolGroup::Missing(symbol) = group {
                return Err(hvf::Error::MissingStateApi(symbol.name()));
            }
        }
        Ok(Self {
            max_vcpus: host::max_vcpu_count()?,
            ipa_bits: host::default_ipa_bits()?,
            clock: hvf::capture_clock_cut()?,
            model: host::model_registers(&framework)?,
            gic_sizes: host::gic_region_sizes(&framework)?,
            gic_alignments: host::gic_base_alignments(&framework)?,
            gic_spis: host::gic_spi_range(&framework)?,
        })
    }

    fn check_ipa(
        &self,
        region: HvfIpaRegion,
        start: u64,
        length: u64,
    ) -> Result<(), HvfCompatibilityError> {
        if length
            .checked_sub(1)
            .and_then(|offset| start.checked_add(offset))
            .is_some_and(|last| last.checked_shr(self.ipa_bits).unwrap_or(0) == 0)
        {
            Ok(())
        } else {
            Err(HvfCompatibilityError::IpaRange {
                region,
                start,
                length,
                destination_bits: self.ipa_bits,
            })
        }
    }

    fn check_spi(&self, irq: u32) -> Result<(), HvfCompatibilityError> {
        if !self.gic_spis.contains(&irq) {
            return Err(HvfCompatibilityError::GicTopology {
                saved: irq,
                destination: self.gic_spis.clone(),
            });
        }
        Ok(())
    }

    fn check_frequency(&self, frequency: u64) -> Result<(), HvfCompatibilityError> {
        if frequency != self.clock.frequency {
            return Err(HvfCompatibilityError::CounterFrequency {
                saved: frequency,
                destination: self.clock.frequency,
            });
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn validate_hvf_host(
    execution: &ValidatedExecution,
    facts: Result<HvfHostFacts, hvf::Error>,
) -> Result<(), InspectionError> {
    let host = facts.map_err(HvfCompatibilityError::from)?;
    let saved = execution.envelope();
    let VmExecutionState::Hvf(vm) = &saved.vm else {
        return Err(InspectionError::Lane);
    };
    if saved.cpus.len() > host.max_vcpus as usize {
        return Err(HvfCompatibilityError::CpuCapacity {
            saved: saved.cpus.len(),
            maximum: host.max_vcpus,
        }
        .into());
    }
    let cpu_count = u64::from(vm.gic.vcpu_count);
    let destination = HvfGicV3::geometry(cpu_count, host.gic_sizes).ok_or(
        HvfCompatibilityError::HostQuery(hvf::Error::ExecutionState(hvf::state::StateError(
            "destination GIC sizes do not fit the MMIO layout",
        ))),
    )?;
    let [dist, dist_size, redist, redist_size] = vm.gic.properties;
    for (region, address, length, alignment) in [
        (
            HvfIpaRegion::GicDistributor,
            dist,
            dist_size,
            host.gic_alignments[0],
        ),
        (
            HvfIpaRegion::GicRedistributors,
            redist,
            redist_size,
            host.gic_alignments[1],
        ),
    ] {
        host.check_ipa(region, address, length)?;
        if alignment == 0 || !address.is_multiple_of(alignment) {
            return Err(HvfCompatibilityError::GicBaseAlignment {
                region,
                address,
                alignment,
            }
            .into());
        }
    }
    if vm.gic.properties != destination {
        return Err(HvfCompatibilityError::GicGeometry {
            saved: vm.gic.properties,
            destination,
        }
        .into());
    }
    for range in &saved.memory_regions {
        host.check_ipa(HvfIpaRegion::Ram, range.start(), range.byte_len())?;
    }
    for device in &saved.attachments {
        let (address, irq) = (device.address, device.irq);
        host.check_ipa(HvfIpaRegion::Mmio, address, MMIO_LEN)?;
        MMIODeviceManager::validate_restore_position(address, irq, arch::IRQ_MAX).map_err(
            |_| HvfCompatibilityError::MmioPlacement {
                address,
                irq,
                minimum_address: arch::MMIO_MEM_START,
                alignment: MMIO_LEN,
                minimum_irq: arch::IRQ_BASE,
                maximum_irq: arch::IRQ_MAX,
            },
        )?;
        host.check_spi(irq)?;
    }
    for legacy in &saved.legacy {
        host.check_ipa(HvfIpaRegion::LegacyMmio, legacy.address, MMIO_LEN)?;
        if let Some(irq) = legacy.irq {
            host.check_spi(irq)?;
        }
    }
    host.check_frequency(vm.clock.frequency)?;
    let timebase = (vm.clock.timebase_numer, vm.clock.timebase_denom);
    let destination_timebase = (host.clock.timebase_numer, host.clock.timebase_denom);
    if timebase != destination_timebase {
        return Err(HvfCompatibilityError::MachTimebase {
            saved: timebase,
            destination: destination_timebase,
        }
        .into());
    }
    for cpu in &saved.cpus {
        let CpuExecutionState::Hvf(cpu) = cpu else {
            return Err(InspectionError::Lane);
        };
        host.check_frequency(cpu.frequency)?;
        for destination in &host.model {
            let saved =
                cpu.model_value(destination.id)
                    .map_err(|source| InspectionError::Codec {
                        role: RestoreRole::Execution,
                        source: utils::state::Error::Invalid(source.0),
                    })?;
            // The GIC field reflects the instantiated controller, not the standalone
            // configuration. Construction still compares the full initialized model.
            let comparable = if destination.id == PFR0 {
                !(0xf << 24)
            } else {
                u64::MAX
            };
            if (saved ^ destination.value) & comparable != 0 {
                return Err(HvfCompatibilityError::CpuModelRegister {
                    cpu: cpu.logical_id,
                    register: destination.id,
                    saved,
                    destination: destination.value,
                }
                .into());
            }
        }
    }
    Ok(())
}

/// Admits bounded native metadata and probes the actual destination.
/// This never opens a RAM stream or allocates any restored-child resource.
pub fn inspect_compatibility(
    inputs: InspectionInputs<'_>,
    expected_devices: &[ExpectedDevice],
    deadline: Instant,
) -> Result<AdmittedShape, InspectionError> {
    check_deadline(deadline)?;
    if inputs.layout_object.is_identified()
        != matches!(inputs.expected.ram_image, crate::api::live::RamInputAuthority::IdentifiedSnapshot(_))
    {
        return Err(InspectionError::Binding);
    }
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let layout = validate_hvf_layout(
        ValidatedRamLayout::decode_record(&bytes)?,
        &execution,
        host_page_granule().map_err(crate::vmm::memory::image::RamImageError::from)?,
    )?;
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let layout = {
        let layout = ValidatedRamLayout::decode(&bytes)?;
        layout.validate_execution(&execution)?;
        layout
    };
    for device in &devices {
        validate_queue_geometry(device, &layout)?;
    }
    check_deadline(deadline)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    crate::vmm::linux::execution::inspect_host_execution(execution.envelope(), deadline)
        .map_err(|cause| InspectionError::Host { cause })?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    validate_hvf_host(&execution, HvfHostFacts::query())?;
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
    )))]
    return Err(InspectionError::Host {
        cause: "destination CPU/register inventory probe unavailable for this unqualified lane"
            .into(),
    });
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
    ))]
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
    use crate::api::live::restore::{RestoreProblem, StateObjectAuthority, StateObjectIdentity};
    use crate::api::live::{RamInputAuthority, RamImageAuthentication};
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
                    &StateObjectAuthority::Identified(expected.clone()),
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
            read_object(&file, RestoreRole::Execution, &StateObjectAuthority::Identified(expected.clone()), 7),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::Length,
                ..
            })
        ));
        let bytes = read_object(
            &file,
            RestoreRole::Execution,
            &StateObjectAuthority::Identified(expected),
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
    fn authenticated_execution_fixture_rejects_wrong_lane_or_schema_without_host_probe() {
        let mut envelope = crate::vmm::execution::tests::envelope();
        envelope.binding.live_state_schema = "silo.live-state/unsupported".into();
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
            ram_image: RamInputAuthority::IdentifiedSnapshot(RamImageAuthentication {
                state: envelope.binding.clone(),
                stream: [1; 32],
            }),
            execution_object: StateObjectAuthority::Identified(identity.clone()),
            devices_object: StateObjectAuthority::Identified(identity),
        };
        assert!(matches!(
            authenticate_execution(&file, &expected),
            Err(InspectionError::Lane
                | InspectionError::Schema { .. }
                | InspectionError::Architecture { .. })
        ));
        if let RamInputAuthority::IdentifiedSnapshot(authentication) = &mut expected.ram_image {
            authentication.state.capture = [99; 16];
        }
        assert!(matches!(
            authenticate_execution(&file, &expected),
            Err(InspectionError::Binding)
        ));
        if let RamInputAuthority::IdentifiedSnapshot(authentication) = &mut expected.ram_image {
            authentication.state = expected.binding.clone();
        }
        if let StateObjectAuthority::Identified(identity) = &mut expected.execution_object {
            identity.sha256[0] ^= 1;
        }
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

    #[test]
    fn saved_transport_observation_uses_exact_codec_and_preserves_ring_counters() {
        let (binding, mut record) = crate::vmm::execution::device_restore::tests::rng_binding();
        record.state.queues[0].used_ring = 8192;
        record.state.queues[0].next_used = 13;
        let expected = record.state.clone();
        let configured_id = record.identity.configured_id.clone();
        let bytes = DeviceEnvelope {
            binding,
            records: vec![crate::vmm::execution::device_restore::DeviceRecord {
                identity: record.identity,
                state: record.state,
                payload: record.payload,
            }],
        }
        .encode()
        .unwrap();
        let observations = decode_device_transports(&bytes).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].configured_id, configured_id);
        assert_eq!(observations[0].transport, expected);
        assert!(decode_device_transports(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_device_transports(&vec![0; 32 * 1024 * 1024 + 1]).is_err());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    mod hvf {
        use crate::api::live::inspection::*;
        use crate::vmm::device_manager::quiescence::AttachmentIdentity;
        use crate::vmm::execution::{CpuIdentity, HvfVmState};
        use ::hvf::state::CpuState;
        use arch::guest_memory::GuestRange;
        use devices::legacy::state::{LegacyPayload, LegacyState, RtcState};

        const RAM_START: u64 = 0x8000_0000;
        const RAM_SIZE: u64 = 0x40_0000;
        const GIC: [u64; 4] = [0x09fd_0000, 0x1_0000, 0x09fe_0000, 0x2_0000];

        fn fixture() -> (ExecutionEnvelope, HvfHostFacts) {
            let mut saved = crate::vmm::execution::tests::envelope();
            saved.memory_regions = vec![GuestRange::new(RAM_START, RAM_SIZE).unwrap()];
            saved.attachments = vec![AttachmentIdentity {
                device_type: devices::DeviceType::Virtio(4),
                configured_id: "rng-instance-0".into(),
                address: arch::MMIO_MEM_START + 2 * MMIO_LEN,
                irq: arch::IRQ_BASE + 1,
            }];
            saved.legacy = vec![LegacyState {
                address: arch::MMIO_MEM_START + MMIO_LEN,
                irq: Some(arch::IRQ_BASE),
                payload: LegacyPayload::Rtc(RtcState {
                    guest_nanoseconds: 0,
                    match_value: 0,
                    load: 0,
                    interrupt_mask: 0,
                    interrupt_status: 0,
                }),
            }];
            vm(&mut saved).gic.properties = GIC;
            let host = HvfHostFacts {
                max_vcpus: 8,
                ipa_bits: 36,
                clock: vm(&mut saved).clock,
                model: std::array::from_fn(|index| RegisterValue {
                    id: MODEL_REGISTERS[index + 1],
                    value: 0,
                }),
                gic_sizes: [0x1_0000, 0x2_0000],
                gic_alignments: [0x1_0000, 0x1_0000],
                gic_spis: 32..1020,
            };
            validate_hvf_host(&decode(&saved), Ok(host.clone())).unwrap();
            (saved, host)
        }

        fn vm(saved: &mut ExecutionEnvelope) -> &mut HvfVmState {
            let VmExecutionState::Hvf(vm) = &mut saved.vm else {
                panic!("HVF VM fixture required");
            };
            vm
        }

        fn cpu(saved: &mut ExecutionEnvelope) -> &mut CpuState {
            let CpuExecutionState::Hvf(cpu) = &mut saved.cpus[0] else {
                panic!("HVF CPU fixture required");
            };
            cpu
        }

        fn decode(saved: &ExecutionEnvelope) -> ValidatedExecution {
            let envelope = ExecutionEnvelope::decode(&saved.encode().unwrap()).unwrap();
            ValidatedExecution::validate(envelope, &saved.binding, saved.lane).unwrap()
        }

        #[test]
        fn host_query_refusal_preserves_the_native_status() {
            let (saved, _) = fixture();
            let error = ::hvf::Error::NativeCall {
                symbol: "hv_vm_get_max_vcpu_count",
                status: ::hvf::bindings::HV_DENIED,
            };
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Err(error)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::HostQuery(
                    ::hvf::Error::NativeCall { symbol: "hv_vm_get_max_vcpu_count", status }
                ))) if status == ::hvf::bindings::HV_DENIED
            ));
        }

        #[test]
        fn refuses_cpu_count_above_destination_capacity() {
            let (mut saved, mut host) = fixture();
            let mut second = cpu(&mut saved).clone();
            second.logical_id = 1;
            second.mpidr += 1;
            saved.topology.push(CpuIdentity {
                logical_id: second.logical_id,
                architectural_id: second.mpidr,
            });
            saved.cpus.push(CpuExecutionState::Hvf(second));
            let vm = vm(&mut saved);
            vm.gic.vcpu_count = 2;
            vm.gic.properties = HvfGicV3::geometry(2, host.gic_sizes).unwrap();
            let execution = decode(&saved);
            validate_hvf_host(&execution, Ok(host.clone())).unwrap();
            host.max_vcpus = 1;
            assert!(matches!(
                validate_hvf_host(&execution, Ok(host)),
                Err(InspectionError::HvfHost(
                    HvfCompatibilityError::CpuCapacity {
                        saved: 2,
                        maximum: 1,
                    }
                ))
            ));
        }

        #[test]
        fn refuses_out_of_width_ram_after_admitting_exact_end() {
            let (saved, mut host) = fixture();
            host.check_ipa(HvfIpaRegion::Ram, (1 << 36) - RAM_SIZE, RAM_SIZE)
                .unwrap();
            host.ipa_bits = 31;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::IpaRange {
                    region: HvfIpaRegion::Ram,
                    start: RAM_START,
                    length: RAM_SIZE,
                    destination_bits: 31,
                }))
            ));
        }

        #[test]
        fn refuses_out_of_width_gic_windows() {
            let (saved, mut host) = fixture();
            host.ipa_bits = 27;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::IpaRange {
                    region: HvfIpaRegion::GicDistributor,
                    destination_bits: 27,
                    ..
                }))
            ));
            let (mut saved, host) = fixture();
            vm(&mut saved).gic.properties[2] = 1 << 36;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::IpaRange {
                    region: HvfIpaRegion::GicRedistributors,
                    destination_bits: 36,
                    ..
                }))
            ));
        }

        #[test]
        fn refuses_out_of_width_mmio_and_overflowing_legacy_windows() {
            let (mut saved, host) = fixture();
            saved.attachments[0].address = 1 << 36;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::IpaRange {
                    region: HvfIpaRegion::Mmio,
                    destination_bits: 36,
                    ..
                }))
            ));
            let (mut saved, host) = fixture();
            saved.legacy[0].address = u64::MAX - MMIO_LEN + 2;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::IpaRange {
                    region: HvfIpaRegion::LegacyMmio,
                    destination_bits: 36,
                    ..
                }))
            ));
        }

        #[test]
        fn refuses_page_granule_of_bound_layout() {
            let (saved, _) = fixture();
            let execution = decode(&saved);
            let bytes = br#"{"architecture":"aarch64","kind":"ram-layout","magic":"KRUNRAML","packedLength":4194304,"pageGranule":4096,"regions":[{"guestPhysicalAddress":2147483648,"length":4194304,"streamOffset":0}],"schema":1,"topology":{"fdtAddress":2149580800,"firmwareAddress":0,"initrdAddress":2149580799,"ramLastAddress":2151677952,"ramStartAddress":2147483648,"shmStartAddress":3221225472}}"#;
            let layout = ValidatedRamLayout::decode_record(bytes).unwrap();
            assert!(validate_hvf_layout(layout, &execution, 4096).is_ok());
            let layout = ValidatedRamLayout::decode_record(bytes).unwrap();
            assert!(matches!(
                validate_hvf_layout(layout, &execution, 16384),
                Err(InspectionError::HvfHost(
                    HvfCompatibilityError::PageGranule {
                        saved: 4096,
                        destination: 16384,
                    }
                ))
            ));
        }

        #[test]
        fn refuses_a_changed_guest_visible_cpu_model_register() {
            let (mut saved, host) = fixture();
            cpu(&mut saved)
                .model
                .iter_mut()
                .find(|reg| reg.id == PFR0)
                .unwrap()
                .value = 1;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(
                    HvfCompatibilityError::CpuModelRegister {
                        cpu: 0,
                        register: PFR0,
                        saved: 1,
                        destination: 0,
                    }
                ))
            ));
        }

        #[test]
        fn leaves_the_vm_dependent_pfr0_gic_field_to_construction() {
            let (mut saved, host) = fixture();
            cpu(&mut saved)
                .model
                .iter_mut()
                .find(|reg| reg.id == PFR0)
                .unwrap()
                .value = 1 << 24;
            validate_hvf_host(&decode(&saved), Ok(host)).unwrap();
        }

        #[test]
        fn refuses_an_incompatible_counter_frequency() {
            let (mut saved, host) = fixture();
            vm(&mut saved).clock.frequency = 25_000_000;
            cpu(&mut saved).frequency = 25_000_000;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(
                    HvfCompatibilityError::CounterFrequency {
                        saved: 25_000_000,
                        destination: 24_000_000,
                    }
                ))
            ));
        }

        #[test]
        fn refuses_an_incompatible_mach_timebase() {
            let (mut saved, host) = fixture();
            vm(&mut saved).clock.timebase_denom = 4;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(
                    HvfCompatibilityError::MachTimebase {
                        saved: (125, 4),
                        destination: (125, 3),
                    }
                ))
            ));
        }

        #[test]
        fn refuses_a_different_gic_geometry() {
            let (mut saved, host) = fixture();
            vm(&mut saved).gic.properties[0] -= 0x1_0000;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(
                    HvfCompatibilityError::GicGeometry {
                        saved: [0x09fc_0000, 0x1_0000, 0x09fe_0000, 0x2_0000],
                        destination: GIC,
                    }
                ))
            ));
        }

        #[test]
        fn refuses_a_gic_base_without_destination_alignment() {
            let (mut saved, host) = fixture();
            vm(&mut saved).gic.properties[0] -= 0x1000;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(
                    HvfCompatibilityError::GicBaseAlignment {
                        region: HvfIpaRegion::GicDistributor,
                        address: 0x09fc_f000,
                        alignment: 0x1_0000,
                    }
                ))
            ));
        }

        #[test]
        fn refuses_an_spi_outside_destination_gic_topology() {
            let (saved, mut host) = fixture();
            host.gic_spis.start += 1;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::GicTopology {
                    saved: arch::IRQ_BASE, destination,
                })) if destination == (33..1020)
            ));
        }

        #[test]
        fn refuses_mmio_position_outside_the_construction_profile() {
            let (mut saved, host) = fixture();
            saved.attachments[0].address += 1;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::MmioPlacement {
                    address, minimum_address: arch::MMIO_MEM_START, alignment: MMIO_LEN, ..
                })) if address == arch::MMIO_MEM_START + 2 * MMIO_LEN + 1
            ));
            let (mut saved, host) = fixture();
            saved.attachments[0].irq = arch::IRQ_MAX + 1;
            assert!(matches!(
                validate_hvf_host(&decode(&saved), Ok(host)),
                Err(InspectionError::HvfHost(HvfCompatibilityError::MmioPlacement {
                    irq, maximum_irq: arch::IRQ_MAX, ..
                })) if irq == arch::IRQ_MAX + 1
            ));
        }
    }
}
