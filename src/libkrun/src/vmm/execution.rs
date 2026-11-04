use arch::guest_memory::GuestRange;
use std::sync::Arc;
use vm_memory::{GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};

use crate::vmm::device_manager::quiescence::AttachmentIdentity;
pub use arch::hvf_state as hvf;
use devices::legacy::state::{LegacyPayload, LegacyState, MAX_LEGACY_DEVICES};
use utils::state::{Error, Reader, Writer};

pub(crate) mod device_restore;
mod hvf_codec;
pub mod kvm;
pub(crate) mod runtime;

pub const EXECUTION_ABI: u32 = 1;
pub const MAX_EXECUTION_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NATIVE_BINDING: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"KRUNEXEC";

pub(crate) fn native_page_granule() -> Result<u32, Error> {
    let granule = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .map_err(|_| Error::Invalid("host page granule query"))?
        .ok_or(Error::Invalid("unknown host page granule"))?;
    let granule = u32::try_from(granule).map_err(|_| Error::Invalid("host page granule"))?;
    if !granule.is_power_of_two() {
        return Err(Error::Invalid("unsupported host page granule"));
    }
    Ok(granule)
}

pub(crate) fn host_page_granule() -> Result<u32, Error> {
    let granule = native_page_granule()?;
    if !(4096..=65536).contains(&granule) {
        return Err(Error::Invalid("unsupported capture page granule"));
    }
    Ok(granule)
}

pub(crate) fn memory_regions(memory: &GuestMemoryMmap) -> Result<Vec<GuestRange>, Error> {
    if memory.num_regions() > 512 {
        return Err(Error::Limit);
    }
    memory
        .iter()
        .map(|region| {
            GuestRange::new(region.start_addr().0, region.len())
                .map_err(|_| Error::Invalid("RAM region"))
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpuExecutionState {
    Kvm(kvm::KvmCpuState),
    Hvf(hvf::CpuState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfVmState {
    pub clock: hvf::ClockCut,
    pub gic: hvf::GicState,
}

// One bounded VM snapshot belongs to each retained cut; boxing adds an
// allocation without changing the separately bounded variable-length payloads.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmExecutionState {
    Kvm(kvm::KvmVmState),
    Hvf(HvfVmState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfCpuTimePlan {
    pub logical_id: u8,
    pub timer: hvf::TimerState,
    pub absolute_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpuTimePlan {
    Kvm(kvm::KvmCpuTimePlan),
    Hvf(HvfCpuTimePlan),
}

// Commands already share this bounded input through Arc<CpuExecutionInput>.
// Boxing Install would add a second allocation and indirection per install.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpuExecutionInput {
    Install(CpuExecutionState),
    PrepareTime(CpuTimePlan),
    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    InitializeDeviceWitness(SourceWitnessBootstrap),
}

#[cfg(all(
    feature = "native-device-probe",
    target_os = "linux",
    target_arch = "x86_64"
))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceWitnessBootstrap {
    pub regs: [u64; 18],
    pub special: kvm::X86Special,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionLane {
    KvmX86,
    KvmArm64,
    HvfArm64,
}

impl ExecutionLane {
    fn tag(self) -> u8 {
        match self {
            Self::KvmX86 => 1,
            Self::KvmArm64 => 2,
            Self::HvfArm64 => 3,
        }
    }

    fn decode(tag: u8) -> Result<Self, Error> {
        match tag {
            1 => Ok(Self::KvmX86),
            2 => Ok(Self::KvmArm64),
            3 => Ok(Self::HvfArm64),
            _ => Err(Error::Invalid("execution lane")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateBinding {
    pub native_producer: String,
    pub silo_producer: [u8; 32],
    pub profile: [u8; 32],
    pub topology: [u8; 32],
    pub ram_layout: [u8; 32],
    pub source_run: [u8; 16],
    pub pause_generation: u64,
    pub capture: [u8; 16],
}

impl StateBinding {
    pub fn validate(&self) -> Result<(), Error> {
        if self.native_producer.is_empty()
            || self.native_producer.len() > MAX_NATIVE_BINDING
            || self.silo_producer == [0; 32]
            || self.profile == [0; 32]
            || self.topology == [0; 32]
            || self.ram_layout == [0; 32]
            || self.source_run == [0; 16]
            || self.capture == [0; 16]
            || self.pause_generation == 0
        {
            return Err(Error::Invalid("execution binding"));
        }
        Ok(())
    }

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        self.validate()?;
        w.bytes(self.native_producer.as_bytes(), MAX_NATIVE_BINDING)?;
        for value in [
            &self.silo_producer,
            &self.profile,
            &self.topology,
            &self.ram_layout,
        ] {
            w.fixed(value)?;
        }
        w.fixed(&self.source_run)?;
        w.u64(self.pause_generation)?;
        w.fixed(&self.capture)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let native_producer = std::str::from_utf8(r.bytes(MAX_NATIVE_BINDING)?)
            .map_err(|_| Error::Invalid("native producer UTF-8"))?
            .to_owned();
        let binding = Self {
            native_producer,
            silo_producer: r.fixed()?,
            profile: r.fixed()?,
            topology: r.fixed()?,
            ram_layout: r.fixed()?,
            source_run: r.fixed()?,
            pause_generation: r.u64()?,
            capture: r.fixed()?,
        };
        binding.validate()?;
        Ok(binding)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuIdentity {
    pub logical_id: u8,
    pub architectural_id: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IrqRouteIdentity {
    pub gsi: u32,
    pub members: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionEnvelope {
    pub binding: StateBinding,
    pub lane: ExecutionLane,
    pub topology: Vec<CpuIdentity>,
    pub attachments: Vec<AttachmentIdentity>,
    pub irq_routes: Vec<IrqRouteIdentity>,
    pub page_granule: u32,
    pub memory_regions: Vec<GuestRange>,
    pub vm: VmExecutionState,
    pub cpus: Vec<CpuExecutionState>,
    pub legacy: Vec<LegacyState>,
}

#[derive(Clone, Debug)]
pub struct ValidatedExecution {
    envelope: Arc<ExecutionEnvelope>,
}

impl ValidatedExecution {
    pub fn envelope(&self) -> &ExecutionEnvelope {
        &self.envelope
    }

    pub(crate) fn validate(
        envelope: ExecutionEnvelope,
        expected: &StateBinding,
        lane: ExecutionLane,
    ) -> Result<Self, Error> {
        envelope.validate()?;
        if &envelope.binding != expected || envelope.lane != lane {
            return Err(Error::Invalid("exact destination execution binding"));
        }
        Ok(Self {
            envelope: Arc::new(envelope),
        })
    }

    pub fn decode(
        bytes: &[u8],
        expected: &StateBinding,
        lane: ExecutionLane,
        topology: &[CpuIdentity],
        legacy: &[(u8, u64, Option<u32>)],
    ) -> Result<Self, Error> {
        let envelope = ExecutionEnvelope::decode(bytes)?;
        if &envelope.binding != expected {
            return Err(Error::Invalid("exact producer/profile/cut/layout binding"));
        }
        if envelope.lane != lane || envelope.topology != topology {
            return Err(Error::Invalid("destination CPU topology"));
        }
        if envelope.legacy.len() != legacy.len()
            || envelope.legacy.iter().zip(legacy).any(|(state, identity)| {
                (state.payload.tag(), state.address, state.irq) != *identity
            })
        {
            return Err(Error::Invalid("destination legacy inventory"));
        }
        Ok(Self {
            envelope: Arc::new(envelope),
        })
    }
}

impl CpuExecutionState {
    pub fn id(&self) -> u8 {
        match self {
            Self::Kvm(state) => state.id(),
            Self::Hvf(state) => state.logical_id,
        }
    }

    pub fn lane(&self) -> ExecutionLane {
        match self {
            Self::Kvm(kvm::KvmCpuState::X86(_)) => ExecutionLane::KvmX86,
            Self::Kvm(kvm::KvmCpuState::Arm64(_)) => ExecutionLane::KvmArm64,
            Self::Hvf(_) => ExecutionLane::HvfArm64,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Kvm(state) => state
                .validate()
                .map_err(|_| Error::Invalid("KVM CPU state")),
            Self::Hvf(state) => state
                .validate()
                .map_err(|_| Error::Invalid("HVF CPU state")),
        }
    }

    fn architectural_id(&self) -> Result<u64, Error> {
        match self {
            Self::Kvm(kvm::KvmCpuState::X86(state)) => state
                .cpuid
                .iter()
                .find(|entry| entry.function == 1 && entry.index == 0)
                .map(|entry| u64::from(entry.values[1] >> 24))
                .ok_or(Error::Invalid("APIC identity")),
            Self::Kvm(kvm::KvmCpuState::Arm64(state)) => Ok(state.mpidr),
            Self::Hvf(state) => Ok(state.mpidr),
        }
    }
}

fn validate_x86_package_topology(
    cpuid: &[kvm::CpuidEntry],
    package_slots: u8,
    multiple_cpus: bool,
) -> Result<(), Error> {
    let leaf = cpuid
        .iter()
        .find(|entry| entry.function == 1 && entry.index == 0)
        .ok_or(Error::Invalid("x86 package CPUID leaf"))?;
    if (leaf.values[1] >> 16) & 0xff != u32::from(package_slots)
        || (leaf.values[3] & (1 << 28) != 0) != multiple_cpus
    {
        return Err(Error::Invalid("x86 package CPU topology"));
    }
    Ok(())
}

impl ExecutionEnvelope {
    pub fn validate_memory(&self, memory: &GuestMemoryMmap) -> Result<(), Error> {
        if self.page_granule != host_page_granule()?
            || self.memory_regions != memory_regions(memory)?
        {
            return Err(Error::Invalid("destination RAM geometry/granule"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.binding.validate()?;
        if !self.page_granule.is_power_of_two()
            || !(4096..=65536).contains(&self.page_granule)
            || self.memory_regions.is_empty()
            || self.memory_regions.len() > 512
        {
            return Err(Error::Invalid("RAM geometry extent/granule"));
        }
        let mut total = 0_u64;
        let mut previous_end = 0_u64;
        for region in &self.memory_regions {
            if region.start() < previous_end
                || region.start() % u64::from(self.page_granule) != 0
                || region.byte_len() % u64::from(self.page_granule) != 0
            {
                return Err(Error::Invalid("RAM overlap/alignment"));
            }
            total = total
                .checked_add(region.byte_len())
                .ok_or(Error::Overflow)?;
            previous_end = region.end();
        }
        if total > 1_u64 << 40 {
            return Err(Error::Limit);
        }
        if self.topology.is_empty()
            || self.topology.len() > 255
            || self.cpus.len() != self.topology.len()
            || self.legacy.len() > MAX_LEGACY_DEVICES
        {
            return Err(Error::Invalid("execution topology extent"));
        }
        if self.attachments.len() > 256 {
            return Err(Error::Limit);
        }
        for (index, attachment) in self.attachments.iter().enumerate() {
            if !matches!(attachment.device_type, devices::DeviceType::Virtio(_))
                || attachment.configured_id.is_empty()
                || attachment.configured_id.len() > 256
                || self.attachments[..index].iter().any(|previous| {
                    previous.address >= attachment.address
                        || previous.configured_id == attachment.configured_id
                            && previous.device_type == attachment.device_type
                })
            {
                return Err(Error::Invalid("execution attachment inventory"));
            }
        }
        for (index, (identity, cpu)) in self.topology.iter().zip(&self.cpus).enumerate() {
            cpu.validate()?;
            if usize::from(identity.logical_id) != index
                || cpu.id() != identity.logical_id
                || cpu.lane() != self.lane
                || cpu.architectural_id()? != identity.architectural_id
                || self.topology[..index]
                    .iter()
                    .any(|previous| previous.architectural_id == identity.architectural_id)
            {
                return Err(Error::Invalid("execution CPU identity"));
            }
        }
        match (&self.vm, self.lane) {
            (VmExecutionState::Kvm(state @ kvm::KvmVmState::X86(_)), ExecutionLane::KvmX86)
            | (VmExecutionState::Kvm(state @ kvm::KvmVmState::Arm64(_)), ExecutionLane::KvmArm64) =>
            {
                state
                    .validate()
                    .map_err(|_| Error::Invalid("KVM VM state"))?;
                if let kvm::KvmVmState::Arm64(state) = state {
                    if state.mpidrs.len() != self.topology.len()
                        || state
                            .mpidrs
                            .iter()
                            .zip(&self.topology)
                            .any(|(mpidr, identity)| *mpidr != identity.architectural_id)
                    {
                        return Err(Error::Invalid("VGIC CPU topology"));
                    }
                    for cpu in &self.cpus {
                        let CpuExecutionState::Kvm(kvm::KvmCpuState::Arm64(cpu)) = cpu else {
                            return Err(Error::Invalid("VGIC CPU architecture"));
                        };
                        kvm::validate_arm_cpu_controller(cpu, state)
                            .map_err(|_| Error::Invalid("ARM CPU/controller register binding"))?;
                    }
                }
                if matches!(state, kvm::KvmVmState::X86(_)) {
                    // Match the source CPUID transform's addressable package
                    // slots, including its u8 overflow refusal above 128 CPUs.
                    let cpu_count = u8::try_from(self.cpus.len()).map_err(|_| Error::Limit)?;
                    let package_slots = cpu_count
                        .checked_next_power_of_two()
                        .ok_or(Error::Invalid("x86 package CPU count"))?;
                    let mut rate = None;
                    for cpu in &self.cpus {
                        let CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu)) = cpu else {
                            return Err(Error::Invalid("x86 CPU architecture"));
                        };
                        validate_x86_package_topology(&cpu.cpuid, package_slots, cpu_count > 1)?;
                        if rate.is_some_and(|previous| previous != cpu.tsc_khz) {
                            return Err(Error::Invalid("common TSC frequency"));
                        }
                        rate = Some(cpu.tsc_khz);
                    }
                }
            }
            (VmExecutionState::Hvf(state), ExecutionLane::HvfArm64) => {
                state
                    .clock
                    .validate()
                    .map_err(|_| Error::Invalid("HVF clock"))?;
                state
                    .gic
                    .validate()
                    .map_err(|_| Error::Invalid("HVF GIC"))?;
                if usize::from(state.gic.vcpu_count) != self.topology.len()
                    || self.cpus.iter().any(|cpu| !matches!(cpu, CpuExecutionState::Hvf(cpu) if cpu.frequency == state.clock.frequency)) {
                    return Err(Error::Invalid("HVF controller/counter topology"));
                }
            }
            _ => return Err(Error::Invalid("mixed execution architecture")),
        }
        let mut previous = None;
        for legacy in &self.legacy {
            legacy.payload.validate()?;
            let identity = (legacy.payload.tag(), legacy.address);
            if previous.is_some_and(|value| value >= identity) {
                return Err(Error::Invalid("legacy canonical inventory"));
            }
            previous = Some(identity);
            let x86 = matches!(
                legacy.payload,
                LegacyPayload::Uart(_) | LegacyPayload::Cmos(_) | LegacyPayload::I8042(_)
            );
            if x86 != (self.lane == ExecutionLane::KvmX86) {
                return Err(Error::Invalid("legacy architecture"));
            }
        }
        if self.irq_routes.len() > 512
            || self.irq_routes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.lane == ExecutionLane::HvfArm64 && !self.irq_routes.is_empty()
        {
            return Err(Error::Invalid("native IRQ route inventory"));
        }
        let mut members = 0_usize;
        for (index, route) in self.irq_routes.iter().enumerate() {
            members = members
                .checked_add(route.members.len())
                .ok_or(Error::Overflow)?;
            if route.gsi > 1023
                || route.members.is_empty()
                || members > 512
                || route.members.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(Error::Invalid("native IRQ route members"));
            }
            for member in &route.members {
                if self.irq_routes[..index]
                    .iter()
                    .any(|previous| previous.members.contains(member))
                {
                    return Err(Error::Invalid("duplicate actual IRQ producer"));
                }
                let attached =
                    self.attachments.iter().any(|attachment| {
                        attachment.address == *member && attachment.irq == route.gsi
                    }) || self
                        .legacy
                        .iter()
                        .any(|legacy| legacy.address == *member && legacy.irq == Some(route.gsi));
                let unused_com1 = self.lane == ExecutionLane::KvmX86
                    && route.gsi == 4
                    && *member == 0x3f8
                    && !self.legacy.iter().any(|legacy| legacy.address == *member);
                if !attached && !unused_com1 {
                    return Err(Error::Invalid("unknown IRQ producer"));
                }
            }
        }
        if self.lane != ExecutionLane::HvfArm64 {
            for (address, irq) in self
                .attachments
                .iter()
                .map(|attachment| (attachment.address, attachment.irq))
                .chain(
                    self.legacy
                        .iter()
                        .filter_map(|legacy| legacy.irq.map(|irq| (legacy.address, irq))),
                )
            {
                if !self
                    .irq_routes
                    .iter()
                    .any(|route| route.gsi == irq && route.members.contains(&address))
                {
                    return Err(Error::Invalid("missing actual IRQ producer"));
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut w = Writer::new(MAX_EXECUTION_BYTES);
        w.fixed(MAGIC)?;
        w.u16(1)?;
        w.u32(EXECUTION_ABI)?;
        w.u8(self.lane.tag())?;
        self.binding.encode(&mut w)?;
        w.count(self.topology.len(), 255)?;
        for cpu in &self.topology {
            w.u8(cpu.logical_id)?;
            w.u64(cpu.architectural_id)?;
        }
        w.u32(self.page_granule)?;
        w.count(self.memory_regions.len(), 512)?;
        for region in &self.memory_regions {
            w.u64(region.start())?;
            w.u64(region.byte_len())?;
        }
        w.count(self.attachments.len(), 256)?;
        for attachment in &self.attachments {
            #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
            let devices::DeviceType::Virtio(kind) = attachment.device_type;
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            let kind = match attachment.device_type {
                devices::DeviceType::Virtio(kind) => kind,
                #[cfg(target_arch = "aarch64")]
                devices::DeviceType::Gpio | devices::DeviceType::RTC => {
                    return Err(Error::Invalid("attachment kind"));
                }
                #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
                devices::DeviceType::Serial => return Err(Error::Invalid("attachment kind")),
            };
            w.u32(kind)?;
            w.bytes(attachment.configured_id.as_bytes(), 256)?;
            w.u64(attachment.address)?;
            w.u32(attachment.irq)?;
        }
        w.count(self.irq_routes.len(), 512)?;
        for route in &self.irq_routes {
            w.u32(route.gsi)?;
            w.count(route.members.len(), 512)?;
            for member in &route.members {
                w.u64(*member)?;
            }
        }
        match &self.vm {
            VmExecutionState::Kvm(state) => state.encode(&mut w)?,
            VmExecutionState::Hvf(state) => hvf_codec::encode_vm(state, &mut w)?,
        }
        w.count(self.cpus.len(), 255)?;
        for cpu in &self.cpus {
            match cpu {
                CpuExecutionState::Kvm(state) => state.encode(&mut w)?,
                CpuExecutionState::Hvf(state) => hvf_codec::encode_cpu(state, &mut w)?,
            }
        }
        w.count(self.legacy.len(), MAX_LEGACY_DEVICES)?;
        for legacy in &self.legacy {
            legacy.encode(&mut w)?;
        }
        Ok(w.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_EXECUTION_BYTES {
            return Err(Error::Limit);
        }
        let mut r = Reader::new(bytes);
        if &r.fixed::<8>()? != MAGIC || r.u16()? != 1 || r.u32()? != EXECUTION_ABI {
            return Err(Error::Invalid("execution magic/version/ABI"));
        }
        let lane = ExecutionLane::decode(r.u8()?)?;
        let binding = StateBinding::decode(&mut r)?;
        let count = r.count(255, 9)?;
        let mut topology = Vec::with_capacity(count);
        for _ in 0..count {
            topology.push(CpuIdentity {
                logical_id: r.u8()?,
                architectural_id: r.u64()?,
            });
        }
        let page_granule = r.u32()?;
        let count = r.count(512, 16)?;
        let mut memory_regions = Vec::with_capacity(count);
        for _ in 0..count {
            memory_regions.push(
                GuestRange::new(r.u64()?, r.u64()?).map_err(|_| Error::Invalid("RAM region"))?,
            );
        }
        let count = r.count(256, 20)?;
        let mut attachments = Vec::with_capacity(count);
        for _ in 0..count {
            let device_type = devices::DeviceType::Virtio(r.u32()?);
            let configured_id = std::str::from_utf8(r.bytes(256)?)
                .map_err(|_| Error::Invalid("attachment UTF-8"))?
                .to_owned();
            attachments.push(AttachmentIdentity {
                device_type,
                configured_id,
                address: r.u64()?,
                irq: r.u32()?,
            });
        }
        let count = r.count(512, 8)?;
        let mut irq_routes = Vec::with_capacity(count);
        for _ in 0..count {
            let gsi = r.u32()?;
            let count = r.count(512, 8)?;
            let mut members = Vec::with_capacity(count);
            for _ in 0..count {
                members.push(r.u64()?);
            }
            irq_routes.push(IrqRouteIdentity { gsi, members });
        }
        let vm = match lane {
            ExecutionLane::KvmX86 | ExecutionLane::KvmArm64 => {
                VmExecutionState::Kvm(kvm::KvmVmState::decode(&mut r)?)
            }
            ExecutionLane::HvfArm64 => VmExecutionState::Hvf(hvf_codec::decode_vm(&mut r)?),
        };
        let count = r.count(255, 1)?;
        let mut cpus = Vec::with_capacity(count);
        for _ in 0..count {
            cpus.push(match lane {
                ExecutionLane::KvmX86 | ExecutionLane::KvmArm64 => {
                    CpuExecutionState::Kvm(kvm::KvmCpuState::decode(&mut r)?)
                }
                ExecutionLane::HvfArm64 => CpuExecutionState::Hvf(hvf_codec::decode_cpu(&mut r)?),
            });
        }
        let count = r.count(MAX_LEGACY_DEVICES, 12)?;
        let mut legacy = Vec::with_capacity(count);
        for _ in 0..count {
            legacy.push(LegacyState::decode(&mut r)?);
        }
        r.finish()?;
        let envelope = Self {
            binding,
            lane,
            topology,
            attachments,
            irq_routes,
            page_granule,
            memory_regions,
            vm,
            cpus,
            legacy,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use crate::vmm::execution::*;

    fn registers(ids: &[u16]) -> Vec<hvf::RegisterValue> {
        ids.iter()
            .map(|id| hvf::RegisterValue { id: *id, value: 0 })
            .collect()
    }

    fn envelope() -> ExecutionEnvelope {
        let cpu = hvf::CpuState {
            logical_id: 0,
            mpidr: 0x80000000,
            frequency: 24_000_000,
            model: registers(hvf::MODEL_REGISTERS),
            general: [0; 35],
            simd: [[37; 16]; 32],
            system: registers(hvf::SYSTEM_REGISTERS),
            debug: registers(&hvf::debug_inventory(0)),
            icc: registers(hvf::ICC_REGISTERS),
            timer: hvf::TimerState {
                offset: 19,
                masked: true,
                virtual_compare: 100,
                virtual_control: 1,
                physical_compare: 200,
                physical_control: 0,
            },
            pending_irq: true,
            pending_fiq: false,
            software: hvf::SoftwareState {
                disposition: hvf::CpuDisposition::Waiting,
                pending_irqs: vec![27, 33],
                wake_pending: true,
                cpu_on: None,
            },
        };
        ExecutionEnvelope {
            binding: StateBinding {
                native_producer: "exact-native-test-producer".into(),
                silo_producer: [1; 32],
                profile: [2; 32],
                topology: [3; 32],
                ram_layout: [4; 32],
                source_run: [5; 16],
                pause_generation: 6,
                capture: [7; 16],
            },
            lane: ExecutionLane::HvfArm64,
            topology: vec![CpuIdentity {
                logical_id: 0,
                architectural_id: cpu.mpidr,
            }],
            attachments: Vec::new(),
            irq_routes: Vec::new(),
            page_granule: 4096,
            memory_regions: vec![GuestRange::new(0x40000000, 0x200000).unwrap()],
            vm: VmExecutionState::Hvf(HvfVmState {
                clock: hvf::ClockCut {
                    host_counter: 900,
                    frequency: 24_000_000,
                    timebase_numer: 125,
                    timebase_denom: 3,
                },
                gic: hvf::GicState {
                    vcpu_count: 1,
                    properties: [0x1000, 0x1000, 0x2000, 0x2000],
                    bytes: vec![17, 19, 23],
                },
            }),
            cpus: vec![CpuExecutionState::Hvf(cpu)],
            legacy: Vec::new(),
        }
    }

    #[test]
    fn derived_restore_topology_requires_independent_binding_and_lane() {
        let saved = envelope();
        let expected = saved.binding.clone();
        assert_eq!(
            ValidatedExecution::validate(saved.clone(), &expected, saved.lane)
                .unwrap()
                .envelope(),
            &saved,
        );
        let mut foreign = expected.clone();
        foreign.profile[0] ^= 1;
        assert!(ValidatedExecution::validate(saved.clone(), &foreign, saved.lane).is_err());
        assert!(
            ValidatedExecution::validate(saved.clone(), &expected, ExecutionLane::KvmX86).is_err()
        );
        let mut malformed = saved.clone();
        malformed.topology.clear();
        assert!(ValidatedExecution::validate(malformed, &expected, saved.lane).is_err());
    }

    #[test]
    fn execution_envelope_roundtrip_is_canonical_and_closed() {
        let original = envelope();
        let bytes = original.encode().unwrap();
        let restored = ExecutionEnvelope::decode(&bytes).unwrap();
        assert_eq!(restored, original);
        assert_eq!(restored.encode().unwrap(), bytes);
        let validated = ValidatedExecution::decode(
            &bytes,
            &original.binding,
            original.lane,
            &original.topology,
            &[],
        )
        .unwrap();
        assert_eq!(validated.envelope(), &original);
        for length in 0..bytes.len() {
            assert!(
                ExecutionEnvelope::decode(&bytes[..length]).is_err(),
                "prefix {length}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(ExecutionEnvelope::decode(&trailing), Err(Error::Trailing));
        for offset in [0, 8, 10, 14] {
            let mut unknown = bytes.clone();
            unknown[offset] = 255;
            assert!(ExecutionEnvelope::decode(&unknown).is_err());
        }
        assert_eq!(
            ExecutionEnvelope::decode(&vec![0; MAX_EXECUTION_BYTES + 1]),
            Err(Error::Limit)
        );
    }

    #[test]
    fn execution_envelope_exact_binding_and_topology_are_not_advisory() {
        let original = envelope();
        let bytes = original.encode().unwrap();
        let mut wrong = original.binding.clone();
        wrong.silo_producer[0] ^= 1;
        assert!(
            ValidatedExecution::decode(&bytes, &wrong, original.lane, &original.topology, &[])
                .is_err()
        );
        wrong = original.binding.clone();
        wrong.native_producer.push('x');
        assert!(
            ValidatedExecution::decode(&bytes, &wrong, original.lane, &original.topology, &[])
                .is_err()
        );
        wrong = original.binding.clone();
        wrong.pause_generation += 1;
        assert!(
            ValidatedExecution::decode(&bytes, &wrong, original.lane, &original.topology, &[])
                .is_err()
        );
        for lane in [ExecutionLane::KvmX86, ExecutionLane::KvmArm64] {
            assert!(
                ValidatedExecution::decode(
                    &bytes,
                    &original.binding,
                    lane,
                    &original.topology,
                    &[]
                )
                .is_err()
            );
        }
        assert!(
            ValidatedExecution::decode(&bytes, &original.binding, original.lane, &[], &[]).is_err()
        );
        let mut mixed = original.clone();
        mixed.lane = ExecutionLane::KvmArm64;
        assert!(mixed.encode().is_err());
        let mut duplicate = original.clone();
        duplicate.topology.push(duplicate.topology[0].clone());
        duplicate.cpus.push(duplicate.cpus[0].clone());
        assert!(duplicate.encode().is_err());
        let mut wrong_affinity = original;
        wrong_affinity.topology[0].architectural_id ^= 1;
        assert!(wrong_affinity.encode().is_err());
    }

    #[test]
    fn execution_envelope_refuses_missing_and_duplicate_legacy_or_attachment_identity() {
        let mut original = envelope();
        original.legacy.push(LegacyState {
            address: 0x9000000,
            irq: Some(34),
            payload: LegacyPayload::Rtc(devices::legacy::state::RtcState {
                guest_nanoseconds: 100,
                match_value: 12,
                load: 0,
                interrupt_mask: 1,
                interrupt_status: 1,
            }),
        });
        let bytes = original.encode().unwrap();
        assert!(
            ValidatedExecution::decode(
                &bytes,
                &original.binding,
                original.lane,
                &original.topology,
                &[]
            )
            .is_err()
        );
        assert!(
            ValidatedExecution::decode(
                &bytes,
                &original.binding,
                original.lane,
                &original.topology,
                &[(5, 0x9000000, Some(34))]
            )
            .is_ok()
        );
        original.legacy.push(original.legacy[0].clone());
        assert!(original.encode().is_err());
        original.legacy.clear();
        let attachment = AttachmentIdentity {
            device_type: devices::DeviceType::Virtio(4),
            configured_id: "rng0".into(),
            address: 0x10000000,
            irq: 35,
        };
        original.attachments = vec![attachment.clone(), attachment];
        assert!(original.encode().is_err());
    }
    #[test]
    fn execution_envelope_refuses_overlapping_ram_and_foreign_native_route_data() {
        let mut state = envelope();
        state
            .memory_regions
            .push(GuestRange::new(0x40001000, 4096).unwrap());
        assert!(state.encode().is_err());
        let mut state = envelope();
        state.page_granule = 3;
        assert!(state.encode().is_err());
        let mut state = envelope();
        state.irq_routes.push(IrqRouteIdentity {
            gsi: 35,
            members: vec![0x10000000],
        });
        assert!(state.encode().is_err());
        let mut state = envelope();
        let memory =
            GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0x40000000), 0x200000)])
                .unwrap();
        state.page_granule = host_page_granule().unwrap();
        state.validate_memory(&memory).unwrap();
        let wrong =
            GuestMemoryMmap::from_ranges(&[(vm_memory::GuestAddress(0x40000000), 0x100000)])
                .unwrap();
        assert!(state.validate_memory(&wrong).is_err());
    }

    #[test]
    fn execution_envelope_x86_cpuid_package_topology_is_exact() {
        for (count, slots, multiple) in [(1u8, 1u8, false), (2, 2, true), (3, 4, true)] {
            assert_eq!(count.checked_next_power_of_two(), Some(slots));
            let leaf = kvm::CpuidEntry {
                function: 1,
                index: 0,
                flags: 0,
                values: [0, u32::from(slots) << 16, 0, u32::from(multiple) << 28],
            };
            assert!(
                validate_x86_package_topology(std::slice::from_ref(&leaf), slots, count > 1,)
                    .is_ok()
            );
            let mut wrong_slots = leaf.clone();
            wrong_slots.values[1] ^= 1 << 16;
            assert!(validate_x86_package_topology(&[wrong_slots], slots, multiple).is_err());
            let mut wrong_htt = leaf;
            wrong_htt.values[3] ^= 1 << 28;
            assert!(validate_x86_package_topology(&[wrong_htt], slots, multiple).is_err());
        }
        assert!(validate_x86_package_topology(&[], 1, false).is_err());
        assert!(129u8.checked_next_power_of_two().is_none());
    }
}
