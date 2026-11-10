//! Closed KVM execution records. These are wire values, never native ABI struct images.
use arch::x86_state::CpuFeatures;
use devices::legacy::kvm_state::{GicRegister, validate_gic};
use utils::state::{Error, Reader, Writer};

pub const MAX_MSRS: usize = 4096;
pub const MAX_ONE_REGS: usize = 4096;
pub const MAX_XSAVE: usize = 65536;
pub const MAX_CPUID: usize = 256;
const KVM_CPU_STATE_MAGIC: &[u8; 8] = b"KRUNKCPU";
const KVM_CPU_STATE_SCHEMA: u16 = 1;
const KVM_VM_STATE_MAGIC: &[u8; 8] = b"KRUNKVMS";
const KVM_VM_STATE_SCHEMA: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuidEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub values: [u32; 4],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsrValue {
    pub index: u32,
    pub value: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsrDescriptor {
    pub index: u32,
    pub class: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XstateComponent {
    pub id: u32,
    pub size: u32,
    pub offset: u32,
    pub flags: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub attributes: [u8; 9],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X86Special {
    pub segments: [Segment; 8],
    pub gdt: (u64, u16),
    pub idt: (u64, u16),
    // CR0, CR2, CR3, CR4, CR8, EFER, APICBASE, SREGS2 flags, PDPTR0..3.
    pub values: [u64; 12],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X86CpuState {
    pub id: u8,
    pub cpuid: Vec<CpuidEntry>,
    pub inventory: Vec<MsrDescriptor>,
    pub msrs: Vec<MsrValue>,
    pub model_msrs: Vec<MsrValue>,
    pub mce_cap: u64,
    pub xstate: Vec<XstateComponent>,
    pub xsave: Vec<u8>,
    pub xcrs: Vec<MsrValue>,
    // RAX,RBX,RCX,RDX,RSI,RDI,RSP,RBP,R8..15,RIP,RFLAGS.
    pub regs: [u64; 18],
    pub special: X86Special,
    // DR0..3, DR6, DR7, flags.
    pub debug: [u64; 7],
    pub lapic: Vec<u8>,
    // Exception/intr/NMI/SIPI/SMM/triple-fault validity and payload, without ABI padding.
    pub events: [u64; 24],
    pub mp_state: u32,
    pub tsc_offset: u64,
    pub tsc_khz: u32,
    pub tsc_observed: u64,
    pub deadline: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneReg {
    pub id: u64,
    pub class: u8,
    pub value: Vec<u8>,
}
/// The VM-wide KVM offset API binds both counter views to this one guest epoch.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmCounterModel {
    CommonPhysicalVirtual = 1,
}

impl ArmCounterModel {
    pub fn offset_for(self, host_counter: u64, guest_counter: u64) -> u64 {
        match self {
            Self::CommonPhysicalVirtual => host_counter.wrapping_sub(guest_counter),
        }
    }
}

/// Sequential native reads, not a claim that separately sampled counters are equal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmCounterObservation {
    pub physical_before: u64,
    pub virtual_counter: u64,
    pub physical_after: u64,
}

impl ArmCounterObservation {
    pub fn validate(&self) -> Result<(), String> {
        let elapsed = self.physical_after.wrapping_sub(self.physical_before);
        if elapsed >= (1 << 63) || self.virtual_counter.wrapping_sub(self.physical_before) > elapsed
        {
            return Err("kvm/arm64/counter-views-outside-common-epoch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmCpuState {
    pub id: u8,
    pub target: u32,
    pub features: [u32; 7],
    pub mpidr: u64,
    pub counter_observation: ArmCounterObservation,
    pub registers: Vec<OneReg>,
    pub mp_state: u32,
    pub timer_irqs: [u32; 2],
    // serror_pending, serror_has_esr, ext_dabt_pending, serror_esr.
    pub events: [u64; 4],
}
// Owner messages already retain this bounded record in an Arc; boxing would add a second allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KvmCpuState {
    X86(X86CpuState),
    Arm64(ArmCpuState),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PitChannel {
    pub count: u32,
    pub latched_count: u16,
    pub bytes: [u8; 10],
    pub count_load_time: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X86VmState {
    pub clock: u64,
    pub clock_flags: u32,
    pub host_tsc: u64,
    pub realtime: u64,
    pub host_kernel: String,
    pub host_mode: u8,
    pub pit: [PitChannel; 3],
    pub pit_flags: u32,
    // 0=reset, 1=qualified retired Linux PIT.
    pub pit_profile: u8,
    pub pic: [[u8; 16]; 2],
    pub ioapic_base: u64,
    pub ioapic_select: u32,
    pub ioapic_id: u32,
    pub ioapic_irr: u32,
    pub ioapic_routes: [u64; 24],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmVmState {
    pub counter_model: ArmCounterModel,
    pub counter: u64,
    pub frequency: u64,
    pub properties: [u64; 4],
    pub irq_count: u32,
    pub mpidrs: Vec<u64>,
    pub registers: Vec<GicRegister>,
}
// One retained VM cut owns these bounded controller fields; keep them inline without another allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KvmVmState {
    X86(X86VmState),
    Arm64(ArmVmState),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KvmCpuTimePlan {
    X86 { id: u8, offset: u64, tsc_khz: u32 },
    Arm64 { id: u8, counter_offset: u64 },
}

fn arm_icc_alias(id: u64) -> bool {
    id & 0xffffffffffff0000 == 0x6030000000130000
        && matches!(id&0xffff,0xc230|0xc643..=0xc64b|0xc663..=0xc667)
}

pub fn validate_arm_cpu_controller(cpu: &ArmCpuState, vm: &ArmVmState) -> Result<(), String> {
    if !vm.mpidrs.contains(&cpu.mpidr) {
        return Err("kvm/arm64/controller-affinity".into());
    }
    cpu.counter_observation.validate()?;
    if vm.mpidrs.first() == Some(&cpu.mpidr)
        && vm.counter != cpu.counter_observation.virtual_counter
    {
        return Err("kvm/arm64/common-counter-cut".into());
    }
    for r in &cpu.registers {
        if r.id == 0x603000000013df00 {
            let value = u64::from_le_bytes(
                r.value
                    .as_slice()
                    .try_into()
                    .map_err(|_| "kvm/arm64/frequency-width")?,
            );
            if value != vm.frequency {
                return Err("kvm/arm64/controller-frequency".into());
            }
        }
        if arm_icc_alias(r.id) {
            let attr = devices::legacy::kvm_state::affinity(cpu.mpidr) | (r.id & 0xffff);
            let canonical = vm
                .registers
                .iter()
                .find(|g| g.group == 6 && g.attr == attr)
                .ok_or("kvm/arm64/icc-canonical-missing")?;
            let value = u64::from_le_bytes(
                r.value
                    .as_slice()
                    .try_into()
                    .map_err(|_| "kvm/arm64/icc-width")?,
            );
            if canonical.value != value {
                return Err("kvm/arm64/icc-alias-disagreement".into());
            }
        }
    }
    Ok(())
}

pub fn arm_register_class(id: u64) -> Result<u8, String> {
    if id >> 56 != 0x60 {
        return Err(format!("kvm/arm64/register/{id:#x}/architecture"));
    }
    if arm_icc_alias(id) {
        return Ok(2);
    }
    let coprocessor = (id >> 16) & 0xffff;
    match coprocessor {
        0x10 => return Ok(0),
        0x11 | 0x14 | 0x16 => return Ok(1),
        0x13 => (),
        _ => return Err(format!("kvm/arm64/register/{id:#x}/unsupported-family")),
    }
    match id {
        0x603000000013df1a | 0x603000000013df01 => return Ok(2),
        0x603000000013df02 | 0x603000000013df19 | 0x603000000013df12 | 0x603000000013df11 => {
            return Ok(3);
        }
        0x603000000013df00 => return Ok(1),
        _ => (),
    }
    let encoding = id & 0xffff;
    let crn = (encoding >> 7) & 15;
    let op0 = (encoding >> 14) & 3;
    let op1 = (encoding >> 11) & 7;
    let crm = (encoding >> 3) & 15;
    if op0 == 3 && op1 == 0 && crn == 0 {
        return Ok(1);
    }
    if (op0 == 2 && op1 == 0 && crn <= 1)
        || (op0 == 3 && op1 == 0 && matches!(crn, 1 | 2 | 4 | 5 | 6 | 7 | 9 | 10 | 12 | 13 | 14))
        || (op0 == 3 && op1 == 3 && matches!(crn, 9 | 13 | 14))
        || (op0 == 3 && op1 == 1 && crn == 0 && crm == 0)
        || id == 0x603000000013d000
    {
        return Ok(0);
    }
    Err(format!("kvm/arm64/register/{id:#x}/unknown-exposed-state"))
}

fn ordered<T>(entries: &[T], key: impl Fn(&T) -> u64) -> bool {
    entries.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}
impl KvmCpuState {
    pub fn id(&self) -> u8 {
        match self {
            Self::X86(s) => s.id,
            Self::Arm64(s) => s.id,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::X86(s) => {
                if s.cpuid.is_empty()
                    || s.cpuid.len() > MAX_CPUID
                    || !ordered(&s.cpuid, |e| {
                        (u64::from(e.function) << 32) | u64::from(e.index)
                    })
                {
                    return Err("kvm/cpuid/inventory".into());
                }
                let lookup = |function, index| {
                    s.cpuid
                        .iter()
                        .find(|e| e.function == function && e.index == index)
                        .map(|e| e.values)
                };
                let root = lookup(0, 0).ok_or("kvm/cpuid/root-missing")?;
                if !((root[1] == 0x68747541 && root[3] == 0x69746e65 && root[2] == 0x444d4163)
                    || (root[1] == 0x756e6547 && root[3] == 0x49656e69 && root[2] == 0x6c65746e))
                {
                    return Err("kvm/cpuid/vendor-unqualified".into());
                }
                if lookup(1, 0).is_none() || s.cpuid.iter().any(|e| e.flags & !7 != 0) {
                    return Err("kvm/cpuid/missing-model-or-unknown-flags".into());
                }
                if s.inventory.len() > MAX_MSRS
                    || !ordered(&s.inventory, |e| u64::from(e.index))
                    || s.inventory.iter().any(|e| e.class > 4)
                    || s.msrs.len() > MAX_MSRS
                    || !ordered(&s.msrs, |e| u64::from(e.index))
                {
                    return Err("kvm/msr/inventory".into());
                }
                CpuFeatures::from_cpuid(lookup)
                    .validate_inventory(s.inventory.iter().map(|e| (e.index, e.class)))
                    .map_err(|index| {
                        format!("kvm/msr/{index:#x}/missing-unknown-or-misclassified-exposed-state")
                    })?;
                if s.msrs.iter().any(|e| {
                    matches!(e.index, 0x10 | 0x1b | 0x6e0 | 0xc0000080)
                        || (0x800..=0xbff).contains(&e.index)
                }) {
                    return Err("kvm/msr/canonical-owner".into());
                }
                let mut required: Vec<u32> = s
                    .inventory
                    .iter()
                    .filter(|e| e.class == 0)
                    .map(|e| e.index)
                    .collect();
                let banks = (s.mce_cap & 255) as u32;
                if banks > 32 {
                    return Err("kvm/mce/bank-count".into());
                }
                if s.mce_cap & (1 << 9) != 0 || s.mce_cap & (255 << 16) != 0 {
                    return Err("kvm/mce/extended-register-file-unqualified".into());
                }
                required.push(0x17a);
                if s.mce_cap & (1 << 8) != 0 {
                    required.push(0x17b);
                }
                if s.mce_cap & (1 << 27) != 0 {
                    required.push(0x4d0);
                }
                for bank in 0..banks {
                    for field in 0..4 {
                        required.push(0x400 + 4 * bank + field);
                    }
                    if s.mce_cap & (1 << 10) != 0 {
                        required.push(0x280 + bank);
                    }
                }
                required.sort_unstable();
                required.dedup();
                if !required.into_iter().eq(s.msrs.iter().map(|e| e.index)) {
                    return Err("kvm/msr/missing-or-extra-values".into());
                }
                if s.model_msrs.len() > MAX_MSRS
                    || !ordered(&s.model_msrs, |e| u64::from(e.index))
                    || !s
                        .inventory
                        .iter()
                        .filter(|e| e.class == 1)
                        .map(|e| e.index)
                        .eq(s.model_msrs.iter().map(|e| e.index))
                {
                    return Err("kvm/msr/model-inventory".into());
                }
                if s.xsave.len() < 4096
                    || s.xsave.len() > MAX_XSAVE
                    || s.xsave.len() % 4 != 0
                    || s.xstate.len() > 64
                    || !ordered(&s.xstate, |e| u64::from(e.id))
                {
                    return Err("kvm/xsave/extent-layout".into());
                }
                for c in &s.xstate {
                    if c.id > 63
                        || c.size == 0
                        || c.flags & !7 != 0
                        || (c.flags & 1 == 0
                            && c.offset
                                .checked_add(c.size)
                                .is_none_or(|end| end as usize > s.xsave.len()))
                    {
                        return Err("kvm/xsave/component".into());
                    }
                }
                if s.xcrs.len() > 16
                    || !ordered(&s.xcrs, |e| u64::from(e.index))
                    || s.lapic.len() != 1024
                    || s.tsc_khz == 0
                    || s.special.values[7] & !1 != 0
                    || s.debug[6] != 0
                    || !matches!(s.mp_state, 0..=4 | 9 | 10)
                {
                    return Err("kvm/x86/adjunct".into());
                }
                if s.cpuid.iter().any(|e| {
                    e.function == 0xd
                        && ((e.index == 0 && (e.values[0] & !7 != 0 || e.values[3] != 0))
                            || (e.index == 1 && (e.values[2] != 0 || e.values[3] != 0)))
                }) {
                    return Err("kvm/xsave/expanded-guest-components-unqualified".into());
                }
                let xcr0 = s
                    .xcrs
                    .iter()
                    .find(|e| e.index == 0)
                    .ok_or("kvm/xcr0/missing")?
                    .value;
                if xcr0 & !7 != 0 || xcr0 & 1 == 0 || (xcr0 & 4 != 0 && xcr0 & 2 == 0) {
                    return Err("kvm/xcr0/component-consistency".into());
                }
                let exposure = lookup(0xd, 0).ok_or("kvm/xsave/cpuid-missing")?[0];
                if xcr0 & !u64::from(exposure) != 0 {
                    return Err("kvm/xcr0/unsupported-component".into());
                }
                if exposure & 4 != 0 {
                    let guest = lookup(0xd, 2).ok_or("kvm/xsave/ymm-layout-missing")?;
                    let host = s
                        .xstate
                        .iter()
                        .find(|c| c.id == 2)
                        .ok_or("kvm/xsave/host-ymm-layout-missing")?;
                    if guest[0] != host.size || guest[1] != host.offset {
                        return Err("kvm/xsave/component-layout-mismatch".into());
                    }
                }
                let header = s.xsave.get(512..528).ok_or("kvm/xsave/header")?;
                let active =
                    u64::from_le_bytes(header[..8].try_into().map_err(|_| "kvm/xsave/header")?);
                let compact =
                    u64::from_le_bytes(header[8..].try_into().map_err(|_| "kvm/xsave/header")?);
                if active & !xcr0 != 0 || compact != 0 {
                    return Err("kvm/xsave/xcr0-header-consistency".into());
                }
                for index in [0, 2, 3, 5, 7, 9, 10, 11, 14, 15, 16, 17, 18, 19] {
                    if s.events[index] > 1 {
                        return Err("kvm/events/boolean".into());
                    }
                }
                if s.events[1] > 31
                    || s.events[4] > u64::from(u32::MAX)
                    || s.events[6] > 255
                    || s.events[8] > 3
                    || s.events[12] > 255
                    || s.events[13] & !63 != 0
                    || s.events[21..].iter().any(|v| *v != 0)
                {
                    return Err("kvm/events/flags-width".into());
                }
                for segment in &s.special.segments {
                    let a = segment.attributes;
                    if a[0] > 15 || a[2] > 3 || [1, 3, 4, 5, 6, 7, 8].iter().any(|i| a[*i] > 1) {
                        return Err("kvm/segment/attributes".into());
                    }
                }
                let mode = lapic_u32(&s.lapic, 0x320)? & (3 << 17);
                if mode != (2 << 17)
                    && (s.deadline != 0
                        || lapic_u32(&s.lapic, 0x380)? != 0
                        || lapic_u32(&s.lapic, 0x390)? != 0)
                {
                    return Err(format!("lapic/{}/unqualified-count-mode", s.id));
                }
                if mode == (3 << 17) {
                    return Err("lapic/reserved-mode".into());
                }
            }
            Self::Arm64(s) => {
                s.counter_observation.validate()?;
                if s.features[0] & !0x65 != 0 || s.features[1..].iter().any(|v| *v != 0) {
                    return Err("kvm/arm64/init-feature-unqualified".into());
                }
                if s.registers.is_empty()
                    || s.registers.len() > MAX_ONE_REGS
                    || !ordered(&s.registers, |r| r.id)
                {
                    return Err("kvm/arm64/register-inventory".into());
                }
                for r in &s.registers {
                    let width = 1usize
                        .checked_shl(((r.id >> 52) & 15) as u32)
                        .ok_or("kvm/arm64/register-width")?;
                    if width > 16 || width != r.value.len() || r.class > 3 {
                        return Err("kvm/arm64/register-width-class".into());
                    }
                    if arm_register_class(r.id)? != r.class {
                        return Err("kvm/arm64/register-class".into());
                    }
                    if r.id == 0x603000000013c021 {
                        let value = u64::from_le_bytes(
                            r.value
                                .as_slice()
                                .try_into()
                                .map_err(|_| "kvm/arm64/id-width")?,
                        );
                        if value & (15 << 24) != 0 {
                            return Err("kvm/arm64/sme-unqualified".into());
                        }
                    }
                }
                if s.mp_state != 0 && s.mp_state != 5 {
                    return Err("kvm/arm64/mp-state".into());
                }
                if s.events[..3].iter().any(|v| *v > 1)
                    || s.timer_irqs.iter().any(|irq| !(16..32).contains(irq))
                    || s.timer_irqs[0] == s.timer_irqs[1]
                {
                    return Err("kvm/arm64/event-or-timer-irq".into());
                }
            }
        }
        Ok(())
    }
    pub fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        self.validate()
            .map_err(|_| Error::Invalid("kvm/cpu/state"))?;
        w.header(KVM_CPU_STATE_MAGIC, KVM_CPU_STATE_SCHEMA)?;
        match self {
            Self::X86(s) => {
                w.u8(1)?;
                w.u8(s.id)?;
                w.u32(s.cpuid.len() as u32)?;
                for e in &s.cpuid {
                    w.u32(e.function)?;
                    w.u32(e.index)?;
                    w.u32(e.flags)?;
                    for v in e.values {
                        w.u32(v)?;
                    }
                }
                w.u32(s.inventory.len() as u32)?;
                for e in &s.inventory {
                    w.u32(e.index)?;
                    w.u8(e.class)?;
                }
                put_msrs(w, &s.msrs)?;
                put_msrs(w, &s.model_msrs)?;
                w.u64(s.mce_cap)?;
                w.u32(s.xstate.len() as u32)?;
                for e in &s.xstate {
                    w.u32(e.id)?;
                    w.u32(e.size)?;
                    w.u32(e.offset)?;
                    w.u32(e.flags)?;
                }
                w.bytes(&s.xsave, MAX_XSAVE)?;
                put_msrs(w, &s.xcrs)?;
                for v in s.regs {
                    w.u64(v)?;
                }
                for e in &s.special.segments {
                    w.u64(e.base)?;
                    w.u32(e.limit)?;
                    w.u16(e.selector)?;
                    for v in e.attributes {
                        w.u8(v)?;
                    }
                }
                for (base, limit) in [s.special.gdt, s.special.idt] {
                    w.u64(base)?;
                    w.u16(limit)?;
                }
                for v in s.special.values {
                    w.u64(v)?;
                }
                for v in s.debug {
                    w.u64(v)?;
                }
                w.bytes(&s.lapic, 1024)?;
                for v in s.events {
                    w.u64(v)?;
                }
                w.u32(s.mp_state)?;
                w.u64(s.tsc_offset)?;
                w.u32(s.tsc_khz)?;
                w.u64(s.tsc_observed)?;
                w.u64(s.deadline)?;
            }
            Self::Arm64(s) => {
                w.u8(2)?;
                w.u8(s.id)?;
                w.u32(s.target)?;
                for v in s.features {
                    w.u32(v)?;
                }
                w.u64(s.mpidr)?;
                w.u64(s.counter_observation.physical_before)?;
                w.u64(s.counter_observation.virtual_counter)?;
                w.u64(s.counter_observation.physical_after)?;
                w.u32(s.registers.len() as u32)?;
                for r in &s.registers {
                    w.u64(r.id)?;
                    w.u8(r.class)?;
                    w.bytes(&r.value, 16)?;
                }
                w.u32(s.mp_state)?;
                for irq in s.timer_irqs {
                    w.u32(irq)?;
                }
                for v in s.events {
                    w.u64(v)?;
                }
            }
        }
        Ok(())
    }
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        r.header(KVM_CPU_STATE_MAGIC, KVM_CPU_STATE_SCHEMA)?;
        let tag = r.u8()?;
        let id = r.u8()?;
        let state = match tag {
            1 => {
                let mut cpuid = Vec::new();
                for _ in 0..count(r, MAX_CPUID)? {
                    cpuid.push(CpuidEntry {
                        function: r.u32()?,
                        index: r.u32()?,
                        flags: r.u32()?,
                        values: [r.u32()?, r.u32()?, r.u32()?, r.u32()?],
                    });
                }
                let mut inventory = Vec::new();
                for _ in 0..count(r, MAX_MSRS)? {
                    inventory.push(MsrDescriptor {
                        index: r.u32()?,
                        class: r.u8()?,
                    });
                }
                let msrs = get_msrs(r, MAX_MSRS)?;
                let model_msrs = get_msrs(r, MAX_MSRS)?;
                let mce_cap = r.u64()?;
                let mut xstate = Vec::new();
                for _ in 0..count(r, 64)? {
                    xstate.push(XstateComponent {
                        id: r.u32()?,
                        size: r.u32()?,
                        offset: r.u32()?,
                        flags: r.u32()?,
                    });
                }
                let xsave = r.bytes(MAX_XSAVE)?.to_vec();
                let xcrs = get_msrs(r, 16)?;
                let mut regs = [0; 18];
                for v in &mut regs {
                    *v = r.u64()?;
                }
                let mut segments = std::array::from_fn(|_| Segment {
                    base: 0,
                    limit: 0,
                    selector: 0,
                    attributes: [0; 9],
                });
                for e in &mut segments {
                    e.base = r.u64()?;
                    e.limit = r.u32()?;
                    e.selector = r.u16()?;
                    for v in &mut e.attributes {
                        *v = r.u8()?;
                    }
                }
                let gdt = (r.u64()?, r.u16()?);
                let idt = (r.u64()?, r.u16()?);
                let mut values = [0; 12];
                for v in &mut values {
                    *v = r.u64()?;
                }
                let mut debug = [0; 7];
                for v in &mut debug {
                    *v = r.u64()?;
                }
                let lapic = r.bytes(1024)?.to_vec();
                let mut events = [0; 24];
                for v in &mut events {
                    *v = r.u64()?;
                }
                Self::X86(X86CpuState {
                    id,
                    cpuid,
                    inventory,
                    msrs,
                    model_msrs,
                    mce_cap,
                    xstate,
                    xsave,
                    xcrs,
                    regs,
                    special: X86Special {
                        segments,
                        gdt,
                        idt,
                        values,
                    },
                    debug,
                    lapic,
                    events,
                    mp_state: r.u32()?,
                    tsc_offset: r.u64()?,
                    tsc_khz: r.u32()?,
                    tsc_observed: r.u64()?,
                    deadline: r.u64()?,
                })
            }
            2 => {
                let target = r.u32()?;
                let mut features = [0; 7];
                for v in &mut features {
                    *v = r.u32()?;
                }
                let mpidr = r.u64()?;
                let counter_observation = ArmCounterObservation {
                    physical_before: r.u64()?,
                    virtual_counter: r.u64()?,
                    physical_after: r.u64()?,
                };
                let mut registers = Vec::new();
                for _ in 0..count(r, MAX_ONE_REGS)? {
                    registers.push(OneReg {
                        id: r.u64()?,
                        class: r.u8()?,
                        value: r.bytes(16)?.to_vec(),
                    });
                }
                let mp_state = r.u32()?;
                let timer_irqs = [r.u32()?, r.u32()?];
                let mut events = [0; 4];
                for v in &mut events {
                    *v = r.u64()?;
                }
                Self::Arm64(ArmCpuState {
                    id,
                    target,
                    features,
                    mpidr,
                    counter_observation,
                    registers,
                    mp_state,
                    timer_irqs,
                    events,
                })
            }
            _ => return Err(Error::Invalid("kvm/cpu/tag")),
        };
        state
            .validate()
            .map_err(|_| Error::Invalid("kvm/cpu/state"))?;
        Ok(state)
    }
}
fn count(r: &mut Reader<'_>, limit: usize) -> Result<usize, Error> {
    r.count(limit, 1)
}
fn put_msrs(w: &mut Writer, entries: &[MsrValue]) -> Result<(), Error> {
    w.u32(entries.len() as u32)?;
    for e in entries {
        w.u32(e.index)?;
        w.u64(e.value)?;
    }
    Ok(())
}
fn get_msrs(r: &mut Reader<'_>, limit: usize) -> Result<Vec<MsrValue>, Error> {
    let mut v = Vec::new();
    for _ in 0..count(r, limit)? {
        v.push(MsrValue {
            index: r.u32()?,
            value: r.u64()?,
        });
    }
    Ok(v)
}
pub fn lapic_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or("lapic/extent")?;
    let value = bytes.get(offset..end).ok_or("lapic/extent")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

impl KvmVmState {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::X86(s) => {
                if s.host_kernel.is_empty() || s.host_kernel.len() > 256 || s.host_mode > 1 {
                    return Err("kvm/clock/host-semantics-profile".into());
                }
                if s.pit_profile > 1 || s.clock_flags & 10 != 10 || s.clock_flags & !15 != 0 {
                    return Err("kvm/clock/unstable-unpaired-or-unknown-flags".into());
                }
                if s.pit_flags & !1 != 0 {
                    return Err("pit/speaker-or-unknown-flags".into());
                }
                if s.pit_profile == 0 && s.pit.iter().any(|c| c.bytes[7] != 255) {
                    return Err("pit/reset/programmed-channel".into());
                }
                if s.pit_profile == 1 {
                    if s.pic[0][2] & 1 == 0 || s.ioapic_routes[0] & (1 << 16) == 0 {
                        return Err("pit/0/unmasked-route".into());
                    }
                    for (i, c) in s.pit.iter().enumerate() {
                        if c.count > 65536
                            || c.bytes[0] != 0
                            || c.bytes[1] != 0
                            || c.bytes[3] == 4
                            || c.bytes[4] == 4
                        {
                            return Err(format!("pit/{i}/partial-programming-or-latched-read"));
                        }
                        if i == 0 && !((c.bytes[7] == 0 && c.count == 65536) || c.bytes[7] == 255) {
                            return Err("pit/0/unqualified-retired-shape".into());
                        }
                        if i == 2 && c.bytes[9] != 0 && c.bytes[7] != 255 {
                            return Err("pit/2/active-speaker-counter".into());
                        }
                    }
                }
            }
            Self::Arm64(s) => {
                if s.frequency == 0 {
                    return Err("kvm/arm64/zero-frequency".into());
                }
                validate_gic(s.properties, s.irq_count, &s.mpidrs, &s.registers)?;
            }
        }
        Ok(())
    }
    pub fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        self.validate()
            .map_err(|_| Error::Invalid("kvm/vm/state"))?;
        w.header(KVM_VM_STATE_MAGIC, KVM_VM_STATE_SCHEMA)?;
        match self {
            Self::X86(s) => {
                w.u8(1)?;
                w.u64(s.clock)?;
                w.u32(s.clock_flags)?;
                w.u64(s.host_tsc)?;
                w.u64(s.realtime)?;
                w.bytes(s.host_kernel.as_bytes(), 256)?;
                w.u8(s.host_mode)?;
                for c in &s.pit {
                    w.u32(c.count)?;
                    w.u16(c.latched_count)?;
                    for v in c.bytes {
                        w.u8(v)?;
                    }
                    w.u64(c.count_load_time)?;
                }
                w.u32(s.pit_flags)?;
                w.u8(s.pit_profile)?;
                for p in s.pic {
                    for b in p {
                        w.u8(b)?;
                    }
                }
                w.u64(s.ioapic_base)?;
                w.u32(s.ioapic_select)?;
                w.u32(s.ioapic_id)?;
                w.u32(s.ioapic_irr)?;
                for v in s.ioapic_routes {
                    w.u64(v)?;
                }
            }
            Self::Arm64(s) => {
                w.u8(2)?;
                w.u8(s.counter_model as u8)?;
                w.u64(s.counter)?;
                w.u64(s.frequency)?;
                for v in s.properties {
                    w.u64(v)?;
                }
                w.u32(s.irq_count)?;
                w.u32(s.mpidrs.len() as u32)?;
                for v in &s.mpidrs {
                    w.u64(*v)?;
                }
                w.u32(s.registers.len() as u32)?;
                for v in &s.registers {
                    w.u32(v.group)?;
                    w.u64(v.attr)?;
                    w.u64(v.value)?;
                    w.u8(v.width)?;
                }
            }
        }
        Ok(())
    }
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        r.header(KVM_VM_STATE_MAGIC, KVM_VM_STATE_SCHEMA)?;
        let state = match r.u8()? {
            1 => {
                let clock = r.u64()?;
                let clock_flags = r.u32()?;
                let host_tsc = r.u64()?;
                let realtime = r.u64()?;
                let host_kernel = std::str::from_utf8(r.bytes(256)?)
                    .map_err(|_| Error::Invalid("kvm/clock/kernel-utf8"))?
                    .to_owned();
                let host_mode = r.u8()?;
                let mut pit = std::array::from_fn(|_| PitChannel {
                    count: 0,
                    latched_count: 0,
                    bytes: [0; 10],
                    count_load_time: 0,
                });
                for c in &mut pit {
                    c.count = r.u32()?;
                    c.latched_count = r.u16()?;
                    for b in &mut c.bytes {
                        *b = r.u8()?;
                    }
                    c.count_load_time = r.u64()?;
                }
                let pit_flags = r.u32()?;
                let pit_profile = r.u8()?;
                let mut pic = [[0; 16]; 2];
                for p in &mut pic {
                    for b in p {
                        *b = r.u8()?;
                    }
                }
                let ioapic_base = r.u64()?;
                let ioapic_select = r.u32()?;
                let ioapic_id = r.u32()?;
                let ioapic_irr = r.u32()?;
                let mut ioapic_routes = [0; 24];
                for v in &mut ioapic_routes {
                    *v = r.u64()?;
                }
                Self::X86(X86VmState {
                    clock,
                    clock_flags,
                    host_tsc,
                    realtime,
                    host_kernel,
                    host_mode,
                    pit,
                    pit_flags,
                    pit_profile,
                    pic,
                    ioapic_base,
                    ioapic_select,
                    ioapic_id,
                    ioapic_irr,
                    ioapic_routes,
                })
            }
            2 => {
                let counter_model = match r.u8()? {
                    1 => ArmCounterModel::CommonPhysicalVirtual,
                    _ => return Err(Error::Invalid("kvm/arm64/counter-model")),
                };
                let counter = r.u64()?;
                let frequency = r.u64()?;
                let mut properties = [0; 4];
                for v in &mut properties {
                    *v = r.u64()?;
                }
                let irq_count = r.u32()?;
                let mut mpidrs = Vec::new();
                for _ in 0..count(r, 255)? {
                    mpidrs.push(r.u64()?);
                }
                let mut registers = Vec::new();
                for _ in 0..count(r, 32768)? {
                    registers.push(GicRegister {
                        group: r.u32()?,
                        attr: r.u64()?,
                        value: r.u64()?,
                        width: r.u8()?,
                    });
                }
                Self::Arm64(ArmVmState {
                    counter_model,
                    counter,
                    frequency,
                    properties,
                    irq_count,
                    mpidrs,
                    registers,
                })
            }
            _ => return Err(Error::Invalid("kvm/vm/tag")),
        };
        state
            .validate()
            .map_err(|_| Error::Invalid("kvm/vm/state"))?;
        Ok(state)
    }
}

pub fn common_tsc_offset(
    source_clock: u64,
    source_host: u64,
    source_offset: u64,
    destination_clock: u64,
    destination_host: u64,
    khz: u32,
) -> Result<u64, String> {
    if khz == 0 {
        return Err("kvm/clock/zero-rate".into());
    }
    let elapsed = destination_clock
        .checked_sub(source_clock)
        .ok_or("kvm/clock/backwards")?;
    let ticks = u128::from(elapsed) * u128::from(khz) / 1_000_000;
    let ticks = u64::try_from(ticks).map_err(|_| "kvm/clock/overflow")?;
    Ok(source_offset
        .wrapping_add(source_host)
        .wrapping_sub(destination_host)
        .wrapping_add(ticks))
}

#[cfg(test)]
mod tests {
    use crate::vmm::execution::kvm::{
        ArmCounterModel, ArmCounterObservation, ArmCpuState, ArmVmState, CpuidEntry, GicRegister,
        KvmCpuState, KvmVmState, MsrDescriptor, MsrValue, OneReg, PitChannel, Segment, X86CpuState,
        X86Special, X86VmState, XstateComponent, arm_register_class, common_tsc_offset,
    };
    use devices::legacy::kvm_state::{CPU, descriptors, sys};
    use utils::state::{Error, Reader, StateHeaderError, Writer};
    #[test]
    fn kvm_execution_common_clock_preserves_offset_and_nanosecond_units() {
        assert_eq!(
            common_tsc_offset(1000, 100, 17, 2000, 200, 3_600_000).unwrap(),
            3517
        );
        let a = common_tsc_offset(1000, 100, 17, 2000, 200, 3_600_000).unwrap();
        let b = common_tsc_offset(1000, 100, 42, 2000, 200, 3_600_000).unwrap();
        assert_eq!(b.wrapping_sub(a), 25);
    }
    #[test]
    fn kvm_execution_clock_wrap_and_bad_observations() {
        assert_eq!(common_tsc_offset(1, 0, 0, 1, 1, 1).unwrap(), u64::MAX);
        assert!(common_tsc_offset(2, 0, 0, 1, 0, 1).is_err());
        assert!(common_tsc_offset(0, 0, 0, u64::MAX, 0, u32::MAX).is_err());
        assert!(common_tsc_offset(0, 0, 0, 0, 0, 0).is_err());
    }

    fn cpu() -> KvmCpuState {
        let mut lapic = vec![0; 1024];
        lapic[0x320..0x324].copy_from_slice(&(2u32 << 17).to_le_bytes());
        let mut xsave = vec![0; 4096];
        xsave[512] = 7;
        KvmCpuState::X86(X86CpuState {
            id: 0,
            cpuid: vec![
                CpuidEntry {
                    function: 0,
                    index: 0,
                    flags: 0,
                    values: [0xd, 0x756e6547, 0x6c65746e, 0x49656e69],
                },
                CpuidEntry {
                    function: 1,
                    index: 0,
                    flags: 0,
                    values: [0; 4],
                },
                CpuidEntry {
                    function: 0xd,
                    index: 0,
                    flags: 0,
                    values: [7, 832, 832, 0],
                },
                CpuidEntry {
                    function: 0xd,
                    index: 2,
                    flags: 0,
                    values: [256, 576, 0, 0],
                },
            ],
            inventory: vec![
                MsrDescriptor {
                    index: 0x10,
                    class: 3,
                },
                MsrDescriptor {
                    index: 0x174,
                    class: 0,
                },
                MsrDescriptor {
                    index: 0x179,
                    class: 1,
                },
            ],
            msrs: vec![
                MsrValue {
                    index: 0x174,
                    value: 0,
                },
                MsrValue {
                    index: 0x17a,
                    value: 0,
                },
            ],
            model_msrs: vec![MsrValue {
                index: 0x179,
                value: 0,
            }],
            mce_cap: 0,
            xstate: vec![XstateComponent {
                id: 2,
                size: 256,
                offset: 576,
                flags: 0,
            }],
            xsave,
            xcrs: vec![MsrValue { index: 0, value: 7 }],
            regs: [0; 18],
            special: X86Special {
                segments: std::array::from_fn(|_| Segment {
                    base: 0,
                    limit: 0,
                    selector: 0,
                    attributes: [0; 9],
                }),
                gdt: (0, 0),
                idt: (0, 0),
                values: [0; 12],
            },
            debug: [0; 7],
            lapic,
            events: [0; 24],
            mp_state: 3,
            tsc_offset: 7,
            tsc_khz: 3_600_000,
            tsc_observed: 100,
            deadline: 1,
        })
    }
    #[test]
    fn kvm_execution_codec_keeps_due_original_deadline_without_irr() {
        for deadline in [0, 1, 10000] {
            let mut state = cpu();
            let KvmCpuState::X86(s) = &mut state else {
                panic!()
            };
            s.deadline = deadline;
            s.lapic[0x320..0x324].copy_from_slice(&((2u32 << 17) | (1 << 16) | 236).to_le_bytes());
            s.lapic[0x270..0x274].copy_from_slice(&(1u32 << 12).to_le_bytes());
            state.validate().unwrap();
            let mut writer = Writer::new(131072);
            state.encode(&mut writer).unwrap();
            let bytes = writer.finish();
            let mut reader = Reader::new(&bytes);
            assert_eq!(KvmCpuState::decode(&mut reader).unwrap(), state);
            reader.finish().unwrap();
        }
        let original = cpu();
        original.validate().unwrap();
        let mut writer = Writer::new(131072);
        original.encode(&mut writer).unwrap();
        let encoded = writer.finish();
        assert_eq!(
            KvmCpuState::decode(&mut Reader::new(&encoded)).unwrap(),
            original
        );
        let KvmCpuState::X86(s) = original else {
            panic!()
        };
        assert_eq!(s.deadline, 1);
        assert!(s.lapic[0x200..0x280].iter().all(|v| *v == 0));
    }
    #[test]
    fn kvm_execution_codec_rejects_missing_values_bad_xsave_and_truncation() {
        let state = cpu();
        let mut writer = Writer::new(131072);
        state.encode(&mut writer).unwrap();
        let bytes = writer.finish();
        for offset in [0, 8] {
            let mut wrong = bytes.clone();
            wrong[offset] ^= 1;
            let result = KvmCpuState::decode(&mut Reader::new(&wrong));
            match offset {
                0 => assert!(matches!(
                    result,
                    Err(Error::Header(StateHeaderError::Magic { .. }))
                )),
                _ => assert!(matches!(
                    result,
                    Err(Error::Header(StateHeaderError::Schema { .. }))
                )),
            }
        }
        for end in 0..bytes.len() {
            assert!(KvmCpuState::decode(&mut Reader::new(&bytes[..end])).is_err());
        }
        let mut broken = state.clone();
        let KvmCpuState::X86(s) = &mut broken else {
            panic!()
        };
        s.msrs.pop();
        assert!(broken.validate().is_err());
        let mut broken = state.clone();
        let KvmCpuState::X86(s) = &mut broken else {
            panic!()
        };
        s.xsave[512] = 8;
        assert!(broken.validate().is_err());
        let mut broken = state;
        let KvmCpuState::X86(s) = &mut broken else {
            panic!()
        };
        s.inventory.push(s.inventory[0].clone());
        assert!(broken.validate().is_err());
        let mut writer = Writer::new(16);
        writer.header(b"KRUNKCPU", 1).unwrap();
        writer.fixed(&[1, 0, 255, 255, 255, 255]).unwrap();
        assert_eq!(
            KvmCpuState::decode(&mut Reader::new(&writer.finish())),
            Err(Error::Limit)
        );
    }
    #[test]
    fn kvm_execution_offline_and_active_count_mode_are_distinct() {
        let mut state = cpu();
        let KvmCpuState::X86(s) = &mut state else {
            panic!()
        };
        s.mp_state = 1;
        s.deadline = 0;
        s.lapic.fill(0);
        state.validate().unwrap();
        let KvmCpuState::X86(s) = &mut state else {
            panic!()
        };
        s.lapic[0x380] = 1;
        assert!(state.validate().is_err());
    }
    #[test]
    fn kvm_execution_arm_inventory_widths_and_swapped_timer_ids_are_pure() {
        assert_eq!(arm_register_class(0x603000000013df1a).unwrap(), 2);
        assert_eq!(arm_register_class(0x603000000013df02).unwrap(), 3);
        assert!(arm_register_class(0xffffffffffffffff).is_err());
        let state = KvmCpuState::Arm64(ArmCpuState {
            id: 1,
            target: 0,
            features: [0; 7],
            mpidr: 1,
            counter_observation: ArmCounterObservation {
                physical_before: 100,
                virtual_counter: 105,
                physical_after: 110,
            },
            registers: vec![OneReg {
                id: 0x6040000000100040,
                class: 0,
                value: vec![3; 16],
            }],
            mp_state: 5,
            timer_irqs: [27, 30],
            events: [0; 4],
        });
        let mut writer = Writer::new(4096);
        state.encode(&mut writer).unwrap();
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(KvmCpuState::decode(&mut reader).unwrap(), state);
        reader.finish().unwrap();
        let mut broken = state;
        let KvmCpuState::Arm64(s) = &mut broken else {
            panic!()
        };
        s.registers[0].value.pop();
        assert!(broken.validate().is_err());
    }
    #[test]
    fn kvm_execution_gic_codec_rejects_missing_and_duplicate_line_state() {
        let registers = descriptors(64, &[0x80000000], &[5])
            .unwrap()
            .into_iter()
            .map(|(group, attr, width)| GicRegister {
                group,
                attr,
                width,
                value: if group == CPU && attr == sys(3, 0, 12, 12, 4) {
                    4 << 8
                } else {
                    0
                },
            })
            .collect();
        let state = KvmVmState::Arm64(ArmVmState {
            counter_model: ArmCounterModel::CommonPhysicalVirtual,
            counter: 100,
            frequency: 24000000,
            properties: [0x80000000, 65536, 0x7ffe0000, 131072],
            irq_count: 64,
            mpidrs: vec![0x80000000],
            registers,
        });
        let mut writer = Writer::new(65536);
        state.encode(&mut writer).unwrap();
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(KvmVmState::decode(&mut reader).unwrap(), state);
        reader.finish().unwrap();
        for offset in [0, 8] {
            let mut wrong = bytes.clone();
            wrong[offset] ^= 1;
            let result = KvmVmState::decode(&mut Reader::new(&wrong));
            match offset {
                0 => assert!(matches!(
                    result,
                    Err(Error::Header(StateHeaderError::Magic { .. }))
                )),
                _ => assert!(matches!(
                    result,
                    Err(Error::Header(StateHeaderError::Schema { .. }))
                )),
            }
        }
        let mut broken = state.clone();
        let KvmVmState::Arm64(s) = &mut broken else {
            panic!()
        };
        s.registers.pop();
        assert!(broken.validate().is_err());
        let mut broken = state;
        let KvmVmState::Arm64(s) = &mut broken else {
            panic!()
        };
        s.registers.push(s.registers[0].clone());
        assert!(broken.validate().is_err());
    }

    #[test]
    fn kvm_execution_arm_common_counter_observation_admits_only_bracketed_views() {
        for (physical_before, virtual_counter, physical_after) in [
            (100, 100, 100),
            (100, 105, 110),
            (u64::MAX - 4, u64::MAX, 2),
        ] {
            assert!(
                ArmCounterObservation {
                    physical_before,
                    virtual_counter,
                    physical_after,
                }
                .validate()
                .is_ok()
            );
        }
        for (physical_before, virtual_counter, physical_after) in [
            (100, 99, 110),
            (100, 111, 110),
            (1_000_000, 5, 1_000_010),
            (110, 105, 100),
            (0, 1, 1 << 63),
        ] {
            assert!(
                ArmCounterObservation {
                    physical_before,
                    virtual_counter,
                    physical_after,
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn kvm_execution_arm_common_counter_plan_preserves_both_timer_epochs_after_dwell() {
        let model = ArmCounterModel::CommonPhysicalVirtual;
        let source_counter = 10_000u64;
        let physical_compare = source_counter - 7;
        let virtual_compare = source_counter + 200;
        for host_after_dwell in [1_000_000u64, 1_000_000_000_000, 5] {
            let offset = model.offset_for(host_after_dwell, source_counter);
            let physical = host_after_dwell.wrapping_sub(offset);
            let virtual_counter = host_after_dwell.wrapping_sub(offset);
            assert_eq!(physical, source_counter);
            assert_eq!(virtual_counter, source_counter);
            assert_eq!(physical.wrapping_sub(virtual_counter), 0);
            assert_eq!(physical_compare.wrapping_sub(physical) as i64, -7);
            assert_eq!(virtual_compare.wrapping_sub(virtual_counter), 200);
        }
    }

    #[test]
    fn kvm_execution_arm_counter_model_rejects_missing_or_unknown_wire_tag() {
        for bytes in [&[2u8][..], &[2u8, 0][..], &[2u8, 2][..]] {
            let mut writer = Writer::new(16);
            writer.header(b"KRUNKVMS", 1).unwrap();
            writer.fixed(bytes).unwrap();
            assert!(KvmVmState::decode(&mut Reader::new(&writer.finish())).is_err());
        }
    }
    #[test]
    fn kvm_execution_passive_pit_is_not_active_pit_omission() {
        let mut state = KvmVmState::X86(X86VmState {
            clock: 1,
            clock_flags: 10,
            host_tsc: 1,
            realtime: 1,
            host_kernel: "unit-profile".into(),
            host_mode: 0,
            pit: std::array::from_fn(|_| PitChannel {
                count: 0,
                latched_count: 0,
                bytes: [0, 0, 0, 0, 0, 0, 0, 255, 0, 0],
                count_load_time: 0,
            }),
            pit_flags: 0,
            pit_profile: 0,
            pic: [[0; 16]; 2],
            ioapic_base: 0,
            ioapic_select: 0,
            ioapic_id: 0,
            ioapic_irr: 0,
            ioapic_routes: [0; 24],
        });
        state.validate().unwrap();
        let KvmVmState::X86(s) = &mut state else {
            panic!()
        };
        s.pit_profile = 1;
        s.pit[0].bytes[7] = 0;
        s.pit[0].count = 65536;
        s.pic[0][2] = 1;
        s.ioapic_routes[0] = 1 << 16;
        state.validate().unwrap();
        let mut writer = Writer::new(4096);
        state.encode(&mut writer).unwrap();
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(KvmVmState::decode(&mut reader).unwrap(), state);
        let KvmVmState::X86(s) = &mut state else {
            panic!()
        };
        s.pit[0].bytes[7] = 2;
        assert!(state.validate().is_err());
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        not(any(feature = "tee", feature = "aws-nitro"))
    ))]
    #[test]
    fn restored_capture_profile_requires_authenticated_retired_pit_codec_tag() {
        use crate::vmm::execution::runtime::KvmCaptureProfile;
        use crate::vmm::execution::{
            CpuExecutionState, CpuIdentity, ExecutionEnvelope, ExecutionLane, StateBinding,
            ValidatedExecution, VmExecutionState,
        };
        let expected = StateBinding {
            live_state_schema: crate::api::capabilities::LIVE_STATE_SCHEMA.into(),
            architecture: crate::api::capabilities::guest_architecture().into(),
            profile: [2; 32],
            topology: [3; 32],
            ram_layout: [4; 32],
            source_run: [5; 16],
            pause_generation: 1,
            capture: [6; 16],
        };
        for tag in [0, 1] {
            let mut cpu = cpu();
            let KvmCpuState::X86(state) = &mut cpu else {
                panic!()
            };
            state
                .cpuid
                .iter_mut()
                .find(|leaf| leaf.function == 1)
                .unwrap()
                .values[1] = 1 << 16;
            let mut vm = X86VmState {
                clock: 1,
                clock_flags: 10,
                host_tsc: 1,
                realtime: 1,
                host_kernel: "unit-profile".into(),
                host_mode: 0,
                pit: std::array::from_fn(|_| PitChannel {
                    count: 0,
                    latched_count: 0,
                    bytes: [0, 0, 0, 0, 0, 0, 0, 255, 0, 0],
                    count_load_time: 0,
                }),
                pit_flags: 0,
                pit_profile: tag,
                pic: [[0; 16]; 2],
                ioapic_base: 0,
                ioapic_select: 0,
                ioapic_id: 0,
                ioapic_irr: 0,
                ioapic_routes: [0; 24],
            };
            if tag == 1 {
                vm.pit[0].bytes[7] = 0;
                vm.pit[0].count = 65536;
                vm.pic[0][2] = 1;
                vm.ioapic_routes[0] = 1 << 16;
            }
            let envelope = ExecutionEnvelope {
                binding: expected.clone(),
                lane: ExecutionLane::KvmX86,
                topology: vec![CpuIdentity {
                    logical_id: 0,
                    architectural_id: 0,
                }],
                attachments: Vec::new(),
                irq_routes: Vec::new(),
                page_granule: 4096,
                memory_regions: vec![arch::guest_memory::GuestRange::new(0, 4096).unwrap()],
                vm: VmExecutionState::Kvm(KvmVmState::X86(vm)),
                cpus: vec![CpuExecutionState::Kvm(cpu)],
                legacy: Vec::new(),
            };
            let bytes = envelope.encode().unwrap();
            let validated = ValidatedExecution::decode(
                &bytes,
                &expected,
                ExecutionLane::KvmX86,
                &envelope.topology,
                &[],
            )
            .unwrap();
            let profile = KvmCaptureProfile::from_restored_execution(&validated);
            if tag == 0 {
                assert!(profile.is_err());
            } else {
                assert!(matches!(
                    profile.unwrap(),
                    KvmCaptureProfile::RetiredLinuxPit {
                        clocksource_tsc: true,
                        all_online_clockevents_deadline: true,
                        broadcast_uses_pit: false,
                        speaker_or_counter_consumer: false,
                        ..
                    }
                ));
            }
            let mut foreign = expected.clone();
            foreign.profile[0] ^= 1;
            assert!(
                ValidatedExecution::decode(
                    &bytes,
                    &foreign,
                    ExecutionLane::KvmX86,
                    &envelope.topology,
                    &[],
                )
                .is_err()
            );
        }
    }

    #[test]
    fn kvm_execution_dynamic_xsave_tail_is_never_truncated() {
        let mut state = cpu();
        let KvmCpuState::X86(s) = &mut state else {
            panic!()
        };
        s.xsave.resize(8192, 0);
        s.xsave[7000] = 99;
        let mut writer = Writer::new(131072);
        state.encode(&mut writer).unwrap();
        let bytes = writer.finish();
        assert_eq!(
            KvmCpuState::decode(&mut Reader::new(&bytes)).unwrap(),
            state
        );
        let KvmCpuState::X86(s) = &mut state else {
            panic!()
        };
        s.xsave.resize(65540, 0);
        assert!(state.validate().is_err());
    }
}
