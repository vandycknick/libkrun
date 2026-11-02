use crate::vmm::execution::kvm::{
    ArmCounterModel, ArmCounterObservation, ArmCpuState, KvmCpuState, KvmCpuTimePlan, MAX_ONE_REGS,
    OneReg,
};
use crate::vmm::linux::execution::CpuCaptureConfig;
use kvm_bindings::*;
use kvm_ioctls::{VcpuFd, VmFd};
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

ioctl_iow_nr!(set_counter_offset, KVMIO, 0xb5, kvm_arm_counter_offset);
// The attribute descriptor is input; KVM writes through its addr, so GET uses _IOW too.
ioctl_iow_nr!(get_vcpu_attr, KVMIO, 0xe2, kvm_device_attr);

const fn sys(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    0x6030000000130000 | (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}
pub(crate) use arch::aarch64::regs::{
    KVM_REG_ARM_TIMER_CNT as TIMER_CNT, KVM_REG_ARM_TIMER_CTL as TIMER_CTL,
    KVM_REG_ARM_TIMER_CVAL as TIMER_CVAL,
};
const PHYS_CVAL: u64 = sys(3, 3, 14, 2, 2);
const PHYS_CTL: u64 = sys(3, 3, 14, 2, 1);
const PHYS_CNT: u64 = sys(3, 3, 14, 0, 1);
pub(crate) const COUNTER_FREQUENCY: u64 = sys(3, 3, 14, 0, 0);

use crate::vmm::execution::kvm::arm_register_class as register_class;

fn timer_irqs(fd: &VcpuFd) -> Result<[u32; 2], String> {
    let mut result = [0; 2];
    for (i, selector) in [KVM_ARM_VCPU_TIMER_IRQ_VTIMER, KVM_ARM_VCPU_TIMER_IRQ_PTIMER]
        .into_iter()
        .enumerate()
    {
        let attr = kvm_device_attr {
            group: KVM_ARM_VCPU_TIMER_CTRL,
            attr: selector.into(),
            addr: &mut result[i] as *mut u32 as u64,
            flags: 0,
        };
        fd.has_device_attr(&attr)
            .map_err(|e| format!("kvm/arm64/timer-irq/unsupported: {e}"))?;
        let ret = unsafe { ioctl_with_ref(fd, get_vcpu_attr(), &attr) };
        if ret < 0 {
            return Err(format!(
                "kvm/arm64/GET_TIMER_IRQ: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(result)
}
fn inventory(fd: &VcpuFd) -> Result<Vec<u64>, String> {
    let mut native = RegList::new(MAX_ONE_REGS)
        .map_err(|e| format!("kvm/arm64/GET_REG_LIST/allocation: {e:?}"))?;
    fd.get_reg_list(&mut native)
        .map_err(|e| format!("kvm/arm64/GET_REG_LIST: {e}"))?;
    let mut ids = native.as_slice().to_vec();
    ids.sort_unstable();
    if ids.windows(2).any(|p| p[0] == p[1]) {
        return Err("kvm/arm64/register-duplicate".into());
    }
    Ok(ids)
}
fn get(fd: &VcpuFd, id: u64) -> Result<Vec<u8>, String> {
    let width = 1usize
        .checked_shl(((id >> 52) & 15) as u32)
        .ok_or("kvm/arm64/register-width")?;
    if width > 16 {
        return Err(format!("kvm/arm64/register/{id:#x}/expanded-width"));
    }
    let mut value = vec![0; width];
    let completed = fd
        .get_one_reg(id, &mut value)
        .map_err(|e| format!("kvm/arm64/GET_ONE_REG/{id:#x}: {e}"))?;
    if completed != width {
        return Err(format!(
            "kvm/arm64/GET_ONE_REG/{id:#x}/requested={width}/completed={completed}"
        ));
    }
    Ok(value)
}
fn set(fd: &VcpuFd, r: &OneReg) -> Result<(), String> {
    let completed = fd
        .set_one_reg(r.id, &r.value)
        .map_err(|e| format!("kvm/arm64/SET_ONE_REG/{:#x}: {e}", r.id))?;
    if completed != r.value.len() {
        return Err(format!(
            "kvm/arm64/SET_ONE_REG/{:#x}/requested={}/completed={completed}",
            r.id,
            r.value.len()
        ));
    }
    Ok(())
}
fn counter(fd: &VcpuFd, id: u64) -> Result<u64, String> {
    let mut bytes = [0; 8];
    let completed = fd
        .get_one_reg(id, &mut bytes)
        .map_err(|e| format!("kvm/arm64/GET_COUNTER/{id:#x}: {e}"))?;
    if completed != bytes.len() {
        return Err(format!(
            "kvm/arm64/GET_COUNTER/{id:#x}/requested=8/completed={completed}"
        ));
    }
    Ok(u64::from_le_bytes(bytes))
}

fn observe_counters(fd: &VcpuFd) -> Result<ArmCounterObservation, String> {
    let observation = ArmCounterObservation {
        physical_before: counter(fd, PHYS_CNT)?,
        virtual_counter: counter(fd, TIMER_CNT)?,
        physical_after: counter(fd, PHYS_CNT)?,
    };
    observation.validate()?;
    Ok(observation)
}

pub(crate) fn capture_cpu(
    fd: &VcpuFd,
    id: u8,
    config: &CpuCaptureConfig,
) -> Result<KvmCpuState, String> {
    if config.init.features[0] & (1 << KVM_ARM_VCPU_SVE) != 0 {
        return Err("kvm/arm64/sve-unqualified".into());
    }
    let mp_state = fd
        .get_mp_state()
        .map_err(|e| format!("kvm/arm64/GET_MP_STATE: {e}"))?
        .mp_state;
    let mut registers = Vec::new();
    for id in inventory(fd)? {
        registers.push(OneReg {
            id,
            class: register_class(id)?,
            value: get(fd, id)?,
        });
    }
    let mpidr = registers
        .iter()
        .find(|r| r.id == sys(3, 0, 0, 0, 5))
        .ok_or("kvm/arm64/mpidr-missing")?;
    let bytes: [u8; 8] = mpidr
        .value
        .as_slice()
        .try_into()
        .map_err(|_| "kvm/arm64/mpidr-width")?;
    let mpidr = u64::from_le_bytes(bytes);
    let event = fd
        .get_vcpu_events()
        .map_err(|e| format!("kvm/arm64/GET_VCPU_EVENTS: {e}"))?
        .exception;
    let state = KvmCpuState::Arm64(ArmCpuState {
        id,
        target: config.init.target,
        features: config.init.features,
        mpidr,
        // Verify the constructor-established epoch before the owner fences either timer.
        counter_observation: observe_counters(fd)?,
        registers,
        mp_state,
        timer_irqs: timer_irqs(fd)?,
        events: [
            event.serror_pending.into(),
            event.serror_has_esr.into(),
            event.ext_dabt_pending.into(),
            event.serror_esr,
        ],
    });
    state.validate()?;
    Ok(state)
}
fn restore_events(fd: &VcpuFd, s: &ArmCpuState) -> Result<(), String> {
    let v = s.events;
    let events = kvm_vcpu_events {
        exception: kvm_vcpu_events__bindgen_ty_1 {
            serror_pending: u8::try_from(v[0]).map_err(|_| "kvm/arm64/event-flag")?,
            serror_has_esr: u8::try_from(v[1]).map_err(|_| "kvm/arm64/event-flag")?,
            ext_dabt_pending: u8::try_from(v[2]).map_err(|_| "kvm/arm64/event-flag")?,
            serror_esr: v[3],
            ..Default::default()
        },
        ..Default::default()
    };
    fd.set_vcpu_events(&events)
        .map_err(|e| format!("kvm/arm64/SET_VCPU_EVENTS: {e}"))?;
    fd.set_mp_state(kvm_mp_state {
        mp_state: s.mp_state,
    })
    .map_err(|e| format!("kvm/arm64/SET_MP_STATE: {e}"))
}
pub(crate) fn fence_cpu_timer(fd: &VcpuFd, state: &KvmCpuState) -> Result<(), String> {
    let KvmCpuState::Arm64(s) = state else {
        return Err("kvm/arm64/backend".into());
    };
    for r in s
        .registers
        .iter()
        .filter(|r| [TIMER_CTL, PHYS_CTL].contains(&r.id))
    {
        let bytes: [u8; 8] = r
            .value
            .as_slice()
            .try_into()
            .map_err(|_| "kvm/arm64/timer-width")?;
        let disabled = OneReg {
            id: r.id,
            class: r.class,
            value: (u64::from_le_bytes(bytes) & !1).to_le_bytes().to_vec(),
        };
        set(fd, &disabled)?;
    }
    Ok(())
}
pub(crate) fn install_cpu(
    fd: &VcpuFd,
    state: &KvmCpuState,
    config: &CpuCaptureConfig,
) -> Result<(), String> {
    let KvmCpuState::Arm64(s) = state else {
        return Err("kvm/arm64/backend".into());
    };
    if s.target != config.init.target || s.features != config.init.features {
        return Err("kvm/arm64/init-contract".into());
    }
    let ids = inventory(fd)?;
    if !ids.iter().copied().eq(s.registers.iter().map(|r| r.id)) {
        return Err("kvm/arm64/destination-register-inventory".into());
    }
    for r in &s.registers {
        if register_class(r.id)? != r.class {
            return Err("kvm/arm64/register-class".into());
        }
        if r.class == 1 && get(fd, r.id)? != r.value {
            return Err(format!("kvm/arm64/model/{:#x}", r.id));
        }
    }
    for (i, selector) in [KVM_ARM_VCPU_TIMER_IRQ_VTIMER, KVM_ARM_VCPU_TIMER_IRQ_PTIMER]
        .into_iter()
        .enumerate()
    {
        let irq = s.timer_irqs[i];
        fd.set_device_attr(&kvm_device_attr {
            group: KVM_ARM_VCPU_TIMER_CTRL,
            attr: selector.into(),
            addr: &irq as *const u32 as u64,
            flags: 0,
        })
        .map_err(|e| format!("kvm/arm64/SET_TIMER_IRQ: {e}"))?;
    }
    fence_cpu_timer(fd, state)?;
    for r in s.registers.iter().filter(|r| r.class == 0) {
        set(fd, r)?;
    }
    restore_events(fd, s)
}
pub(crate) fn prepare_cpu_time(
    fd: &VcpuFd,
    state: &KvmCpuState,
    plan: &KvmCpuTimePlan,
) -> Result<(), String> {
    let (KvmCpuState::Arm64(s), KvmCpuTimePlan::Arm64 { id, .. }) = (state, plan) else {
        return Err("kvm/arm64/time-backend".into());
    };
    if *id != s.id {
        return Err("kvm/arm64/time-cpu".into());
    }
    observe_counters(fd)?;
    // The coordinator installs the VM-wide offset exclusively before any owner replays compares.
    for id in [PHYS_CVAL, TIMER_CVAL, PHYS_CTL, TIMER_CTL] {
        if let Some(r) = s.registers.iter().find(|r| r.id == id) {
            set(fd, r)?;
        }
    }
    restore_events(fd, s)
}
pub(crate) fn initialize_counter_model(fd: &VmFd) -> Result<ArmCounterModel, String> {
    if !fd.check_extension(kvm_ioctls::Cap::CounterOffset) {
        return Err("kvm/arm64/common-counter-offset-unsupported".into());
    }
    let model = ArmCounterModel::CommonPhysicalVirtual;
    // This runs before vCPU creation. KVM retains this VM policy across VCPU_INIT,
    // uses it for both timer views, and ignores later SET_ONE_REG counter writes.
    apply_counter_offset(fd, model, 0)?;
    Ok(model)
}

pub(crate) fn apply_counter_offset(
    fd: &VmFd,
    model: ArmCounterModel,
    counter: u64,
) -> Result<u64, String> {
    let host: u64;
    // No nix API exposes architectural counters; reading CNTVCT_EL0 is non-mutating.
    unsafe {
        std::arch::asm!("isb", "mrs {counter}, cntvct_el0",counter=out(reg)host,options(nomem,nostack,preserves_flags));
    }
    let offset = model.offset_for(host, counter);
    let state = kvm_arm_counter_offset {
        counter_offset: offset,
        reserved: 0,
    };
    let result = unsafe { ioctl_with_ref(fd, set_counter_offset(), &state) };
    if result < 0 {
        return Err(format!(
            "kvm/arm64/SET_COUNTER_OFFSET: {}",
            std::io::Error::last_os_error()
        ));
    }
    if result != 0 {
        return Err(format!(
            "kvm/arm64/SET_COUNTER_OFFSET/unexpected-result/{result}"
        ));
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use crate::vmm::linux::execution::native::{TIMER_CNT, TIMER_CVAL, register_class};
    #[test]
    fn kvm_execution_arm_timer_ids_follow_swapped_uapi() {
        assert_eq!(TIMER_CNT, 0x603000000013df1a);
        assert_eq!(TIMER_CVAL, 0x603000000013df02);
        assert_eq!(register_class(TIMER_CNT).unwrap(), 2);
        assert_eq!(register_class(TIMER_CVAL).unwrap(), 3);
    }
}
