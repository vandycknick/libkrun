//! Owner-thread KVM execution operations. No method enters KVM_RUN.
use crate::vmm::execution::kvm::{KvmCpuState, KvmCpuTimePlan};
use kvm_ioctls::VcpuFd;

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KvmClockObservation {
    pub source: [u64; 4],
    pub destination: [u64; 4],
}

#[cfg(target_arch = "x86_64")]
#[path = "execution_x86.rs"]
mod native;
#[cfg(target_arch = "aarch64")]
#[path = "execution_arm.rs"]
mod native;

#[derive(Clone, Debug)]
pub(crate) struct CpuCaptureConfig {
    #[cfg(target_arch = "x86_64")]
    pub logical_id: u8,
    #[cfg(target_arch = "x86_64")]
    pub host_cpuid: kvm_bindings::CpuId,
    #[cfg(target_arch = "x86_64")]
    pub raw_msrs: Vec<u32>,
    #[cfg(target_arch = "x86_64")]
    pub xsave_size: usize,
    #[cfg(target_arch = "x86_64")]
    pub deadline_supported: bool,
    #[cfg(target_arch = "aarch64")]
    pub init: kvm_bindings::kvm_vcpu_init,
}

pub(crate) fn capture_cpu(
    fd: &VcpuFd,
    id: u8,
    config: &CpuCaptureConfig,
) -> Result<KvmCpuState, String> {
    if cfg!(feature = "tee") {
        return Err("kvm/execution/tee-excluded".into());
    }
    native::capture_cpu(fd, id, config)
}
pub(crate) fn install_cpu(
    fd: &VcpuFd,
    state: &KvmCpuState,
    config: &CpuCaptureConfig,
) -> Result<(), String> {
    state.validate()?;
    native::install_cpu(fd, state, config)
}
pub(crate) fn prepare_cpu_time(
    fd: &VcpuFd,
    state: &KvmCpuState,
    plan: &KvmCpuTimePlan,
) -> Result<(), String> {
    native::prepare_cpu_time(fd, state, plan)
}

pub(crate) fn fence_cpu_timer(fd: &VcpuFd, state: &KvmCpuState) -> Result<(), String> {
    native::fence_cpu_timer(fd, state)
}

#[cfg(target_arch = "x86_64")]
pub(crate) use native::{KvmCaptureProfile, capture_vm, install_vm, prepare_vm_time};

#[cfg(target_arch = "aarch64")]
pub(crate) use native::initialize_counter_model;

#[cfg(target_arch = "aarch64")]
pub(crate) struct KvmCaptureProfile {
    pub controller: devices::legacy::IrqChip,
    pub cpus: Vec<KvmCpuState>,
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn capture_arm_vm(
    profile: &KvmCaptureProfile,
    counter_model: crate::vmm::execution::kvm::ArmCounterModel,
) -> Result<crate::vmm::execution::kvm::KvmVmState, String> {
    use crate::vmm::execution::kvm::{ArmVmState, KvmVmState};
    let mut mpidrs = Vec::with_capacity(profile.cpus.len());
    let mut counter = None;
    let mut frequency = None;
    for cpu in &profile.cpus {
        cpu.validate()?;
        let KvmCpuState::Arm64(cpu) = cpu else {
            return Err("kvm/arm64/mixed-cpu".into());
        };
        mpidrs.push(cpu.mpidr);
        let scalar = |id| -> Result<u64, String> {
            let reg = cpu
                .registers
                .iter()
                .find(|r| r.id == id)
                .ok_or("kvm/arm64/counter-register-missing")?;
            Ok(u64::from_le_bytes(
                reg.value
                    .as_slice()
                    .try_into()
                    .map_err(|_| "kvm/arm64/counter-width")?,
            ))
        };
        let rate = scalar(native::COUNTER_FREQUENCY)?;
        if frequency.is_some_and(|f| f != rate) {
            return Err("kvm/arm64/counter-frequency-disagreement".into());
        }
        frequency = Some(rate);
        if counter.is_none() {
            counter = Some(cpu.counter_observation.virtual_counter);
        }
    }
    let gic = profile
        .controller
        .lock()
        .map_err(|_| "kvm/gic/lock")?
        .capture_kvm_state(&mpidrs)?;
    let state = KvmVmState::Arm64(ArmVmState {
        counter_model,
        counter: counter.ok_or("kvm/arm64/no-cpus")?,
        frequency: frequency.ok_or("kvm/arm64/no-frequency")?,
        properties: gic.properties,
        irq_count: gic.irq_count,
        mpidrs: gic.mpidrs,
        registers: gic.registers,
    });
    state.validate()?;
    Ok(state)
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn arm_gic_state(
    state: &crate::vmm::execution::kvm::KvmVmState,
) -> Result<devices::legacy::kvm_state::GicState, String> {
    let crate::vmm::execution::kvm::KvmVmState::Arm64(state) = state else {
        return Err("kvm/gic/backend".into());
    };
    Ok(devices::legacy::kvm_state::GicState {
        properties: state.properties,
        irq_count: state.irq_count,
        mpidrs: state.mpidrs.clone(),
        registers: state.registers.clone(),
    })
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn prepare_arm_time(
    fd: &kvm_ioctls::VmFd,
    state: &crate::vmm::execution::kvm::KvmVmState,
    cpus: &[KvmCpuState],
) -> Result<Vec<KvmCpuTimePlan>, String> {
    let crate::vmm::execution::kvm::KvmVmState::Arm64(state) = state else {
        return Err("kvm/arm64/clock-backend".into());
    };
    if cpus.len() != state.mpidrs.len() {
        return Err("kvm/arm64/clock-topology".into());
    }
    let offset = native::apply_counter_offset(fd, state.counter_model, state.counter)?;
    cpus.iter()
        .map(|cpu| match cpu {
            KvmCpuState::Arm64(cpu) => Ok(KvmCpuTimePlan::Arm64 {
                id: cpu.id,
                counter_offset: offset,
            }),
            _ => Err("kvm/arm64/clock-backend".into()),
        })
        .collect()
}
