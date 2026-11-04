//! Owner-thread KVM execution operations. No method enters KVM_RUN.
use crate::vmm::execution::kvm::{KvmCpuState, KvmCpuTimePlan};
use arch::guest_memory::{NativeEffectsPermit, TrackingMode};
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

pub(crate) fn native_result<T>(
    permit: &NativeEffectsPermit,
    result: Result<T, String>,
) -> Result<T, String> {
    if result.is_err() {
        // An error or short native completion is not evidence that guest RAM was untouched.
        permit.coverage_lost();
    }
    result
}

fn validate_native(permit: &NativeEffectsPermit) -> Result<(), String> {
    permit
        .validate_domain(permit.domain())
        .map_err(|e| format!("kvm/native/authority: {e}"))?;
    if permit.domain().tracking_mode() != Some(TrackingMode::Capture) {
        return Err("kvm/native/memory-tracking-not-finalized".into());
    }
    Ok(())
}

pub(crate) fn capture_cpu(
    fd: &VcpuFd,
    id: u8,
    config: &CpuCaptureConfig,
    permit: &NativeEffectsPermit,
) -> Result<KvmCpuState, String> {
    if cfg!(feature = "tee") {
        return Err("kvm/execution/tee-excluded".into());
    }
    validate_native(permit)?;
    native_result(permit, native::capture_cpu(fd, id, config))
}
pub(crate) fn install_cpu(
    fd: &VcpuFd,
    state: &KvmCpuState,
    config: &CpuCaptureConfig,
    permit: &NativeEffectsPermit,
) -> Result<(), String> {
    state.validate()?;
    validate_native(permit)?;
    native_result(permit, native::install_cpu(fd, state, config))
}
pub(crate) fn prepare_cpu_time(
    fd: &VcpuFd,
    state: &KvmCpuState,
    plan: &KvmCpuTimePlan,
    permit: &NativeEffectsPermit,
) -> Result<(), String> {
    validate_native(permit)?;
    native_result(permit, native::prepare_cpu_time(fd, state, plan))
}

pub(crate) fn fence_cpu_timer(
    fd: &VcpuFd,
    state: &KvmCpuState,
    permit: &NativeEffectsPermit,
) -> Result<(), String> {
    validate_native(permit)?;
    native_result(permit, native::fence_cpu_timer(fd, state))
}

#[cfg(all(feature = "native-device-probe", target_arch = "x86_64"))]
pub(crate) fn initialize_device_witness(
    fd: &VcpuFd,
    state: &crate::vmm::execution::kvm::X86CpuState,
    permit: &NativeEffectsPermit,
) -> Result<(), String> {
    validate_native(permit)?;
    native_result(permit, native::initialize_device_witness(fd, state))
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
    permit: &NativeEffectsPermit,
) -> Result<crate::vmm::execution::kvm::KvmVmState, String> {
    validate_native(permit)?;
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

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use arch::guest_memory::{BackingKind, DirtyPageMap, MemoryDomain, PageIndex};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::vmm::linux::execution::{native_result, validate_native};

    #[test]
    fn native_execution_refuses_construction_and_disabled_domains() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        let (_, construction, mut control) =
            MemoryDomain::construct(memory, 4096, BackingKind::Boot).unwrap();
        let constructing = construction.native_effects().unwrap();
        assert!(validate_native(&constructing).is_err());
        drop(constructing);
        control.finish_untracked(construction).unwrap();
        let disabled = control.runtime_native_effects().unwrap();
        assert!(validate_native(&disabled).is_err());

        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        let (_, construction, mut control) =
            MemoryDomain::construct(memory, 4096, BackingKind::Boot).unwrap();
        let epoch = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, epoch).unwrap();
        let tracked = control.runtime_native_effects().unwrap();
        assert!(validate_native(&tracked).is_ok());
    }

    #[test]
    fn native_partial_failure_invalidates_coverage_without_erasing_known_writes() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 8192)]).unwrap();
        let (domain, construction, mut control) =
            MemoryDomain::construct(memory, 4096, BackingKind::Boot).unwrap();
        let initial = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, initial).unwrap();
        let permit = control.runtime_native_effects().unwrap();
        let write = permit.write(GuestAddress(4095), 2).unwrap();
        write.write_view(0, 2).unwrap().copy_from(&[0x42, 0x17]);
        drop(write);
        let error =
            native_result::<()>(&permit, Err("short SET_MSRS completion".into())).unwrap_err();
        assert_eq!(error, "short SET_MSRS completion");
        assert!(!domain.coverage_valid());
        assert!(control.close().is_err());
        drop(permit);
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("completed native owner must drain");
        };
        let cut = control.seal(&drained).unwrap();
        let mut retained = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&cut, &mut retained).unwrap();
        assert!(retained.contains(PageIndex::new(0)));
        assert!(retained.contains(PageIndex::new(1)));
        let mut bytes = [0; 2];
        domain.read_slice(&mut bytes, GuestAddress(4095)).unwrap();
        assert_eq!(bytes, [0x42, 0x17]);
    }

    #[test]
    fn successful_native_completion_does_not_restore_lost_coverage() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        let (domain, construction, _) =
            MemoryDomain::construct(memory, 4096, BackingKind::Boot).unwrap();
        let permit = construction.native_effects().unwrap();
        assert_eq!(native_result(&permit, Ok(7)).unwrap(), 7);
        assert!(domain.coverage_valid());
        assert!(native_result::<()>(&permit, Err("entered native failure".into())).is_err());
        assert!(!domain.coverage_valid());
        native_result(&permit, Ok(())).unwrap();
        assert!(!domain.coverage_valid());
    }
}
