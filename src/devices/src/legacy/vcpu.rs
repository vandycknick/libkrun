use crossbeam_channel::Sender;
use std::collections::VecDeque;
use std::sync::Mutex;

use arch::aarch64::layout::VTIMER_IRQ;
use arch::aarch64::sysreg::*;
use hvf::bindings::{
    HV_SUCCESS, hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1, hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2,
    hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1, hv_vcpu_get_sys_reg, hv_vcpu_set_sys_reg,
};
use hvf::{TranslationOrderingProbe, Vcpus, vcpu_request_exit};

// See https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/ICC-IAR0-EL1--Interrupt-Controller-Interrupt-Acknowledge-Register-0
const GIC_INTID_SPURIOUS: u32 = 1023;
const ACTLR_EL1_ENTSO: u64 = 1 << 1;
const AIDR_EL1_TSO: u64 = 1 << 9;
const APPLE_CPU_IMPLEMENTOR: u64 = 0x61;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestTranslationOrderingBlocker {
    HostActlrUnavailable,
    GuestAidrUnavailable { midr: u64 },
}

enum VcpuStatus {
    Running,
    Waiting,
}

struct PerCPUInterruptControllerState {
    vcpuid: u64,
    status: VcpuStatus,
    pending_irqs: VecDeque<u32>,
    wfe_sender: Option<Sender<u32>>,
}

impl PerCPUInterruptControllerState {
    fn set_irq_common(&mut self, irq: u32) {
        debug!(
            "[GICv3] SET_IRQ_COMMON vcpuid={}, irq_line={}",
            self.vcpuid, irq
        );
        self.pending_irqs.push_back(irq);

        match self.status {
            VcpuStatus::Waiting => {
                self.wfe_sender
                    .as_mut()
                    .unwrap()
                    .send(self.vcpuid as u32)
                    .unwrap();
                self.status = VcpuStatus::Running;
            }
            VcpuStatus::Running => {
                vcpu_request_exit(self.vcpuid).unwrap();
            }
        }
    }

    fn should_wait(&mut self) -> bool {
        if self.pending_irqs.is_empty() {
            self.status = VcpuStatus::Waiting;
            return true;
        }
        false
    }

    fn has_pending_irq(&self) -> bool {
        !self.pending_irqs.is_empty()
    }

    fn get_pending_irq(&mut self) -> u32 {
        self.pending_irqs.pop_front().unwrap_or(GIC_INTID_SPURIOUS)
    }
}

pub struct VcpuList {
    cpu_count: u64,
    vcpus: Vec<Mutex<PerCPUInterruptControllerState>>,
    translation_ordering: Mutex<Option<u64>>,
}

impl VcpuList {
    pub fn new(cpu_count: u64) -> Self {
        let mut vcpus = Vec::with_capacity(cpu_count as usize);
        for vcpuid in 0..cpu_count {
            vcpus.push(Mutex::new(PerCPUInterruptControllerState {
                vcpuid,
                status: VcpuStatus::Running,
                pending_irqs: VecDeque::new(),
                wfe_sender: None,
            }));
        }

        Self {
            cpu_count,
            vcpus,
            translation_ordering: Mutex::new(None),
        }
    }

    pub fn set_host_translation_ordering_consensus(
        &self,
        probes: &[TranslationOrderingProbe],
    ) -> bool {
        let consensus = translation_ordering_consensus(self.cpu_count, probes);
        if let Ok(mut state) = self.translation_ordering.lock() {
            *state = consensus;
            consensus.is_some()
        } else {
            false
        }
    }

    fn translation_ordering_midr(&self) -> Option<u64> {
        self.translation_ordering
            .lock()
            .ok()
            .and_then(|state| *state)
    }

    pub fn guest_translation_ordering_blocker(&self) -> GuestTranslationOrderingBlocker {
        match self.translation_ordering_midr() {
            Some(midr) => GuestTranslationOrderingBlocker::GuestAidrUnavailable { midr },
            None => GuestTranslationOrderingBlocker::HostActlrUnavailable,
        }
    }

    pub fn get_cpu_count(&self) -> u64 {
        self.cpu_count
    }

    pub fn set_irq_common(&self, vcpuid: u64, irq: u32) {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .set_irq_common(irq);
    }

    pub fn set_sgi_irq(&self, vcpuid: u64, irq: u32) {
        assert!(vcpuid < self.cpu_count);
        assert!(irq < 16);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .set_irq_common(irq);
    }

    pub fn register(&self, vcpuid: u64, wfe_sender: Sender<u32>) {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize].lock().unwrap().wfe_sender = Some(wfe_sender);
    }
}

impl Vcpus for VcpuList {
    fn set_vtimer_irq(&self, vcpuid: u64) {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .set_irq_common(VTIMER_IRQ);
    }

    fn should_wait(&self, vcpuid: u64) -> bool {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize].lock().unwrap().should_wait()
    }

    fn has_pending_irq(&self, vcpuid: u64) -> bool {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .has_pending_irq()
    }

    fn get_pending_irq(&self, vcpuid: u64) -> u32 {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .get_pending_irq()
    }

    fn handle_sysreg_read(&self, vcpuid: u64, reg: u32) -> Option<u64> {
        assert!(vcpuid < self.cpu_count);

        match reg {
            SYSREG_MIDR_EL1 => return self.translation_ordering_midr().or(Some(0)),
            SYSREG_AIDR_EL1 => {
                return Some(if self.translation_ordering_midr().is_some() {
                    AIDR_EL1_TSO
                } else {
                    0
                });
            }
            SYSREG_ACTLR_EL1 if self.translation_ordering_midr().is_some() => {
                let mut value = 0;
                let status = unsafe {
                    hv_vcpu_get_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1, &mut value)
                };
                return (status == HV_SUCCESS).then_some(value & ACTLR_EL1_ENTSO);
            }
            _ => {}
        }

        if is_id_sysreg(reg) {
            return Some(0);
        }

        match reg {
            SYSREG_ICC_IAR1_EL1 => Some(
                self.vcpus[vcpuid as usize]
                    .lock()
                    .unwrap()
                    .get_pending_irq() as u64,
            ),
            SYSREG_ICC_PMR_EL1 => Some(0),
            SYSREG_ICC_CTLR_EL1 => Some(
                (1 << ICC_CTLR_EL1_RSS_SHIFT)
                    | (1 << ICC_CTLR_EL1_A3V_SHIFT)
                    | (1 << ICC_CTLR_EL1_ID_BITS_SHIFT)
                    | (4 << ICC_CTLR_EL1_PRI_BITS_SHIFT),
            ),
            SYSREG_CNTHCTL_EL2 => {
                let val: u64 = 0;
                let ret = unsafe {
                    hv_vcpu_get_sys_reg(
                        vcpuid,
                        hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2,
                        &val as *const _ as *mut _,
                    )
                };
                if ret == HV_SUCCESS { Some(val) } else { None }
            }
            SYSREG_MDCCINT_EL1 => {
                let val: u64 = 0;
                let ret = unsafe {
                    hv_vcpu_get_sys_reg(
                        vcpuid,
                        hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1,
                        &val as *const _ as *mut _,
                    )
                };
                if ret == HV_SUCCESS { Some(val) } else { None }
            }
            _ => None,
        }
    }

    fn handle_sysreg_write(&self, vcpuid: u64, reg: u32, val: u64) -> bool {
        assert!(vcpuid < self.cpu_count);

        if reg == SYSREG_ACTLR_EL1 && self.translation_ordering_midr().is_some() {
            if val & !ACTLR_EL1_ENTSO != 0 {
                return false;
            }
            let mut current = 0;
            if unsafe {
                hv_vcpu_get_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1, &mut current)
            } != HV_SUCCESS
            {
                return false;
            }
            let target = (current & !ACTLR_EL1_ENTSO) | val;
            if unsafe { hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1, target) }
                != HV_SUCCESS
            {
                return false;
            }
            let mut readback = 0;
            return unsafe {
                hv_vcpu_get_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1, &mut readback)
            } == HV_SUCCESS
                && readback == target;
        }

        if is_id_sysreg(reg) {
            return true;
        }

        match reg {
            SYSREG_ICC_SGI1R_EL1 => {
                let target_list = val & 0xffff;
                let intid = ((val >> 24) & 0xf) as u32;
                let irm = (val & (1 << 40)) >> 40;
                let is_broadcast = irm == 1;
                let aff3aff2aff1 = val & ((0xff << 48) | (0xff << 32) | (0xff << 16));
                let rs = (val & (0xf << 44)) >> 44;

                debug!("vCPU {vcpuid} GenerateSoftwareInterrupt={intid} (0x{val:x})");

                // A flat core hierarchy should be good enough, but if we ever start using
                // Aff[123] MPIDR fields (currently MPID is configured via DT), GICv3 support
                // will need to be added.
                assert_eq!(
                    aff3aff2aff1, 0,
                    "[GICv3] only flat core hierarchy supported for now"
                );

                assert!(
                    !is_broadcast,
                    "[GICv3] SGI broadcast is not implemented yet"
                );

                // for each core in target list
                for target_id in 0u64..=15u64 {
                    if (target_list >> target_id) & 1 == 1 {
                        self.set_sgi_irq(rs * 16 + target_id, intid)
                    }
                }

                true
            }
            SYSREG_CNTHCTL_EL2 => {
                let ret = unsafe {
                    hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2, val)
                };
                ret == HV_SUCCESS
            }
            SYSREG_MDCCINT_EL1 => {
                let ret = unsafe {
                    hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1, val)
                };
                ret == HV_SUCCESS
            }
            SYSREG_ICC_EOIR1_EL1
            | SYSREG_ICC_IGRPEN1_EL1
            | SYSREG_ICC_PMR_EL1
            | SYSREG_ICC_BPR1_EL1
            | SYSREG_ICC_CTLR_EL1
            | SYSREG_ICC_AP1R0_EL1
            | SYSREG_LORC_EL1
            | SYSREG_OSLAR_EL1
            | SYSREG_OSDLR_EL1 => true,
            _ => false,
        }
    }
}

fn translation_ordering_consensus(
    cpu_count: u64,
    probes: &[TranslationOrderingProbe],
) -> Option<u64> {
    if probes.len() != cpu_count as usize {
        return None;
    }
    let mut midr = None;
    for probe in probes {
        let TranslationOrderingProbe::Supported { midr: current } = probe else {
            return None;
        };
        if current >> 24 & 0xff != APPLE_CPU_IMPLEMENTOR {
            return None;
        }
        match midr {
            Some(expected) if expected != *current => return None,
            None => midr = Some(*current),
            _ => {}
        }
    }
    midr
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::process::{Command, Stdio};
    use std::ptr;
    use std::sync::mpsc::sync_channel;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::legacy::vcpu::{GuestTranslationOrderingBlocker, translation_ordering_consensus};
    use hvf::bindings::{
        HV_SUCCESS, hv_reg_t_HV_REG_PC, hv_reg_t_HV_REG_X0, hv_vcpu_get_reg, hv_vcpu_set_reg,
    };
    use hvf::reclaim::ReclaimState;
    use hvf::{HvfVcpu, HvfVm, TranslationOrderingProbe, VcpuExit};

    use crate::legacy::VcpuList;

    const CODE_GPA: u64 = 0x6000_0000;
    const HOST_PAGE_SIZE: usize = 0x4000;
    const CHILD_TIMEOUT: Duration = Duration::from_secs(8);

    unsafe extern "C" {
        // nix does not expose the macOS instruction-cache invalidation routine.
        fn sys_icache_invalidate(start: *mut c_void, length: usize);
    }

    #[link(name = "Hypervisor", kind = "framework")]
    unsafe extern "C" {}

    struct HostMapping(*mut u8);

    unsafe impl Send for HostMapping {}

    impl HostMapping {
        fn new() -> Self {
            let address = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    HOST_PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            assert_ne!(address, libc::MAP_FAILED, "anonymous mmap failed");
            Self(address.cast())
        }

        fn write_words(&mut self, words: &[u32]) {
            assert!(size_of_val(words) <= HOST_PAGE_SIZE);
            unsafe {
                ptr::copy_nonoverlapping(words.as_ptr().cast::<u8>(), self.0, size_of_val(words));
                sys_icache_invalidate(self.0.cast::<c_void>(), size_of_val(words));
            }
        }
    }

    impl Drop for HostMapping {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::munmap(self.0.cast(), HOST_PAGE_SIZE) }, 0);
        }
    }

    fn mrs(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32, rt: u32) -> u32 {
        0xd520_0000 | op0 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt
    }

    fn msr(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32, rt: u32) -> u32 {
        0xd500_0000 | op0 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt
    }

    fn set_reg(vcpu: &HvfVcpu<'_>, register: u32, value: u64) {
        assert_eq!(
            unsafe { hv_vcpu_set_reg(vcpu.id(), register, value) },
            HV_SUCCESS
        );
    }

    fn get_reg(vcpu: &HvfVcpu<'_>, register: u32) -> u64 {
        let mut value = 0;
        assert_eq!(
            unsafe { hv_vcpu_get_reg(vcpu.id(), register, &mut value) },
            HV_SUCCESS
        );
        value
    }

    fn child_scenario(name: &str, scenario: fn()) {
        const CHILD_ENV: &str = "LIBKRUN_ACTUAL_TSO_CHILD";
        if std::env::var_os(CHILD_ENV).as_deref() == Some(name.as_ref()) {
            scenario();
            return;
        }
        let executable = std::env::current_exe().expect("current test executable");
        let test_name = thread::current()
            .name()
            .expect("named test thread")
            .to_string();
        let mut child = Command::new(executable)
            .args(["--exact", &test_name, "--ignored", "--nocapture"])
            .env(CHILD_ENV, name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn isolated HVF scenario");
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                let output = child.wait_with_output().expect("collect child output");
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
                print!("{}", String::from_utf8_lossy(&output.stdout));
                assert!(
                    status.success(),
                    "isolated scenario {name} failed: {status}"
                );
                return;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill timed-out HVF scenario");
                let output = child.wait_with_output().expect("collect timed-out child");
                panic!(
                    "isolated scenario {name} exceeded {CHILD_TIMEOUT:?}: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn translation_ordering_guest_scenario() {
        let vm = HvfVm::new(false).expect("create HVF VM");
        let mut code = HostMapping::new();
        code.write_words(&[
            mrs(3, 0, 0, 0, 0, 0),
            mrs(3, 1, 0, 0, 7, 1),
            mrs(3, 0, 1, 0, 1, 2),
            msr(3, 0, 1, 0, 1, 3),
            mrs(3, 0, 1, 0, 1, 4),
            mrs(3, 0, 0, 0, 0, 31),
            msr(3, 0, 1, 0, 1, 31),
            mrs(3, 0, 1, 0, 1, 6),
            msr(3, 0, 1, 0, 1, 5),
        ]);
        vm.map_memory(code.0 as u64, CODE_GPA, HOST_PAGE_SIZE as u64)
            .expect("map code");
        let vcpus = Arc::new(VcpuList::new(2));
        let reclaim = Arc::new(ReclaimState::new());
        let barrier = Arc::new(Barrier::new(3));
        let (probe_tx, probe_rx) = sync_channel(2);
        let first_vcpus = Arc::clone(&vcpus);
        let first_reclaim = Arc::clone(&reclaim);
        let first_barrier = Arc::clone(&barrier);
        let first_tx = probe_tx.clone();
        let first = thread::spawn(move || {
            let mut vcpu = HvfVcpu::new(0, false).expect("create first vCPU");
            let probe = vcpu.probe_translation_ordering().expect("probe first vCPU");
            first_tx.send(probe).expect("report first probe");
            first_barrier.wait();
            vcpu.set_initial_state(CODE_GPA, 0)
                .expect("initialize first vCPU");
            set_reg(&vcpu, hv_reg_t_HV_REG_X0 + 3, 2);
            set_reg(&vcpu, hv_reg_t_HV_REG_X0 + 5, 4);
            for index in 0..8 {
                assert!(matches!(
                    vcpu.run(first_vcpus.clone(), &first_reclaim)
                        .expect("emulate supported system register"),
                    VcpuExit::SystemRegister
                ));
                assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_PC), CODE_GPA + index * 4);
            }
            assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_X0), 0x610f_0000);
            assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_X0 + 1), 1 << 9);
            assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_X0 + 2), 0);
            assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_X0 + 4), 2);
            assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_X0 + 6), 0);
            assert!(vcpu.run(first_vcpus.clone(), &first_reclaim).is_err());
            assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_PC), CODE_GPA + 32);
            assert!(vcpu.run(first_vcpus, &first_reclaim).is_err());
            assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_PC), CODE_GPA + 32);
            first_barrier.wait();
            vcpu.destroy().expect("destroy first vCPU");
        });
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            let vcpu = HvfVcpu::new(0x100, false).expect("create second vCPU");
            let probe = vcpu
                .probe_translation_ordering()
                .expect("probe second vCPU");
            probe_tx.send(probe).expect("report second probe");
            second_barrier.wait();
            second_barrier.wait();
            vcpu.destroy().expect("destroy second vCPU");
        });
        let probes = [
            probe_rx.recv().expect("first probe"),
            probe_rx.recv().expect("second probe"),
        ];
        eprintln!("translation_ordering_probes={probes:?}");
        assert!(vcpus.set_host_translation_ordering_consensus(&probes));
        barrier.wait();
        barrier.wait();
        first.join().expect("first vCPU owner");
        second.join().expect("second vCPU owner");
        vm.unmap_memory(CODE_GPA, HOST_PAGE_SIZE as u64)
            .expect("unmap code");
        vm.destroy().expect("destroy HVF VM");
    }

    #[test]
    fn translation_ordering_requires_coherent_apple_vcpus() {
        let apple = TranslationOrderingProbe::Supported { midr: 0x610f_0000 };
        assert_eq!(
            translation_ordering_consensus(2, &[apple, apple]),
            Some(0x610f_0000)
        );
        assert_eq!(translation_ordering_consensus(2, &[apple]), None);
        assert_eq!(
            translation_ordering_consensus(
                2,
                &[
                    apple,
                    TranslationOrderingProbe::Unsupported(
                        hvf::TranslationOrderingUnsupported::MidrRead { status: 1 },
                    ),
                ],
            ),
            None
        );
        assert_eq!(
            translation_ordering_consensus(
                2,
                &[
                    apple,
                    TranslationOrderingProbe::Supported { midr: 0x610f_0010 },
                ],
            ),
            None
        );
        assert_eq!(
            translation_ordering_consensus(
                1,
                &[TranslationOrderingProbe::Supported { midr: 0x410f_0000 }],
            ),
            None
        );
    }

    #[test]
    fn host_actlr_support_does_not_qualify_guest_aidr() {
        let vcpus = VcpuList::new(2);
        let probes = [
            TranslationOrderingProbe::Supported { midr: 0x610f_0000 },
            TranslationOrderingProbe::Supported { midr: 0x610f_0000 },
        ];

        assert!(vcpus.set_host_translation_ordering_consensus(&probes));
        assert_eq!(
            vcpus.guest_translation_ordering_blocker(),
            GuestTranslationOrderingBlocker::GuestAidrUnavailable { midr: 0x610f_0000 }
        );
    }

    #[test]
    #[ignore = "requires a signed test binary and exclusive Hypervisor.framework access"]
    fn actual_hvf_guest_translation_ordering_contract() {
        child_scenario(
            "translation-ordering-guest",
            translation_ordering_guest_scenario,
        );
    }
}
