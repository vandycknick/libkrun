// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::mem::{MaybeUninit, size_of, size_of_val};
use std::ptr;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use arch::guest_memory::GuestRange;

use crate::HvfVmLifetime;
use crate::bindings::{
    HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, HV_SUCCESS,
    hv_exit_reason_t_HV_EXIT_REASON_EXCEPTION, hv_reg_t_HV_REG_CPSR, hv_reg_t_HV_REG_PC,
    hv_reg_t_HV_REG_X0, hv_reg_t_HV_REG_X1, hv_reg_t_HV_REG_X2, hv_reg_t_HV_REG_X3,
    hv_reg_t_HV_REG_X4, hv_sys_reg_t_HV_SYS_REG_ESR_EL1, hv_sys_reg_t_HV_SYS_REG_FAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1, hv_sys_reg_t_HV_SYS_REG_VBAR_EL1, hv_vcpu_create,
    hv_vcpu_destroy, hv_vcpu_exit_t, hv_vcpu_get_reg, hv_vcpu_get_sys_reg, hv_vcpu_run,
    hv_vcpu_set_reg, hv_vcpu_set_sys_reg, hv_vcpu_set_trap_debug_exceptions, hv_vcpus_exit,
    hv_vm_map, hv_vm_unmap,
};
use crate::reclaim::ReclaimQualification;

const DATA_SIZE: usize = 2 * 1024 * 1024;
const REQUIRED_PERCENT: u64 = 75;
const ABSENT_DROP_PERCENT: u64 = 25;
const RUN_DEADLINE: Duration = Duration::from_secs(1);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(1);
const ACCOUNTING_SETTLE: Duration = Duration::from_millis(20);
const PSTATE_EL1H_MASKED: u64 = 0x3c5;
const EC_AA64_BKPT: u64 = 0x3c;
const TASK_VM_INFO: u32 = 22;
const PROT_READ: i32 = 0x01;
const PROT_WRITE: i32 = 0x02;
const MAP_PRIVATE: i32 = 0x0002;
const MAP_ANON: i32 = 0x1000;
const MADV_FREE_REUSABLE: i32 = 7;
const MADV_FREE_REUSE: i32 = 8;

// str x3, [x0]; ldr x5, [x0]; add x4, x4, x5; add x3, x3, #1;
// add x0, x0, x2; subs x1, x1, #1; b.ne loop; mov x0, x4; brk #0.
const TOUCH_PROGRAM: [u32; 9] = [
    0xf900_0003,
    0xf940_0005,
    0x8b05_0084,
    0x9100_0463,
    0x8b02_0000,
    0xf100_0421,
    0x54ff_ff41,
    0xaa04_03e0,
    0xd420_0000,
];

unsafe extern "C" {
    static mach_task_self_: u32;
    fn task_info(task: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
    fn getpagesize() -> i32;
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> i32;
    fn madvise(address: *mut c_void, length: usize, advice: i32) -> i32;
    fn sys_icache_invalidate(start: *mut c_void, length: usize);
}

#[cfg(test)]
#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct TaskVmInfoRev1 {
    virtual_size: u64,
    region_count: i32,
    page_size: i32,
    resident_size: u64,
    resident_size_peak: u64,
    device: u64,
    device_peak: u64,
    internal: u64,
    internal_peak: u64,
    external: u64,
    external_peak: u64,
    reusable: u64,
    reusable_peak: u64,
    purgeable_volatile_pmap: u64,
    purgeable_volatile_resident: u64,
    purgeable_volatile_virtual: u64,
    compressed: u64,
    compressed_peak: u64,
    compressed_lifetime: u64,
    phys_footprint: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemorySample {
    pub phys_footprint: u64,
    pub resident: u64,
    pub reusable: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeMode {
    Release,
    NegativeControl,
    #[cfg(test)]
    HangControl {
        teardown_delay: Duration,
        completion_delay: Duration,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReport {
    pub qualification: ReclaimQualification,
    pub baseline: MemorySample,
    pub touched: MemorySample,
    pub released: MemorySample,
    pub retouched: Option<MemorySample>,
    pub elapsed: Duration,
    pub detail: String,
}

#[derive(Debug)]
pub struct ProbeCleanupError(String);

impl Display for ProbeCleanupError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "scratch reclaim probe cleanup failed: {}", self.0)
    }
}

impl std::error::Error for ProbeCleanupError {}

enum ProbeSetupError {
    Operation(String),
    Cleanup(ProbeCleanupError),
}

struct HostMapping {
    address: *mut c_void,
    length: usize,
    live: bool,
}

impl HostMapping {
    fn anonymous(length: usize) -> Result<Self, String> {
        let address = unsafe {
            mmap(
                ptr::null_mut(),
                length,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        if address as usize == usize::MAX {
            return Err(format!(
                "anonymous mmap: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            address,
            length,
            live: true,
        })
    }

    fn close(&mut self) -> Result<(), String> {
        if !self.live {
            return Ok(());
        }
        if unsafe { munmap(self.address, self.length) } != 0 {
            return Err(format!("host munmap: {}", std::io::Error::last_os_error()));
        }
        self.live = false;
        Ok(())
    }

    fn leak(&mut self) {
        self.live = false;
    }
}

impl Drop for HostMapping {
    fn drop(&mut self) {
        if self.live && unsafe { munmap(self.address, self.length) } != 0 {
            log::error!(
                "failed emergency scratch host munmap: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

struct ScratchMappings {
    code: HostMapping,
    data: HostMapping,
    code_gpa: u64,
    data_gpa: u64,
    code_mapped: bool,
    data_mapped: bool,
}

impl ScratchMappings {
    fn create(
        code_gpa: u64,
        data_gpa: u64,
        page_size: usize,
        mode: ProbeMode,
        vm_lifetime: &HvfVmLifetime,
    ) -> Result<Self, ProbeSetupError> {
        let mut code = HostMapping::anonymous(page_size).map_err(ProbeSetupError::Operation)?;
        let mut data = match HostMapping::anonymous(DATA_SIZE) {
            Ok(data) => data,
            Err(error) => {
                code.close()
                    .map_err(|cleanup| ProbeSetupError::Cleanup(ProbeCleanupError(cleanup)))?;
                return Err(ProbeSetupError::Operation(error));
            }
        };
        unsafe {
            let program = match mode {
                ProbeMode::Release | ProbeMode::NegativeControl => TOUCH_PROGRAM.as_slice(),
                #[cfg(test)]
                ProbeMode::HangControl { .. } => &[0x1400_0000],
            };
            ptr::copy_nonoverlapping(
                program.as_ptr().cast::<u8>(),
                code.address.cast::<u8>(),
                size_of_val(program),
            );
            code.address.cast::<u32>().add(0x200 / 4).write(0xd420_0000);
            sys_icache_invalidate(code.address, size_of_val(program));
            sys_icache_invalidate(code.address.cast::<u8>().add(0x200).cast(), 4);
        }
        if unsafe {
            hv_vm_map(
                code.address,
                code_gpa,
                page_size,
                (HV_MEMORY_READ | HV_MEMORY_EXEC).into(),
            )
        } != HV_SUCCESS
        {
            let mut failures = Vec::new();
            if let Err(error) = data.close() {
                failures.push(error);
            }
            if let Err(error) = code.close() {
                failures.push(error);
            }
            if !failures.is_empty() {
                return Err(ProbeSetupError::Cleanup(ProbeCleanupError(
                    failures.join(", "),
                )));
            }
            return Err(ProbeSetupError::Operation(
                "HVF rejected scratch code mapping".to_string(),
            ));
        }
        let mut mappings = Self {
            code,
            data,
            code_gpa,
            data_gpa,
            code_mapped: true,
            data_mapped: false,
        };
        if unsafe {
            hv_vm_map(
                mappings.data.address,
                data_gpa,
                DATA_SIZE,
                (HV_MEMORY_READ | HV_MEMORY_WRITE).into(),
            )
        } != HV_SUCCESS
        {
            if let Err(error) = mappings.close(page_size, vm_lifetime) {
                return Err(ProbeSetupError::Cleanup(error));
            }
            return Err(ProbeSetupError::Operation(
                "HVF rejected scratch data mapping".to_string(),
            ));
        }
        mappings.data_mapped = true;
        Ok(mappings)
    }

    fn release_data(&mut self) -> Result<(), String> {
        if unsafe { hv_vm_unmap(self.data_gpa, DATA_SIZE) } != HV_SUCCESS {
            return Err("HVF rejected scratch data release".to_string());
        }
        self.data_mapped = false;
        if unsafe { madvise(self.data.address, DATA_SIZE, MADV_FREE_REUSABLE) } != 0 {
            return Err(format!(
                "scratch MADV_FREE_REUSABLE: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn restore_data(&mut self) -> Result<(), String> {
        if unsafe { madvise(self.data.address, DATA_SIZE, MADV_FREE_REUSE) } != 0 {
            return Err(format!(
                "scratch MADV_FREE_REUSE: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe {
            hv_vm_map(
                self.data.address,
                self.data_gpa,
                DATA_SIZE,
                (HV_MEMORY_READ | HV_MEMORY_WRITE).into(),
            )
        } != HV_SUCCESS
        {
            return Err("HVF rejected scratch data restore".to_string());
        }
        self.data_mapped = true;
        Ok(())
    }

    fn close(
        &mut self,
        page_size: usize,
        vm_lifetime: &HvfVmLifetime,
    ) -> Result<(), ProbeCleanupError> {
        let mut failures = Vec::new();
        if self.data_mapped {
            if unsafe { hv_vm_unmap(self.data_gpa, DATA_SIZE) } != HV_SUCCESS {
                failures.push("scratch data HVF unmap".to_string());
            } else {
                self.data_mapped = false;
            }
        }
        if self.code_mapped {
            if unsafe { hv_vm_unmap(self.code_gpa, page_size) } != HV_SUCCESS {
                failures.push("scratch code HVF unmap".to_string());
            } else {
                self.code_mapped = false;
            }
        }
        if requires_emergency_destroy(self.code_mapped, self.data_mapped)
            && vm_lifetime.destroy().is_ok()
        {
            self.data_mapped = false;
            self.code_mapped = false;
        } else if requires_emergency_destroy(self.code_mapped, self.data_mapped) {
            failures.push("emergency HVF VM destroy".to_string());
        }
        // HVF may still reference this backing. A fatal bounded leak is safer than
        // unmapping memory that a VM or vCPU can still access.
        if self.data_mapped {
            self.data.leak();
        }
        if self.code_mapped {
            self.code.leak();
        }
        if !self.data_mapped
            && let Err(error) = self.data.close()
        {
            failures.push(error);
        }
        if !self.code_mapped
            && let Err(error) = self.code.close()
        {
            failures.push(error);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ProbeCleanupError(failures.join(", ")))
        }
    }
}

enum ProbeEvent {
    RunStarted(u64),
    RunFinished,
}

struct ScratchVcpu {
    id: u64,
    exit: *mut hv_vcpu_exit_t,
}

impl ScratchVcpu {
    fn create() -> Result<Self, ProbeSetupError> {
        let mut id = 0;
        let mut exit = ptr::null_mut();
        if unsafe { hv_vcpu_create(&mut id, &mut exit, ptr::null_mut()) } != HV_SUCCESS {
            return Err(ProbeSetupError::Operation(
                "HVF rejected scratch vCPU creation".to_string(),
            ));
        }
        if exit.is_null() {
            if unsafe { hv_vcpu_destroy(id) } != HV_SUCCESS {
                return Err(ProbeSetupError::Cleanup(ProbeCleanupError(
                    "null scratch vCPU exit pointer and destroy failed".to_string(),
                )));
            }
            return Err(ProbeSetupError::Operation(
                "HVF returned a null scratch vCPU exit pointer".to_string(),
            ));
        }
        Ok(Self { id, exit })
    }

    fn run(
        &self,
        code_gpa: u64,
        data_gpa: u64,
        page_size: u64,
        seed: u64,
        events: &Sender<ProbeEvent>,
    ) -> Result<u64, String> {
        let _ = events.send(ProbeEvent::RunStarted(self.id));
        let result = run_touch_pass(self.id, self.exit, code_gpa, data_gpa, page_size, seed);
        let _ = events.send(ProbeEvent::RunFinished);
        result
    }

    fn close(self) -> Result<(), ProbeCleanupError> {
        if unsafe { hv_vcpu_destroy(self.id) } != HV_SUCCESS {
            Err(ProbeCleanupError(
                "HVF rejected scratch vCPU destruction".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

fn run_touch_pass(
    id: u64,
    exit: *mut hv_vcpu_exit_t,
    code_gpa: u64,
    data_gpa: u64,
    page_size: u64,
    seed: u64,
) -> Result<u64, String> {
    let page_count = u64::try_from(DATA_SIZE)
        .map_err(|_| "scratch size is not representable".to_string())?
        / page_size;
    for (register, value) in [
        (hv_reg_t_HV_REG_CPSR, PSTATE_EL1H_MASKED),
        (hv_reg_t_HV_REG_PC, code_gpa),
        (hv_reg_t_HV_REG_X0, data_gpa),
        (hv_reg_t_HV_REG_X1, page_count),
        (hv_reg_t_HV_REG_X2, page_size),
        (hv_reg_t_HV_REG_X3, seed),
        (hv_reg_t_HV_REG_X4, 0),
    ] {
        if unsafe { hv_vcpu_set_reg(id, register, value) } != HV_SUCCESS {
            return Err(format!("failed to initialize scratch register {register}"));
        }
    }
    let mut sctlr = 0;
    if unsafe { hv_vcpu_get_sys_reg(id, hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1, &mut sctlr) }
        != HV_SUCCESS
        || unsafe { hv_vcpu_set_sys_reg(id, hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1, sctlr & !1) }
            != HV_SUCCESS
    {
        return Err("failed to set scratch MMU-disabled state".to_string());
    }
    if unsafe { hv_vcpu_set_sys_reg(id, hv_sys_reg_t_HV_SYS_REG_VBAR_EL1, code_gpa) } != HV_SUCCESS
    {
        return Err("failed to set scratch exception vector".to_string());
    }
    if unsafe { hv_vcpu_set_trap_debug_exceptions(id, true) } != HV_SUCCESS {
        return Err("failed to configure scratch breakpoint trap".to_string());
    }
    if unsafe { hv_vcpu_run(id) } != HV_SUCCESS {
        return Err("failed to run scratch vCPU".to_string());
    }
    let exit =
        unsafe { exit.as_ref() }.ok_or_else(|| "scratch exit pointer vanished".to_string())?;
    if exit.reason != hv_exit_reason_t_HV_EXIT_REASON_EXCEPTION
        || (exit.exception.syndrome >> 26) & 0x3f != EC_AA64_BKPT
    {
        return Err(format!(
            "scratch vCPU stopped at unexpected exit reason={} syndrome={:#x} va={:#x} pa={:#x} code_gpa={code_gpa:#x} data_gpa={data_gpa:#x}",
            exit.reason,
            exit.exception.syndrome,
            exit.exception.virtual_address,
            exit.exception.physical_address
        ));
    }
    let mut pc = 0;
    if unsafe { hv_vcpu_get_reg(id, hv_reg_t_HV_REG_PC, &mut pc) } != HV_SUCCESS {
        return Err("failed to read scratch trap PC".to_string());
    }
    if pc != code_gpa + 8 * 4 {
        let mut esr = 0;
        let mut far = 0;
        let esr_status =
            unsafe { hv_vcpu_get_sys_reg(id, hv_sys_reg_t_HV_SYS_REG_ESR_EL1, &mut esr) };
        let far_status =
            unsafe { hv_vcpu_get_sys_reg(id, hv_sys_reg_t_HV_SYS_REG_FAR_EL1, &mut far) };
        return Err(format!(
            "scratch guest took an exception: trap_pc={pc:#x} esr={esr:#x} far={far:#x} esr_status={esr_status} far_status={far_status}"
        ));
    }
    let mut checksum = 0;
    if unsafe { hv_vcpu_get_reg(id, hv_reg_t_HV_REG_X0, &mut checksum) } != HV_SUCCESS {
        return Err("failed to read scratch checksum".to_string());
    }
    Ok(checksum)
}

pub fn run_reclaim_probe<T: Send + 'static>(
    ipa_bits: u32,
    occupied: &[GuestRange],
    mode: ProbeMode,
    vm_lifetime: std::sync::Arc<HvfVmLifetime>,
    parent_lifetime: T,
) -> Result<ProbeReport, ProbeCleanupError> {
    run_reclaim_probe_with_start(
        ipa_bits,
        occupied,
        mode,
        vm_lifetime,
        parent_lifetime,
        || {},
    )
}

fn run_reclaim_probe_with_start<T: Send + 'static, F: FnOnce() + Send + 'static>(
    ipa_bits: u32,
    occupied: &[GuestRange],
    mode: ProbeMode,
    vm_lifetime: std::sync::Arc<HvfVmLifetime>,
    parent_lifetime: T,
    worker_started: F,
) -> Result<ProbeReport, ProbeCleanupError> {
    let occupied = occupied.to_vec();
    let (events_tx, events_rx) = channel();
    let worker = thread::spawn(move || {
        worker_started();
        let result = run_owned_reclaim_probe(ipa_bits, &occupied, mode, events_tx, &vm_lifetime);
        drop(vm_lifetime);
        drop(parent_lifetime);
        result
    });
    wait_for_probe_worker(worker, events_rx)
}

fn wait_for_probe_worker(
    worker: JoinHandle<Result<ProbeReport, ProbeCleanupError>>,
    events: Receiver<ProbeEvent>,
) -> Result<ProbeReport, ProbeCleanupError> {
    let mut running_vcpu = None;
    let mut watchdog_canceled = false;
    let mut deadline = Instant::now() + CLEANUP_DEADLINE;
    loop {
        let now = Instant::now();
        if now >= deadline {
            let Some(mut id) = running_vcpu.take() else {
                return Err(ProbeCleanupError(
                    "scratch probe worker exceeded its bounded non-execution phase".to_string(),
                ));
            };
            if unsafe { hv_vcpus_exit(&mut id, 1) } != HV_SUCCESS {
                return Err(ProbeCleanupError(
                    "scratch vCPU deadline and hv_vcpus_exit failed; worker retains all VM memory ownership"
                        .to_string(),
                ));
            }
            watchdog_canceled = true;
            deadline = Instant::now() + CLEANUP_DEADLINE;
            continue;
        }
        if worker.is_finished() {
            let mut report = worker
                .join()
                .map_err(|_| ProbeCleanupError("scratch probe worker panicked".to_string()))??;
            if watchdog_canceled {
                report.qualification = ReclaimQualification::Failed;
                report.detail = format!(
                    "watchdog cancellation and worker teardown completed; {}",
                    report.detail
                );
            }
            return Ok(report);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(10));
        match events.recv_timeout(wait) {
            Ok(ProbeEvent::RunStarted(id)) => {
                running_vcpu = Some(id);
                deadline = Instant::now() + RUN_DEADLINE;
            }
            Ok(ProbeEvent::RunFinished) => {
                running_vcpu = None;
                deadline = Instant::now() + CLEANUP_DEADLINE;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {}
        }
    }
}

fn run_owned_reclaim_probe(
    ipa_bits: u32,
    occupied: &[GuestRange],
    mode: ProbeMode,
    events: Sender<ProbeEvent>,
    vm_lifetime: &HvfVmLifetime,
) -> Result<ProbeReport, ProbeCleanupError> {
    let started = Instant::now();
    let page_size = match usize::try_from(unsafe { getpagesize() }) {
        Ok(size) if size.is_power_of_two() && DATA_SIZE.is_multiple_of(size) => size,
        _ => {
            return Ok(inconclusive_report(started, "unsupported host page size"));
        }
    };
    let (code_gpa, data_gpa) = match choose_scratch_gpas(ipa_bits, occupied, page_size as u64) {
        Some(gpas) => gpas,
        None => {
            return Ok(inconclusive_report(
                started,
                "no disjoint scratch GPA range",
            ));
        }
    };
    let mut mappings =
        match ScratchMappings::create(code_gpa, data_gpa, page_size, mode, vm_lifetime) {
            Ok(mappings) => mappings,
            Err(ProbeSetupError::Operation(error)) => return Ok(failed_report(started, error)),
            Err(ProbeSetupError::Cleanup(error)) => return Err(error),
        };
    let vcpu = match ScratchVcpu::create() {
        Ok(vcpu) => vcpu,
        Err(ProbeSetupError::Operation(error)) => {
            mappings.close(page_size, vm_lifetime)?;
            return Ok(failed_report(started, error));
        }
        Err(ProbeSetupError::Cleanup(vcpu_error)) => {
            if vm_lifetime.destroy().is_ok() {
                mappings.code_mapped = false;
                mappings.data_mapped = false;
            }
            return match mappings.close(page_size, vm_lifetime) {
                Ok(()) => Err(vcpu_error),
                Err(mapping_error) => {
                    Err(ProbeCleanupError(format!("{vcpu_error}; {mapping_error}")))
                }
            };
        }
    };

    let probe_result = run_probe_steps(&mut mappings, &vcpu, page_size, mode, started, &events);
    #[cfg(test)]
    if let ProbeMode::HangControl { teardown_delay, .. } = mode {
        thread::sleep(teardown_delay);
    }
    let vcpu_cleanup = vcpu.close();
    if vcpu_cleanup.is_err() && vm_lifetime.destroy().is_ok() {
        mappings.code_mapped = false;
        mappings.data_mapped = false;
    }
    let mapping_cleanup = mappings.close(page_size, vm_lifetime);
    let result = match (vcpu_cleanup, mapping_cleanup) {
        (Ok(()), Ok(())) => Ok(probe_result),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(vcpu_error), Err(mapping_error)) => {
            Err(ProbeCleanupError(format!("{vcpu_error}; {mapping_error}")))
        }
    };
    #[cfg(test)]
    if let ProbeMode::HangControl {
        completion_delay, ..
    } = mode
    {
        thread::sleep(completion_delay);
    }
    result
}

fn run_probe_steps(
    mappings: &mut ScratchMappings,
    vcpu: &ScratchVcpu,
    page_size: usize,
    mode: ProbeMode,
    started: Instant,
    events: &Sender<ProbeEvent>,
) -> ProbeReport {
    let baseline = match memory_sample() {
        Ok(sample) => sample,
        Err(error) => return inconclusive_report(started, error),
    };
    let first_seed = 0x4b52_554e_u64;
    let expected = expected_checksum(first_seed, DATA_SIZE / page_size);
    match vcpu.run(
        mappings.code_gpa,
        mappings.data_gpa,
        page_size as u64,
        first_seed,
        events,
    ) {
        Ok(checksum) if checksum == expected => {}
        Ok(checksum) => {
            return report_with_samples(
                ReclaimQualification::Failed,
                started,
                baseline,
                MemorySample::default(),
                MemorySample::default(),
                None,
                format!("first guest checksum mismatch: expected {expected:#x}, got {checksum:#x}"),
            );
        }
        Err(error) => return failed_report_with_baseline(started, baseline, error),
    }
    if !host_pages_match(&mappings.data, page_size, first_seed) {
        return failed_report_with_baseline(
            started,
            baseline,
            "first guest touch was not visible in every host page".to_string(),
        );
    }
    let touched = match memory_sample() {
        Ok(sample) => sample,
        Err(error) => return inconclusive_report_with_samples(started, baseline, error),
    };
    let charged = touched
        .phys_footprint
        .saturating_sub(baseline.phys_footprint);
    if !at_least_percent(charged, DATA_SIZE as u64, REQUIRED_PERCENT) {
        return report_with_samples(
            ReclaimQualification::Inconclusive,
            started,
            baseline,
            touched,
            MemorySample::default(),
            None,
            format!("footprint rise {charged} bytes is below 75% of {DATA_SIZE}"),
        );
    }

    if mode == ProbeMode::Release
        && let Err(error) = mappings.release_data()
    {
        return failed_report_with_touched(started, baseline, touched, error);
    }
    thread::sleep(ACCOUNTING_SETTLE);
    let released = match memory_sample() {
        Ok(sample) => sample,
        Err(error) => {
            return inconclusive_report_with_touched(started, baseline, touched, error);
        }
    };
    let dropped = touched
        .phys_footprint
        .saturating_sub(released.phys_footprint);
    if mode == ProbeMode::NegativeControl {
        let absent = at_most_percent(dropped, charged, ABSENT_DROP_PERCENT);
        return report_with_samples(
            if absent {
                ReclaimQualification::Passed
            } else {
                ReclaimQualification::Failed
            },
            started,
            baseline,
            touched,
            released,
            None,
            format!(
                "negative-control charged={charged} dropped={dropped} resident={} reusable={}",
                released.resident, released.reusable
            ),
        );
    }
    if !at_least_percent(dropped, charged, REQUIRED_PERCENT) {
        return report_with_samples(
            ReclaimQualification::Failed,
            started,
            baseline,
            touched,
            released,
            None,
            format!("footprint drop {dropped} bytes is below 75% of charged {charged}"),
        );
    }
    if let Err(error) = mappings.restore_data() {
        return failed_report_with_release(started, baseline, touched, released, error);
    }
    let second_seed = 0x5349_4c4f_u64;
    let second_expected = expected_checksum(second_seed, DATA_SIZE / page_size);
    match vcpu.run(
        mappings.code_gpa,
        mappings.data_gpa,
        page_size as u64,
        second_seed,
        events,
    ) {
        Ok(checksum) if checksum == second_expected => {}
        Ok(checksum) => {
            return failed_report_with_release(
                started,
                baseline,
                touched,
                released,
                format!(
                    "second guest checksum mismatch: expected {second_expected:#x}, got {checksum:#x}"
                ),
            );
        }
        Err(error) => {
            return failed_report_with_release(started, baseline, touched, released, error);
        }
    }
    if !host_pages_match(&mappings.data, page_size, second_seed) {
        return failed_report_with_release(
            started,
            baseline,
            touched,
            released,
            "second guest touch was not visible in every host page".to_string(),
        );
    }
    let retouched = match memory_sample() {
        Ok(sample) => sample,
        Err(error) => {
            return inconclusive_report_with_release(started, baseline, touched, released, error);
        }
    };
    let recharged = retouched
        .phys_footprint
        .saturating_sub(released.phys_footprint);
    let qualification = if at_least_percent(recharged, DATA_SIZE as u64, REQUIRED_PERCENT) {
        ReclaimQualification::Passed
    } else {
        ReclaimQualification::Failed
    };
    report_with_samples(
        qualification,
        started,
        baseline,
        touched,
        released,
        Some(retouched),
        format!(
            "charged={charged} dropped={dropped} recharged={recharged} resident={}/{}/{} reusable={}/{}/{}",
            touched.resident,
            released.resident,
            retouched.resident,
            touched.reusable,
            released.reusable,
            retouched.reusable
        ),
    )
}

pub(crate) fn memory_sample() -> Result<MemorySample, String> {
    let mut info = MaybeUninit::<TaskVmInfoRev1>::zeroed();
    let mut count = u32::try_from(size_of::<TaskVmInfoRev1>() / size_of::<i32>())
        .map_err(|_| "TASK_VM_INFO count is not representable".to_string())?;
    let status = unsafe {
        task_info(
            mach_task_self_,
            TASK_VM_INFO,
            info.as_mut_ptr().cast::<i32>(),
            &mut count,
        )
    };
    if status != 0 {
        return Err(format!("TASK_VM_INFO failed with Mach status {status}"));
    }
    if usize::try_from(count).unwrap_or(0) * size_of::<i32>() < size_of::<TaskVmInfoRev1>() {
        return Err(format!("TASK_VM_INFO returned short count {count}"));
    }
    let info = unsafe { info.assume_init() };
    Ok(MemorySample {
        phys_footprint: info.phys_footprint,
        resident: info.resident_size,
        reusable: info.reusable,
    })
}

fn choose_scratch_gpas(
    ipa_bits: u32,
    occupied: &[GuestRange],
    page_size: u64,
) -> Option<(u64, u64)> {
    if ipa_bits == 0 || ipa_bits >= 64 || !page_size.is_power_of_two() {
        return None;
    }
    let total = page_size.checked_add(DATA_SIZE as u64)?;
    let cap = 1_u64.checked_shl(ipa_bits)?;
    let mut start = 0_u64;
    loop {
        let candidate_end = start.checked_add(total)?;
        if candidate_end > cap {
            return None;
        }
        let overlap = occupied
            .iter()
            .filter(|range| {
                start < range.start() + range.byte_len() && range.start() < candidate_end
            })
            .max_by_key(|range| range.start() + range.byte_len());
        match overlap {
            None => return Some((start, start.checked_add(page_size)?)),
            Some(range) => {
                start = align_up(range.start().checked_add(range.byte_len())?, page_size)?
            }
        }
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn requires_emergency_destroy(code_mapped: bool, data_mapped: bool) -> bool {
    code_mapped || data_mapped
}

fn expected_checksum(seed: u64, pages: usize) -> u64 {
    let pages = pages as u64;
    pages
        .wrapping_mul(seed)
        .wrapping_add(pages.wrapping_mul(pages.saturating_sub(1)) / 2)
}

fn host_pages_match(mapping: &HostMapping, page_size: usize, seed: u64) -> bool {
    (0..DATA_SIZE / page_size).all(|page| {
        let value = unsafe {
            mapping
                .address
                .cast::<u8>()
                .add(page * page_size)
                .cast::<u64>()
                .read_volatile()
        };
        value == seed.wrapping_add(page as u64)
    })
}

fn at_least_percent(value: u64, reference: u64, percent: u64) -> bool {
    (value as u128) * 100 >= (reference as u128) * (percent as u128)
}

fn at_most_percent(value: u64, reference: u64, percent: u64) -> bool {
    (value as u128) * 100 <= (reference as u128) * (percent as u128)
}

fn report_with_samples(
    qualification: ReclaimQualification,
    started: Instant,
    baseline: MemorySample,
    touched: MemorySample,
    released: MemorySample,
    retouched: Option<MemorySample>,
    detail: String,
) -> ProbeReport {
    ProbeReport {
        qualification,
        baseline,
        touched,
        released,
        retouched,
        elapsed: started.elapsed(),
        detail,
    }
}

fn inconclusive_report(started: Instant, detail: impl Into<String>) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Inconclusive,
        started,
        MemorySample::default(),
        MemorySample::default(),
        MemorySample::default(),
        None,
        detail.into(),
    )
}

fn failed_report(started: Instant, detail: impl Into<String>) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Failed,
        started,
        MemorySample::default(),
        MemorySample::default(),
        MemorySample::default(),
        None,
        detail.into(),
    )
}

fn failed_report_with_baseline(
    started: Instant,
    baseline: MemorySample,
    detail: String,
) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Failed,
        started,
        baseline,
        MemorySample::default(),
        MemorySample::default(),
        None,
        detail,
    )
}

fn inconclusive_report_with_samples(
    started: Instant,
    baseline: MemorySample,
    detail: String,
) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Inconclusive,
        started,
        baseline,
        MemorySample::default(),
        MemorySample::default(),
        None,
        detail,
    )
}

fn failed_report_with_touched(
    started: Instant,
    baseline: MemorySample,
    touched: MemorySample,
    detail: String,
) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Failed,
        started,
        baseline,
        touched,
        MemorySample::default(),
        None,
        detail,
    )
}

fn inconclusive_report_with_touched(
    started: Instant,
    baseline: MemorySample,
    touched: MemorySample,
    detail: String,
) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Inconclusive,
        started,
        baseline,
        touched,
        MemorySample::default(),
        None,
        detail,
    )
}

fn failed_report_with_release(
    started: Instant,
    baseline: MemorySample,
    touched: MemorySample,
    released: MemorySample,
    detail: String,
) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Failed,
        started,
        baseline,
        touched,
        released,
        None,
        detail,
    )
}

fn inconclusive_report_with_release(
    started: Instant,
    baseline: MemorySample,
    touched: MemorySample,
    released: MemorySample,
    detail: String,
) -> ProbeReport {
    report_with_samples(
        ReclaimQualification::Inconclusive,
        started,
        baseline,
        touched,
        released,
        None,
        detail,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::process::Command;
    use std::sync::Arc;

    use arch::guest_memory::GuestRange;

    use crate::probe::{
        ABSENT_DROP_PERCENT, DATA_SIZE, REQUIRED_PERCENT, at_least_percent, at_most_percent,
        choose_scratch_gpas, expected_checksum, requires_emergency_destroy,
    };

    #[test]
    fn qualification_thresholds_do_not_round_down() {
        let size = DATA_SIZE as u64;
        assert!(at_least_percent(size * 3 / 4, size, REQUIRED_PERCENT));
        assert!(!at_least_percent(size * 3 / 4 - 1, size, REQUIRED_PERCENT));
        assert!(at_most_percent(size / 4, size, ABSENT_DROP_PERCENT));
        assert!(!at_most_percent(size / 4 + 1, size, ABSENT_DROP_PERCENT));
    }

    #[test]
    fn scratch_gpa_selection_avoids_occupied_ranges_and_ipa_cap() {
        let page = 0x4000;
        let cap = 1_u64 << 36;
        let top = GuestRange::new(cap - 0x40_0000, 0x40_0000).unwrap();
        let middle = GuestRange::new(cap - 0x80_0000, 0x20_0000).unwrap();
        let low = GuestRange::new(0, 0x8000_0000).unwrap();
        let (code, data) = choose_scratch_gpas(36, &[middle, top, low], page).unwrap();
        assert_eq!(code, low.start() + low.byte_len());
        assert_eq!(data, code + page);
        assert!(data + DATA_SIZE as u64 <= middle.start());
    }

    #[test]
    fn scratch_gpa_selection_rejects_invalid_caps_and_full_space() {
        assert_eq!(choose_scratch_gpas(64, &[], 0x4000), None);
        assert_eq!(choose_scratch_gpas(36, &[], 0x3000), None);
        assert_eq!(
            choose_scratch_gpas(32, &[GuestRange::new(0, 1_u64 << 32).unwrap()], 0x4000),
            None
        );
    }

    #[test]
    fn checksum_matches_wrapping_guest_accumulation() {
        let seed = u64::MAX - 3;
        let expected =
            (0_u64..128).fold(0_u64, |sum, page| sum.wrapping_add(seed.wrapping_add(page)));
        assert_eq!(expected_checksum(seed, 128), expected);
    }

    #[test]
    fn cleanup_escalates_while_any_stage_two_mapping_remains() {
        assert!(!requires_emergency_destroy(false, false));
        assert!(requires_emergency_destroy(true, false));
        assert!(requires_emergency_destroy(false, true));
        assert!(requires_emergency_destroy(true, true));
    }

    #[test]
    fn task_vm_info_layout_matches_public_sdk_headers() {
        let sdk = Command::new("xcrun")
            .arg("--show-sdk-path")
            .output()
            .unwrap();
        assert!(sdk.status.success());
        let sdk = String::from_utf8(sdk.stdout).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "libkrun-task-vm-info-layout-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let executable = directory.join("layout");
        let source =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/task_vm_info_layout.c");
        let compile = Command::new("/usr/bin/clang")
            .args(["-isysroot", sdk.trim()])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let output = Command::new(&executable).output().unwrap();
        assert!(output.status.success());
        let values: HashMap<_, _> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| {
                let (name, value) = line.split_once('=').unwrap();
                (name.to_string(), value.parse::<usize>().unwrap())
            })
            .collect();

        assert_eq!(
            size_of::<super::TaskVmInfoRev1>() / size_of::<i32>(),
            values["rev1_count"]
        );
        assert!(values["full_count"] * size_of::<i32>() <= values["full_size"]);
        assert_eq!(
            std::mem::offset_of!(super::TaskVmInfoRev1, resident_size),
            values["resident_offset"]
        );
        assert_eq!(
            std::mem::offset_of!(super::TaskVmInfoRev1, reusable),
            values["reusable_offset"]
        );
        assert_eq!(
            std::mem::offset_of!(super::TaskVmInfoRev1, phys_footprint),
            values["footprint_offset"]
        );

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
    fn real_hvf_guest_touch_positive_and_negative_controls() {
        use crate::HvfVmLifetime;
        use crate::bindings::{
            HV_SUCCESS, hv_vm_config_create, hv_vm_config_get_ipa_size, hv_vm_create,
        };
        use crate::probe::{ProbeMode, run_reclaim_probe};
        use crate::reclaim::ReclaimQualification;

        let config = unsafe { hv_vm_config_create() };
        let mut ipa_bits = 0;
        assert_eq!(
            unsafe { hv_vm_config_get_ipa_size(config, &mut ipa_bits) },
            HV_SUCCESS
        );
        assert_eq!(unsafe { hv_vm_create(config) }, HV_SUCCESS);
        let vm_lifetime = Arc::new(HvfVmLifetime::new());
        let occupied = [GuestRange::new(0, 0x8000_0000).unwrap()];
        let negative = run_reclaim_probe(
            ipa_bits,
            &occupied,
            ProbeMode::NegativeControl,
            Arc::clone(&vm_lifetime),
            (),
        );
        let positive = if negative.is_ok() {
            Some(run_reclaim_probe(
                ipa_bits,
                &occupied,
                ProbeMode::Release,
                Arc::clone(&vm_lifetime),
                (),
            ))
        } else {
            None
        };
        let destroy = vm_lifetime.destroy();

        assert!(destroy.is_ok());
        eprintln!("ipa_bits={ipa_bits} host_page_size={}", unsafe {
            super::getpagesize()
        });
        let negative = negative.unwrap();
        eprintln!("negative control: {negative:?}");
        assert_eq!(negative.qualification, ReclaimQualification::Passed);
        let positive = positive.unwrap().unwrap();
        eprintln!("positive control: {positive:?}");
        assert_eq!(positive.qualification, ReclaimQualification::Passed);
    }

    #[test]
    #[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
    fn real_hvf_hung_guest_is_canceled_before_worker_completion() {
        use std::sync::mpsc::sync_channel;
        use std::time::{Duration, Instant};

        use crate::probe::{ProbeMode, run_reclaim_probe_with_start};
        use crate::reclaim::ReclaimQualification;
        use crate::{Error, HvfVm};

        let vm = HvfVm::new(false).unwrap();
        let ipa_bits = vm.ipa_bits.unwrap();
        let final_owner = Arc::clone(&vm.lifetime);
        let worker_owner = Arc::clone(&vm.lifetime);
        let occupied = [GuestRange::new(0, 0x8000_0000).unwrap()];
        let (started_tx, started_rx) = sync_channel(0);
        let (proceed_tx, proceed_rx) = sync_channel(0);
        let started = Instant::now();
        let probe = std::thread::spawn(move || {
            run_reclaim_probe_with_start(
                ipa_bits,
                &occupied,
                ProbeMode::HangControl {
                    teardown_delay: Duration::from_millis(100),
                    completion_delay: Duration::from_millis(100),
                },
                worker_owner,
                (),
                move || {
                    started_tx.send(()).unwrap();
                    proceed_rx.recv().unwrap();
                },
            )
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let busy_destroy = vm.destroy();
        assert!(matches!(&busy_destroy, Err(Error::VmBusy)));
        proceed_tx.send(()).unwrap();
        let result = probe.join().unwrap();
        let elapsed = started.elapsed();
        let final_owner = Arc::try_unwrap(final_owner).ok().unwrap();
        let destroy = final_owner.destroy();

        eprintln!("worker-owned destroy={busy_destroy:?} final destroy={destroy:?}");
        assert!(destroy.is_ok());
        let report = result.unwrap();
        eprintln!("timeout control elapsed={elapsed:?}: {report:?}");
        assert_eq!(report.qualification, ReclaimQualification::Failed);
        assert!(report.detail.contains("watchdog cancellation"));
        assert!(elapsed >= Duration::from_millis(1200));
        assert!(elapsed < Duration::from_secs(2));
    }
}
