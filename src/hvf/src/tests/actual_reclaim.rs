// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Real Hypervisor.framework coverage for the release cycle. Each scenario
//! runs in an isolated, ad-hoc code-signed child process because HVF allows
//! one VM per process and needs the hypervisor entitlement.

use std::ffi::c_void;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use arch::guest_memory::{GuestRange, RamLayout, RamPermissions, RamRegion};

use crate::bindings::{
    HV_SUCCESS, hv_reg_t_HV_REG_CPSR, hv_reg_t_HV_REG_PC, hv_reg_t_HV_REG_X0, hv_reg_t_HV_REG_X1,
    hv_reg_t_HV_REG_X2, hv_reg_t_HV_REG_X3, hv_reg_t_HV_REG_X4, hv_reg_t_HV_REG_X5,
    hv_reg_t_HV_REG_X6, hv_reg_t_HV_REG_X7, hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_VBAR_EL1, hv_vcpu_destroy, hv_vcpu_get_reg, hv_vcpu_get_sys_reg,
    hv_vcpu_set_reg, hv_vcpu_set_sys_reg, hv_vcpu_set_trap_debug_exceptions,
};
use crate::discard::PageState;
use crate::probe::{
    DATA_SIZE, PSTATE_EL1H_MASKED, TOUCH_PROGRAM, expected_checksum, memory_sample,
};
use crate::reclaim::{ReclaimState, ReleaseOutcome};
use crate::{HvfVcpu, HvfVm, VcpuExit, Vcpus};

const HOST_PAGE_SIZE: usize = 0x4000;
const CODE_GPA: u64 = 0x4000_0000;
const DATA_GPA: u64 = 0x5000_0000;
const CONTROL_GPA: u64 = 0x6000_0000;
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);
const BRK: u32 = 0xd420_0000;

unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> i32;
    fn sys_icache_invalidate(start: *mut c_void, length: usize);
    fn madvise(address: *mut c_void, length: usize, advice: i32) -> i32;
}

struct NullVcpus;

impl Vcpus for NullVcpus {
    fn set_vtimer_irq(&self, _vcpuid: u64) {}
    fn should_wait(&self, _vcpuid: u64) -> bool {
        false
    }
    fn has_pending_irq(&self, _vcpuid: u64) -> bool {
        false
    }
    fn get_pending_irq(&self, _vcpuid: u64) -> u32 {
        0
    }
    fn handle_sysreg_read(&self, _vcpuid: u64, _reg: u32) -> Option<u64> {
        None
    }
    fn handle_sysreg_write(&self, _vcpuid: u64, _reg: u32, _val: u64) -> bool {
        false
    }
}

struct HostMapping {
    address: *mut u8,
    length: usize,
}

unsafe impl Send for HostMapping {}
unsafe impl Sync for HostMapping {}

impl HostMapping {
    fn new(length: usize) -> Self {
        let address = unsafe { mmap(ptr::null_mut(), length, 0x1 | 0x2, 0x0002 | 0x1000, -1, 0) };
        assert_ne!(address as usize, usize::MAX, "anonymous mmap failed");
        Self {
            address: address.cast(),
            length,
        }
    }

    fn write_words(&self, words: &[u32]) {
        assert!(size_of_val(words) <= self.length);
        unsafe {
            ptr::copy_nonoverlapping(
                words.as_ptr().cast::<u8>(),
                self.address,
                size_of_val(words),
            );
            sys_icache_invalidate(self.address.cast(), size_of_val(words));
        }
    }

    /// First word of every host page, as the touch program writes them.
    fn page_words(&self) -> Vec<u64> {
        (0..self.length / HOST_PAGE_SIZE)
            .map(|page| unsafe {
                ptr::read_volatile(self.address.add(page * HOST_PAGE_SIZE).cast::<u64>())
            })
            .collect()
    }
}

impl Drop for HostMapping {
    fn drop(&mut self) {
        assert_eq!(unsafe { munmap(self.address.cast(), self.length) }, 0);
    }
}

struct Fixture {
    vm: Option<HvfVm>,
    mappings: Vec<(u64, HostMapping)>,
}

impl Fixture {
    fn new(regions: &[(u64, usize)]) -> Self {
        Self::with_host_population(regions, false)
    }

    fn with_host_population(regions: &[(u64, usize)], populate: bool) -> Self {
        let vm = HvfVm::new(false).expect("create HVF VM");
        let mut layout = RamLayout::new(HOST_PAGE_SIZE as u64).expect("create layout");
        let mut mappings = Vec::new();
        for (gpa, length) in regions {
            let mapping = HostMapping::new(*length);
            if populate {
                unsafe { ptr::write_bytes(mapping.address, 0x5a, mapping.length) };
            }
            vm.map_memory(mapping.address as u64, *gpa, *length as u64)
                .expect("map fixture RAM");
            layout
                .register_region(
                    RamRegion::new(
                        *gpa,
                        mapping.address as u64,
                        *length as u64,
                        RamPermissions::READ_WRITE_EXECUTE,
                    )
                    .expect("fixture RAM region"),
                )
                .expect("register fixture RAM");
            mappings.push((*gpa, mapping));
        }
        vm.initialize_reclaim(layout)
            .expect("install reclaim layout");
        let state = vm.reclaim_state();
        state.enable_policy_for_test();
        state.qualify_for_test();
        assert!(state.is_effective());
        Self {
            vm: Some(vm),
            mappings,
        }
    }

    fn state(&self) -> Arc<ReclaimState> {
        self.vm.as_ref().expect("live VM").reclaim_state()
    }

    fn mapping(&self, gpa: u64) -> &HostMapping {
        &self
            .mappings
            .iter()
            .find(|(candidate, _)| *candidate == gpa)
            .expect("known mapping")
            .1
    }

    fn close(mut self) {
        let vm = self.vm.take().expect("live VM");
        for (gpa, mapping) in &self.mappings {
            vm.unmap_memory(*gpa, mapping.length as u64)
                .expect("unmap fixture RAM");
        }
        vm.destroy().expect("destroy HVF VM");
    }
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

/// Creates a vCPU on the calling thread (HVF vCPUs are thread-bound) that
/// starts at `pc` with the MMU disabled and breakpoints trapped to the host.
fn create_vcpu(mpidr: u64, pc: u64) -> HvfVcpu<'static> {
    let vcpu = HvfVcpu::new(mpidr, false).expect("create vCPU");
    vcpu.set_initial_state(pc, 0).expect("initialize vCPU");
    let mut sctlr = 0;
    assert_eq!(
        unsafe { hv_vcpu_get_sys_reg(vcpu.id(), hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1, &mut sctlr) },
        HV_SUCCESS
    );
    assert_eq!(
        unsafe { hv_vcpu_set_sys_reg(vcpu.id(), hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1, sctlr & !1) },
        HV_SUCCESS
    );
    assert_eq!(
        unsafe { hv_vcpu_set_sys_reg(vcpu.id(), hv_sys_reg_t_HV_SYS_REG_VBAR_EL1, pc) },
        HV_SUCCESS
    );
    assert_eq!(
        unsafe { hv_vcpu_set_trap_debug_exceptions(vcpu.id(), true) },
        HV_SUCCESS
    );
    vcpu
}

fn destroy_vcpu(vcpu: HvfVcpu<'_>) {
    assert_eq!(unsafe { hv_vcpu_destroy(vcpu.id()) }, HV_SUCCESS);
}

struct TouchRun {
    checksum: u64,
    retries: u32,
}

/// Runs the probe's touch program over `data_gpa` once: every page gets
/// `seed + index` stored and read back, and the guest returns the sum.
/// `MemoryRetry` exits are re-run until the guest hits its breakpoint.
fn run_touch(
    vcpu: &mut HvfVcpu<'_>,
    state: &Arc<ReclaimState>,
    data_gpa: u64,
    data_len: usize,
    seed: u64,
) -> TouchRun {
    for (register, value) in [
        (hv_reg_t_HV_REG_CPSR, PSTATE_EL1H_MASKED),
        (hv_reg_t_HV_REG_PC, CODE_GPA),
        (hv_reg_t_HV_REG_X0, data_gpa),
        (hv_reg_t_HV_REG_X1, (data_len / HOST_PAGE_SIZE) as u64),
        (hv_reg_t_HV_REG_X2, HOST_PAGE_SIZE as u64),
        (hv_reg_t_HV_REG_X3, seed),
        (hv_reg_t_HV_REG_X4, 0),
    ] {
        set_reg(vcpu, register, value);
    }
    let mut retries = 0;
    loop {
        match vcpu
            .run(Arc::new(NullVcpus), state)
            .expect("touch program run")
        {
            VcpuExit::Breakpoint => break,
            VcpuExit::MemoryRetry => retries += 1,
            other => panic!("unexpected touch exit: {other:?}"),
        }
    }
    assert_eq!(get_reg(vcpu, hv_reg_t_HV_REG_PC), CODE_GPA + 8 * 4);
    TouchRun {
        checksum: get_reg(vcpu, hv_reg_t_HV_REG_X0),
        retries,
    }
}

fn assert_page_pattern(mapping: &HostMapping, seed: u64) {
    for (index, word) in mapping.page_words().into_iter().enumerate() {
        assert_eq!(
            word,
            seed + index as u64,
            "page {index} lost its last write"
        );
    }
}

fn child_scenario(name: &str, scenario: fn()) {
    const CHILD_ENV: &str = "LIBKRUN_ACTUAL_HVF_CHILD";
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

/// Guest-only writes become discardable without host payload reads, and reuse
/// is handled in-kernel. Footprint changes are diagnostic, not the assertion.
fn release_cycle_scenario() {
    const DATA_LEN: usize = 2 * DATA_SIZE;
    let fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE), (DATA_GPA, DATA_LEN)]);
    fixture.mapping(CODE_GPA).write_words(&TOUCH_PROGRAM);
    let state = fixture.state();
    let pages = DATA_LEN / HOST_PAGE_SIZE;
    let mut vcpu = create_vcpu(0, CODE_GPA);

    let baseline = memory_sample().expect("baseline sample");
    let first = run_touch(&mut vcpu, &state, DATA_GPA, DATA_LEN, 0x1000);
    assert_eq!(first.checksum, expected_checksum(0x1000, pages));
    assert_eq!(first.retries, 0);
    thread::sleep(Duration::from_millis(20));
    let touched = memory_sample().expect("touched sample");

    let pages_before = PageState::sample(
        fixture.mapping(DATA_GPA).address.cast(),
        DATA_LEN,
        HOST_PAGE_SIZE,
    )
    .unwrap();
    let range = GuestRange::new(DATA_GPA, DATA_LEN as u64).expect("data range");
    let released_at = Instant::now();
    assert_eq!(
        state.release_report(range).expect("release data"),
        ReleaseOutcome::Released
    );
    let release_time = released_at.elapsed();
    thread::sleep(Duration::from_millis(20));
    let released = memory_sample().expect("released sample");
    let pages_after = PageState::sample(
        fixture.mapping(DATA_GPA).address.cast(),
        DATA_LEN,
        HOST_PAGE_SIZE,
    )
    .unwrap();
    eprintln!("page state before={pages_before:?} after={pages_after:?}");
    assert!(pages_after.is_discardable());

    let second = run_touch(&mut vcpu, &state, DATA_GPA, DATA_LEN, 0x2000);
    assert_eq!(second.checksum, expected_checksum(0x2000, pages));
    assert_eq!(
        second.retries, 0,
        "refault after remap must not exit to userspace"
    );
    assert_page_pattern(fixture.mapping(DATA_GPA), 0x2000);
    thread::sleep(Duration::from_millis(20));
    let retouched = memory_sample().expect("retouched sample");

    let stats = state.stats();
    let charged = touched
        .phys_footprint
        .saturating_sub(baseline.phys_footprint);
    let dropped = touched
        .phys_footprint
        .saturating_sub(released.phys_footprint);
    eprintln!(
        "release_cycle charged={charged} dropped={dropped} release_time={release_time:?} baseline={baseline:?} touched={touched:?} released={released:?} retouched={retouched:?} stats={stats:?}"
    );
    assert_eq!(stats.released_extents, 1);
    assert_eq!(stats.released_bytes, DATA_LEN as u64);
    assert_eq!(stats.failed_operations, 0);
    assert_eq!(pages_before.modified, pages);
    assert_eq!(pages_before.resident, pages);
    destroy_vcpu(vcpu);
    fixture.close();
}

/// A vCPU that faults inside the unmap window waits for the remap, exits with
/// `MemoryRetry` with its PC and registers untouched, and then runs normally.
fn fault_during_transition_scenario() {
    let fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE), (DATA_GPA, HOST_PAGE_SIZE)]);
    // str x1, [x0]; brk #0. Never discard the instruction being retried.
    fixture.mapping(CODE_GPA).write_words(&[0xf900_0001, BRK]);
    let state = fixture.state();
    let barrier = Arc::new(Barrier::new(2));
    let hook_barrier = Arc::clone(&barrier);
    let (unmapped_tx, unmapped_rx) = sync_channel(1);
    state.set_transition_hook(Box::new(move || {
        unmapped_tx.send(()).unwrap();
        hook_barrier.wait();
    }));
    let release_state = Arc::clone(&state);
    let release_worker = thread::spawn(move || {
        let range = GuestRange::new(DATA_GPA, HOST_PAGE_SIZE as u64).expect("data range");
        release_state.release_report(range).expect("release data")
    });
    unmapped_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    let (ready_tx, ready_rx) = sync_channel(0);
    let vcpu_state = Arc::clone(&state);
    let vcpu_worker = thread::spawn(move || {
        let mut vcpu = create_vcpu(0, CODE_GPA);
        let sentinels = [
            (hv_reg_t_HV_REG_X0, DATA_GPA),
            (hv_reg_t_HV_REG_X1, 0x2222_2222_2222_2222),
            (hv_reg_t_HV_REG_X2, 0x3333_3333_3333_3333),
            (hv_reg_t_HV_REG_X3, 0x4444_4444_4444_4444),
            (hv_reg_t_HV_REG_X4, 0x5555_5555_5555_5555),
            (hv_reg_t_HV_REG_X5, 0x6666_6666_6666_6666),
            (hv_reg_t_HV_REG_X6, 0x7777_7777_7777_7777),
            (hv_reg_t_HV_REG_X7, 0x8888_8888_8888_8888),
        ];
        for (register, value) in sentinels {
            set_reg(&vcpu, register, value);
        }
        ready_tx.send(()).expect("signal vCPU ready");
        let waited = Instant::now();
        let first = vcpu
            .run(Arc::new(NullVcpus), &vcpu_state)
            .expect("first run");
        let wait_time = waited.elapsed();
        let first_retry = matches!(first, VcpuExit::MemoryRetry);
        let syndrome = vcpu.vcpu_exit.exception.syndrome;
        let pa = vcpu.vcpu_exit.exception.physical_address;
        let pc = get_reg(&vcpu, hv_reg_t_HV_REG_PC);
        let registers: Vec<u64> = sentinels
            .iter()
            .map(|(register, _)| get_reg(&vcpu, *register))
            .collect();
        let second = vcpu
            .run(Arc::new(NullVcpus), &vcpu_state)
            .expect("second run");
        let second_breakpoint = matches!(second, VcpuExit::Breakpoint);
        destroy_vcpu(vcpu);
        (
            first_retry,
            syndrome,
            pa,
            pc,
            registers,
            second_breakpoint,
            wait_time,
            sentinels.map(|(_, value)| value),
        )
    });

    ready_rx.recv().expect("vCPU ready");
    // Give the vCPU time to run into the unmapped data page and start waiting
    // in the fault handler before the cycle is allowed to remap.
    thread::sleep(Duration::from_millis(250));
    barrier.wait();

    assert_eq!(
        release_worker.join().expect("release worker"),
        ReleaseOutcome::Released
    );
    let (first_retry, syndrome, pa, pc, registers, second_breakpoint, wait_time, expected) =
        vcpu_worker.join().expect("vCPU worker");
    let stats = state.stats();
    eprintln!(
        "fault_during_transition first_retry={first_retry} syndrome={syndrome:#x} pa={pa:#x} pc={pc:#x} second_breakpoint={second_breakpoint} wait_time={wait_time:?} stats={stats:?}"
    );
    assert!(first_retry, "vCPU did not exit with MemoryRetry");
    assert!(matches!((syndrome >> 26) & 0x3f, 0x24 | 0x25));
    assert_eq!(pa, DATA_GPA);
    assert_eq!(pc, CODE_GPA);
    assert_eq!(registers, expected.to_vec());
    assert!(second_breakpoint, "retry did not reach the breakpoint");
    assert_eq!(
        fixture.mapping(DATA_GPA).page_words(),
        vec![0x2222_2222_2222_2222]
    );
    assert!(wait_time >= Duration::from_millis(100));
    assert_eq!(stats.retried_faults, 1);
    assert_eq!(stats.released_extents, 1);
    fixture.close();
}

/// A vCPU that enters the guest while a cycle is already in flight, then
/// faults on that extent, must be told to retry once the remap lands. Before
/// the completion generation was published ahead of the extent state, such a
/// vCPU could observe "mapped, unchanged generation" and be killed as an
/// invalid access.
fn fault_entered_mid_transition_scenario() {
    let fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE)]);
    fixture.mapping(CODE_GPA).write_words(&[BRK]);
    let state = fixture.state();
    let (result_tx, result_rx) = sync_channel(1);
    let entered = Arc::new(Barrier::new(2));
    let hook_state = Arc::clone(&state);
    let hook_entered = Arc::clone(&entered);
    let first_cycle = std::sync::atomic::AtomicBool::new(true);
    state.set_transition_hook(Box::new(move || {
        // Only the first cycle spawns the mid-transition observer.
        if !first_cycle.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let observer_state = Arc::clone(&hook_state);
        let observer_entered = Arc::clone(&hook_entered);
        let result_tx = result_tx.clone();
        thread::spawn(move || {
            // Sampled while the cycle is in flight: this is what a vCPU
            // entering the guest right now would record.
            let entered = observer_state.vcpu_run_generation().expect("effective");
            observer_entered.wait();
            let resolution = observer_state.resolve_translation_fault(CODE_GPA, entered);
            result_tx
                .send((entered, resolution))
                .expect("deliver result");
        });
        // Hold the remap until the observer has sampled its entry generation.
        hook_entered.wait();
    }));

    let range = GuestRange::new(CODE_GPA, HOST_PAGE_SIZE as u64).expect("code range");
    let generation_before = state.vcpu_run_generation().expect("effective");
    assert_eq!(
        state.release_report(range).expect("release code"),
        ReleaseOutcome::Released
    );
    let (entered, resolution) = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("observer result");
    let stats = state.stats();
    eprintln!(
        "fault_entered_mid_transition generation_before={generation_before} entered={entered} resolution={resolution:?} stats={stats:?}"
    );
    assert_eq!(
        entered,
        generation_before + 1,
        "observer must have entered mid-cycle"
    );
    assert_eq!(
        resolution.expect("resolution"),
        crate::reclaim::FaultResolution::Retry
    );
    assert_eq!(stats.retried_faults, 1);
    fixture.close();
}

/// Releases race a vCPU that keeps touching the released range while a second
/// range next to it is never released. Every exit is a breakpoint or a retry,
/// the untouched control range keeps every write, and reclaim stays enabled.
fn concurrent_release_stress_scenario() {
    const CYCLES: usize = 300;
    const SWEEPS: u64 = 40;
    let fixture = Fixture::new(&[
        (CODE_GPA, HOST_PAGE_SIZE),
        (DATA_GPA, DATA_SIZE),
        (CONTROL_GPA, DATA_SIZE),
    ]);
    fixture.mapping(CODE_GPA).write_words(&TOUCH_PROGRAM);
    let state = fixture.state();
    let pages = DATA_SIZE / HOST_PAGE_SIZE;

    let (start_tx, start_rx) = sync_channel(0);
    let release_state = Arc::clone(&state);
    let release_worker = thread::spawn(move || {
        start_rx.recv().expect("start releases");
        let range = GuestRange::new(DATA_GPA, DATA_SIZE as u64).expect("data range");
        let mut released = 0;
        let started = Instant::now();
        for _ in 0..CYCLES {
            if release_state.release_report(range).expect("release data")
                == ReleaseOutcome::Released
            {
                released += 1;
            }
        }
        (released, started.elapsed())
    });

    let vcpu_state = Arc::clone(&state);
    let vcpu_worker = thread::spawn(move || {
        let mut vcpu = create_vcpu(0, CODE_GPA);
        start_tx.send(()).expect("start releases");
        let mut retries = 0;
        let mut control_checksums_ok = 0;
        for sweep in 0..SWEEPS {
            let seed = 0x10_0000 * (sweep + 1);
            let data = run_touch(&mut vcpu, &vcpu_state, DATA_GPA, DATA_SIZE, seed);
            retries += data.retries;
            let control = run_touch(&mut vcpu, &vcpu_state, CONTROL_GPA, DATA_SIZE, seed);
            assert_eq!(
                control.retries, 0,
                "control range must never fault to userspace"
            );
            if control.checksum == expected_checksum(seed, pages) {
                control_checksums_ok += 1;
            }
        }
        destroy_vcpu(vcpu);
        (retries, control_checksums_ok)
    });

    let (released, release_time) = release_worker.join().expect("release worker");
    let (retries, control_checksums_ok) = vcpu_worker.join().expect("vCPU worker");
    assert_page_pattern(fixture.mapping(CONTROL_GPA), 0x10_0000 * SWEEPS);
    let stats = state.stats();
    eprintln!(
        "concurrent_release_stress cycles={CYCLES} released={released} release_time={release_time:?} sweeps={SWEEPS} retries={retries} control_ok={control_checksums_ok} stats={stats:?}"
    );
    assert_eq!(released, CYCLES);
    assert_eq!(control_checksums_ok, SWEEPS);
    assert_eq!(stats.failed_operations, 0);
    assert_eq!(stats.released_extents, CYCLES as u64);
    assert_eq!(stats.retried_faults, u64::from(retries));
    assert!(state.is_effective());
    fixture.close();
}

fn partial_report_scenario(normalize: bool) {
    const DATA_LEN: usize = 3 * DATA_SIZE;
    let fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE), (DATA_GPA, DATA_LEN)]);
    fixture.mapping(CODE_GPA).write_words(&TOUCH_PROGRAM);
    let state = fixture.state();
    let mapping = fixture.mapping(DATA_GPA);
    let mut vcpu = create_vcpu(0, CODE_GPA);
    for cycle in 0..16 {
        let seed = 0x1000 * (cycle + 1);
        let first = run_touch(&mut vcpu, &state, DATA_GPA, DATA_LEN, seed);
        assert_eq!(
            first.checksum,
            expected_checksum(seed, DATA_LEN / HOST_PAGE_SIZE)
        );
        if normalize {
            unsafe { state.normalize_host_mappings() }.unwrap();
        }
        // Exercise native-page and multi-extent subranges in one large backing
        // object, not just replacement/release of an entire allocation.
        let start = DATA_SIZE - HOST_PAGE_SIZE;
        let len = if cycle % 2 == 0 {
            HOST_PAGE_SIZE
        } else {
            DATA_SIZE
        };
        let address = mapping.address.wrapping_add(start);
        let before = PageState::sample(address.cast(), len, HOST_PAGE_SIZE).unwrap();
        assert_eq!(before.modified, len / HOST_PAGE_SIZE);
        let range = GuestRange::new(DATA_GPA + start as u64, len as u64).unwrap();
        assert_eq!(
            state.release_report(range).unwrap(),
            ReleaseOutcome::Released
        );
        let after = PageState::sample(address.cast(), len, HOST_PAGE_SIZE).unwrap();
        assert!(
            after.is_discardable(),
            "normalize={normalize} cycle={cycle}: {after:?}"
        );
        let prefix = PageState::sample(mapping.address.cast(), start, HOST_PAGE_SIZE).unwrap();
        let suffix = PageState::sample(
            mapping.address.wrapping_add(start + len).cast(),
            DATA_LEN - start - len,
            HOST_PAGE_SIZE,
        )
        .unwrap();
        assert_eq!(prefix.modified, prefix.pages);
        assert_eq!(suffix.modified, suffix.pages);
        let reuse = run_touch(&mut vcpu, &state, range.start(), len, 0x9000);
        assert_eq!(
            reuse.checksum,
            expected_checksum(0x9000, len / HOST_PAGE_SIZE)
        );
        assert_eq!(reuse.retries, 0);
        if cycle == 15 {
            for (index, value) in mapping.page_words().into_iter().enumerate() {
                let offset = index * HOST_PAGE_SIZE;
                let expected = if (start..start + len).contains(&offset) {
                    0x9000 + ((offset - start) / HOST_PAGE_SIZE) as u64
                } else {
                    seed + index as u64
                };
                assert_eq!(value, expected, "live page {index}");
            }
        }
    }
    assert_eq!(state.stats().failed_operations, 0);
    assert_eq!(state.stats().released_extents, 16);
    destroy_vcpu(vcpu);
    fixture.close();
}

fn log_object_accounting(label: &str) {
    let output = Command::new("/usr/bin/footprint")
        .args([
            "-p",
            &std::process::id().to_string(),
            "--wide",
            "--vmObjectDirty",
        ])
        .output()
        .expect("observe VM-object accounting");
    assert!(output.status.success());
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.contains("untagged (VM_ALLOCATE)") || line.contains("phys_footprint:") {
            eprintln!("{label}: {line}");
        }
    }
}

fn large_backing_scenario(normalize: bool) {
    const DATA_LEN: usize = 128 * 1024 * 1024;
    for (populate, host_write_after_guest) in [(false, false), (true, false), (false, true)] {
        let baseline = memory_sample().unwrap();
        let fixture = Fixture::with_host_population(
            &[(CODE_GPA, HOST_PAGE_SIZE), (DATA_GPA, DATA_LEN)],
            populate,
        );
        fixture.mapping(CODE_GPA).write_words(&TOUCH_PROGRAM);
        let mapping = fixture.mapping(DATA_GPA);
        let state = fixture.state();
        let mut vcpu = create_vcpu(0, CODE_GPA);
        let touched = run_touch(&mut vcpu, &state, DATA_GPA, DATA_LEN, 0x1000);
        assert_eq!(
            touched.checksum,
            expected_checksum(0x1000, DATA_LEN / HOST_PAGE_SIZE)
        );
        if host_write_after_guest {
            for offset in (0..DATA_LEN).step_by(HOST_PAGE_SIZE) {
                unsafe {
                    ptr::write_volatile(
                        mapping.address.add(offset).cast::<u64>(),
                        0x1000 + (offset / HOST_PAGE_SIZE) as u64,
                    )
                };
            }
        }
        eprintln!(
            "large backing normalize={normalize} host_populated={populate} host_write_after_guest={host_write_after_guest}"
        );
        log_object_accounting("touched");
        // Keep live neighbors while reporting the interior in Linux-sized blocks.
        let start = DATA_SIZE;
        let end = DATA_LEN - DATA_SIZE;
        for offset in (start..end).step_by(DATA_SIZE) {
            assert_eq!(
                state
                    .release_report(
                        GuestRange::new(DATA_GPA + offset as u64, DATA_SIZE as u64).unwrap()
                    )
                    .unwrap(),
                ReleaseOutcome::Released
            );
        }
        let sample = || {
            PageState::sample(
                mapping.address.wrapping_add(start).cast(),
                end - start,
                HOST_PAGE_SIZE,
            )
            .unwrap()
        };
        let released = sample();
        eprintln!("released page state: {released:?}");
        assert!(released.is_discardable());
        log_object_accounting("released");
        if normalize {
            let before = memory_sample().unwrap();
            unsafe { state.normalize_host_mappings() }.unwrap();
            let after = memory_sample().unwrap();
            // Allow live neighbors and VMM bookkeeping, not another RAM-sized
            // host charge. A future kernel may already avoid the extra charge.
            assert!(
                after.phys_footprint
                    <= baseline.phys_footprint + (2 * DATA_SIZE + 16 * 1024 * 1024) as u64,
                "host PTE charge survived normalization: baseline={baseline:?} before={before:?} after={after:?}"
            );
            let normalized = sample();
            eprintln!("normalized page state: {normalized:?}");
            assert!(normalized.is_discardable());
            log_object_accounting("normalized");
        }
        thread::sleep(Duration::from_secs(5));
        let idle = sample();
        eprintln!("idle page state: {idle:?}");
        assert!(idle.is_discardable());
        log_object_accounting("idle");
        // Inspect only the unreported neighbors, never fault reported payloads in.
        for offset in (0..start).chain(end..DATA_LEN).step_by(HOST_PAGE_SIZE) {
            let actual = unsafe { ptr::read_volatile(mapping.address.add(offset).cast::<u64>()) };
            assert_eq!(actual, 0x1000 + (offset / HOST_PAGE_SIZE) as u64);
        }
        destroy_vcpu(vcpu);
        fixture.close();
    }
}

fn concurrent_normalization_scenario() {
    const LENGTH: usize = 4 * DATA_SIZE;
    const CYCLES: u64 = 64;
    let fixture = Fixture::with_host_population(
        &[
            (CODE_GPA, HOST_PAGE_SIZE),
            (DATA_GPA, LENGTH),
            (CONTROL_GPA, LENGTH),
        ],
        true,
    );
    fixture.mapping(CODE_GPA).write_words(&TOUCH_PROGRAM);
    let state = fixture.state();
    let barrier = Barrier::new(3);
    thread::scope(|scope| {
        let vcpu_worker = scope.spawn(|| {
            let mut vcpu = create_vcpu(0, CODE_GPA);
            for cycle in 0..CYCLES {
                barrier.wait();
                let result = run_touch(&mut vcpu, &state, DATA_GPA, LENGTH, cycle * 0x1000);
                barrier.wait();
                assert_eq!(
                    result.checksum,
                    expected_checksum(cycle * 0x1000, LENGTH / HOST_PAGE_SIZE)
                );
                assert_eq!(result.retries, 0);
            }
            destroy_vcpu(vcpu);
        });
        let host_worker = scope.spawn(|| {
            let mapping = fixture.mapping(CONTROL_GPA);
            for cycle in 0..CYCLES {
                barrier.wait();
                for offset in (0..LENGTH).step_by(HOST_PAGE_SIZE) {
                    unsafe {
                        ptr::write_volatile(
                            mapping.address.add(offset).cast::<u64>(),
                            cycle + offset as u64,
                        )
                    };
                }
                barrier.wait();
                for offset in (0..LENGTH).step_by(HOST_PAGE_SIZE) {
                    assert_eq!(
                        unsafe { ptr::read_volatile(mapping.address.add(offset).cast::<u64>()) },
                        cycle + offset as u64
                    );
                }
            }
        });
        for _ in 0..CYCLES {
            barrier.wait();
            unsafe { state.normalize_host_mappings() }.unwrap();
            barrier.wait();
        }
        vcpu_worker.join().unwrap();
        host_worker.join().unwrap();
    });
    assert_page_pattern(fixture.mapping(DATA_GPA), (CYCLES - 1) * 0x1000);
    assert_eq!(state.stats().failed_operations, 0);
    fixture.close();
}

fn unmap_control_scenario() {
    let fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE), (DATA_GPA, DATA_SIZE)]);
    fixture.mapping(CODE_GPA).write_words(&TOUCH_PROGRAM);
    let state = fixture.state();
    let mapping = fixture.mapping(DATA_GPA);
    let mut vcpu = create_vcpu(0, CODE_GPA);
    let touched = run_touch(&mut vcpu, &state, DATA_GPA, DATA_SIZE, 0x1000);
    assert_eq!(
        touched.checksum,
        expected_checksum(0x1000, DATA_SIZE / HOST_PAGE_SIZE)
    );
    let flags = (crate::bindings::HV_MEMORY_READ | crate::bindings::HV_MEMORY_WRITE).into();
    assert_eq!(
        unsafe { crate::bindings::hv_vm_unmap(DATA_GPA, DATA_SIZE) },
        HV_SUCCESS
    );
    assert_eq!(
        unsafe { crate::bindings::hv_vm_map(mapping.address.cast(), DATA_GPA, DATA_SIZE, flags) },
        HV_SUCCESS
    );
    let untouched = PageState::sample(mapping.address.cast(), DATA_SIZE, HOST_PAGE_SIZE).unwrap();
    assert_eq!(untouched.modified, untouched.pages);
    assert!(!untouched.is_discardable());

    assert_eq!(
        unsafe { crate::bindings::hv_vm_unmap(DATA_GPA, DATA_SIZE) },
        HV_SUCCESS
    );
    assert_eq!(unsafe { madvise(mapping.address.cast(), DATA_SIZE, 5) }, 0);
    assert_eq!(
        unsafe { crate::bindings::hv_vm_map(mapping.address.cast(), DATA_GPA, DATA_SIZE, flags) },
        HV_SUCCESS
    );
    let bulk = PageState::sample(mapping.address.cast(), DATA_SIZE, HOST_PAGE_SIZE).unwrap();
    // A future kernel may fix bulk advice; that must not fail this regression.
    eprintln!("unmap-only={untouched:?} bulk-free={bulk:?}");
    assert_eq!(
        state
            .release_report(GuestRange::new(DATA_GPA, DATA_SIZE as u64).unwrap())
            .unwrap(),
        ReleaseOutcome::Released
    );
    let pagewise = PageState::sample(mapping.address.cast(), DATA_SIZE, HOST_PAGE_SIZE).unwrap();
    eprintln!("pagewise-free={pagewise:?}");
    assert!(pagewise.is_discardable());
    destroy_vcpu(vcpu);
    fixture.close();
}

fn pressure_reclaim_scenario(precompressed: bool) {
    const DATA_LEN: usize = 16 * DATA_SIZE;
    let pressure_mib: usize = std::env::var("KRUN_RECLAIM_PRESSURE_MIB")
        .expect("set KRUN_RECLAIM_PRESSURE_MIB explicitly to authorize host memory pressure")
        .parse()
        .expect("pressure budget in MiB");
    assert!(
        (1..=4096).contains(&pressure_mib),
        "pressure budget must be 1..=4096 MiB"
    );
    let fixture = Fixture::new(&[
        (CODE_GPA, HOST_PAGE_SIZE),
        (DATA_GPA, DATA_LEN),
        (CONTROL_GPA, DATA_LEN),
    ]);
    fixture.mapping(CODE_GPA).write_words(&TOUCH_PROGRAM);
    let state = fixture.state();
    let mapping = fixture.mapping(DATA_GPA);
    let mut vcpu = create_vcpu(0, CODE_GPA);
    for gpa in [DATA_GPA, CONTROL_GPA] {
        let touched = run_touch(&mut vcpu, &state, gpa, DATA_LEN, 0x1000);
        assert_eq!(
            touched.checksum,
            expected_checksum(0x1000, DATA_LEN / HOST_PAGE_SIZE)
        );
    }
    let report = GuestRange::new(DATA_GPA, DATA_LEN as u64).unwrap();
    if !precompressed {
        assert_eq!(
            state.release_report(report).unwrap(),
            ReleaseOutcome::Released
        );
        assert!(
            PageState::sample(mapping.address.cast(), DATA_LEN, HOST_PAGE_SIZE)
                .unwrap()
                .is_discardable()
        );
    }

    // A page-sized pseudorandom pattern avoids a large staging allocation and
    // does not compress like a pressure buffer with only one dirty byte/page.
    let mut pattern = vec![0u64; HOST_PAGE_SIZE / 8];
    let mut random = 0x1234_5678_9abc_def0_u64;
    for word in &mut pattern {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        *word = random;
    }
    let fill = |mapping: &HostMapping| {
        for offset in (0..mapping.length).step_by(HOST_PAGE_SIZE) {
            unsafe {
                ptr::copy_nonoverlapping(
                    pattern.as_ptr().cast::<u8>(),
                    mapping.address.add(offset),
                    HOST_PAGE_SIZE,
                )
            };
        }
    };
    let canary = HostMapping::new(DATA_LEN);
    fill(&canary);
    unsafe { crate::discard::advise_free(canary.address.cast(), DATA_LEN, HOST_PAGE_SIZE) }
        .unwrap();
    let pressure = HostMapping::new(pressure_mib * 1024 * 1024);
    fill(&pressure);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let observed = PageState::sample(mapping.address.cast(), DATA_LEN, HOST_PAGE_SIZE).unwrap();
        let control = PageState::sample(canary.address.cast(), DATA_LEN, HOST_PAGE_SIZE).unwrap();
        let reached = if precompressed {
            observed.paged_out != 0
        } else {
            control.resident == 0
                && control.paged_out == 0
                && observed.resident == 0
                && observed.paged_out == 0
        };
        if reached {
            eprintln!(
                "pressure_mib={pressure_mib} precompressed={precompressed} target={observed:?} canary={control:?}"
            );
            break;
        }
        if Instant::now() >= deadline {
            if !precompressed && control.resident == 0 && control.paged_out == 0 {
                panic!(
                    "guest backing survived pressure that discarded the control: target={observed:?}"
                );
            }
            panic!(
                "INCONCLUSIVE: bounded pressure did not reach the required state; target={observed:?} canary={control:?}"
            );
        }
        // Keep the pressure allocation active rather than allowing the host to
        // satisfy pressure by compressing that allocation instead of our data.
        for offset in (0..pressure.length).step_by(HOST_PAGE_SIZE) {
            unsafe { ptr::write_volatile(pressure.address.add(offset), 0x5a) };
        }
        thread::sleep(Duration::from_millis(200));
    }
    if precompressed {
        assert_eq!(
            state.release_report(report).unwrap(),
            ReleaseOutcome::Released
        );
        let after = PageState::sample(mapping.address.cast(), DATA_LEN, HOST_PAGE_SIZE).unwrap();
        eprintln!("compressed backing after page-wise advice: {after:?}");
        assert!(
            after.is_discardable(),
            "compressed backing survived report: {after:?}"
        );
    } else {
        assert!(
            mapping.page_words().iter().all(|word| *word == 0),
            "discarded pages did not zero-fill"
        );
    }
    assert_page_pattern(fixture.mapping(CONTROL_GPA), 0x1000);
    let reused = run_touch(&mut vcpu, &state, DATA_GPA, DATA_LEN, 0x2000);
    assert_eq!(
        reused.checksum,
        expected_checksum(0x2000, DATA_LEN / HOST_PAGE_SIZE)
    );
    assert_eq!(reused.retries, 0);
    thread::sleep(Duration::from_secs(1));
    assert_page_pattern(mapping, 0x2000);
    destroy_vcpu(vcpu);
    fixture.close();
}

#[test]
#[ignore = "isolated HVF process; compares real VM-object accounting on 128 MiB backing"]
fn actual_large_backing_page_state_and_object_accounting() {
    child_scenario("large-backing", || large_backing_scenario(false));
}

#[test]
#[ignore = "isolated HVF process; compares content-preserving Mach normalization"]
fn actual_large_backing_mach_normalization_and_object_accounting() {
    child_scenario("normalized-large-backing", || large_backing_scenario(true));
}

#[test]
#[ignore = "isolated HVF process; concurrent host and guest access during Mach remapping"]
fn actual_mach_normalization_preserves_concurrent_host_and_guest_writes() {
    child_scenario(
        "concurrent-normalization",
        concurrent_normalization_scenario,
    );
}

#[test]
#[ignore = "host pressure requires an explicit KRUN_RECLAIM_PRESSURE_MIB budget"]
fn pressure_reported_pages_discard_instead_of_compressing() {
    child_scenario("pressure-discard", || pressure_reclaim_scenario(false));
}

#[test]
#[ignore = "host pressure requires an explicit KRUN_RECLAIM_PRESSURE_MIB budget"]
fn pressure_already_compressed_pages_are_forgotten() {
    child_scenario("pressure-compressed", || pressure_reclaim_scenario(true));
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_partial_reports_preserve_live_neighbors_and_reuse() {
    child_scenario("partial-reports", || partial_report_scenario(false));
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_mach_normalized_partial_reports_preserve_live_neighbors_and_reuse() {
    child_scenario("normalized-partial-reports", || {
        partial_report_scenario(true)
    });
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_unmap_and_bulk_advice_controls() {
    child_scenario("unmap-and-bulk-controls", unmap_control_scenario);
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_release_cycle_clears_page_state_and_refaults_in_kernel() {
    child_scenario("release-cycle", release_cycle_scenario);
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_fault_during_transition_retries_with_state_preserved() {
    child_scenario("fault-during-transition", fault_during_transition_scenario);
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_vcpu_entering_mid_transition_is_told_to_retry() {
    child_scenario(
        "fault-entered-mid-transition",
        fault_entered_mid_transition_scenario,
    );
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_concurrent_releases_never_break_a_running_vcpu() {
    child_scenario(
        "concurrent-release-stress",
        concurrent_release_stress_scenario,
    );
}
