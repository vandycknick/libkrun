use std::ffi::c_void;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use arch::guest_memory::{GuestRange, HostMemoryAccess, RamPermissions, RamRegion, ReclaimLedger};

use crate::bindings::{
    HV_SUCCESS, hv_reg_t_HV_REG_PC, hv_reg_t_HV_REG_X0, hv_reg_t_HV_REG_X1, hv_reg_t_HV_REG_X2,
    hv_reg_t_HV_REG_X3, hv_reg_t_HV_REG_X4, hv_reg_t_HV_REG_X5, hv_reg_t_HV_REG_X6,
    hv_reg_t_HV_REG_X7, hv_sys_reg_t_HV_SYS_REG_MAIR_EL1, hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TCR_EL1, hv_sys_reg_t_HV_SYS_REG_TTBR0_EL1, hv_vcpu_destroy,
    hv_vcpu_get_reg, hv_vcpu_get_sys_reg, hv_vcpu_set_reg, hv_vcpu_set_sys_reg,
    hv_vcpu_set_trap_debug_exceptions,
};
use crate::reclaim::{ReclaimState, ReleaseOutcome};
use crate::{HvfVcpu, HvfVm, VcpuExit, Vcpus};

const HOST_PAGE_SIZE: usize = 0x4000;
const CODE_GPA: u64 = 0x4000_0000;
const TABLE_GPA: u64 = 0x5000_0000;
const CHILD_TIMEOUT: Duration = Duration::from_secs(8);

const BRK: u32 = 0xd420_0000;
// Arm ARM DDI0487 translation-table descriptor and TCR_EL1 fields. This is a
// 39-bit VA, 4 KiB-granule, three-level identity mapping using normal WBWA RAM.
const TABLE_DESCRIPTOR: u64 = 0b11;
const PAGE_DESCRIPTOR: u64 = (1 << 10) | (0b11 << 8) | 0b11;
const TCR_EL1_39BIT_4K_WBWA: u64 = 25 | (1 << 8) | (1 << 10) | (0b11 << 12) | (1 << 23);

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

impl HostMapping {
    fn new(length: usize) -> Self {
        let address = unsafe { mmap(ptr::null_mut(), length, 0x1 | 0x2, 0x0002 | 0x1000, -1, 0) };
        assert_ne!(address as usize, usize::MAX, "anonymous mmap failed");
        Self {
            address: address.cast(),
            length,
        }
    }

    fn write_words(&mut self, words: &[u32]) {
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
}

impl Drop for HostMapping {
    fn drop(&mut self) {
        assert_eq!(unsafe { munmap(self.address.cast(), self.length) }, 0);
    }
}

struct Fixture {
    vm: Option<HvfVm>,
    mappings: Vec<(u64, HostMapping)>,
    vcpu_ids: Vec<u64>,
}

impl Fixture {
    fn new(regions: &[(u64, usize)]) -> Self {
        let vm = HvfVm::new(false).expect("create HVF VM");
        let mut ledger = ReclaimLedger::new(HOST_PAGE_SIZE as u64).expect("create ledger");
        let mut mappings = Vec::new();
        for (gpa, length) in regions {
            let mapping = HostMapping::new(*length);
            vm.map_memory(mapping.address as u64, *gpa, *length as u64)
                .expect("map fixture RAM");
            ledger
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
        vm.begin_memory_initialization(ledger)
            .expect("reserve reclaim state")
            .commit();
        let state = vm.reclaim_state();
        state.enable_policy_for_test();
        state.qualify_for_test();
        Self {
            vm: Some(vm),
            mappings,
            vcpu_ids: Vec::new(),
        }
    }

    fn state(&self) -> Arc<ReclaimState> {
        self.vm.as_ref().expect("live VM").reclaim_state()
    }

    fn mapping_mut(&mut self, gpa: u64) -> &mut HostMapping {
        &mut self
            .mappings
            .iter_mut()
            .find(|(candidate, _)| *candidate == gpa)
            .expect("known mapping")
            .1
    }

    fn vcpu(&mut self, pc: u64) -> HvfVcpu<'static> {
        let mpidr = (self.vcpu_ids.len() as u64) << 8;
        let vcpu = HvfVcpu::new(mpidr, false).expect("create vCPU");
        vcpu.set_initial_state(pc, 0).expect("initialize vCPU");
        assert_eq!(
            unsafe { hv_vcpu_set_trap_debug_exceptions(vcpu.id(), true) },
            HV_SUCCESS
        );
        self.vcpu_ids.push(vcpu.id());
        vcpu
    }

    fn close(mut self) {
        for id in self.vcpu_ids.drain(..) {
            assert_eq!(unsafe { hv_vcpu_destroy(id) }, HV_SUCCESS, "destroy vCPU");
        }
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

fn set_sys_reg(vcpu: &HvfVcpu<'_>, register: u16, value: u64) {
    assert_eq!(
        unsafe { hv_vcpu_set_sys_reg(vcpu.id(), register, value) },
        HV_SUCCESS
    );
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

fn instruction_abort_scenario() {
    let mut fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE)]);
    fixture.mapping_mut(CODE_GPA).write_words(&[BRK]);
    let state = fixture.state();
    let range = GuestRange::new(CODE_GPA, HOST_PAGE_SIZE as u64).expect("code range");
    assert_eq!(
        state.release_report(range).expect("release code"),
        ReleaseOutcome::Released
    );
    let before = state.stats();
    let mut vcpu = fixture.vcpu(CODE_GPA);
    let sentinels = [
        (hv_reg_t_HV_REG_X0, 0x1111_1111_1111_1111),
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
    let exit = vcpu
        .run(Arc::new(NullVcpus), &state)
        .expect("resolve instruction abort");
    assert!(matches!(exit, VcpuExit::MemoryRestored));
    let syndrome = vcpu.vcpu_exit.exception.syndrome;
    let pa = vcpu.vcpu_exit.exception.physical_address;
    assert!(matches!((syndrome >> 26) & 0x3f, 0x20 | 0x21));
    assert_eq!(pa, CODE_GPA);
    assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_PC), CODE_GPA);
    for (register, value) in sentinels {
        assert_eq!(get_reg(&vcpu, register), value);
    }
    assert!(matches!(
        vcpu.run(Arc::new(NullVcpus), &state)
            .expect("execute restored code"),
        VcpuExit::Breakpoint
    ));
    let after = state.stats();
    eprintln!(
        "instruction_abort syndrome={syndrome:#x} pa={pa:#x} pc={:#x} stats_before={before:?} stats_after={after:?}",
        get_reg(&vcpu, hv_reg_t_HV_REG_PC)
    );
    assert_eq!(after.restored_extents - before.restored_extents, 1);
    fixture.close();
}

fn install_three_level_4k_tables(tables: &mut HostMapping, code_gpa: u64) {
    assert_eq!(tables.length, HOST_PAGE_SIZE);
    let root_pa = TABLE_GPA;
    let level_two_pa = TABLE_GPA + 0x1000;
    let level_three_pa = TABLE_GPA + 0x2000;
    let level_one_index = ((code_gpa >> 30) & 0x1ff) as usize;
    let level_two_index = ((code_gpa >> 21) & 0x1ff) as usize;
    let level_three_index = ((code_gpa >> 12) & 0x1ff) as usize;
    unsafe {
        let entries = std::slice::from_raw_parts_mut(tables.address.cast::<u64>(), 0x3000 / 8);
        entries[level_one_index] = level_two_pa | TABLE_DESCRIPTOR;
        entries[0x1000 / 8 + level_two_index] = level_three_pa | TABLE_DESCRIPTOR;
        entries[0x2000 / 8 + level_three_index] = code_gpa | PAGE_DESCRIPTOR;
    }
    eprintln!(
        "page_tables root_pa={root_pa:#x} l2_pa={level_two_pa:#x} l3_pa={level_three_pa:#x} leaf_pa={code_gpa:#x} indexes={level_one_index}/{level_two_index}/{level_three_index}"
    );
}

fn page_walk_scenario() {
    let mut fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE), (TABLE_GPA, HOST_PAGE_SIZE)]);
    fixture.mapping_mut(CODE_GPA).write_words(&[BRK]);
    install_three_level_4k_tables(fixture.mapping_mut(TABLE_GPA), CODE_GPA);
    let state = fixture.state();
    let mut vcpu = fixture.vcpu(CODE_GPA);
    set_sys_reg(&vcpu, hv_sys_reg_t_HV_SYS_REG_MAIR_EL1, 0xff);
    set_sys_reg(
        &vcpu,
        hv_sys_reg_t_HV_SYS_REG_TCR_EL1,
        TCR_EL1_39BIT_4K_WBWA,
    );
    set_sys_reg(&vcpu, hv_sys_reg_t_HV_SYS_REG_TTBR0_EL1, TABLE_GPA);
    let mut sctlr = 0;
    assert_eq!(
        unsafe { hv_vcpu_get_sys_reg(vcpu.id(), hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1, &mut sctlr) },
        HV_SUCCESS
    );
    set_sys_reg(&vcpu, hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1, sctlr | 1);
    set_reg(&vcpu, hv_reg_t_HV_REG_X0, 0xa5a5_a5a5_a5a5_a5a5);
    let tables = GuestRange::new(TABLE_GPA, HOST_PAGE_SIZE as u64).expect("table range");
    assert_eq!(
        state.release_report(tables).expect("release tables"),
        ReleaseOutcome::Released
    );
    let before = state.stats();
    let exit = vcpu
        .run(Arc::new(NullVcpus), &state)
        .expect("resolve stage-1 walk abort");
    assert!(matches!(exit, VcpuExit::MemoryRestored));
    let syndrome = vcpu.vcpu_exit.exception.syndrome;
    let pa = vcpu.vcpu_exit.exception.physical_address;
    assert_ne!(syndrome & (1 << 7), 0, "abort was not a stage-1 walk");
    assert!(pa >= tables.start() && pa < tables.start() + tables.byte_len());
    assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_PC), CODE_GPA);
    assert_eq!(get_reg(&vcpu, hv_reg_t_HV_REG_X0), 0xa5a5_a5a5_a5a5_a5a5);
    assert!(matches!(
        vcpu.run(Arc::new(NullVcpus), &state)
            .expect("execute after table restore"),
        VcpuExit::Breakpoint
    ));
    let after = state.stats();
    eprintln!(
        "page_walk syndrome={syndrome:#x} s1ptw={} pa={pa:#x} root_pa={TABLE_GPA:#x} extent=[{:#x},{:#x}) pc={:#x} stats_before={before:?} stats_after={after:?}",
        (syndrome >> 7) & 1,
        tables.start(),
        tables.start() + tables.byte_len(),
        get_reg(&vcpu, hv_reg_t_HV_REG_PC)
    );
    assert_eq!(after.restored_extents - before.restored_extents, 1);
    fixture.close();
}

fn stale_two_vcpu_scenario() {
    let mut fixture = Fixture::new(&[(CODE_GPA, HOST_PAGE_SIZE)]);
    fixture.mapping_mut(CODE_GPA).write_words(&[BRK]);
    let state = fixture.state();
    let range = GuestRange::new(CODE_GPA, HOST_PAGE_SIZE as u64).expect("code range");
    assert_eq!(
        state.release_report(range).expect("release code"),
        ReleaseOutcome::Released
    );
    let barrier = Arc::new(Barrier::new(2));
    let first_state = Arc::clone(&state);
    let first_barrier = Arc::clone(&barrier);
    let first_worker = thread::spawn(move || {
        let mut first = HvfVcpu::new(0, false).expect("create first vCPU on owner thread");
        first
            .set_initial_state(CODE_GPA, 0)
            .expect("initialize first vCPU");
        assert_eq!(
            unsafe { hv_vcpu_set_trap_debug_exceptions(first.id(), true) },
            HV_SUCCESS
        );
        set_reg(&first, hv_reg_t_HV_REG_X0, 0x1111);
        first.set_after_hvf_exit_barrier(first_barrier);
        let exit = first
            .run(Arc::new(NullVcpus), &first_state)
            .expect("first production run");
        let result = (
            matches!(exit, VcpuExit::MemoryRestored),
            first.vcpu_exit.exception.syndrome,
            first.vcpu_exit.exception.physical_address,
            get_reg(&first, hv_reg_t_HV_REG_PC),
            get_reg(&first, hv_reg_t_HV_REG_X0),
        );
        assert!(matches!(
            first
                .run(Arc::new(NullVcpus), &first_state)
                .expect("first retry"),
            VcpuExit::Breakpoint
        ));
        assert_eq!(unsafe { hv_vcpu_destroy(first.id()) }, HV_SUCCESS);
        result
    });
    let second_state = Arc::clone(&state);
    let second_barrier = Arc::clone(&barrier);
    let second_worker = thread::spawn(move || {
        let mut second = HvfVcpu::new(0x100, false).expect("create second vCPU on owner thread");
        second
            .set_initial_state(CODE_GPA, 0)
            .expect("initialize second vCPU");
        assert_eq!(
            unsafe { hv_vcpu_set_trap_debug_exceptions(second.id(), true) },
            HV_SUCCESS
        );
        set_reg(&second, hv_reg_t_HV_REG_X0, 0x2222);
        second.set_after_hvf_exit_barrier(second_barrier);
        let exit = second
            .run(Arc::new(NullVcpus), &second_state)
            .expect("second production run");
        let result = (
            matches!(exit, VcpuExit::MemoryRestored),
            second.vcpu_exit.exception.syndrome,
            second.vcpu_exit.exception.physical_address,
            get_reg(&second, hv_reg_t_HV_REG_PC),
            get_reg(&second, hv_reg_t_HV_REG_X0),
        );
        assert!(matches!(
            second
                .run(Arc::new(NullVcpus), &second_state)
                .expect("second retry"),
            VcpuExit::Breakpoint
        ));
        assert_eq!(unsafe { hv_vcpu_destroy(second.id()) }, HV_SUCCESS);
        result
    });
    let first_result = first_worker.join().expect("first worker");
    let second_result = second_worker.join().expect("second worker");
    for result in [first_result, second_result] {
        assert!(result.0);
        assert!(matches!((result.1 >> 26) & 0x3f, 0x20 | 0x21));
        assert_eq!(result.2, CODE_GPA);
        assert_eq!(result.3, CODE_GPA);
    }
    assert_eq!(first_result.4, 0x1111);
    assert_eq!(second_result.4, 0x2222);
    let stats = state.stats();
    eprintln!(
        "stale_two_vcpu first={first_result:?} second={second_result:?} restored_extents={} no_mmio=true stats={stats:?}",
        stats.restored_extents
    );
    assert_eq!(
        stats.restored_extents, 1,
        "one extent must be restored once"
    );
    fixture.close();
}

fn host_first_async_lease_scenario() {
    const LENGTH: usize = 2 * 1024 * 1024;
    let mut fixture = Fixture::new(&[(CODE_GPA, LENGTH)]);
    let state = fixture.state();
    let range = GuestRange::new(CODE_GPA, LENGTH as u64).expect("I/O range");
    unsafe { ptr::write_bytes(fixture.mapping_mut(CODE_GPA).address, 0x5a, LENGTH) };
    assert_eq!(
        state.release_report(range).expect("release I/O extent"),
        ReleaseOutcome::Released
    );
    let before = state.stats();
    thread::sleep(Duration::from_millis(20));
    let released_sample = crate::probe::memory_sample().expect("released memory sample");
    let provider: Arc<dyn HostMemoryAccess> = state.clone();
    let lease = provider
        .clone()
        .access(range)
        .expect("host-first restore and lease");
    let restored = state.stats();
    thread::sleep(Duration::from_millis(20));
    let restored_sample = crate::probe::memory_sample().expect("restored memory sample");
    assert_eq!(restored.restored_extents - before.restored_extents, 1);
    assert_eq!(state.test_ledger_counts(), (0, 1));

    let path = std::env::temp_dir().join(format!("libkrun-actual-hvf-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .expect("create real I/O file");
    let bytes =
        unsafe { std::slice::from_raw_parts(fixture.mapping_mut(CODE_GPA).address, LENGTH) };
    file.write_all(bytes)
        .expect("complete host-first file write");
    file.seek(SeekFrom::Start(0)).expect("rewind file");
    let mut checksum_bytes = vec![0; LENGTH];
    file.read_exact(&mut checksum_bytes)
        .expect("read file checksum data");
    assert!(checksum_bytes.iter().all(|byte| *byte == 0x5a));
    thread::sleep(Duration::from_millis(20));
    let host_touched_sample = crate::probe::memory_sample().expect("host-touched memory sample");

    let address = fixture.mapping_mut(CODE_GPA).address as usize;
    let (mut socket_sender, mut socket_receiver) = UnixStream::pair().expect("socket pair");
    let (ready_tx, ready_rx) = sync_channel(0);
    let (go_tx, go_rx) = sync_channel(0);
    let completion = thread::spawn(move || {
        ready_tx.send(()).expect("completion ready");
        go_rx.recv().expect("completion start");
        let bytes = unsafe { std::slice::from_raw_parts(address as *const u8, 0x10_000) };
        socket_sender
            .write_all(bytes)
            .expect("async socket completion");
        drop(lease);
    });
    ready_rx.recv().expect("completion worker ready");
    assert_eq!(
        state
            .release_report(range)
            .expect("release racing socket completion"),
        ReleaseOutcome::Skipped
    );
    go_tx.send(()).expect("start socket completion");
    let mut socket_bytes = vec![0; 0x10_000];
    socket_receiver
        .read_exact(&mut socket_bytes)
        .expect("receive async socket data");
    completion.join().expect("completion worker");
    assert!(socket_bytes.iter().all(|byte| *byte == 0x5a));
    assert_eq!(state.test_ledger_counts(), (0, 0));

    let error_lease = provider.clone().access(range).expect("error lease");
    let read_only = std::fs::File::open(&path).expect("open read-only error target");
    let (error_ready_tx, error_ready_rx) = sync_channel(0);
    let (error_go_tx, error_go_rx) = sync_channel(0);
    let error_worker = thread::spawn(move || {
        let mut read_only = read_only;
        error_ready_tx.send(()).expect("error ready");
        error_go_rx.recv().expect("error start");
        let error = read_only
            .write_all(b"must fail")
            .expect_err("read-only file write must fail");
        drop(error_lease);
        error.raw_os_error()
    });
    error_ready_rx.recv().expect("error worker ready");
    assert_eq!(
        state
            .release_report(range)
            .expect("release racing async error"),
        ReleaseOutcome::Skipped
    );
    error_go_tx.send(()).expect("start error worker");
    assert_eq!(error_worker.join().expect("error worker"), Some(9));
    assert_eq!(state.test_ledger_counts(), (0, 0));

    let cancel_lease = provider.clone().access(range).expect("cancel lease");
    let (cancel_ready_tx, cancel_ready_rx) = sync_channel(0);
    let (cancel_tx, cancel_rx) = sync_channel(0);
    let cancel_worker = thread::spawn(move || {
        cancel_ready_tx.send(()).expect("cancel ready");
        cancel_rx.recv().expect("cancel signal");
        drop(cancel_lease);
    });
    cancel_ready_rx.recv().expect("cancel worker ready");
    assert_eq!(
        state
            .release_report(range)
            .expect("release racing cancellation"),
        ReleaseOutcome::Skipped
    );
    cancel_tx.send(()).expect("cancel async operation");
    cancel_worker.join().expect("cancel worker");
    assert_eq!(state.test_ledger_counts(), (0, 0));

    assert_eq!(
        state
            .release_report(range)
            .expect("release after completion"),
        ReleaseOutcome::Released
    );
    let final_lease = provider.access(range).expect("restore for cleanup");
    drop(final_lease);
    std::fs::remove_file(&path).expect("remove real I/O file");
    let after = state.stats();
    eprintln!(
        "host_first_async released_sample={released_sample:?} restored_before_host_touch={restored_sample:?} host_touched_sample={host_touched_sample:?} before={before:?} restored={restored:?} after={after:?} file_checksum=pass socket_checksum=pass lease_counts=1->0 completion=pass error=pass cancel=pass skipped_during_lease={} cpu_touches=0",
        after.skipped_reports - restored.skipped_reports
    );
    assert!(
        released_sample
            .reusable
            .saturating_sub(restored_sample.reusable)
            >= (LENGTH as u64 * 3 / 4),
        "MADV_FREE_REUSE did not restore live accounting before host access"
    );
    assert!(
        host_touched_sample
            .phys_footprint
            .saturating_sub(released_sample.phys_footprint)
            >= (LENGTH as u64 * 3 / 4),
        "host-first I/O did not recharge live footprint"
    );
    fixture.close();
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_instruction_abort_refault_preserves_pc_and_registers() {
    child_scenario("instruction-abort", instruction_abort_scenario);
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_stage_one_page_walk_refault_proves_fault_pa() {
    child_scenario("page-walk", page_walk_scenario);
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_two_vcpu_stale_exits_restore_once_without_mmio() {
    child_scenario("stale-two-vcpu", stale_two_vcpu_scenario);
}

#[test]
#[ignore = "requires an isolated code-signed process with Hypervisor entitlement"]
fn actual_host_first_async_lease_race_cleans_all_paths() {
    child_scenario("host-first-async", host_first_async_lease_scenario);
}
