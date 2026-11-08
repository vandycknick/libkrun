//! Standalone, qualification-ineligible CPU execution diagnostic.
use std::ffi::OsString;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

use arch::ArchMemoryInfo;
use devices::virtio::RuntimeGuestMemory;
use devices::{Bus, BusDevice};
use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::api::capabilities::execution_state_producer;
use crate::vmm::Vmm;
use crate::vmm::builder::restore::{
    PreparedDeviceInstall, build_execution_fixture, build_restore_prepared,
};
use crate::vmm::control::{CpuCommandKind, RequestId};
use crate::vmm::execution::kvm::{KvmCpuState, KvmVmState, X86CpuState, lapic_u32};
use crate::vmm::execution::runtime::KvmCaptureProfile;
use crate::vmm::execution::{
    CpuExecutionState, CpuIdentity, ExecutionEnvelope, ExecutionLane, StateBinding,
    ValidatedExecution, VmExecutionState,
};
use crate::vmm::memory::RamCaptureRequest;
use crate::vmm::memory::image::layout::MAX_RAM_LAYOUT_BYTES;
use crate::vmm::memory::image::{
    AuthenticatedRamImage, RamImageAuthentication, RamOutputFiles, RestoredRam, ValidatedRamLayout,
    map_restore_ram,
};

const RAM_BYTES: usize = 0x300000;
const MAX_FIXTURE: usize = 0x10000;
const WAIT: Duration = Duration::from_secs(5);
const ENTRY: u64 = 0x1000;
const SLOT: u64 = 0x100000;
const STRIDE: u64 = 0x1000;
const MAGIC: u64 = 0x53494c4f;
const MEMORY: [(GuestAddress, usize); 1] = [(GuestAddress(0), RAM_BYTES)];

#[derive(Debug)]
pub struct ProbeResult {
    json: String,
}
impl ProbeResult {
    pub fn json(&self) -> &str {
        &self.json
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Case {
    Future,
    Due,
    DueNoIrr,
    Masked,
    PendingFuture,
    InService,
    Offline,
    Io,
    Mmio,
}
impl Case {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "future" => Ok(Self::Future),
            "due" => Ok(Self::Due),
            "masked" => Ok(Self::Masked),
            "due-no-irr" => Ok(Self::DueNoIrr),
            "pending-future" => Ok(Self::PendingFuture),
            "in-service" => Ok(Self::InService),
            "offline" => Ok(Self::Offline),
            "io" => Ok(Self::Io),
            "mmio" => Ok(Self::Mmio),
            _ => Err(format!("unknown execution case: {value}")),
        }
    }
    fn command(self) -> u64 {
        match self {
            Self::Future => 1,
            Self::Due => 2,
            Self::DueNoIrr => 10,
            Self::Masked => 3,
            Self::PendingFuture => 4,
            Self::InService => 5,
            Self::Offline => 0,
            Self::Io => 6,
            Self::Mmio => 7,
        }
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular fixture file", path.display()));
    }
    let len = metadata.len();
    if len > limit as u64 {
        return Err(format!("{} exceeds {limit} bytes", path.display()));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("input grew past fixture limit".into());
    }
    Ok(bytes)
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
fn memory() -> Result<GuestMemoryMmap, String> {
    GuestMemoryMmap::from_ranges(&MEMORY).map_err(|e| format!("fixture RAM: {e}"))
}
fn ram_bytes(memory: &RuntimeGuestMemory) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0; RAM_BYTES];
    memory
        .read_slice(&mut bytes, GuestAddress(0))
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn word(memory: &RuntimeGuestMemory, cpu: usize, offset: u64) -> Result<u64, String> {
    memory
        .read_obj(GuestAddress(SLOT + cpu as u64 * STRIDE + offset))
        .map_err(|e| e.to_string())
}
fn set_word(
    memory: &RuntimeGuestMemory,
    cpu: usize,
    offset: u64,
    value: u64,
) -> Result<(), String> {
    memory
        .write_obj(value, GuestAddress(SLOT + cpu as u64 * STRIDE + offset))
        .map_err(|e| e.to_string())
}
fn wait_until(
    label: &str,
    mut predicate: impl FnMut() -> Result<bool, String>,
) -> Result<(), String> {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if predicate()? {
            return Ok(());
        }
        thread::sleep(Duration::from_micros(100));
    }
    Err(format!("timeout: {label}"))
}
fn key(generation: u64) -> BarrierKey {
    BarrierKey {
        operation: OperationId(generation),
        generation: BarrierGeneration(generation),
    }
}
fn binding(path: &Path, generation: u64) -> Result<StateBinding, String> {
    decode_binding(&bounded_read(path, 160)?, generation)
}
fn decode_binding(bytes: &[u8], generation: u64) -> Result<StateBinding, String> {
    if bytes.len() != 160 {
        return Err("fixture binding must contain exactly 160 bytes".into());
    }
    let mut chunks = bytes.chunks_exact(32);
    let mut next = || -> Result<[u8; 32], String> {
        chunks
            .next()
            .ok_or_else(|| String::from("binding truncated"))?
            .try_into()
            .map_err(|_| "binding width".into())
    };
    let silo_producer = next()?;
    let profile = next()?;
    let topology = next()?;
    let ram_layout = next()?;
    let identity = next()?;
    let source_run = identity[..16]
        .try_into()
        .map_err(|_| "run identity width")?;
    let capture = identity[16..]
        .try_into()
        .map_err(|_| "capture identity width")?;
    let binding = StateBinding {
        native_producer: execution_state_producer()?,
        silo_producer,
        profile,
        topology,
        ram_layout,
        source_run,
        pause_generation: generation,
        capture,
    };
    binding.validate().map_err(|error| error.to_string())?;
    Ok(binding)
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "layout binding deadline expired".into())
}

fn socket_write(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| e.to_string())?;
        match stream.write(bytes) {
            Ok(0) => return Err("layout binding write made no progress".into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => (),
            Err(error) => return Err(format!("layout binding write: {error}")),
        }
    }
    Ok(())
}

fn socket_read(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), String> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|e| e.to_string())?;
        match stream.read(bytes) {
            Ok(0) => return Err("layout binding unexpected EOF".into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => (),
            Err(error) => return Err(format!("layout binding read: {error}")),
        }
    }
    Ok(())
}

fn exchange_binding(
    stream: &mut UnixStream,
    layout: &[u8],
    deadline: Instant,
) -> Result<StateBinding, String> {
    if layout.is_empty() || layout.len() > MAX_RAM_LAYOUT_BYTES {
        return Err("layout binding length outside bound".into());
    }
    let length = u32::try_from(layout.len()).map_err(|_| "layout binding length overflow")?;
    socket_write(stream, &length.to_le_bytes(), deadline)?;
    socket_write(stream, layout, deadline)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut bytes = [0; 160];
    socket_read(stream, &mut bytes, deadline)?;
    let mut extra = [0];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|error| error.to_string())?;
        match stream.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err("layout binding contains trailing bytes".into()),
            Err(error) if error.kind() == ErrorKind::Interrupted => (),
            Err(error) => return Err(format!("layout binding framing: {error}")),
        }
    }
    remaining(deadline)?;
    decode_binding(&bytes, 1)
}

fn inherited_channel(argument: &OsString) -> Result<UnixStream, String> {
    let fd = text(argument)?
        .parse::<i32>()
        .map_err(|_| "invalid layout binding FD")?;
    if fd <= 2 {
        return Err("layout binding FD must be an inherited socket".into());
    }
    // The standalone controller transfers this descriptor exactly once via pass_fds.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream
        .peer_addr()
        .map_err(|error| format!("layout binding socket: {error}"))?;
    Ok(stream)
}

fn check_preparation(vmm: &Vmm, prepared: &ValidatedRamLayout) -> Result<(), String> {
    let current = vmm.memory_layout().map_err(|error| error.to_string())?;
    if current.canonical_bytes() != prepared.canonical_bytes() {
        return Err("canonical layout changed after preparation".into());
    }
    Ok(())
}

fn fixture_info() -> Result<ArchMemoryInfo, String> {
    Ok(ArchMemoryInfo {
        ram_below_gap: RAM_BYTES as u64,
        ram_above_gap: 0,
        ram_last_addr: RAM_BYTES as u64,
        firmware_addr: 0,
        shm_start_addr: 0x1_0000_0000,
        page_size: crate::vmm::execution::host_page_granule().map_err(|error| error.to_string())?
            as usize,
        initrd_addr: RAM_BYTES as u64,
    })
}

fn decode_ram_authentication(
    bytes: &[u8],
    state: &StateBinding,
) -> Result<RamImageAuthentication, String> {
    if bytes.len() != 64 || bytes[..32] != state.ram_layout {
        return Err("RAM authentication layout identity mismatch".into());
    }
    let stream = bytes[32..]
        .try_into()
        .map_err(|_| "RAM stream identity width")?;
    Ok(RamImageAuthentication {
        state: state.clone(),
        stream,
    })
}

fn restored_ram(
    input: &Path,
    execution: &ValidatedExecution,
    ram_fd: &OsString,
    layout_fd: &OsString,
) -> Result<RestoredRam, String> {
    let bytes = bounded_read(&input.join("ram-authentication.bin"), 64)?;
    let authentication = decode_ram_authentication(&bytes, &execution.envelope().binding)?;
    let parse_fd = |argument: &OsString| -> Result<i32, String> {
        let fd = text(argument)?
            .parse::<i32>()
            .map_err(|_| "invalid inherited RAM FD")?;
        if fd <= 2 {
            return Err("RAM FD must be a transferred readonly descriptor".into());
        }
        Ok(fd)
    };
    let ram_fd = parse_fd(ram_fd)?;
    let layout_fd = parse_fd(layout_fd)?;
    if ram_fd == layout_fd {
        return Err("RAM and layout descriptors must differ".into());
    }
    // The controller transfers each authenticated descriptor exactly once.
    let ram = unsafe { File::from_raw_fd(ram_fd) };
    let layout = unsafe { File::from_raw_fd(layout_fd) };
    let image = AuthenticatedRamImage::for_restore(ram, layout, authentication, execution)
        .map_err(|error| error.to_string())?;
    map_restore_ram(Arc::new(image), execution).map_err(|error| error.to_string())
}
fn topology(count: u8) -> Vec<CpuIdentity> {
    (0..count)
        .map(|id| CpuIdentity {
            logical_id: id,
            architectural_id: u64::from(id),
        })
        .collect()
}
fn x86(state: &CpuExecutionState) -> Result<&X86CpuState, String> {
    match state {
        CpuExecutionState::Kvm(KvmCpuState::X86(s)) => Ok(s),
        _ => Err("not KVM x86 state".into()),
    }
}
fn validate_cut(
    envelope: &ExecutionEnvelope,
    memory: &RuntimeGuestMemory,
    case: Case,
    count: u8,
) -> Result<(), String> {
    for cpu in 0..usize::from(count) {
        let state = x86(envelope.cpus.get(cpu).ok_or("missing captured CPU")?)?;
        if case == Case::Offline && cpu == 1 {
            if word(memory, cpu, 8)? != 0 || state.mp_state != 1 {
                return Err("offline AP executed before guest INIT/SIPI".into());
            }
            continue;
        }
        if word(memory, cpu, 0)? != MAGIC
            || word(memory, cpu, 8)? != 1
            || word(memory, cpu, 24)? != 0
        {
            return Err(format!("CPU {cpu} initialization/sentinel failure"));
        }
        if state.regs[12] != 0x13579bdf2468ace0 || state.regs[13] != 0xfedcba9876543210 {
            return Err(format!("CPU {cpu} captured live GPR sentinel differs"));
        }
        let sentinel = [0x0123456789abcdefu64, 0xfedcba9876543210u64];
        for (index, value) in sentinel.iter().enumerate() {
            if state.xsave.get(400 + index * 8..408 + index * 8)
                != Some(value.to_le_bytes().as_slice())
            {
                return Err(format!("CPU {cpu} captured live SSE sentinel differs"));
            }
        }
        if state.xsave.get(32..42) != Some([0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f].as_slice()) {
            return Err(format!("CPU {cpu} captured live x87 sentinel differs"));
        }
        if word(memory, cpu, 128)? != 0 {
            let component = state
                .xstate
                .iter()
                .find(|c| c.id == 2)
                .ok_or("missing admitted YMM layout")?;
            let offset = component.offset as usize + 14 * 16;
            for (index, value) in [0x1122334455667788u64, 0x8877665544332211u64]
                .iter()
                .enumerate()
            {
                if state.xsave.get(offset + index * 8..offset + index * 8 + 8)
                    != Some(value.to_le_bytes().as_slice())
                {
                    return Err(format!(
                        "CPU {cpu} captured live upper YMM sentinel differs"
                    ));
                }
            }
        }
        let exposed_xstate = state
            .cpuid
            .iter()
            .find(|entry| entry.function == 0xd && entry.index == 0)
            .map(|entry| u64::from(entry.values[0]) | (u64::from(entry.values[3]) << 32))
            .ok_or("actual xstate exposure CPUID leaf missing")?;
        if exposed_xstate & !7 != 0
            || state
                .xcrs
                .iter()
                .any(|xcr| xcr.index == 0 && xcr.value & !7 != 0)
        {
            return Err("unqualified expanded-xstate profile: fixture must not claim an unwitnessed component or suppress CPUID".into());
        }
        if cpu == 0 && matches!(case, Case::Io | Case::Mmio | Case::DueNoIrr) {
            let offset = if case == Case::Mmio { 248 } else { 240 };
            let value = if case == Case::Mmio { 0x5a } else { 0xa5 };
            if state.regs[16] != word(memory, cpu, offset)? || state.regs[0] & 255 != value {
                return Err("IO/MMIO completion was not installed exactly before the first result-store instruction".into());
            }
        }
        let vector = lapic_u32(&state.lapic, 0x320)? & 255;
        let irr = lapic_u32(&state.lapic, 0x200 + (vector / 32) as usize * 16)?
            & (1 << (vector % 32))
            != 0;
        let isr = lapic_u32(&state.lapic, 0x100 + (vector / 32) as usize * 16)?
            & (1 << (vector % 32))
            != 0;
        let cut_tsc = match &envelope.vm {
            VmExecutionState::Kvm(KvmVmState::X86(vm)) => {
                vm.host_tsc.wrapping_add(state.tsc_offset)
            }
            _ => return Err("native x86 clock cut missing".into()),
        };
        let original_compare = word(memory, cpu, 64)?;
        match case {
            Case::Future
                if state.deadline == 0
                    || state.deadline != original_compare
                    || state.deadline <= cut_tsc
                    || state.mp_state != 3 =>
            {
                return Err("future cut lacks original comparator/HALTED state".into());
            }
            Case::Due
                if state.deadline != 0
                    || !irr
                    || original_compare == 0
                    || original_compare > cut_tsc =>
            {
                return Err("materialized original pending timer cut not observed".into());
            }
            Case::DueNoIrr
                if cpu == 0
                    && (state.deadline == 0
                        || state.deadline != original_compare
                        || state.deadline > cut_tsc
                        || irr
                        || isr) =>
            {
                return Err("original due comparator without IRR was not observed".into());
            }
            Case::Masked
                if state.deadline != original_compare
                    || original_compare == 0
                    || original_compare > cut_tsc
                    || lapic_u32(&state.lapic, 0x320)? & (1 << 16) == 0 =>
            {
                return Err("original expired masked comparator cut not observed".into());
            }
            Case::PendingFuture
                if !irr
                    || state.deadline == 0
                    || state.deadline != original_compare
                    || state.deadline <= cut_tsc =>
            {
                return Err("pending-plus-original-new-future-comparator cut not observed".into());
            }
            Case::InService
                if !isr
                    || state.deadline != 0
                    || original_compare == 0
                    || original_compare > cut_tsc =>
            {
                return Err("in-service original timer cut not observed".into());
            }
            _ => (),
        }
    }
    match &envelope.vm {
        VmExecutionState::Kvm(KvmVmState::X86(vm)) if vm.pit_profile == 0 => Ok(()),
        _ => Err("CPU fixture must use reset PIT, never pretend retired Linux admission".into()),
    }
}

fn malformed_cases(bytes: &[u8], expected: &StateBinding, count: u8) -> Result<usize, String> {
    let mut cases = 0;
    for length in [0, 1, 7, bytes.len() / 2, bytes.len().saturating_sub(1)] {
        if ExecutionEnvelope::decode(&bytes[..length]).is_ok() {
            return Err("truncated execution accepted".into());
        }
        cases += 1;
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    if ExecutionEnvelope::decode(&trailing).is_ok() {
        return Err("trailing execution accepted".into());
    }
    cases += 1;
    let mut wrong = expected.clone();
    wrong.profile[0] ^= 1;
    if ValidatedExecution::decode(bytes, &wrong, ExecutionLane::KvmX86, &topology(count), &[])
        .is_ok()
    {
        return Err("wrong execution profile accepted".into());
    }
    cases += 1;
    let mut wrong = expected.clone();
    wrong.native_producer.push_str("different");
    if ValidatedExecution::decode(bytes, &wrong, ExecutionLane::KvmX86, &topology(count), &[])
        .is_ok()
    {
        return Err("wrong producer accepted".into());
    }
    if ValidatedExecution::decode(
        bytes,
        expected,
        ExecutionLane::KvmX86,
        &topology(count),
        &[(1, 0x3f8, Some(4))],
    )
    .is_ok()
    {
        return Err("missing actual participant accepted".into());
    }
    cases += 2;
    Ok(cases)
}

#[derive(Default)]
struct CompletionGate {
    hold: AtomicBool,
    entered: AtomicBool,
    calls: AtomicU64,
}
struct InputPort {
    gate: Arc<CompletionGate>,
    value: u8,
}
impl BusDevice for InputPort {
    fn read(&mut self, _cpu: u64, _offset: u64, data: &mut [u8]) {
        self.gate.entered.store(true, Ordering::Release);
        while self.gate.hold.load(Ordering::Acquire) {
            thread::sleep(Duration::from_micros(100));
        }
        data.fill(self.value);
        self.gate.calls.fetch_add(1, Ordering::Release);
    }
}
fn buses(gate: &Arc<CompletionGate>) -> Result<(Bus, Bus), String> {
    let mut io = Bus::new();
    let mut mmio = Bus::new();
    io.insert(
        Arc::new(Mutex::new(InputPort {
            gate: Arc::clone(gate),
            value: 0xa5,
        })),
        0x500,
        1,
    )
    .map_err(|e| e.to_string())?;
    mmio.insert(
        Arc::new(Mutex::new(InputPort {
            gate: Arc::clone(gate),
            value: 0x5a,
        })),
        0x300000,
        1,
    )
    .map_err(|e| e.to_string())?;
    Ok((io, mmio))
}

fn capture(
    vmm: &mut Vmm,
    expected: &StateBinding,
    request: u64,
    prepared: &ValidatedRamLayout,
) -> Result<Arc<ExecutionEnvelope>, String> {
    check_preparation(vmm, prepared)?;
    let barrier = BarrierRequest {
        key: key(expected.pause_generation),
        deadline: Instant::now() + WAIT,
    };
    vmm.begin_execution_capture(
        RequestId(request),
        barrier,
        expected.clone(),
        &KvmCaptureProfile::ResetPit,
        true,
    )?;
    loop {
        match vmm.poll_execution_capture() {
            Poll::Ready(result) => return result,
            Poll::Pending => thread::sleep(Duration::from_micros(100)),
        }
    }
}
fn capture_withheld(
    vmm: &mut Vmm,
    expected: &StateBinding,
    out: &Path,
    prepared: &ValidatedRamLayout,
) -> Result<Arc<ExecutionEnvelope>, String> {
    check_preparation(vmm, prepared)?;
    let cpu = vmm
        .vcpus_handles
        .len()
        .checked_sub(1)
        .ok_or("withheld owner missing")?;
    vmm.vcpus_handles[cpu].set_probe_ack_hold(Some(CpuCommandKind::CaptureExecution))?;
    let barrier = BarrierRequest {
        key: key(expected.pause_generation),
        deadline: Instant::now() + Duration::from_millis(40),
    };
    vmm.begin_execution_capture(
        RequestId(2),
        barrier,
        expected.clone(),
        &KvmCaptureProfile::ResetPit,
        true,
    )?;
    let failure = loop {
        match vmm.poll_execution_capture() {
            Poll::Ready(Err(error)) => break error,
            Poll::Ready(Ok(_)) => {
                return Err("capture succeeded despite withheld real typed ACK".into());
            }
            Poll::Pending => thread::sleep(Duration::from_micros(100)),
        }
    };
    let ack = vmm.vcpus_handles[cpu]
        .probe_held_ack()?
        .ok_or("actual capture ACK did not reach retained gate")?;
    let reconciled = vmm.control.cpus.reconciled();
    private_write(
        &out.join("withheld-capture-ack.txt"),
        format!("deadline_failure={failure}\nreconciled={reconciled}\nactual_ack={ack:#?}")
            .as_bytes(),
    )?;
    if ack.request != RequestId(2)
        || ack.key != barrier.key
        || ack.cpu_id as usize != cpu
        || ack.kind != crate::vmm::control::CpuAckKind::Captured
        || ack.result.is_err()
        || ack.execution.is_none()
        || reconciled
    {
        return Err(format!(
            "withheld capture ACK was not the exact successful typed owner result; failure={failure}; reconciled={reconciled}; actual_ack={ack:#?}"
        ));
    }
    vmm.vcpus_handles[cpu].set_probe_ack_hold(None)?;
    let captured = loop {
        match vmm.poll_execution_capture() {
            Poll::Ready(result) => break result?,
            Poll::Pending => thread::sleep(Duration::from_micros(100)),
        }
    };
    if ack.execution.as_deref() != captured.cpus.get(cpu) {
        return Err("late capture reconciliation replaced the retained actual payload".into());
    }
    // Reconciliation is not a backdated success for the expired caller.
    let recaptured = capture(vmm, expected, 4, prepared)?;
    if captured != recaptured {
        return Err("fresh capture changed the reconciled logical cut".into());
    }
    Ok(recaptured)
}
fn progress(memory: &RuntimeGuestMemory, count: u8) -> Result<Vec<u64>, String> {
    (0..usize::from(count))
        .map(|cpu| word(memory, cpu, 16))
        .collect()
}
fn identities(memory: &RuntimeGuestMemory, count: u8) -> Result<(), String> {
    for cpu in 0..usize::from(count) {
        if word(memory, cpu, 0)? != MAGIC
            || word(memory, cpu, 8)? != 1
            || word(memory, cpu, 24)? != 0
        {
            return Err(format!(
                "CPU {cpu} rebooted or lost a live register sentinel"
            ));
        }
    }
    Ok(())
}
fn continued(memory: &RuntimeGuestMemory, count: u8) -> Result<Vec<u64>, String> {
    let before = progress(memory, count)?;
    wait_until("guest sustained progress", || {
        Ok(progress(memory, count)?
            .iter()
            .zip(&before)
            .all(|(a, b)| a > b))
    })?;
    identities(memory, count)?;
    progress(memory, count)
}
fn bracket(
    memory: &RuntimeGuestMemory,
    count: u8,
    offset_difference: u64,
) -> Result<Vec<u64>, String> {
    if count == 1 {
        return Ok(Vec::new());
    }
    let sequence = word(memory, 0, 88)?
        .max(word(memory, 1, 88)?)
        .checked_add(1)
        .ok_or("clock request exhausted")?;
    let finish_sequence = sequence.checked_add(1).ok_or("clock request exhausted")?;
    set_word(memory, 0, 80, sequence)?;
    wait_until("primary bracket start", || {
        Ok(word(memory, 0, 88)? == sequence)
    })?;
    let lower = word(memory, 0, 96)?;
    set_word(memory, 1, 80, sequence)?;
    wait_until("contemporary AP timestamp", || {
        Ok(word(memory, 1, 88)? == sequence)
    })?;
    let middle = word(memory, 1, 96)?;
    set_word(memory, 0, 80, finish_sequence)?;
    wait_until("primary bracket end", || {
        Ok(word(memory, 0, 88)? == finish_sequence)
    })?;
    let upper = word(memory, 0, 96)?;
    let normalized = middle.wrapping_sub(offset_difference);
    if !(lower <= normalized && normalized <= upper) {
        return Err(format!(
            "cross-CPU TSC bracket: {lower} <= {normalized} <= {upper} failed (raw AP={middle})"
        ));
    }
    Ok(vec![lower, middle, normalized, upper])
}
fn prepare_case(vmm: &mut Vmm, count: u8, case: Case, gate: &CompletionGate) -> Result<(), String> {
    if case == Case::Offline {
        return Ok(());
    }
    for cpu in 0..usize::from(count) {
        set_word(&vmm.guest_memory, cpu, 32, 0)?;
    }
    wait_until("guest command idle", || {
        for cpu in 0..usize::from(count) {
            if word(&vmm.guest_memory, cpu, 40)? != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    if matches!(case, Case::Io | Case::Mmio | Case::DueNoIrr) {
        gate.entered.store(false, Ordering::Release);
        gate.hold.store(true, Ordering::Release);
        set_word(&vmm.guest_memory, 0, 32, case.command())?;
        wait_until("actual bus callback", || {
            Ok(gate.entered.load(Ordering::Acquire))
        })?;
        if case == Case::DueNoIrr {
            thread::sleep(Duration::from_millis(600));
        }
        return Ok(());
    }
    for cpu in 0..usize::from(count) {
        set_word(&vmm.guest_memory, cpu, 32, case.command())?;
    }
    wait_until("original guest timer programmed", || {
        for cpu in 0..usize::from(count) {
            let ready = match case {
                Case::Future => word(&vmm.guest_memory, cpu, 40)? == 1,
                Case::Due | Case::Masked => word(&vmm.guest_memory, cpu, 144)? == 1,
                Case::PendingFuture => word(&vmm.guest_memory, cpu, 144)? == 2,
                Case::InService => word(&vmm.guest_memory, cpu, 152)? == 1,
                _ => false,
            };
            if !ready {
                return Ok(false);
            }
        }
        Ok(true)
    })
}
fn park(vmm: &mut Vmm, generation: u64, gate: &CompletionGate) -> Result<(), String> {
    let barrier = BarrierRequest {
        key: key(generation),
        deadline: Instant::now() + WAIT,
    };
    let result = vmm.control.cpus.begin(
        RequestId(1),
        barrier,
        CpuCommandKind::Park,
        &vmm.vcpus_handles,
    );
    // Release the actual bus callback only after Park has been accepted.
    gate.hold.store(false, Ordering::Release);
    result.map_err(|e| e.to_string())?;
    loop {
        match vmm.control.cpus.poll(&mut vmm.vcpus_handles) {
            Poll::Ready(result) => return result.map_err(|e| e.to_string()),
            Poll::Pending => thread::sleep(Duration::from_micros(100)),
        }
    }
}

struct Attempt {
    vmm: Vmm,
    gate: Arc<CompletionGate>,
    stopped: bool,
}
impl Attempt {
    fn stop(&mut self) -> Result<(), String> {
        self.gate.hold.store(false, Ordering::Release);
        let mut failure = None;
        for handle in &self.vmm.vcpus_handles {
            if let Err(error) = handle.set_probe_ack_hold(None) {
                failure.get_or_insert(error);
            }
        }
        let barrier = BarrierRequest {
            key: key(u64::MAX),
            deadline: Instant::now() + WAIT,
        };
        loop {
            match self
                .vmm
                .stop_execution_attempt(RequestId(u64::MAX), barrier)
            {
                Poll::Ready(Ok(())) => {
                    self.stopped = true;
                    return failure.map_or(Ok(()), Err);
                }
                Poll::Ready(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Poll::Pending => (),
            }
            if Instant::now() >= barrier.deadline {
                return Err(format!(
                    "terminal cleanup deadline; retained_failure={failure:?}; all_reaped=false"
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}
fn release(vmm: &mut Vmm, generation: u64) -> Result<(u128, String), String> {
    let barrier = BarrierRequest {
        key: BarrierKey {
            operation: OperationId(1000 + generation),
            generation: BarrierGeneration(generation),
        },
        deadline: Instant::now() + WAIT,
    };
    let start = Instant::now();
    vmm.prepare_execution_release(RequestId(100), barrier)?;
    // Same preparation key must be an absolute idempotent target, never an added displacement.
    vmm.prepare_execution_release(RequestId(100), barrier)?;
    let plans = vmm
        .execution
        .preparation_observation()
        .ok_or("actual preparation plans absent")?;
    let clocks = vmm
        .vm
        .execution_time_observation()?
        .ok_or("actual paired-clock preparation observation absent")?;
    let observation = format!("plans={plans:#?}; clocks={clocks:#?}");
    vmm.release_prepared_execution(RequestId(101), barrier)?;
    Ok((start.elapsed().as_nanos(), observation))
}
fn resume_original(
    attempt: &mut Attempt,
    envelope: &ExecutionEnvelope,
    count: u8,
    case: Case,
) -> Result<String, String> {
    let memory = attempt.vmm.guest_memory.clone();
    let active = if matches!(case, Case::Offline | Case::DueNoIrr) {
        1
    } else {
        count
    };
    let irq_before = (0..usize::from(active))
        .map(|cpu| word(&memory, cpu, 48))
        .collect::<Result<Vec<_>, _>>()?;
    let arms_before = (0..usize::from(active))
        .map(|cpu| word(&memory, cpu, 56))
        .collect::<Result<Vec<_>, _>>()?;
    let completion_offset = if case == Case::Mmio { 112 } else { 104 };
    let completion_before = word(&memory, 0, completion_offset)?;
    let callbacks_before = attempt.gate.calls.load(Ordering::Acquire);
    let expected_residual_ns = if case == Case::Future {
        let state = x86(envelope.cpus.first().ok_or("missing BSP cut")?)?;
        let VmExecutionState::Kvm(KvmVmState::X86(vm)) = &envelope.vm else {
            return Err("missing VM clock cut".into());
        };
        let guest_cut = vm.host_tsc.wrapping_add(state.tsc_offset);
        let ticks = state
            .deadline
            .checked_sub(guest_cut)
            .ok_or("future deadline already due at cut")?;
        u128::from(ticks) * 1_000_000 / u128::from(state.tsc_khz)
    } else {
        0
    };
    let resumed_at = Instant::now();
    let (preparation_ns, preparation_observation) =
        release(&mut attempt.vmm, envelope.binding.pause_generation)?;
    if matches!(case, Case::Due | Case::Masked | Case::PendingFuture) {
        // Only guest interrupt acceptance changes. No replacement comparator or host IRQ.
        for cpu in 0..usize::from(active) {
            set_word(&memory, cpu, 32, 9)?;
        }
    } else if case == Case::InService {
        for cpu in 0..usize::from(active) {
            set_word(&memory, cpu, 32, 0)?;
        }
    }
    if matches!(
        case,
        Case::Future | Case::Due | Case::DueNoIrr | Case::Masked | Case::PendingFuture
    ) {
        let expected = if case == Case::PendingFuture { 2 } else { 1 };
        wait_until("original timer expiry, never test-side rearmed", || {
            for (cpu, before) in irq_before.iter().enumerate() {
                if word(&memory, cpu, 48)?.saturating_sub(*before) < expected {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        if case == Case::Future && resumed_at.elapsed().as_nanos() < expected_residual_ns / 2 {
            return Err(
                "future original timer aged through prepared dwell or woke immediately".into(),
            );
        }
        for cpu in 0..usize::from(active) {
            set_word(&memory, cpu, 32, 0)?;
        }
        thread::sleep(Duration::from_millis(50));
        for cpu in 0..usize::from(active) {
            if word(&memory, cpu, 48)? - irq_before[cpu] != expected
                || word(&memory, cpu, 56)? != arms_before[cpu]
            {
                return Err("original timer duplicated, lost, or fixture rearmed it".into());
            }
        }
    } else if case == Case::Offline && count == 2 {
        if word(&memory, 1, 8)? != 0 {
            return Err("destination offline AP executed before guest wake".into());
        }
        set_word(&memory, 0, 32, 8)?;
        wait_until(
            "restored guest INIT/SIPI starts original offline AP",
            || Ok(word(&memory, 1, 8)? == 1),
        )?;
    }
    let before = continued(&memory, count)?;
    if case == Case::InService {
        for cpu in 0..usize::from(active) {
            if word(&memory, cpu, 48)? != irq_before[cpu]
                || word(&memory, cpu, 56)? != arms_before[cpu]
            {
                return Err(
                    "original in-service timer was duplicated or rearmed before EOI".into(),
                );
            }
        }
    }
    if matches!(case, Case::Io | Case::Mmio | Case::DueNoIrr) {
        let expected = completion_before
            .checked_add(1)
            .ok_or("fixture completion count overflow")?;
        wait_until("original IO/MMIO result store", || {
            Ok(word(&memory, 0, completion_offset)? >= expected)
        })?;
        if word(&memory, 0, completion_offset)? != expected
            || attempt.gate.calls.load(Ordering::Acquire) != callbacks_before
        {
            return Err(
                "captured IO/MMIO executed again or completion was not exactly once".into(),
            );
        }
    }
    let bsp_offset = x86(envelope.cpus.first().ok_or("BSP offset missing")?)?.tsc_offset;
    let offset_difference = if count == 2 {
        x86(envelope.cpus.get(1).ok_or("AP offset missing")?)?
            .tsc_offset
            .wrapping_sub(bsp_offset)
    } else {
        0
    };
    let bracket = bracket(&memory, count, offset_difference)?;
    let steady_before = (0..usize::from(count))
        .map(|cpu| {
            Ok([
                word(&memory, cpu, 48)?,
                word(&memory, cpu, 104)?,
                word(&memory, cpu, 112)?,
            ])
        })
        .collect::<Result<Vec<_>, String>>()?;
    // Start NEW guest work only after the original-cause oracle has completed.
    for cpu in 0..usize::from(count) {
        set_word(&memory, cpu, 32, 13)?;
    }
    wait_until("guest starts sustained deadline and IO workload", || {
        for cpu in 0..usize::from(count) {
            if word(&memory, cpu, 40)? != 13 {
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    thread::sleep(Duration::from_secs(1));
    let after = continued(&memory, count)?;
    if after.iter().zip(&before).any(|(a, b)| a <= b) {
        return Err("guest stopped making useful progress".into());
    }
    let steady_after = (0..usize::from(count))
        .map(|cpu| {
            Ok([
                word(&memory, cpu, 48)?,
                word(&memory, cpu, 104)?,
                word(&memory, cpu, 112)?,
            ])
        })
        .collect::<Result<Vec<_>, String>>()?;
    for (after, before) in steady_after.iter().zip(&steady_before) {
        if after
            .iter()
            .zip(before)
            .any(|(a, b)| a.saturating_sub(*b) < 10)
        {
            return Err(
                "sustained original guest did not complete many timer/IO/MMIO cycles".into(),
            );
        }
    }
    Ok(format!(
        "\"preparation_ns\":{preparation_ns},\"preparation_observation\":{},\"expected_residual_ns\":{expected_residual_ns},\"progress_before\":{before:?},\"progress_after\":{after:?},\"tsc_bracket\":{bracket:?},\"irq_before\":{irq_before:?},\"arms_before\":{arms_before:?},\"steady_before\":{steady_before:?},\"steady_after\":{steady_after:?}",
        json_string(&preparation_observation)
    ))
}
fn checked_msr_count_proof(envelope: &ExecutionEnvelope) -> Result<String, String> {
    let mut output = String::from("[");
    for (index, cpu) in envelope.cpus.iter().enumerate() {
        let cpu = x86(cpu)?;
        if index != 0 {
            output.push(',');
        }
        write!(output, "{{\"cpu\":{},\"proof\":\"derived-from-successfully-checked-native-transfer-not-raw-return-ledger\"", cpu.id)
            .map_err(|error| error.to_string())?;
        for (name, entries) in [
            ("state", cpu.msrs.as_slice()),
            ("model", cpu.model_msrs.as_slice()),
        ] {
            write!(output, ",\"get_{name}_requested_completed_chunks\":[")
                .map_err(|error| error.to_string())?;
            for (index, chunk) in entries.chunks(256).enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write!(output, "{}", chunk.len()).map_err(|error| error.to_string())?;
            }
            output.push(']');
        }
        output.push_str(
            ",\"single_get_requested_completed\":1,\"single_get_indices\":[377,16,1760]}",
        );
    }
    output.push(']');
    Ok(output)
}
fn save_capture(
    attempt: &mut Attempt,
    out: &Path,
    expected: &StateBinding,
    count: u8,
    case: Case,
    prepared: &ValidatedRamLayout,
) -> Result<Arc<ExecutionEnvelope>, String> {
    prepare_case(&mut attempt.vmm, count, case, &attempt.gate)?;
    park(&mut attempt.vmm, expected.pause_generation, &attempt.gate)?;
    let first = capture(&mut attempt.vmm, expected, 2, prepared)?;
    validate_cut(&first, &attempt.vmm.guest_memory, case, count)?;
    let bytes = first.encode().map_err(|e| e.to_string())?;
    let checks = malformed_cases(&bytes, expected, count)?;
    private_write(&out.join("execution.state"), &bytes)?;
    // A real output-open failure must not consume the source cut.
    if private_write(&out.join("execution.state"), &bytes).is_ok() {
        return Err("exclusive output failure was not exercised".into());
    }
    thread::sleep(Duration::from_millis(20));
    let second = capture(&mut attempt.vmm, expected, 3, prepared)?;
    if first != second || bytes != second.encode().map_err(|e| e.to_string())? {
        return Err("repeated capture aged or replaced the retained logical cut".into());
    }
    let output_file = |name: &str| -> Result<File, String> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out.join(name))
            .map_err(|error| error.to_string())
    };
    let output = RamOutputFiles::new(
        output_file("ram.bin")?,
        output_file("memory-layout.json")?,
        true,
    );
    let cut_key = key(expected.pause_generation);
    let id = attempt
        .vmm
        .diagnostic_begin_memory_capture(cut_key, RamCaptureRequest::Full)
        .map_err(|error| error.to_string())?;
    let completed =
        attempt
            .vmm
            .diagnostic_write_memory_capture(cut_key, &id, output, Instant::now() + WAIT);
    // This diagnostic never continues against a newly accepted source baseline.
    // Resolve even failed writes explicitly, preserving the coordinator's dirty union.
    let abandoned = attempt.vmm.diagnostic_abandon_memory(cut_key, &id);
    let candidate =
        completed.map_err(|error| format!("RAM output: {error}; abandon={abandoned:?}"))?;
    abandoned.map_err(|error| error.to_string())?;
    drop(candidate);
    private_write(
        &out.join("native-inventory.txt"),
        format!("{first:#?}").as_bytes(),
    )?;
    let msr_counts = checked_msr_count_proof(&first)?;
    private_write(&out.join("capture.json"), format!("{{\"schema\":1,\"scope\":\"cpu-execution-only\",\"qualification_eligible\":false,\"vcpus\":{count},\"case\":{},\"malformed_refusals\":{checks},\"repeated_capture_equal\":true,\"failed_output_recapture_equal\":true,\"native_inventory\":\"native-inventory.txt\",\"execution\":\"execution.state\",\"ram\":\"ram.bin\",\"layout\":\"memory-layout.json\",\"memory_attempt\":\"explicitly-abandoned\",\"msr_checked_counts\":{msr_counts}}}", json_string(&format!("{case:?}"))).as_bytes())?;
    Ok(first)
}
fn new_output(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("create private evidence directory {}: {e}", path.display()))
}
fn text(value: &OsString) -> Result<&str, String> {
    value.to_str().ok_or_else(|| "argument is not UTF-8".into())
}
fn cpu_count(value: &OsString) -> Result<u8, String> {
    match text(value)?.parse::<u8>() {
        Ok(count @ 1..=2) => Ok(count),
        _ => Err("fixture CPU count must be one or two".into()),
    }
}
fn load_state(
    input: &Path,
    expected: &StateBinding,
    count: u8,
) -> Result<ValidatedExecution, String> {
    let bytes = bounded_read(
        &input.join("execution.state"),
        crate::vmm::execution::MAX_EXECUTION_BYTES,
    )?;
    ValidatedExecution::decode(
        &bytes,
        expected,
        ExecutionLane::KvmX86,
        &topology(count),
        &[],
    )
    .map_err(|e| e.to_string())
}
fn fixture_memory(payload: &Path, handler: u64) -> Result<GuestMemoryMmap, String> {
    let bytes = bounded_read(payload, MAX_FIXTURE)?;
    if bytes.is_empty()
        || handler < ENTRY
        || handler >= ENTRY + bytes.len() as u64
        || handler > 0xffff
    {
        return Err("invalid fixture/interrupt symbol extent".into());
    }
    let memory = memory()?;
    memory
        .write_slice(&bytes, GuestAddress(ENTRY))
        .map_err(|e| e.to_string())?;
    let mut gate = [0u8; 16];
    gate[..2].copy_from_slice(&(handler as u16).to_le_bytes());
    gate[2..4].copy_from_slice(&24u16.to_le_bytes());
    gate[5] = 0x8e;
    gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
    gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
    memory
        .write_slice(&gate, GuestAddress(0xb000 + 0xe0 * 16))
        .map_err(|e| e.to_string())?;
    Ok(memory)
}

/// Execute only through the opt-in standalone target. Unit tests never call this.
pub fn run(args: Vec<OsString>) -> Result<ProbeResult, ProbeResult> {
    run_inner(&args).map(|json| ProbeResult { json }).map_err(|error| ProbeResult {
        json: format!("{{\"schema\":1,\"status\":\"failed\",\"scope\":\"cpu-execution-only\",\"qualification_eligible\":false,\"native_pause\":false,\"public_live\":\"not-delivered\",\"error\":{}}}", json_string(&error)),
    })
}
fn run_inner(args: &[OsString]) -> Result<String, String> {
    let mode = args.first().ok_or("expected source or restore command")?;
    let mode = text(mode)?;
    if mode == "partial" {
        if args.len() != 7 {
            return Err("partial INPUT BINDING CPUS GENERATION RAM_FD LAYOUT_FD".into());
        }
        let input = PathBuf::from(&args[1]);
        let count = cpu_count(&args[3])?;
        let generation = text(&args[4])?.parse::<u64>().map_err(|e| e.to_string())?;
        let expected = binding(Path::new(&args[2]), generation)?;
        let validated = load_state(&input, &expected, count)?;
        let index = usize::from(count - 1);
        let ram = restored_ram(&input, &validated, &args[5], &args[6])?;
        let gate = Arc::new(CompletionGate::default());
        let (io, mmio) = buses(&gate)?;
        let mut devices = PreparedDeviceInstall::diagnostic(&expected, io, mmio)?;
        devices.hold_diagnostic_install_ack(count - 1)?;
        let mut failure = match build_restore_prepared(
            ram,
            validated,
            devices,
            &mut polly::event_manager::EventManager::new()
                .map_err(|error| format!("restore event manager: {error:?}"))?,
            Instant::now() + Duration::from_millis(200),
        ) {
            Ok(vmm) => {
                let mut attempt = Attempt {
                    vmm,
                    gate,
                    stopped: false,
                };
                attempt.stop()?;
                return Err(
                    "fresh construction succeeded with an actual native install ACK withheld"
                        .into(),
                );
            }
            Err(failure) => failure,
        };
        let native_error = failure.error.clone();
        let vmm = failure
            .attempt
            .take()
            .ok_or("partial install did not retain actual owner handles")?;
        let mut attempt = Attempt {
            vmm: *vmm,
            gate,
            stopped: false,
        };
        let no_entry = !attempt.vmm.control.cpus.release_may_have_run();
        let ack = attempt
            .vmm
            .vcpus_handles
            .get(index)
            .ok_or("partial owner missing")?
            .probe_held_ack()?
            .ok_or("actual native Installed ACK was not retained at the failure boundary")?;
        let installed = ack.cpu_id as usize == index
            && ack.request == RequestId(0)
            && ack.key.operation == OperationId(0)
            && ack.key.generation.0 == generation
            && ack.kind == crate::vmm::control::CpuAckKind::Installed
            && ack.result.is_ok()
            && ack.execution.is_none()
            && !attempt.vmm.control.cpus.reconciled();
        let observation = format!("{ack:#?}");
        attempt.stop()?;
        if !no_entry || !installed {
            return Err(format!(
                "wrong partial native install-completion boundary or first entry: {native_error}; {observation}"
            ));
        }
        return Ok(format!(
            "{{\"schema\":1,\"status\":\"passed\",\"scope\":\"cpu-execution-only\",\"qualification_eligible\":false,\"native_pause\":false,\"all_reaped\":true,\"zero_first_instruction\":true,\"release_may_have_run\":false,\"boundary\":\"native-install-completion-withheld\",\"native_error\":{},\"actual_installed_ack\":{}}}",
            json_string(&native_error),
            json_string(&observation)
        ));
    }
    if mode == "source" || mode == "negative" {
        if args.len() != 7 {
            return Err(
                "source|negative OUT LAYOUT_BINDING_FD FIXTURE HANDLER:IO:MMIO CPUS CASE".into(),
            );
        }
        let negative = mode == "negative";
        let out = PathBuf::from(&args[1]);
        let count = cpu_count(&args[5])?;
        let case = if negative {
            Case::Future
        } else {
            Case::parse(text(&args[6])?)?
        };
        if case == Case::Offline && count != 2 {
            return Err("offline witness needs two CPUs".into());
        }
        let mut channel = inherited_channel(&args[2])?;
        let deadline = Instant::now() + WAIT;
        let symbols = text(&args[4])?
            .split(':')
            .map(|value| {
                u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if symbols.len() != 3 {
            return Err("expected HANDLER:IO_COMPLETE:MMIO_COMPLETE symbols".into());
        }
        let memory = fixture_memory(Path::new(&args[3]), symbols[0])?;
        memory
            .write_obj(symbols[1], GuestAddress(SLOT + 240))
            .map_err(|error| error.to_string())?;
        memory
            .write_obj(symbols[2], GuestAddress(SLOT + 248))
            .map_err(|error| error.to_string())?;
        let gate = Arc::new(CompletionGate::default());
        let (io, mmio) = buses(&gate)?;
        let vmm = build_execution_fixture(
            memory,
            fixture_info()?,
            count,
            ENTRY,
            case == Case::Offline,
            io,
            mmio,
            deadline,
        )?;
        let mut attempt = Attempt {
            vmm,
            gate,
            stopped: false,
        };
        let result: Result<String, String> = (|| {
            let prepared = attempt
                .vmm
                .memory_layout()
                .map_err(|error| error.to_string())?;
            let expected = exchange_binding(&mut channel, prepared.canonical_bytes(), deadline)?;
            new_output(&out)?;
            let vm_capabilities = format!(
                "{{\"KVM_CAP_XSAVE2\":{},\"KVM_CAP_TSC_DEADLINE_TIMER\":{}}}",
                attempt
                    .vmm
                    .vm
                    .fd()
                    .check_extension_int(kvm_ioctls::Cap::Xsave2),
                attempt
                    .vmm
                    .vm
                    .fd()
                    .check_extension(kvm_ioctls::Cap::TscDeadlineTimer)
            );
            private_write(
                &out.join("vm-capabilities.json"),
                vm_capabilities.as_bytes(),
            )?;
            attempt.vmm.resume_vcpus().map_err(|e| e.to_string())?;
            let active = if case == Case::Offline { 1 } else { count };
            continued(&attempt.vmm.guest_memory, active)?;
            // Observe actual native TSC frequency before allowing the fixture to arm.
            park(&mut attempt.vmm, 1, &attempt.gate)?;
            let seed = capture_withheld(&mut attempt.vmm, &expected, &out, &prepared)?;
            release(&mut attempt.vmm, 1)?;
            // Seed writes belong to the reopened epoch, never to the sealed execution cut.
            for (cpu, state) in seed.cpus.iter().enumerate() {
                set_word(
                    &attempt.vmm.guest_memory,
                    cpu,
                    136,
                    u64::from(x86(state)?.tsc_khz) * 500,
                )?;
            }
            let mut next = expected;
            next.pause_generation = 2;
            if negative {
                let (guest_command, subject) = match text(&args[6])? {
                    "active-pit" => (11, "pit/"),
                    "count-lapic" => (12, "lapic/"),
                    _ => return Err("unknown negative native timer profile".into()),
                };
                set_word(&attempt.vmm.guest_memory, 0, 32, guest_command)?;
                wait_until("guest genuinely programs unsupported native timer", || {
                    Ok(word(&attempt.vmm.guest_memory, 0, 40)? == guest_command)
                })?;
                park(&mut attempt.vmm, 2, &attempt.gate)?;
                let native_error = match capture(&mut attempt.vmm, &next, 2, &prepared) {
                    Err(error) => error,
                    Ok(_) => {
                        return Err("active unsupported native timer profile was admitted".into());
                    }
                };
                if !native_error.contains(subject) {
                    return Err(format!("wrong native refusal boundary: {native_error}"));
                }
                return Ok(format!(
                    "{{\"schema\":1,\"status\":\"passed\",\"scope\":\"cpu-execution-only\",\"qualification_eligible\":false,\"native_pause\":false,\"all_reaped\":true,\"native_profile_refused\":{}}}",
                    json_string(&native_error)
                ));
            }
            let captured = save_capture(&mut attempt, &out, &next, count, case, &prepared)?;
            let continuation = resume_original(&mut attempt, &captured, count, case)?;
            Ok(format!(
                "{{\"schema\":1,\"status\":\"passed\",\"scope\":\"cpu-execution-only\",\"qualification_eligible\":false,\"native_pause\":false,\"public_live\":\"not-delivered\",\"source_resumed\":true,\"pid\":{},\"all_reaped\":true,{continuation}}}",
                std::process::id()
            ))
        })();
        return finish_attempt(&mut attempt, result);
    }
    if mode != "restore" || args.len() != 10 {
        return Err(
            "restore INPUT OUT BINDING CPUS CASE GENERATION DWELL_MS RAM_FD LAYOUT_FD".into(),
        );
    }
    let input = PathBuf::from(&args[1]);
    let out = PathBuf::from(&args[2]);
    let count = cpu_count(&args[4])?;
    let case = Case::parse(text(&args[5])?)?;
    let generation = text(&args[6])?.parse::<u64>().map_err(|e| e.to_string())?;
    let dwell = text(&args[7])?.parse::<u64>().map_err(|e| e.to_string())?;
    if dwell > 60_000 || !(2..=100).contains(&generation) {
        return Err("fixture dwell/generation bound".into());
    }
    let expected = binding(Path::new(&args[3]), generation)?;
    let validated = load_state(&input, &expected, count)?;
    let original = validated.envelope().clone();
    let ram = restored_ram(&input, &validated, &args[8], &args[9])?;
    let gate = Arc::new(CompletionGate::default());
    let (io, mmio) = buses(&gate)?;
    let devices = PreparedDeviceInstall::diagnostic(&expected, io, mmio)?;
    let vmm = match build_restore_prepared(
        ram,
        validated,
        devices,
        &mut polly::event_manager::EventManager::new()
            .map_err(|error| format!("restore event manager: {error:?}"))?,
        Instant::now() + WAIT,
    ) {
        Ok(vmm) => vmm,
        Err(mut failure) => {
            if let Some(vmm) = failure.attempt.take() {
                let mut attempt = Attempt {
                    vmm: *vmm,
                    gate,
                    stopped: false,
                };
                let cleanup = attempt.stop();
                return Err(format!(
                    "fresh install refused: {}; cleanup={cleanup:?}",
                    failure.error
                ));
            }
            return Err(format!(
                "fresh install refused before owners: {}",
                failure.error
            ));
        }
    };
    let mut attempt = Attempt {
        vmm,
        gate,
        stopped: false,
    };
    let result: Result<String, String> = (|| {
        let prepared = attempt
            .vmm
            .memory_layout()
            .map_err(|error| error.to_string())?;
        new_output(&out)?;
        if attempt.vmm.control.cpus.release_may_have_run() {
            return Err("fresh prepared construction accepted a premature CPU Release".into());
        }
        let before = ram_bytes(&attempt.vmm.guest_memory)?;
        thread::sleep(Duration::from_millis(dwell));
        if before != ram_bytes(&attempt.vmm.guest_memory)? {
            return Err("prepared dwell mutated guest RAM or executed an instruction".into());
        }
        validate_cut(&original, &attempt.vmm.guest_memory, case, count)?;
        let continuation = resume_original(&mut attempt, &original, count, case)?;
        let mut next = expected;
        next.pause_generation = generation + 1;
        let recapture_case = if case == Case::Offline {
            Case::Future
        } else {
            case
        };
        let recaptured = save_capture(&mut attempt, &out, &next, count, recapture_case, &prepared)?;
        if recaptured.cpus == original.cpus {
            return Err("child recapture copied ancestor CPU state".into());
        }
        Ok(format!(
            "{{\"schema\":1,\"status\":\"passed\",\"scope\":\"cpu-execution-only\",\"qualification_eligible\":false,\"native_pause\":false,\"public_live\":\"not-delivered\",\"fresh_process\":true,\"pid\":{},\"dwell_ms\":{dwell},\"prepared_ram_unchanged\":true,\"child_recaptured\":true,\"all_reaped\":true,{continuation}}}",
            std::process::id()
        ))
    })();
    finish_attempt(&mut attempt, result)
}

fn finish_attempt(attempt: &mut Attempt, result: Result<String, String>) -> Result<String, String> {
    let cleanup = attempt.stop();
    match (result, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (result, cleanup) => Err(format!(
            "execution={result:?}; cleanup={cleanup:?}; all_reaped={}",
            attempt.stopped
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::api::native_execution_probe::{Case, cpu_count, json_string};
    #[test]
    fn native_execution_probe_closed_cases_and_bounds() {
        for name in [
            "future",
            "due",
            "due-no-irr",
            "masked",
            "pending-future",
            "in-service",
            "offline",
            "io",
            "mmio",
        ] {
            assert!(Case::parse(name).is_ok());
        }
        assert!(Case::parse("active-pit").is_err());
        assert!(cpu_count(&"0".into()).is_err());
        assert!(cpu_count(&"3".into()).is_err());
        assert_eq!(cpu_count(&"2".into()).unwrap(), 2);
    }
    #[test]
    fn native_execution_probe_json_escapes_native_errors() {
        assert_eq!(
            json_string("native\\\"\n\u{1}"),
            "\"native\\\\\\\"\\n\\u0001\""
        );
    }
    #[test]
    fn native_execution_probe_fixture_ram_copy_preserves_boundaries() {
        use crate::api::native_execution_probe::{RAM_BYTES, memory, ram_bytes};
        use crate::vmm::memory::runtime_memory_for_test;
        use vm_memory::GuestAddress;
        let ram = runtime_memory_for_test(memory().unwrap());
        ram.write_slice(&[0x35, 0xa7], GuestAddress(0)).unwrap();
        ram.write_slice(&[0x81, 0x19], GuestAddress(RAM_BYTES as u64 - 2))
            .unwrap();
        let observed = ram.clone();
        assert!(std::sync::Arc::ptr_eq(ram.domain(), observed.domain()));
        drop(ram);
        let bytes = ram_bytes(&observed).unwrap();
        assert_eq!(bytes.len(), RAM_BYTES);
        assert_eq!(&bytes[..2], &[0x35, 0xa7]);
        assert_eq!(&bytes[RAM_BYTES - 2..], &[0x81, 0x19]);
    }
    #[test]
    fn native_execution_probe_fixture_files_are_bounded_private_and_regular() {
        use crate::api::native_execution_probe::{
            ENTRY, bounded_read, fixture_memory, new_output, private_write,
        };
        use nix::sys::stat::Mode;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "krun-execution-pure-{}-{nonce}",
            std::process::id()
        ));
        new_output(&directory).unwrap();
        let file = directory.join("bytes");
        private_write(&file, &[1, 2, 3]).unwrap();
        assert_eq!(bounded_read(&file, 3).unwrap(), [1, 2, 3]);
        assert!(bounded_read(&file, 2).is_err());
        assert!(private_write(&file, &[4]).is_err());
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let empty = directory.join("empty");
        private_write(&empty, &[]).unwrap();
        assert!(fixture_memory(&empty, ENTRY).is_err());
        let fifo = directory.join("fifo");
        nix::unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        assert!(bounded_read(&fifo, 3).is_err());
        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_file(empty).unwrap();
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    fn binding_material() -> [u8; 160] {
        let mut material = [1; 160];
        material[96..128].fill(4);
        material
    }

    #[test]
    fn native_layout_binding_uses_exact_fixed_response_and_eof() {
        use crate::api::native_execution_probe::{WAIT, exchange_binding};
        use std::io::{Read, Write};
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Instant;
        let (mut native, mut controller) = UnixStream::pair().unwrap();
        let peer = std::thread::spawn(move || {
            let mut header = [0; 4];
            controller.read_exact(&mut header).unwrap();
            let mut layout = Vec::new();
            controller.read_to_end(&mut layout).unwrap();
            assert_eq!(u32::from_le_bytes(header) as usize, layout.len());
            assert_eq!(layout, b"exact-prepared-bytes");
            for fragment in binding_material().chunks(7) {
                controller.write_all(fragment).unwrap();
            }
            controller.shutdown(Shutdown::Write).unwrap();
        });
        let binding =
            exchange_binding(&mut native, b"exact-prepared-bytes", Instant::now() + WAIT).unwrap();
        assert_eq!(binding.ram_layout, [4; 32]);
        assert_eq!(binding.pause_generation, 1);
        peer.join().unwrap();
    }

    #[test]
    fn native_layout_binding_rejects_short_extra_invalid_and_expired_frames() {
        use crate::api::native_execution_probe::{MAX_RAM_LAYOUT_BYTES, WAIT, exchange_binding};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};
        let mut extra = binding_material().to_vec();
        extra.push(1);
        for reply in [vec![], vec![1; 159], extra, vec![0; 160]] {
            let (mut native, mut controller) = UnixStream::pair().unwrap();
            let peer = std::thread::spawn(move || {
                let mut layout = Vec::new();
                controller.read_to_end(&mut layout).unwrap();
                controller.write_all(&reply).unwrap();
            });
            assert!(exchange_binding(&mut native, b"layout", Instant::now() + WAIT).is_err());
            peer.join().unwrap();
        }
        let (mut native, _peer) = UnixStream::pair().unwrap();
        assert!(exchange_binding(&mut native, &[], Instant::now() + WAIT).is_err());
        assert!(
            exchange_binding(
                &mut native,
                &vec![1; MAX_RAM_LAYOUT_BYTES + 1],
                Instant::now() + WAIT
            )
            .is_err()
        );
        assert!(
            exchange_binding(
                &mut native,
                b"layout",
                Instant::now() - Duration::from_millis(1)
            )
            .is_err()
        );
        assert!(
            exchange_binding(
                &mut native,
                b"layout",
                Instant::now() + Duration::from_millis(10)
            )
            .is_err()
        );
    }

    #[test]
    fn native_ram_authentication_binds_exact_width_and_layout_identity() {
        use crate::api::native_execution_probe::{decode_binding, decode_ram_authentication};
        let binding = decode_binding(&binding_material(), 2).unwrap();
        let mut auth = [0; 64];
        auth[..32].copy_from_slice(&binding.ram_layout);
        let decoded = decode_ram_authentication(&auth, &binding).unwrap();
        assert_eq!(decoded.state, binding);
        assert_eq!(decoded.stream, [0; 32]);
        auth[0] ^= 1;
        assert!(decode_ram_authentication(&auth, &binding).is_err());
        assert!(decode_ram_authentication(&auth[..63], &binding).is_err());
        assert!(decode_binding(&[1; 159], 1).is_err());
        assert!(decode_binding(&binding_material(), 0).is_err());
    }

    #[test]
    fn native_cpu_fixture_prepares_valid_actual_canonical_topology() {
        use crate::api::native_execution_probe::{RAM_BYTES, fixture_info, memory};
        use crate::vmm::execution::ExecutionLane;
        use crate::vmm::memory::image::ValidatedRamLayout;
        use crate::vmm::memory::runtime_memory_for_test;
        let memory = runtime_memory_for_test(memory().unwrap());
        let info = fixture_info().unwrap();
        let layout = ValidatedRamLayout::from_registered(
            memory.domain().layout(),
            &info,
            ExecutionLane::KvmX86,
        )
        .unwrap();
        assert_eq!(layout.packed_len(), RAM_BYTES as u64);
        assert_eq!(layout.granule() as usize, info.page_size);
        assert_eq!(
            ValidatedRamLayout::decode(layout.canonical_bytes()).unwrap(),
            layout
        );
        assert!(
            ValidatedRamLayout::from_registered(
                memory.domain().layout(),
                &arch::ArchMemoryInfo::default(),
                ExecutionLane::KvmX86,
            )
            .is_err()
        );
    }
}
