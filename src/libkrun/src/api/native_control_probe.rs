//! Opt-in Linux/x86_64 CPU sub-barrier diagnostic, never whole-machine qualification.

use std::fmt::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

use devices::{Bus, BusDevice};
use kvm_bindings::kvm_pit_config;
use kvm_ioctls::Kvm;
use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::vmm::control::{ControlFailure, CpuAckKind, CpuCommandKind, CpuController, RequestId};
use crate::vmm::vstate::{Vcpu, VcpuHandle, Vm};

const WAIT: Duration = Duration::from_secs(2);
const SHORT: Duration = Duration::from_millis(40);
const ENTRY: u64 = 0x1000;
const HANDLER: u64 = 0x1800;
const MMIO: u64 = 0x8000;
const MEMORY_RANGES: [(GuestAddress, usize); 2] = [
    (GuestAddress(0), MMIO as usize),
    (GuestAddress(MMIO + 0x1000), 0x1_7000),
];

/// Serialized evidence from a completed diagnostic. Success requires every owner reaped.
#[derive(Debug)]
pub struct ProbeResult {
    json: String,
}

impl ProbeResult {
    pub fn json(&self) -> &str {
        &self.json
    }
}

#[derive(Default)]
struct ExitGate {
    hold: AtomicBool,
    entered: AtomicBool,
    calls: AtomicU64,
    supplied: AtomicU64,
    supplied_len: AtomicU64,
}

impl ExitGate {
    fn arm(&self) {
        self.entered.store(false, Ordering::Release);
        self.hold.store(true, Ordering::Release);
    }

    fn open(&self) {
        self.hold.store(false, Ordering::Release);
    }
}

struct ProbePort {
    gate: Arc<ExitGate>,
    value: u8,
}

impl BusDevice for ProbePort {
    fn read(&mut self, _cpu: u64, _offset: u64, data: &mut [u8]) {
        self.gate.calls.fetch_add(1, Ordering::Relaxed);
        self.gate.entered.store(true, Ordering::Release);
        while self.gate.hold.load(Ordering::Acquire) {
            thread::sleep(Duration::from_micros(100));
        }
        data.fill(self.value);
        self.gate.supplied.store(
            data.first().map_or(256, |value| u64::from(*value)),
            Ordering::Release,
        );
        self.gate
            .supplied_len
            .store(data.len() as u64, Ordering::Release);
    }
}

struct ProbeVm {
    memory: devices::virtio::RuntimeGuestMemory,
    vm: Vm,
    handles: Vec<VcpuHandle>,
    cpus: CpuController,
    gates: Vec<Arc<ExitGate>>,
    request: u64,
    evidence: String,
    stopped: bool,
}

impl ProbeVm {
    fn new(count: u8) -> Result<Self, String> {
        let kvm = Kvm::new().map_err(|error| format!("open KVM: {error}"))?;
        let mut vm = Vm::new(&kvm).map_err(|error| format!("create VM: {error}"))?;
        let memory = GuestMemoryMmap::from_ranges(&MEMORY_RANGES)
            .map_err(|error| format!("allocate RAM: {error}"))?;
        vm.memory_init(&memory, kvm.get_nr_memslots())
            .map_err(|error| format!("register RAM: {error}"))?;
        vm.fd()
            .create_irq_chip()
            .map_err(|error| format!("create irqchip: {error}"))?;
        vm.fd()
            .create_pit2(kvm_pit_config::default())
            .map_err(|error| format!("create PIT: {error}"))?;
        memory
            .write_slice(&guest_payload()?.bytes, GuestAddress(ENTRY))
            .map_err(|error| format!("write payload: {error}"))?;
        // The interrupt handler preserves the guest's accumulator and DS identity.
        memory
            .write_slice(
                &[
                    0xff, 0x06, 0x06, 0x00, 0x50, 0xb0, 0x20, 0xe6, 0x20, 0x58, 0xcf,
                ],
                GuestAddress(HANDLER),
            )
            .map_err(|error| format!("write timer handler: {error}"))?;
        memory
            .write_obj(HANDLER as u16, GuestAddress(0x20 * 4))
            .map_err(|error| format!("write IVT: {error}"))?;
        let (domain, construction, mut memory_control) =
            arch::guest_memory::MemoryDomain::construct(
                memory,
                crate::vmm::execution::native_page_granule().map_err(|error| error.to_string())?,
                arch::guest_memory::BackingKind::Boot,
            )
            .map_err(|error| error.to_string())?;
        vm.bind_memory_domain(domain.clone())
            .map_err(|error| error.to_string())?;
        memory_control
            .finish_untracked(construction)
            .map_err(|error| error.to_string())?;
        let memory = devices::virtio::RuntimeGuestMemory::new(domain);
        Vcpu::register_kick_signal_handler().map_err(|error| format!("install kick: {error}"))?;
        let mut probe = Self {
            memory,
            vm,
            handles: Vec::with_capacity(usize::from(count)),
            cpus: CpuController::new(usize::from(count)),
            gates: Vec::with_capacity(usize::from(count)),
            request: 0,
            evidence: String::new(),
            stopped: false,
        };
        for cpu in 0..count {
            if let Err(error) = probe.add_cpu(cpu) {
                let cleanup = probe.stop();
                return Err(format!("{error}; startup cleanup: {cleanup:?}"));
            }
        }
        Ok(probe)
    }

    fn add_cpu(&mut self, cpu: u8) -> Result<(), String> {
        let gate = Arc::new(ExitGate::default());
        let mut io = Bus::new();
        io.insert(
            Arc::new(Mutex::new(ProbePort {
                gate: gate.clone(),
                value: 0xa5,
            })),
            0x500,
            1,
        )
        .map_err(|error| format!("insert IO: {error}"))?;
        let mut mmio = Bus::new();
        mmio.insert(
            Arc::new(Mutex::new(ProbePort {
                gate: gate.clone(),
                value: 0x5a,
            })),
            MMIO,
            1,
        )
        .map_err(|error| format!("insert MMIO: {error}"))?;
        let exit = EventFd::new(EFD_NONBLOCK).map_err(|error| format!("exit event: {error}"))?;
        let mut vcpu = Vcpu::new_x86_64(
            cpu,
            self.vm.fd_owner(),
            self.vm.supported_cpuid().clone(),
            self.vm.supported_msrs().clone(),
            io,
            exit,
        )
        .map_err(|error| format!("create CPU {cpu}: {error}"))?;
        vcpu.configure_control_probe(ENTRY, 0x1000 + u16::from(cpu) * 0x100, mmio)
            .map_err(|error| format!("configure CPU {cpu}: {error}"))?;
        vcpu.retain_resources(&self.vm)
            .map_err(|error| error.to_string())?;
        self.memory
            .write_obj(
                0xc000u16 + u16::from(cpu),
                Self::address(usize::from(cpu), 2),
            )
            .map_err(|error| format!("write identity: {error}"))?;
        self.memory
            .write_obj(u16::from(cpu), Self::address(usize::from(cpu), 10))
            .map_err(|error| format!("write CPU identity: {error}"))?;
        let handle = vcpu
            .start_threaded()
            .map_err(|error| format!("start CPU {cpu}: {error}"))?;
        self.handles.push(handle);
        self.gates.push(gate);
        self.cpus = CpuController::new(self.handles.len());
        Ok(())
    }

    fn address(cpu: usize, offset: u64) -> GuestAddress {
        GuestAddress(0x1_0000 + cpu as u64 * 0x1000 + offset)
    }

    fn word(&self, cpu: usize, offset: u64) -> Result<u16, String> {
        self.memory
            .read_obj(Self::address(cpu, offset))
            .map_err(|error| format!("read guest: {error}"))
    }

    fn mode(&self, cpu: usize, mode: u8) -> Result<(), String> {
        self.memory
            .write_obj(mode, Self::address(cpu, 8))
            .map_err(|error| format!("write guest mode: {error}"))
    }

    fn begin(
        &mut self,
        key: BarrierKey,
        kind: CpuCommandKind,
        budget: Duration,
    ) -> Result<BarrierRequest, String> {
        self.begin_at(key, kind, Instant::now() + budget)
    }

    fn begin_at(
        &mut self,
        key: BarrierKey,
        kind: CpuCommandKind,
        deadline: Instant,
    ) -> Result<BarrierRequest, String> {
        if Instant::now() >= deadline {
            return Err("operation deadline expired before submission".into());
        }
        self.request = self.request.checked_add(1).ok_or("request exhausted")?;
        let barrier = BarrierRequest { key, deadline };
        let result = self
            .cpus
            .begin(RequestId(self.request), barrier, kind, &self.handles);
        writeln!(self.evidence, "{{\"request\":{},\"operation\":{},\"generation\":{},\"command\":\"{kind:?}\",\"accepted_result\":{}}},",
            self.request, key.operation.0, key.generation.0, json_string(&format!("{result:?}")))
            .map_err(|error| error.to_string())?;
        result.map_err(|error| error.to_string())?;
        Ok(barrier)
    }

    fn finish(&mut self) -> Result<(), ControlFailure> {
        loop {
            match self.cpus.poll(&mut self.handles) {
                Poll::Ready(result) => {
                    let progress = json_string(&format!("{:?}", self.progress()));
                    let _ = writeln!(
                        self.evidence,
                        "{{\"request\":{},\"poll_result\":{},\"reconciled\":{},\"progress\":{progress}}},",
                        self.request,
                        json_string(&format!("{result:?}")),
                        self.cpus.reconciled()
                    );
                    return result;
                }
                Poll::Pending => thread::sleep(Duration::from_micros(100)),
            }
        }
    }

    fn command(&mut self, key: BarrierKey, kind: CpuCommandKind) -> Result<(), String> {
        self.begin(key, kind, WAIT)?;
        self.finish().map_err(|error| error.to_string())
    }

    fn release(&mut self, key: BarrierKey) -> Result<(), String> {
        self.release_at(key, Instant::now() + WAIT)
    }

    fn release_at(&mut self, key: BarrierKey, deadline: Instant) -> Result<(), String> {
        self.begin_at(
            key,
            CpuCommandKind::PrepareResume { paused_ticks: 0 },
            deadline,
        )?;
        self.finish().map_err(|error| error.to_string())?;
        self.begin_at(key, CpuCommandKind::Release, deadline)?;
        self.finish().map_err(|error| error.to_string())
    }

    fn progress(&self) -> Result<Vec<u16>, String> {
        (0..self.handles.len())
            .map(|cpu| self.word(cpu, 4))
            .collect()
    }

    fn continued(&self) -> Result<(), String> {
        let before = self.progress()?;
        wait_until(
            &format!("continued progress after request {}", self.request),
            || {
                let after = self.progress()?;
                Ok(after
                    .iter()
                    .zip(&before)
                    .all(|(after, before)| after != before))
            },
        )?;
        self.identity()
    }

    fn identity(&self) -> Result<(), String> {
        for cpu in 0..self.handles.len() {
            if self.word(cpu, 0)? != 1 || self.word(cpu, 2)? != 0xc000 + cpu as u16 {
                return Err(format!(
                    "guest initialization identity changed on CPU {cpu}"
                ));
            }
        }
        Ok(())
    }

    fn frozen(&self) -> Result<(), String> {
        let before = self.progress()?;
        thread::sleep(Duration::from_millis(15));
        if self.progress()? != before {
            return Err("guest progressed after completed park".into());
        }
        self.identity()
    }

    fn held_ack(&mut self, cpu: usize, key: BarrierKey, kind: CpuAckKind) -> Result<(), String> {
        wait_until(
            &format!("held {kind:?} ACK for request {} CPU {cpu}", self.request),
            || {
                let _ = self.cpus.poll(&mut self.handles);
                Ok(self.handles[cpu].probe_held_ack()?.is_some())
            },
        )?;
        let ack = self.handles[cpu]
            .probe_held_ack()?
            .ok_or("real ACK was not retained")?;
        if ack.cpu_id as usize != cpu
            || ack.request != RequestId(self.request)
            || ack.key != key
            || ack.kind != kind
            || ack.result.is_err()
        {
            return Err(format!("held ACK identity/result mismatch: {ack:?}"));
        }
        writeln!(self.evidence, "{{\"held_ack\":{{\"cpu\":{},\"request\":{},\"operation\":{},\"generation\":{},\"kind\":\"{:?}\",\"result\":{}}}}},",
            ack.cpu_id, ack.request.0, ack.key.operation.0, ack.key.generation.0, ack.kind,
            json_string(&format!("{:?}", ack.result))).map_err(|error| error.to_string())
    }

    fn exit_race(&mut self, generation: u64, mode: u8) -> Result<(), String> {
        let cpu = self.handles.len() - 1;
        self.gates[cpu].arm();
        self.mode(cpu, mode)?;
        wait_until(
            &format!("exit callback entry generation={generation} mode={mode} CPU={cpu}"),
            || Ok(self.gates[cpu].entered.load(Ordering::Acquire)),
        )?;
        let key = key(generation);
        self.begin(key, CpuCommandKind::Park, WAIT)?;
        if !matches!(self.cpus.poll(&mut self.handles), Poll::Pending) {
            return Err("park acknowledged before held exit emulation completed".into());
        }
        self.gates[cpu].open();
        self.finish().map_err(|error| error.to_string())?;
        let state = self.handles[cpu]
            .probe_park_state()?
            .ok_or("missing owner-thread park state")?;
        let payload = guest_payload()?;
        let (expected_rip, expected_al) = match mode {
            1 => (payload.io_completed_rip, 0xa5),
            2 => (payload.mmio_completed_rip, 0x5a),
            _ => return Err("invalid input-completion fixture mode".into()),
        };
        if state.request != RequestId(self.request)
            || state.key != key
            || usize::from(state.cpu_id) != cpu
            || state.rip != expected_rip
            || state.rax as u8 != expected_al
        {
            return Err(format!(
                "incomplete input at Park ACK: state={state:?}, expected rip={expected_rip:#x} al={expected_al:#x}"
            ));
        }
        writeln!(self.evidence, "{{\"park_cut\":{{\"cpu\":{},\"request\":{},\"operation\":{},\"generation\":{},\"rip\":{},\"expected_rip\":{},\"rax\":{},\"expected_al\":{}}}}},",
            state.cpu_id, state.request.0, state.key.operation.0, state.key.generation.0,
            state.rip, expected_rip, state.rax, expected_al).map_err(|error| error.to_string())?;
        self.frozen()?;
        self.release(key)?;
        wait_until(&format!("input result generation={generation} mode={mode} CPU={cpu}"), || {
            let offset = if mode == 1 { 12 } else { 13 };
            let expected = if mode == 1 { 0xa5 } else { 0x5a };
            let value: u8 = self
                .memory
                .read_obj(Self::address(cpu, offset))
                .map_err(|error| error.to_string())?;
            Ok(value == expected)
        }).map_err(|error| format!(
            "{error}: input completion generation={generation} mode={mode} cpu={cpu}, guest_mode_word={:?}, io_mmio_marker_word={:?}, progress={:?}, callbacks={}, supplied_byte={}, supplied_len={}",
            self.word(cpu, 8), self.word(cpu, 12), self.progress(),
            self.gates[cpu].calls.load(Ordering::Acquire),
            self.gates[cpu].supplied.load(Ordering::Acquire),
            self.gates[cpu].supplied_len.load(Ordering::Acquire)
        ))?;
        self.continued()
    }

    fn scenario(&mut self) -> Result<(), String> {
        self.release(key(0))?;
        self.continued()?;
        self.command(key(1), CpuCommandKind::Park)?;
        self.frozen()?;
        self.release(key(1))?;
        self.continued()?;
        self.exit_race(2, 1)?;
        self.exit_race(3, 2)?;

        self.mode(0, 3)?;
        let timer = self.word(0, 6)?;
        wait_until("PIT interrupt after STI/HLT on CPU 0", || {
            Ok(self.word(0, 6)? != timer)
        })?;
        self.command(key(4), CpuCommandKind::Park)?;
        self.frozen()?;
        self.mode(0, 0)?;
        self.release(key(4))?;
        self.continued()?;

        let last = self.handles.len() - 1;
        self.handles[last].set_probe_ack_hold(Some(CpuCommandKind::Park))?;
        self.begin(key(5), CpuCommandKind::Park, SHORT)?;
        if self.finish() != Err(ControlFailure::Deadline) || self.cpus.reconciled() {
            return Err("withheld real park ACK did not retain pending ownership".into());
        }
        self.held_ack(last, key(5), CpuAckKind::Parked)?;
        self.handles[last].set_probe_ack_hold(None)?;
        self.command(key(5), CpuCommandKind::Park)?;
        self.frozen()?;
        self.release(key(5))?;
        self.continued()?;

        // This is explicit cancellation: settle every accepted old park before releasing.
        self.gates[last].arm();
        self.mode(last, 1)?;
        wait_until("partial pause held IO callback entry", || {
            Ok(self.gates[last].entered.load(Ordering::Acquire))
        })?;
        self.begin(key(6), CpuCommandKind::Park, SHORT)?;
        if self.finish() != Err(ControlFailure::Deadline) || self.cpus.reconciled() {
            return Err("partial park did not expire with accepted ownership".into());
        }
        let cancellation_deadline = Instant::now() + WAIT;
        self.begin_at(key(6), CpuCommandKind::Park, cancellation_deadline)?;
        self.gates[last].open();
        self.finish()
            .map_err(|error| format!("cancel reconciliation: {error}"))?;
        self.frozen()?;
        self.release_at(key(6), cancellation_deadline)?;
        self.continued()?;

        self.command(key(7), CpuCommandKind::Park)?;
        self.begin(key(6), CpuCommandKind::Release, WAIT)?;
        if !matches!(self.finish(), Err(ControlFailure::Participant(_))) {
            return Err("stale CPU release authority was not refused".into());
        }
        self.frozen()?;
        self.release(key(7))?;
        self.continued()?;

        self.command(key(8), CpuCommandKind::Park)?;
        self.command(key(8), CpuCommandKind::PrepareResume { paused_ticks: 0 })?;
        self.handles[last].set_probe_ack_hold(Some(CpuCommandKind::Release))?;
        self.begin(key(8), CpuCommandKind::Release, SHORT)?;
        if self.finish() != Err(ControlFailure::Deadline) || self.cpus.reconciled() {
            return Err("ambiguous release did not retain pending ownership".into());
        }
        self.held_ack(last, key(8), CpuAckKind::Released)?;
        self.continued()?;
        let mut identities = String::new();
        for cpu in 0..self.handles.len() {
            if cpu != 0 {
                identities.push(',');
            }
            write!(identities, "{{\"cpu\":{cpu},\"initializations\":{},\"identity\":{},\"progress\":{},\"timer_interrupts\":{}}}",
                self.word(cpu, 0)?, self.word(cpu, 2)?, self.word(cpu, 4)?, self.word(cpu, 6)?)
                .map_err(|error| error.to_string())?;
        }
        writeln!(
            self.evidence,
            "{{\"final_guest_identity_progress_timer\":[{identities}]}},"
        )
        .map_err(|error| error.to_string())?;
        self.stop()?;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        for gate in &self.gates {
            gate.open();
        }
        // Startup can fail after only a prefix of CPUs exists.
        if self.handles.is_empty() {
            self.stopped = true;
            return Ok(());
        }
        self.request = self.request.checked_add(1).ok_or("request exhausted")?;
        let barrier = BarrierRequest {
            key: key(u64::MAX),
            deadline: Instant::now() + WAIT,
        };
        let submission = self.cpus.begin(
            RequestId(self.request),
            barrier,
            CpuCommandKind::Stop,
            &self.handles,
        );
        let mut failure = submission.err().map(|error| error.to_string());
        // Keep polling the same production journal even after its reporting deadline.
        // RAM and VM ownership cannot escape while any native owner remains alive.
        loop {
            match self.cpus.poll(&mut self.handles) {
                Poll::Ready(Ok(())) => {
                    self.stopped = true;
                    let _ = writeln!(
                        self.evidence,
                        "{{\"request\":{},\"command\":\"Stop\",\"all_reaped\":true}},",
                        self.request
                    );
                    return failure.map_or(Ok(()), Err);
                }
                Poll::Ready(Err(error)) => {
                    failure.get_or_insert_with(|| error.to_string());
                }
                Poll::Pending => (),
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for ProbeVm {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}

/// Execute actual KVM guests with one, then two vCPUs. Never called by unit tests.
/// This diagnostic does not grant native/public live capabilities or a machine pause token.
pub fn run() -> Result<ProbeResult, ProbeResult> {
    run_scenarios().map_err(|error| ProbeResult {
        json: failure_json(&error),
    })
}

fn run_scenarios() -> Result<ProbeResult, String> {
    let mut json = String::from(
        "{\"schema\":1,\"lane\":\"linux-x86_64-kvm\",\"scope\":\"cpu-sub-barrier-only\",\"native_pause\":false,\"public_live\":\"not-delivered\",\"scenarios\":[",
    );
    for count in [1, 2] {
        let mut probe = ProbeVm::new(count)?;
        let scenario = probe.scenario();
        let cleanup = probe.stop();
        if let Err(error) = scenario {
            return Err(format!(
                "{count} vCPUs: {error}; cleanup={cleanup:?}; journal=[{}]",
                probe.evidence.trim_end_matches([',', '\n'])
            ));
        }
        cleanup?;
        if count != 1 {
            json.push(',');
        }
        write!(json, "{{\"vcpus\":{count},\"status\":\"passed\",\"all_reaped\":true,\"initialization_unchanged\":true,\"tight_loop\":true,\"io_completion_kick\":true,\"mmio_completion_kick\":true,\"pit_timer_wait\":true,\"withheld_late_park_ack\":true,\"stale_release_refused\":true,\"partial_pause_cancel_continued\":true,\"ambiguous_release_stopped\":true,\"journal\":[{}]}}", probe.evidence.trim_end_matches([',', '\n']))
            .map_err(|error| error.to_string())?;
    }
    json.push_str("]}");
    Ok(ProbeResult { json })
}

/// Encode a diagnostic failure as JSON, including any retained transition journal.
fn failure_json(error: &str) -> String {
    format!(
        "{{\"schema\":1,\"lane\":\"linux-x86_64-kvm\",\"scope\":\"cpu-sub-barrier-only\",\"status\":\"failed\",\"error\":{}}}",
        json_string(error)
    )
}

fn key(generation: u64) -> BarrierKey {
    BarrierKey {
        operation: OperationId(generation),
        generation: BarrierGeneration(generation),
    }
}

fn wait_until(phase: &str, mut ready: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
    let deadline = Instant::now() + WAIT;
    loop {
        if ready().map_err(|error| format!("{phase}: {error}"))? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("guest observation deadline expired: {phase}"));
        }
        thread::sleep(Duration::from_micros(100));
    }
}

fn json_string(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            character if character.is_control() => {
                // Writing to String is infallible.
                let _ = write!(result, "\\u{:04x}", u32::from(character));
            }
            character => result.push(character),
        }
    }
    result.push('"');
    result
}

struct GuestPayload {
    bytes: Vec<u8>,
    io_completed_rip: u64,
    mmio_completed_rip: u64,
}

fn guest_payload() -> Result<GuestPayload, String> {
    let mut code = vec![0xfa, 0xff, 0x06, 0, 0, 0x83, 0x3e, 10, 0, 0, 0x75, 0];
    let skip_init = code.len() - 1;
    code.extend_from_slice(&[
        0xb0, 0x11, 0xe6, 0x20, 0xe6, 0xa0, 0xb0, 0x20, 0xe6, 0x21, 0xb0, 0x28, 0xe6, 0xa1, 0xb0,
        4, 0xe6, 0x21, 0xb0, 2, 0xe6, 0xa1, 0xb0, 1, 0xe6, 0x21, 0xe6, 0xa1, 0xb0, 0xfe, 0xe6,
        0x21, 0xb0, 0xff, 0xe6, 0xa1, 0xb0, 0x36, 0xe6, 0x43, 0xb0, 0x9b, 0xe6, 0x40, 0xb0, 0x2e,
        0xe6, 0x40,
    ]);
    let running = code.len();
    patch_jump(&mut code, skip_init, running)?;
    code.extend_from_slice(&[0xff, 0x06, 4, 0]);
    let mut branches = Vec::new();
    for mode in [1, 2, 3] {
        code.extend_from_slice(&[0x80, 0x3e, 8, 0, mode, 0x74, 0]);
        branches.push(code.len() - 1);
    }
    jump(&mut code, running)?;
    let io = code.len();
    code.extend_from_slice(&[0xba, 0, 5, 0xec, 0xa2, 12, 0, 0xc6, 0x06, 8, 0, 0]);
    jump(&mut code, running)?;
    let mmio = code.len();
    code.extend_from_slice(&[
        0x2e,
        0xa0,
        MMIO as u8,
        (MMIO >> 8) as u8,
        0xa2,
        13,
        0,
        0xc6,
        0x06,
        8,
        0,
        0,
    ]);
    jump(&mut code, running)?;
    let timer = code.len();
    code.extend_from_slice(&[0xfb, 0xf4, 0xfa]);
    jump(&mut code, running)?;
    for (branch, target) in branches.into_iter().zip([io, mmio, timer]) {
        patch_jump(&mut code, branch, target)?;
    }
    Ok(GuestPayload {
        bytes: code,
        io_completed_rip: ENTRY + io as u64 + 4,
        mmio_completed_rip: ENTRY + mmio as u64 + 4,
    })
}

fn jump(code: &mut Vec<u8>, target: usize) -> Result<(), String> {
    code.extend_from_slice(&[0xeb, 0]);
    let branch = code.len() - 1;
    patch_jump(code, branch, target)
}

fn patch_jump(code: &mut [u8], displacement: usize, target: usize) -> Result<(), String> {
    let relative = target as i64 - displacement as i64 - 1;
    let relative = i8::try_from(relative).map_err(|_| "guest jump out of range")?;
    let byte = code
        .get_mut(displacement)
        .ok_or("guest jump outside payload")?;
    *byte = relative as u8;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::api::native_control_probe::{
        ENTRY, HANDLER, MEMORY_RANGES, MMIO, guest_payload, json_string, patch_jump,
    };
    use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

    #[test]
    fn native_control_probe_payload_has_bounded_real_mode_branches() {
        let payload = guest_payload().expect("bounded payload").bytes;
        assert!(payload.len() < (HANDLER - ENTRY) as usize);
        assert!(payload.windows(2).any(|bytes| bytes == [0xfb, 0xf4]));
        assert!(
            payload
                .windows(4)
                .any(|bytes| bytes == [0x2e, 0xa0, 0x00, 0x80])
        );
        assert!(payload.contains(&0xec));
        assert!(patch_jump(&mut [0], 0, 129).is_err());
        assert!(patch_jump(&mut [], 0, 1).is_err());
    }

    #[test]
    fn native_control_probe_mmio_load_targets_unmapped_real_mode_hole() {
        let payload = guest_payload().expect("bounded payload").bytes;
        let instruction = payload
            .windows(2)
            .position(|bytes| bytes == [0x2e, 0xa0])
            .expect("CS-relative real-mode byte load");
        let address = u64::from(u16::from_le_bytes([
            payload[instruction + 2],
            payload[instruction + 3],
        ]));
        assert_eq!(address, MMIO);
        let memory = GuestMemoryMmap::<()>::from_ranges(&MEMORY_RANGES).expect("fixture RAM");
        assert!(memory.get_host_address(GuestAddress(address)).is_err());
        for address in [ENTRY, HANDLER, 0x1_0000, 0x1_1ff0] {
            assert!(memory.get_host_address(GuestAddress(address)).is_ok());
        }
    }

    #[test]
    fn native_control_probe_completion_cuts_precede_guest_result_stores() {
        let payload = guest_payload().expect("bounded payload");
        let io = (payload.io_completed_rip - ENTRY) as usize;
        let mmio = (payload.mmio_completed_rip - ENTRY) as usize;
        assert_eq!(&payload.bytes[io - 4..io], &[0xba, 0, 5, 0xec]);
        assert_eq!(&payload.bytes[mmio - 4..mmio], &[0x2e, 0xa0, 0, 0x80]);
        assert_eq!(&payload.bytes[io..io + 3], &[0xa2, 12, 0]);
        assert_eq!(&payload.bytes[mmio..mmio + 3], &[0xa2, 13, 0]);
    }

    #[test]
    fn native_control_probe_json_escapes_errors() {
        assert_eq!(
            json_string("quote\"\\\n\u{0001}"),
            "\"quote\\\"\\\\\\n\\u0001\""
        );
    }
}
