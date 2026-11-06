//! Bounded, diagnostic-only source construction and observations. Restored state
//! is never reseeded. The ordinary Linux CPUs and providers remain the owners.
use std::fmt::Write as FmtWrite;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use devices::bus::BusAccessObserver;
use devices::virtio::RuntimeGuestMemory;
use vm_memory::GuestAddress;

use crate::api::live::irq_probe::{Fixture, FixtureLayout, ProbeObservation};
use crate::api::vmm_builder::native_device_probe::write_new;
use crate::vmm::Vmm;
use crate::vmm::control::CpuCommandKind;
use crate::vmm::execution::kvm::{KvmCpuState, KvmCpuTimePlan, KvmVmState, Segment, lapic_u32};
use crate::vmm::execution::{
    CpuExecutionInput, CpuExecutionState, CpuTimePlan, SourceWitnessBootstrap, VmExecutionState,
};

pub const BASE: u64 = 0x1c000000;
const SLOT: u64 = BASE + 0x10000;
const CODE: u64 = BASE + 0x1000;
const LOW: u64 = 0x70000;

/// Preserve both epoch reads; an interrupted publication is evidence, not a
/// completed IRQ record. No guest work or request is retried by this reader.
fn irq_words(memory: &RuntimeGuestMemory) -> Result<([u64; 23], [u64; 2]), String> {
    let before = memory
        .load(GuestAddress(SLOT + 184), Ordering::SeqCst)
        .map_err(|e| e.to_string())?;
    let mut words = [0u64; 23];
    for (index, word) in words.iter_mut().enumerate() {
        *word = memory
            .load(GuestAddress(SLOT + index as u64 * 8), Ordering::SeqCst)
            .map_err(|e| e.to_string())?;
    }
    let after = memory
        .load(GuestAddress(SLOT + 184), Ordering::SeqCst)
        .map_err(|e| e.to_string())?;
    Ok((words, [before, after]))
}

fn fixture_symbol(symbols: &str, name: &str) -> Result<u64, String> {
    let mut found = None;
    for line in symbols.lines() {
        let mut fields = line.split_whitespace();
        let (Some(address), Some(kind), Some(symbol)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if symbol != name {
            continue;
        }
        let address = u64::from_str_radix(address, 16)
            .map_err(|_| format!("invalid witness symbol {name}"))?;
        if fields.next().is_some()
            || !matches!(kind, "T" | "t")
            || !(CODE..BASE + 0x4000).contains(&address)
            || found.replace(address).is_some()
        {
            return Err(format!(
                "duplicate, foreign or malformed witness symbol {name}"
            ));
        }
    }
    found.ok_or_else(|| format!("missing witness symbol {name}"))
}

pub(crate) fn fixture_layout(code: &[u8], symbols: &str) -> Result<FixtureLayout, String> {
    let symbol = |name| fixture_symbol(symbols, name);
    let layout = FixtureLayout {
        handler: symbol("witness_interrupt")?,
        idt: symbol("witness_idt")?,
        completion_ips: [
            symbol("witness_io_complete")?,
            symbol("witness_mmio_complete")?,
        ],
    };
    let end = CODE + code.len() as u64;
    if symbol("_start")? != CODE
        || code.is_empty()
        || layout.idt + 225 * 16 > end
        || layout.handler >= end
        || layout.completion_ips.iter().any(|ip| *ip >= end)
    {
        return Err("witness symbols/code extent disagree".into());
    }
    Ok(layout)
}

#[derive(Default)]
struct GateState {
    armed: bool,
    entered: bool,
    released: bool,
    timed_out: bool,
    writes: u64,
}
#[derive(Default)]
pub struct Witness {
    gate: Mutex<GateState>,
    wake: Condvar,
    address: Mutex<Option<u64>>,
    completion_ips: Mutex<Option<[u64; 2]>>,
}
impl BusAccessObserver for Witness {
    fn completed(&self, cpu: u64, address: u64, write: bool, _data: &[u8]) {
        if cpu != 2
            || !write
            || (address != 0x3ef && self.address.lock().ok().and_then(|v| *v) != Some(address))
        {
            return;
        }
        let Ok(mut state) = self.gate.lock() else {
            return;
        };
        state.writes += 1;
        if !state.armed {
            return;
        }
        state.entered = true;
        self.wake.notify_all();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !state.released {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                state.timed_out = true;
                break;
            };
            match self.wake.wait_timeout(state, remaining) {
                Ok((next, _)) => state = next,
                Err(_) => return,
            }
        }
        state.armed = false;
    }
}
impl Witness {
    pub fn attach(self: &Arc<Self>, vmm: &Vmm) -> Result<(), String> {
        *self
            .address
            .lock()
            .map_err(|_| "witness address poisoned")? = vmm
            .mmio_device_manager
            .quiescence
            .attachment_identities()
            .into_iter()
            .find(|a| matches!(a.configured_id.as_str(), "rng-line-padding-0" | "rng"))
            .map(|a| a.address + 0x30);
        vmm.mmio_device_manager
            .bus
            .observe_accesses(self.clone())
            .map_err(|e| e.to_string())?;
        vmm.mmio_device_manager.observe_probe_io(self.clone())
    }
    pub fn release_accepted_park(&self, vmm: &Vmm) -> Result<(), String> {
        let mut state = self.gate.lock().map_err(|_| "witness gate poisoned")?;
        if state.entered
            && !state.released
            && vmm
                .control
                .cpus
                .active_request()
                .is_some_and(|(_, _, kind)| kind == CpuCommandKind::Park)
        {
            state.released = true;
            self.wake.notify_all();
        }
        Ok(())
    }
    pub fn release(&self) {
        if let Ok(mut state) = self.gate.lock() {
            state.released = true;
            self.wake.notify_all();
        }
    }
    pub(crate) fn arm(&self, vmm: &Vmm, case: u64) -> Result<(), String> {
        if !matches!(case, 1..=13) {
            return Err("witness command out of range".into());
        }
        if matches!(case, 3 | 7 | 8) {
            *self.gate.lock().map_err(|_| "witness gate poisoned")? = GateState {
                armed: true,
                ..GateState::default()
            };
        }
        write_command(vmm, case)
    }
    pub(crate) fn begin_initialize(
        &self,
        vmm: &mut Vmm,
        fixture: Fixture,
        deadline: Instant,
    ) -> Result<Arc<CpuExecutionInput>, String> {
        let Fixture { code, layout } = fixture;
        let FixtureLayout {
            handler,
            idt,
            completion_ips: ips,
        } = layout;
        validate_source(vmm)?;
        *self
            .completion_ips
            .lock()
            .map_err(|_| "witness completion lock poisoned")? = Some(ips);
        let (request, barrier, inputs) = {
            let vmm = &mut *vmm;
            let active = vmm
                .control
                .active
                .as_ref()
                .ok_or("source construction requires completed pause")?;
            let request = active.request.id;
            let barrier = active.barrier;
            let cut = vmm
                .execution
                .retained
                .as_ref()
                .ok_or("source construction lacks retained cut")?;
            if cut.cpus.len() != 4
                || vmm
                    .guest_memory
                    .read_obj::<u64>(GuestAddress(SLOT))
                    .map_err(|e| e.to_string())?
                    != 0
            {
                return Err(
                    "source witness must be initialized exactly once with four CPUs".into(),
                );
            }
            let Some(CpuExecutionState::Kvm(KvmCpuState::X86(cpu))) = cut.cpus.get(2) else {
                return Err("witness requires KVM x86 AP2".into());
            };
            if cpu.mp_state != 1 {
                return Err("source witness CPU already started".into());
            }
            let tsc_khz = cpu.tsc_khz;
            let mut bootstrap = SourceWitnessBootstrap {
                regs: [0; 18],
                special: cpu.special.clone(),
            };
            let address = vmm
                .mmio_device_manager
                .quiescence
                .attachment_identities()
                .into_iter()
                .find(|a| matches!(a.configured_id.as_str(), "rng-line-padding-0" | "rng"))
                .ok_or("real RNG witness attachment missing")?
                .address
                + 0x30;
            *self
                .address
                .lock()
                .map_err(|_| "witness address poisoned")? = Some(address);
            if !vmm
                .reopen_memory_for_resume(barrier.key)
                .map_err(|error| error.to_string())?
            {
                return Err("source witness native writers remain outstanding".into());
            }
            let memory = &vmm.guest_memory;
            memory
                .write_slice(&code, GuestAddress(CODE))
                .map_err(|e| e.to_string())?;
            let mut gate = [0u8; 16];
            gate[..2].copy_from_slice(&(handler as u16).to_le_bytes());
            gate[2..4].copy_from_slice(&8u16.to_le_bytes());
            gate[5] = 0x8e;
            gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
            gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
            memory
                .write_slice(&gate, GuestAddress(idt + 224 * 16))
                .map_err(|e| e.to_string())?;
            for index in 0..512u64 {
                memory
                    .write_obj(0u64, GuestAddress(BASE + 0x4000 + index * 8))
                    .map_err(|e| e.to_string())?;
                memory
                    .write_obj(0u64, GuestAddress(BASE + 0x5000 + index * 8))
                    .map_err(|e| e.to_string())?;
            }
            memory
                .write_obj((BASE + 0x5000) | 3, GuestAddress(BASE + 0x4000))
                .map_err(|e| e.to_string())?;
            for pd in 0..4u64 {
                memory
                    .write_obj(
                        (BASE + 0x6000 + pd * 0x1000) | 3,
                        GuestAddress(BASE + 0x5000 + pd * 8),
                    )
                    .map_err(|e| e.to_string())?;
                for index in 0..512u64 {
                    memory
                        .write_obj(
                            ((pd * 512 + index) * 0x200000) | 0x83,
                            GuestAddress(BASE + 0x6000 + pd * 0x1000 + index * 8),
                        )
                        .map_err(|e| e.to_string())?;
                }
            }
            for (index, value) in [0u64, 0x00af9b000000ffff, 0x00cf93000000ffff]
                .into_iter()
                .enumerate()
            {
                memory
                    .write_obj(value, GuestAddress(BASE + 0xb000 + index as u64 * 8))
                    .map_err(|e| e.to_string())?;
            }
            // Real-mode AP3 code touches only the explicitly reserved low region.
            let ap: [u8; 15] = [
                0xfa, 0xb8, 0x00, 0x70, 0x8e, 0xd8, 0xc6, 0x06, 0x00, 0xf0, 0x01, 0xfb, 0xf4, 0xeb,
                0xfd,
            ];
            memory
                .write_slice(&ap, GuestAddress(LOW))
                .map_err(|e| e.to_string())?;
            memory
                .write_obj(0u8, GuestAddress(LOW + 0xf000))
                .map_err(|e| e.to_string())?;
            memory
                .write_obj(u64::from(tsc_khz), GuestAddress(SLOT + 80))
                .map_err(|e| e.to_string())?;
            memory
                .write_obj(address - 0x30, GuestAddress(SLOT + 136))
                .map_err(|e| e.to_string())?;
            bootstrap.regs[16] = CODE;
            bootstrap.regs[17] = 2;
            bootstrap.special.values[0] = 0x80010033;
            bootstrap.special.values[1] = 0;
            bootstrap.special.values[2] = BASE + 0x4000;
            bootstrap.special.values[3] = 0x620;
            bootstrap.special.values[4] = 0;
            bootstrap.special.values[5] = 0xd00;
            bootstrap.special.values[7..].fill(0);
            bootstrap.special.segments[0] = Segment {
                base: 0,
                limit: u32::MAX,
                selector: 8,
                attributes: [11, 1, 0, 0, 1, 1, 1, 0, 0],
            };
            for segment in &mut bootstrap.special.segments[1..6] {
                *segment = Segment {
                    base: 0,
                    limit: u32::MAX,
                    selector: 16,
                    attributes: [3, 1, 0, 1, 1, 0, 1, 0, 0],
                };
            }
            bootstrap.special.gdt = (BASE + 0xb000, 23);
            bootstrap.special.idt = (idt, 225 * 16 - 1);
            (
                request,
                barrier,
                [
                    None,
                    None,
                    Some(Arc::new(CpuExecutionInput::InitializeDeviceWitness(
                        bootstrap,
                    ))),
                    None,
                ],
            )
        };
        {
            let vmm = &mut *vmm;
            vmm.control
                .cpus
                .begin_execution(
                    request,
                    polly::event_manager::BarrierRequest {
                        deadline,
                        ..barrier
                    },
                    CpuCommandKind::InitializeDeviceWitness,
                    &inputs,
                    &vmm.vcpus_handles,
                    Some(vmm.memory.native()?),
                )
                .map_err(|e| e.to_string())?;
        }
        inputs
            .into_iter()
            .nth(2)
            .flatten()
            .ok_or_else(|| "source bootstrap payload disappeared".into())
    }
    pub(crate) fn poll_initialize(
        &self,
        vmm: &mut Vmm,
        input: &CpuExecutionInput,
    ) -> Poll<Result<(), String>> {
        let CpuExecutionInput::InitializeDeviceWitness(bootstrap) = input else {
            return Poll::Ready(Err("source bootstrap payload disappeared".into()));
        };
        match vmm.control.cpus.poll(&mut vmm.vcpus_handles) {
            Poll::Ready(result) => {
                if let Err(error) = result {
                    return Poll::Ready(Err(error.to_string()));
                }
                let Some(CpuExecutionState::Kvm(KvmCpuState::X86(cpu))) = vmm
                    .execution
                    .retained
                    .as_mut()
                    .and_then(|cut| cut.cpus.get_mut(2))
                else {
                    return Poll::Ready(Err("source retained AP2 disappeared".into()));
                };
                cpu.regs = bootstrap.regs;
                cpu.special = bootstrap.special.clone();
                cpu.mp_state = 0;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    pub(crate) fn validate(&self, vmm: &Vmm, case: &str) -> Result<(), String> {
        let cut = vmm
            .execution
            .retained
            .as_ref()
            .ok_or("witness requires retained whole-machine cut")?;
        let CpuExecutionState::Kvm(KvmCpuState::X86(cpu)) =
            cut.cpus.get(2).ok_or("witness CPU missing")?
        else {
            return Err("witness CPU type".into());
        };
        let VmExecutionState::Kvm(KvmVmState::X86(vm)) = &cut.vm else {
            return Err("witness VM type".into());
        };
        if vm.pit_profile != 1 {
            return Err("ordinary Linux native PIT predicate not retained".into());
        }
        if vmm
            .guest_memory
            .read_obj::<u64>(GuestAddress(SLOT))
            .map_err(|e| e.to_string())?
            != 0x53494c4f
            || vmm
                .guest_memory
                .read_obj::<u64>(GuestAddress(SLOT + 8))
                .map_err(|e| e.to_string())?
                != 1
        {
            return Err(
                "original guest witness was not retained across its single source initialization"
                    .into(),
            );
        }
        if cpu.regs[12] != 0x13579bdf2468ace0
            || cpu.regs[13] != 0xfedcba9876543210
            || cpu.xsave.get(400..416) != Some([0xffu8; 16].as_slice())
            || cpu.xsave.get(32..42) != Some([0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f].as_slice())
        {
            return Err("original live native GPR/SSE/x87 sentinels differ".into());
        }
        if vmm
            .guest_memory
            .read_obj::<u64>(GuestAddress(SLOT + 168))
            .map_err(|e| e.to_string())?
            != 0
        {
            let ymm = cpu
                .xstate
                .iter()
                .find(|component| component.id == 2)
                .ok_or("native YMM layout absent")?;
            let start = usize::try_from(ymm.offset).map_err(|_| "native YMM offset")? + 14 * 16;
            if cpu.xsave.get(start..start + 16) != Some([0xffu8; 16].as_slice()) {
                return Err("original live native YMM sentinel differs".into());
            }
        }
        let irr = lapic_u32(&cpu.lapic, 0x270).map_err(|e| e.to_string())? & 1 != 0;
        let isr = lapic_u32(&cpu.lapic, 0x170).map_err(|e| e.to_string())? & 1 != 0;
        let masked = lapic_u32(&cpu.lapic, 0x320).map_err(|e| e.to_string())? & (1 << 16) != 0;
        if matches!(case, "io" | "mmio") {
            let ips = self
                .completion_ips
                .lock()
                .map_err(|_| "witness completion lock poisoned")?
                .ok_or("source witness completion symbols missing")?;
            if cpu.regs[16] != ips[usize::from(case == "mmio")] {
                return Err(
                    "original IO/MMIO did not complete at its exact native instruction boundary"
                        .into(),
                );
            }
        }
        let valid = match case {
            "future" | "halted" => cpu.deadline != 0 && cpu.deadline.wrapping_sub(cpu.tsc_observed) < (1 << 63) && !irr && cpu.mp_state == 3,
            "due-no-irr" => cpu.deadline != 0 && cpu.tsc_observed.wrapping_sub(cpu.deadline) < (1 << 63) && !irr && !isr,
            "pending" => irr && cpu.deadline == 0 && !isr,
            "pending-future" => irr && cpu.deadline != 0 && cpu.deadline.wrapping_sub(cpu.tsc_observed) < (1 << 63),
            "masked" => {
                let original_deadline = vmm
                    .guest_memory
                    .load::<u64>(GuestAddress(SLOT + 56), Ordering::SeqCst)
                    .map_err(|e| e.to_string())?;
                masked && !irr && !isr && original_deadline != 0
                    && (cpu.deadline == 0 || cpu.deadline == original_deadline)
                    && cpu.tsc_observed.wrapping_sub(original_deadline) < (1 << 63)
            }
            "masked-future" => masked && !irr && !isr && cpu.deadline != 0
                && cpu.deadline.wrapping_sub(cpu.tsc_observed) < (1 << 63),
            "in-service" => isr && !irr,
            "steady" => cpu.deadline == 0 && !irr && !isr,
            "offline" => matches!(cut.cpus.get(3), Some(CpuExecutionState::Kvm(KvmCpuState::X86(ap))) if ap.mp_state == 1)
                && vmm.guest_memory.read_obj::<u8>(GuestAddress(LOW + 0xf000)).map_err(|e| e.to_string())? == 0,
            "io" => cut.legacy.iter().any(|legacy| legacy.address == 0x3e8
                && matches!(&legacy.payload, devices::legacy::state::LegacyPayload::Uart(uart) if uart.scratch == 0x5a)),
            "mmio" => {
                let gate = self.gate.lock().map_err(|_| "witness gate poisoned")?;
                gate.entered && gate.released && gate.writes == 1
            }
            _ => return Err("unknown witness cut case".into()),
        };
        if !valid {
            return Err(format!("original {case} native cause absent: {cpu:#?}"));
        }
        Ok(())
    }
    pub(crate) fn snapshot(&self, vmm: &Vmm, path: &Path) -> Result<(), String> {
        let (words, irq_publication) = irq_words(&vmm.guest_memory)?;
        let state = self.gate.lock().map_err(|_| "witness gate poisoned")?;
        if state.timed_out {
            return Err("actual bus completion hold timed out".into());
        }
        let ap = vmm
            .guest_memory
            .read_obj::<u8>(GuestAddress(LOW + 0xf000))
            .map_err(|e| e.to_string())?;
        let mut offsets = [0u64; 4];
        let mut deadlines = [0u64; 4];
        let mut observed = [0u64; 4];
        let mut rates = [0u32; 4];
        let mut count = 0;
        if let Some(cut) = &vmm.execution.retained {
            if cut.cpus.len() > offsets.len() {
                return Err("bounded witness CPU inventory".into());
            }
            for (index, cpu) in cut.cpus.iter().enumerate() {
                let CpuExecutionState::Kvm(KvmCpuState::X86(cpu)) = cpu else {
                    return Err("foreign witness CPU inventory".into());
                };
                offsets[index] = cpu.tsc_offset;
                deadlines[index] = cpu.deadline;
                observed[index] = cpu.tsc_observed;
                rates[index] = cpu.tsc_khz;
                count += 1;
            }
        }
        let offsets = &offsets[..count];
        let deadlines = &deadlines[..count];
        let observed = &observed[..count];
        let rates = &rates[..count];
        let native = format!(
            "{:?}",
            vmm.execution.retained.as_ref().map(|c| (&c.vm, &c.cpus))
        );
        let native_path = path.with_extension("native.txt");
        write_new(&native_path, native.as_bytes())?;
        let mut json = format!(
            "{{\"pid\":{},\"words\":{words:?},\"irq_publication\":{irq_publication:?},\"ap_started\":{ap},\"bus_writes\":{},\"bus_held\":{},\"bus_released\":{},\"release_may_have_run\":{},\"offsets\":{offsets:?},\"deadlines\":{deadlines:?},\"observed_tsc\":{observed:?},\"rates\":{rates:?},\"clock\":",
            std::process::id(),
            state.writes,
            state.entered && !state.released,
            state.released,
            vmm.control.cpus.release_may_have_run()
        );
        if let Some(clock) = vmm.vm.execution_time_observation()? {
            write!(
                json,
                "{{\"source\":{:?},\"destination\":{:?}}}",
                clock.source, clock.destination
            )
            .map_err(|_| "witness clock JSON formatting")?;
        } else {
            json.push_str("null");
        }
        json.push_str(",\"preparation_key\":");
        if let Some(preparation) = vmm.execution.preparation_observation() {
            write!(
                json,
                "{{\"operation\":{},\"generation\":{}}}",
                preparation.key.operation.0, preparation.key.generation.0
            )
            .map_err(|_| "witness preparation JSON formatting")?;
        } else {
            json.push_str("null");
        }
        json.push_str(",\"time_offsets\":");
        if let Some(preparation) = vmm.execution.preparation_observation() {
            if preparation.plans.len() > 4 {
                return Err("bounded time-plan inventory".into());
            }
            json.push('[');
            for (index, plan) in preparation.plans.iter().enumerate() {
                let CpuTimePlan::Kvm(KvmCpuTimePlan::X86 { id, offset, .. }) = plan else {
                    return Err("foreign witness time-plan inventory".into());
                };
                if usize::from(*id) != index {
                    return Err("out-of-order witness time-plan inventory".into());
                }
                if index != 0 {
                    json.push(',');
                }
                write!(json, "{offset}").map_err(|_| "witness time-offset JSON formatting")?;
            }
            json.push(']');
        } else {
            json.push_str("null");
        }
        json.push_str(",\"cut_clock\":");
        if let Some(cut) = &vmm.execution.retained {
            let VmExecutionState::Kvm(KvmVmState::X86(clock)) = &cut.vm else {
                return Err("foreign witness VM clock".into());
            };
            write!(
                json,
                "{:?}",
                [
                    clock.clock,
                    u64::from(clock.clock_flags),
                    clock.host_tsc,
                    clock.realtime
                ]
            )
            .map_err(|_| "witness cut-clock JSON formatting")?;
        } else {
            json.push_str("null");
        }
        json.push_str("}\n");
        write_new(path, json.as_bytes())
    }
}
pub(crate) fn write_command(vmm: &Vmm, value: u64) -> Result<(), String> {
    vmm.guest_memory
        .store(value, GuestAddress(SLOT + 24), Ordering::SeqCst)
        .map_err(|error| error.to_string())
}

pub(crate) fn observe(vmm: &Vmm) -> Result<ProbeObservation, String> {
    let (words, irq_publication) = irq_words(&vmm.guest_memory)?;
    let native = match vmm
        .execution
        .retained
        .as_ref()
        .and_then(|cut| cut.cpus.get(2))
    {
        Some(CpuExecutionState::Kvm(KvmCpuState::X86(cpu))) => Some((
            lapic_u32(&cpu.lapic, 0x270).map_err(|e| e.to_string())? & 1 != 0,
            lapic_u32(&cpu.lapic, 0x170).map_err(|e| e.to_string())? & 1 != 0,
            cpu.deadline,
        )),
        Some(_) => return Err("foreign witness CPU inventory".into()),
        None => None,
    };
    Ok(ProbeObservation {
        words,
        irq_publication,
        pending: native.map(|value| value.0),
        in_service: native.map(|value| value.1),
        deadline: native.map(|value| value.2),
    })
}

fn source_commandline(commandline: &str) -> Result<(), String> {
    let mut maxcpus = false;
    let mut high = false;
    let mut low = false;
    for word in commandline.split_whitespace() {
        let duplicate = match word {
            "maxcpus=2" => std::mem::replace(&mut maxcpus, true),
            "memmap=16M$448M" => std::mem::replace(&mut high, true),
            "memmap=64K$448K" => std::mem::replace(&mut low, true),
            word if word.starts_with("maxcpus=") || word.starts_with("memmap=") => true,
            _ => false,
        };
        if duplicate {
            return Err("source witness has conflicting CPU/RAM construction arguments".into());
        }
    }
    if !maxcpus || !high || !low {
        return Err("source witness requires reserved high/low RAM and maxcpus=2".into());
    }
    Ok(())
}

pub(crate) fn validate_source(vmm: &Vmm) -> Result<(), String> {
    source_commandline(vmm.kernel_cmdline.as_str())?;
    if vmm.memory.restore_installation().is_some()
        || vmm.memory_domain.backing_kind() == arch::guest_memory::BackingKind::RestoredPrivate
        || !matches!(
            vmm.control.state,
            crate::vmm::control::ControlState::Paused(_)
        )
        || !vmm.control.cpus.reconciled()
    {
        return Err("witness construction requires a reconciled paused original source".into());
    }
    Ok(())
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use crate::api::vmm_builder::native_device_probe::witness::{
        CODE, SLOT, fixture_symbol, irq_words, source_commandline,
    };

    #[test]
    fn source_construction_requires_actual_reserved_ram_and_offline_ap_commandline() {
        let valid = "console=hvc0 maxcpus=2 memmap=16M$448M memmap=64K$448K";
        assert!(source_commandline(valid).is_ok());
        assert!(source_commandline("").is_err());
        assert!(source_commandline("maxcpus=2 memmap=16M$448M").is_err());
        assert!(source_commandline(&valid.replace("maxcpus=2", "maxcpus=4")).is_err());
        assert!(source_commandline(&format!("{valid} maxcpus=4")).is_err());
        assert!(source_commandline(&format!("{valid} maxcpus=2")).is_err());
        assert!(source_commandline(&valid.replace("memmap=64K$448K", "memmap=64K$449K")).is_err());
        assert!(source_commandline(&format!("{valid} memmap=exactmap")).is_err());
        assert!(source_commandline(&format!("{valid} memmap=16M$448M")).is_err());
    }

    #[test]
    fn device_witness_symbols_bind_exact_source_text() {
        assert_eq!(
            fixture_symbol("000000001c001000 T _start\n", "_start").unwrap(),
            CODE
        );
        assert!(fixture_symbol("", "_start").is_err());
        assert!(fixture_symbol("000000001c001000 U _start\n", "_start").is_err());
        assert!(fixture_symbol("000000001c001000 T _start extra\n", "_start").is_err());
        assert!(
            fixture_symbol(
                "000000001c001000 T _start\n000000001c001000 T _start\n",
                "_start"
            )
            .is_err()
        );
        assert!(fixture_symbol("0000000000001000 T _start\n", "_start").is_err());
        assert!(fixture_symbol("000000001c004000 T _start\n", "_start").is_err());
        assert!(fixture_symbol("not-a-number T _start\n", "_start").is_err());
    }

    #[test]
    fn device_witness_irq_publication_retains_incomplete_epoch() {
        let memory = crate::vmm::memory::runtime_memory_for_test(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(SLOT), 0x1000)]).unwrap(),
        );
        memory
            .store(1u64, GuestAddress(SLOT + 184), Ordering::SeqCst)
            .unwrap();
        let mut expected = [0u64; 23];
        expected[5] = 1;
        expected[18] = 0x1_2345_6789;
        expected[19] = 0x1111_2222;
        for (index, word) in expected.iter().enumerate() {
            memory
                .store(
                    *word,
                    GuestAddress(SLOT + index as u64 * 8),
                    Ordering::SeqCst,
                )
                .unwrap();
        }
        let (words, epochs) = irq_words(&memory).unwrap();
        assert_eq!(words, expected);
        assert_eq!(epochs, [1, 1]);
        memory
            .store(2u64, GuestAddress(SLOT + 184), Ordering::SeqCst)
            .unwrap();
        let (words, epochs) = irq_words(&memory).unwrap();
        assert_eq!(words, expected);
        assert_eq!(epochs, [2, 2]);
        // A completed IRQ publication may still be held in-service before EOI.
        assert_eq!(words[20], 0);
    }
}
