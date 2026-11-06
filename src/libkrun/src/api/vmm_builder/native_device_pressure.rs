use std::fmt::Write;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::Instant;

use devices::virtio::balloon::{
    ReclaimBacking, ReclaimQualification, ReclaimReason, ReclaimStatus,
};
use devices::virtio::balloon::{
    ReportDescriptor, ReportIdentity, ReportWitness, ReportWitnessState,
};
use devices::virtio::block::Block;
use devices::virtio::lifecycle::ProviderFault;
use devices::virtio::{Balloon, Console, Vsock};
use vm_memory::GuestAddress;

use crate::api::vmm_builder::native_device_probe::{Driver, Resource, WAIT, write_new};
use crate::vmm::control::ControlState;
use crate::vmm::device_manager::quiescence::{DeviceQuiescence, ManagerError, ManagerFault};
use crate::vmm::execution::kvm::{KvmCpuState, KvmVmState};
use crate::vmm::execution::{CpuExecutionState, VmExecutionState};

#[derive(Debug)]
enum ObservationError {
    Busy(String),
    Fault(String),
}

impl From<String> for ObservationError {
    fn from(error: String) -> Self {
        Self::Fault(error)
    }
}

impl From<&str> for ObservationError {
    fn from(error: &str) -> Self {
        Self::Fault(error.into())
    }
}

impl From<ManagerError> for ObservationError {
    fn from(error: ManagerError) -> Self {
        match &error.fault {
            ManagerFault::LockBusy | ManagerFault::Provider(ProviderFault::LockBusy) => {
                Self::Busy(error.to_string())
            }
            ManagerFault::Lifecycle(lifecycle) if lifecycle.fault == ProviderFault::LockBusy => {
                Self::Busy(error.to_string())
            }
            _ => Self::Fault(error.to_string()),
        }
    }
}

fn observe_lock<'a, T: ?Sized>(
    lock: &'a Mutex<T>,
    context: &str,
) -> Result<MutexGuard<'a, T>, ObservationError> {
    lock.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => ObservationError::Busy(format!("{context}: lock busy")),
        TryLockError::Poisoned(_) => ObservationError::Fault(format!("{context}: lock poisoned")),
    })
}

fn provider_error(context: &str, fault: ProviderFault) -> ObservationError {
    let error = format!("{context}: {fault:?}");
    match fault {
        ProviderFault::LockBusy => ObservationError::Busy(error),
        _ => ObservationError::Fault(error),
    }
}

fn quoted(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            value if value < '\u{20}' => {
                let _ = write!(result, "\\u{:04x}", u32::from(value));
            }
            value => result.push(value),
        }
    }
    result.push('"');
    result
}

pub(in crate::api::vmm_builder::native_device_probe) fn reclaim_status_json(
    status: ReclaimStatus,
) -> String {
    let backing = match status.backing {
        ReclaimBacking::Boot => "boot",
        ReclaimBacking::RestoredPrivate => "restored-private",
    };
    let reason = match status.reason {
        ReclaimReason::None => "none",
        ReclaimReason::TrackedCapture => "tracked-capture",
        ReclaimReason::RestoredPrivateMapping => "restored-private-mapping",
    };
    let qualification = match status.qualification {
        ReclaimQualification::NotRun => "not-run",
        ReclaimQualification::Passed => "passed",
        ReclaimQualification::Failed => "failed",
        ReclaimQualification::Inconclusive => "inconclusive",
    };
    format!(
        concat!(
            "{{\"backing\":\"{}\",\"reason\":\"{}\",\"requested\":{},\"qualification\":\"{}\",\"effective\":{},",
            "\"released_bytes\":{},\"released_extents\":{},\"retried_faults\":{},\"skipped_reports\":{},\"failed_operations\":{}}}"
        ),
        backing,
        reason,
        status.requested,
        qualification,
        status.effective,
        status.released_bytes,
        status.released_extents,
        status.retried_faults,
        status.skipped_reports,
        status.failed_operations,
    )
}

fn reclaim_field<T: std::str::FromStr>(
    fields: &mut std::str::SplitWhitespace<'_>,
    name: &str,
) -> Result<T, String> {
    fields
        .next()
        .ok_or_else(|| format!("reclaim command missing {name}"))?
        .parse()
        .map_err(|_| format!("reclaim command invalid {name}"))
}

fn child_report(operand: &str) -> Result<(u8, u8, ReportIdentity), String> {
    let mut fields = operand.split_whitespace();
    let source = reclaim_field(&mut fields, "source seed")?;
    let child = reclaim_field(&mut fields, "child seed")?;
    let mut report = ReportIdentity {
        head: reclaim_field(&mut fields, "head")?,
        next_avail: reclaim_field(&mut fields, "next_avail")?,
        next_used: reclaim_field(&mut fields, "next_used")?,
        avail_idx: reclaim_field(&mut fields, "avail_idx")?,
        used_idx: reclaim_field(&mut fields, "used_idx")?,
        gpa: reclaim_field(&mut fields, "gpa")?,
        desc_table: reclaim_field(&mut fields, "desc_table")?,
        avail_ring: reclaim_field(&mut fields, "avail_ring")?,
        used_ring: reclaim_field(&mut fields, "used_ring")?,
        descriptors: Vec::new(),
    };
    let count: usize = reclaim_field(&mut fields, "descriptor count")?;
    if !(1..=256).contains(&count) {
        return Err("reclaim descriptor count outside reporting queue capacity".into());
    }
    report.descriptors.reserve_exact(count);
    for _ in 0..count {
        report.descriptors.push(ReportDescriptor {
            addr: reclaim_field(&mut fields, "descriptor addr")?,
            len: reclaim_field(&mut fields, "descriptor len")?,
            flags: reclaim_field(&mut fields, "descriptor flags")?,
            next: reclaim_field(&mut fields, "descriptor next")?,
        });
    }
    if fields.next().is_some() || source == 0 || child == 0 || source == child {
        return Err("reclaim child requires exact identity and distinct nonzero seeds".into());
    }
    Ok((source, child, report))
}

fn report_witness_json(witness: &ReportWitness) -> String {
    let state = match witness.state {
        ReportWitnessState::Idle => "idle",
        ReportWitnessState::Holding => "holding",
        ReportWitnessState::SourceSeeded => "source-seeded",
        ReportWitnessState::ChildCompleted => "child-completed",
        ReportWitnessState::Failed => "failed",
    };
    let report = witness.report.as_ref().map_or_else(|| "null".into(), |report| {
        let descriptors = report.descriptors.iter().map(|descriptor| format!(
            "{{\"addr\":{},\"len\":{},\"flags\":{},\"next\":{}}}",
            descriptor.addr, descriptor.len, descriptor.flags, descriptor.next,
        )).collect::<Vec<_>>().join(",");
        format!(
            concat!(
                "{{\"head\":{},\"next_avail\":{},\"next_used\":{},\"avail_idx\":{},\"used_idx\":{},",
                "\"gpa\":{},\"desc_table\":{},\"avail_ring\":{},\"used_ring\":{},\"descriptors\":[{}]}}"
            ),
            report.head, report.next_avail, report.next_used, report.avail_idx, report.used_idx,
            report.gpa, report.desc_table, report.avail_ring, report.used_ring, descriptors,
        )
    });
    let barrier = witness.barrier.map_or_else(
        || "null".into(),
        |key| {
            format!(
                "{{\"operation\":{},\"generation\":{}}}",
                key.operation.0, key.generation.0,
            )
        },
    );
    format!(
        concat!(
            "\"state\":\"{}\",\"report\":{},\"seed\":{},\"verified_bytes\":{},\"used_after\":{},",
            "\"barrier\":{},\"parked_cpus\":{},\"failure\":{}"
        ),
        state,
        report,
        witness
            .seed
            .map_or_else(|| "null".into(), |seed| seed.to_string()),
        witness.verified_bytes,
        witness
            .used_after
            .map_or_else(|| "null".into(), |index| index.to_string()),
        barrier,
        witness.parked_cpus,
        witness
            .failure
            .as_ref()
            .map_or_else(|| "null".into(), |failure| quoted(failure)),
    )
}

pub(in crate::api::vmm_builder::native_device_probe) fn reclaim_command(
    driver: &mut Driver,
    resources: &[Resource],
    operation: &str,
    operand: &str,
) -> Result<(), String> {
    let source_seed = if operation == "reclaim-hold-source" {
        let seed = operand.parse::<u8>().map_err(|_| "reclaim source seed")?;
        if seed == 0 {
            return Err("reclaim source seed must be nonzero".into());
        }
        Some(seed)
    } else {
        None
    };
    let child = if operation == "reclaim-complete-child" {
        Some(child_report(operand)?)
    } else {
        None
    };
    if operation == "reclaim-release-hold" && !operand.is_empty() {
        return Err("reclaim-release-hold takes no operands".into());
    }
    let vmm = driver
        .vmm
        .try_lock()
        .map_err(|_| "reclaim VMM lock unavailable")?;
    if source_seed.is_some() && !matches!(vmm.control.state, ControlState::Running) {
        return Err("source reclaim hold requires a running source".into());
    }
    if child.is_some() && !matches!(vmm.control.state, ControlState::RestorePrepared { .. }) {
        return Err("child reclaim completion must arm before restore release".into());
    }
    let mut balloons = resources
        .iter()
        .filter(|resource| resource.id == "balloon0");
    let resource = balloons.next().ok_or("reclaim actual balloon absent")?;
    if balloons.next().is_some() {
        return Err("reclaim actual balloon is not unique".into());
    }
    let mut device = resource
        .device
        .try_lock()
        .map_err(|_| "reclaim balloon lock unavailable")?;
    let balloon = (*device)
        .as_mut_any()
        .downcast_mut::<Balloon>()
        .ok_or("reclaim requires actual Balloon")?;
    match operation {
        "reclaim-hold-source" => {
            let seed = source_seed.ok_or("reclaim source seed absent")?;
            balloon.pressure_hold_reports()?;
            balloon.pressure_arm_source(seed)
        }
        "reclaim-complete-child" => {
            let (source, child, report) = child.ok_or("reclaim child identity absent")?;
            balloon.pressure_hold_reports()?;
            balloon.pressure_arm_child(report, source, child)
        }
        "reclaim-release-hold" => balloon.pressure_release_reports(),
        "reclaim-witness" => {
            let witness = balloon.pressure_report_witness();
            let output = format!(
                "{{\"schema\":1,\"native_pid\":{},{},\"reclaim\":{},\"remapper_present\":{}}}\n",
                std::process::id(),
                report_witness_json(&witness),
                reclaim_status_json(balloon.reclaim_status()),
                balloon.pressure_remapper_present(),
            );
            write_new(Path::new(operand), output.as_bytes())
        }
        _ => Err("unknown reclaim operation".into()),
    }
}

pub(in crate::api::vmm_builder::native_device_probe) fn command(
    driver: &mut Driver,
    resources: &[Resource],
    operand: &str,
) -> Result<(), String> {
    let (operation, value) = operand
        .split_once(' ')
        .ok_or("pressure operation needs operand")?;
    match operation {
        "snapshot" => snapshot(driver, resources, Path::new(value)),
        "wake" | "wake-restore" => {
            let resource = resources
                .iter()
                .find(|resource| resource.id == value)
                .ok_or("pressure wake participant absent")?;
            let mut device = resource
                .device
                .try_lock()
                .map_err(|_| "pressure block lock")?;
            let block = (*device)
                .as_mut_any()
                .downcast_mut::<Block>()
                .ok_or("pressure wake requires actual raw Block")?;
            if operation == "wake" {
                block.pressure_arm_wake_failure()
            } else {
                block.pressure_restore_wake()
            }
            .map_err(|error| format!("actual block wake boundary: {error:?}"))
        }
        "request" => {
            let (mode, id) = value
                .split_once(' ')
                .ok_or("pressure request needs owned|unpopped|release and id")?;
            let resource = resources
                .iter()
                .find(|resource| resource.id == id)
                .ok_or("pressure request participant absent")?;
            let mut device = resource
                .device
                .try_lock()
                .map_err(|_| "pressure request lock")?;
            let block = (*device)
                .as_mut_any()
                .downcast_mut::<Block>()
                .ok_or("pressure request requires actual raw Block")?;
            match mode {
                "owned" => block.pressure_hold_request(true),
                "unpopped" => block.pressure_hold_request(false),
                "release" => block.pressure_release_request(),
                _ => return Err("pressure request expects owned|unpopped|release".into()),
            }
            .map_err(|error| format!("actual request ownership boundary: {error:?}"))
        }
        "evq" => {
            let held = match value {
                "hold" => true,
                "release" => false,
                _ => return Err("pressure evq expects hold|release".into()),
            };
            let resource = resources
                .iter()
                .find(|resource| resource.id == "vsock0")
                .ok_or("actual vsock0 absent")?;
            let mut device = resource
                .device
                .try_lock()
                .map_err(|_| "pressure vsock lock")?;
            (*device)
                .as_mut_any()
                .downcast_mut::<Vsock>()
                .ok_or("pressure requires actual native mux Vsock")?
                .hold_event_queue(held)
                .map_err(|error| format!("actual EVQ boundary: {error:?}"))
        }
        "irq" => {
            let (mode, id) = value
                .split_once(' ')
                .ok_or("pressure irq needs hold|release and id")?;
            let held = match mode {
                "hold" => true,
                "release" => false,
                _ => return Err("pressure irq expects hold|release".into()),
            };
            irq(driver, id, held)
        }
        _ => Err(format!("unknown pressure operation {operation}")),
    }
}

fn irq(driver: &mut Driver, id: &str, held: bool) -> Result<(), String> {
    let deadline = Instant::now() + WAIT;
    let mut address = None;
    loop {
        if Instant::now() >= deadline {
            return Err("pressure IRQ admission deadline expired".into());
        }
        let result = (|| {
            let vmm = observe_lock(&driver.vmm, "pressure IRQ VMM")?;
            let inventory = &vmm.mmio_device_manager.quiescence;
            let address = match address {
                Some(address) => address,
                None => {
                    let resolved = inventory
                        .attachment_identities()
                        .into_iter()
                        .find(|identity| identity.configured_id == id)
                        .ok_or("pressure IRQ attachment absent")?
                        .address;
                    address = Some(resolved);
                    resolved
                }
            };
            irq_admission(inventory, address, held)
        })();
        match result {
            Ok(()) if Instant::now() < deadline => return Ok(()),
            Ok(()) => return Err("pressure IRQ completion deadline expired".into()),
            Err(ObservationError::Busy(error)) => {
                if Instant::now() >= deadline {
                    return Err(format!("pressure IRQ admission deadline expired: {error}"));
                }
                // Only pre-effect contention reaches dispatch, with all guards dropped.
                driver.poll()?;
            }
            Err(ObservationError::Fault(error)) => return Err(error),
        }
    }
}

fn irq_admission(
    inventory: &DeviceQuiescence,
    address: u64,
    held: bool,
) -> Result<(), ObservationError> {
    inventory
        .diagnostic_hold_irq_acks(address, held)
        .map_err(|error| {
            // The manager's transport try_lock precedes the effect. Provider
            // errors can follow ACK application and must never replay it.
            if matches!(error.fault, ManagerFault::LockBusy) {
                ObservationError::Busy(error.to_string())
            } else {
                ObservationError::Fault(error.to_string())
            }
        })
}

fn snapshot(driver: &mut Driver, resources: &[Resource], path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + WAIT;
    loop {
        if Instant::now() >= deadline {
            return Err("pressure observation deadline expired".into());
        }
        match snapshot_observation(driver, resources) {
            Ok(result) if Instant::now() < deadline => {
                return write_new(path, result.as_bytes());
            }
            Ok(_) => return Err("pressure observation deadline expired".into()),
            Err(ObservationError::Busy(error)) => {
                if Instant::now() >= deadline {
                    return Err(format!("pressure observation deadline expired: {error}"));
                }
                // The failed read has dropped every guard before dispatch needs
                // the VMM or the same participant. No effect command is replayed.
                driver.poll()?;
            }
            Err(ObservationError::Fault(error)) => return Err(error),
        }
    }
}

fn snapshot_observation(
    driver: &Driver,
    resources: &[Resource],
) -> Result<String, ObservationError> {
    let vmm = observe_lock(&driver.vmm, "pressure VMM")?;
    let snapshots = vmm.mmio_device_manager.quiescence.lifecycle_snapshots()?;
    let captured_key = match &vmm.control.state {
        ControlState::Paused(_) => Some(
            vmm.execution
                .retained
                .as_ref()
                .ok_or("paused pressure cut missing")?
                .key,
        ),
        ControlState::RestorePrepared { key } => Some(*key),
        _ => None,
    };
    let captured = captured_key
        .map(|key| vmm.mmio_device_manager.quiescence.capture_devices(key))
        .transpose()?;
    let mut devices = Vec::with_capacity(resources.len());
    let mut blocks = Vec::new();
    let mut consoles = Vec::new();
    let mut vsock = None;
    let mut balloon_reclaim = None;
    for resource in resources {
        let device = observe_lock(&resource.device, &resource.id)?;
        let (_, lifecycle) = snapshots
            .iter()
            .find(|(identity, _)| identity.configured_id == resource.id)
            .ok_or("actual resource missing from participant inventory")?;
        let record = captured.as_ref().and_then(|records| {
            records
                .iter()
                .find(|record| record.identity.configured_id == resource.id)
        });
        let queues = record.map(|record| {
            record.state.queues.iter().map(|queue| {
                let ring_index = |base: u64| -> Result<String, String> {
                    if !queue.ready { return Ok("null".into()); }
                    let address = base.checked_add(2).ok_or("pressure ring-index overflow")?;
                    let index: u16 = vmm.guest_memory.read_obj(GuestAddress(address))
                        .map_err(|error| format!("actual queue index read: {error}"))?;
                    Ok(u16::from_le(index).to_string())
                };
                Ok(format!(
                    "{{\"max_size\":{},\"size\":{},\"ready\":{},\"next_avail\":{},\"next_used\":{},\"desc_table\":{},\"avail_ring\":{},\"used_ring\":{},\"event_idx_enabled\":{},\"num_added\":{},\"avail_idx\":{},\"used_idx\":{}}}",
                    queue.max_size, queue.size, queue.ready, queue.next_avail, queue.next_used, queue.desc_table, queue.avail_ring,
                    queue.used_ring, queue.event_idx_enabled, queue.num_added, ring_index(queue.avail_ring)?, ring_index(queue.used_ring)?
                ))
            }).collect::<Result<Vec<_>, String>>().map(|queues| queues.join(","))
        }).transpose()?;
        let failure = lifecycle
            .failure
            .map(|error| quoted(&format!("{error:?}")))
            .unwrap_or_else(|| "null".into());
        let queue_count = record
            .map(|record| record.state.queues.len().to_string())
            .unwrap_or_else(|| "null".into());
        devices.push(format!(
            "{{\"id\":{},\"kind\":{},\"avail_features\":{},\"acked_features\":{},\"interrupt_status\":{},\"lifecycle\":{{\"stage\":{},\"accepted\":{},\"failure\":{},\"queues_owned\":{}}},\"queues\":{}}}",
            quoted(&resource.id), device.device_type(), device.avail_features(), device.acked_features(),
            record.map(|record| record.state.interrupt_status.to_string()).unwrap_or_else(|| "null".into()),
            quoted(&format!("{:?}", lifecycle.stage)), lifecycle.accepted, failure, queue_count,
            queues.map(|queues| format!("[{queues}]")).unwrap_or_else(|| "null".into())
        ));
        if let Some(block) = (*device).as_any().downcast_ref::<Block>() {
            let owned = block
                .pressure_ownership()
                .map_err(|error| provider_error("actual block owner observation", error))?;
            blocks.push(format!(
                "{{\"id\":{},\"worker_handle_retained\":{},\"worker_finished\":{},\"returned_worker_retained\":{},\"backend_retained\":{},\"subscribed_wake_held\":{},\"wake_errno\":{},\"owned_head\":{},\"available_unpopped\":{},\"consumed_kicks\":{}}}",
                quoted(&resource.id), owned.worker_handle_retained, owned.worker_finished, owned.returned_worker_retained,
                owned.backend_retained, owned.subscribed_wake_held, owned.wake_errno.map(|error| error.to_string()).unwrap_or_else(|| "null".into()),
                owned.owned_head.map(|head| head.to_string()).unwrap_or_else(|| "null".into()), owned.available_unpopped, owned.consumed_kicks
            ));
        }
        if let Some(console) = (*device).as_any().downcast_ref::<Console>() {
            let ports = console
                .output_observations()
                .map_err(|error| provider_error("actual console output observation", error))?
                .iter()
                .map(|port| {
                    format!(
                        "{{\"port_id\":{},\"worker_handle_retained\":{},\"worker_finished\":{},\"admission_closed\":{},\"blocked_head\":{},\"bytes_written\":{},\"write_remaining\":{}}}",
                        port.port_id, port.worker_handle_retained, port.worker_finished,
                        port.admission_closed,
                        port.blocked_head.map(|head| head.to_string()).unwrap_or_else(|| "null".into()),
                        port.bytes_written, port.write_remaining
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            consoles.push(format!(
                "{{\"id\":{},\"ports\":[{}]}}",
                quoted(&resource.id),
                ports
            ));
        }
        if let Some(balloon) = (*device).as_any().downcast_ref::<Balloon>() {
            balloon_reclaim = Some(reclaim_status_json(balloon.reclaim_status()));
        }
        if let Some(device) = (*device).as_any().downcast_ref::<Vsock>() {
            let observation = device
                .pressure_observation()
                .map_err(|error| provider_error("actual vsock observation", error))?;
            vsock = Some(format!(
                concat!(
                    "{{\"stage\":{},\"accepted\":{},\"pending_reset\":{},\"reset_deliveries\":{},\"event_queue_held\":{},\"event_queue_owned\":{},",
                    "\"worker_threads\":[{}],\"unfinished_workers\":{},\"expected\":{},\"started\":{},\"parked\":{},\"exited\":{},\"reconciled\":{},\"paused\":{},\"activation_fenced\":{},\"transport_ready\":{},",
                    "\"host_connects\":{},\"guest_requests\":{},\"admitted\":{},\"rejected\":{},\"credit_queued\":{},\"credit_delivered\":{},\"reaps\":{},\"overflowed\":{},",
                    "\"sessions\":{},\"listeners\":{},\"connected\":{},\"waiting_credit\":{},\"pending_host\":{},\"deferred_credits\":{},\"response_queue_len\":{}}}"
                ),
                quoted(&format!("{:?}", observation.stage)),
                observation.accepted,
                observation.pending_reset,
                observation.reset_deliveries,
                observation.event_queue_held,
                observation.event_queue_owned,
                observation
                    .worker_threads
                    .iter()
                    .flatten()
                    .map(|id| quoted(&format!("{id:?}")))
                    .collect::<Vec<_>>()
                    .join(","),
                observation.unfinished_workers,
                observation.expected,
                observation.started,
                observation.parked,
                observation.exited,
                observation.reconciled,
                observation.paused,
                observation.activation_fenced,
                observation.transport_ready,
                observation.host_connects,
                observation.guest_requests,
                observation.admitted,
                observation.rejected,
                observation.credit_queued,
                observation.credit_delivered,
                observation.reaps,
                observation.overflowed,
                observation.sessions,
                observation.listeners,
                observation.connected,
                observation.waiting_credit,
                observation.pending_host,
                observation.deferred_credits,
                observation.response_queue_len
            ));
        }
    }
    let routes = vmm.mmio_device_manager.diagnostic_irq_routes(vmm.vm.fd())?.iter().map(|route| format!(
        "{{\"irq\":{},\"members\":{:?},\"registered\":{},\"ioapic_irr\":{},\"ioapic_route\":{}}}",
        route.gsi, route.members, route.registered,
        route.ioapic_irr.map(|pending| pending.to_string()).unwrap_or_else(|| "null".into()),
        route.ioapic_route.map(|word| word.to_string()).unwrap_or_else(|| "null".into())
    )).collect::<Vec<_>>().join(",");
    let irq_members = vmm.mmio_device_manager.quiescence.diagnostic_irq_snapshots()
        .map_err(ObservationError::from)?.iter().map(|(identity, irq)| format!(
            "{{\"id\":{},\"irq\":{},\"interrupt_status\":{},\"signal_attempts\":{},\"signal_successes\":{},\"ack_count\":{},\"ack_applied\":{},\"held_acks\":{},\"ack_hold\":{},\"overflow\":{}}}",
            quoted(&identity.configured_id), identity.irq, irq.status, irq.signal_attempts, irq.signal_successes,
            irq.ack_writes, irq.ack_applied, irq.held_acks, irq.ack_hold, irq.overflow
        )).collect::<Vec<_>>().join(",");
    let legacy = vmm
        .mmio_device_manager
        .quiescence
        .legacy_attachments()
        .iter()
        .map(|identity| {
            format!(
                "{{\"kind\":{},\"address\":{},\"irq\":{}}}",
                quoted(&format!("{:?}", identity.kind)),
                identity.address,
                identity
                    .irq
                    .map(|irq| irq.to_string())
                    .unwrap_or_else(|| "null".into())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let controller = if let Some(cut) = &vmm.execution.retained {
        if let VmExecutionState::Kvm(KvmVmState::X86(state)) = &cut.vm {
            let cpus =
                cut.cpus
                    .iter()
                    .map(|cpu| {
                        let CpuExecutionState::Kvm(KvmCpuState::X86(cpu)) = cpu else {
                            return Err("foreign CPU variant in actual x86 controller observation"
                                .to_string());
                        };
                        Ok(format!(
                            "{{\"id\":{},\"lapic\":{:?},\"events\":{:?}}}",
                            cpu.id, cpu.lapic, cpu.events
                        ))
                    })
                    .collect::<Result<Vec<_>, String>>()?
                    .join(",");
            format!(
                "{{\"ioapic_irr\":{},\"ioapic_routes\":{:?},\"cpus\":[{}]}}",
                state.ioapic_irr, state.ioapic_routes, cpus
            )
        } else {
            "null".into()
        }
    } else {
        "null".into()
    };
    let clock_pairs = vmm
        .vm
        .execution_time_observation()?
        .map(|observation| {
            format!(
                "{{\"source\":{:?},\"destination\":{:?}}}",
                observation.source, observation.destination
            )
        })
        .unwrap_or_else(|| "null".into());
    let result = format!(
        concat!(
            "{{\"pid\":{},\"controller\":{{\"state\":{},\"release_may_have_run\":{},\"time\":{},\"writes\":{:?},\"clock_pairs\":{}}},",
            "\"devices\":[{}],\"irq_routes\":[{}],\"irq_members\":[{}],\"legacy\":[{}],\"vsock\":{},\"block\":[{}],\"consoles\":[{}],\"balloon\":{{\"reclaim\":{}}},\"retained_native_controller\":{}}}\n"
        ),
        std::process::id(),
        quoted(&format!("{:?}", vmm.control.state)),
        vmm.control.cpus.release_may_have_run(),
        quoted(&format!("{:?}", vmm.execution.preparation_observation())),
        vmm.vm.execution_controller_writes(),
        clock_pairs,
        devices.join(","),
        routes,
        irq_members,
        legacy,
        vsock.ok_or("actual Vsock provider missing")?,
        blocks.join(","),
        consoles.join(","),
        balloon_reclaim.ok_or("actual Balloon provider missing")?,
        controller
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::api::vmm_builder::native_device_probe::pressure::{ObservationError, irq_admission};
    use crate::vmm::device_manager::quiescence::{AttachmentIdentity, DeviceQuiescence};
    use devices::legacy::DummyIrqChip;
    use devices::virtio::{MmioTransport, Rng};
    use devices::{BusDevice, DeviceType};
    use std::sync::{Arc, Mutex};
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn pressure_observation_real_transport_contention_is_pending_but_poison_is_terminal() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let device = Arc::new(Mutex::new(Rng::new().unwrap()));
        let transport = Arc::new(Mutex::new(
            MmioTransport::new(
                crate::vmm::memory::runtime_memory_for_test(memory),
                DummyIrqChip::new().into(),
                device.clone(),
                None,
            )
            .unwrap(),
        ));
        let identity = AttachmentIdentity {
            device_type: DeviceType::Virtio(4),
            configured_id: "actual-entropy".into(),
            address: 0xd000_0000,
            irq: 5,
        };
        let mut inventory = DeviceQuiescence::default();
        inventory.retain_transport(identity.clone(), transport.clone(), device);
        let held = transport
            .lock()
            .expect("hold the actual observed transport");
        for error in [
            inventory.lifecycle_snapshots().unwrap_err(),
            inventory.diagnostic_irq_snapshots().unwrap_err(),
        ] {
            assert_eq!(error.attachment.as_ref(), Some(&identity));
            assert!(matches!(
                ObservationError::from(error),
                ObservationError::Busy(_)
            ));
        }
        assert!(matches!(
            irq_admission(&inventory, identity.address, true),
            Err(ObservationError::Busy(_))
        ));
        assert!(!held.diagnostic_irq_snapshot().ack_hold);
        drop(held);
        assert_eq!(inventory.lifecycle_snapshots().unwrap().len(), 1);
        assert_eq!(inventory.diagnostic_irq_snapshots().unwrap().len(), 1);
        irq_admission(&inventory, identity.address, true).unwrap();
        let mut held = transport.lock().expect("access actual IRQ transport");
        for (offset, value) in [
            (0x70, 1_u32),
            (0x70, 3),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x30, 0),
            (0x38, 8),
            (0x80, 0),
            (0x90, 0x1000),
            (0xa0, 0x2000),
            (0x44, 1),
            (0x70, 15),
        ] {
            held.write(0, offset, &value.to_le_bytes());
        }
        held.interrupt(1).unwrap();
        held.write(0, 0x64, &1_u32.to_le_bytes());
        let before = held.diagnostic_irq_snapshot();
        assert!(before.ack_hold);
        assert_eq!(before.status, 1);
        assert_eq!(
            (before.ack_writes, before.ack_applied, before.held_acks),
            (1, 0, 1)
        );
        assert!(matches!(
            irq_admission(&inventory, identity.address, false),
            Err(ObservationError::Busy(_))
        ));
        let pending = held.diagnostic_irq_snapshot();
        assert!(pending.ack_hold);
        assert_eq!(pending.ack_applied, before.ack_applied);
        assert_eq!(pending.held_acks, before.held_acks);
        assert_eq!(pending.status, before.status);
        drop(held);
        irq_admission(&inventory, identity.address, false).unwrap();
        let released = transport
            .lock()
            .expect("observe released actual IRQ transport")
            .diagnostic_irq_snapshot();
        assert!(!released.ack_hold);
        assert_eq!(released.status, 0);
        assert_eq!(
            (
                released.ack_writes,
                released.ack_applied,
                released.held_acks
            ),
            (1, 1, 0)
        );
        assert!(
            std::thread::spawn(move || {
                let _held = transport
                    .lock()
                    .expect("poison the actual observed transport");
                panic!("poison the actual observed transport");
            })
            .join()
            .is_err()
        );
        for error in [
            inventory.lifecycle_snapshots().unwrap_err(),
            inventory.diagnostic_irq_snapshots().unwrap_err(),
        ] {
            assert!(matches!(
                ObservationError::from(error),
                ObservationError::Fault(_)
            ));
        }
        for held in [true, false] {
            assert!(matches!(
                irq_admission(&inventory, identity.address, held),
                Err(ObservationError::Fault(_))
            ));
        }
    }

    #[test]
    fn pressure_json_string_escapes_observed_native_error_bytes() {
        assert_eq!(
            crate::api::vmm_builder::native_device_probe::pressure::quoted("a\"\\\n\0\t"),
            "\"a\\\"\\\\\\n\\u0000\\t\""
        );
    }
}
