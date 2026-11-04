use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arch::ArchMemoryInfo;
use devices::legacy::{IrqChip, IrqChipDevice};
use kernel::cmdline::Cmdline;
use utils::eventfd::{EFD_NONBLOCK, EventFd};
#[cfg(all(
    feature = "native-execution-probe",
    target_os = "linux",
    target_arch = "x86_64"
))]
use vm_memory::GuestMemoryMmap;

use crate::api::capabilities::execution_state_producer;
use crate::vmm::Vmm;
#[cfg(any(target_os = "macos", feature = "native-execution-probe"))]
use crate::vmm::builder::setup_vm;
use crate::vmm::control::{
    BarrierGeneration, BarrierKey, BarrierRequest, ControlOwner, CpuCommandKind, OperationId,
    RequestId,
};
use crate::vmm::device_manager::mmio::MMIODeviceManager;
#[cfg(target_arch = "aarch64")]
use crate::vmm::execution::CpuExecutionState;
pub(crate) use crate::vmm::execution::device_restore::PreparedDeviceInstall;
use crate::vmm::execution::runtime::{ExecutionOwner, RetainedCut};
use crate::vmm::execution::{
    CpuExecutionInput, ExecutionLane, ValidatedExecution, VmExecutionState,
};
use crate::vmm::memory::image::RestoredRam;
use crate::vmm::vstate::{Vcpu, Vm};

pub(crate) struct RestoreFailure {
    pub error: String,
    pub attempt: Option<Box<Vmm>>,
}

impl std::fmt::Debug for RestoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreFailure")
            .field("error", &self.error)
            .field("attempt_retained", &self.attempt.is_some())
            .finish()
    }
}

fn refusal(error: impl ToString) -> RestoreFailure {
    RestoreFailure {
        error: error.to_string(),
        attempt: None,
    }
}

fn barrier(generation: u64, deadline: Instant) -> BarrierRequest {
    BarrierRequest {
        key: BarrierKey {
            operation: OperationId(0),
            generation: BarrierGeneration(generation),
        },
        deadline,
    }
}

fn assemble(
    info: ArchMemoryInfo,
    vm: Vm,
    controller: IrqChip,
    manager: MMIODeviceManager,
    exit: EventFd,
    generation: BarrierGeneration,
    memory_coordinator: crate::vmm::memory::MemoryCoordinator,
) -> Result<Vmm, String> {
    let memory_domain = memory_coordinator.control.domain().clone();
    Ok(Vmm {
        guest_memory: devices::virtio::RuntimeGuestMemory::new(memory_domain.clone()),
        memory_domain,
        memory: memory_coordinator,
        balloon_bindings: Vec::new(),
        generation_binding: None,
        reclaim_observer: None,
        arch_memory_info: info,
        vm,
        execution_controller: controller,
        mmio_device_manager: manager,
        exit_evt: exit,
        exit_observers: Vec::new(),
        exit_code: Arc::new(AtomicI32::new(i32::MAX)),
        vcpus_handles: Vec::new(),
        kernel_cmdline: Cmdline::new(arch::CMDLINE_MAX_SIZE),
        control: ControlOwner::new(generation).map_err(|error| error.to_string())?,
        execution: ExecutionOwner::default(),
    })
}

pub(crate) fn build_restore_prepared(
    ram: RestoredRam,
    execution: ValidatedExecution,
    mut devices: PreparedDeviceInstall,
    events: &mut polly::event_manager::EventManager,
    deadline: Instant,
) -> Result<Vmm, RestoreFailure> {
    let saved = execution.envelope();
    if Instant::now() >= deadline {
        return Err(refusal("restore deadline expired"));
    }
    if saved.binding != devices.binding {
        return Err(refusal("execution/device cut binding mismatch"));
    }
    saved.validate().map_err(refusal)?;
    ram.domain().layout().validate_capture().map_err(refusal)?;
    if saved.attachments.len() != devices.devices.len()
        || saved
            .attachments
            .iter()
            .zip(&devices.devices)
            .any(|(expected, actual)| expected != &actual.identity)
    {
        return Err(refusal("execution/device attachment identity mismatch"));
    }
    if saved.binding.native_producer != execution_state_producer().map_err(refusal)? {
        return Err(refusal("restore exact native producer mismatch"));
    }
    #[cfg(feature = "native-execution-probe")]
    let cpu_only_fixture = devices.diagnostic_buses.is_some();
    #[cfg(not(feature = "native-execution-probe"))]
    let cpu_only_fixture = false;
    if cpu_only_fixture
        && (!cfg!(feature = "native-execution-probe")
            || !devices.devices.is_empty()
            || !saved.legacy.is_empty())
    {
        return Err(refusal(
            "diagnostic CPU-only restore cannot omit production participants",
        ));
    }
    let expected_lane = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        ExecutionLane::KvmX86
    } else if cfg!(target_os = "linux") {
        ExecutionLane::KvmArm64
    } else {
        ExecutionLane::HvfArm64
    };
    if saved.lane != expected_lane {
        return Err(refusal("restore backend/ISA mismatch"));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let restored_profile = if cpu_only_fixture {
        None
    } else {
        #[cfg(feature = "native-device-probe")]
        let reset_diagnostic = matches!(&saved.vm,
            VmExecutionState::Kvm(crate::vmm::execution::kvm::KvmVmState::X86(state))
                if state.pit_profile == 0
        );
        #[cfg(not(feature = "native-device-probe"))]
        let reset_diagnostic = false;
        if reset_diagnostic {
            Some(crate::vmm::execution::runtime::KvmCaptureProfile::ResetPit)
        } else {
            Some(
                crate::vmm::execution::runtime::KvmCaptureProfile::from_restored_execution(
                    &execution,
                )
                .map_err(refusal)?,
            )
        }
    };
    validate_legacy_bindings(saved, &devices).map_err(refusal)?;
    devices
        .validate_memory(&ram.domain().read_only())
        .map_err(refusal)?;
    let (memory_domain, authority, memory_control, baseline, info) =
        ram.into_parts(&execution).map_err(refusal)?;
    let mut memory_coordinator =
        crate::vmm::memory::MemoryCoordinator::new(memory_control, authority);
    let exit = EventFd::new(EFD_NONBLOCK).map_err(refusal)?;
    #[cfg(target_os = "linux")]
    let (vm, epoch) = crate::vmm::builder::setup_vm_tracked(
        memory_domain.clone(),
        memory_coordinator
            .construction
            .as_ref()
            .ok_or_else(|| refusal("construction authority missing"))?,
    )
    .map_err(refusal)?;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let mut vm = vm;
    #[cfg(target_os = "macos")]
    let (mut vm, epoch) = {
        let memory = memory_coordinator
            .construction
            .as_ref()
            .ok_or_else(|| refusal("construction authority missing"))?
            .memory()
            .map_err(refusal)?;
        let mut vm = setup_vm(memory, &info, false, false, true).map_err(refusal)?;
        vm.bind_memory_domain(memory_domain.clone())
            .map_err(refusal)?;
        let epoch = vm
            .arm_initial(
                memory_coordinator
                    .construction
                    .as_ref()
                    .ok_or_else(|| refusal("construction authority missing"))?,
            )
            .map_err(refusal)?;
        (vm, epoch)
    };
    memory_coordinator.finish_tracked(epoch).map_err(refusal)?;
    memory_coordinator
        .seed_restored(baseline)
        .map_err(refusal)?;
    #[cfg(target_os = "macos")]
    vm.configure_reclaim(&info, false).map_err(refusal)?;
    let mut base = arch::MMIO_MEM_START;
    let mut manager = MMIODeviceManager::new(&mut base, (arch::IRQ_BASE, arch::IRQ_MAX));
    let mut io_bus = devices::Bus::new();
    #[cfg(feature = "native-execution-probe")]
    if let Some((io, mmio)) = devices.diagnostic_buses.take() {
        io_bus = io;
        manager.bus = mmio;
    }
    let mut cpus = Vec::with_capacity(saved.cpus.len());
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let controller = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(
        devices::legacy::KvmIoapic::new(vm.fd()).map_err(refusal)?,
    ))));
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        for cpu in &saved.cpus {
            let CpuExecutionState::Kvm(crate::vmm::execution::kvm::KvmCpuState::Arm64(state)) = cpu
            else {
                return Err(refusal("ARM CPU state required"));
            };
            let mut cpu =
                Vcpu::new_aarch64(state.id, vm.fd_owner(), exit.try_clone().map_err(refusal)?)
                    .map_err(refusal)?;
            cpu.initialize_aarch64_saved(state).map_err(refusal)?;
            cpus.push(cpu);
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let controller = {
        let VmExecutionState::Kvm(crate::vmm::execution::kvm::KvmVmState::Arm64(state)) = &saved.vm
        else {
            return Err(refusal("ARM VM state required"));
        };
        let state = devices::legacy::kvm_state::GicState {
            properties: state.properties,
            irq_count: state.irq_count,
            mpidrs: state.mpidrs.clone(),
            registers: state.registers.clone(),
        };
        let gic =
            devices::legacy::KvmGicV3::create_for_restore(vm.fd(), &state, memory_domain.clone())
                .map_err(refusal)?;
        gic.initialize().map_err(refusal)?;
        Arc::new(Mutex::new(IrqChipDevice::new(Box::new(gic))))
    };
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    vm.set_execution_controller(controller.clone());
    #[cfg(target_os = "macos")]
    let controller = {
        let gic = devices::legacy::HvfGicV3::new(saved.cpus.len() as u64, vm.framework())
            .map_err(refusal)?;
        vm.record_gic_model(crate::api::capabilities::HvfGicModel::NativeGicV3);
        Arc::new(Mutex::new(IrqChipDevice::new(Box::new(gic))))
    };
    #[cfg(target_os = "macos")]
    {
        let list = Arc::new(devices::legacy::VcpuList::new(saved.cpus.len() as u64));
        let mut senders = std::collections::HashMap::new();
        for state in &saved.cpus {
            let CpuExecutionState::Hvf(state) = state else {
                return Err(refusal("HVF CPU state required"));
            };
            let (sender, receiver) = crossbeam_channel::unbounded();
            senders.insert(state.mpidr, sender);
            let mut cpu = Vcpu::new_aarch64(
                state.logical_id,
                vm_memory::GuestAddress(0),
                Some(receiver),
                exit.try_clone().map_err(refusal)?,
                list.clone(),
                vm.reclaim_state(),
                false,
            )
            .map_err(refusal)?;
            cpu.prepare_restore(state).map_err(refusal)?;
            cpus.push(cpu);
        }
        if let Some(bsp) = cpus.first_mut() {
            bsp.set_boot_senders(senders);
        }
    }
    install_legacy_resources(
        &vm,
        &mut manager,
        &mut io_bus,
        &controller,
        &exit,
        saved,
        &mut devices,
    )
    .map_err(refusal)?;
    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    manager.bind_probe_io_bus(io_bus.clone()).map_err(refusal)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    for state in &saved.cpus {
        cpus.push(
            Vcpu::new_x86_64(
                state.id(),
                vm.fd_owner(),
                vm.supported_cpuid().clone(),
                vm.supported_msrs().clone(),
                io_bus.clone(),
                exit.try_clone().map_err(refusal)?,
            )
            .map_err(refusal)?,
        );
    }
    let request = barrier(saved.binding.pause_generation, deadline);
    memory_coordinator
        .begin_close(request.key)
        .map_err(refusal)?;
    match memory_coordinator.poll_drained() {
        std::task::Poll::Ready(result) => result.map_err(refusal)?,
        std::task::Poll::Pending => return Err(refusal("unexpected restore writer ownership")),
    }
    if events.dispatch_fence().is_some() {
        return Err(refusal(
            "restore requires an unfenced destination event manager",
        ));
    }
    events
        .begin_ingress_fence(request)
        .map_err(|error| refusal(format!("restore ingress fence: {error:?}")))?;
    events
        .park_callbacks(request.key)
        .map_err(|error| refusal(format!("restore callback park: {error:?}")))?;
    let mut attempt = assemble(
        info,
        vm,
        controller,
        manager,
        exit,
        request.key.generation,
        memory_coordinator,
    )
    .map_err(refusal)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        attempt.execution.profile = restored_profile;
    }
    let install_result = (|| {
        attempt
            .memory
            .observe_restore_install_begin()
            .map_err(|error| error.to_string())?;
        let native = attempt.memory.native()?;
        // Bus clones snapshot their mappings. Finish dormant topology construction
        // before owners take their buses; install device payloads only after CPU state.
        attach_device_resources(&mut attempt, &devices)?;
        attempt.balloon_bindings = std::mem::take(&mut devices.balloon_bindings);
        attempt.generation_binding = devices.generation_binding.take();
        if let Some(binding) = &attempt.generation_binding {
            binding.bind(&attempt)?;
        }
        let observer = devices::virtio::balloon::ReclaimObserver::for_domain(
            &attempt.memory_domain,
            #[cfg(target_os = "macos")]
            attempt.vm.reclaim_state(),
        );
        for binding in &attempt.balloon_bindings {
            binding
                .finalize(
                    devices::virtio::balloon::BalloonMemoryPolicy::RestoredPrivate,
                    observer.clone(),
                    &attempt.memory_domain,
                    #[cfg(target_os = "macos")]
                    attempt.vm.reclaim_state(),
                    #[cfg(target_os = "macos")]
                    attempt.vm.host_memory_remapper(),
                )
                .map_err(|error| error.to_string())?;
        }
        attempt.reclaim_observer = Some(observer);
        attempt
            .start_vcpus_parked(cpus)
            .map_err(|error| error.to_string())?;
        #[cfg(all(
            feature = "native-execution-probe",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        if let Some(cpu) = devices.diagnostic_install_ack_hold {
            attempt
                .vcpus_handles
                .get(usize::from(cpu))
                .ok_or("diagnostic install ACK CPU missing")?
                .set_probe_ack_hold(Some(CpuCommandKind::InstallExecution))?;
        }
        match &saved.vm {
            #[cfg(target_os = "linux")]
            VmExecutionState::Kvm(state) => attempt.vm.install_execution(state, &native)?,
            #[cfg(target_os = "macos")]
            VmExecutionState::Hvf(state) => attempt
                .execution_controller
                .try_lock()
                .map_err(|_| "GIC lock")?
                .install_hvf_state(&state.gic)
                .map_err(|error| error.to_string())?,
            _ => return Err("restore VM backend mismatch".into()),
        }
        let inputs = saved
            .cpus
            .iter()
            .map(|cpu| Some(Arc::new(CpuExecutionInput::Install(cpu.clone()))))
            .collect::<Vec<_>>();
        attempt
            .control
            .cpus
            .begin_execution(
                RequestId(0),
                request,
                CpuCommandKind::InstallExecution,
                &inputs,
                &attempt.vcpus_handles,
                Some(native),
            )
            .map_err(|error| error.to_string())?;
        attempt.wait_execution_command(request)?;
        attempt
            .mmio_device_manager
            .quiescence
            .install_legacy(&saved.legacy)?;
        install_devices(&mut attempt, request, &devices)?;
        attempt
            .mmio_device_manager
            .quiescence
            .register_legacy_events(events)?;
        for binding in &devices.devices {
            if let Some(subscriber) = &binding.subscriber {
                events.add_subscriber(subscriber.clone()).map_err(|error| {
                    format!("restore callback {:?}: {error:?}", binding.identity)
                })?;
            }
        }
        #[cfg(target_os = "linux")]
        {
            for route in &saved.irq_routes {
                if saved.lane == ExecutionLane::KvmX86
                    && route.gsi == 4
                    && route.members == [0x3f8]
                    && !saved.legacy.iter().any(|legacy| legacy.address == 0x3f8)
                {
                    attempt
                        .mmio_device_manager
                        .register_restored_irq(
                            attempt.vm.fd(),
                            4,
                            EventFd::new(EFD_NONBLOCK).map_err(|error| error.to_string())?,
                            0x3f8,
                        )
                        .map_err(|error| error.to_string())?;
                }
            }
            if attempt.mmio_device_manager.execution_irq_routes()? != saved.irq_routes {
                return Err("restored actual IRQ producer topology mismatch".into());
            }
        }
        #[cfg(target_os = "linux")]
        attempt
            .mmio_device_manager
            .begin_irq_fence(attempt.vm.fd_owner(), request)
            .map_err(|error| error.to_string())?;
        #[cfg(target_os = "macos")]
        attempt
            .mmio_device_manager
            .begin_irq_fence(request)
            .map_err(|error| error.to_string())?;
        loop {
            match attempt
                .mmio_device_manager
                .poll_irq_routes(request.key)
                .map_err(|error| error.to_string())?
            {
                std::task::Poll::Ready(()) => break,
                std::task::Poll::Pending => {
                    if Instant::now() >= deadline {
                        return Err("restore IRQ fencing deadline".into());
                    }
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
            }
        }
        attempt.execution.retained = Some(RetainedCut {
            key: request.key,
            vm: saved.vm.clone(),
            cpus: saved.cpus.clone(),
            legacy: saved.legacy.clone(),
        });
        attempt.execution.binding = Some(saved.binding.clone());
        attempt.execution.envelope = Some(Arc::new(saved.clone()));
        while !attempt
            .finish_memory_cut(request.key)
            .map_err(|error| error.to_string())?
        {
            if Instant::now() >= deadline {
                return Err("restore native writer drain deadline".into());
            }
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        attempt
            .memory
            .observe_restore_install_complete()
            .map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    })();
    if let Err(error) = install_result {
        attempt.execution.failed_install = true;
        attempt.control.state = crate::vmm::control::ControlState::FailedFenced;
        return Err(RestoreFailure {
            error,
            attempt: Some(Box::new(attempt)),
        });
    }
    attempt.control.state = crate::vmm::control::ControlState::RestorePrepared { key: request.key };
    Ok(attempt)
}

fn validate_legacy_bindings(
    saved: &crate::vmm::execution::ExecutionEnvelope,
    devices: &PreparedDeviceInstall,
) -> Result<(), String> {
    use devices::legacy::state::LegacyPayload;
    for legacy in &saved.legacy {
        let shape = match &legacy.payload {
            LegacyPayload::Uart(state) => Some((state.has_input, state.has_output)),
            LegacyPayload::Pl011(state) => Some((state.has_input, state.has_output)),
            _ => None,
        };
        if let Some((input, output)) = shape
            && (input || output)
        {
            let resource = devices
                .serial
                .iter()
                .find(|(address, _)| *address == legacy.address)
                .ok_or_else(|| {
                    format!("missing destination UART resource at {:#x}", legacy.address)
                })?;
            let device = resource.1.try_lock().map_err(|_| "UART destination lock")?;
            #[cfg(target_arch = "x86_64")]
            let current = device.capture_state().map_err(|error| error.to_string())?;
            #[cfg(target_arch = "aarch64")]
            let current = device.capture_state().map_err(|error| error.to_string())?;
            if (current.has_input, current.has_output) != (input, output) {
                return Err("destination UART endpoint shape".into());
            }
        }
        if matches!(legacy.payload, LegacyPayload::Gpio(_)) && devices.shutdown.is_none() {
            return Err("missing destination GPIO shutdown binding".into());
        }
    }
    for (address, _) in &devices.serial {
        if !saved.legacy.iter().any(|legacy| {
            legacy.address == *address
                && matches!(
                    legacy.payload,
                    LegacyPayload::Uart(_) | LegacyPayload::Pl011(_)
                )
        }) {
            return Err("extra destination UART binding".into());
        }
    }
    Ok(())
}

fn install_legacy_resources(
    vm: &Vm,
    manager: &mut MMIODeviceManager,
    io_bus: &mut devices::Bus,
    controller: &IrqChip,
    exit: &EventFd,
    saved: &crate::vmm::execution::ExecutionEnvelope,
    bindings: &mut PreparedDeviceInstall,
) -> Result<(), String> {
    use crate::vmm::device_manager::quiescence::{LegacyAttachment, LegacyHandle, LegacyKind};
    use devices::legacy::state::LegacyPayload;
    for state in &saved.legacy {
        let event = EventFd::new(EFD_NONBLOCK).map_err(|error| error.to_string())?;
        let (kind, handle) = match &state.payload {
            LegacyPayload::Uart(_) | LegacyPayload::Pl011(_) => {
                let serial = if let Some(index) = bindings
                    .serial
                    .iter()
                    .position(|(address, _)| *address == state.address)
                {
                    bindings.serial.remove(index).1
                } else {
                    Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                        event.try_clone().map_err(|error| error.to_string())?,
                    )))
                };
                #[cfg(target_arch = "aarch64")]
                {
                    let mut device = serial.try_lock().map_err(|_| "UART lock")?;
                    device.set_intc(controller.clone());
                    device.set_irq_line(state.irq.ok_or("UART IRQ missing")?);
                }
                #[cfg(target_arch = "x86_64")]
                io_bus
                    .insert(serial.clone(), state.address, 8)
                    .map_err(|error| format!("UART bus: {error:?}"))?;
                #[cfg(target_arch = "aarch64")]
                manager
                    .bus
                    .insert(serial.clone(), state.address, 4096)
                    .map_err(|error| format!("UART bus: {error:?}"))?;
                (LegacyKind::Serial, LegacyHandle::Serial(serial))
            }
            #[cfg(target_arch = "x86_64")]
            LegacyPayload::Cmos(_) => {
                let cmos = Arc::new(Mutex::new(devices::legacy::Cmos::new(0, 0)));
                io_bus
                    .insert(cmos.clone(), state.address, 8)
                    .map_err(|error| format!("CMOS bus: {error:?}"))?;
                (LegacyKind::Cmos, LegacyHandle::Cmos(cmos))
            }
            #[cfg(target_arch = "x86_64")]
            LegacyPayload::I8042(_) => {
                let keyboard = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
                    exit.try_clone().map_err(|error| error.to_string())?,
                    event.try_clone().map_err(|error| error.to_string())?,
                )));
                io_bus
                    .insert(keyboard.clone(), state.address, 5)
                    .map_err(|error| format!("i8042 bus: {error:?}"))?;
                (LegacyKind::I8042, LegacyHandle::I8042(keyboard))
            }
            #[cfg(target_arch = "aarch64")]
            LegacyPayload::Rtc(_) => {
                let rtc = Arc::new(Mutex::new(devices::legacy::RTC::new(
                    event.try_clone().map_err(|error| error.to_string())?,
                )));
                manager
                    .bus
                    .insert(rtc.clone(), state.address, 4096)
                    .map_err(|error| format!("RTC bus: {error:?}"))?;
                (LegacyKind::Rtc, LegacyHandle::Rtc(rtc))
            }
            #[cfg(target_arch = "aarch64")]
            LegacyPayload::Gpio(_) => {
                let gpio = Arc::new(Mutex::new(devices::legacy::Gpio::new(
                    bindings
                        .shutdown
                        .take()
                        .ok_or("GPIO shutdown binding missing")?,
                    event.try_clone().map_err(|error| error.to_string())?,
                )));
                {
                    let mut device = gpio.try_lock().map_err(|_| "GPIO lock")?;
                    device.set_intc(controller.clone());
                    device.set_irq_line(state.irq.ok_or("GPIO IRQ missing")?);
                }
                manager
                    .bus
                    .insert(gpio.clone(), state.address, 4096)
                    .map_err(|error| format!("GPIO bus: {error:?}"))?;
                (LegacyKind::Gpio, LegacyHandle::Gpio(gpio))
            }
            _ => return Err("legacy architecture mismatch".into()),
        };
        #[cfg(target_os = "linux")]
        if let Some(irq) = state.irq {
            let actual_event = match &handle {
                LegacyHandle::Serial(serial) => serial
                    .try_lock()
                    .map_err(|_| "UART lock")?
                    .interrupt_evt()
                    .try_clone()
                    .map_err(|error| error.to_string())?,
                _ => event,
            };
            manager
                .register_restored_irq(vm.fd(), irq, actual_event, state.address)
                .map_err(|error| error.to_string())?;
        }
        manager.quiescence.retain_legacy_device(
            LegacyAttachment {
                kind,
                address: state.address,
                irq: state.irq,
            },
            handle,
        );
    }
    let _ = (vm, controller, exit, io_bus);
    Ok(())
}

/// Construct transport mappings and native notification bindings without applying saved payloads.
fn attach_device_resources(
    attempt: &mut Vmm,
    bindings: &PreparedDeviceInstall,
) -> Result<(), String> {
    for binding in &bindings.devices {
        attempt
            .mmio_device_manager
            .set_restore_position(binding.identity.address, binding.identity.irq)
            .map_err(|error| error.to_string())?;
        crate::vmm::builder::attach_mmio_device(
            attempt,
            binding.identity.configured_id.clone(),
            attempt.execution_controller.clone(),
            binding.resource.clone(),
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn install_devices(
    attempt: &mut Vmm,
    request: BarrierRequest,
    bindings: &PreparedDeviceInstall,
) -> Result<(), String> {
    attempt
        .mmio_device_manager
        .quiescence
        .prepare_restore(request, &bindings.devices)
}

#[cfg(all(
    feature = "native-execution-probe",
    target_os = "linux",
    target_arch = "x86_64"
))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_execution_fixture(
    memory: GuestMemoryMmap,
    info: ArchMemoryInfo,
    count: u8,
    entry: u64,
    offline_ap: bool,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    deadline: Instant,
) -> Result<Vmm, String> {
    if count == 0 || Instant::now() >= deadline {
        return Err("invalid diagnostic CPU topology/deadline".into());
    }
    let mut vm = setup_vm(&memory, false).map_err(|error| error.to_string())?;
    let (memory_domain, authority, memory_control) = arch::guest_memory::MemoryDomain::construct(
        memory.clone(),
        crate::vmm::execution::host_page_granule().map_err(|error| error.to_string())?,
        arch::guest_memory::BackingKind::Boot,
    )
    .map_err(|error| error.to_string())?;
    vm.bind_memory_domain(memory_domain.clone())
        .map_err(|error| error.to_string())?;
    let memory_coordinator = crate::vmm::memory::MemoryCoordinator::new(memory_control, authority);
    let controller = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(
        devices::legacy::KvmIoapic::new(vm.fd()).map_err(|error| error.to_string())?,
    ))));
    let exit = EventFd::new(EFD_NONBLOCK).map_err(|error| error.to_string())?;
    let mut base = arch::MMIO_MEM_START;
    let mut manager = MMIODeviceManager::new(&mut base, (arch::IRQ_BASE, arch::IRQ_MAX));
    manager.bus = mmio_bus;
    let mut cpus = Vec::with_capacity(usize::from(count));
    for id in 0..count {
        let mut cpu = Vcpu::new_x86_64(
            id,
            vm.fd_owner(),
            vm.supported_cpuid().clone(),
            vm.supported_msrs().clone(),
            io_bus.clone(),
            exit.try_clone().map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        cpu.configure_execution_fixture(entry, offline_ap && id != 0, count)?;
        cpus.push(cpu);
    }
    let mut attempt = assemble(
        info,
        vm,
        controller,
        manager,
        exit,
        BarrierGeneration(0),
        memory_coordinator,
    )?;
    attempt
        .finalize_source_memory(true)
        .map_err(|error| error.to_string())?;
    attempt.reclaim_observer = Some(devices::virtio::balloon::ReclaimObserver::for_domain(
        &attempt.memory_domain,
    ));
    attempt
        .start_vcpus_parked(cpus)
        .map_err(|error| error.to_string())?;
    Ok(attempt)
}
