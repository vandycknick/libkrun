//! Explicit standalone production-kernel driver. RAM transfer is bounded gate
//! machinery, not the delivered RAM image or public capture API.
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, TryLockError};
use std::task::Poll;
use std::time::{Duration, Instant};

use devices::legacy::{Serial, state::LegacyPayload};
use devices::virtio::block::{Block, CacheType, DiskFormat, SyncMode};
use devices::virtio::lifecycle::ProviderFault;
use devices::virtio::vsock::TsiFlags;
use devices::virtio::{Balloon, Console, Net, PortDescription, Rng, VirtioDevice, Vsock, port_io};
use polly::event_manager::{
    BarrierKey, BarrierRequest, DispatchRole, EventManager, OperationId, Subscriber,
};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::api::capabilities::execution_state_producer;
use crate::api::device_builders::{AttachContext, AttachDevice, MmioDeviceManager};
use crate::api::error::VmmError;
use crate::api::payload::{KernelFormat, Payload};
use crate::api::vmm_builder::{VmmBuilder, VmmInner};
use crate::vmm::Vmm;
use crate::vmm::builder::restore::build_restore_prepared;
use crate::vmm::control::{ControlReply, PauseOwner, PauseToken, RequestId, RequestKind};
use crate::vmm::device_manager::quiescence::ManagerFault;
use crate::vmm::execution::device_restore::{
    DeviceEnvelope, RestoreDeviceBinding, ValidatedDevices,
};
use crate::vmm::execution::runtime::KvmCaptureProfile;
use crate::vmm::execution::{ExecutionEnvelope, ExecutionLane, StateBinding, ValidatedExecution};
#[cfg(feature = "native-device-probe")]
use crate::vmm::vstate::NativeRunObserver;

#[cfg(feature = "native-device-probe")]
#[derive(Debug)]
struct NativeRunObservation {
    cpu_id: u8,
    attempts: Result<u64, String>,
}

#[cfg(feature = "native-device-probe")]
fn observe_native_runs(observers: &[NativeRunObserver]) -> Vec<NativeRunObservation> {
    observers
        .iter()
        .map(|observer| NativeRunObservation {
            cpu_id: observer.cpu_id(),
            attempts: observer.attempts(),
        })
        .collect()
}

#[cfg(feature = "native-device-probe")]
fn native_run_coverage(expected: &[u8], observed: &[NativeRunObservation]) -> bool {
    !expected.is_empty()
        && expected.len() == observed.len()
        && expected
            .iter()
            .zip(observed)
            .all(|(id, observation)| *id == observation.cpu_id)
}

#[cfg(feature = "native-device-probe")]
fn native_runs_zero(expected: &[u8], observed: &[NativeRunObservation]) -> bool {
    native_run_coverage(expected, observed)
        && observed
            .iter()
            .all(|observation| matches!(&observation.attempts, Ok(0)))
}

#[cfg(feature = "native-device-probe")]
fn append_native_run_observations(
    output: &mut String,
    observed: &[NativeRunObservation],
) -> Result<(), String> {
    use std::fmt::Write as FmtWrite;
    output.push('[');
    for (index, observation) in observed.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        match &observation.attempts {
            Ok(attempts) => write!(
                output,
                "{{\"cpu_id\":{},\"attempts\":{attempts},\"observed\":true}}",
                observation.cpu_id
            ),
            Err(_) => write!(
                output,
                "{{\"cpu_id\":{},\"attempts\":null,\"observed\":false}}",
                observation.cpu_id
            ),
        }
        .map_err(|error| error.to_string())?;
    }
    output.push(']');
    Ok(())
}

const WAIT: Duration = Duration::from_secs(5);
const MAX_RAM: u64 = 1024 * 1024 * 1024;

#[cfg(feature = "native-device-probe")]
#[path = "native_device_witness.rs"]
mod witness;

#[cfg(feature = "native-device-probe")]
#[path = "native_device_pressure.rs"]
mod pressure;

#[derive(Clone)]
struct Resource {
    id: String,
    device: Arc<Mutex<dyn VirtioDevice>>,
    subscriber: Option<Arc<Mutex<dyn Subscriber + Send>>>,
}
impl<'a> AttachDevice<'a> for Resource {
    fn attach(self: Box<Self>, context: &mut AttachContext) -> Result<(), VmmError> {
        let device = self
            .device
            .try_lock()
            .map_err(|_| VmmError::Internal("console attachment lock".into()))?;
        if let Some(console) = (*device).as_any().downcast_ref::<Console>() {
            context.register_sigwinch(console.get_sigwinch_fd())?;
        }
        drop(device);
        if let Some(subscriber) = &self.subscriber {
            context.subscribe_events(subscriber.clone())?;
        }
        context.register(&self.id, self.device.clone())
    }
}

struct Driver {
    vmm: Arc<Mutex<Vmm>>,
    events: EventManager,
    _worker: Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>>,
    operation: u64,
    token: Option<PauseToken>,
    stopped: bool,
    #[cfg(feature = "native-device-probe")]
    witness: Arc<witness::Witness>,
    #[cfg(feature = "native-device-probe")]
    witness_source: bool,
}
impl Driver {
    fn poll(&mut self) -> Result<(), String> {
        self.poll_control()?;
        self.events
            .run_with_timeout(1)
            .map_err(|error| format!("{error:?}"))?;
        self.poll_control()
    }
    fn poll_control(&mut self) -> Result<(), String> {
        match self.vmm.try_lock() {
            Ok(mut vmm) => vmm.service_control(&mut self.events),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Poisoned(_)) => return Err("driver VMM lock poisoned".into()),
        }
        Ok(())
    }
    fn call(&mut self, kind: RequestKind) -> Result<ControlReply, String> {
        self.operation = self
            .operation
            .checked_add(1)
            .ok_or("driver operation exhausted")?;
        let operation = OperationId(self.operation);
        let deadline = Instant::now() + WAIT;
        let client = self
            .vmm
            .try_lock()
            .map_err(|_| "driver VMM lock")?
            .control
            .client
            .clone();
        std::thread::scope(|scope| {
            let call = scope.spawn(move || client.call(operation, deadline, kind));
            while !call.is_finished() {
                self.poll()?;
                #[cfg(feature = "native-device-probe")]
                self.witness.release_accepted_park(self)?;
            }
            call.join()
                .map_err(|_| "driver control caller panicked")?
                .map_err(|error| error.to_string())
        })
    }
    fn refuse(mut self, reason: &str) -> Result<(), String> {
        let cleanup = self.stop();
        if cleanup.is_err() {
            std::mem::forget(self);
        }
        Err(format!("{reason}; cleanup={cleanup:?}"))
    }
    fn stop(&mut self) -> Result<(), String> {
        #[cfg(feature = "native-device-probe")]
        self.witness.release();
        self.operation = self
            .operation
            .checked_add(1)
            .ok_or("driver operation exhausted")?;
        let generation = {
            let vmm = self.vmm.try_lock().map_err(|_| "driver VMM lock")?;
            vmm.execution
                .retained
                .as_ref()
                .map(|cut| cut.key.generation)
                .or_else(|| {
                    vmm.control
                        .cpus
                        .active_request()
                        .map(|(_, barrier, _)| barrier.key.generation)
                })
                .unwrap_or(polly::event_manager::BarrierGeneration(0))
        };
        let barrier = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(self.operation),
                generation,
            },
            deadline: Instant::now() + WAIT,
        };
        self.events
            .fail_closed(barrier)
            .map_err(|error| format!("{error:?}"))?;
        loop {
            let result = self
                .vmm
                .try_lock()
                .map_err(|_| "driver VMM lock")?
                .stop_execution_attempt(RequestId(u64::MAX - 1), barrier);
            match result {
                Poll::Ready(result) => {
                    result?;
                    self.stopped = true;
                    return Ok(());
                }
                Poll::Pending if Instant::now() < barrier.deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Poll::Pending => return Err("driver stop deadline; real owners retained".into()),
            }
        }
    }
    fn pause(&mut self) -> Result<(), String> {
        match self.call(RequestKind::Pause(PauseOwner::Capture))? {
            ControlReply::Paused(token) => {
                self.token = Some(token);
                Ok(())
            }
            _ => Err("pause returned wrong reply".into()),
        }
    }
    fn capture(
        &mut self,
        directory: &Path,
        binding: StateBinding,
        profile: &KvmCaptureProfile,
        disks: [&Path; 2],
    ) -> Result<(), String> {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|error| error.to_string())?;
        let mut vmm = self.vmm.try_lock().map_err(|_| "driver VMM lock")?;
        let active = vmm
            .control
            .active
            .as_ref()
            .ok_or("capture without retained whole-machine pause")?;
        let barrier = active.barrier;
        let request = active.request.id;
        vmm.flush_devices_for_capture(barrier.key)?;
        for (index, source) in disks.into_iter().enumerate() {
            let destination = directory.join(format!("disk{index}.raw"));
            let mut input = File::open(source).map_err(|error| error.to_string())?;
            if !input
                .metadata()
                .map_err(|error| error.to_string())?
                .is_file()
            {
                return Err("standalone disk capture requires regular raw files".into());
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(destination)
                .map_err(|error| error.to_string())?;
            std::io::copy(&mut input, &mut output).map_err(|error| error.to_string())?;
            output.sync_all().map_err(|error| error.to_string())?;
        }
        vmm.begin_execution_capture(request, barrier, binding, profile, false)?;
        let execution = match vmm.poll_execution_capture() {
            Poll::Ready(result) => result?,
            Poll::Pending => {
                return Err("completed pause did not retain completed execution cut".into());
            }
        };
        let retained = vmm
            .execution
            .retained
            .as_ref()
            .ok_or("captured envelope lacks retained native cut")?;
        if execution.vm != retained.vm
            || execution.cpus != retained.cpus
            || execution.legacy != retained.legacy
        {
            return Err(
                "captured execution envelope differs from current retained native state".into(),
            );
        }
        let devices = vmm.captured_devices()?;
        write_new(
            &directory.join("execution.state"),
            &execution.encode().map_err(|error| error.to_string())?,
        )?;
        write_new(
            &directory.join("devices.state"),
            &devices.encode().map_err(|error| error.to_string())?,
        )?;
        transfer_ram(
            &vmm.guest_memory,
            &execution,
            &directory.join("memory.ram"),
            false,
        )?;
        Ok(())
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}
fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("invalid bounded input".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err("input grew past bound".into());
    }
    Ok(bytes)
}
fn fixed<const N: usize>(directory: &Path, name: &str) -> Result<[u8; N], String> {
    bounded(&directory.join(name), N)?
        .try_into()
        .map_err(|_| format!("binding {name} must contain {N} raw bytes"))
}
fn binding(directory: &Path, generation: u64) -> Result<StateBinding, String> {
    Ok(StateBinding {
        native_producer: execution_state_producer()?,
        silo_producer: fixed(directory, "silo-producer")?,
        profile: fixed(directory, "profile")?,
        topology: fixed(directory, "topology")?,
        ram_layout: fixed(directory, "ram-layout")?,
        source_run: fixed(directory, "source-run")?,
        capture: fixed(directory, "capture")?,
        pause_generation: generation,
    })
}
fn transfer_ram(
    memory: &GuestMemoryMmap,
    execution: &ExecutionEnvelope,
    path: &Path,
    restore: bool,
) -> Result<(), String> {
    let total = execution
        .memory_regions
        .iter()
        .try_fold(0u64, |total, region| total.checked_add(region.byte_len()))
        .ok_or("RAM size overflow")?;
    if total > MAX_RAM {
        return Err("standalone RAM transfer exceeds 1GiB fixture bound".into());
    }
    let mut file = if restore {
        File::open(path)
    } else {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    .map_err(|error| error.to_string())?;
    if restore && file.metadata().map_err(|error| error.to_string())?.len() != total {
        return Err("standalone RAM length mismatch".into());
    }
    let mut chunk = vec![0u8; 1024 * 1024];
    for region in &execution.memory_regions {
        let mut offset = 0;
        while offset < region.byte_len() {
            let length = (region.byte_len() - offset).min(chunk.len() as u64) as usize;
            let address = GuestAddress(region.start() + offset);
            if restore {
                file.read_exact(&mut chunk[..length])
                    .map_err(|error| error.to_string())?;
                memory
                    .write_slice(&chunk[..length], address)
                    .map_err(|error| error.to_string())?;
            } else {
                memory
                    .read_slice(&mut chunk[..length], address)
                    .map_err(|error| error.to_string())?;
                file.write_all(&chunk[..length])
                    .map_err(|error| error.to_string())?;
            }
            offset += length as u64;
        }
    }
    if !restore {
        file.sync_all().map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn resource<T: VirtioDevice + Subscriber + 'static>(id: &str, device: T) -> Resource {
    let device = Arc::new(Mutex::new(device));
    Resource {
        id: id.into(),
        device: device.clone(),
        subscriber: Some(device),
    }
}
fn owned_fd(arguments: &BTreeMap<String, String>, key: &str) -> Result<OwnedFd, String> {
    let fd = argument(arguments, key)?
        .parse::<i32>()
        .map_err(|_| format!("invalid inherited {key}"))?;
    if fd < 3 {
        return Err(format!(
            "{key} must be a separately inherited owned descriptor"
        ));
    }
    // The standalone controller transfers ownership of each distinct inherited fd.
    // F_GETFD validates it before constructing the owning wrapper.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD)
        .map_err(|error| error.to_string())?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn argument<'a>(arguments: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    arguments
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing --{key}"))
}
fn resources(
    arguments: &BTreeMap<String, String>,
    saved: Option<&DeviceEnvelope>,
) -> Result<Vec<Resource>, String> {
    let mut result = Vec::new();
    let console_fd = owned_fd(arguments, "console-fd")?;
    let input_fd = owned_fd(arguments, "console-input-fd")?;
    let output_fd = owned_fd(arguments, "console-output-fd")?;
    let mut ports = Vec::new();
    for index in 0..4 {
        let input = if index == 0 || index == 1 {
            Some(
                port_io::input_to_raw_fd_dup(if index == 0 {
                    console_fd.as_raw_fd()
                } else {
                    input_fd.as_raw_fd()
                })
                .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        let output = if index == 0 || index == 2 {
            Some(
                port_io::output_to_raw_fd_dup(if index == 0 {
                    console_fd.as_raw_fd()
                } else {
                    output_fd.as_raw_fd()
                })
                .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        let terminal: Option<Box<dyn port_io::PortTerminalProperties>> = if index == 0 {
            Some(port_io::term_fd(console_fd.as_raw_fd()).map_err(|error| error.to_string())?)
        } else {
            None
        };
        let name = if index == 0 {
            String::new()
        } else {
            format!("probe{index}")
        };
        ports.push(PortDescription {
            name: Cow::Owned(name),
            input,
            output,
            terminal,
        });
    }
    result.push(resource(
        "hvc0",
        Console::new(ports).map_err(|error| format!("console: {error:?}"))?,
    ));
    for index in 0..(arch::IRQ_MAX - arch::IRQ_BASE) {
        result.push(resource(
            &format!("rng-line-padding-{index}"),
            Rng::new().map_err(|error| format!("IRQ padding RNG: {error:?}"))?,
        ));
    }
    for index in 0..2 {
        let id = format!("disk{index}");
        let disk = Block::new(
            id.clone(),
            None,
            CacheType::Writeback,
            argument(arguments, &id)?.into(),
            DiskFormat::Raw,
            false,
            false,
            SyncMode::Full,
        )
        .map_err(|error| error.to_string())?;
        result.push(Resource {
            id,
            device: Arc::new(Mutex::new(disk)),
            subscriber: None,
        });
    }
    let net_fd = owned_fd(arguments, "net-fd")?;
    let mac = [0x02, 0, 0, 0, 0, if saved.is_some() { 2 } else { 1 }];
    let features = (1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14);
    let net = if saved.is_some() {
        Net::new_restore_binding("net0".into(), net_fd, mac, features)
    } else if arguments
        .get("net-profile")
        .is_some_and(|profile| profile == "generic")
    {
        Net::new(
            "net0".into(),
            devices::virtio::net::device::VirtioNetBackend::UnixgramFd(net_fd.into_raw_fd()),
            mac,
            features,
        )
    } else {
        Net::new_managed("net0".into(), net_fd, mac, features)
    }
    .map_err(|error| format!("net: {error:?}"))?;
    result.push(Resource {
        id: "net0".into(),
        device: Arc::new(Mutex::new(net)),
        subscriber: None,
    });
    let mut vsock = Vsock::new(3, None, None, TsiFlags::empty())
        .map_err(|error| format!("vsock: {error:?}"))?;
    vsock
        .set_unix_mux_fd(owned_fd(arguments, "mux-fd")?)
        .map_err(|error| error.to_string())?;
    if saved.is_some() {
        vsock
            .bind_restore_control_service(1027)
            .map_err(|error| format!("control binding: {error:?}"))?;
    }
    result.push(resource("vsock0", vsock));
    let balloon = if let Some(saved) = saved {
        let offer = saved
            .records
            .iter()
            .find(|record| record.identity.configured_id == "balloon0")
            .ok_or("saved balloon resource missing")?
            .state
            .avail_features;
        Balloon::new_restore_binding(offer)
    } else {
        Balloon::new()
    }
    .map_err(|error| format!("balloon: {error:?}"))?;
    result.push(resource("balloon0", balloon));
    result.push(resource(
        "rng0",
        Rng::new().map_err(|error| format!("rng: {error:?}"))?,
    ));
    Ok(result)
}

fn cold(arguments: &BTreeMap<String, String>, resources: Vec<Resource>) -> Result<Driver, String> {
    let mut manager = MmioDeviceManager::new();
    for resource in resources {
        manager.add(resource);
    }
    let port = argument(arguments, "echo-port")?
        .parse::<u16>()
        .map_err(|_| "invalid echo-port")?;
    if port == 0 {
        return Err("echo-port cannot be zero".into());
    }
    let commandline = if arguments.contains_key("witness") {
        format!(
            "console=hvc0 rdinit=/init panic=-1 probe.echo_port={port} maxcpus=2 memmap=16M$448M memmap=64K$448K"
        )
    } else {
        format!("console=hvc0 rdinit=/init panic=-1 probe.echo_port={port}")
    };
    let payload = Payload::load_external(
        argument(arguments, "kernel")?,
        KernelFormat::Elf,
        Some(argument(arguments, "initramfs")?),
        &commandline,
    )
    .map_err(|error| error.to_string())?;
    let built = VmmBuilder::new()
        .vcpus(if arguments.contains_key("witness") {
            4
        } else {
            2
        })
        .map_err(|error| error.to_string())?
        .ram_mib(512)
        .map_err(|error| error.to_string())?
        .payload(payload)
        .devices(manager)
        .build()
        .map_err(|error| error.to_string())?;
    let VmmInner::Vmm {
        vmm,
        event_manager,
        _worker_sender,
    } = built.inner;
    Ok(Driver {
        vmm,
        events: event_manager,
        _worker: Some(_worker_sender),
        operation: 0,
        token: None,
        stopped: false,
        #[cfg(feature = "native-device-probe")]
        witness: Arc::default(),
        #[cfg(feature = "native-device-probe")]
        witness_source: true,
    })
}
fn restore(
    arguments: &BTreeMap<String, String>,
    saved: &DeviceEnvelope,
    resources: Vec<Resource>,
) -> Result<Driver, String> {
    let directory = Path::new(argument(arguments, "restore")?);
    let bytes = bounded(
        &directory.join("execution.state"),
        crate::vmm::execution::MAX_EXECUTION_BYTES,
    )?;
    let execution = ExecutionEnvelope::decode(&bytes).map_err(|error| error.to_string())?;
    let expected = binding(
        Path::new(argument(arguments, "binding")?),
        execution.binding.pause_generation,
    )?;
    let legacy_ids = execution
        .legacy
        .iter()
        .map(|state| (state.payload.tag(), state.address, state.irq))
        .collect::<Vec<_>>();
    let validated = ValidatedExecution::decode(
        &bytes,
        &expected,
        ExecutionLane::KvmX86,
        &execution.topology,
        &legacy_ids,
    )
    .map_err(|error| error.to_string())?;
    let devices =
        ValidatedDevices::validate(saved.clone(), &execution).map_err(|error| error.to_string())?;
    let ranges = execution
        .memory_regions
        .iter()
        .map(|region| {
            usize::try_from(region.byte_len())
                .map(|length| (GuestAddress(region.start()), length))
                .map_err(|_| "RAM length cannot fit host")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let total = execution
        .memory_regions
        .iter()
        .try_fold(0u64, |sum, region| sum.checked_add(region.byte_len()))
        .ok_or("RAM overflow")?;
    if total > MAX_RAM {
        return Err("standalone RAM exceeds fixture bound".into());
    }
    let memory = GuestMemoryMmap::from_ranges(&ranges).map_err(|error| error.to_string())?;
    transfer_ram(&memory, &execution, &directory.join("memory.ram"), true)?;
    let mut bindings = Vec::new();
    for record in &saved.records {
        let resource = resources
            .iter()
            .find(|resource| resource.id == record.identity.configured_id)
            .ok_or("destination resource missing")?;
        bindings.push(RestoreDeviceBinding {
            identity: record.identity.clone(),
            state: record.state.clone(),
            payload: record.payload.clone(),
            resource: resource.device.clone(),
            subscriber: resource.subscriber.clone(),
        });
    }
    let mut serial = Vec::new();
    for state in &execution.legacy {
        if let LegacyPayload::Uart(uart) = &state.payload {
            if uart.has_input || uart.has_output {
                return Err(
                    "standalone driver requires explicit endpoint bindings for non-sink UART"
                        .into(),
                );
            }
            serial.push((
                state.address,
                Arc::new(Mutex::new(Serial::new_sink(
                    EventFd::new(EFD_NONBLOCK).map_err(|error| error.to_string())?,
                ))),
            ));
        }
    }
    #[allow(unused_mut)]
    let mut prepared = devices.prepare(bindings, serial, None)?;
    #[cfg(feature = "native-device-probe")]
    if options_partial(arguments) {
        prepared.hold_device_probe_install_ack(2)?;
    }
    let install_wait = if options_partial(arguments) {
        Duration::from_millis(200)
    } else {
        WAIT
    };
    let mut events = EventManager::new().map_err(|error| format!("{error:?}"))?;
    #[cfg(feature = "native-device-probe")]
    let observed_memory = memory.clone();
    let vmm = match build_restore_prepared(
        memory,
        arch::ArchMemoryInfo::default(),
        validated,
        prepared,
        &mut events,
        Instant::now() + install_wait,
    ) {
        Ok(vmm) => vmm,
        Err(mut failure) => {
            if let Some(attempt) = failure.attempt.take() {
                let released = attempt.control.cpus.release_may_have_run();
                #[cfg(feature = "native-device-probe")]
                let partial_runs = if options_partial(arguments) {
                    Some((
                        execution
                            .cpus
                            .iter()
                            .map(|cpu| cpu.id())
                            .collect::<Vec<_>>(),
                        attempt
                            .vcpus_handles
                            .iter()
                            .map(|owner| owner.native_run_observer())
                            .collect::<Vec<_>>(),
                    ))
                } else {
                    None
                };
                #[cfg(feature = "native-device-probe")]
                let runs_before = partial_runs
                    .as_ref()
                    .map(|(_, observers)| observe_native_runs(observers));
                #[cfg(feature = "native-device-probe")]
                let partial = if options_partial(arguments) {
                    Some((|| -> Result<(bool, String, String), String> {
                        let ack = attempt
                            .vcpus_handles
                            .get(2)
                            .ok_or("partial witness owner missing")?
                            .probe_held_ack()?
                            .ok_or("actual Installed ACK not retained")?;
                        let cpu_correct = ack.cpu_id == 2;
                        let kind_correct = ack.kind == crate::vmm::control::CpuAckKind::Installed;
                        let install_succeeded = ack.result.is_ok();
                        let unreconciled = !attempt.control.cpus.reconciled();
                        let ram_comparison = ram_difference(
                            &observed_memory,
                            &execution.memory_regions,
                            &directory.join("memory.ram"),
                        );
                        let unchanged = matches!(&ram_comparison, Ok(None));
                        let ack_retained = cpu_correct && kind_correct && install_succeeded;
                        let valid =
                            ack_retained && unreconciled && ram_comparison.is_ok() && !released;
                        let difference = match &ram_comparison {
                            Ok(Some(difference)) => difference.as_str(),
                            _ => "null",
                        };
                        let components = format!(
                            "\"installed_ack_cpu_correct\":{cpu_correct},\"installed_ack_kind_correct\":{kind_correct},\"installed_ack_succeeded\":{install_succeeded},\"cpu_batch_unreconciled\":{unreconciled},\"ram_comparison_succeeded\":{},\"ram_unchanged\":{unchanged},\"ram_first_difference\":{difference},\"actual_installed_ack_retained\":{ack_retained}",
                            ram_comparison.is_ok()
                        );
                        Ok((
                            valid,
                            format!(
                                "{ack:#?}\n{}\n{components}\nRAM comparison: {ram_comparison:?}\nrelease_may_have_run={released}\n",
                                failure.error
                            ),
                            components,
                        ))
                    })())
                } else {
                    None
                };
                let mut driver = Driver {
                    vmm: Arc::new(Mutex::new(*attempt)),
                    events,
                    _worker: None,
                    operation: 0,
                    token: None,
                    stopped: false,
                    #[cfg(feature = "native-device-probe")]
                    witness: Arc::default(),
                    #[cfg(feature = "native-device-probe")]
                    witness_source: false,
                };
                let cleanup = driver.stop();
                if let Err(error) = &cleanup {
                    let error = format!(
                        "restore: {}; release_may_have_run={released}; retained cleanup={error}",
                        failure.error
                    );
                    std::mem::forget(driver);
                    return Err(error);
                }
                #[cfg(feature = "native-device-probe")]
                if let Some(partial) = partial {
                    let output = Path::new(argument(arguments, "partial-install")?);
                    let partial_succeeded = partial.is_ok();
                    let (valid, mut observation, components) = match partial {
                        Ok(observation) => observation,
                        Err(error) => (
                            false,
                            format!("{}\npartial observation error: {error}\nrelease_may_have_run={released}\n", failure.error),
                            "\"installed_ack_cpu_correct\":null,\"installed_ack_kind_correct\":null,\"installed_ack_succeeded\":null,\"cpu_batch_unreconciled\":null,\"ram_comparison_succeeded\":null,\"ram_unchanged\":null,\"ram_first_difference\":null,\"actual_installed_ack_retained\":null".into(),
                        ),
                    };
                    let (expected_ids, observers) = partial_runs
                        .as_ref()
                        .ok_or("partial run observers absent")?;
                    let runs_before = runs_before
                        .as_ref()
                        .ok_or("partial pre-reap observations absent")?;
                    let runs_after = observe_native_runs(observers);
                    let coverage = native_run_coverage(expected_ids, runs_before)
                        && native_run_coverage(expected_ids, &runs_after);
                    let observations_succeeded = runs_before
                        .iter()
                        .chain(&runs_after)
                        .all(|observation| observation.attempts.is_ok());
                    let zero_entry = native_runs_zero(expected_ids, runs_before)
                        && native_runs_zero(expected_ids, &runs_after)
                        && !released;
                    let valid = valid && zero_entry;
                    {
                        use std::fmt::Write as FmtWrite;
                        write!(observation, "Expected CPU IDs: {expected_ids:?}\nNative KVM_RUN attempts before reap: {runs_before:#?}\nNative KVM_RUN attempts after reap: {runs_after:#?}\ncoverage={coverage}; observations_succeeded={observations_succeeded}; zero_first_instruction_proved={zero_entry}; cleanup={cleanup:?}\n")
                            .map_err(|error| error.to_string())?;
                    }
                    write_new(&output.with_extension("native.txt"), observation.as_bytes())?;
                    let status = if valid && cleanup.is_ok() {
                        "passed"
                    } else {
                        "failed"
                    };
                    let mut result = format!(
                        "{{\"schema\":\"native-device-partial-install-v1\",\"pid\":{},\"status\":\"{status}\",\"partial_observation_succeeded\":{partial_succeeded},\"release_may_have_run\":{released},\"all_reaped\":{},\"expected_cpu_ids\":{expected_ids:?},\"native_run_observers_complete\":{coverage},\"native_run_observations_succeeded\":{observations_succeeded},\"zero_first_instruction\":{zero_entry},{components},\"run_attempts_before_reap\":",
                        std::process::id(),
                        cleanup.is_ok()
                    );
                    append_native_run_observations(&mut result, runs_before)?;
                    result.push_str(",\"run_attempts_after_reap\":");
                    append_native_run_observations(&mut result, &runs_after)?;
                    result.push_str("}\n");
                    write_new(output, result.as_bytes())?;
                    if valid && cleanup.is_ok() {
                        return Err("OBSERVED_PARTIAL_REAPED".into());
                    }
                }
                let error = format!(
                    "restore: {}; release_may_have_run={released}; retained cleanup={cleanup:?}",
                    failure.error
                );
                return Err(error);
            }
            return Err(failure.error);
        }
    };
    let control_fd = vmm.control.receiver.as_raw_fd();
    let exit_fd = vmm.exit_evt.as_raw_fd();
    let vmm = Arc::new(Mutex::new(vmm));
    let registration = (|| {
        for resource in &resources {
            let device = resource
                .device
                .try_lock()
                .map_err(|_| "restored console lock")?;
            if let Some(console) = (*device).as_any().downcast_ref::<Console>() {
                crate::vmm::signal_handler::register_sigwinch_handler(console.get_sigwinch_fd())
                    .map_err(|error| error.to_string())?;
            }
        }
        events
            .register_with_role(
                control_fd,
                EpollEvent::new(EventSet::IN, control_fd as u64),
                vmm.clone(),
                DispatchRole::Control,
            )
            .map_err(|error| format!("{error:?}"))?;
        events
            .register_with_role(
                exit_fd,
                EpollEvent::new(EventSet::IN, exit_fd as u64),
                vmm.clone(),
                DispatchRole::Exit,
            )
            .map_err(|error| format!("{error:?}"))
    })();
    if let Err(error) = registration {
        let mut driver = Driver {
            vmm,
            events,
            _worker: None,
            operation: 0,
            token: None,
            stopped: false,
            #[cfg(feature = "native-device-probe")]
            witness: Arc::default(),
            #[cfg(feature = "native-device-probe")]
            witness_source: false,
        };
        let cleanup = driver.stop();
        let error = format!("restore callback registration: {error}; cleanup={cleanup:?}");
        if cleanup.is_err() {
            std::mem::forget(driver);
        }
        return Err(error);
    }
    Ok(Driver {
        vmm,
        events,
        _worker: None,
        operation: 0,
        token: None,
        stopped: false,
        #[cfg(feature = "native-device-probe")]
        witness: Arc::default(),
        #[cfg(feature = "native-device-probe")]
        witness_source: false,
    })
}

fn options_partial(arguments: &BTreeMap<String, String>) -> bool {
    arguments.contains_key("partial-install")
}

#[cfg(feature = "native-device-probe")]
fn ram_difference(
    memory: &GuestMemoryMmap,
    regions: &[arch::guest_memory::GuestRange],
    path: &Path,
) -> Result<Option<String>, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut expected = vec![0u8; 1024 * 1024];
    let mut actual = vec![0u8; expected.len()];
    let mut file_offset = 0u64;
    for (region_index, region) in regions.iter().enumerate() {
        let mut offset = 0;
        while offset < region.byte_len() {
            let length = (region.byte_len() - offset).min(expected.len() as u64) as usize;
            file.read_exact(&mut expected[..length])
                .map_err(|error| error.to_string())?;
            memory
                .read_slice(&mut actual[..length], GuestAddress(region.start() + offset))
                .map_err(|error| error.to_string())?;
            if let Some(index) = actual[..length]
                .iter()
                .zip(&expected[..length])
                .position(|(actual, expected)| actual != expected)
            {
                let end = (index + 16).min(length);
                return Ok(Some(format!(
                    "{{\"region_index\":{region_index},\"region_offset\":{},\"gpa\":{},\"file_offset\":{},\"expected\":{:?},\"actual\":{:?}}}",
                    offset + index as u64,
                    region.start() + offset + index as u64,
                    file_offset + index as u64,
                    &expected[index..end],
                    &actual[index..end]
                )));
            }
            offset += length as u64;
            file_offset += length as u64;
        }
    }
    Ok(None)
}

/// The controller supplies real destination-owned sockets and ordinary Linux
/// workload inputs. Commands never claim an unobserved gate or grant a live bit.
pub fn run(arguments: Vec<OsString>) -> Result<(), String> {
    let mut options = BTreeMap::new();
    let mut arguments = arguments.into_iter();
    while let Some(key) = arguments.next() {
        let key = key.into_string().map_err(|_| "non-UTF8 option")?;
        let key = key
            .strip_prefix("--")
            .ok_or("expected --option value")?
            .to_owned();
        let value = arguments
            .next()
            .ok_or("option missing value")?
            .into_string()
            .map_err(|_| "non-UTF8 value")?;
        if options.insert(key, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    let fds = [
        "console-fd",
        "console-input-fd",
        "console-output-fd",
        "net-fd",
        "mux-fd",
    ]
    .into_iter()
    .map(|key| {
        argument(&options, key)?
            .parse::<i32>()
            .map_err(|_| format!("invalid inherited {key}"))
    })
    .collect::<Result<Vec<_>, _>>()?;
    if fds
        .iter()
        .enumerate()
        .any(|(index, fd)| *fd < 3 || fds[..index].contains(fd))
    {
        return Err("resource descriptors must be distinct inherited owned descriptors".into());
    }
    let saved = options
        .get("restore")
        .map(|directory| {
            let bytes = bounded(
                &Path::new(directory).join("devices.state"),
                32 * 1024 * 1024,
            )?;
            DeviceEnvelope::decode(&bytes).map_err(|error| error.to_string())
        })
        .transpose()?;
    let flags = nix::fcntl::fcntl(std::io::stdin(), nix::fcntl::FcntlArg::F_GETFL)
        .map_err(|error| error.to_string())?;
    nix::fcntl::fcntl(
        std::io::stdin(),
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .map_err(|error| error.to_string())?;
    let resources = resources(&options, saved.as_ref())?;
    let activation_resources = resources.clone();
    let built = if let Some(saved) = &saved {
        restore(&options, saved, resources)
    } else {
        cold(&options, resources)
    };
    let mut driver = match built {
        Err(error) if error == "OBSERVED_PARTIAL_REAPED" => {
            println!("PARTIAL_REAPED");
            return Ok(());
        }
        result => result?,
    };
    if options_partial(&options) {
        return driver.refuse("partial native install unexpectedly completed");
    }
    #[cfg(feature = "native-device-probe")]
    if let Err(error) = driver.witness.attach(&driver) {
        return driver.refuse(&format!("witness observation registration: {error}"));
    }
    #[cfg(not(feature = "native-device-probe"))]
    if options.contains_key("witness") {
        return driver.refuse("execution witnesses require diagnostic native-device-probe feature");
    }
    println!("READY whole-machine-production");
    let mut pending = Vec::new();
    let mut input = [0u8; 4096];
    let result = (|| {
        loop {
            driver.poll()?;
            match std::io::stdin().read(&mut input) {
                Ok(0) => return Err("controller EOF before explicit stop".into()),
                Ok(length) => pending.extend_from_slice(&input[..length]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }
            if pending.len() > 16384 {
                return Err("controller command exceeds bound".into());
            }
            while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let line = String::from_utf8(pending.drain(..=end).collect())
                    .map_err(|_| "controller UTF-8")?;
                let (command, operand) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
                let response: Result<bool, String> = (|| {
                    match command {
                        #[cfg(feature = "native-device-probe")]
                        command if command.starts_with("witness-") => {
                            driver
                                .witness
                                .clone()
                                .command(&mut driver, command, operand)?;
                        }
                        #[cfg(feature = "native-device-probe")]
                        "pressure" => {
                            pressure::command(&mut driver, &activation_resources, operand)?
                        }
                        "profile" => {
                            let profile = observed_profile(Path::new(operand))?;
                            driver
                                .vmm
                                .try_lock()
                                .map_err(|_| "driver lock")?
                                .execution
                                .profile = Some(profile);
                        }
                        "pause" => driver.pause()?,
                        "cancel" => {
                            let operation =
                                operand.parse::<u64>().map_err(|_| "cancel operation")?;
                            driver.call(RequestKind::CancelPause(OperationId(operation)))?;
                        }
                        "resume" => {
                            let token = driver.token.clone().ok_or("no source token")?;
                            driver.call(RequestKind::Resume(token))?;
                        }
                        "release" => {
                            driver.call(RequestKind::ReleaseRestore)?;
                        }
                        "activate" => {
                            driver.operation = driver
                                .operation
                                .checked_add(1)
                                .ok_or("operation exhausted")?;
                            let request = BarrierRequest {
                                key: BarrierKey {
                                    operation: OperationId(driver.operation),
                                    generation: polly::event_manager::BarrierGeneration(
                                        saved
                                            .as_ref()
                                            .ok_or("activation is destination-only")?
                                            .binding
                                            .pause_generation,
                                    ),
                                },
                                deadline: Instant::now() + WAIT,
                            };
                            let mut completed = vec![false; activation_resources.len()];
                            for (resource, completed) in
                                activation_resources.iter().zip(&mut completed)
                            {
                                loop {
                                    if Instant::now() >= request.deadline {
                                        return Err("activation release deadline".into());
                                    }
                                    let mut device = match resource.device.try_lock() {
                                        Ok(device) => device,
                                        Err(TryLockError::WouldBlock) => {
                                            driver.poll()?;
                                            continue;
                                        }
                                        Err(TryLockError::Poisoned(_)) => {
                                            return Err("activation resource lock poisoned".into());
                                        }
                                    };
                                    if !matches!(device.device_type(), 1 | 19) {
                                        *completed = true;
                                        break;
                                    }
                                    let provider = device
                                        .state_provider_mut()
                                        .ok_or("activation provider missing")?;
                                    match provider.begin_activation_release(request) {
                                        Ok(()) => break,
                                        Err(error)
                                            if !error.accepted
                                                && error.fault == ProviderFault::LockBusy =>
                                        {
                                            drop(device);
                                            driver.poll()?;
                                        }
                                        Err(error) => {
                                            return Err(format!(
                                                "activation begin: {:?} (accepted={})",
                                                error.fault, error.accepted
                                            ));
                                        }
                                    }
                                }
                            }
                            loop {
                                let mut pending = false;
                                for (resource, completed) in
                                    activation_resources.iter().zip(&mut completed)
                                {
                                    if *completed {
                                        continue;
                                    }
                                    if Instant::now() >= request.deadline {
                                        return Err("activation release deadline".into());
                                    }
                                    let mut device = match resource.device.try_lock() {
                                        Ok(device) => device,
                                        Err(TryLockError::WouldBlock) => {
                                            pending = true;
                                            continue;
                                        }
                                        Err(TryLockError::Poisoned(_)) => {
                                            return Err("activation resource lock poisoned".into());
                                        }
                                    };
                                    *completed = device
                                        .state_provider_mut()
                                        .ok_or("activation provider missing")?
                                        .poll_activation_release(request.key)
                                        .map_err(|error| format!("activation poll: {error:?}"))?
                                        .is_ready();
                                    pending |= !*completed;
                                }
                                if Instant::now() >= request.deadline {
                                    return Err("activation release deadline".into());
                                }
                                if !pending {
                                    break;
                                }
                                driver.poll()?;
                            }
                        }
                        "capture" => {
                            let (generation, profile) = {
                                let vmm = driver.vmm.try_lock().map_err(|_| "driver lock")?;
                                let generation = vmm
                                    .execution
                                    .retained
                                    .as_ref()
                                    .ok_or("cut absent")?
                                    .key
                                    .generation
                                    .0;
                                (
                                    generation,
                                    vmm.execution.profile.clone().ok_or("profile absent")?,
                                )
                            };
                            driver.capture(
                                Path::new(operand),
                                binding(Path::new(argument(&options, "binding")?), generation)?,
                                &profile,
                                [
                                    Path::new(argument(&options, "disk0")?),
                                    Path::new(argument(&options, "disk1")?),
                                ],
                            )?;
                        }
                        "status" => {
                            let deadline = Instant::now() + WAIT;
                            loop {
                                if Instant::now() >= deadline {
                                    return Err("status observation deadline expired".into());
                                }
                                let complete = (|| -> Result<bool, String> {
                                    let vmm = match driver.vmm.try_lock() {
                                        Ok(vmm) => vmm,
                                        Err(TryLockError::WouldBlock) => return Ok(false),
                                        Err(TryLockError::Poisoned(_)) => {
                                            return Err("status VMM lock poisoned".into());
                                        }
                                    };
                                    let snapshots = match vmm
                                        .mmio_device_manager
                                        .quiescence
                                        .lifecycle_snapshots()
                                    {
                                        Ok(snapshots) => snapshots,
                                        Err(error)
                                            if matches!(error.fault, ManagerFault::LockBusy) =>
                                        {
                                            return Ok(false);
                                        }
                                        Err(error) => return Err(error.to_string()),
                                    };
                                    let irqs = vmm.mmio_device_manager.execution_irq_routes()?;
                                    let control = &vmm.control.state;
                                    let request = vmm.control.cpus.active_request();
                                    let release = vmm.control.cpus.release_may_have_run();
                                    let time = vmm.execution.preparation_observation();
                                    if Instant::now() >= deadline {
                                        return Err("status observation deadline expired".into());
                                    }
                                    println!("CONTROL {control:?} {request:?}");
                                    println!("RELEASE_MAY_HAVE_RUN {release}");
                                    println!("TIME {time:?}");
                                    println!("IRQS {irqs:?}");
                                    for (identity, snapshot) in snapshots {
                                        println!("PARTICIPANT {identity:?} {snapshot:?}");
                                    }
                                    Ok(true)
                                })()?;
                                if complete {
                                    break;
                                }
                                if Instant::now() >= deadline {
                                    return Err("status observation deadline expired".into());
                                }
                                // The incomplete observation has dropped every guard.
                                driver.poll()?;
                            }
                        }
                        "preflight" => {
                            driver
                                .vmm
                                .try_lock()
                                .map_err(|_| "driver lock")?
                                .mmio_device_manager
                                .preflight_quiesce()
                                .map_err(|error| error.to_string())?;
                        }
                        "state" => {
                            let vmm = driver.vmm.try_lock().map_err(|_| "driver lock")?;
                            println!("STATE {:?}", vmm.control.state);
                            for record in vmm
                                .mmio_device_manager
                                .quiescence
                                .capture_devices(
                                    vmm.execution
                                        .retained
                                        .as_ref()
                                        .ok_or("state requires completed cut")?
                                        .key,
                                )
                                .map_err(|error| error.to_string())?
                            {
                                println!(
                                    "DEVICE {} {} {:#x} {:?} {} {:?}",
                                    record.identity.configured_id,
                                    record.state.device_type,
                                    record.identity.address,
                                    record.state.irq_line,
                                    record.state.interrupt_status,
                                    record.state.queues
                                );
                            }
                        }
                        "stop" => {
                            driver.stop()?;
                            return Ok(true);
                        }
                        _ => return Err(format!("unknown controller command {command}")),
                    }
                    Ok(false)
                })();
                match response {
                    Ok(true) => return Ok(()),
                    Ok(false) => println!("OK {command}"),
                    Err(error) => println!("ERROR {command} {error}"),
                }
                std::io::stdout()
                    .flush()
                    .map_err(|error| error.to_string())?;
            }
        }
    })();
    let cleanup = if driver.stopped {
        Ok(())
    } else {
        driver.stop()
    };
    if cleanup.is_err() {
        // A failed stop cannot free resources still owned by native/device threads.
        // The controller must terminate and reap this stopped/fenced process.
        std::mem::forget(driver);
    }
    result.and(cleanup)
}

fn observed_broadcast_uses_pit(device: &str, state: &str) -> Result<bool, String> {
    let fields = state
        .trim()
        .strip_prefix("path=/sys/devices/system/clockevents/broadcast/current_device\nread_complete=1\nbytes_read=")
        .and_then(|fields| fields.split_once("\nkind="))
        .ok_or("profile/broadcast-clockevent/incomplete-read-observation")?;
    let bytes = fields
        .0
        .parse::<usize>()
        .map_err(|_| "profile/broadcast-clockevent/invalid-read-length")?;
    match fields.1 {
        "no-device" if bytes == 0 && device == "\n" => Ok(false),
        "device"
            if bytes != 0
                && bytes.checked_add(1) == Some(device.len())
                && !device.trim().is_empty() =>
        {
            Ok(device.trim() == "pit")
        }
        _ => Err("profile/broadcast-clockevent/inconsistent-device-observation".into()),
    }
}

fn observed_profile(directory: &Path) -> Result<KvmCaptureProfile, String> {
    let text = |name: &str| -> Result<String, String> {
        String::from_utf8(bounded(&directory.join(name), 65536)?)
            .map_err(|_| "profile observation UTF-8".into())
    };
    let kernel_identity = text("kernel-identity")?;
    let clocksource = text("clocksource")?;
    let clockevents = text("clockevents")?;
    let broadcast = text("broadcast-clockevent")?;
    let speaker = text("speaker-consumers")?;
    let broadcast_uses_pit =
        observed_broadcast_uses_pit(&broadcast, &text("broadcast-clockevent-state")?)?;
    if kernel_identity.trim().is_empty() {
        return Err("profile/kernel-identity/empty".into());
    }
    if clocksource.trim() != "tsc" {
        return Err(format!(
            "profile/clocksource/not-tsc:{:?}",
            clocksource.trim()
        ));
    }
    if clockevents.lines().count() != 2
        || clockevents
            .lines()
            .any(|line| line.trim() != "lapic-deadline")
    {
        return Err(format!(
            "profile/clockevents/not-two-lapic-deadline:{clockevents:?}"
        ));
    }
    if broadcast_uses_pit {
        return Err("profile/broadcast-clockevent/pit-selected".into());
    }
    if !speaker.trim().is_empty() {
        return Err(format!("profile/speaker-consumers/active:{speaker:?}"));
    }
    Ok(KvmCaptureProfile::RetiredLinuxPit {
        kernel_identity,
        clocksource_tsc: true,
        all_online_clockevents_deadline: true,
        broadcast_uses_pit: false,
        speaker_or_counter_consumer: false,
    })
}

#[cfg(test)]
mod tests {
    use crate::api::vmm_builder::native_device_probe::observed_broadcast_uses_pit;

    #[test]
    fn device_profile_broadcast_requires_actual_complete_read() {
        let header = "path=/sys/devices/system/clockevents/broadcast/current_device\nread_complete=1\nbytes_read=";
        assert_eq!(
            observed_broadcast_uses_pit("\n", &format!("{header}0\nkind=no-device\n")),
            Ok(false)
        );
        assert!(observed_broadcast_uses_pit("\n", "").is_err());
        assert!(observed_broadcast_uses_pit("\n", &format!("{header}0\nkind=device\n")).is_err());
        assert!(
            observed_broadcast_uses_pit("\n", &format!("{header}1\nkind=no-device\n")).is_err()
        );
        assert!(
            observed_broadcast_uses_pit("pit\n\n", &format!("{header}0\nkind=no-device\n"))
                .is_err()
        );
        assert_eq!(
            observed_broadcast_uses_pit("pit\n\n", &format!("{header}4\nkind=device\n")),
            Ok(true)
        );
        assert_eq!(
            observed_broadcast_uses_pit("hrtimer\n\n", &format!("{header}8\nkind=device\n")),
            Ok(false)
        );
        assert!(
            observed_broadcast_uses_pit("hrtimer\n\n", &format!("{header}7\nkind=device\n"))
                .is_err()
        );
    }

    #[cfg(feature = "native-device-probe")]
    #[test]
    fn device_partial_ram_difference_retains_exact_region_and_bytes() {
        use crate::api::vmm_builder::native_device_probe::ram_difference;
        use arch::guest_memory::GuestRange;
        use std::fs::{OpenOptions, remove_file};
        use std::io::Write;
        use std::time::{SystemTime, UNIX_EPOCH};
        use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

        let memory = GuestMemoryMmap::<()>::from_ranges(&[
            (GuestAddress(0x1000), 4096),
            (GuestAddress(0x4000), 4096),
        ])
        .unwrap();
        let regions = [
            GuestRange::new(0x1000, 4096).unwrap(),
            GuestRange::new(0x4000, 4096).unwrap(),
        ];
        let bytes = [0xa5u8; 4096];
        memory.write_slice(&bytes, GuestAddress(0x1000)).unwrap();
        memory.write_slice(&bytes, GuestAddress(0x4000)).unwrap();
        let path = std::env::temp_dir().join(format!(
            "silo-partial-ram-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        let unchanged = ram_difference(&memory, &regions, &path);
        memory.write_slice(&[0x5a], GuestAddress(0x4fff)).unwrap();
        let difference = ram_difference(&memory, &regions, &path);
        memory.write_slice(&[0x5a], GuestAddress(0x1003)).unwrap();
        let bounded = ram_difference(&memory, &regions, &path);
        remove_file(path).unwrap();
        assert_eq!(unchanged, Ok(None));
        assert_eq!(difference, Ok(Some("{\"region_index\":1,\"region_offset\":4095,\"gpa\":20479,\"file_offset\":8191,\"expected\":[165],\"actual\":[90]}".into())));
        let expected = [0xa5u8; 16];
        let mut actual = expected;
        actual[0] = 0x5a;
        assert_eq!(
            bounded,
            Ok(Some(format!(
                "{{\"region_index\":0,\"region_offset\":3,\"gpa\":4099,\"file_offset\":3,\"expected\":{expected:?},\"actual\":{actual:?}}}"
            )))
        );
    }

    #[cfg(feature = "native-device-probe")]
    #[test]
    fn device_partial_run_proof_requires_every_expected_owner() {
        use crate::api::vmm_builder::native_device_probe::{
            NativeRunObservation, append_native_run_observations, native_runs_zero,
        };
        let expected = [0, 1];
        let mut observed = vec![
            NativeRunObservation {
                cpu_id: 0,
                attempts: Ok(0),
            },
            NativeRunObservation {
                cpu_id: 1,
                attempts: Ok(0),
            },
        ];
        assert!(native_runs_zero(&expected, &observed));
        observed[1].attempts = Ok(1);
        assert!(!native_runs_zero(&expected, &observed));
        observed[1].attempts = Err("unobservable".into());
        assert!(!native_runs_zero(&expected, &observed));
        let mut json = String::new();
        append_native_run_observations(&mut json, &observed).unwrap();
        assert_eq!(
            json,
            "[{\"cpu_id\":0,\"attempts\":0,\"observed\":true},{\"cpu_id\":1,\"attempts\":null,\"observed\":false}]"
        );
        observed[1].attempts = Ok(0);
        observed[1].cpu_id = 2;
        assert!(!native_runs_zero(&expected, &observed));
        observed.pop();
        assert!(!native_runs_zero(&expected, &observed));
        assert!(!native_runs_zero(&[], &[]));
    }
}
