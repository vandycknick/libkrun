//! Explicit standalone production-kernel driver over the native capture coordinator.
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

#[cfg(feature = "native-device-probe")]
use arch::guest_memory::{MemoryDomain, ReadGuestMemory};
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
#[cfg(feature = "native-device-probe")]
use vm_memory::GuestAddress;

use crate::api::capabilities::execution_state_producer;
use crate::api::device_builders::{
    AttachContext, AttachDevice, BalloonBinding, GenerationBinding, MmioDeviceManager,
};
use crate::api::error::VmmError;
use crate::api::payload::{KernelFormat, Payload};
use crate::api::vmm_builder::{VmmBuilder, VmmInner};
use crate::vmm::Vmm;
use crate::vmm::builder::restore::build_restore_prepared;
use crate::vmm::control::{ControlReply, PauseOwner, PauseToken, RequestId, RequestKind};
use crate::vmm::control::{GenerationAuthority, GenerationMode, GenerationTicket};
use crate::vmm::device_manager::quiescence::ManagerFault;
use crate::vmm::execution::device_restore::{
    DeviceEnvelope, RestoreDeviceBinding, ValidatedDevices,
};
use crate::vmm::execution::runtime::KvmCaptureProfile;
use crate::vmm::execution::{ExecutionEnvelope, ExecutionLane, StateBinding, ValidatedExecution};
use crate::vmm::memory::image::ValidatedRamLayout;
use crate::vmm::memory::image::{
    AuthenticatedRamImage, RamImageAuthentication, RamOutputFiles, map_restore_ram,
};
use crate::vmm::memory::{AttemptId, CompletedCandidate, DirtyCrossoverPercent, RamCaptureRequest};
#[cfg(feature = "native-device-probe")]
use crate::vmm::vstate::NativeRunObserver;
use devices::virtio::generation::{
    DEVICE_ID, Generation, GenerationFailure, GenerationObservation,
};

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

#[cfg(feature = "native-device-probe")]
fn diagnostic_memory_mappings(domain: &Arc<MemoryDomain>) -> Result<String, String> {
    use arch::guest_memory::BackingKind;
    use std::fmt::Write as FmtWrite;

    if domain.backing_kind() != BackingKind::RestoredPrivate {
        return Err("mapping evidence requires restored private RAM".into());
    }
    let layout = domain.layout();
    layout
        .validate_capture()
        .map_err(|error| error.to_string())?;
    let mut identities = domain.file_backing_identities();
    let mut output = format!(
        "{{\"schema\":1,\"native_pid\":{},\"packed_len\":{},\"regions\":[",
        std::process::id(),
        layout.packed_len()
    );
    for (index, region) in layout.regions().iter().enumerate() {
        let identity = identities
            .next()
            .ok_or("registered RAM region lacks retained file backing")?
            .map_err(|error| error.to_string())?;
        let range = region.guest_range();
        let length = usize::try_from(range.byte_len()).map_err(|error| error.to_string())?;
        let guard = domain
            .read(GuestAddress(range.start()), length)
            .map_err(|error| error.to_string())?;
        let host_start = guard
            .read_view(0, 1)
            .map_err(|error| error.to_string())?
            .as_ptr() as usize as u64;
        if !domain.matches_region_mapping(region.id(), host_start)
            || host_start.checked_add(range.byte_len()).is_none()
        {
            return Err("registered RAM mapping identity mismatch".into());
        }
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"gpa\":{},\"length\":{},\"stream_offset\":{},\"host_start\":{},\"device\":{},\"inode\":{}}}",
            range.start(),
            range.byte_len(),
            region.stream_offset(),
            host_start,
            identity.device,
            identity.inode,
        )
        .map_err(|error| error.to_string())?;
    }
    if identities.next().is_some() {
        return Err("file backing inventory exceeds registered RAM".into());
    }
    output.push_str("]}\n");
    Ok(output)
}

#[derive(Clone)]
struct Resource {
    id: String,
    device: Arc<Mutex<dyn VirtioDevice>>,
    subscriber: Option<Arc<Mutex<dyn Subscriber + Send>>>,
    balloon_binding: Option<BalloonBinding>,
    generation_binding: Option<GenerationBinding>,
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
        context.register(&self.id, self.device.clone())?;
        if let Some(binding) = self.balloon_binding {
            context.retain_balloon_binding(binding);
        }
        if let Some(binding) = self.generation_binding {
            context.retain_generation_binding(binding)?;
        }
        Ok(())
    }
}

struct MemoryCaptureOptions {
    full: bool,
    prepared: bool,
    fail_output: bool,
}

struct Driver {
    vmm: Arc<Mutex<Vmm>>,
    events: EventManager,
    _worker: Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>>,
    operation: u64,
    token: Option<PauseToken>,
    generation_ticket: Option<GenerationTicket>,
    stopped: bool,
    prepared_layout: Option<Arc<ValidatedRamLayout>>,
    memory_attempt: Option<AttemptId>,
    memory_candidate: Option<CompletedCandidate>,
    memory_directory: Option<std::path::PathBuf>,
    memory_prepared: bool,
    memory_stats: Option<Vec<u8>>,
    prepared_devices: Option<Arc<DeviceEnvelope>>,
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
        let command = match &kind {
            RequestKind::Resume(_) => Some("resume"),
            RequestKind::ReleaseRestore => Some("release"),
            _ => None,
        };
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
                .map_err(|error| {
                    if let Some(command) = command
                        && matches!(&error, crate::vmm::control::ControlFailure::Busy)
                    {
                        println!("MEMORY_COMMAND_FAILURE {{\"schema\":1,\"command\":\"{command}\",\"kind\":\"busy\"}}");
                    }
                    error.to_string()
                })
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
        self.vmm
            .try_lock()
            .map_err(|_| "driver VMM lock")?
            .fail_generation(GenerationFailure::Stopped);
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
        profile: Option<&KvmCaptureProfile>,
        disks: [&Path; 2],
        options: MemoryCaptureOptions,
    ) -> Result<(), String> {
        let MemoryCaptureOptions {
            full,
            prepared,
            fail_output,
        } = options;
        let mut vmm = self.vmm.try_lock().map_err(|_| "driver VMM lock")?;
        if self.memory_attempt.is_some() {
            return Err("memory candidate unresolved".into());
        }
        let layout = vmm.memory_layout().map_err(|error| error.to_string())?;
        if self
            .prepared_layout
            .as_ref()
            .is_none_or(|prepared| prepared.canonical_bytes() != layout.canonical_bytes())
        {
            return Err("capture requires exact canonical layout preparation".into());
        }
        if !prepared {
            let active = vmm
                .control
                .active
                .as_ref()
                .ok_or("capture without retained whole-machine pause")?;
            let barrier = active.barrier;
            let request = active.request.id;
            vmm.flush_devices_for_capture(barrier.key)?;
            vmm.begin_execution_capture(
                request,
                barrier,
                binding,
                profile.ok_or("capture profile absent")?,
                false,
            )?;
        }
        let execution = if prepared {
            vmm.execution
                .captured_envelope()
                .cloned()
                .ok_or("prepared execution envelope absent")?
        } else {
            match vmm.poll_execution_capture() {
                Poll::Ready(result) => result?,
                Poll::Pending => {
                    return Err("completed pause did not retain completed execution cut".into());
                }
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
        let devices = if prepared {
            self.prepared_devices
                .clone()
                .ok_or("prepared device envelope absent")?
        } else {
            vmm.captured_devices()?
        };
        #[cfg(feature = "native-device-probe")]
        let dirty = diagnostic_dirty_memory(&vmm, self.token.as_ref(), &execution)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|error| error.to_string())?;
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
        write_new(
            &directory.join("execution.state"),
            &execution.encode().map_err(|error| error.to_string())?,
        )?;
        write_new(
            &directory.join("devices.state"),
            &devices.encode().map_err(|error| error.to_string())?,
        )?;
        let token = vmm.baseline_token();
        let baseline_generation = token.as_ref().map(|token| token.memory_generation());
        let request = if full {
            RamCaptureRequest::Full
        } else {
            RamCaptureRequest::Incremental {
                baseline: token.as_ref(),
                crossover: DirtyCrossoverPercent::default(),
            }
        };
        #[cfg(feature = "native-device-probe")]
        let key = vmm
            .execution
            .retained
            .as_ref()
            .ok_or("memory cut absent")?
            .key;
        let attempt = if prepared {
            #[cfg(feature = "native-device-probe")]
            {
                vmm.diagnostic_begin_memory_capture(key, request)
            }
            #[cfg(not(feature = "native-device-probe"))]
            {
                return Err("prepared capture requires native-device-probe".into());
            }
        } else {
            vmm.begin_memory_capture(
                self.token
                    .as_ref()
                    .ok_or("capture without exact pause token")?,
                request,
            )
        }
        .map_err(|error| error.to_string())?;
        self.memory_attempt = Some(attempt.clone());
        self.memory_directory = Some(directory.to_path_buf());
        self.memory_prepared = prepared;
        let ram = image_output(&directory.join("memory.ram"))?;
        let ram = if fail_output {
            drop(ram);
            File::open(directory.join("memory.ram")).map_err(|error| error.to_string())?
        } else {
            ram
        };
        let output = RamOutputFiles::new(ram, image_output(&directory.join("memory-layout.json"))?);
        let result = if prepared {
            #[cfg(feature = "native-device-probe")]
            {
                vmm.diagnostic_write_memory_capture(key, &attempt, output, Instant::now() + WAIT)
            }
            #[cfg(not(feature = "native-device-probe"))]
            {
                return Err("prepared capture requires native-device-probe".into());
            }
        } else {
            vmm.write_memory_capture(
                self.token
                    .as_ref()
                    .ok_or("capture without exact pause token")?,
                &attempt,
                output,
                Instant::now() + WAIT,
            )
        };
        let candidate = match result {
            Ok(candidate) => candidate,
            Err(error) => {
                if let crate::vmm::memory::CaptureError::Write(failure) = &error {
                    use crate::vmm::memory::image::{
                        DescriptorProblem, RamFileRole, RamImageEffects, RamImageError,
                    };
                    if let RamImageError::DescriptorRole {
                        role: RamFileRole::OutputRam,
                        problem: DescriptorProblem::WrongAccess,
                    } = &failure.error
                    {
                        let effects = match failure.effects {
                            RamImageEffects::None => "none",
                            RamImageEffects::Started => "started",
                        };
                        let baseline = baseline_generation
                            .map_or("null".into(), |generation| generation.to_string());
                        let stats = &failure.stats;
                        let evidence = format!(
                            "{{\"schema\":1,\"kind\":\"ram-image-failure\",\"role\":\"output-ram\",\"problem\":\"wrong-access\",\"effects\":\"{effects}\",\"baseline_generation\":{baseline},\"attempt_sequence\":{},\"stats\":{{\"logical_bytes\":{},\"live_bytes_read\":{},\"baseline_bytes_read\":{},\"baseline_bytes_written\":{},\"overlay_bytes_written\":{},\"full_bytes_written\":{},\"layout_bytes_written\":{},\"baseline_hole_bytes\":{},\"zero_bytes_omitted\":{},\"explicit_zero_bytes_written\":{},\"extent_queries\":{}}}}}\n",
                            attempt.sequence(),
                            stats.logical_bytes,
                            stats.live_bytes_read,
                            stats.baseline_bytes_read,
                            stats.baseline_bytes_written,
                            stats.overlay_bytes_written,
                            stats.full_bytes_written,
                            stats.layout_bytes_written,
                            stats.baseline_hole_bytes,
                            stats.zero_bytes_omitted,
                            stats.explicit_zero_bytes_written,
                            stats.extent_queries,
                        );
                        write_new(&directory.join("memory-failure.json"), evidence.as_bytes())
                            .map_err(|evidence_error| {
                                format!("{error}; recording failure: {evidence_error}")
                            })?;
                    }
                }
                return Err(error.to_string());
            }
        };
        let receipt = candidate.receipt();
        let stats = receipt.stats();
        let mode = if matches!(
            receipt.mode(),
            crate::vmm::memory::image::RamCaptureMode::Full
        ) {
            "full"
        } else {
            "incremental"
        };
        let baseline_json =
            baseline_generation.map_or("null".into(), |generation| generation.to_string());
        let fallback = match candidate.full_reason() {
            None => "null",
            Some(crate::vmm::memory::FullCaptureReason::Requested) => "\"requested-full\"",
            Some(crate::vmm::memory::FullCaptureReason::NoBaseline) => "\"no-baseline\"",
            Some(crate::vmm::memory::FullCaptureReason::BaselineToken) => "\"baseline-token\"",
            Some(crate::vmm::memory::FullCaptureReason::CoverageLost) => "\"coverage-lost\"",
            Some(crate::vmm::memory::FullCaptureReason::DirtyCrossover) => "\"dirty-crossover\"",
        };
        let chunks = receipt
            .affected_chunks()
            .map(|chunk| chunk.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let dirty_pages = if prepared {
            #[cfg(feature = "native-device-probe")]
            {
                vmm.diagnostic_memory_dirty_pages(key)
                    .map_err(|error| error.to_string())?
                    .count()
            }
            #[cfg(not(feature = "native-device-probe"))]
            {
                return Err("prepared capture requires native-device-probe".into());
            }
        } else {
            vmm.memory_dirty_pages(self.token.as_ref().ok_or("pause absent")?)?
                .count()
        };
        let metadata = format!(
            "{{\"schema\":1,\"scope\":\"accepted-baseline-ledger\",\"mode\":\"{mode}\",\"fallback\":{fallback},\"baseline_generation\":{baseline_json},\"candidate_generation\":{},\"attempt_sequence\":{},\"pause_generation\":{},\"dirty_pages\":{dirty_pages},\"stats\":{{\"logical_bytes\":{},\"live_bytes_read\":{},\"baseline_bytes_read\":{},\"baseline_bytes_written\":{},\"overlay_bytes_written\":{},\"full_bytes_written\":{},\"layout_bytes_written\":{},\"baseline_hole_bytes\":{},\"zero_bytes_omitted\":{},\"explicit_zero_bytes_written\":{},\"extent_queries\":{}}},\"affected_chunks\":[{chunks}]}}\n",
            candidate.memory_generation(), attempt.sequence(), execution.binding.pause_generation,
            stats.logical_bytes, stats.live_bytes_read, stats.baseline_bytes_read, stats.baseline_bytes_written,
            stats.overlay_bytes_written, stats.full_bytes_written, stats.layout_bytes_written, stats.baseline_hole_bytes,
            stats.zero_bytes_omitted, stats.explicit_zero_bytes_written, stats.extent_queries,
        ).into_bytes();
        self.memory_candidate = Some(candidate);
        self.memory_stats = Some(metadata.clone());
        write_new(&directory.join("memory-image.json"), &metadata)?;
        #[cfg(feature = "native-device-probe")]
        {
            write_new(&directory.join("memory-dirty.json"), &dirty.0)?;
            write_new(&directory.join("memory-dirty.bitmap"), &dirty.1)?;
        }
        Ok(())
    }
    fn prepare_layout(&mut self, path: &Path) -> Result<(), String> {
        let vmm = self.vmm.try_lock().map_err(|_| "driver VMM lock")?;
        let layout = vmm.memory_layout().map_err(|error| error.to_string())?;
        if layout.packed_len() > MAX_RAM {
            return Err("standalone RAM exceeds fixture bound".into());
        }
        write_new(path, layout.canonical_bytes())?;
        self.prepared_layout = Some(layout);
        Ok(())
    }

    fn abandon_memory(&mut self) -> Result<(), String> {
        let Some(attempt) = self.memory_attempt.as_ref() else {
            return Ok(());
        };
        let mut vmm = self.vmm.try_lock().map_err(|_| "driver VMM lock")?;
        if self.memory_prepared {
            #[cfg(feature = "native-device-probe")]
            {
                let key = vmm
                    .execution
                    .retained
                    .as_ref()
                    .ok_or("prepared cut absent")?
                    .key;
                vmm.diagnostic_abandon_memory(key, attempt)
            }
            #[cfg(not(feature = "native-device-probe"))]
            {
                return Err("prepared capture requires native-device-probe".into());
            }
        } else {
            vmm.abandon_memory(self.token.as_ref().ok_or("pause absent")?, attempt)
        }
        .map_err(|error| error.to_string())?;
        self.memory_candidate = None;
        self.memory_attempt = None;
        Ok(())
    }

    fn accept_memory(&mut self, authentication: &Path) -> Result<(), String> {
        let bytes: [u8; 64] = bounded(authentication, 64)?
            .try_into()
            .map_err(|_| "authentication must contain 64 bytes")?;
        let directory = self
            .memory_directory
            .as_ref()
            .ok_or("candidate directory absent")?;
        let mut vmm = self.vmm.try_lock().map_err(|_| "driver VMM lock")?;
        let state = vmm
            .execution
            .captured_envelope()
            .ok_or("execution envelope absent")?
            .binding
            .clone();
        if bytes[..32] != state.ram_layout {
            return Err("authentication layout binding mismatch".into());
        }
        let stream = bytes[32..]
            .try_into()
            .map_err(|_| "stream identity width")?;
        let candidate = self
            .memory_candidate
            .as_mut()
            .ok_or("completed candidate absent")?;
        let image = candidate
            .seal(
                File::open(directory.join("memory.ram")).map_err(|error| error.to_string())?,
                File::open(directory.join("memory-layout.json"))
                    .map_err(|error| error.to_string())?,
                RamImageAuthentication { state, stream },
            )
            .map_err(|error| error.to_string())?;
        let candidate = self
            .memory_candidate
            .take()
            .ok_or("completed candidate absent")?;
        if self.memory_prepared {
            #[cfg(feature = "native-device-probe")]
            {
                let key = vmm
                    .execution
                    .retained
                    .as_ref()
                    .ok_or("prepared cut absent")?
                    .key;
                vmm.diagnostic_accept_memory(key, candidate, image)
            }
            #[cfg(not(feature = "native-device-probe"))]
            {
                return Err("prepared capture requires native-device-probe".into());
            }
        } else {
            vmm.accept_memory(self.token.as_ref().ok_or("pause absent")?, candidate, image)
        }
        .map_err(|error| error.to_string())?;
        self.memory_attempt = None;
        Ok(())
    }
}

#[cfg(feature = "native-device-probe")]
fn dirty_failure_json(failure: Option<arch::guest_memory::DirtyFailure>) -> String {
    use arch::guest_memory::{DirtyEffect, DirtyLocation, DirtyOperation};
    let Some(failure) = failure else {
        return "null".into();
    };
    let operation = match failure.operation {
        DirtyOperation::Bind => "bind",
        DirtyOperation::Arm => "arm",
        DirtyOperation::Collect => "collect",
        DirtyOperation::Rearm => "rearm",
        DirtyOperation::Reestablish => "reestablish",
        DirtyOperation::Native => "native",
        DirtyOperation::Fault => "fault",
    };
    let effect = match failure.effect {
        DirtyEffect::PreEffectRefusal => "pre-effect-refusal",
        DirtyEffect::CoverageLost => "coverage-lost",
        DirtyEffect::ProtectionUnknown => "protection-unknown",
    };
    let slot = match failure.location {
        DirtyLocation::Slot(slot) => slot.to_string(),
        _ => "null".into(),
    };
    format!(
        "{{\"operation\":\"{operation}\",\"slot\":{slot},\"native_code\":{},\"effect\":\"{effect}\"}}",
        failure.native_code
    )
}
#[cfg(feature = "native-device-probe")]
fn diagnostic_dirty_memory(
    vmm: &Vmm,
    token: Option<&PauseToken>,
    execution: &ExecutionEnvelope,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use std::fmt::Write as FmtWrite;
    let layout = vmm.memory_domain.layout();
    layout
        .validate_capture()
        .map_err(|error| error.to_string())?;
    let dirty = if let Some(token) = token {
        vmm.memory_dirty_pages(token)?
    } else {
        vmm.diagnostic_memory_dirty_pages(
            vmm.execution
                .retained
                .as_ref()
                .ok_or("prepared cut absent")?
                .key,
        )
        .map_err(|error| error.to_string())?
    };
    if layout.packed_len() > MAX_RAM
        || layout.regions().len() != execution.memory_regions.len()
        || layout.page_count() != dirty.page_count()
        || dirty.words().len() != layout.page_count().div_ceil(64)
    {
        return Err("standalone dirty geometry exceeds bounds or differs from RAM".into());
    }
    let scope = if vmm.baseline_token().is_some() {
        "accepted-baseline-ledger"
    } else {
        "cumulative-union-no-accepted-baseline"
    };
    let mut metadata = format!(
        "{{\"schema\":1,\"scope\":\"{scope}\",\"bitmap_encoding\":\"u64-le-lsb0-dense\",\"granule\":{},\"packed_len\":{},\"page_count\":{},\"dirty_pages\":{},\"bitmap_bytes\":{},\"pause_generation\":{},\"regions\":[",
        layout.granule(),
        layout.packed_len(),
        layout.page_count(),
        dirty.count(),
        dirty.words().len() * 8,
        execution.binding.pause_generation,
    );
    for (index, (region, captured)) in layout
        .regions()
        .iter()
        .zip(&execution.memory_regions)
        .enumerate()
    {
        let guest = region.guest_range();
        if guest.start() != captured.start() || guest.byte_len() != captured.byte_len() {
            return Err("standalone dirty layout differs from packed execution RAM".into());
        }
        if index != 0 {
            metadata.push(',');
        }
        write!(
            metadata,
            "{{\"id\":{},\"gpa\":{},\"byte_len\":{},\"stream_offset\":{},\"first_page\":{}}}",
            region.id().index(),
            guest.start(),
            guest.byte_len(),
            region.stream_offset(),
            region.first_page(),
        )
        .map_err(|error| error.to_string())?;
    }
    metadata.push_str("]}\n");
    let mut bitmap = Vec::with_capacity(dirty.words().len() * 8);
    for word in dirty.words() {
        bitmap.extend_from_slice(&word.to_le_bytes());
    }
    Ok((metadata.into_bytes(), bitmap))
}

#[cfg(feature = "native-device-probe")]
fn diagnostic_host_write(driver: &Driver, operand: &str) -> Result<(), String> {
    use crate::vmm::control::ControlState;
    use devices::virtio::RuntimeGuestMemory;
    let mut fields = operand.split_whitespace();
    let address = fields
        .next()
        .ok_or("host write GPA")?
        .parse::<u64>()
        .map_err(|_| "host write GPA")?;
    let before = fields
        .next()
        .ok_or("host write expected byte")?
        .parse::<u8>()
        .map_err(|_| "host write expected byte")?;
    let after = fields
        .next()
        .ok_or("host write replacement byte")?
        .parse::<u8>()
        .map_err(|_| "host write replacement byte")?;
    if fields.next().is_some() || address % 4096 != 0 || before == after {
        return Err("host write requires one aligned fixture page and distinct bytes".into());
    }
    let vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
    if !matches!(vmm.control.state, ControlState::Running) {
        return Err("host write requires actual running/reopened memory admission".into());
    }
    let memory = RuntimeGuestMemory::new(vmm.memory_domain.clone());
    let mut observed = [0u8; 4096];
    memory
        .read_slice(&mut observed, GuestAddress(address))
        .map_err(|error| error.to_string())?;
    if observed != [before; 4096] {
        return Err("host write fixture ownership pattern differs".into());
    }
    let page = vmm
        .memory_domain
        .layout()
        .page_at(address)
        .ok_or("host write GPA outside registered RAM")?;
    let host_dirty_before = vmm
        .memory_domain
        .host_page_dirty(page)
        .map_err(|error| error.to_string())?;
    if host_dirty_before {
        return Err(
            "host write proof requires a clean active host-page bit after prior cut".into(),
        );
    }
    memory
        .write_slice(&[after; 4096], GuestAddress(address))
        .map_err(|error| error.to_string())?;
    let host_dirty_after = vmm
        .memory_domain
        .host_page_dirty(page)
        .map_err(|error| error.to_string())?;
    if !host_dirty_after {
        return Err("actual directional host write did not dirty the active host-page bit".into());
    }
    memory
        .read_slice(&mut observed, GuestAddress(address))
        .map_err(|error| error.to_string())?;
    if observed != [after; 4096] {
        return Err("host write production directional readback differs".into());
    }
    println!(
        "HOST_MEMORY_WRITE {{\"gpa\":{address},\"dense_page\":{},\"bytes\":4096,\"before\":{before},\"after\":{after},\"host_dirty_before\":{host_dirty_before},\"host_dirty_after\":{host_dirty_after},\"readback_verified\":true,\"path\":\"RuntimeGuestMemory::write_slice\"}}",
        page.index()
    );
    Ok(())
}

#[cfg(feature = "native-device-probe")]
fn diagnostic_host_page(driver: &Driver, operand: &str) -> Result<(), String> {
    let address = operand
        .parse::<u64>()
        .map_err(|_| "host page observation GPA")?;
    let vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
    let page = vmm
        .memory_domain
        .layout()
        .page_at(address)
        .ok_or("host page observation GPA outside registered RAM")?;
    let dirty = vmm
        .memory_domain
        .host_page_dirty(page)
        .map_err(|error| error.to_string())?;
    println!(
        "HOST_MEMORY_PAGE {{\"gpa\":{address},\"dense_page\":{},\"host_dirty\":{dirty}}}",
        page.index()
    );
    Ok(())
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
fn image_output(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn resource<T: VirtioDevice + Subscriber + 'static>(id: &str, device: T) -> Resource {
    let device = Arc::new(Mutex::new(device));
    Resource {
        id: id.into(),
        device: device.clone(),
        subscriber: Some(device),
        balloon_binding: None,
        generation_binding: None,
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
            balloon_binding: None,
            generation_binding: None,
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
        balloon_binding: None,
        generation_binding: None,
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
    let balloon = Arc::new(Mutex::new(balloon));
    result.push(Resource {
        id: "balloon0".into(),
        device: balloon.clone(),
        subscriber: Some(balloon.clone()),
        balloon_binding: Some(BalloonBinding::new(balloon)),
        generation_binding: None,
    });
    result.push(resource(
        "rng0",
        Rng::new().map_err(|error| format!("rng: {error:?}"))?,
    ));
    if arguments
        .get("generation")
        .is_some_and(|value| value == "on")
    {
        if saved.is_some_and(|saved| {
            saved
                .records
                .iter()
                .filter(|record| {
                    record.state.device_type == devices::virtio::generation::DEVICE_TYPE
                        && record.identity.configured_id == DEVICE_ID
                })
                .count()
                != 1
        }) {
            return Err("generation restore requires exact captured attachment".into());
        }
        let device = Arc::new(Mutex::new(Generation::new()));
        result.push(Resource {
            id: DEVICE_ID.into(),
            device: device.clone(),
            subscriber: None,
            balloon_binding: None,
            generation_binding: Some(GenerationBinding::new(device)),
        });
    }
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
    let mut commandline = if arguments.contains_key("witness") {
        format!(
            "console=hvc0 rdinit=/init panic=-1 probe.echo_port={port} maxcpus=2 memmap=16M$448M memmap=64K$448K"
        )
    } else {
        format!("console=hvc0 rdinit=/init panic=-1 probe.echo_port={port}")
    };
    if let Some(mode) = arguments.get("generation-proof-mode") {
        if !matches!(mode.as_str(), "1" | "2" | "3") {
            return Err("diagnostic generation proof mode must be 1, 2 or 3".into());
        }
        commandline.push_str(&format!(" virtio_silo_vmgenid.proof_mode={mode}"));
    }
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
        generation_ticket: None,
        stopped: false,
        prepared_layout: None,
        memory_attempt: None,
        memory_candidate: None,
        memory_directory: None,
        memory_prepared: false,
        memory_stats: None,
        prepared_devices: None,
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
    let authentication: [u8; 64] = bounded(&directory.join("memory-authentication.bin"), 64)?
        .try_into()
        .map_err(|_| "RAM authentication must contain 64 bytes")?;
    if authentication[..32] != expected.ram_layout {
        return Err("restore RAM authentication layout mismatch".into());
    }
    let image = Arc::new(
        AuthenticatedRamImage::for_restore(
            File::from(owned_fd(arguments, "ram-image-fd")?),
            File::from(owned_fd(arguments, "ram-layout-fd")?),
            RamImageAuthentication {
                state: expected,
                stream: authentication[32..]
                    .try_into()
                    .map_err(|_| "stream identity width")?,
            },
            &validated,
        )
        .map_err(|error| error.to_string())?,
    );
    if image.layout().packed_len() > MAX_RAM {
        return Err("standalone RAM exceeds fixture bound".into());
    }
    let memory = map_restore_ram(image, &validated).map_err(|error| error.to_string())?;
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
            generation_binding: resource.generation_binding.clone(),
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
    let mut prepared = devices.prepare(bindings, serial, None)?;
    prepared.balloon_bindings = resources
        .iter()
        .filter_map(|resource| resource.balloon_binding.clone())
        .collect();
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
    let observed_memory = memory.domain().clone();
    let vmm = match build_restore_prepared(
        memory,
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
                            observed_memory.read_only(),
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
                    generation_ticket: None,
                    stopped: false,
                    prepared_layout: None,
                    memory_attempt: None,
                    memory_candidate: None,
                    memory_directory: None,
                    memory_prepared: false,
                    memory_stats: None,
                    prepared_devices: None,
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
            generation_ticket: None,
            stopped: false,
            prepared_layout: None,
            memory_attempt: None,
            memory_candidate: None,
            memory_directory: None,
            memory_prepared: false,
            memory_stats: None,
            prepared_devices: Some(Arc::new(saved.clone())),
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
        generation_ticket: None,
        stopped: false,
        prepared_layout: None,
        memory_attempt: None,
        memory_candidate: None,
        memory_directory: None,
        memory_prepared: false,
        memory_stats: None,
        prepared_devices: Some(Arc::new(saved.clone())),
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
    memory: ReadGuestMemory<'_>,
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
    .chain(
        options
            .contains_key("restore")
            .then_some(["ram-image-fd", "ram-layout-fd"])
            .into_iter()
            .flatten(),
    )
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
                    if matches!(
                        command,
                        "generation-fresh"
                            | "generation-clock"
                            | "generation-resume"
                            | "generation-snapshot"
                            | "generation-wait"
                    ) && !operand.is_empty()
                    {
                        return Err("generation command takes no operands".into());
                    }
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
                        #[cfg(feature = "native-device-probe")]
                        "reclaim-hold-source"
                        | "reclaim-complete-child"
                        | "reclaim-witness"
                        | "reclaim-release-hold" => pressure::reclaim_command(
                            &mut driver,
                            &activation_resources,
                            command,
                            operand,
                        )?,
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
                        "generation-fresh" | "generation-clock" => {
                            let authority = if let Some(token) = &driver.token {
                                GenerationAuthority::Pause(token.clone())
                            } else {
                                let vmm = driver.vmm.try_lock().map_err(|_| "driver lock")?;
                                let crate::vmm::control::ControlState::RestorePrepared { key } =
                                    vmm.control.state
                                else {
                                    return Err(
                                        "generation preparation requires stopped authority".into(),
                                    );
                                };
                                GenerationAuthority::Restore(key)
                            };
                            let mode = if command == "generation-fresh" {
                                GenerationMode::Fresh
                            } else {
                                GenerationMode::ClockOnly
                            };
                            let deadline = Instant::now() + WAIT;
                            let ControlReply::Generation(ticket) =
                                driver.call(RequestKind::PrepareGeneration {
                                    authority,
                                    mode,
                                    deadline,
                                })?
                            else {
                                return Err("generation preparation reply".into());
                            };
                            driver.generation_ticket = Some(ticket);
                        }
                        "generation-resume" => {
                            let ticket = driver
                                .generation_ticket
                                .clone()
                                .ok_or("generation ticket absent")?;
                            let request = if let Some(token) = &driver.token {
                                RequestKind::ResumeGeneration(token.clone(), ticket)
                            } else {
                                RequestKind::ReleaseRestoreGeneration(ticket)
                            };
                            driver.call(request)?;
                            driver.token = None;
                        }
                        "generation-capture" => {
                            use std::sync::atomic::Ordering;

                            if operand.is_empty() {
                                return Err("generation-capture requires an output path".into());
                            }
                            let vmm = driver.vmm.try_lock().map_err(|_| "driver lock")?;
                            let key = vmm
                                .execution
                                .retained
                                .as_ref()
                                .ok_or("generation capture requires actual cut")?
                                .key;
                            let interrupt = vmm
                                .mmio_device_manager
                                .quiescence
                                .interrupt_binding(
                                    devices::virtio::generation::DEVICE_TYPE,
                                    DEVICE_ID,
                                )
                                .map_err(|error| error.to_string())?;
                            let before_config_generation = interrupt.config_generation();
                            let before_interrupt_status =
                                interrupt.status().load(Ordering::SeqCst) as u32;
                            let records = vmm
                                .mmio_device_manager
                                .quiescence
                                .capture_devices(key)
                                .map_err(|error| error.to_string())?;
                            let mut records = records
                                .iter()
                                .filter(|record| record.identity.configured_id == DEVICE_ID);
                            let record = records.next().ok_or("generation attachment absent")?;
                            if records.next().is_some() {
                                return Err("duplicate generation attachment".into());
                            }
                            record
                                .state
                                .validate_payload_binding(&record.payload)
                                .map_err(|error| format!("{error:?}"))?;
                            write_new(Path::new(operand), &record.payload)?;
                            let after_config_generation = interrupt.config_generation();
                            let after_interrupt_status =
                                interrupt.status().load(Ordering::SeqCst) as u32;
                            println!(
                                "GENERATION_CAPTURE bytes={} config_generation={} interrupt_status={} avail_features={} acked_features={} before_config_generation={before_config_generation} before_interrupt_status={before_interrupt_status} after_config_generation={after_config_generation} after_interrupt_status={after_interrupt_status}",
                                record.payload.len(),
                                record.state.config_generation,
                                record.state.interrupt_status,
                                record.state.avail_features,
                                record.state.acked_features
                            );
                        }
                        "generation-snapshot" => {
                            let ControlReply::GenerationSnapshot(snapshot) =
                                driver.call(RequestKind::GenerationSnapshot)?
                            else {
                                return Err("generation snapshot reply".into());
                            };
                            let ticket = driver.generation_ticket.as_ref();
                            let observed = ticket.map(|ticket| ticket.observe(Instant::now()));
                            let outcome = match observed {
                                None => "none",
                                Some(GenerationObservation::Pending) => "pending",
                                Some(GenerationObservation::Acknowledged(_)) => "acknowledged",
                                Some(GenerationObservation::Failed(
                                    GenerationFailure::Deadline,
                                )) => "deadline",
                                Some(GenerationObservation::Failed(_)) => "failed",
                            };
                            let timely = matches!(observed, Some(GenerationObservation::Acknowledged(receipt))
                                if ticket.is_some_and(|ticket| receipt.completed_at < ticket.deadline()));
                            let deadline = ticket
                                .map(|ticket| format!("{:?}", ticket.deadline()))
                                .unwrap_or_default();
                            let committed = snapshot.committed.map_or(0, |tuple| tuple.sequence);
                            let counter = snapshot
                                .config_generation
                                .ok_or("generation snapshot interrupt binding absent")?;
                            println!(
                                "GENERATION {{\"sequence\":{},\"id\":{:?},\"flags\":{},\"processed_sequence\":{},\"processed_id\":{:?},\"driver_status\":{},\"clock_latch\":{},\"config_generation\":{counter},\"committed_sequence\":{committed},\"outcome\":\"{outcome}\",\"deadline\":\"{deadline}\",\"timely\":{timely}}}",
                                snapshot.request.sequence,
                                snapshot.request.id,
                                snapshot.request.flags,
                                snapshot.processed.sequence,
                                snapshot.processed.id,
                                snapshot.driver_status,
                                snapshot.clock_latch
                            );
                        }
                        "generation-wait" => {
                            let ticket = driver
                                .generation_ticket
                                .clone()
                                .ok_or("generation ticket absent")?;
                            loop {
                                match ticket.observe(Instant::now()) {
                                    GenerationObservation::Pending => driver.poll()?,
                                    observation => {
                                        println!("GENERATION_OUTCOME {observation:?}");
                                        break;
                                    }
                                }
                            }
                        }
                        #[cfg(feature = "native-device-probe")]
                        "memory-host-write" => diagnostic_host_write(&driver, operand)?,
                        #[cfg(feature = "native-device-probe")]
                        "memory-host-page" => diagnostic_host_page(&driver, operand)?,
                        #[cfg(feature = "native-device-probe")]
                        "memory-fail-next-harvest" => {
                            if !operand.is_empty() {
                                return Err("memory-fail-next-harvest takes no operands".into());
                            }
                            let slot = driver
                                .vmm
                                .try_lock()
                                .map_err(|_| "driver VMM lock")?
                                .diagnostic_fail_next_memory_harvest()
                                .map_err(|error| error.to_string())?;
                            println!("MEMORY_FAIL_NEXT_HARVEST_SLOT {slot}");
                        }
                        #[cfg(feature = "native-device-probe")]
                        "memory-recover-cut" => {
                            if !operand.is_empty() {
                                return Err("memory-recover-cut takes no operands".into());
                            }
                            let mut vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
                            let token = vmm
                                .diagnostic_recover_memory_cut()
                                .map_err(|error| error.to_string())?;
                            driver.token = Some(token);
                        }
                        #[cfg(feature = "native-device-probe")]
                        "memory-recovery-stats" => {
                            let vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
                            let observation = vmm.diagnostic_memory_recovery_observation();
                            let registered = observation.map_or("null".into(), |value| {
                                format!("{:?}", value.registered_slots)
                            });
                            let successful = observation.map_or("null".into(), |value| {
                                format!("{:?}", value.successful_slots)
                            });
                            let epoch = observation
                                .and_then(|value| value.epoch)
                                .map_or("null".into(), |value| value.to_string());
                            let failure =
                                dirty_failure_json(observation.and_then(|value| value.failure));
                            let tracking_failure = dirty_failure_json(
                                vmm.diagnostic_memory_tracking_failure().or_else(|| {
                                    observation.and_then(|value| value.harvest_failure)
                                }),
                            );
                            let coverage = vmm.diagnostic_memory_coverage_valid();
                            let full_required = vmm.diagnostic_memory_full_required();
                            let output = format!(
                                "{{\"schema\":1,\"registered_slots\":{registered},\"successful_slots\":{successful},\"epoch\":{epoch},\"failure\":{failure},\"tracking_failure\":{tracking_failure},\"coverage_valid\":{coverage},\"full_required\":{full_required}}}\n"
                            );
                            write_new(Path::new(operand), output.as_bytes())?;
                        }
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
                        "memory-layout" => driver.prepare_layout(Path::new(operand))?,
                        "memory-accept" => driver.accept_memory(Path::new(operand))?,
                        "memory-abandon" => driver.abandon_memory()?,
                        "memory-stats" => write_new(
                            Path::new(operand),
                            driver.memory_stats.as_ref().ok_or("memory stats absent")?,
                        )?,
                        #[cfg(feature = "native-device-probe")]
                        "memory-reporting" => {
                            use std::sync::atomic::Ordering;

                            let vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
                            let mut resources = activation_resources
                                .iter()
                                .filter(|resource| resource.id == "balloon0");
                            let resource =
                                resources.next().ok_or("actual balloon resource absent")?;
                            if resources.next().is_some() {
                                return Err("actual balloon resource is not unique".into());
                            }
                            let device = resource
                                .device
                                .try_lock()
                                .map_err(|_| "actual balloon resource lock")?;
                            let balloon = (*device)
                                .as_any()
                                .downcast_ref::<Balloon>()
                                .ok_or("actual balloon resource type")?;
                            let queue = balloon.pressure_reporting_queue();
                            let used_idx = queue
                                .used_ring
                                .map(|ring| {
                                    let address = ring
                                        .checked_add(2)
                                        .ok_or("reporting used-ring address overflow")?;
                                    vmm.memory_domain
                                        .read_only()
                                        .load::<u16>(GuestAddress(address), Ordering::Acquire)
                                        .map(u16::from_le)
                                        .map_err(|error| error.to_string())
                                })
                                .transpose()?;
                            let next_used = queue
                                .next_used
                                .map_or("null".into(), |value| value.to_string());
                            let used_idx =
                                used_idx.map_or("null".into(), |value| value.to_string());
                            let used_ring = queue
                                .used_ring
                                .map_or("null".into(), |value| value.to_string());
                            let output = format!(
                                "{{\"schema\":1,\"native_pid\":{},\"reporting_negotiated\":{},\"reclaim\":{},\"ready\":{},\"next_used\":{next_used},\"used_idx\":{used_idx},\"used_ring\":{used_ring}}}\n",
                                std::process::id(),
                                queue.reporting_negotiated,
                                pressure::reclaim_status_json(balloon.reclaim_status()),
                                queue.ready,
                            );
                            write_new(Path::new(operand), output.as_bytes())?;
                        }
                        #[cfg(feature = "native-device-probe")]
                        "memory-mappings" => {
                            use crate::vmm::control::ControlState;
                            let vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
                            if !matches!(
                                &vmm.control.state,
                                ControlState::Paused(_) | ControlState::RestorePrepared { .. }
                            ) {
                                return Err("mapping evidence requires a stopped RAM owner".into());
                            }
                            write_new(
                                Path::new(operand),
                                diagnostic_memory_mappings(&vmm.memory_domain)?.as_bytes(),
                            )?;
                        }
                        #[cfg(feature = "native-device-probe")]
                        "memory-prepared" => {
                            let vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
                            let envelope = vmm
                                .execution
                                .captured_envelope()
                                .ok_or("prepared envelope absent")?;
                            let runs = vmm
                                .vcpus_handles
                                .iter()
                                .map(|owner| owner.native_run_observer().attempts())
                                .collect::<Result<Vec<_>, _>>()?;
                            let mut wall_clock_gpas = Vec::new();
                            for cpu in &envelope.cpus {
                                if let crate::vmm::execution::CpuExecutionState::Kvm(
                                    crate::vmm::execution::kvm::KvmCpuState::X86(cpu),
                                ) = cpu
                                {
                                    for msr in &cpu.msrs {
                                        if matches!(msr.index, 0x11 | 0x4b564d00)
                                            && msr.value != 0
                                            && !wall_clock_gpas.contains(&msr.value)
                                        {
                                            wall_clock_gpas.push(msr.value);
                                        }
                                    }
                                }
                            }
                            let backing = vmm
                                .memory_domain
                                .file_backing_identities()
                                .next()
                                .ok_or("prepared backing absent")?
                                .map_err(|error| error.to_string())?;
                            let generation = vmm
                                .baseline_token()
                                .ok_or("prepared baseline absent")?
                                .memory_generation();
                            let output = format!(
                                "{{\"schema\":1,\"native_run_entries\":{runs:?},\"wall_clock_gpas\":{wall_clock_gpas:?},\"baseline_generation\":{generation},\"backing\":{{\"device\":{},\"inode\":{}}}}}\n",
                                backing.device, backing.inode
                            );
                            write_new(Path::new(operand), output.as_bytes())?;
                        }
                        #[cfg(feature = "native-device-probe")]
                        "prepared-memory-dirty" => {
                            let vmm = driver.vmm.try_lock().map_err(|_| "driver VMM lock")?;
                            let envelope = vmm
                                .execution
                                .captured_envelope()
                                .ok_or("prepared envelope absent")?;
                            let (metadata, bitmap) = diagnostic_dirty_memory(&vmm, None, envelope)?;
                            let directory = Path::new(operand);
                            fs::DirBuilder::new()
                                .mode(0o700)
                                .create(directory)
                                .map_err(|error| error.to_string())?;
                            write_new(&directory.join("memory-dirty.json"), &metadata)?;
                            write_new(&directory.join("memory-dirty.bitmap"), &bitmap)?;
                        }
                        "capture"
                        | "capture-cumulative"
                        | "memory-capture"
                        | "memory-capture-fail"
                        | "prepared-memory-capture" => {
                            let (operand, mode) =
                                if matches!(command, "capture" | "capture-cumulative") {
                                    (operand, "full")
                                } else {
                                    operand
                                        .rsplit_once(' ')
                                        .ok_or("expected PATH full|incremental")?
                                };
                            if !matches!(mode, "full" | "incremental") {
                                return Err("invalid RAM capture mode".into());
                            }
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
                                (generation, vmm.execution.profile.clone())
                            };
                            driver.capture(
                                Path::new(operand),
                                binding(Path::new(argument(&options, "binding")?), generation)?,
                                profile.as_ref(),
                                [
                                    Path::new(argument(&options, "disk0")?),
                                    Path::new(argument(&options, "disk1")?),
                                ],
                                MemoryCaptureOptions {
                                    full: mode == "full",
                                    prepared: command == "prepared-memory-capture",
                                    fail_output: command == "memory-capture-fail",
                                },
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

    #[cfg(feature = "native-device-probe")]
    #[test]
    fn mapping_evidence_binds_actual_region_addresses_and_retained_file_identity() {
        use crate::api::vmm_builder::native_device_probe::diagnostic_memory_mappings;
        use arch::guest_memory::{BackingKind, MemoryDomain};
        use std::fs::{File, OpenOptions, remove_file};
        use std::os::unix::fs::MetadataExt;
        use std::time::{SystemTime, UNIX_EPOCH};
        use vm_memory::mmap::MmapRegion;
        use vm_memory::{
            FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion,
            GuestRegionMmap, MemoryRegionAddress,
        };

        let path = std::env::temp_dir().join(format!(
            "silo-mapping-evidence-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        output.set_len(8192).unwrap();
        drop(output);
        let input = File::open(&path).unwrap();
        let metadata = input.metadata().unwrap();
        let mut regions = Vec::new();
        for (gpa, offset) in [(0x1000, 0), (0x4000, 4096)] {
            let mapping = MmapRegion::<()>::build(
                Some(FileOffset::new(input.try_clone().unwrap(), offset)),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
            )
            .unwrap();
            regions.push(GuestRegionMmap::new(mapping, GuestAddress(gpa)).unwrap());
        }
        let memory = GuestMemoryMmap::from_regions(regions).unwrap();
        let hosts = memory
            .iter()
            .map(|region| region.get_host_address(MemoryRegionAddress(0)).unwrap() as usize as u64)
            .collect::<Vec<_>>();
        let (domain, _, _) =
            MemoryDomain::construct(memory, 4096, BackingKind::RestoredPrivate).unwrap();
        remove_file(path).unwrap();
        let expected = format!(
            "{{\"schema\":1,\"native_pid\":{},\"packed_len\":8192,\"regions\":[{{\"gpa\":4096,\"length\":4096,\"stream_offset\":0,\"host_start\":{},\"device\":{},\"inode\":{}}},{{\"gpa\":16384,\"length\":4096,\"stream_offset\":4096,\"host_start\":{},\"device\":{},\"inode\":{}}}]}}\n",
            std::process::id(),
            hosts[0],
            metadata.dev(),
            metadata.ino(),
            hosts[1],
            metadata.dev(),
            metadata.ino(),
        );
        assert_eq!(diagnostic_memory_mappings(&domain).unwrap(), expected);

        let anonymous = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x1000), 4096)]).unwrap();
        let (domain, _, _) =
            MemoryDomain::construct(anonymous, 4096, BackingKind::RestoredPrivate).unwrap();
        assert!(diagnostic_memory_mappings(&domain).is_err());
    }

    #[cfg(feature = "native-device-probe")]
    #[test]
    fn dirty_failure_evidence_projects_typed_native_facts() {
        use crate::api::vmm_builder::native_device_probe::dirty_failure_json;
        use arch::guest_memory::{DirtyEffect, DirtyFailure, DirtyLocation, DirtyOperation};
        assert_eq!(dirty_failure_json(None), "null");
        let failure = DirtyFailure {
            operation: DirtyOperation::Collect,
            location: DirtyLocation::Slot(7),
            native_code: 14,
            effect: DirtyEffect::CoverageLost,
        };
        assert_eq!(
            dirty_failure_json(Some(failure)),
            "{\"operation\":\"collect\",\"slot\":7,\"native_code\":14,\"effect\":\"coverage-lost\"}",
        );
        let recovery = DirtyFailure {
            operation: DirtyOperation::Reestablish,
            location: DirtyLocation::Vm,
            native_code: -5,
            effect: DirtyEffect::ProtectionUnknown,
        };
        assert_eq!(
            dirty_failure_json(Some(recovery)),
            "{\"operation\":\"reestablish\",\"slot\":null,\"native_code\":-5,\"effect\":\"protection-unknown\"}",
        );
    }

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
        let unchanged = ram_difference(
            arch::guest_memory::ReadGuestMemory::new(&memory),
            &regions,
            &path,
        );
        memory.write_slice(&[0x5a], GuestAddress(0x4fff)).unwrap();
        let difference = ram_difference(
            arch::guest_memory::ReadGuestMemory::new(&memory),
            &regions,
            &path,
        );
        memory.write_slice(&[0x5a], GuestAddress(0x1003)).unwrap();
        let bounded = ram_difference(
            arch::guest_memory::ReadGuestMemory::new(&memory),
            &regions,
            &path,
        );
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
