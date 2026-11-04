#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "blk",
    feature = "net",
    not(any(feature = "tee", feature = "aws-nitro"))
))]
#[doc(hidden)]
pub mod native_device_probe;

use std::marker::PhantomData;
#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex};

use crate::vmm::Vmm as InnerVmm;
use crate::vmm::control::{
    ControlClient, ControlFailure, ControlReply, ControlState, PauseOwner, PauseToken, RequestKind,
};
#[cfg(unix)]
use crate::vmm::resources::SerialConsoleConfig;
use crate::vmm::resources::VmResources;
use crate::vmm::vmm_config::machine_config::VmConfig;
use crossbeam_channel::unbounded;
use polly::event_manager::EventManager;
use polly::event_manager::OperationId;
use std::time::{Duration, Instant};
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use utils::eventfd::EventFd;

use crate::api::device_builders::{DeviceManager, MmioDeviceManager};
use crate::api::error::VmmError;
use crate::api::payload::Payload;

#[derive(Default)]
pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    payload: Option<Payload>,
    device_manager: Option<Box<dyn DeviceManager<'a> + 'a>>,
    #[cfg(unix)]
    serial_consoles: Vec<SerialConsoleConfig>,
    kernel_console: Option<String>,
    nested_virt: bool,
    split_irqchip: bool,
    smbios_oem_strings: Vec<String>,
    shutdown_support: bool,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vcpus(mut self, count: u8) -> Result<Self, VmmError> {
        if count == 0 {
            return Err(VmmError::OutOfRange());
        }
        self.vcpus = Some(count);
        Ok(self)
    }

    pub fn ram_mib(mut self, mib: u32) -> Result<Self, VmmError> {
        if mib == 0 {
            return Err(VmmError::OutOfRange());
        }
        self.ram_mib = Some(mib);
        Ok(self)
    }

    pub fn payload(mut self, payload: Payload) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn devices(mut self, devices: MmioDeviceManager<'a>) -> Self {
        self.device_manager = Some(Box::new(devices));
        self
    }

    pub fn set_kernel_console(mut self, console: &str) -> Self {
        self.kernel_console = Some(console.to_string());
        self
    }

    /// Add a legacy serial console device with the given input and output file descriptors.
    ///
    /// Can be called multiple times to add multiple serial consoles (ttyS0, ttyS1, …).
    /// This is required for FreeBSD guests which use the legacy serial console instead
    /// of the virtio console.
    ///
    /// The descriptors are borrowed, not duplicated. They must remain open and valid
    /// until the VMM exits.
    #[cfg(unix)]
    pub fn add_serial_console(
        mut self,
        input_fd: Option<BorrowedFd<'a>>,
        output_fd: Option<BorrowedFd<'a>>,
    ) -> Result<Self, VmmError> {
        let in_fd = input_fd.map_or(-1, |fd| fd.as_raw_fd());
        let out_fd = output_fd.map_or(-1, |fd| fd.as_raw_fd());
        self.serial_consoles.push(SerialConsoleConfig {
            input_fd: in_fd,
            output_fd: out_fd,
        });
        Ok(self)
    }

    pub fn nested_virt(mut self, enabled: bool) -> Self {
        self.nested_virt = enabled;
        self
    }

    pub fn split_irqchip(mut self, enabled: bool) -> Result<Self, VmmError> {
        if enabled && !cfg!(target_arch = "x86_64") {
            return Err(VmmError::InvalidParam());
        }
        self.split_irqchip = enabled;
        Ok(self)
    }

    pub fn add_smbios_oem_string(mut self, s: &str) -> Self {
        self.smbios_oem_strings.push(s.to_string());
        self
    }

    /// Enable the optional guest shutdown device.
    ///
    /// When enabled on aarch64 macOS, [`VmmHandle::shutdown`] signals the
    /// guest through the PL061 GPIO device. The device is not attached by
    /// default. On other platforms, shutdown remains unsupported.
    pub fn shutdown_support(mut self, enabled: bool) -> Self {
        self.shutdown_support = enabled;
        self
    }

    pub fn build(self) -> Result<Vmm<'a>, VmmError> {
        build_vm(self).inspect_err(|e| log::error!("{e}"))
    }
}

enum VmmInner {
    Vmm {
        vmm: Arc<Mutex<InnerVmm>>,
        event_manager: EventManager,
        #[allow(dead_code)]
        _worker_sender: crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        shutdown_efd: Option<EventFd>,
    },
    #[cfg(feature = "aws-nitro")]
    Nitro(aws_nitro::enclave::NitroEnclave),
}

pub struct Vmm<'a> {
    inner: VmmInner,
    _lifetime: PhantomData<&'a ()>,
}

/// Handle to the inner VMM, usable from another thread while the
/// event loop runs on the main thread via [`Vmm::run`].
///
/// Obtain via [`Vmm::handle`] before calling `run()`.
// FIXME: make Vmm::run() non-blocking (requires making EventManager Send)
// so that run() returns a RunningVmm with wait(). Then this handle
// can be obtained from RunningVmm instead of requiring a pre-run call.
pub struct VmmHandle {
    control: ControlClient,
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    shutdown_efd: Option<Arc<EventFd>>,
    reclaim_observer: devices::virtio::balloon::ReclaimObserver,
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    hvf_vm_facts: crate::api::capabilities::HvfVmFacts,
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
impl VmmHandle {
    pub fn hvf_vm_facts(&self) -> crate::api::capabilities::HvfVmFacts {
        self.hvf_vm_facts
    }
}

impl Clone for VmmHandle {
    fn clone(&self) -> Self {
        Self {
            control: self.control.clone(),
            reclaim_observer: self.reclaim_observer.clone(),
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            hvf_vm_facts: self.hvf_vm_facts,
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd: self.shutdown_efd.clone(),
        }
    }
}

impl VmmHandle {
    /// Observe finalized backing, policy and process-local advice operations.
    pub fn host_reclaim_status(&self) -> devices::virtio::balloon::ReclaimStatus {
        self.reclaim_observer.status()
    }

    /// Wait for the complete machine barrier. Caller timeout/drop is not cancellation.
    pub fn pause(
        &self,
        owner: PauseOwner,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<PauseToken, ControlFailure> {
        match self
            .control
            .call(operation, deadline, RequestKind::Pause(owner))?
        {
            ControlReply::Paused(token) => Ok(token),
            _ => Err(ControlFailure::OwnerUnavailable),
        }
    }

    pub fn resume(
        &self,
        token: PauseToken,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), ControlFailure> {
        match self
            .control
            .call(operation, deadline, RequestKind::Resume(token))?
        {
            ControlReply::Complete => Ok(()),
            _ => Err(ControlFailure::OwnerUnavailable),
        }
    }

    pub fn cancel_pause(
        &self,
        pausing: OperationId,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<(), ControlFailure> {
        match self
            .control
            .call(operation, deadline, RequestKind::CancelPause(pausing))?
        {
            ControlReply::Complete => Ok(()),
            _ => Err(ControlFailure::OwnerUnavailable),
        }
    }

    pub fn control_state(&self, deadline: Instant) -> Result<ControlState, ControlFailure> {
        match self
            .control
            .call(OperationId(0), deadline, RequestKind::Status)?
        {
            ControlReply::State(state) => Ok(state),
            _ => Err(ControlFailure::OwnerUnavailable),
        }
    }

    pub fn stop(&self, operation: OperationId, deadline: Instant) -> Result<(), ControlFailure> {
        match self.control.call(operation, deadline, RequestKind::Stop)? {
            ControlReply::Complete => Ok(()),
            _ => Err(ControlFailure::OwnerUnavailable),
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl VmmHandle {
    /// Signal the guest to perform an orderly ACPI shutdown.
    ///
    /// This requires [`VmmBuilder::shutdown_support`] to have been enabled
    /// before building the VMM. On aarch64 macOS it writes to the GPIO
    /// device's eventfd, which triggers a restart-key press in the guest. On
    /// other platforms, or when support was not enabled, it returns
    /// [`VmmError::FeatureDisabled`].
    pub fn shutdown(&self) -> Result<(), VmmError> {
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            let Some(shutdown_efd) = &self.shutdown_efd else {
                return Err(VmmError::FeatureDisabled());
            };
            shutdown_efd
                .write(1)
                .map_err(|e| VmmError::Internal(format!("shutdown: {e}")))
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        Err(VmmError::FeatureDisabled())
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> Vmm<'a> {
    /// Obtain a thread-safe handle to the inner VMM.
    ///
    /// Must be called before [`run`](Self::run) which consumes `self`.
    /// The handle can be moved to another thread for pause/resume.
    pub fn handle(&self) -> Result<VmmHandle, VmmError> {
        match &self.inner {
            VmmInner::Vmm {
                vmm,
                #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                shutdown_efd,
                ..
            } => {
                // Lock once: a second `lock()` while the first guard is still
                // alive within one expression would deadlock the caller.
                let inner = vmm
                    .lock()
                    .map_err(|error| VmmError::Internal(error.to_string()))?;
                Ok(VmmHandle {
                    control: inner.control.client.clone(),
                    reclaim_observer: inner.reclaim_observer.clone().ok_or_else(|| {
                        VmmError::Internal("reclaim observation not finalized".into())
                    })?,
                    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                    hvf_vm_facts: inner.vm.live_facts(),
                    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                    shutdown_efd: shutdown_efd
                        .as_ref()
                        .map(|efd| efd.try_clone().map(Arc::new))
                        .transpose()
                        .map_err(|error| VmmError::Internal(error.to_string()))?,
                })
            }
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(_) => Err(VmmError::FeatureDisabled()),
        }
    }

    pub fn run(self) {
        match self.inner {
            VmmInner::Vmm {
                vmm,
                mut event_manager,
                ..
            } => {
                #[cfg(target_os = "macos")]
                let remapper = {
                    match vmm.lock() {
                        Ok(inner) => inner.vm.host_memory_remapper(),
                        Err(error) => {
                            log::error!("cannot initialize host mapping maintenance: {error}");
                            None
                        }
                    }
                };
                loop {
                    let pending = match vmm.lock() {
                        Ok(inner) => inner.control_pending(),
                        Err(error) => {
                            log::error!("cannot service native control: {error}");
                            break;
                        }
                    };
                    #[cfg(target_os = "macos")]
                    let maintenance_timeout = match remapper
                        .as_ref()
                        .map(|worker| worker.timeout_millis())
                        .transpose()
                    {
                        Ok(timeout) => timeout.unwrap_or(-1),
                        Err(error) => {
                            log::error!("fatal HostMemoryRemapper error: {error}");
                            break;
                        }
                    };
                    #[cfg(not(target_os = "macos"))]
                    let maintenance_timeout = -1;
                    let timeout = if pending {
                        if maintenance_timeout < 0 {
                            1
                        } else {
                            maintenance_timeout.min(1)
                        }
                    } else if maintenance_timeout < 0 {
                        50
                    } else {
                        maintenance_timeout.min(50)
                    };
                    if let Err(error) = event_manager.run_with_timeout(timeout) {
                        log::error!("fatal event loop error: {error:?}");
                        break;
                    }
                    match vmm.lock() {
                        Ok(mut inner) => {
                            inner.service_control(&mut event_manager);
                            if inner.control.state == ControlState::Stopped {
                                break;
                            }
                        }
                        Err(error) => {
                            log::error!("cannot service native control: {error}");
                            break;
                        }
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(remapper) = &remapper {
                        // This scope retains the owning VMM and its guest_memory.
                        if let Err(error) = unsafe { remapper.poll() } {
                            log::error!("fatal HostMemoryRemapper error: {error}");
                            break;
                        }
                    }
                }
                terminal_cleanup(&vmm);
            }
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(enclave) => {
                let exit_code = enclave.run().unwrap_or_else(|e| {
                    log::error!("Error running nitro enclave: {e}");
                    -libc::EINVAL
                });
                unsafe { libc::_exit(exit_code) }
            }
        }
    }
}

/// Terminal cleanup runs after dispatch has stopped, never while holding a VM
/// or device mutex. Native termination may outlive a caller's deadline; owners
/// and RAM cannot be released until the native threads actually finish.
fn terminal_cleanup(vmm: &Arc<Mutex<InnerVmm>>) {
    use crate::vmm::control::{CpuCommandKind, CpuController, RequestId};
    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest};
    let mut handles = {
        let mut inner = match vmm.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.control.state = ControlState::Stopping;
        std::mem::take(&mut inner.vcpus_handles)
    };
    let mut cpus = CpuController::new(handles.len());
    let barrier = BarrierRequest {
        key: BarrierKey {
            operation: OperationId(u64::MAX),
            generation: BarrierGeneration(u64::MAX),
        },
        deadline: Instant::now() + Duration::from_secs(1),
    };
    let _ = cpus.begin(RequestId(u64::MAX), barrier, CpuCommandKind::Stop, &handles);
    loop {
        let _ = cpus.poll(&mut handles);
        let routes_settled = {
            let mut inner = match vmm.lock() {
                Ok(inner) => inner,
                Err(poisoned) => poisoned.into_inner(),
            };
            inner.mmio_device_manager.poll_irq_cleanup()
        };
        if handles.iter().all(|handle| handle.is_finished()) && routes_settled {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // Drop's stop/join fallback is terminal-only, outside the VM lock.
    drop(handles);
    let mut inner = match vmm.lock() {
        Ok(inner) => inner,
        Err(poisoned) => poisoned.into_inner(),
    };
    inner.control.state = ControlState::Stopped;
}

#[cfg_attr(feature = "ffi", ffier::export)]
pub fn check_nested_virt() -> bool {
    #[cfg(target_os = "macos")]
    {
        hvf::check_nested_virt().unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let paths = [
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        ];
        paths.iter().any(|path| {
            fs::read_to_string(path).is_ok_and(|contents| {
                let val = contents.trim();
                val == "1" || val.eq_ignore_ascii_case("Y")
            })
        })
    }
}

fn build_vm(builder_cfg: VmmBuilder<'_>) -> Result<Vmm<'_>, VmmError> {
    use super::payload::PayloadKind;

    let vcpus_count = builder_cfg
        .vcpus
        .ok_or_else(|| VmmError::MissingConfig("vcpus not set".into()))?;
    let ram_mib = builder_cfg
        .ram_mib
        .ok_or_else(|| VmmError::MissingConfig("ram_mib not set".into()))?;
    let payload = builder_cfg
        .payload
        .ok_or_else(|| VmmError::MissingConfig("payload not set".into()))?;

    #[cfg(feature = "aws-nitro")]
    if let PayloadKind::Nitro(nitro_config) = payload.kind {
        let enclave = nitro_config
            .into_enclave(vcpus_count, ram_mib as usize)
            .map_err(|e| VmmError::MissingConfig(e.to_string()))?;
        return Ok(Vmm {
            inner: VmmInner::Nitro(enclave),
            _lifetime: PhantomData,
        });
    }

    let device_manager = builder_cfg
        .device_manager
        .ok_or_else(|| VmmError::MissingConfig("no device manager set (call .devices())".into()))?;

    let mut vm_resources = VmResources::default();
    vm_resources
        .set_vm_config(&VmConfig {
            vcpu_count: Some(vcpus_count),
            mem_size_mib: Some(ram_mib as usize),
            ht_enabled: Some(false),
            cpu_template: None,
        })
        .map_err(|e| {
            log::error!("vm config: {e:?}");
            VmmError::InvalidParam()
        })?;

    match payload.kind {
        PayloadKind::Kernel { bundle } => {
            vm_resources.kernel_bundle = Some(bundle);
        }
        PayloadKind::External { kernel } => {
            vm_resources.external_kernel = Some(kernel);
        }
        PayloadKind::Firmware { path } => {
            vm_resources
                .set_firmware_config(crate::vmm::vmm_config::firmware::FirmwareConfig { path });
        }
        #[cfg(feature = "tee")]
        PayloadKind::Tee {
            bundle,
            qboot_bundle,
            initrd_bundle,
            tee_config_path,
            #[cfg(feature = "tdx")]
            firmware_path,
        } => {
            vm_resources.kernel_bundle = Some(bundle);
            if let Some(qboot_bundle) = qboot_bundle {
                vm_resources.set_qboot_bundle(qboot_bundle).map_err(|e| {
                    log::error!("qboot bundle: {e}");
                    VmmError::InvalidParam()
                })?;
            }
            #[cfg(feature = "tdx")]
            if let Some(path) = firmware_path {
                vm_resources.set_tee_firmware_config(
                    crate::vmm::vmm_config::firmware::TeeFirmwareConfig {
                        fw_type: crate::vmm::vmm_config::firmware::TeeFirmwareType::TdShim,
                        path,
                    },
                );
            }
            vm_resources.set_initrd_bundle(initrd_bundle);
            vm_resources.set_tee_config(tee_config_path).map_err(|e| {
                log::error!("tee config: {e:?}");
                VmmError::InvalidParam()
            })?;
        }
        #[cfg(feature = "aws-nitro")]
        PayloadKind::Nitro(_) => unreachable!("handled above"),
    }

    vm_resources.kernel_cmdline.prolog = Some(payload.cmdline);

    vm_resources.nested_enabled = builder_cfg.nested_virt;
    vm_resources.split_irqchip = builder_cfg.split_irqchip;
    if !builder_cfg.smbios_oem_strings.is_empty() {
        vm_resources.smbios_oem_strings = Some(builder_cfg.smbios_oem_strings);
    }

    if let Some(console) = builder_cfg.kernel_console {
        vm_resources.kernel_console = Some(console);
    }

    #[cfg(unix)]
    {
        vm_resources.serial_consoles = builder_cfg.serial_consoles;
    }

    let mut event_manager =
        EventManager::new().map_err(|e| VmmError::Internal(format!("{e:?}")))?;

    let (sender, receiver) = unbounded();

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    let shutdown_efd = if builder_cfg.shutdown_support {
        Some(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(|_| VmmError::ResourceAlloc())?)
    } else {
        None
    };
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    let _ = builder_cfg.shutdown_support;

    let inner = crate::vmm::builder::build_microvm(
        &vm_resources,
        &mut event_manager,
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        shutdown_efd
            .as_ref()
            .map(|efd| EventFd::try_clone(efd).expect("dup shutdown_efd")),
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        None,
        sender.clone(),
        device_manager,
    )
    .map_err(|e| VmmError::BootError(format!("{e:?}")))?;
    inner
        .lock()
        .map_err(|error| VmmError::Internal(error.to_string()))?
        .register_control_roles(&mut event_manager)
        .map_err(|error| VmmError::Internal(format!("{error:?}")))?;

    let needs_worker = {
        #[cfg(any(feature = "amd-sev", feature = "tdx"))]
        {
            true
        }
        #[cfg(not(any(feature = "amd-sev", feature = "tdx")))]
        {
            #[cfg(target_arch = "x86_64")]
            {
                builder_cfg.split_irqchip
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                false
            }
        }
    };

    if needs_worker {
        crate::vmm::worker::start_worker_thread(inner.clone(), receiver.clone())
            .map_err(|e| VmmError::Internal(format!("worker thread: {e}")))?;
    } else {
        let _ = receiver;
    }

    Ok(Vmm {
        inner: VmmInner::Vmm {
            vmm: inner,
            event_manager,
            _worker_sender: sender,
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd,
        },
        _lifetime: PhantomData,
    })
}
