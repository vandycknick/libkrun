// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::result;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::vmm::vmm_config::machine_config::CpuFeaturesTemplate;
use crate::vmm::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};

use arch::ArchMemoryInfo;
use arch::guest_memory::{RamLayout, RamPermissions, RamRegion, ReclaimError};
use crossbeam_channel::{Receiver, Sender, after, select, unbounded};
use devices::legacy::VcpuList;
use hvf::reclaim::{ReclaimState, ReclaimStateError};
use hvf::{HvfVcpu, HvfVm, VcpuExit, Vcpus};
use utils::eventfd::EventFd;
use vm_memory::{
    Address, GuestAddress, GuestMemoryBackend, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
};

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
#[allow(unused)]
pub enum Error {
    /// Invalid guest memory configuration.
    GuestMemoryMmap(GuestMemoryError),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    NotEnoughMemorySlots,
    /// Error configuring the general purpose aarch64 registers.
    REGSConfiguration(arch::aarch64::regs::Error),
    /// Cannot set the memory regions.
    SetUserMemoryRegion(hvf::Error),
    /// Cannot restore a partially initialized HVF memory map.
    MemoryMappingRollback(hvf::Error),
    /// Workload RAM does not match the authoritative architecture layout.
    ReclaimLayout(ReclaimError),
    /// The vCPU event channel was closed (the vCPU thread has exited).
    VcpuChannelClosed,
    /// Failed to signal Vcpu.
    SignalVcpu(utils::errno::Error),
    /// Error doing Vcpu Init on Arm.
    VcpuArmInit,
    /// Error getting the Vcpu preferred target on Arm.
    VcpuArmPreferredTarget,
    /// vCPU count is not initialized.
    VcpuCountNotInitialized,
    /// Cannot run the VCPUs.
    VcpuRun,
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    /// Cannot cleanly initialize vcpu TLS.
    VcpuTlsInit,
    /// Vcpu not present in TLS.
    VcpuTlsNotPresent,
    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,
    /// Cannot configure the microvm.
    VmSetup(hvf::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            GuestMemoryMmap(e) => write!(f, "Guest memory error: {e:?}"),
            VcpuCountNotInitialized => write!(f, "vCPU count is not initialized"),
            VmSetup(e) => write!(f, "Cannot configure the microvm: {e:?}"),
            VcpuRun => write!(f, "Cannot run the VCPUs"),
            NotEnoughMemorySlots => write!(
                f,
                "The number of configured slots is bigger than the maximum reported by KVM"
            ),
            SetUserMemoryRegion(e) => write!(f, "Cannot set the memory regions: {e:?}"),
            MemoryMappingRollback(e) => {
                write!(f, "Cannot roll back partially mapped guest memory: {e:?}")
            }
            ReclaimLayout(e) => write!(f, "Invalid workload RAM layout: {e}"),
            SignalVcpu(e) => write!(f, "Failed to signal Vcpu: {e}"),
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose aarch64 registers: {e:?}"
            ),
            VcpuSpawn(e) => write!(f, "Cannot spawn a new vCPU thread: {e}"),
            VcpuTlsInit => write!(f, "Cannot clean init vcpu TLS"),
            VcpuTlsNotPresent => write!(f, "Vcpu not present in TLS"),
            VcpuUnhandledKvmExit => write!(f, "Unexpected KVM_RUN exit reason"),
            VcpuArmPreferredTarget => write!(f, "Error getting the Vcpu preferred target on Arm"),
            VcpuArmInit => write!(f, "Error doing Vcpu Init on Arm"),
            VcpuChannelClosed => write!(f, "vCPU event channel closed"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// A wrapper around creating and using a VM.
pub struct Vm {
    hvf_vm: HvfVm,
    remapper: Option<Arc<hvf::remap::HostMemoryRemapper>>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(nested_enabled: bool) -> Result<Self> {
        let hvf_vm = HvfVm::new(nested_enabled).map_err(Error::VmSetup)?;

        Ok(Vm {
            hvf_vm,
            remapper: None,
        })
    }

    /// Initializes the guest memory.
    pub fn memory_init(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        reclaim_layout: RamLayout,
    ) -> Result<()> {
        if self.hvf_vm.reclaim_state().is_initialized() {
            return Err(Error::VmSetup(hvf::Error::ReclaimState(
                ReclaimStateError::AlreadyInitialized,
            )));
        }
        let mappings = memory_mappings(guest_mem)?;
        let mut mapped = Vec::new();
        for (host_addr, guest_start, len) in mappings {
            debug!(
                "Guest memory host_addr={:x?} guest_addr={:x?} len={:x?}",
                host_addr, guest_start, len
            );
            if let Err(error) = self.hvf_vm.map_memory(host_addr, guest_start, len) {
                self.rollback_memory_mappings(&mapped)?;
                return Err(Error::SetUserMemoryRegion(error));
            }
            mapped.push((guest_start, len));
        }

        self.hvf_vm
            .initialize_reclaim(reclaim_layout)
            .map_err(Error::VmSetup)?;
        self.remapper = hvf::remap::HostMemoryRemapper::new(self.reclaim_state()).map(Arc::new);
        Ok(())
    }

    pub fn host_memory_remapper(&self) -> Option<Arc<hvf::remap::HostMemoryRemapper>> {
        self.remapper.clone()
    }

    fn rollback_memory_mappings(&self, mapped: &[(u64, u64)]) -> Result<()> {
        let mut first_error = None;
        for (guest_start, len) in mapped.iter().rev() {
            if let Err(error) = self.hvf_vm.unmap_memory(*guest_start, *len)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(Error::MemoryMappingRollback(error)),
            None => Ok(()),
        }
    }

    pub fn add_mapping(
        &self,
        reply_sender: Sender<bool>,
        host_addr: u64,
        guest_addr: u64,
        len: u64,
    ) {
        debug!("add_mapping: host_addr={host_addr:x}, guest_addr={guest_addr:x}, len={len}");
        if let Err(e) = self.hvf_vm.unmap_memory(guest_addr, len) {
            error!("Error removing memory map: {e:?}");
        }

        if let Err(e) = self.hvf_vm.map_memory(host_addr, guest_addr, len) {
            error!("Error adding memory map: {e:?}");
            reply_sender.send(false).unwrap();
        } else {
            reply_sender.send(true).unwrap();
        }
    }

    pub fn remove_mapping(&self, reply_sender: Sender<bool>, guest_addr: u64, len: u64) {
        debug!("remove_mapping: guest_addr={guest_addr:x}, len={len}");
        if let Err(e) = self.hvf_vm.unmap_memory(guest_addr, len) {
            error!("Error removing memory map: {e:?}");
            reply_sender.send(false).unwrap();
        } else {
            reply_sender.send(true).unwrap();
        }
    }

    pub fn reclaim_state(&self) -> Arc<ReclaimState> {
        self.hvf_vm.reclaim_state()
    }

    pub fn configure_reclaim(
        &self,
        guest_mem: &GuestMemoryMmap,
        mem_info: &ArchMemoryInfo,
        requested: bool,
    ) -> Result<()> {
        let reclaim_state = self.hvf_vm.reclaim_state();
        reclaim_state.set_policy_enabled(requested);
        if !requested {
            return Ok(());
        }
        let mut occupied = Vec::with_capacity(guest_mem.num_regions() + 1);
        occupied.push(
            arch::guest_memory::GuestRange::new(0, mem_info.ram_start_addr)
                .map_err(Error::ReclaimLayout)?,
        );
        for region in guest_mem.iter() {
            occupied.push(
                arch::guest_memory::GuestRange::new(region.start_addr().raw_value(), region.len())
                    .map_err(Error::ReclaimLayout)?,
            );
        }
        self.hvf_vm
            .qualify_reclaim(&occupied, guest_mem.clone())
            .map_err(Error::VmSetup)
    }

    #[cfg(test)]
    pub fn destroy(self) -> Result<()> {
        self.hvf_vm.destroy().map_err(Error::VmSetup)
    }
}

fn memory_mappings(guest_mem: &GuestMemoryMmap) -> Result<Vec<(u64, u64, u64)>> {
    guest_mem
        .iter()
        .map(|region| {
            let host_addr = guest_mem
                .get_host_address(region.start_addr())
                .map_err(Error::GuestMemoryMmap)?;
            Ok((
                host_addr as u64,
                region.start_addr().raw_value(),
                region.len(),
            ))
        })
        .collect()
}

/// Describes the workload RAM the balloon may release. File-backed RAM is
/// mapped but never registered, so reclaim stays inert for it.
pub(crate) fn build_reclaim_layout(
    guest_mem: &GuestMemoryMmap,
    mem_info: &ArchMemoryInfo,
) -> Result<RamLayout> {
    let granule = u64::try_from(mem_info.page_size)
        .map_err(|_| Error::ReclaimLayout(ReclaimError::InvalidAlignment))?;
    let ram_len = mem_info
        .ram_last_addr
        .checked_sub(mem_info.ram_start_addr)
        .filter(|len| *len > 0)
        .ok_or(Error::ReclaimLayout(ReclaimError::EmptyRange))?;
    let ram_start = GuestAddress(mem_info.ram_start_addr);
    let memory_region = guest_mem
        .find_region(ram_start)
        .ok_or(Error::ReclaimLayout(ReclaimError::NotRam))?;
    let region_end = memory_region
        .start_addr()
        .raw_value()
        .checked_add(memory_region.len())
        .ok_or(Error::ReclaimLayout(ReclaimError::AddressOverflow))?;
    if memory_region.start_addr() != ram_start || region_end != mem_info.ram_last_addr {
        return Err(Error::ReclaimLayout(ReclaimError::NotRam));
    }
    let host_addr = guest_mem
        .get_host_address(ram_start)
        .map_err(Error::GuestMemoryMmap)?;
    let mut layout = RamLayout::new(granule).map_err(Error::ReclaimLayout)?;
    if memory_region.file_offset().is_some() {
        return Ok(layout);
    }
    layout
        .register_region(
            RamRegion::new(
                mem_info.ram_start_addr,
                host_addr as u64,
                ram_len,
                RamPermissions::READ_WRITE_EXECUTE,
            )
            .map_err(Error::ReclaimLayout)?,
        )
        .map_err(Error::ReclaimLayout)?;
    Ok(layout)
}

/// Encapsulates configuration parameters for the guest vCPUS.
#[derive(Debug, Eq, PartialEq)]
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    pub vcpu_count: u8,
    /// Enable hyperthreading in the CPUID configuration.
    pub ht_enabled: bool,
    /// CPUID template to use.
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

// Using this for easier explicit type-casting to help IDEs interpret the code.
type VcpuCell = Cell<Option<*const Vcpu>>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    id: u8,
    boot_entry_addr: u64,
    boot_receiver: Option<Receiver<u64>>,
    boot_senders: Option<HashMap<u64, Sender<u64>>>,
    fdt_addr: u64,
    mmio_bus: Option<devices::Bus>,
    #[cfg_attr(all(test, target_arch = "aarch64"), allow(unused))]
    exit_evt: EventFd,

    #[cfg(target_arch = "aarch64")]
    mpidr: u64,

    event_receiver: Receiver<VcpuEvent>,
    // The transmitting end of the events channel which will be given to the handler.
    event_sender: Option<Sender<VcpuEvent>>,
    // The receiving end of the responses channel which will be given to the handler.
    response_receiver: Option<Receiver<VcpuResponse>>,
    // The transmitting end of the responses channel owned by the vcpu side.
    response_sender: Sender<VcpuResponse>,

    vcpu_list: Arc<VcpuList>,
    reclaim_state: Arc<ReclaimState>,
    nested_enabled: bool,
}

impl Vcpu {
    thread_local!(static TLS_VCPU_PTR: VcpuCell = const { Cell::new(None) });

    /// Associates `self` with the current thread.
    ///
    /// It is a prerequisite to successfully run `init_thread_local_data()` before using
    /// `run_on_thread_local()` on the current thread.
    /// This function will return an error if there already is a `Vcpu` present in the TLS.
    fn init_thread_local_data(&mut self) -> Result<()> {
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if cell.get().is_some() {
                return Err(Error::VcpuTlsInit);
            }
            cell.set(Some(self as *const Vcpu));
            Ok(())
        })
    }

    /// Deassociates `self` from the current thread.
    ///
    /// Should be called if the current `self` had called `init_thread_local_data()` and
    /// now needs to move to a different thread.
    ///
    /// Fails if `self` was not previously associated with the current thread.
    fn reset_thread_local_data(&mut self) -> Result<()> {
        // Best-effort to clean up TLS. If the `Vcpu` was moved to another thread
        // _before_ running this, then there is nothing we can do.
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if let Some(vcpu_ptr) = cell.get()
                && std::ptr::eq(vcpu_ptr, self)
            {
                Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| cell.take());
                return Ok(());
            }
            Err(Error::VcpuTlsNotPresent)
        })
    }

    /// Registers a signal handler which makes use of TLS and kvm immediate exit to
    /// kick the vcpu running on the current thread, if there is one.
    pub fn register_kick_signal_handler() {
        /*
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            // This is safe because it's temporarily aliasing the `Vcpu` object, but we are
            // only reading `vcpu.fd` which does not change for the lifetime of the `Vcpu`.
            unsafe {
                let _ = Vcpu::run_on_thread_local(|_vcpu| {
                    vcpu.fd.set_kvm_immediate_exit(1);
                    fence(Ordering::Release);
                });
            }
        }
        */

        //register_signal_handler(sigrtmin() + VCPU_RTSIG_OFFSET, handle_signal)
        //    .expect("Failed to register vcpu signal handler");
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    pub fn new_aarch64(
        id: u8,
        boot_entry_addr: GuestAddress,
        boot_receiver: Option<Receiver<u64>>,
        exit_evt: EventFd,
        vcpu_list: Arc<VcpuList>,
        reclaim_state: Arc<ReclaimState>,
        nested_enabled: bool,
    ) -> Result<Self> {
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();

        Ok(Vcpu {
            id,
            boot_entry_addr: boot_entry_addr.raw_value(),
            boot_receiver,
            boot_senders: None,
            fdt_addr: 0,
            mmio_bus: None,
            exit_evt,
            mpidr: id as u64,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            vcpu_list,
            reclaim_state,
            nested_enabled,
        })
    }

    /// Returns the cpu index as seen by the guest OS.
    pub fn cpu_index(&self) -> u8 {
        self.id
    }

    /// Gets the MPIDR register value.
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    pub fn reclaim_state(&self) -> &Arc<ReclaimState> {
        &self.reclaim_state
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    pub fn set_boot_senders(&mut self, boot_senders: HashMap<u64, Sender<u64>>) {
        self.boot_senders = Some(boot_senders);
    }

    /// Configures an aarch64 specific vcpu.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The guest memory used by this microvm.
    pub fn configure_aarch64(&mut self, mem_info: &ArchMemoryInfo) -> Result<()> {
        self.fdt_addr = mem_info.fdt_addr;

        Ok(())
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().unwrap();
        let response_receiver = self.response_receiver.take().unwrap();
        let (init_tls_sender, init_tls_receiver) = unbounded();

        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || {
                self.init_thread_local_data()
                    .expect("Cannot cleanly initialize vcpu TLS.");

                self.run(init_tls_sender);
            })
            .map_err(Error::VcpuSpawn)?;

        let hvf_id = init_tls_receiver
            .recv()
            .expect("Error waiting for TLS initialization.");

        Ok(VcpuHandle::new(
            event_sender,
            response_receiver,
            hvf_id,
            vcpu_thread,
        ))
    }

    /// Returns error or enum specifying whether emulation was handled or interrupted.
    fn run_emulation(&mut self, hvf_vcpu: &mut HvfVcpu) -> Result<VcpuEmulation> {
        let vcpuid = hvf_vcpu.id();

        match hvf_vcpu.run(self.vcpu_list.clone(), &self.reclaim_state) {
            Ok(exit) => match exit {
                VcpuExit::Breakpoint => {
                    debug!("vCPU {vcpuid} breakpoint");
                    Ok(VcpuEmulation::Interrupted)
                }
                VcpuExit::Canceled => {
                    debug!("vCPU {vcpuid} canceled");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::CpuOn(mpidr, entry, context_id) => {
                    debug!("CpuOn: mpidr=0x{mpidr:x} entry=0x{entry:x} context_id={context_id}");
                    if let Some(boot_senders) = &self.boot_senders {
                        if let Some(sender) = boot_senders.get(&mpidr) {
                            sender.send(entry).unwrap()
                        }
                    } else {
                        error!("CpuOn request coming from an unexpected vCPU={}", self.id);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::HypervisorCall => {
                    debug!("vCPU {vcpuid} HVC");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioRead(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        debug!("vCPU {vcpuid} MMIO read 0x{addr:x}");
                        mmio_bus.read(vcpuid, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        mmio_bus.write(vcpuid, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MemoryRetry => Ok(VcpuEmulation::Handled),
                VcpuExit::PsciHandled => {
                    debug!("vCPU {vcpuid} PSCI");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::SecureMonitorCall => {
                    debug!("vCPU {vcpuid} SMC");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::Shutdown => {
                    info!("vCPU {vcpuid} received shutdown signal");
                    Ok(VcpuEmulation::Stopped)
                }
                VcpuExit::SystemRegister => {
                    debug!("vCPU {vcpuid} accessed a system register");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::VtimerActivated => {
                    debug!("vCPU {vcpuid} VtimerActivated");
                    self.vcpu_list.set_vtimer_irq(vcpuid);
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::WaitForEvent => {
                    debug!("vCPU {vcpuid} WaitForEvent");
                    Ok(VcpuEmulation::WaitForEvent)
                }
                VcpuExit::WaitForEventExpired => {
                    debug!("vCPU {vcpuid} WaitForEventExpired");
                    Ok(VcpuEmulation::WaitForEventExpired)
                }
                VcpuExit::WaitForEventTimeout(duration) => {
                    debug!("vCPU {vcpuid} WaitForEventTimeout timeout={duration:?}");
                    Ok(VcpuEmulation::WaitForEventTimeout(duration))
                }
            },
            Err(error) => {
                error!("Error running HVF vCPU {vcpuid}: {error:?}");
                Err(Error::VcpuRun)
            }
        }
    }

    /// Main loop of the vCPU thread.
    pub fn run(&mut self, init_tls_sender: Sender<u64>) {
        let mut hvf_vcpu =
            HvfVcpu::new(self.mpidr, self.nested_enabled).expect("Can't create HVF vCPU");
        let hvf_vcpuid = hvf_vcpu.id();

        // Report the HVF-assigned vCPU id (creation order is not deterministic)
        // so the coordinator can break this vCPU out of HVF to pause it.
        init_tls_sender
            .send(hvf_vcpuid)
            .expect("Cannot notify vcpu TLS initialization.");

        let (wfe_sender, wfe_receiver) = unbounded();
        self.vcpu_list.register(hvf_vcpuid, wfe_sender);

        let entry_addr = if let Some(boot_receiver) = &self.boot_receiver {
            boot_receiver.recv().unwrap()
        } else {
            self.boot_entry_addr
        };

        hvf_vcpu
            .set_initial_state(entry_addr, self.fdt_addr)
            .unwrap_or_else(|_| panic!("Can't set HVF vCPU {hvf_vcpuid} initial state"));

        loop {
            // An out-of-band pause request breaks the vCPU out of HVF via
            // `vcpu_request_exit` (-> Canceled), so we observe it here between
            // guest runs and freeze on this thread, where the HvfVcpu lives.
            if let Ok(VcpuEvent::Pause) = self.event_receiver.try_recv() {
                self.pause_and_park(&hvf_vcpu);
            }
            match self.run_emulation(&mut hvf_vcpu) {
                // Emulation ran successfully, continue.
                Ok(VcpuEmulation::Handled) => (),
                // Emulation was interrupted by a breakpoint.
                Ok(VcpuEmulation::Interrupted) => self.wait_for_resume(),
                // Wait for an external event.
                Ok(VcpuEmulation::WaitForEvent) => {
                    self.wait_for_event(hvf_vcpuid, &wfe_receiver, None, &hvf_vcpu)
                }
                Ok(VcpuEmulation::WaitForEventExpired) => (),
                Ok(VcpuEmulation::WaitForEventTimeout(timeout)) => {
                    self.wait_for_event(hvf_vcpuid, &wfe_receiver, Some(timeout), &hvf_vcpu)
                }
                // The guest was rebooted or halted.
                Ok(VcpuEmulation::Stopped) => {
                    self.exit(FC_EXIT_CODE_OK);
                    break;
                }
                // Emulation errors lead to vCPU exit.
                Err(_) => {
                    self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                    break;
                }
            }
        }
    }

    /// Park until woken by a device IRQ (`receiver`), the optional vtimer
    /// `timeout`, or an out-of-band [`VcpuEvent::Pause`]. Watching the pause
    /// channel here too is load-bearing: an idle vCPU blocks in this recv (not
    /// in HVF), so `vcpu_request_exit` can't break it out — without this arm a
    /// pause request would hang forever.
    fn wait_for_event(
        &mut self,
        hvf_vcpuid: u64,
        receiver: &Receiver<u32>,
        timeout: Option<Duration>,
        hvf_vcpu: &HvfVcpu,
    ) {
        if !self.vcpu_list.should_wait(hvf_vcpuid) {
            return;
        }
        let paused = if let Some(timeout) = timeout {
            select! {
                recv(receiver) -> r => { r.expect("WFE channel closed unexpectedly"); false }
                recv(self.event_receiver) -> ev => matches!(ev, Ok(VcpuEvent::Pause)),
                recv(after(timeout)) -> _ => false,
            }
        } else {
            select! {
                recv(receiver) -> r => { r.expect("WFE channel closed unexpectedly"); false }
                recv(self.event_receiver) -> ev => matches!(ev, Ok(VcpuEvent::Pause)),
            }
        };
        if paused {
            self.pause_and_park(hvf_vcpu);
        }
    }

    fn wait_for_resume(&mut self) {}

    /// Freeze this vCPU in response to a `Pause` event and block until `Resume`,
    /// which carries the paused tick count. Advancing the vtimer offset by it
    /// keeps the guest's CNTVCT continuous so armed timers don't fire en masse
    /// to catch up the gap. The coordinator computes the tick count once for the
    /// whole VM, so multi-vCPU offsets stay in lockstep.
    fn pause_and_park(&mut self, hvf_vcpu: &HvfVcpu) {
        self.response_sender
            .send(VcpuResponse::Paused)
            .expect("failed to send Paused status");
        loop {
            match self.event_receiver.recv() {
                Ok(VcpuEvent::Resume(paused_ticks)) => {
                    hvf_vcpu
                        .advance_vtimer_offset(paused_ticks)
                        .unwrap_or_else(|e| {
                            panic!("vCPU {} vtimer advance failed: {e:?}", self.id)
                        });
                    self.response_sender
                        .send(VcpuResponse::Resumed)
                        .expect("failed to send Resumed status");
                    return;
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    }

    fn exit(&mut self, exit_code: u8) {
        self.response_sender
            .send(VcpuResponse::Exited(exit_code))
            .expect("failed to send Exited status");

        if let Err(e) = self.exit_evt.write(1) {
            error!("Failed signaling vcpu exit event: {e}");
        }
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        let _ = self.reset_thread_local_data();
    }
}

#[derive(Debug)]
/// List of events that the Vcpu can receive.
pub enum VcpuEvent {
    /// Pause the Vcpu.
    Pause,
    /// Resume the Vcpu, advancing its vtimer offset by this many host ticks
    /// (the wall-clock time the VM spent paused). The coordinator sends the
    /// same value to every vCPU so their counters stay synchronized.
    Resume(u64),
}

#[derive(Debug, Eq, PartialEq)]
/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu is stopped.
    Exited(u8),
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
pub struct VcpuHandle {
    event_sender: Sender<VcpuEvent>,
    response_receiver: Receiver<VcpuResponse>,
    hvf_id: u64,
}

impl VcpuHandle {
    pub fn new(
        event_sender: Sender<VcpuEvent>,
        response_receiver: Receiver<VcpuResponse>,
        hvf_id: u64,
        _vcpu_thread: thread::JoinHandle<()>,
    ) -> Self {
        Self {
            event_sender,
            response_receiver,
            hvf_id,
        }
    }

    /// HVF-assigned vCPU id, reported by the thread at boot. Used to break the
    /// vCPU out of HVF (`vcpu_request_exit`) when pausing.
    pub fn hvf_id(&self) -> u64 {
        self.hvf_id
    }

    pub fn send_event(&self, event: VcpuEvent) -> Result<()> {
        self.event_sender
            .send(event)
            .map_err(|_| Error::VcpuChannelClosed)
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
    WaitForEvent,
    WaitForEventExpired,
    WaitForEventTimeout(Duration),
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use crossbeam_channel::RecvTimeoutError;
    use std::sync::Arc;
    #[cfg(target_arch = "x86_64")]
    use std::time::Duration;

    use crate::vmm::macos::vstate::{Vcpu, Vm, build_reclaim_layout, memory_mappings};
    #[cfg(target_arch = "x86_64")]
    use crate::vmm::macos::vstate::{VcpuEvent, VcpuHandle, VcpuResponse};
    use arch::ArchMemoryInfo;
    use arch::aarch64::layout::DRAM_MEM_START_EFI;
    use devices::legacy::VcpuList;
    use hvf::reclaim::{ReclaimState, ReclaimStateError};
    use utils::eventfd::EventFd;
    use vm_memory::{FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

    // Auxiliary function being used throughout the tests.
    // Does NOT create a real HVF VM — Vcpu::new_aarch64 and most vcpu methods
    // work without one, keeping tests free from the one-VM-per-process limit.
    fn setup_vcpu(mem_size: usize) -> (Vcpu, GuestMemoryMmap) {
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let vcpu_list = Arc::new(VcpuList::new(1));
        let reclaim_state = Arc::new(ReclaimState::new());
        let vcpu = Vcpu::new_aarch64(
            1,
            GuestAddress(0),
            None,
            exit_evt,
            vcpu_list,
            reclaim_state,
            false,
        )
        .unwrap();
        (vcpu, gm)
    }

    #[test]
    fn test_set_mmio_bus() {
        let (mut vcpu, _) = setup_vcpu(0x1000);
        assert!(vcpu.mmio_bus.is_none());
        vcpu.set_mmio_bus(devices::Bus::new());
        assert!(vcpu.mmio_bus.is_some());
    }

    #[test]
    fn test_vcpu_owns_shared_reclaim_state() {
        let state = Arc::new(ReclaimState::new());
        let vcpu = Vcpu::new_aarch64(
            0,
            GuestAddress(0),
            None,
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            Arc::new(VcpuList::new(1)),
            Arc::clone(&state),
            false,
        )
        .unwrap();

        assert!(Arc::ptr_eq(vcpu.reclaim_state(), &state));
    }

    #[test]
    fn test_reclaim_layout_excludes_shm_region() {
        let ram_start = DRAM_MEM_START_EFI;
        let ram_len = 0x8000;
        let shm_start = ram_start + 0x1_0000;
        let guest_mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(ram_start), ram_len),
            (GuestAddress(shm_start), 0x4000),
        ])
        .unwrap();
        let mem_info = ArchMemoryInfo {
            ram_start_addr: ram_start,
            ram_last_addr: ram_start + ram_len as u64,
            shm_start_addr: shm_start,
            page_size: 0x4000,
            ..ArchMemoryInfo::default()
        };

        let layout = build_reclaim_layout(&guest_mem, &mem_info).unwrap();
        assert_eq!(layout.granule(), 0x4000);
        assert!(layout.region_containing(ram_start).is_some());
        assert!(layout.region_containing(shm_start).is_none());
    }

    #[test]
    fn test_file_backed_ram_is_mapped_but_not_reclaimable() {
        let ram_start = DRAM_MEM_START_EFI;
        let ram_len = 0x4000;
        let path = std::env::temp_dir().join(format!(
            "libkrun-reclaim-file-backed-{}",
            std::process::id()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(ram_len as u64).unwrap();
        std::fs::remove_file(path).unwrap();
        let guest_mem = GuestMemoryMmap::from_ranges_with_files(&[(
            GuestAddress(ram_start),
            ram_len,
            Some(FileOffset::new(file, 0)),
        )])
        .unwrap();
        let mem_info = ArchMemoryInfo {
            ram_start_addr: ram_start,
            ram_last_addr: ram_start + ram_len as u64,
            page_size: 0x4000,
            ..ArchMemoryInfo::default()
        };

        let layout = build_reclaim_layout(&guest_mem, &mem_info).unwrap();
        assert!(!layout.has_registered_regions());
        assert!(layout.region_containing(ram_start).is_none());
        let mappings = memory_mappings(&guest_mem).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].1, ram_start);
        assert_eq!(mappings[0].2, ram_len as u64);
    }

    #[test]
    fn test_vm_memory_init_rejects_duplicate_before_mapping() {
        let mut vm = Vm::new(false).expect("Cannot create new vm");

        // Use a realistic guest physical address; hv_vm_map rejects GPA 0.
        let first_gpa = DRAM_MEM_START_EFI;
        let len = 0x20_0000;
        let gm = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(first_gpa),
            len, // 2 MB
        )])
        .unwrap();
        let mem_info = ArchMemoryInfo {
            ram_start_addr: first_gpa,
            ram_last_addr: first_gpa + len as u64,
            page_size: 0x4000,
            ..ArchMemoryInfo::default()
        };
        let reclaim_layout = build_reclaim_layout(&gm, &mem_info).expect("invalid RAM layout");
        vm.memory_init(&gm, reclaim_layout)
            .expect("memory_init failed");

        let second_gpa = first_gpa + 0x40_0000;
        let second_gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(second_gpa), len)]).unwrap();
        let second_mem_info = ArchMemoryInfo {
            ram_start_addr: second_gpa,
            ram_last_addr: second_gpa + len as u64,
            page_size: 0x4000,
            ..ArchMemoryInfo::default()
        };
        let second_layout =
            build_reclaim_layout(&second_gm, &second_mem_info).expect("invalid second RAM layout");
        assert!(matches!(
            vm.memory_init(&second_gm, second_layout),
            Err(crate::vmm::macos::vstate::Error::VmSetup(
                hvf::Error::ReclaimState(ReclaimStateError::AlreadyInitialized)
            ))
        ));

        let first_host = gm
            .get_host_address(GuestAddress(first_gpa))
            .expect("first host mapping is unavailable");
        assert!(matches!(
            vm.hvf_vm
                .map_memory(first_host as u64, first_gpa, len as u64),
            Err(hvf::Error::MemoryMap)
        ));
        let second_host = second_gm
            .get_host_address(GuestAddress(second_gpa))
            .expect("second host mapping is unavailable");
        vm.hvf_vm
            .map_memory(second_host as u64, second_gpa, len as u64)
            .expect("duplicate initialization mapped the second range");
        vm.hvf_vm
            .unmap_memory(second_gpa, len as u64)
            .expect("failed to clean up second mapping");

        vm.hvf_vm
            .unmap_memory(first_gpa, len as u64)
            .expect("first mapping was removed by duplicate initialization");
    }

    #[test]
    fn test_configure_vcpu() {
        // configure_aarch64 only sets fdt_addr — no HVF VM needed.
        let mem_info = arch::ArchMemoryInfo::default();

        // Try it for when vcpu id is 0.
        let vcpu_list = Arc::new(VcpuList::new(1));
        let reclaim_state = Arc::new(ReclaimState::new());
        let mut vcpu = Vcpu::new_aarch64(
            0,
            GuestAddress(0),
            None,
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            vcpu_list,
            reclaim_state,
            false,
        )
        .unwrap();
        assert!(vcpu.configure_aarch64(&mem_info).is_ok());

        // Try it for when vcpu id is NOT 0.
        let vcpu_list = Arc::new(VcpuList::new(2));
        let reclaim_state = Arc::new(ReclaimState::new());
        let mut vcpu = Vcpu::new_aarch64(
            1,
            GuestAddress(0),
            None,
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            vcpu_list,
            reclaim_state,
            false,
        )
        .unwrap();
        assert!(vcpu.configure_aarch64(&mem_info).is_ok());
    }

    #[test]
    fn test_vcpu_tls() {
        let (mut vcpu, _) = setup_vcpu(0x1000);

        // Reset should fail before TLS is initialized.
        assert!(vcpu.reset_thread_local_data().is_err());

        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();

        // Reset vcpu TLS.
        assert!(vcpu.reset_thread_local_data().is_ok());

        // Second reset should return error.
        assert!(vcpu.reset_thread_local_data().is_err());
    }

    #[test]
    fn test_invalid_tls() {
        let (mut vcpu, _) = setup_vcpu(0x1000);
        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();
        // Trying to initialize non-empty TLS should error.
        vcpu.init_thread_local_data().unwrap_err();
    }

    #[cfg(target_arch = "x86_64")]
    // Sends an event to a vcpu and expects a particular response.
    fn queue_event_expect_response(handle: &VcpuHandle, event: VcpuEvent, response: VcpuResponse) {
        handle
            .send_event(event)
            .expect("failed to send event to vcpu");
        assert_eq!(
            handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(100))
                .expect("did not receive event response from vcpu"),
            response
        );
    }

    #[cfg(target_arch = "x86_64")]
    // Sends an event to a vcpu and expects no response.
    fn queue_event_expect_timeout(handle: &VcpuHandle, event: VcpuEvent) {
        handle
            .send_event(event)
            .expect("failed to send event to vcpu");
        assert_eq!(
            handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(100)),
            Err(RecvTimeoutError::Timeout)
        );
    }
}
