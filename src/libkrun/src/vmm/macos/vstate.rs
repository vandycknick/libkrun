// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::result;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::api::capabilities::{HvfGicModel, HvfVmFacts, Observation};
use crate::vmm::control::RequestId;
use crate::vmm::control::{CpuAck, CpuAckKind, CpuCommand, CpuCommandKind, CpuSubmission};
use crate::vmm::execution::{CpuExecutionInput, CpuExecutionState, CpuTimePlan};
use crate::vmm::vmm_config::machine_config::CpuFeaturesTemplate;
use crate::vmm::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};
use hvf::state::{CpuDisposition, CpuOn};

use arch::ArchMemoryInfo;
use arch::guest_memory::{
    BackingKind, ConstructionAuthority, CpuHarvest, CpuTrackingEpoch, DirtyEffect, DirtyFailure,
    DirtyLocation, DirtyOperation, DirtyPageMap, MemoryCut, MemoryDomain, RamLayout,
    RamPermissions, RamRegion, ReclaimError, TrackingMode,
};
use crossbeam_channel::{Receiver, Sender, TryRecvError, after, never, select, unbounded};
use devices::legacy::VcpuList;
use hvf::reclaim::{ReclaimInhibition, ReclaimState, ReclaimStateError};
use hvf::{HvfVcpu, HvfVm, VcpuExit, Vcpus};
use polly::event_manager::{BarrierGeneration, BarrierKey, OperationId};
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
    MemoryMappingRollback {
        primary: hvf::Error,
        cleanup: hvf::Error,
    },
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
    VcpuRun(hvf::Error),
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    VcpuResourcesMissing,
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
            VcpuRun(error) => write!(f, "Cannot run the VCPUs: {error}"),
            NotEnoughMemorySlots => write!(
                f,
                "The number of configured slots is bigger than the maximum reported by KVM"
            ),
            SetUserMemoryRegion(e) => write!(f, "Cannot set the memory regions: {e:?}"),
            MemoryMappingRollback { primary, cleanup } => {
                write!(
                    f,
                    "Cannot map guest RAM: {primary}; rollback also failed: {cleanup}"
                )
            }
            ReclaimLayout(e) => write!(f, "Invalid workload RAM layout: {e}"),
            SignalVcpu(e) => write!(f, "Failed to signal Vcpu: {e}"),
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose aarch64 registers: {e:?}"
            ),
            VcpuSpawn(e) => write!(f, "Cannot spawn a new vCPU thread: {e}"),
            VcpuResourcesMissing => write!(f, "vCPU startup requires owned VM and RAM resources"),
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
    live_facts: HvfVmFacts,
    pending_reclaim: Option<RamLayout>,
    memory_domain: Option<Arc<MemoryDomain>>,
    registered_memory: Option<GuestMemoryMmap>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(nested_enabled: bool) -> Result<Self> {
        let hvf_vm = HvfVm::new(nested_enabled).map_err(Error::VmSetup)?;

        Ok(Vm {
            hvf_vm,
            remapper: None,
            pending_reclaim: None,
            memory_domain: None,
            registered_memory: None,
            live_facts: HvfVmFacts {
                gic_model: Observation::NotEvaluated,
                nested: nested_enabled,
            },
        })
    }

    pub fn framework(&self) -> Arc<hvf::framework::HvfFramework> {
        self.hvf_vm.framework()
    }

    pub fn record_gic_model(&mut self, model: HvfGicModel) {
        self.live_facts.gic_model = Observation::Observed(model);
    }

    pub fn live_facts(&self) -> HvfVmFacts {
        self.live_facts
    }
    /// Initializes the guest memory.
    pub fn memory_init(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        reclaim_layout: RamLayout,
    ) -> Result<()> {
        if self.pending_reclaim.is_some() || self.hvf_vm.reclaim_state().is_initialized() {
            return Err(Error::VmSetup(hvf::Error::ReclaimState(
                ReclaimStateError::AlreadyInitialized,
            )));
        }
        let mappings = memory_mappings(guest_mem)?;
        self.hvf_vm
            .retain_memory_backing(guest_mem.clone())
            .map_err(Error::VmSetup)?;
        self.registered_memory = Some(guest_mem.clone());
        self.pending_reclaim = Some(reclaim_layout);
        self.hvf_vm
            .ram_protection()
            .reserve_mappings(mappings.len())
            .map_err(|error| Error::VmSetup(hvf::Error::DirtyTracking(error)))?;
        let mut mapped = Vec::with_capacity(mappings.len());
        for (host_addr, guest_start, len) in mappings {
            debug!(
                "Guest memory host_addr={:x?} guest_addr={:x?} len={:x?}",
                host_addr, guest_start, len
            );
            if let Err(error) = self.hvf_vm.map_memory(host_addr, guest_start, len) {
                if let Err(cleanup) = self.rollback_memory_mappings(&mapped) {
                    return Err(Error::MemoryMappingRollback {
                        primary: error,
                        cleanup,
                    });
                }
                return Err(Error::SetUserMemoryRegion(error));
            }
            mapped.push((guest_start, len));
        }

        Ok(())
    }

    pub fn bind_memory_domain(
        &mut self,
        domain: Arc<MemoryDomain>,
    ) -> std::result::Result<(), DirtyFailure> {
        if self
            .registered_memory
            .as_ref()
            .is_none_or(|memory| !domain.matches_mapping(memory))
        {
            return Err(DirtyFailure {
                operation: DirtyOperation::Bind,
                location: DirtyLocation::Vm,
                native_code: 0,
                effect: DirtyEffect::PreEffectRefusal,
            });
        }
        self.hvf_vm.bind_memory_domain(Arc::clone(&domain))?;
        self.memory_domain = Some(domain);
        Ok(())
    }

    pub fn arm_initial(
        &mut self,
        authority: &ConstructionAuthority,
    ) -> std::result::Result<CpuTrackingEpoch, DirtyFailure> {
        self.hvf_vm.ram_protection().arm_initial(authority)
    }

    pub fn collect_cpu_dirty(
        &mut self,
        cut: &MemoryCut,
        retained: &mut DirtyPageMap,
    ) -> std::result::Result<CpuHarvest, DirtyFailure> {
        self.hvf_vm
            .ram_protection()
            .collect_cpu_dirty(cut, retained)
    }

    pub fn rearm_cpu_dirty(
        &mut self,
        cut: &MemoryCut,
        harvested: CpuHarvest,
    ) -> std::result::Result<CpuTrackingEpoch, DirtyFailure> {
        self.hvf_vm.ram_protection().rearm_cpu_dirty(cut, harvested)
    }

    pub fn reestablish_cpu_dirty(
        &mut self,
        cut: &MemoryCut,
        retained: &mut DirtyPageMap,
    ) -> std::result::Result<CpuTrackingEpoch, DirtyFailure> {
        self.hvf_vm
            .ram_protection()
            .reestablish_cpu_dirty(cut, retained)
    }

    pub fn host_memory_remapper(&self) -> Option<Arc<hvf::remap::HostMemoryRemapper>> {
        self.remapper.clone()
    }

    fn rollback_memory_mappings(
        &self,
        mapped: &[(u64, u64)],
    ) -> std::result::Result<(), hvf::Error> {
        let mut first_error = None;
        for (guest_start, len) in mapped.iter().rev() {
            if let Err(error) = self.hvf_vm.unmap_memory(*guest_start, *len)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
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
        if let Err(error) = self.hvf_vm.ram_protection().check_mapping_mutation() {
            error!("Refusing tracked mapping replacement: {error:?}");
            let _ = reply_sender.send(false);
            return;
        }
        if self
            .memory_domain
            .as_ref()
            .is_some_and(|domain| domain.with_external_mapping(|_| ()).is_err())
        {
            let _ = reply_sender.send(false);
            return;
        }
        if let Err(e) = self.hvf_vm.unmap_memory(guest_addr, len) {
            error!("Error removing memory map: {e:?}");
        }

        if let Err(e) = self.hvf_vm.map_memory(host_addr, guest_addr, len) {
            error!("Error adding memory map: {e:?}");
            let _ = reply_sender.send(false);
        } else {
            let _ = reply_sender.send(true);
        }
    }

    pub fn remove_mapping(&self, reply_sender: Sender<bool>, guest_addr: u64, len: u64) {
        debug!("remove_mapping: guest_addr={guest_addr:x}, len={len}");
        if let Err(error) = self.hvf_vm.ram_protection().check_mapping_mutation() {
            error!("Refusing tracked mapping removal: {error:?}");
            let _ = reply_sender.send(false);
            return;
        }
        if self
            .memory_domain
            .as_ref()
            .is_some_and(|domain| domain.with_external_mapping(|_| ()).is_err())
        {
            let _ = reply_sender.send(false);
            return;
        }
        if let Err(e) = self.hvf_vm.unmap_memory(guest_addr, len) {
            error!("Error removing memory map: {e:?}");
            let _ = reply_sender.send(false);
        } else {
            let _ = reply_sender.send(true);
        }
    }

    pub fn reclaim_state(&self) -> Arc<ReclaimState> {
        self.hvf_vm.reclaim_state()
    }

    pub fn configure_reclaim(&mut self, mem_info: &ArchMemoryInfo, requested: bool) -> Result<()> {
        let reclaim_state = self.hvf_vm.reclaim_state();
        let domain = self
            .memory_domain
            .as_ref()
            .ok_or(Error::VmSetup(hvf::Error::InvalidMemoryFault))?;
        let guest_mem = self
            .registered_memory
            .as_ref()
            .ok_or(Error::VmSetup(hvf::Error::InvalidMemoryFault))?;
        let layout =
            self.pending_reclaim
                .take()
                .ok_or(Error::VmSetup(hvf::Error::ReclaimState(
                    ReclaimStateError::AlreadyInitialized,
                )))?;
        let reason = match (domain.backing_kind(), domain.tracking_mode()) {
            (BackingKind::RestoredPrivate, Some(TrackingMode::Capture)) => {
                Some(ReclaimInhibition::RestoredPrivateMapping)
            }
            (_, Some(TrackingMode::Capture)) => Some(ReclaimInhibition::TrackedCapture),
            (BackingKind::Boot, Some(TrackingMode::Disabled)) => None,
            _ => return Err(Error::VmSetup(hvf::Error::InvalidMemoryFault)),
        };
        if let Some(reason) = reason {
            reclaim_state
                .initialize_inhibited(u64::from(domain.layout().granule()), reason)
                .map_err(|error| Error::VmSetup(hvf::Error::ReclaimState(error)))?;
            return Ok(());
        }
        self.hvf_vm
            .initialize_reclaim(layout)
            .map_err(Error::VmSetup)?;
        self.remapper =
            hvf::remap::HostMemoryRemapper::new(Arc::clone(&reclaim_state)).map(Arc::new);
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

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    id: u8,
    boot_entry_addr: u64,
    boot_receiver: Option<Receiver<CpuOn>>,
    boot_senders: Option<HashMap<u64, Sender<CpuOn>>>,
    fdt_addr: u64,
    mmio_bus: Option<devices::Bus>,
    exit_evt: EventFd,

    mpidr: u64,

    event_receiver: Receiver<CpuCommand>,
    event_sender: Option<Sender<CpuCommand>>,
    // The receiving end of the responses channel which will be given to the handler.
    response_receiver: Option<Receiver<VcpuResponse>>,
    // The transmitting end of the responses channel owned by the vcpu side.
    response_sender: Sender<VcpuResponse>,
    control_receiver: Option<Receiver<CpuAck>>,
    control_sender: Sender<CpuAck>,
    _resources: Option<hvf::HvfCpuResources>,
    memory_domain: Option<Arc<MemoryDomain>>,

    vcpu_list: Arc<VcpuList>,
    reclaim_state: Arc<ReclaimState>,
    nested_enabled: bool,
    restore_prepared: bool,
}

impl Vcpu {
    pub fn retain_resources(&mut self, vm: &Vm) -> Result<()> {
        let domain = vm
            .memory_domain
            .as_ref()
            .ok_or(Error::VcpuResourcesMissing)?;
        let memory = vm
            .registered_memory
            .as_ref()
            .ok_or(Error::VcpuResourcesMissing)?;
        if !domain.matches_mapping(memory) {
            return Err(Error::VcpuResourcesMissing);
        }
        self._resources = Some(vm.hvf_vm.cpu_resources());
        self.memory_domain = Some(Arc::clone(domain));
        Ok(())
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
        boot_receiver: Option<Receiver<CpuOn>>,
        exit_evt: EventFd,
        vcpu_list: Arc<VcpuList>,
        reclaim_state: Arc<ReclaimState>,
        nested_enabled: bool,
    ) -> Result<Self> {
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();
        let (control_sender, control_receiver) = unbounded();

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
            control_receiver: Some(control_receiver),
            control_sender,
            _resources: None,
            memory_domain: None,
            vcpu_list,
            reclaim_state,
            nested_enabled,
            restore_prepared: false,
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

    pub fn set_boot_senders(&mut self, boot_senders: HashMap<u64, Sender<CpuOn>>) {
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

    pub fn prepare_restore(&mut self, state: &hvf::state::CpuState) -> Result<()> {
        state
            .validate()
            .map_err(|error| Error::VmSetup(hvf::Error::ExecutionState(error)))?;
        if state.logical_id != self.id || self.nested_enabled {
            return Err(Error::VmSetup(hvf::Error::ExecutionState(
                hvf::state::StateError("restore CPU identity or nested profile"),
            )));
        }
        self.mpidr = state.mpidr;
        self.restore_prepared = true;
        Ok(())
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self) -> Result<VcpuHandle> {
        if self._resources.is_none()
            || self
                .memory_domain
                .as_ref()
                .is_none_or(|domain| domain.tracking_mode().is_none())
        {
            return Err(Error::VcpuResourcesMissing);
        }
        let event_sender = self.event_sender.take().ok_or(Error::VcpuChannelClosed)?;
        let response_receiver = self
            .response_receiver
            .take()
            .ok_or(Error::VcpuChannelClosed)?;
        let control_receiver = self
            .control_receiver
            .take()
            .ok_or(Error::VcpuChannelClosed)?;
        let (ready_sender, ready_receiver) = unbounded();
        let cpu_id = self.id;
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || self.run(ready_sender))
            .map_err(Error::VcpuSpawn)?;
        let (hvf_id, startup_error) = ready_receiver.recv().unwrap_or_else(|_| {
            (
                None,
                Some("HVF vCPU initialization channel closed".to_owned()),
            )
        });
        Ok(VcpuHandle {
            event_sender,
            response_receiver,
            control_receiver,
            hvf_id,
            cpu_id,
            startup_error,
            vcpu_thread: Some(vcpu_thread),
        })
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
                            sender
                                .send(CpuOn {
                                    entry,
                                    context: context_id,
                                })
                                .map_err(|_| Error::VcpuChannelClosed)?;
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
                Err(Error::VcpuRun(error))
            }
        }
    }

    fn run(&mut self, ready_sender: Sender<(Option<u64>, Option<String>)>) {
        let Some(resources) = &self._resources else {
            let _ = ready_sender.send((None, Some("HVF vCPU resources missing".to_owned())));
            return;
        };
        let protection = resources.ram_protection();
        let mut hvf_vcpu = match HvfVcpu::new(self.nested_enabled, protection) {
            Ok(cpu) => cpu,
            Err(error) => {
                let _ = ready_sender.send((None, Some(format!("CPU {} create: {error}", self.id))));
                self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                return;
            }
        };
        let hvf_id = hvf_vcpu.id();
        let (wfe_sender, wfe_receiver) = unbounded();
        if let Err(error) = self.vcpu_list.register_owner(self.id, hvf_id, wfe_sender) {
            let _ = ready_sender.send((Some(hvf_id), Some(error.to_string())));
            return;
        }
        let mut initialized = self.boot_receiver.is_none();
        let startup_error = hvf_vcpu
            .initialize(self.mpidr)
            .and_then(|()| {
                if initialized && !self.restore_prepared {
                    hvf_vcpu.set_initial_state(self.boot_entry_addr, self.fdt_addr)
                } else {
                    Ok(())
                }
            })
            .err()
            .map(|error| format!("CPU {} initialize: {error}", self.id));
        let mut terminal_fault = startup_error.clone();
        let _ = ready_sender.send((Some(hvf_id), startup_error));
        let mut parked = true;
        let mut key = BarrierKey {
            operation: OperationId(0),
            generation: BarrierGeneration(0),
        };
        let mut timer_plan = hvf::VtimerResume::new(hvf_vcpu.vtimer_offset());
        let mut prepared = None;
        let mut completion_failed = false;
        let mut waiting: Option<Option<Duration>> = None;
        let framework = match &self._resources {
            Some(resources) => resources.framework(),
            None => return,
        };
        let mut captured: Option<Arc<CpuExecutionState>> = None;
        let mut installed: Option<Arc<CpuExecutionInput>> = None;
        let mut installed_time: Option<(BarrierKey, Arc<CpuExecutionInput>)> = None;
        let mut pending_cpu_on: Option<CpuOn> = None;
        let mut capture_request: Option<RequestId> = None;

        loop {
            let command = match self.event_receiver.try_recv() {
                Ok(command) => Some(command),
                Err(TryRecvError::Disconnected) => {
                    if let Err(error) = hvf_vcpu.destroy() {
                        log::error!("CPU {} disconnected cleanup: {error}", self.id);
                        thread::park();
                        continue;
                    }
                    return;
                }
                Err(TryRecvError::Empty) if parked => self.event_receiver.recv().ok(),
                Err(TryRecvError::Empty) if !initialized && pending_cpu_on.is_some() => {
                    if let Some(start) = pending_cpu_on.take() {
                        match hvf_vcpu
                            .set_initial_state(start.entry, self.fdt_addr)
                            .and_then(|()| hvf_vcpu.write_reg(0, start.context))
                        {
                            Ok(()) => initialized = true,
                            Err(error) => {
                                parked = true;
                                terminal_fault = Some(error.to_string());
                            }
                        }
                    }
                    None
                }
                Err(TryRecvError::Empty) if !initialized => {
                    let boot = self.boot_receiver.as_ref().cloned().unwrap_or_else(never);
                    select! {
                        recv(self.event_receiver) -> command => command.ok(),
                        recv(boot) -> entry => {
                            match entry {
                                Ok(start) => match hvf_vcpu.set_initial_state(start.entry, self.fdt_addr)
                                    .and_then(|()| hvf_vcpu.write_reg(0, start.context)) {
                                    Ok(()) => initialized = true,
                                    Err(error) => {
                                        log::error!("CPU {} CPU_ON: {error}", self.id);
                                        parked = true;
                                        completion_failed = true;
                                        terminal_fault = Some(error.to_string());
                                        self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                                    }
                                },
                                Err(_) => {
                                    parked = true;
                                    completion_failed = true;
                                    terminal_fault = Some("HVF CPU_ON channel closed".to_owned());
                                    self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                                }
                            }
                            None
                        }
                    }
                }
                Err(TryRecvError::Empty) => {
                    if let Some(timeout) = waiting
                        && self.vcpu_list.should_wait(hvf_id)
                    {
                        let timer = timeout.map(after).unwrap_or_else(never);
                        let started = Instant::now();
                        select! {
                            recv(self.event_receiver) -> command => {
                                if let Some(Some(remaining)) = waiting.as_mut() {
                                    *remaining = remaining.saturating_sub(started.elapsed());
                                }
                                command.ok()
                            },
                            recv(wfe_receiver) -> wake => {
                                waiting = None;
                                if wake.is_err() {
                                    parked = true;
                                    completion_failed = true;
                                    terminal_fault = Some("HVF WFE channel closed".to_owned());
                                    self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                                }
                                None
                            },
                            recv(timer) -> _ => { waiting = None; None }
                        }
                    } else {
                        waiting = None;
                        None
                    }
                }
            };
            if let Some(mut command) = command {
                let ack_kind = match command.kind {
                    CpuCommandKind::Park => CpuAckKind::Parked,
                    CpuCommandKind::PrepareResume { .. } => CpuAckKind::Prepared,
                    CpuCommandKind::Release => CpuAckKind::Released,
                    CpuCommandKind::Stop => CpuAckKind::Stopped,
                    CpuCommandKind::CaptureExecution => CpuAckKind::Captured,
                    CpuCommandKind::InstallExecution => CpuAckKind::Installed,
                    CpuCommandKind::PrepareExecutionTime => CpuAckKind::TimePrepared,
                };
                let mut stopped = false;
                let mut execution = None;
                let mut execution_mutated = false;
                let authority = if matches!(
                    command.kind,
                    CpuCommandKind::CaptureExecution
                        | CpuCommandKind::InstallExecution
                        | CpuCommandKind::PrepareExecutionTime
                ) {
                    self.memory_domain
                        .as_ref()
                        .ok_or_else(|| {
                            "HVF native effects lack the retained memory domain".to_owned()
                        })
                        .and_then(|domain| {
                            if domain.tracking_mode() != Some(TrackingMode::Capture) {
                                return Err(
                                    "HVF native effects require tracked capture memory".to_owned()
                                );
                            }
                            command
                                .native_effects
                                .as_ref()
                                .ok_or_else(|| "HVF native effects lack authority".to_owned())?
                                .validate_domain(domain)
                                .map_err(|error| error.to_string())
                        })
                } else {
                    Ok(())
                };
                let outcome = authority.and_then(|()| match command.kind {
                    CpuCommandKind::Stop => {
                        parked = true;
                        hvf_vcpu
                            .destroy()
                            .map(|()| stopped = true)
                            .map_err(|error| error.to_string())
                    }
                    CpuCommandKind::Park => {
                        if command.barrier.key == key && !parked
                            || command.barrier.key != key
                                && command.barrier.key.generation.0 <= key.generation.0
                        {
                            Err("stale or foreign HVF park key".to_owned())
                        } else {
                            parked = true;
                            match hvf_vcpu.finish_pending_emulation() {
                                Ok(()) => {
                                    completion_failed = false;
                                    if key != command.barrier.key {
                                        key = command.barrier.key;
                                        timer_plan =
                                            hvf::VtimerResume::new(hvf_vcpu.vtimer_offset());
                                        prepared = None;
                                        captured = None;
                                        installed_time = None;
                                        capture_request = None;
                                    }
                                    if let Some(error) = &terminal_fault {
                                        Err(error.clone())
                                    } else {
                                        Ok(())
                                    }
                                }
                                Err(error) => {
                                    completion_failed = true;
                                    Err(error.to_string())
                                }
                            }
                        }
                    }
                    CpuCommandKind::PrepareResume { paused_ticks } => {
                        if !parked
                            || key.generation != command.barrier.key.generation
                            || completion_failed
                            || terminal_fault.is_some()
                            || self.restore_prepared && installed.is_none()
                        {
                            Err("HVF CPU is not parked at the requested key".to_owned())
                        } else {
                            match hvf::state::resume_time_action(
                                captured.is_some(),
                                &command.barrier.key,
                                installed_time.as_ref().map(|(key, _)| key),
                                prepared.as_ref(),
                                paused_ticks,
                            )
                            .map_err(|error| error.to_string())
                            {
                                Ok(hvf::state::ResumeTimeAction::RetainInstalledExecution) => {
                                    Ok(())
                                }
                                Ok(hvf::state::ResumeTimeAction::PrepareOrdinaryOffset) => {
                                    timer_plan.prepare(paused_ticks).and_then(|target| {
                                        hvf_vcpu
                                            .set_vtimer_offset(target)
                                            .map(|()| prepared = Some(command.barrier.key))
                                            .map_err(|error| error.to_string())
                                    })
                                }
                                Err(error) => Err(error),
                            }
                        }
                    }
                    CpuCommandKind::Release => {
                        if !parked
                            || completion_failed
                            || terminal_fault.is_some()
                            || self.restore_prepared && installed.is_none()
                            || prepared != Some(command.barrier.key)
                        {
                            Err("HVF release lacks exact completed preparation".to_owned())
                        } else {
                            parked = false;
                            Ok(())
                        }
                    }
                    CpuCommandKind::CaptureExecution => {
                        if !parked
                            || key.generation != command.barrier.key.generation
                            || captured.is_none() && key != command.barrier.key
                            || completion_failed
                            || terminal_fault.is_some()
                        {
                            Err("HVF capture requires the exact completed pause".to_owned())
                        } else if let Some(state) = &captured {
                            if capture_request == Some(command.request) {
                                execution = Some(state.clone());
                                Ok(())
                            } else {
                                prepared = None;
                                installed_time = None;
                                hvf_vcpu
                                    .fence_execution_time()
                                    .map_err(|error| error.to_string())
                                    .map(|()| {
                                        capture_request = Some(command.request);
                                        execution = Some(state.clone());
                                    })
                            }
                        } else {
                            let disposition = if !initialized {
                                CpuDisposition::Offline
                            } else if waiting.is_some() {
                                CpuDisposition::Waiting
                            } else {
                                CpuDisposition::Runnable
                            };
                            self.vcpu_list
                                .capture_execution_state(self.id, disposition)
                                .map_err(|error| error.to_string())
                                .and_then(|mut software| {
                                    if !initialized
                                        && pending_cpu_on.is_none()
                                        && let Some(boot) = &self.boot_receiver
                                    {
                                        match boot.try_recv() {
                                            Ok(start) => pending_cpu_on = Some(start),
                                            Err(TryRecvError::Empty) => {}
                                            Err(TryRecvError::Disconnected) => {
                                                return Err("HVF CPU_ON channel closed".to_owned());
                                            }
                                        }
                                    }
                                    software.cpu_on = pending_cpu_on;
                                    hvf_vcpu
                                        .capture_execution_state(self.id, software, &framework)
                                        .map_err(|error| error.to_string())
                                })
                                .and_then(|state| {
                                    let state = Arc::new(CpuExecutionState::Hvf(state));
                                    captured = Some(state.clone());
                                    hvf_vcpu
                                        .fence_execution_time()
                                        .map_err(|error| error.to_string())
                                        .map(|()| {
                                            capture_request = Some(command.request);
                                            execution = Some(state);
                                        })
                                })
                        }
                    }
                    CpuCommandKind::InstallExecution => {
                        if !parked || !self.restore_prepared || terminal_fault.is_some() {
                            Err("HVF install requires a fresh fenced restore".to_owned())
                        } else if installed.is_some() {
                            if installed == command.execution && command.barrier.key == key {
                                Ok(())
                            } else {
                                Err("HVF install key/payload changed".to_owned())
                            }
                        } else {
                            match command.execution.as_deref() {
                                Some(CpuExecutionInput::Install(CpuExecutionState::Hvf(state)))
                                    if state.logical_id == self.id && state.mpidr == self.mpidr =>
                                {
                                    execution_mutated = true;
                                    hvf_vcpu
                                        .install_execution_state(
                                            state,
                                            state.timer.offset,
                                            &framework,
                                        )
                                        .map_err(|error| error.to_string())
                                        .and_then(|()| {
                                            self.vcpu_list
                                                .install_execution_state(self.id, &state.software)
                                                .map_err(|error| error.to_string())
                                        })
                                        .map(|()| {
                                            initialized = state.software.disposition
                                                != CpuDisposition::Offline;
                                            waiting = (state.software.disposition
                                                == CpuDisposition::Waiting)
                                                .then_some(None);
                                            pending_cpu_on = state.software.cpu_on;
                                            captured = Some(Arc::new(CpuExecutionState::Hvf(
                                                state.clone(),
                                            )));
                                            installed = command.execution.clone();
                                            key = command.barrier.key;
                                        })
                                }
                                _ => Err("HVF install payload/backend mismatch".to_owned()),
                            }
                        }
                    }
                    CpuCommandKind::PrepareExecutionTime => {
                        if !parked
                            || completion_failed
                            || terminal_fault.is_some()
                            || command.barrier.key.generation != key.generation
                        {
                            Err("HVF time preparation requires a fenced CPU".to_owned())
                        } else if let Some((previous_key, previous)) = &installed_time {
                            if *previous_key == command.barrier.key
                                && Some(previous) == command.execution.as_ref()
                            {
                                Ok(())
                            } else {
                                Err("HVF time preparation key/payload changed".to_owned())
                            }
                        } else {
                            match command.execution.as_deref() {
                                Some(CpuExecutionInput::PrepareTime(CpuTimePlan::Hvf(plan)))
                                    if plan.logical_id == self.id
                                        && matches!(captured.as_deref(),
                                            Some(CpuExecutionState::Hvf(state))
                                                if state.timer == plan.timer) =>
                                {
                                    execution_mutated = true;
                                    hvf_vcpu
                                        .prepare_execution_time(&plan.timer, plan.absolute_offset)
                                        .map_err(|error| error.to_string())
                                        .map(|()| {
                                            prepared = Some(command.barrier.key);
                                            if waiting.is_some() {
                                                waiting = Some(
                                                    hvf_vcpu.execution_timer_wait(&plan.timer),
                                                );
                                            }
                                            if let Some(input) = &command.execution {
                                                installed_time =
                                                    Some((command.barrier.key, input.clone()));
                                            }
                                        })
                                }
                                _ => Err("HVF time payload/backend mismatch".to_owned()),
                            }
                        }
                    }
                });
                if outcome.is_err() && execution_mutated {
                    terminal_fault = outcome.as_ref().err().cloned();
                }
                drop(command.native_effects.take());
                let _ = self.control_sender.send(CpuAck {
                    request: command.request,
                    key: command.barrier.key,
                    cpu_id: self.id,
                    kind: ack_kind,
                    result: outcome,
                    execution,
                });
                let _ = self.exit_evt.write(1);
                if stopped {
                    return;
                }
                continue;
            }
            if parked || !initialized || waiting.is_some() {
                continue;
            }
            match self.run_emulation(&mut hvf_vcpu) {
                Ok(VcpuEmulation::Handled | VcpuEmulation::WaitForEventExpired) => {}
                Ok(VcpuEmulation::WaitForEvent) => waiting = Some(None),
                Ok(VcpuEmulation::WaitForEventTimeout(timeout)) => waiting = Some(Some(timeout)),
                Ok(VcpuEmulation::Stopped) => {
                    match hvf_vcpu.destroy() {
                        Ok(()) => {
                            self.exit(FC_EXIT_CODE_OK);
                            return;
                        }
                        Err(error) => {
                            log::error!("CPU {} shutdown: {error}", self.id);
                            terminal_fault = Some(error.to_string());
                        }
                    }
                    parked = true;
                    completion_failed = true;
                }
                outcome @ (Ok(VcpuEmulation::Interrupted) | Err(_)) => {
                    parked = true;
                    completion_failed = true;
                    terminal_fault = Some(match outcome {
                        Err(error) => error.to_string(),
                        _ => "HVF guest breakpoint".to_owned(),
                    });
                    self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                }
            }
        }
    }

    fn exit(&mut self, exit_code: u8) {
        let _ = self.response_sender.send(VcpuResponse::Exited(exit_code));

        if let Err(e) = self.exit_evt.write(1) {
            error!("Failed signaling vcpu exit event: {e}");
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum VcpuResponse {
    Exited(u8),
}

pub struct VcpuHandle {
    event_sender: Sender<CpuCommand>,
    response_receiver: Receiver<VcpuResponse>,
    control_receiver: Receiver<CpuAck>,
    hvf_id: Option<u64>,
    cpu_id: u8,
    startup_error: Option<String>,
    vcpu_thread: Option<thread::JoinHandle<()>>,
}

impl VcpuHandle {
    pub fn cpu_id(&self) -> u8 {
        self.cpu_id
    }

    pub fn send_control(&self, command: CpuCommand) -> CpuSubmission {
        if let Some(error) = &self.startup_error
            && command.kind != CpuCommandKind::Stop
        {
            return CpuSubmission::Rejected(error.clone());
        }
        if self.event_sender.send(command).is_err() {
            return CpuSubmission::Rejected("HVF vCPU command channel closed".to_owned());
        }
        let kick_error = self.hvf_id.and_then(|id| {
            hvf::vcpu_request_exit(id)
                .err()
                .map(|error| error.to_string())
        });
        CpuSubmission::Accepted { kick_error }
    }

    pub fn try_control_ack(&self) -> std::result::Result<Option<CpuAck>, String> {
        match self.control_receiver.try_recv() {
            Ok(ack) => Ok(Some(ack)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err("HVF CPU ACK channel closed".to_owned()),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.vcpu_thread
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
    }

    pub fn reap(&mut self) -> std::result::Result<bool, String> {
        if !self.is_finished() {
            return Ok(false);
        }
        if let Some(thread) = self.vcpu_thread.take() {
            thread
                .join()
                .map_err(|_| "HVF vCPU owner thread panicked".to_owned())?;
        }
        Ok(true)
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

impl Drop for VcpuHandle {
    fn drop(&mut self) {
        let Some(thread) = self.vcpu_thread.take() else {
            return;
        };
        if !thread.is_finished() {
            let _ = self.event_sender.send(CpuCommand {
                request: RequestId(u64::MAX),
                barrier: polly::event_manager::BarrierRequest {
                    key: BarrierKey {
                        operation: OperationId(0),
                        generation: BarrierGeneration(0),
                    },
                    deadline: Instant::now(),
                },
                kind: CpuCommandKind::Stop,
                execution: None,
                native_effects: None,
            });
            if let Some(id) = self.hvf_id
                && let Err(error) = hvf::vcpu_request_exit(id)
            {
                log::error!("CPU {} final stop wake: {error}", self.cpu_id);
            }
        }
        if thread.join().is_err() {
            log::error!(
                "CPU {} owner thread panicked during final stop",
                self.cpu_id
            );
        }
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
    use std::sync::Arc;

    use crate::vmm::macos::vstate::{Vcpu, Vm, build_reclaim_layout, memory_mappings};
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
    fn cpu_bitmap_uses_dense_registered_pages_across_holes_and_word_tails() {
        use arch::guest_memory::{DirtyPageMap, PageIndex, RegisteredRamLayout};

        let granule = 0x4000;
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x4000_0000), 63 * granule),
            (GuestAddress(0x8000_0000), 3 * granule),
        ])
        .unwrap();
        let layout = RegisteredRamLayout::from_memory(&memory, granule as u32).unwrap();
        assert_eq!(layout.page_count(), 66);
        assert_eq!(
            layout.page_at(0x4000_0000 + 62 * granule as u64),
            Some(PageIndex::new(62))
        );
        assert_eq!(layout.page_at(0x8000_0000), Some(PageIndex::new(63)));
        assert_eq!(layout.page_at(0x6000_0000), None);
        let mut epoch = DirtyPageMap::new(&layout);
        let mut retained = DirtyPageMap::new(&layout);
        for page in [62, 63, 65] {
            epoch.set(PageIndex::new(page)).unwrap();
        }
        retained.merge(&epoch).unwrap();
        retained.merge(&epoch).unwrap();
        assert_eq!(retained.count(), 3);
        epoch.clear();
        epoch.set(PageIndex::new(63)).unwrap();
        epoch.set(PageIndex::new(64)).unwrap();
        retained.merge(&epoch).unwrap();
        assert_eq!(retained.count(), 4);
        assert!(retained.contains(PageIndex::new(62)));
        assert!(retained.contains(PageIndex::new(65)));
        assert!(epoch.set(PageIndex::new(66)).is_err());
        assert_eq!(retained.words()[1], 3);
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
        assert!(!vm.reclaim_state().is_initialized());
        assert!(vm.host_memory_remapper().is_none());

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
}
