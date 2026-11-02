// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(target_arch = "aarch64")]
use arch::ArchMemoryInfo;
use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use libc::{c_int, c_void, siginfo_t};
use std::cell::Cell;
use std::fmt::{Display, Formatter};
use std::io;
#[cfg(all(feature = "tee", target_arch = "x86_64"))]
use std::ops::Range;

#[cfg(all(feature = "tee", target_arch = "x86_64"))]
use std::os::unix::io::RawFd;

#[cfg(target_arch = "x86_64")]
use std::env;
use std::result;
use std::sync::Arc;
use std::sync::atomic::{Ordering, fence};
use std::thread;
#[cfg(target_arch = "x86_64")]
use std::time::Duration;

use crate::vmm::control::{CpuAck, CpuCommand, CpuSubmission};
use crate::vmm::linux::cpu_control::{CpuDisposition, CpuMailbox, submit_command};
use crate::vmm::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};

#[cfg(feature = "amd-sev")]
use crate::vmm::linux::tee::amdsnp::{AmdSnp, Error as SnpError};

#[cfg(feature = "tdx")]
use crate::vmm::linux::tee::inteltdx::{Error as TdxError, IntelTdx};

#[cfg(feature = "amd-sev")]
use kbs_types::Tee;

use crate::vmm::execution::kvm::{KvmCpuState, KvmCpuTimePlan, KvmVmState};
use crate::vmm::execution::{CpuExecutionInput, CpuExecutionState};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::vmm::linux::execution::{self, CpuCaptureConfig};
#[cfg(feature = "tee")]
use crate::vmm::resources::TeeConfig;
use crate::vmm::vmm_config::machine_config::CpuFeaturesTemplate;
#[cfg(target_arch = "x86_64")]
use cpuid::{VmSpec, c3, filter_cpuid, t2};
#[cfg(not(feature = "tee"))]
use kvm_bindings::kvm_userspace_memory_region;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{CpuId, KVM_MAX_CPUID_ENTRIES, MsrList};
use kvm_bindings::{KVM_API_VERSION, KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
#[cfg(feature = "tee")]
use kvm_bindings::{KVM_CAP_EXIT_HYPERCALL, KVM_MEMORY_EXIT_FLAG_PRIVATE, kvm_enable_cap};
#[cfg(all(feature = "tee", target_arch = "x86_64"))]
use kvm_bindings::{
    KVM_MEM_GUEST_MEMFD, KVM_MEMORY_ATTRIBUTE_PRIVATE, kvm_create_guest_memfd,
    kvm_memory_attributes, kvm_userspace_memory_region2,
};
use kvm_ioctls::{Cap::*, *};
use utils::eventfd::EventFd;
use utils::signal::{Killable, register_signal_handler, sigrtmin};
use utils::sm::StateMachine;
#[cfg(feature = "tee")]
use utils::worker_message::{MemoryProperties, WorkerMessage};
use vm_memory::{
    Address, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
};

#[cfg(feature = "amd-sev")]
use crate::vmm::linux::tee::amdsnp::launch as snp;

/// Signal number (SIGRTMIN) used to kick Vcpus.
pub(crate) const VCPU_RTSIG_OFFSET: i32 = 0;

/// Errors associated with the wrappers over KVM ioctls.
#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    ControlChannel,
    SignalHandler(utils::errno::Error),
    #[cfg(target_arch = "x86_64")]
    /// A call to cpuid instruction failed.
    CpuId(cpuid::Error),
    /// Unable to create a KVM guest_memfd.
    CreateGuestMemfd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the floating point related registers
    FPUConfiguration(arch::x86_64::regs::Error),
    #[cfg(target_arch = "x86_64")]
    /// Retrieving supported guest MSRs fails.
    GuestMSRs(arch::x86_64::msr::Error),
    /// Unable to enable KVM hypercall exits.
    #[cfg(feature = "tee")]
    HypercallExitEnable(kvm_ioctls::Error),
    /// The host kernel reports an invalid KVM API version.
    KvmApiVersion(i32),
    /// Cannot initialize the KVM context due to missing capabilities.
    KvmCap(kvm_ioctls::Cap),
    #[cfg(feature = "amd-sev")]
    /// Cannot read the CPUID entries from KVM.
    KvmCpuId(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the MSR registers
    MSRSConfiguration(arch::x86_64::msr::Error),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    NotEnoughMemorySlots,
    #[cfg(target_arch = "aarch64")]
    /// Error configuring the general purpose aarch64 registers.
    REGSConfiguration(arch::aarch64::regs::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed to establish the shared physical/virtual guest counter epoch.
    VmCounterOffset(String),
    #[cfg(target_arch = "riscv64")]
    /// Error configuring the general purpose riscv64 registers.
    REGSConfiguration(arch::riscv64::regs::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the general purpose registers
    REGSConfiguration(arch::x86_64::regs::Error),
    /// Cannot set memory region attributes.
    SetMemoryAttributes(kvm_ioctls::Error),
    /// Cannot set the memory regions.
    SetUserMemoryRegion(kvm_ioctls::Error),
    #[cfg(feature = "amd-sev")]
    /// Error initializing the Secure Virtualization Backend (SNP).
    SnpSecVirtInit(SnpError),
    #[cfg(feature = "amd-sev")]
    /// Error preparing the VM for Secure Virtualization (SNP).
    SnpSecVirtPrepare(SnpError),
    #[cfg(feature = "amd-sev")]
    /// Error attesting the Secure VM (SNP).
    SnpSecVirtAttest(SnpError),
    #[cfg(feature = "tdx")]
    /// Error preparing the VM for Trust Domain Extensions (TDX)
    TdxSecVirtPrepare(TdxError),
    #[cfg(feature = "tee")]
    /// The TEE specified is not supported.
    InvalidTee,
    /// Failed to signal Vcpu.
    SignalVcpu(utils::errno::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the special registers
    SREGSConfiguration(arch::x86_64::regs::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error doing Vcpu Init on Arm.
    VcpuArmInit(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error finalizing a Vcpu feature on Arm.
    VcpuArmFinalize(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error getting the Vcpu preferred target on Arm.
    VcpuArmPreferredTarget(kvm_ioctls::Error),
    /// Cannot open the VCPU file descriptor.
    VcpuFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu regs.
    VcpuGetRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu sregs.
    VcpuGetSregs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu cpuid.
    VcpuSetCpuid(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu mp state.
    VcpuSetMpState(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu regs.
    VcpuSetRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu sregs.
    VcpuSetSregs(kvm_ioctls::Error),
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    /// Cannot cleanly initialize vcpu TLS.
    VcpuTlsInit,
    /// Vcpu not present in TLS.
    VcpuTlsNotPresent,
    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,
    /// Unsupported KVM_EXIT_HYPERCALL.
    #[cfg(feature = "tee")]
    VcpuUnsupportedHypercall,
    /// Cannot open the VM file descriptor.
    VmFd(kvm_ioctls::Error),
    /// Cannot configure the microvm.
    VmSetup(kvm_ioctls::Error),
    /// Failed to enable split IRQCHIP in vm
    VmSplitIrqchip(kvm_ioctls::Error),
    /// Failed to set vm APIC bus clock rate (in nanoseconds)
    VmApicBusClockRate(kvm_ioctls::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            ControlChannel => write!(f, "vCPU control channel unavailable"),
            SignalHandler(e) => write!(f, "Failed to register vCPU kick handler: {e}"),
            #[cfg(target_arch = "x86_64")]
            CpuId(e) => write!(f, "Cpuid error: {e:?}"),
            CreateGuestMemfd(e) => write!(f, "Unable to create KVM guest_memfd: {e:?}"),
            #[cfg(target_arch = "x86_64")]
            GuestMSRs(e) => write!(f, "Retrieving supported guest MSRs fails: {e:?}"),
            #[cfg(feature = "tee")]
            HypercallExitEnable(e) => write!(f, "Unable to enable KVM hypercall exits: {e}"),
            KvmApiVersion(v) => {
                write!(f, "The host kernel reports an invalid KVM API version: {v}")
            }
            KvmCap(cap) => write!(f, "Missing KVM capabilities: {cap:?}"),
            #[cfg(feature = "amd-sev")]
            KvmCpuId(e) => write!(f, "Cannot read CPUID entries from KVM: {e}"),
            VmFd(e) => write!(f, "Cannot open the VM file descriptor: {e}"),
            VcpuFd(e) => write!(f, "Cannot open the VCPU file descriptor: {e}"),
            VmSetup(e) => write!(f, "Cannot configure the microvm: {e}"),
            VmSplitIrqchip(e) => write!(f, "Failed to enable split IRQCHIP: {e}"),
            VmApicBusClockRate(e) => write!(
                f,
                "Failed to set vm APIC bus clock rate (in nanoseconds): {e}"
            ),
            NotEnoughMemorySlots => write!(
                f,
                "The number of configured slots is bigger than the maximum reported by KVM"
            ),
            #[cfg(target_arch = "x86_64")]
            LocalIntConfiguration(e) => write!(
                f,
                "Cannot set the local interruption due to bad configuration: {e:?}"
            ),
            SetMemoryAttributes(e) => write!(f, "Cannot set memory region attributes: {e}"),
            SetUserMemoryRegion(e) => write!(f, "Cannot set the memory regions: {e}"),
            #[cfg(feature = "amd-sev")]
            SnpSecVirtInit(e) => write!(
                f,
                "Error initializing the Secure Virtualization Backend (SEV): {e:?}"
            ),

            #[cfg(feature = "amd-sev")]
            SnpSecVirtPrepare(e) => write!(
                f,
                "Error preparing the VM for Secure Virtualization (SNP): {e:?}"
            ),

            #[cfg(feature = "amd-sev")]
            SnpSecVirtAttest(e) => write!(f, "Error attesting the Secure VM (SNP): {e:?}"),

            SignalVcpu(e) => write!(f, "Failed to signal Vcpu: {e}"),
            #[cfg(feature = "tdx")]
            TdxSecVirtPrepare(e) => write!(
                f,
                "Error preparing the VM for Trust Domain Extensions (TDX): {e:?}"
            ),
            #[cfg(target_arch = "x86_64")]
            MSRSConfiguration(e) => write!(f, "Error configuring the MSR registers: {e:?}"),
            #[cfg(target_arch = "aarch64")]
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose aarch64 registers: {e:?}"
            ),
            #[cfg(target_arch = "aarch64")]
            VmCounterOffset(e) => write!(f, "Cannot establish the ARM common counter epoch: {e}"),
            #[cfg(target_arch = "riscv64")]
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose riscv64 registers: {e:?}"
            ),
            #[cfg(target_arch = "x86_64")]
            REGSConfiguration(e) => {
                write!(f, "Error configuring the general purpose registers: {e:?}")
            }
            #[cfg(target_arch = "x86_64")]
            SREGSConfiguration(e) => write!(f, "Error configuring the special registers: {e:?}"),
            #[cfg(target_arch = "x86_64")]
            FPUConfiguration(e) => write!(
                f,
                "Error configuring the floating point related registers: {e:?}"
            ),
            #[cfg(target_arch = "x86_64")]
            VcpuGetRegs(e) => write!(f, "Failed to get KVM vcpu regs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetSregs(e) => write!(f, "Failed to get KVM vcpu sregs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetCpuid(e) => write!(f, "Failed to set KVM vcpu cpuid: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetMpState(e) => write!(f, "Failed to set KVM vcpu mp state: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetRegs(e) => write!(f, "Failed to set KVM vcpu regs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetSregs(e) => write!(f, "Failed to set KVM vcpu sregs: {e}"),
            VcpuSpawn(e) => write!(f, "Cannot spawn a new vCPU thread: {e}"),
            VcpuTlsInit => write!(f, "Cannot clean init vcpu TLS"),
            VcpuTlsNotPresent => write!(f, "Vcpu not present in TLS"),
            VcpuUnhandledKvmExit => write!(f, "Unexpected KVM_RUN exit reason"),
            #[cfg(feature = "tee")]
            VcpuUnsupportedHypercall => write!(f, "Unsupported KVM_EXIT_HYPERCALL"),
            #[cfg(target_arch = "aarch64")]
            VcpuArmPreferredTarget(e) => {
                write!(f, "Error getting the Vcpu preferred target on Arm: {e}")
            }
            #[cfg(target_arch = "aarch64")]
            VcpuArmInit(e) => write!(f, "Error doing Vcpu Init on Arm: {e}"),
            #[cfg(target_arch = "aarch64")]
            VcpuArmFinalize(e) => {
                write!(f, "Error finalizing a Vcpu feature on Arm: {e}")
            }

            #[cfg(feature = "tee")]
            InvalidTee => write!(f, "TEE selected is not currently supported"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

#[cfg(feature = "tee")]
#[derive(Debug)]
#[allow(dead_code)]
pub struct MeasuredRegion {
    pub guest_addr: u64,
    pub host_addr: u64,
    pub size: usize,
    pub attributes: u32,
}

/// Describes a KVM context that gets attached to the microVM.
/// It gives access to the functionality of the KVM wrapper as
/// long as every required KVM capability is present on the host.
pub struct KvmContext {
    kvm: Kvm,
    max_memslots: usize,
}

impl KvmContext {
    pub fn new() -> Result<Self> {
        let kvm = Kvm::new().expect("Error creating the Kvm object");

        // Check that KVM has the correct version.
        if kvm.get_api_version() != KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm.get_api_version()));
        }

        // A list of KVM capabilities we want to check.
        #[cfg(target_arch = "x86_64")]
        let capabilities = [Irqchip, Ioeventfd, Irqfd, UserMemory, SetTssAddr];

        #[cfg(target_arch = "aarch64")]
        let capabilities = [Irqchip, Ioeventfd, Irqfd, UserMemory, ArmPsci02];

        #[cfg(target_arch = "riscv64")]
        let capabilities = [Irqchip, Ioeventfd, Irqfd, UserMemory];

        // Check that all desired capabilities are supported.
        match capabilities
            .iter()
            .find(|&capability| !kvm.check_extension(*capability))
        {
            None => {
                let max_memslots = kvm.get_nr_memslots();
                Ok(KvmContext { kvm, max_memslots })
            }

            Some(c) => Err(Error::KvmCap(*c)),
        }
    }

    pub fn fd(&self) -> &Kvm {
        &self.kvm
    }

    /// Get the maximum number of memory slots reported by this KVM context.
    pub fn max_memslots(&self) -> usize {
        self.max_memslots
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    fd: Arc<VmFd>,
    next_mem_slot: u32,

    // X86 specific fields.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    supported_cpuid: CpuId,
    #[cfg(target_arch = "x86_64")]
    supported_msrs: MsrList,
    #[cfg(target_arch = "x86_64")]
    retained_pit: Option<kvm_bindings::kvm_pit_state2>,
    #[cfg(target_arch = "x86_64")]
    execution_clock_observation: std::sync::Mutex<Option<execution::KvmClockObservation>>,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    retained_execution: Option<KvmVmState>,
    #[cfg(target_arch = "aarch64")]
    execution_controller: Option<devices::legacy::IrqChip>,
    #[cfg(target_arch = "aarch64")]
    arm_counter_model: crate::vmm::execution::kvm::ArmCounterModel,

    #[cfg(feature = "amd-sev")]
    tee: Option<AmdSnp>,

    #[cfg(feature = "tdx")]
    tdx: Option<IntelTdx>,

    #[cfg(all(feature = "tee", target_arch = "x86_64"))]
    pub guest_memfds: Vec<(Range<u64>, RawFd)>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    #[cfg(not(feature = "tee"))]
    pub fn new(kvm: &Kvm) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm.create_vm().map_err(Error::VmFd)?;
        // Establish both counter views before any vCPU can execute, including cold sources.
        #[cfg(target_arch = "aarch64")]
        let arm_counter_model =
            execution::initialize_counter_model(&vm_fd).map_err(Error::VmCounterOffset)?;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;
        #[cfg(target_arch = "x86_64")]
        let supported_msrs =
            arch::x86_64::msr::supported_guest_msrs(kvm).map_err(Error::GuestMSRs)?;

        Ok(Vm {
            fd: Arc::new(vm_fd),
            next_mem_slot: 0,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            supported_cpuid,
            #[cfg(target_arch = "x86_64")]
            supported_msrs,
            #[cfg(target_arch = "x86_64")]
            retained_pit: None,
            #[cfg(target_arch = "x86_64")]
            execution_clock_observation: std::sync::Mutex::new(None),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            retained_execution: None,
            #[cfg(target_arch = "aarch64")]
            execution_controller: None,
            #[cfg(target_arch = "aarch64")]
            arm_counter_model,
        })
    }

    #[cfg(feature = "amd-sev")]
    pub fn new(kvm: &Kvm, tee_config: &TeeConfig) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm
            .create_vm_with_type(4 /* KVM_X86_SNP_VM */)
            .map_err(Error::VmFd)?;

        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;

        let supported_msrs =
            arch::x86_64::msr::supported_guest_msrs(kvm).map_err(Error::GuestMSRs)?;

        let cap = kvm_enable_cap {
            cap: KVM_CAP_EXIT_HYPERCALL,
            flags: 0,
            args: [1 << 12 /* KVM_HC_MAP_GPA_RANGE */, 0, 0, 0],
            ..Default::default()
        };

        vm_fd.enable_cap(&cap).map_err(Error::HypercallExitEnable)?;

        let tee = match tee_config.tee {
            Tee::Snp => Some(AmdSnp::new().map_err(Error::SnpSecVirtInit)?),
            _ => return Err(Error::InvalidTee),
        };

        Ok(Vm {
            fd: Arc::new(vm_fd),
            next_mem_slot: 0,
            supported_cpuid,
            supported_msrs,
            retained_pit: None,
            execution_clock_observation: std::sync::Mutex::new(None),
            retained_execution: None,
            tee,
            guest_memfds: Vec::new(),
        })
    }

    #[cfg(feature = "tdx")]
    pub fn new(
        kvm: &Kvm,
        _tee_config: &TeeConfig,
        _sender: crossbeam_channel::Sender<WorkerMessage>,
    ) -> Result<Self> {
        // create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm
            .create_vm_with_type(tdx::launch::KVM_X86_TDX_VM)
            .map_err(Error::VmFd)?;

        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;

        let supported_msrs =
            arch::x86_64::msr::supported_guest_msrs(kvm).map_err(Error::GuestMSRs)?;

        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_EXIT_HYPERCALL,
            flags: 0,
            args: [1 << 12 /* KVM_HC_MAP_GPA_RANGE */, 0, 0, 0],
            ..Default::default()
        };
        vm_fd.enable_cap(&cap).map_err(Error::HypercallExitEnable)?;

        cap.cap = kvm_bindings::KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = 24;
        vm_fd.enable_cap(&cap).map_err(Error::VmSplitIrqchip)?;

        cap.cap = 237; // KVM_CAP_X86_APIC_BUS_CYCLES_NS
        cap.args[0] = 40;
        vm_fd.enable_cap(&cap).map_err(Error::VmApicBusClockRate)?;

        Ok(Vm {
            fd: Arc::new(vm_fd),
            next_mem_slot: 0,
            supported_cpuid,
            supported_msrs,
            retained_pit: None,
            execution_clock_observation: std::sync::Mutex::new(None),
            retained_execution: None,
            tdx: Some(IntelTdx::new()),
            guest_memfds: Vec::new(),
        })
    }

    /// Returns a ref to the supported `CpuId` for this Vm.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn supported_cpuid(&self) -> &CpuId {
        &self.supported_cpuid
    }

    /// Returns a ref to the supported `MsrList` for this Vm.
    #[cfg(target_arch = "x86_64")]
    pub fn supported_msrs(&self) -> &MsrList {
        &self.supported_msrs
    }

    /// Initializes the guest memory.
    pub fn memory_init(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kvm_max_memslots: usize,
    ) -> Result<()> {
        if guest_mem.num_regions() > kvm_max_memslots {
            return Err(Error::NotEnoughMemorySlots);
        }

        for region in guest_mem.iter() {
            self.memory_region_set(guest_mem, region)?;
        }

        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS as usize)
            .map_err(Error::VmSetup)?;

        Ok(())
    }

    #[cfg(all(feature = "tee", target_arch = "x86_64"))]
    pub fn guest_memfd_get(&self, gpa: u64) -> Option<(RawFd, u64)> {
        for (range, rawfd) in self.guest_memfds.iter() {
            if range.contains(&gpa) {
                return Some((*rawfd, range.start));
            }
        }
        None
    }

    // GuestMemfd is generally intended for either of two purposes:
    // * sharing the memory with out-of-process components, and conversely,
    // * hiding the memory completely from the VMM process (Confidential Computing).
    //
    // We only use it for the second use case currently, so don't even try to use it
    // outside of TEE builds. Software-protected VMs are only available on x86_64 and
    // are marked with strongly-worded warnings about them being for development only,
    // as of late 2025. Also, on other architectures like aarch64, guest_memfd in
    // general is unstable for now, so don't try to use it without a reason.

    #[cfg(not(feature = "tee"))]
    fn create_guest_physical_memory_slot(
        &mut self,
        host_addr: u64,
        start: u64,
        region: &GuestRegionMmap,
    ) -> Result<()> {
        let memory_region = kvm_userspace_memory_region {
            slot: self.next_mem_slot,
            guest_phys_addr: start,
            memory_size: region.len(),
            userspace_addr: host_addr,
            flags: 0,
        };

        // Safe because we mapped the memory region and ensured regions do not overlap.
        unsafe {
            self.fd
                .set_user_memory_region(memory_region)
                .map_err(Error::SetUserMemoryRegion)?;
        };

        Ok(())
    }

    #[cfg(all(feature = "tee", target_arch = "x86_64"))]
    fn create_guest_physical_memory_slot(
        &mut self,
        host_addr: u64,
        start: u64,
        region: &GuestRegionMmap,
    ) -> Result<()> {
        let end = start + region.len();

        if !self.fd.check_extension(GuestMemfd) {
            return Err(Error::KvmCap(GuestMemfd));
        }

        // GuestMemfd is only used for confidential-memory setups in TEE builds.
        let guest_memfd = self
            .fd
            .create_guest_memfd(kvm_create_guest_memfd {
                size: region.size() as u64,
                flags: 0,
                reserved: [0; 6],
            })
            .map_err(Error::CreateGuestMemfd)?;

        let memory_region = kvm_userspace_memory_region2 {
            slot: self.next_mem_slot,
            flags: KVM_MEM_GUEST_MEMFD,
            guest_phys_addr: start,
            memory_size: region.len(),
            userspace_addr: host_addr,
            guest_memfd_offset: 0,
            guest_memfd: guest_memfd as u32,
            pad1: 0,
            pad2: [0; 14],
        };

        // Safe because we mapped the memory region and ensured regions do not overlap.
        unsafe {
            self.fd
                .set_user_memory_region2(memory_region)
                .map_err(Error::SetUserMemoryRegion)?;
        };

        let attr = kvm_memory_attributes {
            address: start,
            size: region.len(),
            attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
            flags: 0,
        };

        self.fd
            .set_memory_attributes(attr)
            .map_err(Error::SetMemoryAttributes)?;

        self.guest_memfds.push((Range { start, end }, guest_memfd));

        Ok(())
    }

    #[cfg(all(feature = "tee", not(target_arch = "x86_64")))]
    fn create_guest_physical_memory_slot(
        &mut self,
        _host_addr: u64,
        _start: u64,
        _region: &GuestRegionMmap,
    ) -> Result<()> {
        // TEE support should be rejected during VM setup on non-x86_64 targets.
        // Do not silently fall back to the non-TEE path here, because that would
        // ignore an invalid TEE configuration and create a normal VM instead.
        Err(Error::InvalidTee)
    }

    fn memory_region_set(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        region: &GuestRegionMmap,
    ) -> Result<()> {
        let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap() as u64;
        let start = region.start_addr().raw_value();

        self.create_guest_physical_memory_slot(host_addr, start, region)?;

        self.next_mem_slot += 1;

        Ok(())
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_prepare(&self) -> Result<tdx::launch::Launcher> {
        match &self.tdx {
            Some(t) => t
                .vm_prepare(&self.fd, self.supported_cpuid.clone())
                .map_err(Error::TdxSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_init_vcpus(
        &self,
        launcher: &mut tdx::launch::Launcher,
        hob_address: u64,
    ) -> Result<()> {
        match &self.tdx {
            Some(_) => {
                launcher.init_vcpus(hob_address).unwrap();
                Ok(())
            }
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_prepare_memory(
        &self,
        launcher: &mut tdx::launch::Launcher,
        regions: &Vec<crate::vmm::vstate::MeasuredRegion>,
    ) -> Result<()> {
        match &self.tdx {
            Some(t) => t
                .configure_td_memory(launcher, regions)
                .map_err(Error::TdxSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_finalize_vm(&self, launcher: tdx::launch::Launcher) -> Result<()> {
        match &self.tdx {
            Some(t) => t.finalize_vm(launcher).map_err(Error::TdxSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "amd-sev")]
    pub fn snp_secure_virt_prepare(
        &self,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<snp::Launcher<snp::Started, RawFd, RawFd>> {
        match &self.tee {
            Some(s) => s
                .vm_prepare(&self.fd, guest_mem)
                .map_err(Error::SnpSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "amd-sev")]
    pub fn snp_secure_virt_measure(
        &self,
        cpuid: CpuId,
        guest_mem: &GuestMemoryMmap,
        measured_regions: Vec<MeasuredRegion>,
        launcher: snp::Launcher<snp::Started, RawFd, RawFd>,
    ) -> Result<()> {
        match &self.tee {
            Some(s) => s
                .vm_measure(cpuid, guest_mem, measured_regions, launcher)
                .map_err(Error::SnpSecVirtAttest),
            None => Err(Error::InvalidTee),
        }
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.fd
    }

    pub fn fd_owner(&self) -> Arc<VmFd> {
        Arc::clone(&self.fd)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn capture_execution(
        &mut self,
        profile: &execution::KvmCaptureProfile,
    ) -> std::result::Result<KvmVmState, String> {
        if let Some(state) = &self.retained_execution {
            return Ok(state.clone());
        }
        let state = execution::capture_vm(&self.fd, profile, &mut self.retained_pit)?;
        self.retained_execution = Some(state.clone());
        Ok(state)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn install_execution(&self, state: &KvmVmState) -> std::result::Result<(), String> {
        execution::install_vm(&self.fd, state)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn prepare_execution_time(
        &self,
        state: &KvmVmState,
        cpus: &[KvmCpuState],
    ) -> std::result::Result<Vec<KvmCpuTimePlan>, String> {
        let mut observation = self
            .execution_clock_observation
            .lock()
            .map_err(|_| "kvm/clock/observation-lock")?;
        *observation = None;
        execution::prepare_vm_time(&self.fd, state, cpus, &mut observation)
    }

    #[cfg(all(feature = "native-execution-probe", target_arch = "x86_64"))]
    pub(crate) fn execution_time_observation(
        &self,
    ) -> std::result::Result<Option<execution::KvmClockObservation>, String> {
        Ok(*self
            .execution_clock_observation
            .lock()
            .map_err(|_| "kvm/clock/observation-lock")?)
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn finish_execution_release(&mut self) {
        self.retained_execution = None;
        #[cfg(target_arch = "x86_64")]
        {
            self.retained_pit = None;
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn set_execution_controller(&mut self, controller: devices::legacy::IrqChip) {
        self.execution_controller = Some(controller);
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn capture_execution(
        &mut self,
        profile: &execution::KvmCaptureProfile,
    ) -> std::result::Result<KvmVmState, String> {
        if let Some(state) = &self.retained_execution {
            return Ok(state.clone());
        }
        self.set_execution_controller(Arc::clone(&profile.controller));
        let state = execution::capture_arm_vm(profile, self.arm_counter_model)?;
        self.retained_execution = Some(state.clone());
        Ok(state)
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn install_execution(&self, state: &KvmVmState) -> std::result::Result<(), String> {
        state.validate()?;
        self.execution_controller
            .as_ref()
            .ok_or("kvm/gic/controller-not-retained")?
            .lock()
            .map_err(|_| "kvm/gic/controller-lock")?
            .install_kvm_state(&execution::arm_gic_state(state)?)
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn prepare_execution_time(
        &self,
        state: &KvmVmState,
        cpus: &[KvmCpuState],
    ) -> std::result::Result<Vec<KvmCpuTimePlan>, String> {
        self.install_execution(state)?;
        execution::prepare_arm_time(&self.fd, state, cpus)
    }
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
    /// Enable nested virtualization in the CPUID configuration.
    pub nested_enabled: bool,
}

// Using this for easier explicit type-casting to help IDEs interpret the code.
type VcpuCell = Cell<Option<*mut Vcpu>>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    fd: VcpuFd,
    id: u8,
    mmio_bus: Option<devices::Bus>,
    #[allow(dead_code)]
    #[cfg_attr(all(test, target_arch = "aarch64"), allow(unused))]
    exit_evt: EventFd,

    #[cfg(target_arch = "x86_64")]
    io_bus: devices::Bus,
    #[cfg(target_arch = "x86_64")]
    cpuid: CpuId,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    capture_config: CpuCaptureConfig,
    #[cfg(target_arch = "x86_64")]
    kernel_enomem_workaround: bool,

    #[cfg(target_arch = "aarch64")]
    mpidr: u64,

    // The receiving end of events channel owned by the vcpu side.
    event_receiver: Receiver<CpuCommand>,
    // The transmitting end of the events channel which will be given to the handler.
    event_sender: Option<Sender<CpuCommand>>,
    // The receiving end of the responses channel which will be given to the handler.
    response_receiver: Option<Receiver<VcpuResponse>>,
    // The transmitting end of the responses channel owned by the vcpu side.
    response_sender: Sender<VcpuResponse>,
    control_sender: Sender<CpuAck>,
    control_receiver: Option<Receiver<CpuAck>>,
    mailbox: CpuMailbox,
    execution_cut: Option<Arc<CpuExecutionState>>,
    execution_journal: Vec<(CpuCommand, CpuAck)>,
    execution_stop_only: bool,
    execution_time_ready: bool,
    retained_resources: Option<(GuestMemoryMmap, Arc<VmFd>)>,
    #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
    probe_park_state: ProbeParkJournal,

    #[cfg(feature = "tee")]
    pm_sender: Sender<WorkerMessage>,
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
            cell.set(Some(self as *mut Vcpu));
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

    /// Runs `func` for the `Vcpu` associated with the current thread.
    ///
    /// It requires that `init_thread_local_data()` was run on this thread.
    ///
    /// Fails if there is no `Vcpu` associated with the current thread.
    ///
    /// # Safety
    ///
    /// This is marked unsafe as it allows temporary aliasing through
    /// dereferencing from pointer an already borrowed `Vcpu`.
    unsafe fn run_on_thread_local<F>(func: F) -> Result<()>
    where
        F: FnOnce(&mut Vcpu),
    {
        unsafe {
            Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
                if let Some(vcpu_ptr) = cell.get() {
                    // Dereferencing here is safe since `TLS_VCPU_PTR` is populated/non-empty,
                    // and it is being cleared on `Vcpu::drop` so there is no dangling pointer.
                    let vcpu_ref: &mut Vcpu = &mut *vcpu_ptr;
                    func(vcpu_ref);
                    Ok(())
                } else {
                    Err(Error::VcpuTlsNotPresent)
                }
            })
        }
    }

    /// Registers a signal handler which makes use of TLS and kvm immediate exit to
    /// kick the vcpu running on the current thread, if there is one.
    pub fn register_kick_signal_handler() -> Result<()> {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            // This is safe because it's temporarily aliasing the `Vcpu` object, but we are
            // only reading `vcpu.fd` which does not change for the lifetime of the `Vcpu`.
            unsafe {
                let _ = Vcpu::run_on_thread_local(|vcpu: &mut Vcpu| {
                    vcpu.fd.set_kvm_immediate_exit(1);
                    fence(Ordering::Release);
                });
            }
        }

        register_signal_handler(sigrtmin() + VCPU_RTSIG_OFFSET, handle_signal)
            .map_err(Error::SignalHandler)
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `cpuid` - The `CpuId` listing the supported capabilities of this vcpu.
    /// * `msr_list` - The `MsrList` listing the supported MSRs for this vcpu.
    /// * `io_bus` - The io-bus used to access port-io devices.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    #[cfg(target_arch = "x86_64")]
    pub fn new_x86_64(
        id: u8,
        vm_fd: &VmFd,
        cpuid: CpuId,
        msr_list: MsrList,
        io_bus: devices::Bus,
        exit_evt: EventFd,
        #[cfg(feature = "tee")] pm_sender: Sender<WorkerMessage>,
    ) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id as u64).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();
        let (control_sender, control_receiver) = unbounded();

        let kernel_enomem_workaround = if env::var_os("KRUN_ENOMEM_WORKAROUND").is_some() {
            debug!("Enabling ENOMEM workaround");
            true
        } else {
            false
        };

        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            mmio_bus: None,
            exit_evt,
            io_bus,
            cpuid: cpuid.clone(),
            capture_config: CpuCaptureConfig {
                logical_id: id,
                host_cpuid: cpuid,
                raw_msrs: msr_list.as_slice().to_vec(),
                xsave_size: usize::try_from(vm_fd.check_extension_int(kvm_ioctls::Cap::Xsave2))
                    .unwrap_or(0),
                deadline_supported: vm_fd.check_extension(kvm_ioctls::Cap::TscDeadlineTimer),
            },
            kernel_enomem_workaround,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            control_sender,
            control_receiver: Some(control_receiver),
            mailbox: CpuMailbox::new(),
            execution_cut: None,
            execution_journal: Vec::new(),
            execution_stop_only: false,
            execution_time_ready: false,
            retained_resources: None,
            #[cfg(feature = "native-control-probe")]
            probe_park_state: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(feature = "tee")]
            pm_sender,
        })
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    /// * `create_ts` - A timestamp used by the vcpu to calculate its lifetime.
    #[cfg(target_arch = "aarch64")]
    pub fn new_aarch64(id: u8, vm_fd: &VmFd, exit_evt: EventFd) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id as u64).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();
        let (control_sender, control_receiver) = unbounded();

        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            mmio_bus: None,
            exit_evt,
            mpidr: 0,
            capture_config: CpuCaptureConfig {
                init: kvm_bindings::kvm_vcpu_init::default(),
            },
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            control_sender,
            control_receiver: Some(control_receiver),
            mailbox: CpuMailbox::new(),
            execution_cut: None,
            execution_journal: Vec::new(),
            execution_stop_only: false,
            execution_time_ready: false,
            retained_resources: None,
        })
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    /// * `create_ts` - A timestamp used by the vcpu to calculate its lifetime.
    #[cfg(target_arch = "riscv64")]
    pub fn new_riscv64(id: u8, vm_fd: &VmFd, exit_evt: EventFd) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id as u64).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();
        let (control_sender, control_receiver) = unbounded();

        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            mmio_bus: None,
            exit_evt,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            control_sender,
            control_receiver: Some(control_receiver),
            mailbox: CpuMailbox::new(),
            execution_cut: None,
            execution_journal: Vec::new(),
            execution_stop_only: false,
            execution_time_ready: false,
            retained_resources: None,
        })
    }

    /// Returns the cpu index as seen by the guest OS.
    pub fn cpu_index(&self) -> u8 {
        self.id
    }

    /// Gets the MPIDR register value.
    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(unused_variables)]
    /// Configures a x86_64 specific vcpu and should be called once per vcpu.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - The machine configuration of this microvm needed for the CPUID configuration.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    pub fn configure_x86_64(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        vcpu_config: &VcpuConfig,
        kernel_boot: bool,
        pvh: bool,
    ) -> Result<()> {
        let cpuid_vm_spec = VmSpec::new(
            self.id,
            vcpu_config.vcpu_count,
            vcpu_config.ht_enabled,
            vcpu_config.nested_enabled,
        )
        .map_err(Error::CpuId)?;

        filter_cpuid(&mut self.cpuid, &cpuid_vm_spec).map_err(|e| {
            error!("Failure in configuring CPUID for vcpu {}: {:?}", self.id, e);
            Error::CpuId(e)
        })?;

        if let Some(template) = vcpu_config.cpu_template {
            match template {
                CpuFeaturesTemplate::T2 => {
                    t2::set_cpuid_entries(&mut self.cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
                CpuFeaturesTemplate::C3 => {
                    c3::set_cpuid_entries(&mut self.cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
            }
        }

        self.fd
            .set_cpuid2(&self.cpuid)
            .map_err(Error::VcpuSetCpuid)?;

        if kernel_boot {
            arch::x86_64::msr::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
            arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.raw_value(), self.id, pvh)
                .map_err(Error::REGSConfiguration)?;
            arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
            arch::x86_64::regs::setup_sregs(guest_mem, &self.fd, self.id, pvh)
                .map_err(Error::SREGSConfiguration)?;
            arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Configures an aarch64 specific vcpu.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    pub fn configure_aarch64(
        &mut self,
        vm_fd: &VmFd,
        mem_info: &ArchMemoryInfo,
        kernel_load_addr: GuestAddress,
    ) -> Result<()> {
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();

        // This reads back the kernel's preferred target type.
        vm_fd
            .get_preferred_target(&mut kvi)
            .map_err(Error::VcpuArmPreferredTarget)?;
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.id > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        if vm_fd.check_extension(kvm_ioctls::Cap::ArmPtrAuthAddress) {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PTRAUTH_ADDRESS;
        }
        if vm_fd.check_extension(kvm_ioctls::Cap::ArmPtrAuthGeneric) {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PTRAUTH_GENERIC;
        }

        // Expose SVE to the guest when the host can virtualise it.
        let sve = vm_fd.check_extension(kvm_ioctls::Cap::ArmSve);
        if sve {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_SVE;
        }

        self.fd.vcpu_init(&kvi).map_err(Error::VcpuArmInit)?;
        self.capture_config.init = kvi;

        // Must precede any register access; KVM returns -EPERM until finalized.
        if sve {
            self.fd
                .vcpu_finalize(&(kvm_bindings::KVM_ARM_VCPU_SVE as std::os::raw::c_int))
                .map_err(Error::VcpuArmFinalize)?;
        }

        arch::aarch64::regs::setup_regs(&self.fd, self.id, kernel_load_addr.raw_value(), mem_info)
            .map_err(Error::REGSConfiguration)?;

        self.mpidr = arch::aarch64::regs::read_mpidr(&self.fd).map_err(Error::REGSConfiguration)?;

        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    /// Configures an riscv64 specific vcpu.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    pub fn configure_riscv64(
        &mut self,
        _vm_fd: &VmFd,
        guest_mem: &GuestMemoryMmap,
        kernel_load_addr: GuestAddress,
    ) -> Result<()> {
        arch::riscv64::regs::setup_regs(&self.fd, self.id, kernel_load_addr.raw_value(), guest_mem)
            .map_err(Error::REGSConfiguration)?;
        Ok(())
    }

    #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
    pub(crate) fn configure_control_probe(
        &mut self,
        memory: GuestMemoryMmap,
        vm: Arc<VmFd>,
        entry: u64,
        data_segment: u16,
        mmio_bus: devices::Bus,
    ) -> Result<()> {
        self.retained_resources = Some((memory, vm));
        self.mmio_bus = Some(mmio_bus);
        self.fd
            .set_cpuid2(&self.cpuid)
            .map_err(Error::VcpuSetCpuid)?;
        arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        let mut sregs = self.fd.get_sregs().map_err(Error::VcpuGetSregs)?;
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        for segment in [&mut sregs.ds, &mut sregs.es, &mut sregs.ss] {
            segment.base = u64::from(data_segment) << 4;
            segment.selector = data_segment;
        }
        self.fd.set_sregs(&sregs).map_err(Error::VcpuSetSregs)?;
        self.fd
            .set_regs(&kvm_bindings::kvm_regs {
                rip: entry,
                rflags: 2,
                rsp: 0xff0,
                ..Default::default()
            })
            .map_err(Error::VcpuSetRegs)?;
        self.fd
            .set_mp_state(kvm_bindings::kvm_mp_state {
                mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
            })
            .map_err(Error::VcpuSetMpState)
    }

    #[cfg(all(feature = "native-execution-probe", target_arch = "x86_64"))]
    pub(crate) fn configure_execution_fixture(
        &mut self,
        entry: u64,
        offline: bool,
        vcpu_count: u8,
    ) -> std::result::Result<(), String> {
        let spec = VmSpec::new(self.id, vcpu_count, false, false)
            .map_err(|e| format!("fixture/CPU-model: {e:?}"))?;
        filter_cpuid(&mut self.cpuid, &spec).map_err(|e| format!("fixture/CPUID: {e:?}"))?;
        self.fd
            .set_cpuid2(&self.cpuid)
            .map_err(|e| format!("fixture/SET_CPUID2: {e}"))?;
        let mut sregs = self
            .fd
            .get_sregs()
            .map_err(|e| format!("fixture/GET_SREGS: {e}"))?;
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        self.fd
            .set_sregs(&sregs)
            .map_err(|e| format!("fixture/SET_SREGS: {e}"))?;
        self.fd
            .set_regs(&kvm_bindings::kvm_regs {
                rip: entry,
                rflags: 2,
                ..Default::default()
            })
            .map_err(|e| format!("fixture/SET_REGS: {e}"))?;
        self.fd
            .set_mp_state(kvm_bindings::kvm_mp_state {
                mp_state: if offline {
                    kvm_bindings::KVM_MP_STATE_UNINITIALIZED
                } else {
                    kvm_bindings::KVM_MP_STATE_RUNNABLE
                },
            })
            .map_err(|e| format!("fixture/SET_MP_STATE: {e}"))
    }

    pub fn retain_resources(&mut self, memory: GuestMemoryMmap, vm: &Vm) {
        self.retained_resources = Some((memory, vm.fd_owner()));
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().ok_or(Error::ControlChannel)?;
        let response_receiver = self.response_receiver.take().ok_or(Error::ControlChannel)?;
        let control_receiver = self.control_receiver.take().ok_or(Error::ControlChannel)?;
        let (init_tls_sender, init_tls_receiver) = unbounded();
        #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
        let probe_park_state = Arc::clone(&self.probe_park_state);
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || {
                let initialized = self.init_thread_local_data();
                let ready = initialized.is_ok();
                if init_tls_sender.send(initialized).is_err() || !ready {
                    return;
                }

                self.run();
            })
            .map_err(Error::VcpuSpawn)?;

        match init_tls_receiver.recv() {
            Ok(Ok(())) => (),
            result => {
                let _ = vcpu_thread.join();
                return match result {
                    Ok(Err(error)) => Err(error),
                    _ => Err(Error::ControlChannel),
                };
            }
        }

        Ok(VcpuHandle::new(
            event_sender,
            response_receiver,
            control_receiver,
            vcpu_thread,
            #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
            probe_park_state,
        ))
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn initialize_aarch64_saved(
        &mut self,
        state: &crate::vmm::execution::kvm::ArmCpuState,
    ) -> std::result::Result<(), String> {
        let init = kvm_bindings::kvm_vcpu_init {
            target: state.target,
            features: state.features,
        };
        if init.features[0] & (1 << kvm_bindings::KVM_ARM_VCPU_SVE) != 0 {
            return Err("kvm/arm64/sve-unqualified".into());
        }
        self.fd
            .vcpu_init(&init)
            .map_err(|e| format!("kvm/arm64/VCPU_INIT: {e}"))?;
        self.capture_config.init = init;
        self.mpidr = state.mpidr;
        Ok(())
    }

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    fn run_emulation(&mut self) -> Result<VcpuEmulation> {
        // This is a workaround for a kernel bug in the Linux
        // kernel (6.12 and 6.13).
        // https://github.com/containers/libkrun/issues/314#issuecomment-2818154193
        #[cfg(target_arch = "x86_64")]
        {
            if self.kernel_enomem_workaround {
                thread::sleep(Duration::from_millis(5));
            }
        }

        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(feature = "tee")]
                VcpuExit::Hypercall(hypercall) => {
                    if hypercall.nr != 12
                    /* KVM_HC_MAP_GPA_RANGE */
                    {
                        return Err(Error::VcpuUnsupportedHypercall);
                    }

                    let gpa = hypercall.args[0];
                    let size = hypercall.args[1] * 0x1000; /* TARGET_PAGE_SIZE */
                    let attributes = hypercall.args[2];

                    let private = !matches!(attributes, 0);

                    let mem_properties = MemoryProperties { gpa, size, private };

                    let (response_sender, response_receiver) = unbounded();
                    self.pm_sender
                        .send(WorkerMessage::ConvertMemory(
                            response_sender.clone(),
                            mem_properties,
                        ))
                        .unwrap();
                    if !response_receiver.recv().unwrap() {
                        error!(
                            "Unable to convert memory with properties: gpa: 0x{gpa:x} size: 0x{size:x} to_private: {private}"
                        );
                        return Err(Error::VcpuUnhandledKvmExit);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => {
                    self.io_bus.read(0, u64::from(addr), data);
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    self.io_bus.write(0, u64::from(addr), data);
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(feature = "tee")]
                VcpuExit::MemoryFault { gpa, size, flags } => {
                    if flags & !kvm_bindings::KVM_MEMORY_EXIT_FLAG_PRIVATE as u64 != 0 {
                        println!("KVM_EXIT_MEMORY_FAULT: Unknown flag {flags}");
                        Err(Error::VcpuUnhandledKvmExit)
                    } else {
                        let private = (flags & (KVM_MEMORY_EXIT_FLAG_PRIVATE as u64)) != 0;
                        let mem_properties = MemoryProperties { gpa, size, private };
                        let (response_sender, response_receiver) = unbounded();
                        self.pm_sender
                            .send(WorkerMessage::ConvertMemory(
                                response_sender.clone(),
                                mem_properties,
                            ))
                            .unwrap();
                        if !response_receiver.recv().unwrap() {
                            error!(
                                "Unable to convert memory with properties: gpa: 0x{gpa:x} size: 0x{size:x} to_private: {private}"
                            );
                            return Err(Error::VcpuUnhandledKvmExit);
                        }
                        Ok(VcpuEmulation::Handled)
                    }
                }
                VcpuExit::MmioRead(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        mmio_bus.read(0, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        mmio_bus.write(0, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::Hlt => {
                    info!("Received KVM_EXIT_HLT signal");
                    Ok(VcpuEmulation::Stopped)
                }
                VcpuExit::Shutdown => {
                    info!("Received KVM_EXIT_SHUTDOWN signal");
                    Ok(VcpuEmulation::Stopped)
                }
                // Documentation specifies that below kvm exits are considered
                // errors.
                VcpuExit::FailEntry(reason, vcpu) => {
                    error!("Received KVM_EXIT_FAIL_ENTRY signal: reason={reason}, vcpu={vcpu}");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                VcpuExit::InternalError => {
                    error!("Received KVM_EXIT_INTERNAL_ERROR signal");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                VcpuExit::SystemEvent(event, _reason) => {
                    match event {
                        KVM_SYSTEM_EVENT_SHUTDOWN => info!("Received KVM_SYSTEM_EVENT_SHUTDOWN"),
                        KVM_SYSTEM_EVENT_RESET => info!("Received KVM_SYSTEM_EVENT_RESET"),
                        _ => error!("Received an unexpected System Event: {event}"),
                    }
                    Ok(VcpuEmulation::Stopped)
                }
                r => {
                    // TODO: Are we sure we want to finish running a vcpu upon
                    // receiving a vm exit that is not necessarily an error?
                    error!("Unexpected exit reason on vcpu run: {r:?}");
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },
            // The unwrap on raw_os_error can only fail if we have a logic
            // error in our code in which case it is better to panic.
            Err(ref e) => {
                match e.errno() {
                    libc::EAGAIN => Ok(VcpuEmulation::Handled),
                    libc::EINTR => {
                        // KVM_RUN has now completed any pending IO/MMIO instruction.
                        // Notify that this KVM_RUN was interrupted.
                        Ok(VcpuEmulation::Interrupted)
                    }
                    _ => {
                        error!("Failure during vcpu run: {e}");
                        Err(Error::VcpuUnhandledKvmExit)
                    }
                }
            }
        }
    }

    /// Main loop of the vCPU thread.
    ///
    /// Runs the vCPU in KVM context in a loop. Handles KVM_EXITs then goes back in.
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&mut self) {
        // Start running the machine state in the `Paused` state.
        StateMachine::run(self, Self::paused);
    }

    // Clear before checking the authoritative mailbox, never before completing an exit.
    // A kick racing the final mailbox check then remains set for the next KVM_RUN.
    fn running(&mut self) -> StateMachine<Self> {
        self.fd.set_kvm_immediate_exit(0);
        match self.event_receiver.try_recv() {
            Ok(command) => return self.control(command),
            Err(TryRecvError::Disconnected) => return StateMachine::finish(),
            Err(TryRecvError::Empty) => (),
        }
        loop {
            match self.run_emulation() {
                Ok(VcpuEmulation::Handled) => (),
                Ok(VcpuEmulation::Interrupted) => return StateMachine::next(Self::running),
                Ok(VcpuEmulation::Stopped) => return self.exit(FC_EXIT_CODE_OK),
                Err(_) => return self.exit(FC_EXIT_CODE_GENERIC_ERROR),
            }
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn execution_command(
        &mut self,
        command: &CpuCommand,
    ) -> std::result::Result<Option<Arc<CpuExecutionState>>, String> {
        use crate::vmm::control::CpuCommandKind;
        match command.kind {
            CpuCommandKind::CaptureExecution => {
                self.execution_time_ready = false;
                if command.execution.is_some() {
                    return Err("capture has unexpected input".into());
                }
                if self.execution_cut.is_none() {
                    let state = execution::capture_cpu(&self.fd, self.id, &self.capture_config)?;
                    // Native timer cancellation can partially fail. The original cut must already have an owner.
                    self.execution_cut = Some(Arc::new(CpuExecutionState::Kvm(state)));
                }
                let state = self
                    .execution_cut
                    .as_ref()
                    .ok_or("missing retained CPU cut")?;
                let CpuExecutionState::Kvm(native) = state.as_ref() else {
                    return Err("wrong CPU backend".into());
                };
                execution::fence_cpu_timer(&self.fd, native)?;
                Ok(Some(Arc::clone(state)))
            }
            CpuCommandKind::InstallExecution => {
                let Some(input) = command.execution.as_deref() else {
                    return Err("install input missing".into());
                };
                let CpuExecutionInput::Install(CpuExecutionState::Kvm(state)) = input else {
                    return Err("install CPU backend mismatch".into());
                };
                if state.id() != self.id {
                    return Err("install logical CPU mismatch".into());
                }
                self.execution_time_ready = false;
                self.execution_cut = Some(Arc::new(CpuExecutionState::Kvm(state.clone())));
                let installed = execution::install_cpu(&self.fd, state, &self.capture_config);
                if installed.is_err() {
                    self.execution_stop_only = true;
                }
                installed?;
                Ok(None)
            }
            CpuCommandKind::PrepareExecutionTime => {
                self.execution_time_ready = false;
                let Some(input) = command.execution.as_deref() else {
                    return Err("time input missing".into());
                };
                let CpuExecutionInput::PrepareTime(crate::vmm::execution::CpuTimePlan::Kvm(plan)) =
                    input
                else {
                    return Err("time CPU backend mismatch".into());
                };
                let Some(state) = self.execution_cut.as_deref() else {
                    return Err("time preparation requires retained cut".into());
                };
                let CpuExecutionState::Kvm(state) = state else {
                    return Err("time retained backend mismatch".into());
                };
                execution::prepare_cpu_time(&self.fd, state, plan)?;
                self.execution_time_ready = true;
                Ok(None)
            }
            _ => Err("not an execution command".into()),
        }
    }

    fn acknowledge_command(&mut self, command: &CpuCommand) -> CpuAck {
        use crate::vmm::control::CpuCommandKind;
        let execution_kind = matches!(
            command.kind,
            CpuCommandKind::CaptureExecution
                | CpuCommandKind::InstallExecution
                | CpuCommandKind::PrepareExecutionTime
        );
        if let Some((original, result)) = self.execution_journal.iter().find(|(original, _)| {
            original.request == command.request
                && original.barrier.key == command.barrier.key
                && original.kind == command.kind
        }) {
            let mut result = result.clone();
            if original.execution != command.execution {
                result.result = Err("conflicting duplicate CPU execution command".into());
                result.execution = None;
            }
            return result;
        }
        let was_running = self.mailbox.disposition() == CpuDisposition::Running;
        let capture_without_retained = command.kind == CpuCommandKind::CaptureExecution
            && self.mailbox.disposition() == CpuDisposition::Prepared
            && self.execution_cut.is_none();
        let mut ack = self.mailbox.apply(self.id, command.clone());
        if ack.result.is_err() {
            return ack;
        }
        if capture_without_retained {
            self.mailbox.preparation_failed();
            ack.result =
                Err("prepared CPU refence requires an original retained execution cut".into());
            return ack;
        }
        if command.kind == CpuCommandKind::Park && was_running {
            self.execution_cut = None;
            self.execution_journal.clear();
            self.execution_time_ready = false;
        }
        if self.execution_stop_only && command.kind != CpuCommandKind::Stop {
            self.mailbox.preparation_failed();
            ack.result = Err("partial execution installation is stop-only".into());
        } else if matches!(command.kind, CpuCommandKind::PrepareResume { .. }) {
            // The ordinary cold-boot path has no retained execution cut.
            if self.execution_cut.is_some() && !self.execution_time_ready {
                self.mailbox.preparation_failed();
                ack.result = Err("common execution clock not prepared".into());
            }
        }
        if execution_kind && ack.result.is_ok() {
            if self.execution_journal.len() >= 32 {
                ack.result = Err("CPU execution journal limit".into());
                return ack;
            } else {
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                match self.execution_command(command) {
                    Ok(payload) => ack.execution = payload,
                    Err(error) => {
                        self.mailbox.preparation_failed();
                        ack.result = Err(error);
                    }
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    ack.result = Err("execution backend unsupported".into());
                }
            }
            self.execution_journal.push((command.clone(), ack.clone()));
        }
        ack
    }

    fn control(&mut self, command: CpuCommand) -> StateMachine<Self> {
        let ack = self.acknowledge_command(&command);
        #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
        let ack = {
            let mut ack = ack;
            if command.kind == crate::vmm::control::CpuCommandKind::Park && ack.result.is_ok() {
                let state = self
                    .fd
                    .get_regs()
                    .map(|regs| ProbeParkState {
                        request: command.request,
                        key: command.barrier.key,
                        cpu_id: self.id,
                        rip: regs.rip,
                        rax: regs.rax,
                    })
                    .map_err(|error| format!("park register observation failed: {error}"));
                if let Err(error) = &state {
                    ack.result = Err(error.clone());
                }
                match self.probe_park_state.lock() {
                    Ok(mut snapshot) => *snapshot = Some(state),
                    Err(_) => ack.result = Err("park observation journal poisoned".to_owned()),
                }
            }
            ack
        };
        // The VM journal, not the presence of a waiting API caller, owns this transition.
        let _ = self.control_sender.send(ack);
        match self.mailbox.disposition() {
            CpuDisposition::Running => StateMachine::next(Self::running),
            CpuDisposition::Parked | CpuDisposition::Prepared => StateMachine::next(Self::paused),
            CpuDisposition::Stopped => StateMachine::finish(),
        }
    }

    fn paused(&mut self) -> StateMachine<Self> {
        match self.event_receiver.recv() {
            Ok(command) => self.control(command),
            Err(_) => StateMachine::finish(),
        }
    }

    fn exit(&mut self, exit_code: u8) -> StateMachine<Self> {
        self.mailbox.halt();
        let _ = self.response_sender.send(VcpuResponse::Exited(exit_code));
        if let Err(error) = self.exit_evt.write(1) {
            log::error!("Failed signaling vCPU exit event: {error}");
        }
        // musl pthread_exit may be forbidden by the process sandbox on guest shutdown.
        StateMachine::next(Self::halted)
    }

    fn halted(&mut self) -> StateMachine<Self> {
        match self.event_receiver.recv() {
            Ok(command) => {
                let stop = command.kind == crate::vmm::control::CpuCommandKind::Stop;
                let _ = self
                    .control_sender
                    .send(self.mailbox.apply(self.id, command));
                if stop {
                    StateMachine::finish()
                } else {
                    StateMachine::next(Self::halted)
                }
            }
            Err(_) => StateMachine::finish(),
        }
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_prepare(&self, launcher: &mut tdx::launch::Launcher) {
        use std::os::fd::AsRawFd;
        launcher.add_vcpu_fd(self.fd.as_raw_fd());
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        let _ = self.reset_thread_local_data();
    }
}

// Lifecycle exits are separate from correlated control acknowledgements.

#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    // Control acknowledgements are delivered through the control mailbox.
    /// Vcpu is stopped.
    Exited(u8),
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
pub struct VcpuHandle {
    event_sender: Sender<CpuCommand>,
    response_receiver: Receiver<VcpuResponse>,
    control_receiver: Receiver<CpuAck>,
    // Rust JoinHandles have to be wrapped in Option if you ever plan on 'join()'ing them.
    // We want to be able to join these threads in tests.
    vcpu_thread: Option<thread::JoinHandle<()>>,
    #[cfg(all(
        any(feature = "native-control-probe", feature = "native-execution-probe"),
        target_arch = "x86_64"
    ))]
    probe_ack_hold: std::sync::Mutex<ProbeAckHold>,
    #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
    probe_park_state: ProbeParkJournal,
}

impl VcpuHandle {
    fn new(
        event_sender: Sender<CpuCommand>,
        response_receiver: Receiver<VcpuResponse>,
        control_receiver: Receiver<CpuAck>,
        vcpu_thread: thread::JoinHandle<()>,
        #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
        probe_park_state: ProbeParkJournal,
    ) -> Self {
        Self {
            event_sender,
            response_receiver,
            control_receiver,
            vcpu_thread: Some(vcpu_thread),
            #[cfg(all(
                any(feature = "native-control-probe", feature = "native-execution-probe"),
                target_arch = "x86_64"
            ))]
            probe_ack_hold: std::sync::Mutex::new(ProbeAckHold::default()),
            #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
            probe_park_state,
        }
    }

    pub fn send_control(&self, command: CpuCommand) -> CpuSubmission {
        #[cfg(all(
            any(feature = "native-control-probe", feature = "native-execution-probe"),
            target_arch = "x86_64"
        ))]
        if command.kind == crate::vmm::control::CpuCommandKind::Stop {
            match self.probe_ack_hold.lock() {
                Ok(mut hold) => hold.kind = None,
                Err(_) => return CpuSubmission::Rejected("probe ACK gate poisoned".to_owned()),
            }
        }
        submit_command(&self.event_sender, command, || {
            match self.vcpu_thread.as_ref() {
                Some(thread) => thread
                    .kill(sigrtmin() + VCPU_RTSIG_OFFSET)
                    .map_err(|error| error.to_string()),
                None => Err("vCPU thread already reaped".to_owned()),
            }
        })
    }

    pub fn try_control_ack(&self) -> std::result::Result<Option<CpuAck>, String> {
        #[cfg(all(
            any(feature = "native-control-probe", feature = "native-execution-probe"),
            target_arch = "x86_64"
        ))]
        {
            let mut hold = self
                .probe_ack_hold
                .lock()
                .map_err(|_| "probe ACK gate poisoned".to_owned())?;
            if let Some(ack) = hold.pending.as_ref() {
                if hold.kind == Some(ack.kind) {
                    return Ok(None);
                }
                return Ok(hold.pending.take());
            }
            if let Some(ack) = self.receive_control_ack()? {
                if hold.kind == Some(ack.kind) {
                    hold.pending = Some(ack);
                    return Ok(None);
                }
                return Ok(Some(ack));
            }
            Ok(None)
        }
        #[cfg(not(all(
            any(feature = "native-control-probe", feature = "native-execution-probe"),
            target_arch = "x86_64"
        )))]
        self.receive_control_ack()
    }

    fn receive_control_ack(&self) -> std::result::Result<Option<CpuAck>, String> {
        match self.control_receiver.try_recv() {
            Ok(ack) => Ok(Some(ack)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err("vCPU ack channel closed".to_owned()),
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
                .map_err(|_| "vCPU owner thread panicked".to_owned())?;
        }
        Ok(true)
    }

    #[cfg(all(
        any(feature = "native-control-probe", feature = "native-execution-probe"),
        target_arch = "x86_64"
    ))]
    pub(crate) fn set_probe_ack_hold(
        &self,
        kind: Option<crate::vmm::control::CpuCommandKind>,
    ) -> std::result::Result<(), String> {
        use crate::vmm::control::{CpuAckKind, CpuCommandKind};
        let mut hold = self
            .probe_ack_hold
            .lock()
            .map_err(|_| "probe ACK gate poisoned".to_owned())?;
        hold.kind = kind.map(|kind| match kind {
            CpuCommandKind::Park => CpuAckKind::Parked,
            CpuCommandKind::PrepareResume { .. } => CpuAckKind::Prepared,
            CpuCommandKind::Release => CpuAckKind::Released,
            CpuCommandKind::Stop => CpuAckKind::Stopped,
            CpuCommandKind::CaptureExecution => CpuAckKind::Captured,
            CpuCommandKind::InstallExecution => CpuAckKind::Installed,
            CpuCommandKind::PrepareExecutionTime => CpuAckKind::TimePrepared,
        });
        Ok(())
    }

    #[cfg(all(
        any(feature = "native-control-probe", feature = "native-execution-probe"),
        target_arch = "x86_64"
    ))]
    pub(crate) fn probe_held_ack(&self) -> std::result::Result<Option<CpuAck>, String> {
        let hold = self
            .probe_ack_hold
            .lock()
            .map_err(|_| "probe ACK gate poisoned".to_owned())?;
        Ok(hold.pending.clone())
    }

    #[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
    pub(crate) fn probe_park_state(&self) -> std::result::Result<Option<ProbeParkState>, String> {
        let snapshot = self
            .probe_park_state
            .lock()
            .map_err(|_| "park observation journal poisoned".to_owned())?;
        snapshot.clone().transpose()
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

#[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
type ProbeParkJournal = Arc<std::sync::Mutex<Option<std::result::Result<ProbeParkState, String>>>>;

#[cfg(all(feature = "native-control-probe", target_arch = "x86_64"))]
#[derive(Clone, Debug)]
pub(crate) struct ProbeParkState {
    pub request: crate::vmm::control::RequestId,
    pub key: polly::event_manager::BarrierKey,
    pub cpu_id: u8,
    pub rip: u64,
    pub rax: u64,
}

#[cfg(all(
    any(feature = "native-control-probe", feature = "native-execution-probe"),
    target_arch = "x86_64"
))]
#[derive(Default)]
struct ProbeAckHold {
    kind: Option<crate::vmm::control::CpuAckKind>,
    pending: Option<CpuAck>,
}

impl Drop for VcpuHandle {
    fn drop(&mut self) {
        if let Some(thread) = self.vcpu_thread.take() {
            if !thread.is_finished() {
                use crate::vmm::control::{CpuCommandKind, RequestId};
                use polly::event_manager::{
                    BarrierGeneration, BarrierKey, BarrierRequest, OperationId,
                };
                let _ = self.event_sender.send(CpuCommand {
                    request: RequestId(u64::MAX),
                    barrier: BarrierRequest {
                        key: BarrierKey {
                            operation: OperationId(0),
                            generation: BarrierGeneration(0),
                        },
                        deadline: std::time::Instant::now(),
                    },
                    kind: CpuCommandKind::Stop,
                    execution: None,
                });
                let _ = thread.kill(sigrtmin() + VCPU_RTSIG_OFFSET);
            }
            // Event-owner cleanup reaps asynchronously. This is the fallback for
            // construction failure or an API owner dropped outside that loop.
            if thread.join().is_err() {
                log::error!("vCPU owner thread panicked during terminal cleanup");
            }
        }
    }
}

enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    #[cfg(target_arch = "aarch64")]
    use crate::vmm::builder::Payload;
    #[cfg(target_arch = "aarch64")]
    use crate::vmm::builder::create_guest_memory;
    use crate::vmm::linux::vstate::*;
    use devices;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::KvmIoapic;

    use utils::signal::validate_signal_num;

    // Auxiliary function being used throughout the tests.
    fn setup_vcpu(mem_size: usize) -> (Vm, Vcpu, GuestMemoryMmap) {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        assert!(vm.memory_init(&gm, kvm.max_memslots()).is_ok());

        let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();

        let vcpu;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            vcpu = Vcpu::new_x86_64(
                1,
                vm.fd(),
                vm.supported_cpuid().clone(),
                vm.supported_msrs().clone(),
                devices::Bus::new(),
                exit_evt,
            )
            .unwrap();
        }
        #[cfg(target_arch = "aarch64")]
        {
            vcpu = Vcpu::new_aarch64(1, vm.fd(), exit_evt).unwrap();
        }

        (vm, vcpu, gm)
    }

    #[test]
    fn test_set_mmio_bus() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);
        assert!(vcpu.mmio_bus.is_none());
        vcpu.set_mmio_bus(devices::Bus::new());
        assert!(vcpu.mmio_bus.is_some());
    }

    #[ignore]
    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_supported_cpuid() {
        let kvm = KvmContext::new().unwrap();
        let vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        let cpuid = kvm
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .expect("Cannot get supported cpuid");
        assert_eq!(vm.supported_cpuid().as_slice(), cpuid.as_slice());
    }

    #[test]
    fn test_vm_memory_init() {
        let mut kvm_context = KvmContext::new().unwrap();
        let mut vm = Vm::new(kvm_context.fd()).expect("Cannot create new vm");

        // Create valid memory region and test that the initialization is successful.
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        assert!(vm.memory_init(&gm, kvm_context.max_memslots()).is_ok());

        // Set the maximum number of memory slots to 1 in KvmContext to check the error
        // path of memory_init. Create 2 non-overlapping memory slots.
        kvm_context.max_memslots = 1;
        let gm = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x0), 0x1000),
            (GuestAddress(0x1001), 0x2000),
        ])
        .unwrap();
        assert!(vm.memory_init(&gm, kvm_context.max_memslots()).is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_configure_vcpu() {
        let (_vm, mut vcpu, vm_mem) = setup_vcpu(0x10000);

        let mut vcpu_config = VcpuConfig {
            vcpu_count: 1,
            ht_enabled: false,
            cpu_template: None,
            nested_enabled: false,
        };

        assert!(
            vcpu.configure_x86_64(&vm_mem, GuestAddress(0), &vcpu_config, true, false)
                .is_ok()
        );

        // Test configure while using the T2 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::T2);
        assert!(
            vcpu.configure_x86_64(&vm_mem, GuestAddress(0), &vcpu_config, true, false)
                .is_ok()
        );

        // Test configure while using the C3 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::C3);
        assert!(
            vcpu.configure_x86_64(&vm_mem, GuestAddress(0), &vcpu_config, true, false)
                .is_ok()
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_configure_vcpu() {
        let kvm = KvmContext::new().unwrap();
        let (guest_memory, arch_memory_info, _shm_manager, _payload_config) = create_guest_memory(
            128,
            None,
            #[cfg(feature = "tee")]
            None,
            #[cfg(feature = "tee")]
            None,
            None,
            &[],
            None,
            false,
            &Payload::Empty,
            #[cfg(feature = "tee")]
            None,
        )
        .unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("new vm failed");
        assert!(vm.memory_init(&guest_memory, kvm.max_memslots()).is_ok());

        // Try it for when vcpu id is 0.
        let mut vcpu = Vcpu::new_aarch64(
            0,
            vm.fd(),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();

        assert!(
            vcpu.configure_aarch64(vm.fd(), &arch_memory_info, GuestAddress(0))
                .is_ok()
        );

        // Try it for when vcpu id is NOT 0.
        let mut vcpu = Vcpu::new_aarch64(
            1,
            vm.fd(),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();

        assert!(
            vcpu.configure_aarch64(vm.fd(), &arch_memory_info, GuestAddress(0))
                .is_ok()
        );
    }

    #[test]
    fn test_vcpu_tls() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);

        // Running on the TLS vcpu should fail before we actually initialize it.
        unsafe {
            assert!(Vcpu::run_on_thread_local(|_| ()).is_err());
        }

        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();

        // Validate TLS vcpu is the local vcpu by changing the `id` then validating against
        // the one in TLS.
        vcpu.id = 12;
        unsafe {
            assert!(Vcpu::run_on_thread_local(|v| assert_eq!(v.id, 12)).is_ok());
        }

        // Reset vcpu TLS.
        assert!(vcpu.reset_thread_local_data().is_ok());

        // Running on the TLS vcpu after TLS reset should fail.
        unsafe {
            assert!(Vcpu::run_on_thread_local(|_| ()).is_err());
        }

        // Second reset should return error.
        assert!(vcpu.reset_thread_local_data().is_err());
    }

    #[test]
    fn test_invalid_tls() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);
        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();
        // Trying to initialize non-empty TLS should error.
        vcpu.init_thread_local_data().unwrap_err();
    }

    #[test]
    fn test_vcpu_kick() {
        Vcpu::register_kick_signal_handler().unwrap();
        let (vm, mut vcpu, _mem) = setup_vcpu(0x1000);

        let mut kvm_run =
            KvmRunWrapper::mmap_from_fd(&vcpu.fd, vm.fd.run_size()).expect("cannot mmap kvm-run");
        let success = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let vcpu_success = success.clone();
        let barrier = Arc::new(Barrier::new(2));
        let vcpu_barrier = barrier.clone();
        // Start Vcpu thread which will be kicked with a signal.
        let handle = std::thread::Builder::new()
            .name("test_vcpu_kick".to_string())
            .spawn(move || {
                vcpu.init_thread_local_data().unwrap();
                // Notify TLS was populated.
                vcpu_barrier.wait();
                // Loop for max 1 second to check if the signal handler has run.
                for _ in 0..10 {
                    if kvm_run.as_mut_ref().immediate_exit == 1 {
                        // Signal handler has run and set immediate_exit to 1.
                        vcpu_success.store(true, Ordering::Release);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            })
            .expect("cannot start thread");

        // Wait for the vcpu to initialize its TLS.
        barrier.wait();
        // Kick the Vcpu using the custom signal.
        handle
            .kill(sigrtmin() + VCPU_RTSIG_OFFSET)
            .expect("failed to signal thread");
        handle.join().expect("failed to join thread");
        // Verify that the Vcpu saw its kvm immediate-exit as set.
        assert!(success.load(Ordering::Acquire));
    }

    #[test]
    fn test_vcpu_rtsig_offset() {
        assert!(validate_signal_num(sigrtmin() + VCPU_RTSIG_OFFSET).is_ok());
    }
}
