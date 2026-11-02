// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Package-local compiled feature and build-input observations.
pub mod build_facts {
    include!(concat!(env!("OUT_DIR"), "/live_build.rs"));
}

#[allow(non_camel_case_types)]
#[allow(improper_ctypes)]
#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(deref_nullptr)]
pub mod bindings;
mod discard;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub mod framework;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod probe;
pub mod reclaim;
pub mod remap;

use bindings::*;

#[cfg(target_arch = "aarch64")]
use std::arch::asm;
use std::cell::Cell;

use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use crate::framework::{HvfFramework, OwnedConfig};
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use arch::aarch64::sysreg::{SYSREG_MASK, sys_reg_name};
use arch::guest_memory::RamLayout;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use reclaim::ReclaimQualification;
use reclaim::{FaultResolution, ReclaimState, ReclaimStateError};

unsafe extern "C" {
    pub fn mach_absolute_time() -> u64;
}

const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;

const TMR_CTL_ENABLE: u64 = 1 << 0;
const TMR_CTL_IMASK: u64 = 1 << 1;
const TMR_CTL_ISTATUS: u64 = 1 << 2;

const PSR_MODE_EL1H: u64 = 0x0000_0005;
const PSR_MODE_EL2H: u64 = 0x0000_0009;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
const PSTATE_EL1_FAULT_BITS_64: u64 = PSR_MODE_EL1H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;
const PSTATE_EL2_FAULT_BITS_64: u64 = PSR_MODE_EL2H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

const HCR_TLOR: u64 = 1 << 35;
const HCR_RW: u64 = 1 << 31;
const HCR_TSW: u64 = 1 << 22;
const HCR_TACR: u64 = 1 << 21;
const HCR_TIDCP: u64 = 1 << 20;
const HCR_TSC: u64 = 1 << 19;
const HCR_TID3: u64 = 1 << 18;
const HCR_TWE: u64 = 1 << 14;
const HCR_TWI: u64 = 1 << 13;
const HCR_BSU_IS: u64 = 1 << 10;
const HCR_FB: u64 = 1 << 9;
const HCR_AMO: u64 = 1 << 5;
const HCR_IMO: u64 = 1 << 4;
const HCR_FMO: u64 = 1 << 3;
const HCR_PTW: u64 = 1 << 2;
const HCR_SWIO: u64 = 1 << 1;
const HCR_VM: u64 = 1 << 0;
// Use the same bits as KVM uses in vcpu reset.
const HCR_EL2_BITS: u64 = HCR_TSC
    | HCR_TSW
    | HCR_TWE
    | HCR_TWI
    | HCR_VM
    | HCR_BSU_IS
    | HCR_FB
    | HCR_TACR
    | HCR_AMO
    | HCR_SWIO
    | HCR_TIDCP
    | HCR_RW
    | HCR_TLOR
    | HCR_FMO
    | HCR_IMO
    | HCR_PTW
    | HCR_TID3;

const CNTHCTL_EL0VCTEN: u64 = 1 << 1;
const CNTHCTL_EL0PCTEN: u64 = 1 << 0;
// Trap accesses to both virtual and physical counter registers.
const CNTHCTL_EL2_BITS: u64 = CNTHCTL_EL0VCTEN | CNTHCTL_EL0PCTEN;

const AA64PFR0_EL1_EL2EN: u64 = 1 << 8;
const AA64PFR0_EL1_GIC3EN: u64 = 1 << 24;
const AA64PFR1_EL1_SMEMASK: u64 = 3 << 24;

const EC_WFX_TRAP: u64 = 0x1;
const EC_AA64_HVC: u64 = 0x16;
const EC_AA64_SMC: u64 = 0x17;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
const EC_SYSTEMREGISTERTRAP: u64 = 0x18;
const EC_DATAABORT: u64 = 0x24;
const EC_DATAABORT_CURRENT: u64 = 0x25;
const EC_INSTRUCTIONABORT: u64 = 0x20;
const EC_INSTRUCTIONABORT_CURRENT: u64 = 0x21;
const EC_AA64_BKPT: u64 = 0x3c;

#[derive(Debug)]
pub enum Error {
    FindSymbol(libloading::Error),
    LoadFramework(libloading::Error),
    NullObject(&'static str),
    NativeCall {
        symbol: &'static str,
        status: hv_return_t,
    },
    MemoryMap,
    MemorySize,
    MemoryUnmap,
    InvalidMemoryFault,
    ReclaimState(ReclaimStateError),
    ReclaimProbeCleanup(String),
    UnsupportedPsci(u64),
    UnsupportedSystemRegister {
        register: u32,
        write: bool,
    },
    UnexpectedExit {
        reason: hv_exit_reason_t,
        pc: u64,
    },
    UnsupportedException(u64),
    VmBusy,
    VmDestroy,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use crate::Error::*;

        match self {
            FindSymbol(err) => write!(f, "Couldn't find symbol in HVF library: {err}"),
            LoadFramework(err) => write!(f, "Couldn't load HVF framework: {err}"),
            NullObject(symbol) => write!(f, "{symbol} returned a null object"),
            NativeCall { symbol, status } => write!(f, "{symbol} failed: {status}"),
            MemoryMap => write!(f, "Error registering memory region in HVF"),
            MemorySize => write!(f, "Memory region size is not representable by HVF"),
            MemoryUnmap => write!(f, "Error unregistering memory region in HVF"),
            InvalidMemoryFault => write!(f, "Invalid fault in mapped guest RAM"),
            ReclaimState(err) => write!(f, "Error tracking guest RAM in HVF: {err}"),
            ReclaimProbeCleanup(err) => write!(f, "Error cleaning up HVF reclaim probe: {err}"),
            UnsupportedPsci(function) => write!(f, "Unsupported PSCI function {function:#x}"),
            UnsupportedSystemRegister { register, write } => {
                write!(
                    f,
                    "Unsupported system register {register:#x}, write={write}"
                )
            }
            UnexpectedExit { reason, pc } => {
                write!(f, "Unexpected HVF exit {reason:#x} at {pc:#x}")
            }
            UnsupportedException(class) => write!(f, "Unsupported exception class {class:#x}"),
            VmBusy => write!(f, "HVF VM is still owned by a cleanup worker"),
            VmDestroy => write!(f, "Error destroying HVF VM instance"),
        }
    }
}

pub enum InterruptType {
    Irq,
    Fiq,
}

pub trait Vcpus {
    fn set_vtimer_irq(&self, vcpuid: u64);
    fn should_wait(&self, vcpuid: u64) -> bool;
    fn has_pending_irq(&self, vcpuid: u64) -> bool;
    fn get_pending_irq(&self, vcpuid: u64) -> u32;
    fn handle_sysreg_read(&self, vcpuid: u64, reg: u32) -> Option<u64>;
    fn handle_sysreg_write(&self, vcpuid: u64, reg: u32, val: u64) -> bool;
}

pub fn vcpu_request_exit(vcpuid: u64) -> Result<(), Error> {
    let mut vcpu: u64 = vcpuid;
    let ret = unsafe { hv_vcpus_exit(&mut vcpu, 1) };

    if ret != HV_SUCCESS {
        Err(Error::NativeCall {
            symbol: "hv_vcpus_exit",
            status: ret,
        })
    } else {
        Ok(())
    }
}

pub fn vcpu_set_pending_irq(
    vcpuid: u64,
    irq_type: InterruptType,
    pending: bool,
) -> Result<(), Error> {
    let _type = match irq_type {
        InterruptType::Irq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_IRQ,
        InterruptType::Fiq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_FIQ,
    };

    let ret = unsafe { hv_vcpu_set_pending_interrupt(vcpuid, _type, pending) };

    if ret != HV_SUCCESS {
        Err(Error::NativeCall {
            symbol: "hv_vcpu_set_pending_interrupt",
            status: ret,
        })
    } else {
        Ok(())
    }
}

pub fn vcpu_set_vtimer_mask(vcpuid: u64, masked: bool) -> Result<(), Error> {
    let ret = unsafe { hv_vcpu_set_vtimer_mask(vcpuid, masked) };

    if ret != HV_SUCCESS {
        Err(Error::NativeCall {
            symbol: "hv_vcpu_set_vtimer_mask",
            status: ret,
        })
    } else {
        Ok(())
    }
}

/// Checks if Nested Virtualization is supported on the current system. Only
/// M3 or newer chips on macOS 15+ will satisfy the requirements.
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub fn check_nested_virt() -> Result<bool, Error> {
    let framework = HvfFramework::load()?;
    let get_el2_supported = match unsafe {
        framework.symbol::<unsafe extern "C" fn(*mut bool) -> hv_return_t>(
            b"hv_vm_config_get_el2_supported\0",
        )
    } {
        Ok(symbol) => symbol,
        Err(Error::FindSymbol(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut el2_supported = false;
    let ret = unsafe { get_el2_supported(&mut el2_supported) };
    if ret != HV_SUCCESS {
        return Err(Error::NativeCall {
            symbol: "hv_vm_config_get_el2_supported",
            status: ret,
        });
    }
    Ok(el2_supported)
}

pub struct HvfVm {
    reclaim_state: Arc<ReclaimState>,
    nested_enabled: bool,
    ipa_bits: Option<u32>,
    lifetime: Arc<HvfVmLifetime>,
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    framework: Arc<HvfFramework>,
}

/// Keeps the VM and its resolved framework alive on a vCPU owner thread.
pub struct HvfCpuResources {
    _lifetime: Arc<HvfVmLifetime>,
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    _framework: Arc<HvfFramework>,
}

pub(crate) struct HvfVmLifetime {
    destroyed: AtomicBool,
}

impl HvfVmLifetime {
    pub(crate) fn new() -> Self {
        Self {
            destroyed: AtomicBool::new(false),
        }
    }

    pub(crate) fn destroy(&self) -> Result<(), Error> {
        if self.destroyed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if unsafe { hv_vm_destroy() } != HV_SUCCESS {
            self.destroyed.store(false, Ordering::Release);
            Err(Error::VmDestroy)
        } else {
            Ok(())
        }
    }
}

impl Drop for HvfVmLifetime {
    fn drop(&mut self) {
        if !self.destroyed.swap(true, Ordering::AcqRel) && unsafe { hv_vm_destroy() } != HV_SUCCESS
        {
            log::error!("failed to destroy HVF VM at final owner teardown");
        }
    }
}

impl HvfVm {
    pub fn cpu_resources(&self) -> HvfCpuResources {
        HvfCpuResources {
            _lifetime: Arc::clone(&self.lifetime),
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            _framework: Arc::clone(&self.framework),
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    pub fn new(nested_enabled: bool) -> Result<Self, Error> {
        let framework = HvfFramework::load()?;
        let reclaim_state = Arc::new(ReclaimState::new());
        let config = unsafe {
            OwnedConfig::new(
                hv_vm_config_create(),
                Arc::clone(&framework),
                "hv_vm_config_create",
            )?
        };
        let mut ipa_bits = 0;
        let ipa_bits =
            if unsafe { hv_vm_config_get_ipa_size(config.as_ptr(), &mut ipa_bits) } == HV_SUCCESS {
                Some(ipa_bits)
            } else {
                None
            };
        if nested_enabled {
            let set_el2_enabled = unsafe {
                framework.symbol::<unsafe extern "C" fn(hv_vm_config_t, bool) -> hv_return_t>(
                    b"hv_vm_config_set_el2_enabled\0",
                )?
            };
            let ret = unsafe { set_el2_enabled(config.as_ptr(), true) };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vm_config_set_el2_enabled",
                    status: ret,
                });
            }
        }

        let ret = unsafe { hv_vm_create(config.as_ptr()) };

        if ret != HV_SUCCESS {
            Err(Error::NativeCall {
                symbol: "hv_vm_create",
                status: ret,
            })
        } else {
            Ok(Self {
                reclaim_state,
                nested_enabled,
                ipa_bits,
                lifetime: Arc::new(HvfVmLifetime::new()),
                framework,
            })
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    pub fn framework(&self) -> Arc<HvfFramework> {
        Arc::clone(&self.framework)
    }

    pub fn map_memory(
        &self,
        host_start_addr: u64,
        guest_start_addr: u64,
        size: u64,
    ) -> Result<(), Error> {
        let size = size.try_into().map_err(|_| Error::MemorySize)?;
        let ret = unsafe {
            hv_vm_map(
                host_start_addr as *mut core::ffi::c_void,
                guest_start_addr,
                size,
                (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC).into(),
            )
        };
        if ret != HV_SUCCESS {
            Err(Error::MemoryMap)
        } else {
            Ok(())
        }
    }

    pub fn reclaim_state(&self) -> Arc<ReclaimState> {
        Arc::clone(&self.reclaim_state)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    pub fn qualify_reclaim<T: Send + 'static>(
        &self,
        occupied: &[arch::guest_memory::GuestRange],
        parent_lifetime: T,
    ) -> Result<(), Error> {
        if self.nested_enabled {
            self.reclaim_state.record_qualification(
                ReclaimQualification::Inconclusive,
                "host reclaim is not qualified for nested EL2 guests",
            );
            return Ok(());
        }
        if !self.reclaim_state.is_eligible() {
            self.reclaim_state.record_qualification(
                ReclaimQualification::Inconclusive,
                "workload RAM is not private anonymous memory",
            );
            return Ok(());
        }
        let Some(ipa_bits) = self.ipa_bits else {
            self.reclaim_state.record_qualification(
                ReclaimQualification::Inconclusive,
                "hv_vm_config_get_ipa_size did not return the VM IPA cap",
            );
            return Ok(());
        };
        let report = probe::run_reclaim_probe(
            ipa_bits,
            occupied,
            probe::ProbeMode::Release,
            Arc::clone(&self.lifetime),
            parent_lifetime,
        )
        .map_err(|error| Error::ReclaimProbeCleanup(error.to_string()))?;
        let detail = format!(
            "ipa_bits={ipa_bits} elapsed_us={} baseline={:?} touched={:?} released={:?} retouched={:?}; {}",
            report.elapsed.as_micros(),
            report.baseline,
            report.touched,
            report.released,
            report.retouched,
            report.detail
        );
        self.reclaim_state
            .record_qualification(report.qualification, &detail);
        Ok(())
    }

    /// Installs the releasable RAM layout once every region is mapped.
    pub fn initialize_reclaim(&self, layout: RamLayout) -> Result<(), Error> {
        self.reclaim_state
            .initialize(layout)
            .map_err(Error::ReclaimState)
    }

    pub fn unmap_memory(&self, guest_start_addr: u64, size: u64) -> Result<(), Error> {
        let size = size.try_into().map_err(|_| Error::MemorySize)?;
        let ret = unsafe { hv_vm_unmap(guest_start_addr, size) };
        if ret != HV_SUCCESS {
            Err(Error::MemoryUnmap)
        } else {
            Ok(())
        }
    }

    /// Destroys the VM if this is its final lifetime owner.
    ///
    /// A busy error consumes this outer handle, but another owner (such as a
    /// reclaim-probe cleanup worker) retains the VM until its work completes.
    pub fn destroy(self) -> Result<(), Error> {
        let Self { lifetime, .. } = self;
        unique_vm_lifetime(lifetime)?.destroy()
    }
}

fn unique_vm_lifetime(lifetime: Arc<HvfVmLifetime>) -> Result<HvfVmLifetime, Error> {
    Arc::try_unwrap(lifetime).map_err(|_| Error::VmBusy)
}

#[derive(Debug)]
pub enum VcpuExit<'a> {
    Breakpoint,
    Canceled,
    CpuOn(u64, u64, u64),
    HypervisorCall,
    MmioRead(u64, &'a mut [u8]),
    MmioWrite(u64, &'a [u8]),
    /// A stage-2 fault raced a RAM release cycle; re-run the vCPU.
    MemoryRetry,
    PsciHandled,
    SecureMonitorCall,
    Shutdown,
    SystemRegister,
    VtimerActivated,
    WaitForEvent,
    WaitForEventExpired,
    WaitForEventTimeout(Duration),
}

#[derive(Clone, Copy)]
struct MmioRead {
    len: usize,
    srt: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmioAccess {
    is_write: bool,
    len: usize,
    register: u32,
}

/// A single same-VM resume target, retained even when the native setter fails.
pub struct VtimerResume {
    baseline: u64,
    target: Option<u64>,
}

impl VtimerResume {
    pub fn new(baseline: u64) -> Self {
        Self {
            baseline,
            target: None,
        }
    }

    pub fn prepare(&mut self, paused_ticks: u64) -> Result<u64, String> {
        let target = self
            .baseline
            .checked_add(paused_ticks)
            .ok_or_else(|| "HVF timer offset overflow".to_owned())?;
        if self.target.is_some_and(|previous| previous != target) {
            return Err("HVF timer preparation target changed".to_owned());
        }
        self.target = Some(target);
        Ok(target)
    }
}

pub struct HvfVcpu<'a> {
    vcpuid: hv_vcpu_t,
    vcpu_exit: Option<&'a hv_vcpu_exit_t>,
    cntfrq: u64,
    mmio_buf: [u8; 8],
    pending_mmio_read: Option<MmioRead>,
    pending_advance_pc: bool,
    vtimer_masked: bool,
    nested_enabled: bool,
    // Cached copy of the HVF vtimer offset (0 until a live pause advances it),
    // so the WFE deadline check doesn't issue a syscall on every wait.
    vtimer_offset: Cell<u64>,
    destroyed: bool,
    _owner_thread: PhantomData<Rc<()>>,
}

impl HvfVcpu<'_> {
    pub fn new(nested_enabled: bool) -> Result<Self, Error> {
        let mut vcpuid: hv_vcpu_t = 0;
        let mut vcpu_exit_ptr: *mut hv_vcpu_exit_t = std::ptr::null_mut();

        #[cfg(target_arch = "aarch64")]
        let cntfrq = {
            let cntfrq: u64;
            unsafe { asm!("mrs {}, cntfrq_el0", out(reg) cntfrq) };
            cntfrq
        };
        #[cfg(target_arch = "x86_64")]
        let cntfrq = 0u64;
        #[cfg(target_arch = "riscv64")]
        let cntfrq = 0u64;

        let ret = unsafe {
            hv_vcpu_create(
                &mut vcpuid,
                &mut vcpu_exit_ptr as *mut *mut _,
                std::ptr::null_mut(),
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_vcpu_create",
                status: ret,
            });
        }

        Ok(Self {
            vcpuid,
            vcpu_exit: unsafe { vcpu_exit_ptr.as_ref() },
            cntfrq,
            mmio_buf: [0; 8],
            pending_mmio_read: None,
            pending_advance_pc: false,
            vtimer_masked: false,
            nested_enabled,
            vtimer_offset: Cell::new(0),
            destroyed: false,
            _owner_thread: PhantomData,
        })
    }

    pub fn initialize(&self, mpidr: u64) -> Result<(), Error> {
        if self.vcpu_exit.is_none() {
            return Err(Error::NullObject("hv_vcpu_create exit record"));
        }
        let ret =
            unsafe { hv_vcpu_set_sys_reg(self.vcpuid, hv_sys_reg_t_HV_SYS_REG_MPIDR_EL1, mpidr) };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_vcpu_set_sys_reg(MPIDR_EL1)",
                status: ret,
            });
        }
        Ok(())
    }

    pub fn set_initial_state(&self, entry_addr: u64, fdt_addr: u64) -> Result<(), Error> {
        if self.nested_enabled {
            let ret = unsafe {
                hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_CPSR, PSTATE_EL2_FAULT_BITS_64)
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_set_reg(CPSR)",
                    status: ret,
                });
            }

            let ret = unsafe {
                hv_vcpu_set_sys_reg(self.vcpuid, hv_sys_reg_t_HV_SYS_REG_HCR_EL2, HCR_EL2_BITS)
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_set_sys_reg(HCR_EL2)",
                    status: ret,
                });
            }

            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2,
                    CNTHCTL_EL2_BITS,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_set_sys_reg(CNTHCTL_EL2)",
                    status: ret,
                });
            }

            // Enable EL2 and GICv3 in ID_AA64PFR0_EL1
            let mut val: u64 = 0;
            let ret = unsafe {
                hv_vcpu_get_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
                    &mut val as *mut _,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_get_sys_reg(ID_AA64PFR0_EL1)",
                    status: ret,
                });
            }
            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
                    val | AA64PFR0_EL1_EL2EN | AA64PFR0_EL1_GIC3EN,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_set_sys_reg(ID_AA64PFR0_EL1)",
                    status: ret,
                });
            }

            // If SME is enabled in ID_AA64PFR1_EL1 in the VM, the guest will
            // break after enabling the MMU. Mask it out.
            let mut val: u64 = 0;
            let ret = unsafe {
                hv_vcpu_get_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
                    &mut val as *mut _,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_get_sys_reg(ID_AA64PFR1_EL1)",
                    status: ret,
                });
            }
            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
                    val & !AA64PFR1_EL1_SMEMASK,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_set_sys_reg(ID_AA64PFR1_EL1)",
                    status: ret,
                });
            }
        } else {
            let ret = unsafe {
                hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_CPSR, PSTATE_EL1_FAULT_BITS_64)
            };
            if ret != HV_SUCCESS {
                return Err(Error::NativeCall {
                    symbol: "hv_vcpu_set_reg(CPSR)",
                    status: ret,
                });
            }
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_PC, entry_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_vcpu_set_reg(PC)",
                status: ret,
            });
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_X0, fdt_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_vcpu_set_reg(X0)",
                status: ret,
            });
        }

        Ok(())
    }

    pub fn id(&self) -> u64 {
        self.vcpuid
    }

    fn read_reg(&self, reg: u32) -> Result<u64, Error> {
        let mut val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_reg(self.vcpuid, reg, &mut val as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::NativeCall {
                symbol: "hv_vcpu_get_reg",
                status: ret,
            })
        } else {
            Ok(val)
        }
    }

    pub fn write_reg(&self, rt: u32, val: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, rt, val) };
        if ret != HV_SUCCESS {
            Err(Error::NativeCall {
                symbol: "hv_vcpu_set_reg",
                status: ret,
            })
        } else {
            Ok(())
        }
    }

    fn read_sys_reg(&self, reg: u16) -> Result<u64, Error> {
        let mut val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_sys_reg(self.vcpuid, reg, &mut val as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::NativeCall {
                symbol: "hv_vcpu_get_sys_reg",
                status: ret,
            })
        } else {
            Ok(val)
        }
    }

    /// Applies an absolute target, so reconciliation cannot add paused time twice.
    pub fn set_vtimer_offset(&self, target: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_vtimer_offset(self.vcpuid, target) };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_vcpu_set_vtimer_offset",
                status: ret,
            });
        }
        self.vtimer_offset.set(target);
        Ok(())
    }

    pub fn vtimer_offset(&self) -> u64 {
        self.vtimer_offset.get()
    }

    pub fn destroy(&mut self) -> Result<(), Error> {
        if self.destroyed {
            return Ok(());
        }
        let ret = unsafe { hv_vcpu_destroy(self.vcpuid) };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_vcpu_destroy",
                status: ret,
            });
        }
        self.destroyed = true;
        Ok(())
    }

    /// Completes host-side emulation only, without executing another guest instruction.
    pub fn finish_pending_emulation(&mut self) -> Result<(), Error> {
        if let Some(mmio_read) = self.pending_mmio_read {
            if mmio_read.srt < 31 {
                let value = mmio_value(&self.mmio_buf, mmio_read.len)?;
                self.write_reg(mmio_read.srt, value)?;
            }
            self.pending_mmio_read = None;
        }
        if self.pending_advance_pc {
            let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
            let next = pc.checked_add(4).ok_or(Error::InvalidMemoryFault)?;
            self.write_reg(hv_reg_t_HV_REG_PC, next)?;
            self.pending_advance_pc = false;
        }
        Ok(())
    }

    fn hvf_sync_vtimer(&mut self, vcpu_list: Arc<dyn Vcpus>) -> Result<(), Error> {
        if !self.vtimer_masked {
            return Ok(());
        }
        let ctl = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)?;
        let irq_state = (ctl & (TMR_CTL_ENABLE | TMR_CTL_IMASK | TMR_CTL_ISTATUS))
            == (TMR_CTL_ENABLE | TMR_CTL_ISTATUS);
        vcpu_list.set_vtimer_irq(self.vcpuid);
        if !irq_state {
            vcpu_set_vtimer_mask(self.vcpuid, false)?;
            self.vtimer_masked = false;
        }
        Ok(())
    }

    fn handle_psci_request(&self) -> Result<VcpuExit<'_>, Error> {
        match self.read_reg(hv_reg_t_HV_REG_X0)? {
            0x8400_0000 /* QEMU_PSCI_0_2_FN_PSCI_VERSION */ => {
                self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                Ok(VcpuExit::PsciHandled)
            },
            0x8400_0006 /* QEMU_PSCI_0_2_FN_MIGRATE_INFO_TYPE */ => {
                self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                Ok(VcpuExit::PsciHandled)
            },
            0x8400_0008 /* QEMU_PSCI_0_2_FN_SYSTEM_OFF */ => {
                Ok(VcpuExit::Shutdown)
            },
            0x8400_0009 /* QEMU_PSCI_0_2_FN_SYSTEM_RESET */ => {
                Ok(VcpuExit::Shutdown)
            },
            0xc400_0003 /* QEMU_PSCI_0_2_FN64_CPU_ON */ => {
                let mpidr = self.read_reg(hv_reg_t_HV_REG_X1)?;
                let entry = self.read_reg(hv_reg_t_HV_REG_X2)?;
                let context_id = self.read_reg(hv_reg_t_HV_REG_X3)?;
                self.write_reg(hv_reg_t_HV_REG_X0, 0)?;
                Ok(VcpuExit::CpuOn(mpidr, entry, context_id))
            }
            val => Err(Error::UnsupportedPsci(val)),
        }
    }

    pub fn run(
        &mut self,
        vcpu_list: Arc<dyn Vcpus>,
        reclaim_state: &Arc<ReclaimState>,
    ) -> Result<VcpuExit<'_>, Error> {
        self.finish_pending_emulation()?;
        let exit = self
            .vcpu_exit
            .ok_or(Error::NullObject("hv_vcpu_create exit record"))?;
        let entered_generation = reclaim_state.vcpu_run_generation();
        let pending_irq = vcpu_list.has_pending_irq(self.vcpuid);

        if pending_irq {
            vcpu_set_pending_irq(self.vcpuid, InterruptType::Irq, true)?;
        }

        let ret = unsafe { hv_vcpu_run(self.vcpuid) };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_vcpu_run",
                status: ret,
            });
        }

        match exit.reason {
            HV_EXIT_REASON_EXCEPTION => { /* This is the main one, handle below. */ }
            HV_EXIT_REASON_VTIMER_ACTIVATED => {
                self.vtimer_masked = true;
                return Ok(VcpuExit::VtimerActivated);
            }
            HV_EXIT_REASON_CANCELED => return Ok(VcpuExit::Canceled),
            _ => {
                let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
                return Err(Error::UnexpectedExit {
                    reason: exit.reason,
                    pc,
                });
            }
        }

        self.hvf_sync_vtimer(vcpu_list.clone())?;

        let syndrome = exit.exception.syndrome;
        let ec = (syndrome >> 26) & 0x3f;
        match ec {
            EC_AA64_BKPT => {
                log::debug!("vcpu[{}]: BRK exit", self.vcpuid);
                Ok(VcpuExit::Breakpoint)
            }
            EC_INSTRUCTIONABORT | EC_INSTRUCTIONABORT_CURRENT => {
                let pa = exit.exception.physical_address;
                if is_translation_fault(syndrome)
                    && fault_address_is_valid(syndrome)
                    && let Some(generation) = entered_generation
                {
                    match reclaim_state
                        .resolve_translation_fault(pa, generation)
                        .map_err(Error::ReclaimState)?
                    {
                        FaultResolution::Retry => return Ok(VcpuExit::MemoryRetry),
                        FaultResolution::Invalid => {}
                    }
                }
                if !fault_address_is_valid(syndrome) {
                    return Err(Error::InvalidMemoryFault);
                }
                if entered_generation.is_some() && reclaim_state.contains_ram(pa) {
                    return Err(Error::InvalidMemoryFault);
                }
                Err(Error::InvalidMemoryFault)
            }
            EC_DATAABORT | EC_DATAABORT_CURRENT => {
                let pa = exit.exception.physical_address;
                if is_translation_fault(syndrome)
                    && fault_address_is_valid(syndrome)
                    && let Some(generation) = entered_generation
                {
                    match reclaim_state
                        .resolve_translation_fault(pa, generation)
                        .map_err(Error::ReclaimState)?
                    {
                        FaultResolution::Retry => return Ok(VcpuExit::MemoryRetry),
                        FaultResolution::Invalid => {}
                    }
                }
                if is_translation_fault(syndrome) && !fault_address_is_valid(syndrome) {
                    return Err(Error::InvalidMemoryFault);
                }
                if entered_generation.is_some() && reclaim_state.contains_ram(pa) {
                    return Err(Error::InvalidMemoryFault);
                }
                let access = decode_mmio_access(syndrome).ok_or(Error::InvalidMemoryFault)?;
                self.pending_advance_pc = true;

                if access.is_write {
                    let val = if access.register < 31 {
                        self.read_reg(hv_reg_t_HV_REG_X0 + access.register)?
                    } else {
                        0
                    };

                    match access.len {
                        1 => self.mmio_buf[0..1].copy_from_slice(&(val as u8).to_le_bytes()),
                        2 => self.mmio_buf[0..2].copy_from_slice(&(val as u16).to_le_bytes()),
                        4 => self.mmio_buf[0..4].copy_from_slice(&(val as u32).to_le_bytes()),
                        8 => self.mmio_buf[0..8].copy_from_slice(&val.to_le_bytes()),
                        _ => return Err(Error::InvalidMemoryFault),
                    };

                    Ok(VcpuExit::MmioWrite(pa, &self.mmio_buf[0..access.len]))
                } else {
                    self.pending_mmio_read = Some(MmioRead {
                        srt: access.register,
                        len: access.len,
                    });
                    Ok(VcpuExit::MmioRead(pa, &mut self.mmio_buf[0..access.len]))
                }
            }
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            EC_SYSTEMREGISTERTRAP => {
                let isread: bool = (syndrome & 1) != 0;
                let rt: u32 = ((syndrome >> 5) & 0x1f) as u32;
                let reg: u32 = syndrome as u32 & SYSREG_MASK;
                log::debug!(
                    "EC_SYSTEMREGISTERTRAP isread={}, syndrome={}, rt={}, reg={}, reg_name={}",
                    isread as u32,
                    syndrome,
                    rt,
                    reg,
                    sys_reg_name(reg).unwrap_or("unknown sysreg")
                );

                self.pending_advance_pc = true;

                if isread {
                    // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                    if rt == 31 {
                        return Ok(VcpuExit::SystemRegister);
                    }

                    match vcpu_list.handle_sysreg_read(self.vcpuid, reg) {
                        Some(val) => {
                            self.write_reg(rt, val)?;
                            Ok(VcpuExit::SystemRegister)
                        }
                        None => Err(Error::UnsupportedSystemRegister {
                            register: reg,
                            write: false,
                        }),
                    }
                } else {
                    // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                    let val = if rt == 31 { 0u64 } else { self.read_reg(rt)? };

                    if vcpu_list.handle_sysreg_write(self.vcpuid, reg, val) {
                        Ok(VcpuExit::SystemRegister)
                    } else {
                        Err(Error::UnsupportedSystemRegister {
                            register: reg,
                            write: true,
                        })
                    }
                }
            }
            EC_WFX_TRAP => {
                let ctl = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)?;

                self.pending_advance_pc = true;
                if ((ctl & 1) == 0) || (ctl & 2) != 0 {
                    return Ok(VcpuExit::WaitForEvent);
                }

                // Also CNTV_CVAL & CNTV_CVAL_EL0
                let cval = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0)?;
                // This preserves the existing same-VM clock model. Mach/guest
                // counter epoch and rate equivalence still require native qualification.
                let now = unsafe { mach_absolute_time() }.saturating_sub(self.vtimer_offset.get());
                if now > cval {
                    return Ok(VcpuExit::WaitForEventExpired);
                }

                let timeout =
                    ticks_to_duration(cval - now, self.cntfrq).ok_or(Error::InvalidMemoryFault)?;
                Ok(VcpuExit::WaitForEventTimeout(timeout))
            }
            EC_AA64_HVC => self.handle_psci_request(),
            EC_AA64_SMC => {
                self.pending_advance_pc = true;
                self.handle_psci_request()
            }
            _ => Err(Error::UnsupportedException(ec)),
        }
    }
}

impl Drop for HvfVcpu<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.destroy() {
            log::error!(
                "HVF vCPU {} owner-thread cleanup failed: {error}",
                self.vcpuid
            );
            // Unwinding cannot release the surrounding VM/RAM owners while
            // this native CPU still exists. The process owner must reap us.
            loop {
                std::thread::park();
            }
        }
    }
}

fn mmio_value(bytes: &[u8; 8], len: usize) -> Result<u64, Error> {
    match len {
        1 | 2 | 4 | 8 => {
            let mut value = [0; 8];
            value[..len].copy_from_slice(&bytes[..len]);
            Ok(u64::from_le_bytes(value))
        }
        _ => Err(Error::InvalidMemoryFault),
    }
}

fn ticks_to_duration(ticks: u64, frequency: u64) -> Option<Duration> {
    let nanos = u128::from(ticks)
        .checked_mul(1_000_000_000)?
        .checked_div(u128::from(frequency))?;
    Some(Duration::new(
        u64::try_from(nanos / 1_000_000_000).ok()?,
        (nanos % 1_000_000_000) as u32,
    ))
}

fn is_translation_fault(syndrome: u64) -> bool {
    matches!(syndrome & 0x3f, 0b000100..=0b000111)
}

// Arm ESR_EL2 defines FnV at ISS[10]: when set, the fault address supplied for
// an abort is not valid and must not be used for RAM lookup or MMIO dispatch.
fn fault_address_is_valid(syndrome: u64) -> bool {
    syndrome & (1 << 10) == 0
}

fn decode_mmio_access(syndrome: u64) -> Option<MmioAccess> {
    let instruction_syndrome_valid = syndrome & (1 << 24) != 0;
    let stage_one_page_walk = syndrome & (1 << 7) != 0;
    let cache_maintenance = syndrome & (1 << 8) != 0;
    if !is_translation_fault(syndrome)
        || !fault_address_is_valid(syndrome)
        || !instruction_syndrome_valid
        || stage_one_page_walk
        || cache_maintenance
    {
        return None;
    }
    Some(MmioAccess {
        is_write: syndrome & (1 << 6) != 0,
        len: 1usize << ((syndrome >> 22) & 0x3),
        register: ((syndrome >> 16) & 0x1f) as u32,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    mod actual_reclaim;

    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use crate::{
        Error, HvfVmLifetime, MmioAccess, decode_mmio_access, fault_address_is_valid,
        is_translation_fault, unique_vm_lifetime,
    };

    #[test]
    fn vtimer_resume_retries_one_absolute_target() {
        let mut plan = crate::VtimerResume::new(200);
        assert_eq!(plan.prepare(300).unwrap(), 500);
        assert_eq!(plan.prepare(300).unwrap(), 500);
        assert!(plan.prepare(301).is_err());
        assert_eq!(plan.prepare(300).unwrap(), 500);
        assert!(crate::VtimerResume::new(u64::MAX).prepare(1).is_err());
    }

    #[test]
    fn deferred_mmio_value_and_timer_duration_are_bounded() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(crate::mmio_value(&bytes, 1).unwrap(), 1);
        assert_eq!(crate::mmio_value(&bytes, 2).unwrap(), 0x0201);
        assert_eq!(crate::mmio_value(&bytes, 4).unwrap(), 0x0403_0201);
        assert_eq!(
            crate::mmio_value(&bytes, 8).unwrap(),
            u64::from_le_bytes(bytes)
        );
        assert!(crate::mmio_value(&bytes, 0).is_err());
        assert!(crate::mmio_value(&bytes, 3).is_err());
        assert!(crate::mmio_value(&bytes, 9).is_err());
        assert_eq!(
            crate::ticks_to_duration(1, 24_000_000).unwrap().as_nanos(),
            41
        );
        assert_eq!(
            crate::ticks_to_duration(24_000_000, 24_000_000)
                .unwrap()
                .as_secs(),
            1
        );
        assert!(crate::ticks_to_duration(1, 0).is_none());
        assert!(crate::ticks_to_duration(u64::MAX, 1).is_some());
    }

    #[test]
    fn explicit_destroy_requires_unique_lifetime_ownership() {
        let outer = Arc::new(HvfVmLifetime::new());
        let worker = Arc::clone(&outer);

        assert!(matches!(unique_vm_lifetime(outer), Err(Error::VmBusy)));
        assert_eq!(Arc::strong_count(&worker), 1);
        let lifetime = Arc::try_unwrap(worker)
            .ok()
            .expect("last lifetime owner must be unique");
        assert!(!lifetime.destroyed.load(Ordering::Acquire));
        lifetime.destroyed.store(true, Ordering::Release);
    }

    #[test]
    fn decodes_only_translation_fault_status_codes() {
        for level in 0b000100..=0b000111 {
            assert!(is_translation_fault(level));
            assert!(is_translation_fault((0x24 << 26) | (1 << 7) | level));
        }
        for status in [0, 0b001001, 0b001100, 0b010000, 0b100001] {
            assert!(!is_translation_fault(status));
        }
        assert!(fault_address_is_valid(0b000100));
        assert!(!fault_address_is_valid((1 << 10) | 0b000100));

        let valid_mmio = (1 << 24) | (2 << 22) | (3 << 16) | (1 << 6) | 0b000100;
        assert_eq!(
            decode_mmio_access(valid_mmio),
            Some(MmioAccess {
                is_write: true,
                len: 4,
                register: 3,
            })
        );
        assert_eq!(decode_mmio_access(valid_mmio & !(1 << 24)), None);
        assert_eq!(decode_mmio_access(valid_mmio | (1 << 7)), None);
        assert_eq!(decode_mmio_access(valid_mmio | (1 << 8)), None);
        assert_eq!(decode_mmio_access((valid_mmio & !0x3f) | 0b001100), None);
    }
}
