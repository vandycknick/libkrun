use crate::bindings::*;
use crate::framework::HvfFramework;
use crate::state::{
    CpuState, ICC_REGISTERS, MODEL_REGISTERS, RegisterValue, SoftwareState, TimerState,
    debug_inventory,
};
use crate::{Error, HvfVcpu, InterruptType, vcpu_set_pending_irq, vcpu_set_vtimer_mask};

#[repr(C)]
struct MachTimebase {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn mach_timebase_info(info: *mut MachTimebase) -> i32;
}

pub fn capture_clock_cut() -> Result<crate::state::ClockCut, Error> {
    let mut timebase = MachTimebase { numer: 0, denom: 0 };
    let status = unsafe { mach_timebase_info(&mut timebase) };
    if status != 0 {
        return Err(Error::ExecutionState(crate::state::StateError(
            "Mach timebase query failed",
        )));
    }
    let frequency: u64;
    unsafe { std::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency) };
    let cut = crate::state::ClockCut {
        host_counter: crate::host_counter(),
        frequency,
        timebase_numer: timebase.numer,
        timebase_denom: timebase.denom,
    };
    cut.validate().map_err(Error::ExecutionState)?;
    Ok(cut)
}

fn checked(symbol: &'static str, status: hv_return_t) -> Result<(), Error> {
    if status == HV_SUCCESS {
        Ok(())
    } else {
        Err(Error::NativeCall { symbol, status })
    }
}

fn checked_register(symbol: &'static str, register: u32, status: hv_return_t) -> Result<(), Error> {
    if status == HV_SUCCESS {
        Ok(())
    } else {
        Err(Error::ExecutionRegister {
            symbol,
            register,
            status,
        })
    }
}

impl HvfVcpu<'_> {
    pub fn execution_timer_wait(&self, timer: &TimerState) -> Option<std::time::Duration> {
        if timer.virtual_control & 3 != 1 {
            return None;
        }
        let now = crate::host_counter().wrapping_sub(self.vtimer_offset.get());
        crate::ticks_to_duration(
            crate::state::timer_remaining(timer.virtual_compare, now),
            self.cntfrq,
        )
    }

    pub fn fence_execution_time(&mut self) -> Result<(), Error> {
        self.write_system(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0, 0)?;
        self.write_system(hv_sys_reg_t_HV_SYS_REG_CNTP_CTL_EL0, 0)?;
        vcpu_set_vtimer_mask(self.vcpuid, true)?;
        self.vtimer_masked = true;
        Ok(())
    }
    pub fn capture_execution_state(
        &mut self,
        logical_id: u8,
        software: SoftwareState,
        framework: &HvfFramework,
    ) -> Result<CpuState, Error> {
        if self.nested_enabled {
            return Err(Error::ExecutionState(crate::state::StateError(
                "nested HVF state",
            )));
        }
        self.finish_pending_emulation()?;
        let mut general = [0; 35];
        for (id, value) in general.iter_mut().enumerate() {
            *value = self.read_reg(id as u32)?;
        }
        let mut simd = [[0; 16]; 32];
        for (id, value) in simd.iter_mut().enumerate() {
            let mut native = 0;
            checked_register("hv_vcpu_get_simd_fp_reg", id as u32, unsafe {
                hv_vcpu_get_simd_fp_reg(self.vcpuid, id as u32, &mut native)
            })?;
            *value = native.to_le_bytes();
        }
        let mut state = CpuState {
            logical_id,
            mpidr: self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_MPIDR_EL1)?,
            frequency: self.cntfrq,
            model: self.capture_system(MODEL_REGISTERS)?,
            general,
            simd,
            system: Vec::new(),
            debug: Vec::new(),
            icc: Vec::new(),
            timer: self.capture_timer_state()?,
            pending_irq: false,
            pending_fiq: false,
            software,
        };
        state.system =
            self.capture_system(&state.system_inventory().map_err(Error::ExecutionState)?)?;
        state.debug = self.capture_system(&debug_inventory(
            state
                .model_value(crate::state::DFR0)
                .map_err(Error::ExecutionState)?,
        ))?;
        for id in ICC_REGISTERS {
            state.icc.push(RegisterValue {
                id: *id,
                value: framework.get_icc(self.vcpuid, *id)?,
            });
        }
        checked("hv_vcpu_get_pending_interrupt(IRQ)", unsafe {
            hv_vcpu_get_pending_interrupt(
                self.vcpuid,
                hv_interrupt_type_t_HV_INTERRUPT_TYPE_IRQ,
                &mut state.pending_irq,
            )
        })?;
        checked("hv_vcpu_get_pending_interrupt(FIQ)", unsafe {
            hv_vcpu_get_pending_interrupt(
                self.vcpuid,
                hv_interrupt_type_t_HV_INTERRUPT_TYPE_FIQ,
                &mut state.pending_fiq,
            )
        })?;
        state.validate().map_err(Error::ExecutionState)?;
        Ok(state)
    }

    fn capture_system(&self, ids: &[u16]) -> Result<Vec<RegisterValue>, Error> {
        ids.iter()
            .map(|id| {
                Ok(RegisterValue {
                    id: *id,
                    value: self.read_sys_reg(*id)?,
                })
            })
            .collect()
    }

    fn write_system(&self, id: u16, value: u64) -> Result<(), Error> {
        checked_register("hv_vcpu_set_sys_reg", u32::from(id), unsafe {
            hv_vcpu_set_sys_reg(self.vcpuid, id, value)
        })
    }

    pub fn capture_timer_state(&self) -> Result<TimerState, Error> {
        let mut offset = 0;
        let mut masked = false;
        checked("hv_vcpu_get_vtimer_offset", unsafe {
            hv_vcpu_get_vtimer_offset(self.vcpuid, &mut offset)
        })?;
        checked("hv_vcpu_get_vtimer_mask", unsafe {
            hv_vcpu_get_vtimer_mask(self.vcpuid, &mut masked)
        })?;
        if offset != self.vtimer_offset.get() || masked != self.vtimer_masked {
            return Err(Error::ExecutionState(crate::state::StateError(
                "timer cache mismatch",
            )));
        }
        Ok(TimerState {
            offset,
            masked,
            virtual_compare: self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0)?,
            virtual_control: self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)?,
            physical_compare: self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0)?,
            physical_control: self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTP_CTL_EL0)?,
        })
    }

    pub fn install_execution_state(
        &mut self,
        state: &CpuState,
        absolute_offset: u64,
        framework: &HvfFramework,
    ) -> Result<(), Error> {
        state.validate().map_err(Error::ExecutionState)?;
        if self.nested_enabled
            || state.frequency != self.cntfrq
            || self.capture_system(MODEL_REGISTERS)? != state.model
        {
            return Err(Error::ExecutionState(crate::state::StateError(
                "CPU model/frequency mismatch",
            )));
        }
        self.initialize(state.mpidr)?;
        self.set_vtimer_offset(absolute_offset)?;
        for value in state.system.iter().chain(&state.debug) {
            self.write_system(value.id, value.value)?;
        }
        for (id, value) in state.simd.iter().enumerate() {
            checked_register("hv_vcpu_set_simd_fp_reg", id as u32, unsafe {
                hv_vcpu_set_simd_fp_reg(self.vcpuid, id as u32, u128::from_le_bytes(*value))
            })?;
        }
        for (id, value) in state.general.iter().enumerate() {
            self.write_reg(id as u32, *value)?;
        }
        for value in &state.icc {
            framework.set_icc(self.vcpuid, value.id, value.value)?;
        }
        self.fence_execution_time()?;
        self.write_system(
            hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0,
            state.timer.virtual_compare,
        )?;
        self.write_system(
            hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0,
            state.timer.physical_compare,
        )?;
        vcpu_set_pending_irq(self.vcpuid, InterruptType::Irq, state.pending_irq)?;
        vcpu_set_pending_irq(self.vcpuid, InterruptType::Fiq, state.pending_fiq)?;
        self.pending_mmio_read = None;
        self.pending_advance_pc = false;
        Ok(())
    }

    pub fn prepare_execution_time(
        &mut self,
        timer: &TimerState,
        absolute_offset: u64,
    ) -> Result<(), Error> {
        self.set_vtimer_offset(absolute_offset)?;
        self.write_system(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0, 0)?;
        self.write_system(hv_sys_reg_t_HV_SYS_REG_CNTP_CTL_EL0, 0)?;
        self.write_system(hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0, timer.virtual_compare)?;
        self.write_system(
            hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0,
            timer.physical_compare,
        )?;
        self.write_system(
            hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0,
            timer.virtual_control & 3,
        )?;
        self.write_system(
            hv_sys_reg_t_HV_SYS_REG_CNTP_CTL_EL0,
            timer.physical_control & 3,
        )?;
        vcpu_set_vtimer_mask(self.vcpuid, timer.masked)?;
        self.vtimer_masked = timer.masked;
        Ok(())
    }
}
