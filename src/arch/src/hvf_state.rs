use std::fmt::{Display, Formatter};

pub const MAX_GIC_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PENDING_IRQS: usize = 4096;

pub fn timer_remaining(compare: u64, counter: u64) -> u64 {
    let delta = compare.wrapping_sub(counter);
    if delta > i64::MAX as u64 { 0 } else { delta }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeTimeAction {
    RetainInstalledExecution,
    PrepareOrdinaryOffset,
}

pub fn resume_time_action<Key: Eq>(
    retained_execution_cut: bool,
    requested_key: &Key,
    installed_time_key: Option<&Key>,
    prepared_key: Option<&Key>,
    paused_ticks: u64,
) -> Result<ResumeTimeAction, StateError> {
    if retained_execution_cut {
        if installed_time_key != Some(requested_key) || prepared_key != Some(requested_key) {
            return Err(StateError(
                "HVF execution-cut resume lacks the exact completed time plan",
            ));
        }
        if paused_ticks != 0 {
            return Err(StateError(
                "HVF execution-cut resume cannot advance installed time",
            ));
        }
        Ok(ResumeTimeAction::RetainInstalledExecution)
    } else if prepared_key.is_some_and(|key| key != requested_key) {
        Err(StateError("HVF timer preparation key changed"))
    } else {
        Ok(ResumeTimeAction::PrepareOrdinaryOffset)
    }
}
pub const MIDR: u16 = 49152;
pub const PFR0: u16 = 49184;
pub const PFR1: u16 = 49185;
pub const DFR0: u16 = 49192;
pub const ISAR1: u16 = 49201;

// Framework register identifiers are data, not framework symbols: the decoder
// must validate these inventories on hosts which cannot link Hypervisor.framework.
pub const MODEL_REGISTERS: &[u16] = &[
    MIDR, PFR0, PFR1, DFR0, 49193, 49200, ISAR1, 49208, 49209, 49210,
];
pub const SYSTEM_REGISTERS: &[u16] = &[
    49280, 49281, 49282, 49408, 49409, 49410, 49664, 49665, 49672, 57864, 49800, 49801, 49808,
    49920, 50080, 50448, 50456, 50688, 50817, 50820, 50952, 53248, 56962, 56963,
];
pub const PAUTH_REGISTERS: &[u16] = &[
    49416, 49417, 49418, 49419, 49424, 49425, 49426, 49427, 49432, 49433,
];
pub const ICC_REGISTERS: &[u16] = &[
    49712, 50755, 50756, 50760, 50787, 50788, 50789, 50790, 50791,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterValue {
    pub id: u16,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuDisposition {
    Offline,
    Runnable,
    Waiting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuOn {
    pub entry: u64,
    pub context: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareState {
    pub disposition: CpuDisposition,
    pub pending_irqs: Vec<u32>,
    pub wake_pending: bool,
    pub cpu_on: Option<CpuOn>,
}

impl SoftwareState {
    pub fn validate(&self) -> Result<(), StateError> {
        if self.pending_irqs.len() > MAX_PENDING_IRQS
            || self.pending_irqs.iter().any(|irq| *irq >= 1020)
        {
            return Err(StateError("software pending IRQ inventory"));
        }
        if self.cpu_on.is_some() && self.disposition != CpuDisposition::Offline {
            return Err(StateError("CPU_ON on an online CPU"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerState {
    pub offset: u64,
    pub masked: bool,
    pub virtual_compare: u64,
    pub virtual_control: u64,
    pub physical_compare: u64,
    pub physical_control: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuState {
    pub logical_id: u8,
    pub mpidr: u64,
    pub frequency: u64,
    pub model: Vec<RegisterValue>,
    pub general: [u64; 35],
    pub simd: [[u8; 16]; 32],
    pub system: Vec<RegisterValue>,
    pub debug: Vec<RegisterValue>,
    pub icc: Vec<RegisterValue>,
    pub timer: TimerState,
    pub pending_irq: bool,
    pub pending_fiq: bool,
    pub software: SoftwareState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GicState {
    pub vcpu_count: u8,
    pub properties: [u64; 4],
    pub bytes: Vec<u8>,
}

impl GicState {
    pub fn validate(&self) -> Result<(), StateError> {
        if self.vcpu_count == 0 || self.bytes.is_empty() || self.bytes.len() > MAX_GIC_BYTES {
            return Err(StateError("GIC state size or topology"));
        }
        let [dist, dist_size, redist, redist_size] = self.properties;
        if dist_size == 0
            || redist_size == 0
            || dist.checked_add(dist_size).is_none_or(|end| end > redist)
            || redist.checked_add(redist_size).is_none()
            || redist_size % u64::from(self.vcpu_count) != 0
        {
            return Err(StateError("GIC memory topology"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockCut {
    pub host_counter: u64,
    pub frequency: u64,
    pub timebase_numer: u32,
    pub timebase_denom: u32,
}

impl ClockCut {
    pub fn validate(&self) -> Result<(), StateError> {
        if self.frequency == 0 || self.timebase_numer == 0 || self.timebase_denom == 0 {
            return Err(StateError("counter frequency or Mach timebase"));
        }
        Ok(())
    }

    pub fn destination_offset(&self, source_offset: u64, destination_counter: u64) -> u64 {
        destination_counter.wrapping_sub(self.host_counter.wrapping_sub(source_offset))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateError(pub &'static str);

impl Display for StateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for StateError {}

pub fn exact_inventory(values: &[RegisterValue], ids: &[u16]) -> Result<(), StateError> {
    if values.len() != ids.len() || values.iter().zip(ids).any(|(value, id)| value.id != *id) {
        return Err(StateError("register inventory mismatch"));
    }
    Ok(())
}

pub fn debug_inventory(dfr0: u64) -> Vec<u16> {
    let breakpoints = ((dfr0 >> 12) & 15) + 1;
    let watchpoints = ((dfr0 >> 20) & 15) + 1;
    let mut ids = Vec::with_capacity(2 + (breakpoints + watchpoints) as usize * 2);
    ids.extend([32784, 32786]);
    for bank in 0..breakpoints as u16 {
        ids.extend([32772 + bank * 8, 32773 + bank * 8]);
    }
    for bank in 0..watchpoints as u16 {
        ids.extend([32774 + bank * 8, 32775 + bank * 8]);
    }
    ids
}

impl CpuState {
    pub fn model_value(&self, id: u16) -> Result<u64, StateError> {
        self.model
            .iter()
            .find(|value| value.id == id)
            .map(|value| value.value)
            .ok_or(StateError("missing CPU model register"))
    }

    pub fn system_inventory(&self) -> Result<Vec<u16>, StateError> {
        let isar1 = self.model_value(ISAR1)?;
        let mut ids = SYSTEM_REGISTERS.to_vec();
        if isar1 & 0xff0 != 0 || isar1 & 0xff00_0000 != 0 {
            ids.extend(PAUTH_REGISTERS);
        }
        Ok(ids)
    }

    pub fn validate(&self) -> Result<(), StateError> {
        if self.frequency == 0 {
            return Err(StateError("zero counter frequency"));
        }
        exact_inventory(&self.model, MODEL_REGISTERS)?;
        let pfr0 = self.model_value(PFR0)?;
        let pfr1 = self.model_value(PFR1)?;
        if (pfr0 >> 32) & 15 != 0 || (pfr1 >> 24) & 15 != 0 {
            return Err(StateError("SVE/SME CPU state is unqualified"));
        }
        exact_inventory(&self.system, &self.system_inventory()?)?;
        exact_inventory(&self.debug, &debug_inventory(self.model_value(DFR0)?))?;
        exact_inventory(&self.icc, ICC_REGISTERS)?;
        if self.timer.virtual_control & !7 != 0 || self.timer.physical_control & !7 != 0 {
            return Err(StateError("timer control reserved bits"));
        }
        if self.timer.physical_control & 1 != 0 {
            return Err(StateError("HVF physical-timer epoch is not qualified"));
        }
        if self
            .icc
            .iter()
            .find(|reg| reg.id == 50788)
            .is_some_and(|reg| (reg.value >> 8) & 7 > 4)
        {
            return Err(StateError("GIC active-priority register inventory"));
        }
        let dfr0 = self.model_value(DFR0)?;
        if !matches!((dfr0 >> 8) & 15, 0 | 15) {
            return Err(StateError(
                "HVF PMU state has no framework register inventory",
            ));
        }
        if self.model_value(49193)? != 0 {
            return Err(StateError("expanded HVF debug model is unqualified"));
        }
        if self.general[32] >> 32 != 0 || self.general[33] >> 32 != 0 {
            return Err(StateError("FPCR/FPSR register width"));
        }
        self.software.validate()
    }
}

#[cfg(test)]
mod tests {
    use crate::hvf_state::{
        ClockCut, CpuDisposition, ICC_REGISTERS, MAX_PENDING_IRQS, RegisterValue, SoftwareState,
        debug_inventory, exact_inventory,
    };
    use crate::hvf_state::{
        CpuState, GicState, MAX_GIC_BYTES, MODEL_REGISTERS, SYSTEM_REGISTERS, TimerState,
    };

    #[test]
    fn hvf_execution_inventory_excludes_read_only_icc_and_aliases() {
        assert!(!ICC_REGISTERS.contains(&50779));
        assert_eq!(ICC_REGISTERS.len(), 9);
        assert_eq!(debug_inventory(0).len(), 6);
        assert_eq!(debug_inventory((15 << 12) | (15 << 20)).len(), 66);
        assert!(exact_inventory(&[RegisterValue { id: 1, value: 0 }], &[2]).is_err());
    }

    #[test]
    fn hvf_execution_clock_preserves_modular_epoch() {
        let cut = ClockCut {
            host_counter: 100,
            frequency: 24_000_000,
            timebase_numer: 125,
            timebase_denom: 3,
        };
        assert!(cut.validate().is_ok());
        assert_eq!(cut.destination_offset(40, 1_000_000), 999_940);
        assert_eq!(cut.destination_offset(200, 50), 150);
    }

    #[test]
    fn hvf_execution_software_bounds_and_offline_state() {
        let mut state = SoftwareState {
            disposition: CpuDisposition::Offline,
            pending_irqs: vec![27],
            wake_pending: true,
            cpu_on: None,
        };
        assert!(state.validate().is_ok());
        state.pending_irqs = vec![1; MAX_PENDING_IRQS + 1];
        assert!(state.validate().is_err());
    }

    #[test]
    fn hvf_execution_timer_remaining_handles_due_and_counter_wrap() {
        assert_eq!(crate::hvf_state::timer_remaining(99, 100), 0);
        assert_eq!(crate::hvf_state::timer_remaining(100, 100), 0);
        assert_eq!(crate::hvf_state::timer_remaining(101, 100), 1);
        assert_eq!(crate::hvf_state::timer_remaining(3, u64::MAX - 2), 6);
    }

    fn cpu_state() -> CpuState {
        let registers = |ids: &[u16]| {
            ids.iter()
                .map(|id| RegisterValue { id: *id, value: 0 })
                .collect()
        };
        CpuState {
            logical_id: 0,
            mpidr: 0,
            frequency: 24_000_000,
            model: registers(MODEL_REGISTERS),
            general: [0; 35],
            simd: [[0; 16]; 32],
            system: registers(SYSTEM_REGISTERS),
            debug: registers(&debug_inventory(0)),
            icc: registers(ICC_REGISTERS),
            timer: TimerState {
                offset: 42,
                masked: true,
                virtual_compare: 19,
                virtual_control: 5,
                physical_compare: 7,
                physical_control: 0,
            },
            pending_irq: true,
            pending_fiq: false,
            software: SoftwareState {
                disposition: CpuDisposition::Waiting,
                pending_irqs: vec![27],
                wake_pending: true,
                cpu_on: None,
            },
        }
    }

    #[test]
    fn hvf_execution_cpu_inventory_rejects_missing_duplicate_and_expanded_state() {
        let state = cpu_state();
        assert!(state.validate().is_ok());
        let mut invalid = state.clone();
        invalid.system.pop();
        assert!(invalid.validate().is_err());
        let mut invalid = state.clone();
        invalid.debug[1].id = invalid.debug[0].id;
        assert!(invalid.validate().is_err());
        let mut invalid = state.clone();
        invalid.model[1].value = 1 << 32;
        assert!(invalid.validate().is_err());
        let mut invalid = state.clone();
        invalid.model[3].value = 1 << 8;
        assert!(invalid.validate().is_err());
        let mut invalid = state.clone();
        invalid.timer.physical_control = 1;
        assert_eq!(
            invalid.validate(),
            Err(crate::hvf_state::StateError(
                "HVF physical-timer epoch is not qualified"
            ))
        );
        let mut invalid = state;
        invalid.general[32] = 1 << 32;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn hvf_execution_gic_size_and_topology_are_bounded() {
        let mut state = GicState {
            vcpu_count: 2,
            properties: [0x1000, 0x1000, 0x2000, 0x4000],
            bytes: vec![1],
        };
        assert!(state.validate().is_ok());
        state.properties[2] = 0x1001;
        assert!(state.validate().is_err());
        state.properties[2] = 0x2000;
        state.bytes.resize(MAX_GIC_BYTES + 1, 0);
        assert!(state.validate().is_err());
        state.bytes.clear();
        assert!(state.validate().is_err());
    }

    #[test]
    fn hvf_execution_resume_does_not_select_offset_reinstallation() {
        use crate::hvf_state::{ResumeTimeAction, resume_time_action};

        let release_key = (21_u64, 7_u64);
        for _ in 0..2 {
            assert_eq!(
                resume_time_action(
                    true,
                    &release_key,
                    Some(&release_key),
                    Some(&release_key),
                    0,
                ),
                Ok(ResumeTimeAction::RetainInstalledExecution),
            );
        }
    }

    #[test]
    fn hvf_execution_resume_requires_exact_typed_time_completion() {
        use crate::hvf_state::resume_time_action;

        let release_key = (21_u64, 7_u64);
        let other_operation = (22_u64, 7_u64);
        let other_generation = (21_u64, 8_u64);
        assert!(resume_time_action(true, &release_key, None, None, 0).is_err());
        assert!(resume_time_action(true, &release_key, Some(&release_key), None, 0,).is_err());
        for wrong_key in [other_operation, other_generation] {
            assert!(
                resume_time_action(true, &release_key, Some(&wrong_key), Some(&release_key), 0,)
                    .is_err()
            );
            assert!(
                resume_time_action(true, &release_key, Some(&release_key), Some(&wrong_key), 0,)
                    .is_err()
            );
        }
        assert!(
            resume_time_action(
                true,
                &release_key,
                Some(&release_key),
                Some(&release_key),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn hvf_execution_resume_keeps_ordinary_offset_preparation() {
        use crate::hvf_state::{ResumeTimeAction, resume_time_action};

        let release_key = (21_u64, 7_u64);
        let other_key = (22_u64, 7_u64);
        assert_eq!(
            resume_time_action(false, &release_key, None, None, 300),
            Ok(ResumeTimeAction::PrepareOrdinaryOffset),
        );
        assert_eq!(
            resume_time_action(false, &release_key, None, Some(&release_key), 300),
            Ok(ResumeTimeAction::PrepareOrdinaryOffset),
        );
        assert!(resume_time_action(false, &release_key, None, Some(&other_key), 300,).is_err());
    }
}
