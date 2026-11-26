//! Destination facts that do not require a VM or vCPU.

use std::ops::Range;
use std::sync::Arc;

use crate::bindings::*;
use crate::framework::{HvfFramework, OwnedConfig, native_status};
use crate::state::RegisterValue;
use crate::{Error, id_feature_mask};

pub fn max_vcpu_count() -> Result<u32, Error> {
    let mut maximum = 0;
    native_status("hv_vm_get_max_vcpu_count", unsafe {
        hv_vm_get_max_vcpu_count(&mut maximum)
    })?;
    Ok(maximum)
}

pub fn default_ipa_bits() -> Result<u32, Error> {
    let mut bits = 0;
    native_status("hv_vm_config_get_default_ipa_size", unsafe {
        hv_vm_config_get_default_ipa_size(&mut bits)
    })?;
    if !(1..=64).contains(&bits) {
        return Err(Error::ExecutionState(crate::state::StateError(
            "invalid default IPA width",
        )));
    }
    Ok(bits)
}

// MIDR is not a configuration feature register. Restore compares it on the initialized vCPU.
const MODEL_FEATURES: [(u16, hv_feature_reg_t); 9] = [
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64PFR0_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64PFR1_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64DFR0_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64DFR0_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64DFR1_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64DFR1_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64ISAR0_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64ISAR0_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64ISAR1_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64ISAR1_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64MMFR0_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64MMFR0_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64MMFR1_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64MMFR1_EL1,
    ),
    (
        hv_sys_reg_t_HV_SYS_REG_ID_AA64MMFR2_EL1,
        hv_feature_reg_t_HV_FEATURE_REG_ID_AA64MMFR2_EL1,
    ),
];

pub fn model_registers(
    framework: &Arc<HvfFramework>,
) -> Result<[RegisterValue; MODEL_FEATURES.len()], Error> {
    let config = unsafe {
        OwnedConfig::new(
            hv_vcpu_config_create(),
            Arc::clone(framework),
            "hv_vcpu_config_create",
        )?
    };
    let mut model = [const { RegisterValue { id: 0, value: 0 } }; MODEL_FEATURES.len()];
    for (reg, (id, feature)) in model.iter_mut().zip(MODEL_FEATURES) {
        let mut value = 0;
        let status =
            unsafe { hv_vcpu_config_get_feature_reg(config.as_ptr(), feature, &mut value) };
        if status != HV_SUCCESS {
            return Err(Error::ExecutionRegister {
                symbol: "hv_vcpu_config_get_feature_reg",
                register: u32::from(id),
                status,
            });
        }
        *reg = RegisterValue {
            id,
            value: value & !id_feature_mask(id),
        };
    }
    Ok(model)
}

fn gic_region_parameter(
    framework: &HvfFramework,
    name: &'static str,
    symbol: &[u8],
) -> Result<u64, Error> {
    let query =
        unsafe { framework.symbol::<unsafe extern "C" fn(*mut usize) -> hv_return_t>(symbol)? };
    let mut value = 0;
    native_status(name, unsafe { query(&mut value) })?;
    Ok(value as u64)
}

/// The distributor size and the size of one redistributor.
pub fn gic_region_sizes(framework: &HvfFramework) -> Result<[u64; 2], Error> {
    Ok([
        gic_region_parameter(
            framework,
            "hv_gic_get_distributor_size",
            b"hv_gic_get_distributor_size\0",
        )?,
        gic_region_parameter(
            framework,
            "hv_gic_get_redistributor_size",
            b"hv_gic_get_redistributor_size\0",
        )?,
    ])
}

pub fn gic_base_alignments(framework: &HvfFramework) -> Result<[u64; 2], Error> {
    Ok([
        gic_region_parameter(
            framework,
            "hv_gic_get_distributor_base_alignment",
            b"hv_gic_get_distributor_base_alignment\0",
        )?,
        gic_region_parameter(
            framework,
            "hv_gic_get_redistributor_base_alignment",
            b"hv_gic_get_redistributor_base_alignment\0",
        )?,
    ])
}

pub fn gic_spi_range(framework: &HvfFramework) -> Result<Range<u32>, Error> {
    let query = unsafe {
        framework.symbol::<unsafe extern "C" fn(*mut u32, *mut u32) -> hv_return_t>(
            b"hv_gic_get_spi_interrupt_range\0",
        )?
    };
    let (mut start, mut count) = (0_u32, 0_u32);
    native_status("hv_gic_get_spi_interrupt_range", unsafe {
        query(&mut start, &mut count)
    })?;
    let end = start
        .checked_add(count)
        .ok_or(Error::ExecutionState(crate::state::StateError(
            "invalid GIC SPI range",
        )))?;
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use crate::capture_clock_cut;
    use crate::framework::HvfFramework;
    use crate::host::*;
    use crate::state::MODEL_REGISTERS;

    #[test]
    fn destination_facts_without_a_vm() {
        // Evaluate each query before reporting failures so the test diagnoses all native calls.
        let framework = HvfFramework::load().unwrap();
        let maximum = max_vcpu_count();
        let ipa = default_ipa_bits();
        let configured_ipa = (|| {
            let config = unsafe {
                OwnedConfig::new(
                    hv_vm_config_create(),
                    Arc::clone(&framework),
                    "hv_vm_config_create",
                )?
            };
            let mut bits = 0;
            native_status("hv_vm_config_get_ipa_size", unsafe {
                hv_vm_config_get_ipa_size(config.as_ptr(), &mut bits)
            })?;
            Ok::<_, Error>(bits)
        })();
        let model = model_registers(&framework);
        let clock = capture_clock_cut();
        let sizes = gic_region_sizes(&framework);
        let alignments = gic_base_alignments(&framework);
        let spis = gic_spi_range(&framework);
        assert!(
            matches!(maximum, Ok(n) if n > 0)
                && matches!(ipa, Ok(n) if n >= 32)
                && matches!((&ipa, &configured_ipa), (Ok(default), Ok(configured)) if default == configured)
                && model.is_ok()
                && clock.is_ok()
                && sizes.is_ok()
                && alignments.is_ok()
                && spis.is_ok(),
            "max vCPUs: {maximum:?}, default IPA: {ipa:?}, configured IPA: {configured_ipa:?}, model: {model:?}, clock: {clock:?}, sizes: {sizes:?}, alignments: {alignments:?}, SPIs: {spis:?}"
        );
        eprintln!(
            "max vCPUs: {maximum:?}, IPA: {ipa:?}, model: {model:x?}, clock: {clock:?}, GIC sizes: {sizes:x?}, GIC alignments: {alignments:x?}, SPIs: {spis:?}"
        );
        let model = model.unwrap();
        assert!(
            model
                .iter()
                .map(|reg| reg.id)
                .eq(MODEL_REGISTERS[1..].iter().copied())
        );
        assert!(
            model
                .iter()
                .all(|reg| reg.value & id_feature_mask(reg.id) == 0)
        );
        let clock = clock.unwrap();
        let later = capture_clock_cut().unwrap();
        assert!(later.host_counter >= clock.host_counter);
        assert_eq!(later.frequency, clock.frequency);
        assert_eq!(
            (later.timebase_numer, later.timebase_denom),
            (clock.timebase_numer, clock.timebase_denom)
        );
        assert!(sizes.unwrap().iter().all(|size| *size > 0));
        assert!(
            alignments
                .unwrap()
                .iter()
                .all(|alignment| alignment.is_power_of_two())
        );
        assert!(!spis.unwrap().is_empty());
    }
}
