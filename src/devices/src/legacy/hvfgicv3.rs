// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::Arc;

use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;

use hvf::Error;
use hvf::bindings::{HV_SUCCESS, hv_gic_config_t, hv_ipa_t, hv_return_t};
use hvf::framework::{HvfFramework, OwnedConfig};
use hvf::host::gic_region_sizes;
use utils::eventfd::EventFd;

// Device trees specific constants
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

struct HvfGicBindings {
    hv_gic_create: unsafe extern "C" fn(hv_gic_config_t) -> hv_return_t,
    hv_gic_config_create: unsafe extern "C" fn() -> hv_gic_config_t,
    hv_gic_config_set_distributor_base:
        unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t,
    hv_gic_config_set_redistributor_base:
        unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t,
    hv_gic_set_spi: unsafe extern "C" fn(u32, bool) -> hv_return_t,
    framework: Arc<HvfFramework>,
}

pub struct HvfGicV3 {
    bindings: HvfGicBindings,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

impl HvfGicV3 {
    /// [Distributor base, distributor size, redistributor base, total redistributor size].
    pub fn geometry(vcpu_count: u64, [dist_size, redist_size]: [u64; 2]) -> Option<[u64; 4]> {
        let redists_size = redist_size.checked_mul(vcpu_count)?;
        if dist_size == 0 || redists_size == 0 {
            return None;
        }
        let redists_addr = arch::MMIO_MEM_START.checked_sub(redists_size)?;
        let dist_addr = redists_addr.checked_sub(dist_size)?;
        Some([dist_addr, dist_size, redists_addr, redists_size])
    }

    pub fn new(vcpu_count: u64, framework: Arc<HvfFramework>) -> Result<Self, Error> {
        let bindings = unsafe {
            HvfGicBindings {
                hv_gic_create: *framework.symbol(b"hv_gic_create\0")?,
                hv_gic_config_create: *framework.symbol(b"hv_gic_config_create\0")?,
                hv_gic_config_set_distributor_base: *framework
                    .symbol(b"hv_gic_config_set_distributor_base\0")?,
                hv_gic_config_set_redistributor_base: *framework
                    .symbol(b"hv_gic_config_set_redistributor_base\0")?,
                hv_gic_set_spi: *framework.symbol(b"hv_gic_set_spi\0")?,
                framework,
            }
        };

        let properties = Self::geometry(vcpu_count, gic_region_sizes(&bindings.framework)?).ok_or(
            Error::ExecutionState(hvf::state::StateError("GIC memory topology")),
        )?;
        let [dist_addr, _, redists_addr, _] = properties;

        let gic_config = unsafe {
            OwnedConfig::new(
                (bindings.hv_gic_config_create)(),
                Arc::clone(&bindings.framework),
                "hv_gic_config_create",
            )?
        };
        let ret = unsafe {
            (bindings.hv_gic_config_set_distributor_base)(gic_config.as_ptr(), dist_addr)
        };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_gic_config_set_distributor_base",
                status: ret,
            });
        }

        let ret = unsafe {
            (bindings.hv_gic_config_set_redistributor_base)(gic_config.as_ptr(), redists_addr)
        };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_gic_config_set_redistributor_base",
                status: ret,
            });
        }

        let ret = unsafe { (bindings.hv_gic_create)(gic_config.as_ptr()) };
        if ret != HV_SUCCESS {
            return Err(Error::NativeCall {
                symbol: "hv_gic_create",
                status: ret,
            });
        }

        Ok(Self {
            bindings,
            properties,
            vcpu_count,
        })
    }

    pub fn capture_execution_state(&self) -> Result<hvf::state::GicState, Error> {
        let state = hvf::state::GicState {
            vcpu_count: u8::try_from(self.vcpu_count)
                .map_err(|_| Error::ExecutionState(hvf::state::StateError("GIC CPU count")))?,
            properties: self.properties,
            bytes: self.bindings.framework.capture_gic()?,
        };
        state.validate().map_err(Error::ExecutionState)?;
        Ok(state)
    }

    pub fn install_execution_state(&self, state: &hvf::state::GicState) -> Result<(), Error> {
        state.validate().map_err(Error::ExecutionState)?;
        if u64::from(state.vcpu_count) != self.vcpu_count || state.properties != self.properties {
            return Err(Error::ExecutionState(hvf::state::StateError(
                "GIC topology mismatch",
            )));
        }
        self.bindings.framework.install_gic(&state.bytes)
    }
}

impl IrqChipT for HvfGicV3 {
    fn execution_state_supported(&self) -> bool {
        self.bindings
            .framework
            .gic_symbols()
            .into_iter()
            .all(|available| available)
    }

    fn capture_hvf_state(&self) -> Result<hvf::state::GicState, String> {
        self.capture_execution_state()
            .map_err(|error| error.to_string())
    }

    fn install_hvf_state(&self, state: &hvf::state::GicState) -> Result<(), String> {
        self.install_execution_state(state)
            .map_err(|error| error.to_string())
    }

    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(irq_line) = irq_line {
            let ret = unsafe { (self.bindings.hv_gic_set_spi)(irq_line, true) };
            if ret != HV_SUCCESS {
                Err(DeviceError::FailedSignalingUsedQueue(
                    std::io::Error::other("HVF returned error when setting SPI"),
                ))
            } else {
                Ok(())
            }
        } else {
            Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "IRQ not line configured",
            )))
        }
    }
}

impl BusDevice for HvfGicV3 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for HvfGicV3 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-v3".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        7
    }
}

#[cfg(test)]
mod tests {
    use crate::legacy::HvfGicV3;

    #[test]
    fn native_gic_geometry_precedes_mmio_with_one_redistributor_per_cpu() {
        assert_eq!(
            HvfGicV3::geometry(1, [0x1_0000, 0x2_0000]),
            Some([0x09fd_0000, 0x1_0000, 0x09fe_0000, 0x2_0000])
        );
        assert_eq!(
            HvfGicV3::geometry(4, [0x1_0000, 0x2_0000]),
            Some([0x09f7_0000, 0x1_0000, 0x09f8_0000, 0x8_0000])
        );
        assert_eq!(HvfGicV3::geometry(0, [0x1_0000, 0x2_0000]), None);
        assert_eq!(HvfGicV3::geometry(2, [0x1_0000, u64::MAX]), None);
        assert_eq!(HvfGicV3::geometry(1, [u64::MAX, 0x2_0000]), None);
    }
}
