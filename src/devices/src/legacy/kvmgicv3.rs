// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;
use arch::guest_memory::MemoryDomain;
use kvm_bindings::*;
use kvm_ioctls::{DeviceFd, Error, VmFd};
use std::io;
use std::sync::Arc;
use utils::eventfd::EventFd;

const KVM_VGIC_V3_BASE_SIZE: u64 = 0x10000;
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

use crate::legacy::kvm_state::{GicRegister, GicState, affinity, descriptors, sys};

pub struct KvmGicV3 {
    device_fd: DeviceFd,
    _memory_domain: Arc<MemoryDomain>,
    properties: [u64; 4],
    vcpu_count: u64,
    irq_count: u32,
}

fn attribute(group: u32, attr: u64, addr: u64) -> kvm_device_attr {
    kvm_device_attr {
        group,
        attr,
        addr,
        flags: 0,
    }
}
impl KvmGicV3 {
    pub fn new(vm: &VmFd, vcpu_count: u64, domain: Arc<MemoryDomain>) -> Result<Self, Error> {
        let gic = Self::create(vm, vcpu_count, domain)?;
        gic.initialize()?;
        Ok(gic)
    }
    fn create(vm: &VmFd, vcpu_count: u64, domain: Arc<MemoryDomain>) -> Result<Self, Error> {
        if vcpu_count == 0 || vcpu_count > 255 {
            return Err(Error::new(libc::EINVAL));
        }
        let dist_size = KVM_VGIC_V3_BASE_SIZE;
        let dist_addr = arch::MMIO_MEM_START - dist_size;
        let redists_size = 2 * dist_size * vcpu_count;
        let redists_addr = dist_addr - redists_size;
        let mut request = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let device_fd = vm.create_device(&mut request)?;
        device_fd.set_device_attr(&attribute(
            KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST),
            &dist_addr as *const u64 as u64,
        ))?;
        device_fd.set_device_attr(&attribute(
            KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST),
            &redists_addr as *const u64 as u64,
        ))?;
        let irq_count = arch::aarch64::layout::IRQ_MAX - arch::aarch64::layout::IRQ_BASE + 1;
        device_fd.set_device_attr(&attribute(
            KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            &irq_count as *const u32 as u64,
        ))?;
        Ok(Self {
            device_fd,
            _memory_domain: domain,
            properties: [dist_addr, dist_size, redists_addr, redists_size],
            vcpu_count,
            irq_count,
        })
    }
    /// Called after the exact recorded vCPU creation order, never via a GICv2 fallback.
    pub fn create_for_restore(
        vm: &VmFd,
        state: &GicState,
        domain: Arc<MemoryDomain>,
    ) -> Result<Self, String> {
        state.validate()?;
        let gic = Self::create(vm, state.mpidrs.len() as u64, domain)
            .map_err(|e| format!("gic/create: {e}"))?;
        if gic.properties != state.properties || gic.irq_count != state.irq_count {
            return Err("gic/construction-topology".into());
        }
        for offset in [4, 12] {
            let value = state
                .registers
                .iter()
                .find(|r| r.group == KVM_DEV_ARM_VGIC_GRP_DIST_REGS && r.attr == offset)
                .ok_or("gic/missing-compatibility-register")?;
            gic.write(value)?;
        }
        Ok(gic)
    }
    pub fn initialize(&self) -> Result<(), Error> {
        self.device_fd.set_device_attr(&attribute(
            KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
        ))
    }
    fn read(&self, group: u32, attr: u64, width: u8) -> Result<GicRegister, String> {
        let mut wide = 0u64;
        let mut word = 0u32;
        let addr = if width == 4 {
            &mut word as *mut u32 as u64
        } else {
            &mut wide as *mut u64 as u64
        };
        let mut native = attribute(group, attr, addr);
        // DeviceFd requires the caller to provide a correctly sized writable output.
        unsafe { self.device_fd.get_device_attr(&mut native) }
            .map_err(|e| format!("gic/GET/{group}/{attr:#x}: {e}"))?;
        Ok(GicRegister {
            group,
            attr,
            value: if width == 4 { word.into() } else { wide },
            width,
        })
    }
    fn write(&self, r: &GicRegister) -> Result<(), String> {
        let wide = r.value;
        let word = u32::try_from(r.value).unwrap_or(0);
        if r.width == 4 && r.value > u64::from(u32::MAX) {
            return Err("gic/register-u32-overflow".into());
        }
        let addr = if r.width == 4 {
            &word as *const u32 as u64
        } else if r.width == 8 {
            &wide as *const u64 as u64
        } else {
            return Err("gic/register-width".into());
        };
        self.device_fd
            .set_device_attr(&attribute(r.group, r.attr, addr))
            .map_err(|e| format!("gic/SET/{}/{:#x}: {e}", r.group, r.attr))
    }
    fn descriptors(&self, mpidrs: &[u64]) -> Result<Vec<(u32, u64, u8)>, String> {
        if mpidrs.len() as u64 != self.vcpu_count {
            return Err("gic/cpu-count".into());
        }
        let mut priorities = Vec::with_capacity(mpidrs.len());
        for mpidr in mpidrs {
            let ctlr = self
                .read(
                    KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                    affinity(*mpidr) | sys(3, 0, 12, 12, 4),
                    8,
                )?
                .value;
            priorities.push((((ctlr >> 8) & 7) + 1) as u8);
        }
        descriptors(self.irq_count, mpidrs, &priorities)
    }
    pub fn capture_execution_state(&self, mpidrs: &[u64]) -> Result<GicState, String> {
        let mut registers = Vec::new();
        for (group, attr, width) in self.descriptors(mpidrs)? {
            registers.push(self.read(group, attr, width)?);
        }
        // The initial non-ITS profile cannot contain LPI-enabled redistributors.
        if registers.iter().any(|r| {
            r.group == KVM_DEV_ARM_VGIC_GRP_REDIST_REGS
                && r.attr & 0xffffffff == 0
                && r.value & 1 != 0
        }) {
            return Err("gic/lpi-state-unqualified".into());
        }
        Ok(GicState {
            properties: self.properties,
            irq_count: self.irq_count,
            mpidrs: mpidrs.to_vec(),
            registers,
        })
    }
    pub fn install_execution_state(&self, state: &GicState) -> Result<(), String> {
        state.validate()?;
        if state.properties != self.properties || state.irq_count != self.irq_count {
            return Err("gic/topology".into());
        }
        let expected = self.descriptors(&state.mpidrs)?;
        if !expected
            .iter()
            .copied()
            .eq(state.registers.iter().map(|r| (r.group, r.attr, r.width)))
        {
            return Err("gic/register-inventory".into());
        }
        for r in &state.registers {
            let offset = r.attr & 0xffffffff;
            let identity = (r.group == KVM_DEV_ARM_VGIC_GRP_DIST_REGS
                && matches!(offset, 4 | 8 | 12))
                || (r.group == KVM_DEV_ARM_VGIC_GRP_REDIST_REGS && matches!(offset, 4 | 8 | 12));
            if identity && self.read(r.group, r.attr, r.width)?.value != r.value {
                return Err(format!("gic/identity/{offset:#x}"));
            }
        }
        // Disable delivery first. Set/clear register aliases are operations, not duplicate payload owners.
        for r in &state.registers {
            let offset = r.attr & 0xffffffff;
            if (r.group == KVM_DEV_ARM_VGIC_GRP_DIST_REGS && (0x100..0x180).contains(&offset))
                || (r.group == KVM_DEV_ARM_VGIC_GRP_REDIST_REGS && offset == 0x10100)
            {
                self.write(&GicRegister {
                    group: r.group,
                    attr: r.attr + 0x80,
                    value: u32::MAX.into(),
                    width: 4,
                })?;
            }
            if (r.group == KVM_DEV_ARM_VGIC_GRP_DIST_REGS && (0x300..0x380).contains(&offset))
                || (r.group == KVM_DEV_ARM_VGIC_GRP_REDIST_REGS && offset == 0x10300)
            {
                self.write(&GicRegister {
                    group: r.group,
                    attr: r.attr + 0x80,
                    value: u32::MAX.into(),
                    width: 4,
                })?;
            }
        }
        let enabled = |r: &GicRegister| {
            let offset = r.attr & 0xffffffff;
            (r.group == KVM_DEV_ARM_VGIC_GRP_DIST_REGS
                && (offset == 0 || (0x100..0x180).contains(&offset)))
                || (r.group == KVM_DEV_ARM_VGIC_GRP_REDIST_REGS
                    && (offset == 0 || offset == 0x10100))
                || (r.group == KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS
                    && [sys(3, 0, 12, 12, 6), sys(3, 0, 12, 12, 7)].contains(&(r.attr & 0xffff)))
        };
        for final_pass in [false, true] {
            for r in &state.registers {
                let offset = r.attr & 0xffffffff;
                let identity = (r.group == KVM_DEV_ARM_VGIC_GRP_DIST_REGS
                    && matches!(offset, 4 | 8 | 12))
                    || (r.group == KVM_DEV_ARM_VGIC_GRP_REDIST_REGS
                        && matches!(offset, 4 | 8 | 12));
                if !identity && enabled(r) == final_pass {
                    self.write(r)?;
                }
            }
        }
        Ok(())
    }
}
impl IrqChipT for KvmGicV3 {
    fn execution_state_supported(&self) -> bool {
        true
    }
    fn get_mmio_addr(&self) -> u64 {
        0
    }
    fn get_mmio_size(&self) -> u64 {
        0
    }
    fn capture_kvm_state(&self, mpidrs: &[u64]) -> Result<GicState, String> {
        self.capture_execution_state(mpidrs)
    }
    fn install_kvm_state(&self, state: &GicState) -> Result<(), String> {
        self.install_execution_state(state)
    }
    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        let event = interrupt_evt.ok_or_else(|| {
            DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::NotFound,
                "EventFd not set up for irq line",
            ))
        })?;
        event
            .write(1)
            .map_err(DeviceError::FailedSignalingUsedQueue)
    }
}
impl BusDevice for KvmGicV3 {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        log::error!("unexpected userspace read of in-kernel GIC at {offset:#x}");
        data.fill(0);
    }
    fn write(&mut self, _vcpuid: u64, offset: u64, _data: &[u8]) {
        log::error!("unexpected userspace write of in-kernel GIC at {offset:#x}");
    }
}
impl GICDevice for KvmGicV3 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }
    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }
    fn fdt_compatibility(&self) -> String {
        "arm,gic-v3".into()
    }
    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }
    fn version(&self) -> u32 {
        kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3
    }
}
