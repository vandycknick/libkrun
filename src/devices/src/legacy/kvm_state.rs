//! Target-neutral KVM GICv3 data and its one canonical register inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GicRegister {
    pub group: u32,
    pub attr: u64,
    pub value: u64,
    pub width: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GicState {
    pub properties: [u64; 4],
    pub irq_count: u32,
    pub mpidrs: Vec<u64>,
    pub registers: Vec<GicRegister>,
}

pub const DIST: u32 = 1;
pub const REDIST: u32 = 5;
pub const CPU: u32 = 6;
pub const LINES: u32 = 7;
pub fn affinity(mpidr: u64) -> u64 {
    ((mpidr & 0xffffff) | ((mpidr >> 8) & 0xff000000)) << 32
}
pub const fn sys(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

pub fn descriptors(
    irq_count: u32,
    mpidrs: &[u64],
    priority_bits: &[u8],
) -> Result<Vec<(u32, u64, u8)>, String> {
    if mpidrs.is_empty()
        || mpidrs.len() > 255
        || mpidrs.len() != priority_bits.len()
        || !(64..=1024).contains(&irq_count)
        || !irq_count.is_multiple_of(32)
    {
        return Err("gic/cpu-irq-count".into());
    }
    if mpidrs.iter().enumerate().any(|(i, id)| {
        id & !0xffc1ffffff != 0
            || mpidrs[..i]
                .iter()
                .any(|other| affinity(*other) == affinity(*id))
    }) {
        return Err("gic/affinity-inventory".into());
    }
    let mut result = Vec::with_capacity(irq_count as usize * 4 + mpidrs.len() * 40);
    let mut dist = |offset: u64| result.push((DIST, offset, 4));
    for offset in [0, 4, 8, 12, 16] {
        dist(offset);
    }
    for base in [0x80, 0x100, 0x200, 0x300, 0xd00] {
        for n in 1..irq_count / 32 {
            dist(base + u64::from(n) * 4);
        }
    }
    for n in 8..irq_count / 4 {
        dist(0x400 + u64::from(n) * 4);
    }
    for n in 2..irq_count / 16 {
        dist(0xc00 + u64::from(n) * 4);
    }
    for irq in 32..irq_count {
        dist(0x6000 + u64::from(irq) * 8);
        dist(0x6004 + u64::from(irq) * 8);
    }
    for irq in (32..irq_count).step_by(32) {
        result.push((LINES, irq.into(), 4));
    }
    for (mpidr, priority_bits) in mpidrs.iter().zip(priority_bits) {
        let prefix = affinity(*mpidr);
        for offset in [
            0, 4, 8, 12, 16, 20, 0x10080, 0x10100, 0x10200, 0x10300, 0x10c00, 0x10c04, 0x10d00,
        ] {
            result.push((REDIST, prefix | offset, 4));
        }
        for n in 0..8 {
            result.push((REDIST, prefix | (0x10400 + n * 4), 4));
        }
        result.push((LINES, prefix, 4));
        if !(5..=7).contains(priority_bits) {
            return Err("gic/cpu-interface-priority-width".into());
        }
        let active_registers = 1usize << (*priority_bits - 5);
        for register in [
            sys(3, 0, 4, 6, 0),
            sys(3, 0, 12, 8, 3),
            sys(3, 0, 12, 12, 3),
            sys(3, 0, 12, 12, 4),
            sys(3, 0, 12, 12, 5),
            sys(3, 0, 12, 12, 6),
            sys(3, 0, 12, 12, 7),
        ] {
            result.push((CPU, prefix | register, 8));
        }
        for (bank, first) in [(8, 4), (9, 0)] {
            for n in 0..active_registers {
                result.push((CPU, prefix | sys(3, 0, 12, bank, first + n as u64), 8));
            }
        }
    }
    result.sort_unstable();
    if result.len() > 32768 || result.windows(2).any(|p| p[0] == p[1]) {
        return Err("gic/register-limit-or-duplicate".into());
    }
    Ok(result)
}
pub fn validate_gic(
    properties: [u64; 4],
    irq_count: u32,
    mpidrs: &[u64],
    registers: &[GicRegister],
) -> Result<(), String> {
    if mpidrs.len() > 255 || registers.len() > 32768 {
        return Err("gic/state-limit".into());
    }
    if properties[1] != 65536
        || properties[3] != (mpidrs.len() as u64) * 131072
        || !properties[0].is_multiple_of(65536)
        || !properties[2].is_multiple_of(65536)
        || properties[2].checked_add(properties[3]) != Some(properties[0])
    {
        return Err("gic/redistributor-address-topology".into());
    }
    let mut priorities = Vec::with_capacity(mpidrs.len());
    for id in mpidrs {
        let ctlr = registers
            .iter()
            .find(|r| r.group == CPU && r.attr == (affinity(*id) | sys(3, 0, 12, 12, 4)))
            .ok_or("gic/missing-cpu-control")?;
        priorities.push((((ctlr.value >> 8) & 7) + 1) as u8);
    }
    let expected = descriptors(irq_count, mpidrs, &priorities)?;
    if !expected
        .into_iter()
        .eq(registers.iter().map(|r| (r.group, r.attr, r.width)))
    {
        return Err("gic/missing-extra-duplicate-or-unordered-register".into());
    }
    for r in registers {
        if r.width == 4 && r.value > u64::from(u32::MAX) {
            return Err("gic/register-width-value".into());
        }
        if r.group == REDIST && r.attr & 0xffffffff == 0 && r.value & 1 != 0 {
            return Err("gic/lpi-state-unqualified".into());
        }
    }
    Ok(())
}
impl GicState {
    pub fn validate(&self) -> Result<(), String> {
        validate_gic(
            self.properties,
            self.irq_count,
            &self.mpidrs,
            &self.registers,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::legacy::kvm_state::{CPU, LINES, affinity, descriptors, sys};
    #[test]
    fn kvm_execution_gic_inventory_includes_cpu_priority_and_input_lines() {
        let inventory = descriptors(64, &[0, 1], &[5, 7]).unwrap();
        assert!(inventory.contains(&(CPU, affinity(1) | sys(3, 0, 12, 9, 3), 8)));
        assert!(!inventory.contains(&(CPU, sys(3, 0, 12, 9, 3), 8)));
        assert!(inventory.contains(&(LINES, affinity(1), 4)));
        assert!(inventory.contains(&(LINES, 32, 4)));
        assert!(
            !inventory
                .iter()
                .any(|(group, attr, _)| *group == 1 && (0x280..0x300).contains(attr))
        );
        assert!(descriptors(64, &[0, 0], &[5, 5]).is_err());
        assert!(descriptors(65, &[0], &[5]).is_err());
    }
    #[test]
    fn kvm_execution_gic_affinity_preserves_all_four_levels() {
        assert_eq!(affinity(0x1200345678), 0x1234567800000000);
    }
}
