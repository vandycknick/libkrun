//! Target-neutral classification of the effective x86 guest's raw KVM MSR inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MsrClass {
    Mutable = 0,
    Model = 1,
    Command = 2,
    CanonicalAlias = 3,
    Inapplicable = 4,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuFeatures {
    pub amd: bool,
    pub intel_pmu: bool,
    pub svm: bool,
    pub vmx: bool,
    pub amd_extended_counters: bool,
    pub amd_llc_counters: bool,
    pub amd_nb_counters: bool,
    pub ibs: bool,
    pub ibs_features: u32,
    pub hyper_v: bool,
    pub pdcm: bool,
    pub arch_capabilities: bool,
    pub pv: u32,
    pub amd_perf_v2: bool,
}
impl CpuFeatures {
    pub fn from_cpuid(lookup: impl Fn(u32, u32) -> Option<[u32; 4]>) -> Self {
        let root = lookup(0, 0).map_or([0; 4], |v| v);
        let basic = lookup(1, 0).map_or([0; 4], |v| v);
        let amd = lookup(0x80000001, 0).map_or([0; 4], |v| v);
        Self {
            amd: root[1] == 0x68747541 && root[3] == 0x69746e65 && root[2] == 0x444d4163,
            intel_pmu: lookup(0xa, 0).is_some_and(|v| v[0] & 255 != 0),
            svm: amd[2] & (1 << 2) != 0,
            vmx: basic[2] & (1 << 5) != 0,
            amd_extended_counters: amd[2] & (1 << 23) != 0,
            amd_llc_counters: amd[2] & (1 << 28) != 0,
            amd_nb_counters: amd[2] & (1 << 24) != 0,
            ibs: amd[2] & (1 << 10) != 0,
            ibs_features: lookup(0x8000001b, 0).map_or(0, |v| v[0]),
            pdcm: basic[2] & (1 << 15) != 0,
            arch_capabilities: lookup(7, 0).is_some_and(|v| v[3] & (1 << 29) != 0),
            pv: lookup(0x40000001, 0).map_or(0, |v| v[0]),
            amd_perf_v2: lookup(0x80000022, 0).is_some_and(|v| v[0] & 1 != 0),
            hyper_v: lookup(0x40000000, 0).is_some_and(|v| v[1] == 0x7263694d),
        }
    }
    pub fn classify(self, index: u32) -> Result<MsrClass, u32> {
        use MsrClass::{CanonicalAlias, Command, Inapplicable, Model, Mutable};
        Ok(match index {
            0x10 | 0x1b | 0x6e0 | 0xc0000080 | 0x800..=0xbff => CanonicalAlias,
            0x11 | 0x12 => {
                if self.pv & (1 << 3) != 0 {
                    CanonicalAlias
                } else if self.pv & 1 != 0 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x49 | 0x79 | 0x10b | 0xc0010020 => Command,
            0x17 | 0x8b | 0xce | 0xfe | 0x179 | 0x198 | 0x1ad | 0x1ae | 0x606 | 0xc0010042
            | 0xc0010063 | 0xc001100c => Model,
            0x10a => {
                if self.arch_capabilities {
                    Model
                } else {
                    Inapplicable
                }
            }
            0x345 => {
                if self.pdcm {
                    Model
                } else {
                    Inapplicable
                }
            }
            0x3a | 0x480..=0x493 => {
                if self.vmx {
                    return Err(index);
                } else {
                    Inapplicable
                }
            }
            0xc0000104 => Mutable,
            0xc0010114..=0xc0010117 => {
                if self.svm {
                    return Err(index);
                } else {
                    Inapplicable
                }
            }
            0xc1..=0xc8 | 0x186..=0x18d | 0x309..=0x30b | 0x38d..=0x38f | 0x3f1 | 0x3f2 | 0x600 => {
                if self.intel_pmu {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x390 => {
                if self.intel_pmu {
                    Command
                } else {
                    Inapplicable
                }
            }
            0xc0000300 | 0xc0000301 => {
                if self.amd_perf_v2 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0xc0000302 | 0xc0000303 => {
                if self.amd_perf_v2 {
                    Command
                } else {
                    Inapplicable
                }
            }
            0x4b564d00 | 0x4b564d01 => {
                if self.pv & (1 << 3) != 0 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x4b564d02 => {
                if self.pv & (1 << 4) != 0 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x4b564d03 => {
                if self.pv & (1 << 5) != 0 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x4b564d04 => {
                if self.pv & (1 << 6) != 0 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x4b564d05 => {
                if self.pv & (1 << 12) != 0 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x4b564d06 => {
                if self.pv & (1 << 14) != 0 {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x4b564d07 => {
                if self.pv & (1 << 14) != 0 {
                    Command
                } else {
                    Inapplicable
                }
            }
            0xc0010000..=0xc0010007 => {
                if self.amd_extended_counters {
                    CanonicalAlias
                } else {
                    Mutable
                }
            }
            0xc0010200..=0xc001020b => {
                if self.amd_extended_counters {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0xc0010230..=0xc001023b => {
                if self.amd_llc_counters {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0xc0010240..=0xc001024b => {
                if self.amd_nb_counters {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0xc0011030..=0xc001103b | 0xc001103d => {
                if self.ibs {
                    Mutable
                } else {
                    Inapplicable
                }
            }
            0x40000000..=0x400001ff => {
                if self.hyper_v {
                    return Err(index);
                } else {
                    Inapplicable
                }
            }
            0x0
            | 0x1
            | 0x2a
            | 0x2f
            | 0x34
            | 0x3b
            | 0x48
            | 0x8c
            | 0x9e
            | 0xe1
            | 0xe2
            | 0xe7
            | 0xe8
            | 0x10f
            | 0x11e
            | 0x122
            | 0x123
            | 0x140
            | 0x174..=0x176
            | 0x17a
            | 0x17b
            | 0x1a0
            | 0x1a4
            | 0x1aa
            | 0x1c4
            | 0x1c5
            | 0x1c8
            | 0x1c9
            | 0x1d9
            | 0x1da
            | 0x1db..=0x1de
            | 0x1fc
            | 0x200..=0x20f
            | 0x250
            | 0x258
            | 0x259
            | 0x268..=0x26f
            | 0x277
            | 0x2ff
            | 0x400..=0x47f
            | 0x4d0
            | 0x560
            | 0x561
            | 0x570..=0x572
            | 0x580..=0x587
            | 0x680..=0x68f
            | 0x6a0
            | 0x6a2
            | 0x6a4..=0x6a8
            | 0x6c0..=0x6cf
            | 0xd90
            | 0xda0
            | 0xc0000081..=0xc0000084
            | 0xc00000e9
            | 0xc0000100..=0xc0000103
            | 0xc0010010
            | 0xc0010015
            | 0xc001001a
            | 0xc001001b
            | 0xc001001d
            | 0xc001001f
            | 0xc0010030..=0xc0010035
            | 0xc0010041
            | 0xc0010044..=0xc001004b
            | 0xc0010054
            | 0xc0010055
            | 0xc0010058
            | 0xc0010061
            | 0xc0010062
            | 0xc0010064..=0xc001006b
            | 0xc0010112
            | 0xc0010113
            | 0xc001011f
            | 0xc0010140
            | 0xc0010141
            | 0xc0011020..=0xc001102a => Mutable,
            _ => return Err(index),
        })
    }
    pub fn require_complete(self, has: impl Fn(u32) -> bool) -> Result<(), u32> {
        if self.amd_perf_v2 {
            for index in [0xc0000300, 0xc0000301] {
                if !has(index) {
                    return Err(index);
                }
            }
        }
        if self.amd {
            if self.amd_extended_counters {
                for index in 0xc0010200..=0xc001020b {
                    if !has(index) {
                        return Err(index);
                    }
                }
            } else {
                for index in 0xc0010000..=0xc0010007 {
                    if !has(index) {
                        return Err(index);
                    }
                }
            }
        }
        if self.ibs {
            if !has(0xc001103a) {
                return Err(0xc001103a);
            }
            if self.ibs_features & (1 << 1) != 0 {
                for index in 0xc0011030..=0xc0011032 {
                    if !has(index) {
                        return Err(index);
                    }
                }
            }
            if self.ibs_features & (1 << 2) != 0 {
                for index in 0xc0011033..=0xc0011039 {
                    if !has(index) {
                        return Err(index);
                    }
                }
            }
            if self.ibs_features & (1 << 5) != 0 && !has(0xc001103b) {
                return Err(0xc001103b);
            }
        }
        Ok(())
    }
    pub fn validate_inventory(
        self,
        entries: impl Iterator<Item = (u32, u8)> + Clone,
    ) -> Result<(), u32> {
        self.require_complete(|index| entries.clone().any(|(candidate, _)| candidate == index))?;
        for (index, class) in entries.clone() {
            if self.classify(index)? as u8 != class {
                return Err(index);
            }
            if class == MsrClass::CanonicalAlias as u8
                && let Some(canonical) = canonical_alias(index)
                && !entries.clone().any(|(candidate, class)| {
                    candidate == canonical && class == MsrClass::Mutable as u8
                })
            {
                return Err(canonical);
            }
        }
        Ok(())
    }
}

pub fn canonical_alias(index: u32) -> Option<u32> {
    match index {
        0x11 => Some(0x4b564d00),
        0x12 => Some(0x4b564d01),
        0xc0010000..=0xc0010003 => Some(0xc0010200 + (index - 0xc0010000) * 2),
        0xc0010004..=0xc0010007 => Some(0xc0010201 + (index - 0xc0010004) * 2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::x86_state::{CpuFeatures, MsrClass, canonical_alias};
    #[test]
    fn kvm_execution_msr_classification_keeps_amd_performance_state() {
        let features = CpuFeatures {
            amd: true,
            amd_extended_counters: true,
            ..Default::default()
        };
        for index in [0xc0010200, 0xc001020b] {
            assert_eq!(features.classify(index).unwrap(), MsrClass::Mutable);
        }
        assert_eq!(
            features.classify(0xc0010007).unwrap(),
            MsrClass::CanonicalAlias
        );
        assert_eq!(canonical_alias(0xc0010007), Some(0xc0010207));
        assert!(
            features
                .require_complete(|index| index != 0xc001020b)
                .is_err()
        );
        assert!(features.require_complete(|_| true).is_ok());
        assert_eq!(features.classify(0x49).unwrap(), MsrClass::Command);
        assert_eq!(features.classify(0x10).unwrap(), MsrClass::CanonicalAlias);
        assert!(features.classify(0xdeadbeef).is_err());
    }
    #[test]
    fn kvm_execution_msr_exposed_ibs_is_not_zero_value_inapplicability() {
        let features = CpuFeatures {
            ibs: true,
            ibs_features: 6,
            ..Default::default()
        };
        assert_eq!(features.classify(0xc0011033).unwrap(), MsrClass::Mutable);
        assert_eq!(
            features.require_complete(|index| index != 0xc0011037),
            Err(0xc0011037)
        );
        assert_eq!(
            CpuFeatures::default().classify(0xc0011033).unwrap(),
            MsrClass::Inapplicable
        );
    }
    #[test]
    fn kvm_execution_msr_feature_gates_distinguish_raw_support_from_exposure() {
        let hidden = CpuFeatures::default();
        assert_eq!(hidden.classify(0x345).unwrap(), MsrClass::Inapplicable);
        assert_eq!(hidden.classify(0x10a).unwrap(), MsrClass::Inapplicable);
        let exposed = CpuFeatures {
            pdcm: true,
            arch_capabilities: true,
            pv: 8,
            amd_perf_v2: true,
            ..Default::default()
        };
        assert_eq!(exposed.classify(0x345).unwrap(), MsrClass::Model);
        assert_eq!(exposed.classify(0x10a).unwrap(), MsrClass::Model);
        assert_eq!(exposed.classify(0x11).unwrap(), MsrClass::CanonicalAlias);
        assert_eq!(exposed.classify(0x4b564d00).unwrap(), MsrClass::Mutable);
        assert_eq!(exposed.classify(0xc0000301).unwrap(), MsrClass::Mutable);
        assert_eq!(exposed.classify(0xc0000302).unwrap(), MsrClass::Command);
        assert_eq!(
            exposed.require_complete(|index| index != 0xc0000301),
            Err(0xc0000301)
        );
    }
}
