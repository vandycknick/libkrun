//! Machine-less native observations and versioned live-state compatibility.

pub const LIVE_QUERY_ABI: u32 = 1;

/// Bump whenever any execution, CPU, RAM-layout, device or legacy state encoding changes.
pub const LIVE_STATE_SCHEMA: &str = "silo.live-state/1";

pub const fn live_state_schema() -> &'static str {
    LIVE_STATE_SCHEMA
}

pub const fn guest_architecture() -> &'static str {
    std::env::consts::ARCH
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLane {
    KvmX86_64,
    KvmArm64GicV3,
    HvfArm64GicV3,
    Unsupported,
}

impl NativeLane {
    pub fn current() -> Self {
        if cfg!(any(
            feature = "tee",
            feature = "aws-nitro",
            feature = "native-control-probe"
        )) {
            return Self::Unsupported;
        }
        match (std::env::consts::OS, guest_architecture()) {
            ("linux", "x86_64") => Self::KvmX86_64,
            ("linux", "aarch64") => Self::KvmArm64GicV3,
            ("macos", "aarch64") => Self::HvfArm64GicV3,
            _ => Self::Unsupported,
        }
    }

    const fn queries_kvm(self) -> bool {
        matches!(self, Self::KvmX86_64 | Self::KvmArm64GicV3)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryOperation {
    OpenKvm,
    KvmApiVersion,
    KvmCheckExtension(KvmCapability),
    LoadHvfFramework,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeQueryError {
    pub operation: QueryOperation,
    pub raw_os_error: Option<i32>,
    pub kind: std::io::ErrorKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation<T> {
    Observed(T),
    Unavailable(NativeQueryError),
    NotEvaluated,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvmCapability {
    Irqchip,
    Ioeventfd,
    Irqfd,
    UserMemory,
    SetTssAddr,
    ArmPsci02,
    ImmediateExit,
}

const KVM_CAPABILITIES: [KvmCapability; 7] = [
    KvmCapability::Irqchip,
    KvmCapability::Ioeventfd,
    KvmCapability::Irqfd,
    KvmCapability::UserMemory,
    KvmCapability::SetTssAddr,
    KvmCapability::ArmPsci02,
    KvmCapability::ImmediateExit,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvmCapabilityFact {
    pub capability: KvmCapability,
    pub value: Observation<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvmHostFacts {
    pub access: Observation<()>,
    pub api_version: Observation<i32>,
    pub capabilities: [KvmCapabilityFact; 7],
    /// A candidate arm64 lane does not establish the VM's actual GIC model.
    pub gic_model: Observation<()>,
}

impl KvmHostFacts {
    fn not_queried(applicable: bool) -> Self {
        Self {
            access: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
            api_version: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
            capabilities: KVM_CAPABILITIES.map(|capability| KvmCapabilityFact {
                capability,
                value: if applicable {
                    Observation::NotEvaluated
                } else {
                    Observation::NotApplicable
                },
            }),
            gic_model: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
        }
    }

    pub fn capability(&self, capability: KvmCapability) -> Observation<i32> {
        self.capabilities
            .iter()
            .find(|fact| fact.capability == capability)
            .map_or(Observation::NotEvaluated, |fact| fact.value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvmPrerequisites {
    /// All inspected system-fd prerequisites, not VM construction or live admission.
    SystemQueriesAvailable,
    NotApplicable,
    Incomplete,
    Unavailable(NativeQueryError),
    ApiMismatch {
        observed: i32,
        required: i32,
    },
    MissingCapability(KvmCapability),
}

pub fn reduce_kvm_prerequisites(lane: NativeLane, facts: &KvmHostFacts) -> KvmPrerequisites {
    if !matches!(lane, NativeLane::KvmX86_64 | NativeLane::KvmArm64GicV3) {
        return KvmPrerequisites::NotApplicable;
    }
    match facts.access {
        Observation::Observed(()) => {}
        Observation::Unavailable(error) => return KvmPrerequisites::Unavailable(error),
        _ => return KvmPrerequisites::Incomplete,
    }
    match facts.api_version {
        Observation::Observed(12) => {}
        Observation::Observed(observed) => {
            return KvmPrerequisites::ApiMismatch {
                observed,
                required: 12,
            };
        }
        Observation::Unavailable(error) => return KvmPrerequisites::Unavailable(error),
        _ => return KvmPrerequisites::Incomplete,
    }
    if !facts
        .capabilities
        .iter()
        .zip(KVM_CAPABILITIES)
        .all(|(fact, expected)| fact.capability == expected)
    {
        return KvmPrerequisites::Incomplete;
    }
    for capability in KVM_CAPABILITIES {
        if (capability == KvmCapability::SetTssAddr && lane != NativeLane::KvmX86_64)
            || (capability == KvmCapability::ArmPsci02 && lane != NativeLane::KvmArm64GicV3)
        {
            continue;
        }
        match facts.capability(capability) {
            Observation::Observed(value) if value > 0 => {}
            Observation::Observed(0) => return KvmPrerequisites::MissingCapability(capability),
            Observation::Unavailable(error) => return KvmPrerequisites::Unavailable(error),
            _ => return KvmPrerequisites::Incomplete,
        }
    }
    KvmPrerequisites::SystemQueriesAvailable
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HvfGicSymbol {
    StateCreate,
    StateGetSize,
    StateGetData,
    SetState,
    GetIccReg,
    SetIccReg,
}

impl HvfGicSymbol {
    pub const ALL: [Self; 6] = [
        Self::StateCreate,
        Self::StateGetSize,
        Self::StateGetData,
        Self::SetState,
        Self::GetIccReg,
        Self::SetIccReg,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::StateCreate => "hv_gic_state_create",
            Self::StateGetSize => "hv_gic_state_get_size",
            Self::StateGetData => "hv_gic_state_get_data",
            Self::SetState => "hv_gic_set_state",
            Self::GetIccReg => "hv_gic_get_icc_reg",
            Self::SetIccReg => "hv_gic_set_icc_reg",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HvfSymbolGroup {
    Available,
    Missing(HvfGicSymbol),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvfGicSymbols {
    presence: [bool; 6],
}

impl HvfGicSymbols {
    /// Order follows HvfGicSymbol::ALL. Pure input, not a native execution probe.
    pub const fn from_presence(presence: [bool; 6]) -> Self {
        Self { presence }
    }

    pub fn contains(self, symbol: HvfGicSymbol) -> bool {
        self.presence[symbol as usize]
    }

    pub fn blob_group(self) -> HvfSymbolGroup {
        self.group(&HvfGicSymbol::ALL[..4])
    }

    pub fn icc_group(self) -> HvfSymbolGroup {
        self.group(&HvfGicSymbol::ALL[4..])
    }

    fn group(self, symbols: &[HvfGicSymbol]) -> HvfSymbolGroup {
        symbols
            .iter()
            .find(|symbol| !self.contains(**symbol))
            .map_or(HvfSymbolGroup::Available, |symbol| {
                HvfSymbolGroup::Missing(*symbol)
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HvfGicModel {
    NativeGicV3,
    UserspaceGicV3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvfVmFacts {
    pub gic_model: Observation<HvfGicModel>,
    pub nested: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HvfGicAdmission {
    /// GIC prerequisites only, never a live operation or qualification grant.
    PrerequisitesAvailable,
    NotApplicable,
    Incomplete,
    FrameworkUnavailable(NativeQueryError),
    MissingSymbol(HvfGicSymbol),
    UserspaceGic,
    NestedProfile,
    ProvidersNotImplemented,
}

pub fn reduce_hvf_gic_admission(
    lane: NativeLane,
    host: &HvfHostFacts,
    vm: HvfVmFacts,
    providers_complete: bool,
) -> HvfGicAdmission {
    if lane != NativeLane::HvfArm64GicV3 {
        return HvfGicAdmission::NotApplicable;
    }
    match host.framework {
        Observation::Observed(()) => {}
        Observation::Unavailable(error) => return HvfGicAdmission::FrameworkUnavailable(error),
        _ => return HvfGicAdmission::Incomplete,
    }
    let Observation::Observed(symbols) = host.gic_symbols else {
        return HvfGicAdmission::Incomplete;
    };
    for group in [symbols.blob_group(), symbols.icc_group()] {
        if let HvfSymbolGroup::Missing(symbol) = group {
            return HvfGicAdmission::MissingSymbol(symbol);
        }
    }
    if host.gic_blob_symbols != Observation::Observed(symbols.blob_group())
        || host.gic_icc_symbols != Observation::Observed(symbols.icc_group())
    {
        return HvfGicAdmission::Incomplete;
    }
    match vm.gic_model {
        Observation::Observed(HvfGicModel::NativeGicV3) => {}
        Observation::Observed(HvfGicModel::UserspaceGicV3) => return HvfGicAdmission::UserspaceGic,
        _ => return HvfGicAdmission::Incomplete,
    }
    if vm.nested {
        return HvfGicAdmission::NestedProfile;
    }
    if !providers_complete {
        return HvfGicAdmission::ProvidersNotImplemented;
    }
    HvfGicAdmission::PrerequisitesAvailable
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvfHostFacts {
    pub framework: Observation<()>,
    pub vm_admission: Observation<()>,
    pub gic_model: Observation<()>,
    pub gic_symbols: Observation<HvfGicSymbols>,
    pub gic_blob_symbols: Observation<HvfSymbolGroup>,
    pub gic_icc_symbols: Observation<HvfSymbolGroup>,
}

impl HvfHostFacts {
    fn not_queried(applicable: bool) -> Self {
        Self {
            framework: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
            vm_admission: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
            gic_model: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
            gic_symbols: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
            gic_blob_symbols: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
            gic_icc_symbols: if applicable {
                Observation::NotEvaluated
            } else {
                Observation::NotApplicable
            },
        }
    }

    pub fn from_symbols(symbols: HvfGicSymbols) -> Self {
        Self {
            framework: Observation::Observed(()),
            gic_symbols: Observation::Observed(symbols),
            gic_blob_symbols: Observation::Observed(symbols.blob_group()),
            gic_icc_symbols: Observation::Observed(symbols.icc_group()),
            ..Self::not_queried(true)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeUnsupportedReason {
    BuildExcluded,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeOperationSupport {
    Supported,
    Unsupported(NativeUnsupportedReason),
}

impl NativeOperationSupport {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// Implemented native primitives, not host/VM admission or lane qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeLiveOperations {
    pub pause: NativeOperationSupport,
    pub capture: NativeOperationSupport,
    pub restore: NativeOperationSupport,
    pub fork: NativeOperationSupport,
    pub incremental: NativeOperationSupport,
}

impl NativeLiveOperations {
    /// Pause is implemented on every recognized lane. Capture, restore, fork and
    /// incremental capture have exported-API evidence only on KVM x86_64; the
    /// arm64 lanes remain pending until their own runtime gates pass.
    pub const fn for_lane(lane: NativeLane) -> Self {
        let excluded = matches!(lane, NativeLane::Unsupported);
        let not_implemented = NativeOperationSupport::Unsupported(if excluded {
            NativeUnsupportedReason::BuildExcluded
        } else {
            NativeUnsupportedReason::NotImplemented
        });
        let live_state = if matches!(lane, NativeLane::KvmX86_64) {
            NativeOperationSupport::Supported
        } else {
            not_implemented
        };
        Self {
            pause: if excluded {
                NativeOperationSupport::Unsupported(NativeUnsupportedReason::BuildExcluded)
            } else {
                NativeOperationSupport::Supported
            },
            capture: live_state,
            restore: live_state,
            fork: live_state,
            incremental: live_state,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NativeHostReport {
    pub live_state_schema: &'static str,
    pub architecture: &'static str,
    pub lane: NativeLane,
    pub kvm: KvmHostFacts,
    pub kvm_prerequisites: KvmPrerequisites,
    pub hvf: HvfHostFacts,
    pub operations: NativeLiveOperations,
}

/// Observes system APIs only, never constructing a VM, vCPU, GIC or guest workload.
pub fn query_live_host() -> NativeHostReport {
    query_host_for_lane(NativeLane::current())
}

#[cfg(all(
    feature = "native-device-probe",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub fn query_diagnostic_live_host() -> NativeHostReport {
    query_live_host()
}

fn query_host_for_lane(lane: NativeLane) -> NativeHostReport {
    let kvm = if lane.queries_kvm() {
        query_kvm()
    } else {
        KvmHostFacts::not_queried(false)
    };
    let hvf = if lane == NativeLane::HvfArm64GicV3 {
        query_hvf()
    } else {
        HvfHostFacts::not_queried(false)
    };
    NativeHostReport {
        live_state_schema: LIVE_STATE_SCHEMA,
        architecture: guest_architecture(),
        lane,
        kvm_prerequisites: reduce_kvm_prerequisites(lane, &kvm),
        kvm,
        hvf,
        operations: NativeLiveOperations::for_lane(lane),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn query_hvf() -> HvfHostFacts {
    match hvf::framework::HvfFramework::load() {
        Ok(framework) => {
            HvfHostFacts::from_symbols(HvfGicSymbols::from_presence(framework.gic_symbols()))
        }
        Err(error) => {
            log::debug!("HVF framework observation unavailable: {error}");
            HvfHostFacts {
                framework: Observation::Unavailable(NativeQueryError {
                    operation: QueryOperation::LoadHvfFramework,
                    raw_os_error: None,
                    kind: std::io::ErrorKind::Other,
                }),
                ..HvfHostFacts::not_queried(true)
            }
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn query_hvf() -> HvfHostFacts {
    HvfHostFacts::not_queried(false)
}

#[cfg(target_os = "linux")]
fn query_kvm() -> KvmHostFacts {
    use kvm_ioctls::{Cap, Kvm};
    use std::io;

    let mut facts = KvmHostFacts::not_queried(true);
    let kvm = match Kvm::new() {
        Ok(kvm) => kvm,
        Err(error) => {
            let error = io::Error::from_raw_os_error(error.errno());
            facts.access = Observation::Unavailable(NativeQueryError {
                operation: QueryOperation::OpenKvm,
                raw_os_error: error.raw_os_error(),
                kind: error.kind(),
            });
            return facts;
        }
    };
    facts.access = Observation::Observed(());
    facts.api_version = observe_kvm_result(kvm.get_api_version(), QueryOperation::KvmApiVersion);
    for fact in &mut facts.capabilities {
        let cap = match fact.capability {
            KvmCapability::Irqchip => Cap::Irqchip,
            KvmCapability::Ioeventfd => Cap::Ioeventfd,
            KvmCapability::Irqfd => Cap::Irqfd,
            KvmCapability::UserMemory => Cap::UserMemory,
            KvmCapability::SetTssAddr if cfg!(target_arch = "x86_64") => Cap::SetTssAddr,
            KvmCapability::ArmPsci02 if cfg!(target_arch = "aarch64") => Cap::ArmPsci02,
            KvmCapability::ImmediateExit => Cap::ImmediateExit,
            _ => {
                fact.value = Observation::NotApplicable;
                continue;
            }
        };
        fact.value = observe_kvm_result(
            kvm.check_extension_int(cap),
            QueryOperation::KvmCheckExtension(fact.capability),
        );
    }
    if !cfg!(target_arch = "aarch64") {
        facts.gic_model = Observation::NotApplicable;
    }
    facts
}

#[cfg(target_os = "linux")]
fn observe_kvm_result(value: i32, operation: QueryOperation) -> Observation<i32> {
    if value >= 0 {
        Observation::Observed(value)
    } else {
        let error = std::io::Error::last_os_error();
        Observation::Unavailable(NativeQueryError {
            operation,
            raw_os_error: error.raw_os_error(),
            kind: error.kind(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn query_kvm() -> KvmHostFacts {
    KvmHostFacts::not_queried(false)
}

#[cfg(test)]
mod tests {
    use crate::api::capabilities::{
        KVM_CAPABILITIES, KvmCapability, KvmCapabilityFact, KvmHostFacts, KvmPrerequisites,
        LIVE_STATE_SCHEMA, NativeLane, NativeLiveOperations, NativeOperationSupport,
        NativeQueryError, NativeUnsupportedReason, Observation, QueryOperation, live_state_schema,
        reduce_kvm_prerequisites,
    };
    use std::io::ErrorKind;

    #[test]
    fn native_live_schema_is_exposed() {
        assert_eq!(live_state_schema(), LIVE_STATE_SCHEMA);
        assert_eq!(live_state_schema(), "silo.live-state/1");
    }

    fn observed_kvm() -> KvmHostFacts {
        KvmHostFacts {
            access: Observation::Observed(()),
            api_version: Observation::Observed(12),
            capabilities: KVM_CAPABILITIES.map(|capability| KvmCapabilityFact {
                capability,
                value: Observation::Observed(7),
            }),
            gic_model: Observation::NotEvaluated,
        }
    }

    #[test]
    fn native_live_operations_follow_the_explicit_lane_matrix() {
        let supported = NativeOperationSupport::Supported;
        let pending = NativeOperationSupport::Unsupported(NativeUnsupportedReason::NotImplemented);
        let excluded = NativeOperationSupport::Unsupported(NativeUnsupportedReason::BuildExcluded);
        for lane in [
            NativeLane::KvmX86_64,
            NativeLane::KvmArm64GicV3,
            NativeLane::HvfArm64GicV3,
            NativeLane::Unsupported,
        ] {
            // Exhaustive on purpose: a new lane must choose its row here.
            let (pause, live_state) = match lane {
                NativeLane::KvmX86_64 => (supported, supported),
                NativeLane::KvmArm64GicV3 | NativeLane::HvfArm64GicV3 => (supported, pending),
                NativeLane::Unsupported => (excluded, excluded),
            };
            let operations = NativeLiveOperations::for_lane(lane);
            assert_eq!(operations.pause, pause, "{lane:?} pause");
            assert_eq!(
                operations.pause.is_supported(),
                lane != NativeLane::Unsupported,
                "{lane:?} pause"
            );
            for (name, operation) in [
                ("capture", operations.capture),
                ("restore", operations.restore),
                ("fork", operations.fork),
                ("incremental", operations.incremental),
            ] {
                assert_eq!(operation, live_state, "{lane:?} {name}");
                assert_eq!(
                    operation.is_supported(),
                    lane == NativeLane::KvmX86_64,
                    "{lane:?} {name}"
                );
            }
        }
    }

    #[test]
    fn native_live_kvm_reducer_preserves_positive_payloads_and_arm_admission_unknown() {
        let facts = observed_kvm();
        for lane in [NativeLane::KvmX86_64, NativeLane::KvmArm64GicV3] {
            assert_eq!(
                reduce_kvm_prerequisites(lane, &facts),
                KvmPrerequisites::SystemQueriesAvailable
            );
        }
        assert_eq!(
            facts.capability(KvmCapability::ImmediateExit),
            Observation::Observed(7)
        );
        assert_eq!(facts.gic_model, Observation::NotEvaluated);
        assert_eq!(
            reduce_kvm_prerequisites(NativeLane::HvfArm64GicV3, &facts),
            KvmPrerequisites::NotApplicable
        );
    }

    #[test]
    fn native_live_kvm_reducer_preserves_permission_api_and_capability_errors() {
        let error = NativeQueryError {
            operation: QueryOperation::OpenKvm,
            raw_os_error: Some(13),
            kind: ErrorKind::PermissionDenied,
        };
        let mut facts = observed_kvm();
        facts.access = Observation::Unavailable(error);
        assert_eq!(
            reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts),
            KvmPrerequisites::Unavailable(error)
        );
        facts.access = Observation::Observed(());
        facts.api_version = Observation::Observed(11);
        assert_eq!(
            reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts),
            KvmPrerequisites::ApiMismatch {
                observed: 11,
                required: 12
            }
        );
        facts.api_version = Observation::Unavailable(NativeQueryError {
            operation: QueryOperation::KvmApiVersion,
            raw_os_error: Some(5),
            kind: ErrorKind::Other,
        });
        assert!(matches!(
            reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts),
            KvmPrerequisites::Unavailable(NativeQueryError {
                raw_os_error: Some(5),
                ..
            })
        ));
        facts.api_version = Observation::Observed(12);
        for value in [
            Observation::Observed(0),
            Observation::NotEvaluated,
            Observation::NotApplicable,
            Observation::Observed(-1),
        ] {
            facts.capabilities[6].value = value;
            let result = reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts);
            assert!(!matches!(result, KvmPrerequisites::SystemQueriesAvailable));
        }
        let error = NativeQueryError {
            operation: QueryOperation::KvmCheckExtension(KvmCapability::ImmediateExit),
            raw_os_error: Some(22),
            kind: ErrorKind::InvalidInput,
        };
        facts.capabilities[6].value = Observation::Unavailable(error);
        assert_eq!(
            reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts),
            KvmPrerequisites::Unavailable(error)
        );
    }

    #[test]
    fn native_live_kvm_reducer_refuses_partial_and_malformed_inventories() {
        let mut facts = observed_kvm();
        facts.access = Observation::NotEvaluated;
        assert_eq!(
            reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts),
            KvmPrerequisites::Incomplete
        );
        facts.access = Observation::Observed(());
        facts.api_version = Observation::NotEvaluated;
        assert_eq!(
            reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts),
            KvmPrerequisites::Incomplete
        );
        facts.api_version = Observation::Observed(12);
        facts.capabilities[0].capability = KvmCapability::ImmediateExit;
        assert_eq!(
            reduce_kvm_prerequisites(NativeLane::KvmX86_64, &facts),
            KvmPrerequisites::Incomplete
        );
        for capability in KVM_CAPABILITIES {
            let mut facts = observed_kvm();
            for fact in &mut facts.capabilities {
                if fact.capability == capability {
                    fact.value = Observation::Observed(0);
                }
            }
            let lane = if capability == KvmCapability::ArmPsci02 {
                NativeLane::KvmArm64GicV3
            } else {
                NativeLane::KvmX86_64
            };
            assert_eq!(
                reduce_kvm_prerequisites(lane, &facts),
                KvmPrerequisites::MissingCapability(capability)
            );
        }
    }

    #[test]
    fn native_live_hvf_symbol_presence_exhausts_both_independent_groups() {
        use crate::api::capabilities::{HvfGicSymbol, HvfGicSymbols, HvfSymbolGroup};
        let names = [
            "hv_gic_state_create",
            "hv_gic_state_get_size",
            "hv_gic_state_get_data",
            "hv_gic_set_state",
            "hv_gic_get_icc_reg",
            "hv_gic_set_icc_reg",
        ];
        for bits in 0_u8..64 {
            let presence = std::array::from_fn(|index| bits & (1 << index) != 0);
            let symbols = HvfGicSymbols::from_presence(presence);
            for (index, symbol) in HvfGicSymbol::ALL.into_iter().enumerate() {
                assert_eq!(symbol.name(), names[index]);
                assert_eq!(symbols.contains(symbol), presence[index]);
            }
            let expected = |mut range: std::ops::Range<usize>| {
                range
                    .find(|index| !presence[*index])
                    .map_or(HvfSymbolGroup::Available, |index| {
                        HvfSymbolGroup::Missing(HvfGicSymbol::ALL[index])
                    })
            };
            assert_eq!(symbols.blob_group(), expected(0..4));
            assert_eq!(symbols.icc_group(), expected(4..6));
        }
    }

    #[test]
    fn native_live_hvf_admission_exhausts_model_profile_provider_and_symbol_predicates() {
        use crate::api::capabilities::{
            HvfGicAdmission, HvfGicModel, HvfGicSymbol, HvfGicSymbols, HvfHostFacts, HvfVmFacts,
            reduce_hvf_gic_admission,
        };
        for bits in 0_u8..64 {
            let presence = std::array::from_fn(|index| bits & (1 << index) != 0);
            let symbols = HvfGicSymbols::from_presence(presence);
            let host = HvfHostFacts::from_symbols(symbols);
            assert_eq!(host.vm_admission, Observation::NotEvaluated);
            assert_eq!(host.gic_model, Observation::NotEvaluated);
            for lane in [
                NativeLane::Unsupported,
                NativeLane::KvmX86_64,
                NativeLane::KvmArm64GicV3,
                NativeLane::HvfArm64GicV3,
            ] {
                for model in [
                    Observation::NotEvaluated,
                    Observation::NotApplicable,
                    Observation::Observed(HvfGicModel::NativeGicV3),
                    Observation::Observed(HvfGicModel::UserspaceGicV3),
                ] {
                    for nested in [false, true] {
                        for providers in [false, true] {
                            let vm = HvfVmFacts {
                                gic_model: model,
                                nested,
                            };
                            let missing = HvfGicSymbol::ALL
                                .into_iter()
                                .find(|symbol| !symbols.contains(*symbol));
                            let expected = if lane != NativeLane::HvfArm64GicV3 {
                                HvfGicAdmission::NotApplicable
                            } else if let Some(symbol) = missing {
                                HvfGicAdmission::MissingSymbol(symbol)
                            } else {
                                match model {
                                    Observation::Observed(HvfGicModel::UserspaceGicV3) => {
                                        HvfGicAdmission::UserspaceGic
                                    }
                                    Observation::Observed(HvfGicModel::NativeGicV3) if nested => {
                                        HvfGicAdmission::NestedProfile
                                    }
                                    Observation::Observed(HvfGicModel::NativeGicV3)
                                        if !providers =>
                                    {
                                        HvfGicAdmission::ProvidersNotImplemented
                                    }
                                    Observation::Observed(HvfGicModel::NativeGicV3) => {
                                        HvfGicAdmission::PrerequisitesAvailable
                                    }
                                    _ => HvfGicAdmission::Incomplete,
                                }
                            };
                            assert_eq!(
                                reduce_hvf_gic_admission(lane, &host, vm, providers),
                                expected
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn native_live_hvf_admission_refuses_unknown_framework_and_partial_inventory() {
        use crate::api::capabilities::{
            HvfGicAdmission, HvfGicModel, HvfGicSymbols, HvfHostFacts, HvfVmFacts,
            reduce_hvf_gic_admission,
        };
        let vm = HvfVmFacts {
            gic_model: Observation::Observed(HvfGicModel::NativeGicV3),
            nested: false,
        };
        let lane = NativeLane::HvfArm64GicV3;
        let mut host = HvfHostFacts::not_queried(true);
        assert_eq!(
            reduce_hvf_gic_admission(lane, &host, vm, true),
            HvfGicAdmission::Incomplete
        );
        let error = NativeQueryError {
            operation: QueryOperation::LoadHvfFramework,
            raw_os_error: None,
            kind: ErrorKind::Other,
        };
        host.framework = Observation::Unavailable(error);
        assert_eq!(
            reduce_hvf_gic_admission(lane, &host, vm, true),
            HvfGicAdmission::FrameworkUnavailable(error)
        );
        host.framework = Observation::Observed(());
        assert_eq!(
            reduce_hvf_gic_admission(lane, &host, vm, true),
            HvfGicAdmission::Incomplete
        );
        host = HvfHostFacts::from_symbols(HvfGicSymbols::from_presence([true; 6]));
        host.gic_blob_symbols = Observation::NotEvaluated;
        assert_eq!(
            reduce_hvf_gic_admission(lane, &host, vm, true),
            HvfGicAdmission::Incomplete
        );
        host = HvfHostFacts::from_symbols(HvfGicSymbols::from_presence([true; 6]));
        host.gic_icc_symbols = Observation::NotEvaluated;
        assert_eq!(
            reduce_hvf_gic_admission(lane, &host, vm, true),
            HvfGicAdmission::Incomplete
        );
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    #[test]
    fn native_live_hvf_non_hvf_target_is_not_applicable_without_loading_framework() {
        use crate::api::capabilities::{HvfHostFacts, query_hvf};
        assert_eq!(query_hvf(), HvfHostFacts::not_queried(false));
    }
}
