//! Machine-less native observations. Neither build evidence nor system API access grants live operations.

use std::fmt::{self, Write};

mod current {
    include!(concat!(env!("OUT_DIR"), "/live_build.rs"));
}

pub const LIVE_QUERY_ABI: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeBackend {
    Kvm,
    Hvf,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeArchitecture {
    X86_64,
    Aarch64,
    Riscv64,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeLane {
    KvmX86_64,
    KvmArm64GicV3,
    HvfArm64GicV3,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorktreeState {
    Clean,
    Dirty,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceProvenance {
    pub root: Option<&'static str>,
    pub revision: Option<&'static str>,
    pub worktree: WorktreeState,
}

impl SourceProvenance {
    const fn observed(
        root: Option<&'static str>,
        revision: Option<&'static str>,
        clean: Option<bool>,
    ) -> Self {
        Self {
            root,
            revision,
            worktree: match clean {
                Some(true) => WorktreeState::Clean,
                Some(false) => WorktreeState::Dirty,
                None => WorktreeState::Unknown,
            },
        }
    }

    /// A Git-clean observation, not a qualification or content attestation of ignored build inputs.
    pub fn clean_revision(&self) -> Option<&'static str> {
        let revision = self.revision?;
        if self.worktree != WorktreeState::Clean
            || self.root.is_none_or(str::is_empty)
            || !matches!(revision.len(), 40 | 64)
            || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        Some(revision)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageBuildFacts {
    pub name: &'static str,
    pub version: &'static str,
    pub target: Option<&'static str>,
    /// Cargo's normalized CARGO_FEATURE_* identifiers, not inferred parent features.
    pub features: Option<&'static [&'static str]>,
    pub settings: &'static [(&'static str, Option<&'static str>)],
    pub settings_observed: bool,
    pub rustc_version: Option<&'static str>,
    pub source: SourceProvenance,
}

impl PackageBuildFacts {
    pub fn setting(&self, name: &str) -> Option<&'static str> {
        self.settings
            .iter()
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| *value)
    }

    /// Completeness of recorded binding inputs only. This never qualifies an operation.
    pub fn binding_complete(&self) -> bool {
        let Some(features) = self.features else {
            return false;
        };
        !self.name.is_empty()
            && !self.version.is_empty()
            && self.settings_observed
            && self.target.is_some_and(|target| !target.is_empty())
            && self
                .rustc_version
                .is_some_and(|version| !version.is_empty())
            && self.source.clean_revision().is_some()
            && features.iter().all(|feature| {
                feature.strip_prefix("CARGO_FEATURE_").is_some_and(|name| {
                    !name.is_empty()
                        && name.bytes().all(|byte| {
                            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                })
            })
            && features.windows(2).all(|pair| pair[0] < pair[1])
            && [
                "TARGET",
                "HOST",
                "OPT_LEVEL",
                "DEBUG",
                "PROFILE",
                "CARGO_CFG_TARGET_ARCH",
                "CARGO_CFG_TARGET_OS",
                "CARGO_CFG_TARGET_ENDIAN",
                "CARGO_CFG_TARGET_POINTER_WIDTH",
            ]
            .iter()
            .all(|name| self.setting(name).is_some_and(|value| !value.is_empty()))
            && [
                "CARGO_CFG_TARGET_ENV",
                "CARGO_CFG_TARGET_FEATURE",
                "CARGO_ENCODED_RUSTFLAGS",
            ]
            .iter()
            .all(|name| self.setting(name).is_some())
            && self.setting("TARGET") == self.target
            && self.settings.iter().enumerate().all(|(index, (key, _))| {
                self.settings[..index]
                    .iter()
                    .all(|(previous, _)| previous != key)
            })
    }

    /// Length-delimited observations for consumer-side hashing. Missing and empty differ.
    pub fn write_canonical(&self, output: &mut impl Write) -> fmt::Result {
        output.write_str("native-package-v1;")?;
        write_field(output, Some(self.name))?;
        write_field(output, Some(self.version))?;
        write_field(output, self.target)?;
        match self.features {
            Some(features) => {
                write!(output, "{};", features.len())?;
                for feature in features {
                    write_field(output, Some(feature))?;
                }
            }
            None => output.write_str("?;")?,
        }
        write!(output, "{};", self.settings.len())?;
        for (key, value) in self.settings {
            write_field(output, Some(key))?;
            write_field(output, *value)?;
        }
        output.write_str(if self.settings_observed {
            "observed;"
        } else {
            "partial;"
        })?;
        write_field(output, self.rustc_version)?;
        write_field(output, self.source.root)?;
        write_field(output, self.source.revision)?;
        output.write_str(match self.source.worktree {
            WorktreeState::Clean => "clean;",
            WorktreeState::Dirty => "dirty;",
            WorktreeState::Unknown => "unknown;",
        })
    }
}

fn write_field(output: &mut impl Write, value: Option<&str>) -> fmt::Result {
    match value {
        Some(value) => write!(output, "{}:{value};", value.len()),
        None => output.write_str("?;"),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NativeBuildFacts {
    pub query_abi: u32,
    pub control_abi: Option<u32>,
    pub backend: NativeBackend,
    pub architecture: NativeArchitecture,
    pub packages: &'static [PackageBuildFacts],
}

impl NativeBuildFacts {
    /// Optional native packages not yet instrumented cannot yield a complete binding.
    pub fn binding_complete(&self) -> bool {
        let required = [
            "libkrun",
            "krun-arch",
            "krun-arch-gen",
            "krun-devices",
            "krun-kernel",
            "krun-polly",
            "krun-utils",
            "krun-smbios",
        ];
        self.query_abi == LIVE_QUERY_ABI
            && self.backend != NativeBackend::Unsupported
            && self.architecture != NativeArchitecture::Unsupported
            && self.live_profile_included()
            && required.iter().all(|name| self.has_one_package(name))
            && (self.architecture != NativeArchitecture::X86_64
                || self.has_one_package("krun-cpuid"))
            && (self.backend != NativeBackend::Hvf || self.has_one_package("krun-hvf"))
            && self.packages.iter().enumerate().all(|(index, package)| {
                self.packages[..index]
                    .iter()
                    .all(|previous| previous.name != package.name)
            })
            && self
                .packages
                .iter()
                .all(PackageBuildFacts::binding_complete)
            && !self.packages.iter().any(|package| {
                package.features.is_some_and(|features| {
                    features.iter().any(|feature| {
                        matches!(
                            *feature,
                            "CARGO_FEATURE_GPU"
                                | "CARGO_FEATURE_INPUT"
                                | "CARGO_FEATURE_VHOST_USER"
                                | "CARGO_FEATURE_AWS_NITRO"
                                | "CARGO_FEATURE_KRUN_DISPLAY"
                                | "CARGO_FEATURE_KRUN_INPUT"
                        )
                    })
                })
            })
            && self.packages.iter().all(|package| {
                package.target == self.packages.first().and_then(|package| package.target)
            })
    }

    fn live_profile_included(&self) -> bool {
        !self.packages.is_empty()
            && self.packages.iter().all(|package| {
                package.features.is_some_and(|features| {
                    !features.iter().any(|feature| {
                        matches!(
                            *feature,
                            "CARGO_FEATURE_TEE"
                                | "CARGO_FEATURE_AMD_SEV"
                                | "CARGO_FEATURE_TDX"
                                | "CARGO_FEATURE_AWS_NITRO"
                                | "CARGO_FEATURE_NATIVE_CONTROL_PROBE"
                        )
                    })
                })
            })
    }

    fn has_one_package(&self, name: &str) -> bool {
        self.packages
            .iter()
            .filter(|package| package.name == name)
            .count()
            == 1
    }
}

macro_rules! package {
    ($module:path) => {{
        use $module as facts;
        PackageBuildFacts {
            name: facts::NAME,
            version: facts::VERSION,
            target: facts::TARGET,
            features: facts::FEATURES,
            settings: facts::SETTINGS,
            settings_observed: facts::SETTINGS_OBSERVED,
            rustc_version: facts::RUSTC_VERSION,
            source: SourceProvenance::observed(facts::SOURCE_ROOT, facts::REVISION, facts::CLEAN),
        }
    }};
}

static BUILD: NativeBuildFacts = NativeBuildFacts {
    query_abi: LIVE_QUERY_ABI,
    control_abi: Some(1),
    backend: if cfg!(target_os = "linux") {
        NativeBackend::Kvm
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        NativeBackend::Hvf
    } else {
        NativeBackend::Unsupported
    },
    architecture: if cfg!(target_arch = "x86_64") {
        NativeArchitecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        NativeArchitecture::Aarch64
    } else if cfg!(target_arch = "riscv64") {
        NativeArchitecture::Riscv64
    } else {
        NativeArchitecture::Unsupported
    },
    packages: &[
        package!(current),
        package!(arch::build_facts),
        package!(arch::build_facts::arch_gen),
        #[cfg(not(target_os = "windows"))]
        package!(arch::build_facts::smbios),
        #[cfg(target_arch = "x86_64")]
        package!(cpuid::build_facts),
        package!(devices::build_facts),
        #[cfg(target_os = "macos")]
        package!(hvf::build_facts),
        package!(kernel::build_facts),
        package!(polly::build_facts),
        package!(utils::build_facts),
    ],
};

pub fn compiled_live_build() -> &'static NativeBuildFacts {
    &BUILD
}

impl NativeLane {
    pub fn from_build(build: &NativeBuildFacts) -> Self {
        if !build.live_profile_included() {
            return Self::Unsupported;
        }
        match (build.backend, build.architecture) {
            (NativeBackend::Kvm, NativeArchitecture::X86_64) => Self::KvmX86_64,
            (NativeBackend::Kvm, NativeArchitecture::Aarch64) => Self::KvmArm64GicV3,
            (NativeBackend::Hvf, NativeArchitecture::Aarch64) => Self::HvfArm64GicV3,
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
    DeviceProvidersNotImplemented,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeLiveOperations {
    pub pause: NativeOperationSupport,
    pub capture: NativeOperationSupport,
    pub restore: NativeOperationSupport,
    pub fork: NativeOperationSupport,
    pub incremental: NativeOperationSupport,
}

impl NativeLiveOperations {
    pub const fn for_lane(lane: NativeLane) -> Self {
        let excluded = matches!(lane, NativeLane::Unsupported);
        let not_implemented = NativeOperationSupport::Unsupported(if excluded {
            NativeUnsupportedReason::BuildExcluded
        } else {
            NativeUnsupportedReason::NotImplemented
        });
        Self {
            pause: NativeOperationSupport::Unsupported(if excluded {
                NativeUnsupportedReason::BuildExcluded
            } else {
                NativeUnsupportedReason::DeviceProvidersNotImplemented
            }),
            capture: not_implemented,
            restore: not_implemented,
            fork: not_implemented,
            incremental: not_implemented,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NativeHostReport {
    pub build: &'static NativeBuildFacts,
    pub lane: NativeLane,
    pub kvm: KvmHostFacts,
    pub kvm_prerequisites: KvmPrerequisites,
    pub hvf: HvfHostFacts,
    pub operations: NativeLiveOperations,
}

/// Observes system APIs only, never constructing a VM, vCPU, GIC or guest workload.
pub fn query_live_host() -> NativeHostReport {
    let build = compiled_live_build();
    let lane = NativeLane::from_build(build);
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
        build,
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
        LIVE_QUERY_ABI, NativeArchitecture, NativeBackend, NativeBuildFacts, NativeLane,
        NativeLiveOperations, NativeOperationSupport, NativeQueryError, Observation,
        PackageBuildFacts, QueryOperation, SourceProvenance, WorktreeState, compiled_live_build,
        reduce_kvm_prerequisites,
    };
    use std::io::ErrorKind;

    const REVISION: &str = "58253c00580bda34f5ea9fc4e0fccaf1e09a83d4";
    const SOURCE: SourceProvenance = SourceProvenance {
        root: Some("/native"),
        revision: Some(REVISION),
        worktree: WorktreeState::Clean,
    };
    const COMPLETE_PACKAGE: PackageBuildFacts = PackageBuildFacts {
        name: "p",
        version: "v",
        target: Some("t"),
        features: Some(&[]),
        settings_observed: true,
        settings: &[
            ("TARGET", Some("t")),
            ("HOST", Some("h")),
            ("OPT_LEVEL", Some("2")),
            ("DEBUG", Some("false")),
            ("PROFILE", Some("release")),
            ("CARGO_CFG_TARGET_ARCH", Some("aarch64")),
            ("CARGO_CFG_TARGET_OS", Some("linux")),
            ("CARGO_CFG_TARGET_ENDIAN", Some("little")),
            ("CARGO_CFG_TARGET_POINTER_WIDTH", Some("64")),
            ("CARGO_CFG_TARGET_ENV", Some("")),
            ("CARGO_CFG_TARGET_FEATURE", Some("")),
            ("CARGO_ENCODED_RUSTFLAGS", Some("")),
        ],
        rustc_version: Some("rustc observed"),
        source: SOURCE,
    };

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
    fn native_live_source_provenance_refuses_dirty_partial_and_unknown() {
        assert_eq!(SOURCE.clean_revision(), Some(REVISION));
        for worktree in [WorktreeState::Dirty, WorktreeState::Unknown] {
            assert_eq!(
                SourceProvenance { worktree, ..SOURCE }.clean_revision(),
                None
            );
        }
        for revision in [
            None,
            Some(""),
            Some("58253c0"),
            Some("gggggggggggggggggggggggggggggggggggggggg"),
        ] {
            assert_eq!(
                SourceProvenance { revision, ..SOURCE }.clean_revision(),
                None
            );
        }
        assert_eq!(
            SourceProvenance {
                root: None,
                ..SOURCE
            }
            .clean_revision(),
            None
        );
        assert_eq!(
            SourceProvenance {
                root: Some(""),
                ..SOURCE
            }
            .clean_revision(),
            None
        );
    }

    #[test]
    fn native_live_package_serialization_preserves_exact_and_missing_facts() {
        let mut package = PackageBuildFacts {
            name: "p",
            version: "v",
            target: Some("t"),
            features: Some(&["CARGO_FEATURE_A"]),
            settings: &[
                ("flags", Some("a\u{1f}b")),
                ("unset", None),
                ("empty", Some("")),
            ],
            settings_observed: true,
            rustc_version: None,
            source: SourceProvenance {
                root: None,
                revision: None,
                worktree: WorktreeState::Unknown,
            },
        };
        let mut output = String::new();
        package.write_canonical(&mut output).unwrap();
        assert_eq!(
            output,
            "native-package-v1;1:p;1:v;1:t;1;15:CARGO_FEATURE_A;3;5:flags;3:a\u{1f}b;5:unset;?;5:empty;0:;observed;?;?;?;unknown;"
        );
        package.features = None;
        let mut unknown = String::new();
        package.write_canonical(&mut unknown).unwrap();
        package.features = Some(&[]);
        let mut empty = String::new();
        package.write_canonical(&mut empty).unwrap();
        assert_ne!(unknown, empty);
        assert!(!package.binding_complete());
    }

    #[test]
    fn native_live_package_binding_requires_every_recorded_prerequisite() {
        let complete = COMPLETE_PACKAGE;
        assert!(complete.binding_complete());
        for package in [
            PackageBuildFacts {
                target: None,
                ..complete
            },
            PackageBuildFacts {
                features: None,
                ..complete
            },
            PackageBuildFacts {
                rustc_version: None,
                ..complete
            },
            PackageBuildFacts {
                settings_observed: false,
                ..complete
            },
            PackageBuildFacts {
                settings: &[],
                ..complete
            },
            PackageBuildFacts {
                features: Some(&["CARGO_FEATURE_Z", "CARGO_FEATURE_A"]),
                ..complete
            },
            PackageBuildFacts {
                features: Some(&["CARGO_FEATURE_A", "CARGO_FEATURE_A"]),
                ..complete
            },
            PackageBuildFacts {
                features: Some(&[""]),
                ..complete
            },
            PackageBuildFacts {
                source: SourceProvenance {
                    worktree: WorktreeState::Dirty,
                    ..SOURCE
                },
                ..complete
            },
        ] {
            assert!(!package.binding_complete());
        }
    }

    const COMPLETE_PACKAGES: &[PackageBuildFacts] = &[
        PackageBuildFacts {
            name: "libkrun",
            ..COMPLETE_PACKAGE
        },
        PackageBuildFacts {
            name: "krun-arch",
            ..COMPLETE_PACKAGE
        },
        PackageBuildFacts {
            name: "krun-arch-gen",
            ..COMPLETE_PACKAGE
        },
        PackageBuildFacts {
            name: "krun-devices",
            ..COMPLETE_PACKAGE
        },
        PackageBuildFacts {
            name: "krun-kernel",
            ..COMPLETE_PACKAGE
        },
        PackageBuildFacts {
            name: "krun-polly",
            ..COMPLETE_PACKAGE
        },
        PackageBuildFacts {
            name: "krun-utils",
            ..COMPLETE_PACKAGE
        },
        PackageBuildFacts {
            name: "krun-smbios",
            ..COMPLETE_PACKAGE
        },
    ];

    #[test]
    fn native_live_build_binding_refuses_missing_packages_and_unobserved_optional_packages() {
        const PACKAGES: &[PackageBuildFacts] = COMPLETE_PACKAGES;
        let mut build = NativeBuildFacts {
            query_abi: LIVE_QUERY_ABI,
            control_abi: None,
            backend: NativeBackend::Kvm,
            architecture: NativeArchitecture::Aarch64,
            packages: PACKAGES,
        };
        assert!(build.binding_complete());
        build.query_abi = 0;
        assert!(!build.binding_complete());
        build.query_abi = LIVE_QUERY_ABI;
        build.packages = &[];
        assert!(!build.binding_complete());
        build.packages = &PACKAGES[..7];
        assert!(!build.binding_complete());
        build.packages = PACKAGES;
        build.architecture = NativeArchitecture::X86_64;
        assert!(!build.binding_complete());
        build.architecture = NativeArchitecture::Aarch64;
        build.backend = NativeBackend::Hvf;
        assert!(!build.binding_complete());
        build.backend = NativeBackend::Kvm;
        const GPU_PACKAGES: &[PackageBuildFacts] = &[
            PackageBuildFacts {
                features: Some(&["CARGO_FEATURE_GPU"]),
                ..PACKAGES[0]
            },
            PACKAGES[1],
            PACKAGES[2],
            PACKAGES[3],
            PACKAGES[4],
            PACKAGES[5],
            PACKAGES[6],
            PACKAGES[7],
        ];
        build.packages = GPU_PACKAGES;
        assert!(!build.binding_complete());
    }

    #[test]
    fn native_live_compiled_facts_are_static_and_package_local() {
        let build = compiled_live_build();
        assert!(std::ptr::eq(build, compiled_live_build()));
        assert_eq!(build.query_abi, LIVE_QUERY_ABI);
        assert_eq!(build.query_abi, 1);
        assert_eq!(build.control_abi, Some(1));
        assert_eq!(
            build.packages.first().map(|package| package.name),
            Some("libkrun")
        );
        for package in build.packages {
            if let Some(features) = package.features {
                assert!(features.windows(2).all(|pair| pair[0] < pair[1]));
            }
        }
        let devices = build
            .packages
            .iter()
            .find(|package| package.name == "krun-devices")
            .unwrap();
        assert!(
            devices
                .features
                .unwrap()
                .contains(&"CARGO_FEATURE_TEST_UTILS")
        );
        assert!(
            !build.packages[0]
                .features
                .unwrap()
                .contains(&"CARGO_FEATURE_TEST_UTILS")
        );
    }

    #[test]
    fn native_live_operations_remain_false_for_every_lane_and_host_outcome() {
        for lane in [
            NativeLane::KvmX86_64,
            NativeLane::KvmArm64GicV3,
            NativeLane::HvfArm64GicV3,
            NativeLane::Unsupported,
        ] {
            let operations = NativeLiveOperations::for_lane(lane);
            for operation in [
                operations.pause,
                operations.capture,
                operations.restore,
                operations.fork,
                operations.incremental,
            ] {
                assert!(matches!(operation, NativeOperationSupport::Unsupported(_)));
                assert!(!operation.is_supported());
            }
        }
        let mut build = NativeBuildFacts {
            query_abi: LIVE_QUERY_ABI,
            control_abi: None,
            backend: NativeBackend::Hvf,
            architecture: NativeArchitecture::X86_64,
            packages: &[COMPLETE_PACKAGE],
        };
        assert_eq!(NativeLane::from_build(&build), NativeLane::Unsupported);
        build.backend = NativeBackend::Kvm;
        build.architecture = NativeArchitecture::Riscv64;
        assert_eq!(NativeLane::from_build(&build), NativeLane::Unsupported);
    }

    #[test]
    fn native_live_compiled_profiles_exclude_tee_nitro_and_unknown_features_without_host_queries() {
        macro_rules! profile_packages {
            ($features:expr) => {
                &[
                    COMPLETE_PACKAGES[0],
                    COMPLETE_PACKAGES[1],
                    COMPLETE_PACKAGES[2],
                    PackageBuildFacts {
                        features: $features,
                        ..COMPLETE_PACKAGES[3]
                    },
                    COMPLETE_PACKAGES[4],
                    COMPLETE_PACKAGES[5],
                    COMPLETE_PACKAGES[6],
                    COMPLETE_PACKAGES[7],
                ]
            };
        }
        const PROFILES: &[&[PackageBuildFacts]] = &[
            profile_packages!(Some(&["CARGO_FEATURE_TEE"])),
            profile_packages!(Some(&["CARGO_FEATURE_AMD_SEV"])),
            profile_packages!(Some(&["CARGO_FEATURE_TDX"])),
            profile_packages!(Some(&["CARGO_FEATURE_AWS_NITRO"])),
            profile_packages!(Some(&["CARGO_FEATURE_NATIVE_CONTROL_PROBE"])),
            profile_packages!(None),
        ];
        for packages in PROFILES {
            for (backend, architecture) in [
                (NativeBackend::Kvm, NativeArchitecture::X86_64),
                (NativeBackend::Kvm, NativeArchitecture::Aarch64),
                (NativeBackend::Hvf, NativeArchitecture::Aarch64),
            ] {
                let build = NativeBuildFacts {
                    query_abi: LIVE_QUERY_ABI,
                    control_abi: None,
                    backend,
                    architecture,
                    packages,
                };
                assert!(!build.live_profile_included());
                assert!(!build.binding_complete());
                let lane = NativeLane::from_build(&build);
                assert_eq!(lane, NativeLane::Unsupported);
                assert!(!lane.queries_kvm());
                let operations = NativeLiveOperations::for_lane(lane);
                for operation in [
                    operations.pause,
                    operations.capture,
                    operations.restore,
                    operations.fork,
                    operations.incremental,
                ] {
                    assert!(!operation.is_supported());
                }
            }
        }
        let build = NativeBuildFacts {
            query_abi: LIVE_QUERY_ABI,
            control_abi: None,
            backend: NativeBackend::Kvm,
            architecture: NativeArchitecture::Aarch64,
            packages: COMPLETE_PACKAGES,
        };
        assert!(build.live_profile_included());
        assert!(build.binding_complete());
        assert_eq!(NativeLane::from_build(&build), NativeLane::KvmArm64GicV3);
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
                            let operations = NativeLiveOperations::for_lane(lane);
                            assert!(!operations.pause.is_supported());
                            assert!(!operations.capture.is_supported());
                            assert!(!operations.restore.is_supported());
                            assert!(!operations.fork.is_supported());
                            assert!(!operations.incremental.is_supported());
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
