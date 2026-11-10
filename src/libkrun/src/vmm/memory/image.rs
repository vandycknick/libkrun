use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;
use std::time::Instant;

use arch::ArchMemoryInfo;
use arch::guest_memory::{
    BackingKind, ConstructionAuthority, DirtyPageMap, DomainControl, MemoryCut, MemoryDomain,
    MemoryError, TopologyGeneration, TrackingMode,
};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use vm_memory::{FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use crate::vmm::control::BarrierKey;
use crate::vmm::execution::{StateBinding, ValidatedExecution};
use crate::vmm::memory::AttemptId;
use crate::vmm::memory::image::layout::{MAX_RAM_LAYOUT_BYTES, RamTopology};

pub mod layout;
pub mod writer;

pub const RAM_IO_BUFFER_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const RAM_IO_BUFFER_COUNT: usize = 3;
pub const RAM_IDENTITY_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamRegion {
    pub guest_start: u64,
    pub length: u64,
    pub stream_offset: u64,
    pub first_page: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedRamLayout {
    regions: Box<[RamRegion]>,
    granule: u32,
    packed_len: u64,
    topology: RamTopology,
    canonical: Box<[u8]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamFileRole {
    OutputRam,
    OutputLayout,
    InputRam,
    InputLayout,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorProblem {
    NotRegular,
    WrongAccess,
    Append,
    PathOnly,
    DirectIo,
    Length,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedRamRole {
    OtherOutput,
    BaselineRam,
    BaselineLayout,
    MappedBacking,
    OtherInput,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamIoOperation {
    Metadata,
    Flags,
    Read,
    Write,
    Extent,
    SetLength,
}

#[derive(Debug, thiserror::Error)]
pub enum RamImageError {
    #[error("RAM layout codec: {0}")]
    Codec(#[from] utils::state::Error),
    #[error("invalid RAM geometry")]
    Geometry,
    #[error("invalid RAM topology")]
    Topology,
    #[error("RAM execution binding mismatch")]
    ExecutionBinding,
    #[error("invalid RAM descriptor {role:?}: {problem:?}")]
    DescriptorRole {
        role: RamFileRole,
        problem: DescriptorProblem,
    },
    #[error("RAM output {output:?} aliases {protected:?}")]
    Alias {
        output: RamFileRole,
        protected: ProtectedRamRole,
    },
    #[error("RAM authority: {0}")]
    Authority(#[from] MemoryError),
    #[error("RAM access: {0}")]
    GuestMemory(#[from] vm_memory::GuestMemoryError),
    #[error("invalid dirty bitmap")]
    Bitmap,
    #[error("RAM completion does not match")]
    Completion,
    #[error("RAM image deadline expired")]
    Deadline,
    #[error("RAM image allocation failed")]
    Allocation,
    #[error("RAM capture pipeline: {0}")]
    Pipeline(io::Error),
    #[error("RAM {operation:?} on {role:?}: {source}")]
    Io {
        operation: RamIoOperation,
        role: RamFileRole,
        source: io::Error,
    },
    #[error("RAM mapping: {0}")]
    Mapping(vm_memory::mmap::MmapRegionError),
    #[error("RAM collection: {0}")]
    Collection(vm_memory::GuestRegionCollectionError),
}

pub(crate) fn io_error(
    operation: RamIoOperation,
    role: RamFileRole,
    source: io::Error,
) -> RamImageError {
    RamImageError::Io {
        operation,
        role,
        source,
    }
}
pub(crate) fn check_deadline(deadline: Instant) -> Result<(), RamImageError> {
    if Instant::now() >= deadline {
        Err(RamImageError::Deadline)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RamSeedMethod {
    Clone,
    #[default]
    Rebuild,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RamIoStats {
    pub seed_method: RamSeedMethod,
    pub logical_bytes: u64,
    pub live_bytes_read: u64,
    pub baseline_bytes_read: u64,
    pub baseline_bytes_written: u64,
    pub overlay_bytes_written: u64,
    pub full_bytes_written: u64,
    pub layout_bytes_written: u64,
    pub baseline_hole_bytes: u64,
    pub zero_bytes_omitted: u64,
    pub explicit_zero_bytes_written: u64,
    pub extent_queries: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamCaptureMode {
    Full,
    Incremental,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamImageEffects {
    None,
    Started,
}

#[derive(Debug)]
pub struct RamOutputFiles {
    ram: File,
    layout: File,
    protected_inputs: Option<Arc<AuthenticatedRamImage>>,
}
impl RamOutputFiles {
    /// Takes ownership without effects. Open staging roles without truncation so
    /// inode alias preflight can protect existing inputs.
    /// Completion closes the writers; the caller owns the later durability barrier.
    pub fn new(ram: File, layout: File) -> Self {
        Self {
            ram,
            layout,
            protected_inputs: None,
        }
    }
    pub(super) fn protect_baseline(&mut self, baseline: Option<Arc<AuthenticatedRamImage>>) {
        self.protected_inputs = baseline;
    }
}

#[derive(Debug)]
pub struct RamImageFailure {
    pub error: RamImageError,
    pub stats: RamIoStats,
    pub output: RamOutputFiles,
    pub effects: RamImageEffects,
}
impl fmt::Display for RamImageFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.error, self.effects)
    }
}
impl std::error::Error for RamImageFailure {}

pub struct RamIoScratch {
    buffers: [Box<[u8]>; RAM_IO_BUFFER_COUNT],
}
impl RamIoScratch {
    pub fn new() -> Result<Self, RamImageError> {
        fn allocate() -> Result<Box<[u8]>, RamImageError> {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(RAM_IO_BUFFER_BYTES)
                .map_err(|_| RamImageError::Allocation)?;
            buffer.resize(RAM_IO_BUFFER_BYTES, 0);
            Ok(buffer.into_boxed_slice())
        }
        Ok(Self {
            buffers: [allocate()?, allocate()?, allocate()?],
        })
    }
}

/// The trusted caller authenticates imported bytes and excludes all writers.
/// `stream` is the ADR0014 StreamId, not a whole-file digest. Native capture
/// supplies chunk digests, but does not establish immutability from readonly
/// descriptor metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamImageAuthentication {
    pub state: StateBinding,
    pub stream: [u8; 32],
}

pub enum RamWriteMode<'a> {
    Full,
    Incremental {
        baseline: &'a AuthenticatedRamImage,
        dirty: &'a DirtyPageMap,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileFact {
    identity: FileIdentity,
    length: u64,
}

#[derive(Debug)]
pub struct AuthenticatedRamImage {
    ram: Arc<File>,
    layout_file: Arc<File>,
    layout: Arc<ValidatedRamLayout>,
    authentication: RamImageAuthentication,
    ram_fact: FileFact,
    layout_fact: FileFact,
    completion: Option<Arc<()>>,
}
impl AuthenticatedRamImage {
    pub fn for_restore(
        ram: File,
        layout: File,
        auth: RamImageAuthentication,
        execution: &ValidatedExecution,
    ) -> Result<Self, RamImageError> {
        auth.state.validate()?;
        if auth.state != execution.envelope().binding {
            return Err(RamImageError::ExecutionBinding);
        }
        let ram_fact = inspect(&ram, RamFileRole::InputRam)?;
        let layout_fact = inspect(&layout, RamFileRole::InputLayout)?;
        distinct_inputs(ram_fact, layout_fact)?;
        let bytes = read_layout(&layout, layout_fact.length)?;
        let validated = Arc::new(ValidatedRamLayout::decode(&bytes)?);
        validated.validate_execution(execution)?;
        exact_length(ram_fact, validated.packed_len(), RamFileRole::InputRam)?;
        Ok(Self {
            ram: Arc::new(ram),
            layout_file: Arc::new(layout),
            layout: validated,
            authentication: auth,
            ram_fact,
            layout_fact,
            completion: None,
        })
    }
    pub fn layout(&self) -> &Arc<ValidatedRamLayout> {
        &self.layout
    }
    pub fn authentication(&self) -> &RamImageAuthentication {
        &self.authentication
    }
    pub(crate) fn aliases(&self, device: u64, inode: u64) -> bool {
        [self.ram_fact.identity, self.layout_fact.identity]
            .iter()
            .any(|identity| identity.device == device && identity.inode == inode)
    }
    fn recheck(&self) -> Result<(), RamImageError> {
        self.recheck_before(None)
    }
    fn recheck_before(&self, deadline: Option<Instant>) -> Result<(), RamImageError> {
        let ram = inspect_before(&self.ram, RamFileRole::InputRam, deadline)?;
        let layout = inspect_before(&self.layout_file, RamFileRole::InputLayout, deadline)?;
        if ram != self.ram_fact || layout != self.layout_fact {
            return Err(RamImageError::Completion);
        }
        distinct_inputs(ram, layout)?;
        compare_layout_before(
            &self.layout_file,
            layout.length,
            self.layout.canonical_bytes(),
            RamFileRole::InputLayout,
            deadline,
        )
    }
}

pub(crate) struct ReceiptPreparation {
    binding: StateBinding,
    completion: Arc<()>,
}

pub struct RamCaptureReceipt {
    attempt: AttemptId,
    key: BarrierKey,
    domain: Arc<MemoryDomain>,
    cut_generation: u64,
    topology_generation: TopologyGeneration,
    binding: StateBinding,
    layout: Arc<ValidatedRamLayout>,
    ram_fact: FileFact,
    layout_fact: FileFact,
    mode: RamCaptureMode,
    stats: RamIoStats,
    chunks: Vec<u64>,
    chunk_digests: Vec<Option<[u8; 32]>>,
    completion: Arc<()>,
    writers_closed: bool,
}
impl fmt::Debug for RamCaptureReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RamCaptureReceipt")
            .field("attempt", &self.attempt)
            .field("cut_generation", &self.cut_generation)
            .field("mode", &self.mode)
            .field("stats", &self.stats)
            .field("writers_closed", &self.writers_closed)
            .finish()
    }
}
impl RamCaptureReceipt {
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub(crate) fn completed(
        preparation: ReceiptPreparation,
        attempt: AttemptId,
        key: BarrierKey,
        cut: &MemoryCut,
        binding: &StateBinding,
        layout: Arc<ValidatedRamLayout>,
        mode: RamCaptureMode,
        output: RamOutputFiles,
        stats: RamIoStats,
        chunks: Vec<u64>,
        chunk_digests: Vec<Option<[u8; 32]>>,
        deadline: Instant,
    ) -> Result<Self, (RamImageError, RamOutputFiles)> {
        let facts = (|| {
            check_deadline(deadline)?;
            cut.validate_domain(cut.domain())?;
            layout.validate_registered(cut.domain().layout())?;
            if preparation.binding != *binding {
                return Err(RamImageError::Completion);
            }
            let ram = inspect_before(&output.ram, RamFileRole::OutputRam, Some(deadline))?;
            let record = inspect_before(&output.layout, RamFileRole::OutputLayout, Some(deadline))?;
            exact_length(ram, layout.packed_len(), RamFileRole::OutputRam)?;
            compare_layout_before(
                &output.layout,
                record.length,
                layout.canonical_bytes(),
                RamFileRole::OutputLayout,
                Some(deadline),
            )?;
            check_deadline(deadline)?;
            Ok((ram, record))
        })();
        let (ram_fact, layout_fact) = match facts {
            Ok(facts) => facts,
            Err(error) => return Err((error, output)),
        };
        drop(output);
        Ok(Self {
            attempt,
            key,
            domain: cut.domain().clone(),
            cut_generation: cut.generation(),
            topology_generation: cut.domain().topology_generation(),
            binding: preparation.binding,
            layout,
            ram_fact,
            layout_fact,
            mode,
            stats,
            chunks,
            chunk_digests,
            completion: preparation.completion,
            writers_closed: true,
        })
    }
    pub fn output_identities(&self) -> [(u64, u64, u64); 2] {
        [self.ram_fact, self.layout_fact]
            .map(|fact| (fact.identity.device, fact.identity.inode, fact.length))
    }
    pub fn binding(&self) -> &StateBinding {
        &self.binding
    }
    pub fn writers_closed(&self) -> bool {
        self.writers_closed
    }
    pub fn stats(&self) -> &RamIoStats {
        &self.stats
    }
    pub fn layout(&self) -> &Arc<ValidatedRamLayout> {
        &self.layout
    }
    pub fn packed_len(&self) -> u64 {
        self.layout.packed_len()
    }
    pub fn mode(&self) -> RamCaptureMode {
        self.mode
    }
    pub fn attempt(&self) -> &AttemptId {
        &self.attempt
    }
    pub fn affected_chunks(&self) -> impl Iterator<Item = usize> + '_ {
        self.chunks
            .iter()
            .enumerate()
            .flat_map(|(word_index, word)| {
                let mut bits = *word;
                std::iter::from_fn(move || {
                    if bits == 0 {
                        return None;
                    }
                    let bit = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    Some(word_index * 64 + bit)
                })
            })
    }
    /// One digest per 8 MiB logical chunk; `None` denotes all zeros only when
    /// the corresponding affected-chunk bit is set. Unaffected entries are `None`.
    pub fn chunk_digests(&self) -> &[Option<[u8; 32]>] {
        &self.chunk_digests
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matches(
        &self,
        attempt: &AttemptId,
        key: BarrierKey,
        cut: &MemoryCut,
        binding: &StateBinding,
        layout: &ValidatedRamLayout,
        image: &AuthenticatedRamImage,
    ) -> Result<(), RamImageError> {
        cut.validate_domain(&self.domain)?;
        let origin = image.completion.as_ref().ok_or(RamImageError::Completion)?;
        if !self.writers_closed
            || self.attempt != *attempt
            || self.key != key
            || self.cut_generation != cut.generation()
            || self.topology_generation != cut.domain().topology_generation()
            || self.binding != *binding
            || self.binding != image.authentication.state
            || self.layout.as_ref() != layout
            || self.layout.as_ref() != image.layout.as_ref()
            || self.ram_fact != image.ram_fact
            || self.layout_fact != image.layout_fact
            || !Arc::ptr_eq(&self.completion, origin)
        {
            return Err(RamImageError::Completion);
        }
        image.recheck()
    }
}

pub fn seal_completed(
    receipt: &RamCaptureReceipt,
    ram: File,
    layout: File,
    auth: RamImageAuthentication,
) -> Result<AuthenticatedRamImage, RamImageError> {
    if !receipt.writers_closed {
        return Err(RamImageError::Completion);
    }
    auth.state.validate()?;
    if auth.state != receipt.binding {
        return Err(RamImageError::Completion);
    }
    let ram_fact = inspect(&ram, RamFileRole::InputRam)?;
    let layout_fact = inspect(&layout, RamFileRole::InputLayout)?;
    distinct_inputs(ram_fact, layout_fact)?;
    if ram_fact != receipt.ram_fact || layout_fact != receipt.layout_fact {
        return Err(RamImageError::Completion);
    }
    compare_layout(
        &layout,
        layout_fact.length,
        receipt.layout.canonical_bytes(),
    )?;
    let image = AuthenticatedRamImage {
        ram: Arc::new(ram),
        layout_file: Arc::new(layout),
        layout: receipt.layout.clone(),
        authentication: auth,
        ram_fact,
        layout_fact,
        completion: Some(receipt.completion.clone()),
    };
    Ok(image)
}

pub struct RestoredRam {
    domain: Arc<MemoryDomain>,
    construction: ConstructionAuthority,
    control: DomainControl,
    baseline: Arc<AuthenticatedRamImage>,
    info: ArchMemoryInfo,
}
type RestoredRamParts = (
    Arc<MemoryDomain>,
    ConstructionAuthority,
    DomainControl,
    Arc<AuthenticatedRamImage>,
    ArchMemoryInfo,
);
impl RestoredRam {
    pub fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub(crate) fn into_parts(
        self,
        execution: &ValidatedExecution,
    ) -> Result<RestoredRamParts, RamImageError> {
        if self.baseline.authentication.state != execution.envelope().binding {
            return Err(RamImageError::ExecutionBinding);
        }
        self.baseline.layout.validate_execution(execution)?;
        Ok((
            self.domain,
            self.construction,
            self.control,
            self.baseline,
            self.info,
        ))
    }
}

pub fn map_restore_ram(
    image: Arc<AuthenticatedRamImage>,
    execution: &ValidatedExecution,
) -> Result<RestoredRam, RamImageError> {
    image.recheck()?;
    if image.authentication.state != execution.envelope().binding {
        return Err(RamImageError::ExecutionBinding);
    }
    image.layout.validate_execution(execution)?;
    let info = image.layout.arch_info()?;
    let mut regions = Vec::new();
    regions
        .try_reserve_exact(image.layout.regions().len())
        .map_err(|_| RamImageError::Allocation)?;
    for region in image.layout.regions() {
        let offset = FileOffset::from_arc(image.ram.clone(), region.stream_offset);
        let len = usize::try_from(region.length).map_err(|_| RamImageError::Geometry)?;
        let mapping = MmapRegion::<()>::build(
            Some(offset),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
        )
        .map_err(RamImageError::Mapping)?;
        regions.push(
            GuestRegionMmap::new(mapping, GuestAddress(region.guest_start))
                .ok_or(RamImageError::Geometry)?,
        );
    }
    let memory = GuestMemoryMmap::from_regions(regions).map_err(RamImageError::Collection)?;
    let (domain, construction, control) =
        MemoryDomain::construct(memory, image.layout.granule(), BackingKind::RestoredPrivate)?;
    image.layout.validate_registered(domain.layout())?;
    Ok(RestoredRam {
        domain,
        construction,
        control,
        baseline: image,
        info,
    })
}

pub(crate) fn allocate_chunks(layout: &ValidatedRamLayout) -> Result<Vec<u64>, RamImageError> {
    let count = usize::try_from(
        layout
            .packed_len()
            .div_ceil(RAM_IDENTITY_CHUNK_BYTES)
            .div_ceil(64),
    )
    .map_err(|_| RamImageError::Geometry)?;
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(count)
        .map_err(|_| RamImageError::Allocation)?;
    chunks.resize(count, 0);
    Ok(chunks)
}

pub(crate) fn preflight(
    cut: &MemoryCut,
    binding: &StateBinding,
    layout: &ValidatedRamLayout,
    mode: &RamWriteMode<'_>,
    output: &RamOutputFiles,
    deadline: Instant,
) -> Result<ReceiptPreparation, RamImageError> {
    check_deadline(deadline)?;
    binding.validate()?;
    cut.validate_domain(cut.domain())?;
    if cut.domain().tracking_mode() != Some(TrackingMode::Capture) {
        return Err(RamImageError::Authority(MemoryError::State));
    }
    layout.validate_registered(cut.domain().layout())?;
    let ram = inspect_before(&output.ram, RamFileRole::OutputRam, Some(deadline))?;
    let record = inspect_before(&output.layout, RamFileRole::OutputLayout, Some(deadline))?;
    if ram.identity == record.identity {
        return Err(RamImageError::Alias {
            output: RamFileRole::OutputRam,
            protected: ProtectedRamRole::OtherOutput,
        });
    }
    if let Some(baseline) = &output.protected_inputs {
        baseline.recheck_before(Some(deadline))?;
        for (role, fact) in [
            (RamFileRole::OutputRam, ram),
            (RamFileRole::OutputLayout, record),
        ] {
            for (protected, input) in [
                (ProtectedRamRole::BaselineRam, baseline.ram_fact),
                (ProtectedRamRole::BaselineLayout, baseline.layout_fact),
            ] {
                if fact.identity == input.identity {
                    return Err(RamImageError::Alias {
                        output: role,
                        protected,
                    });
                }
            }
        }
    }
    let mut backings = cut.domain().file_backing_identities();
    loop {
        check_deadline(deadline)?;
        let Some(backing) = backings.next() else {
            break;
        };
        let backing =
            backing.map_err(|e| io_error(RamIoOperation::Metadata, RamFileRole::InputRam, e))?;
        for (role, fact) in [
            (RamFileRole::OutputRam, ram),
            (RamFileRole::OutputLayout, record),
        ] {
            if fact.identity.device == backing.device && fact.identity.inode == backing.inode {
                return Err(RamImageError::Alias {
                    output: role,
                    protected: ProtectedRamRole::MappedBacking,
                });
            }
        }
    }
    if let RamWriteMode::Incremental { baseline, dirty } = mode {
        if !output
            .protected_inputs
            .as_ref()
            .is_some_and(|protected| std::ptr::eq(protected.as_ref(), *baseline))
        {
            return Err(RamImageError::Completion);
        }
        if baseline.layout.as_ref() != layout
            || baseline.authentication.state.ram_layout != binding.ram_layout
        {
            return Err(RamImageError::ExecutionBinding);
        }
        if dirty.page_count() != cut.domain().layout().page_count() {
            return Err(RamImageError::Bitmap);
        }
        if !cut.domain().coverage_valid() {
            return Err(RamImageError::Authority(MemoryError::CoverageLost));
        }
    }
    let mut live_state_schema = String::new();
    live_state_schema
        .try_reserve_exact(binding.live_state_schema.len())
        .map_err(|_| RamImageError::Allocation)?;
    live_state_schema.push_str(&binding.live_state_schema);
    let mut architecture = String::new();
    architecture
        .try_reserve_exact(binding.architecture.len())
        .map_err(|_| RamImageError::Allocation)?;
    architecture.push_str(&binding.architecture);
    let retained_binding = StateBinding {
        live_state_schema,
        architecture,
        profile: binding.profile,
        topology: binding.topology,
        ram_layout: binding.ram_layout,
        source_run: binding.source_run,
        pause_generation: binding.pause_generation,
        capture: binding.capture,
    };
    check_deadline(deadline)?;
    Ok(ReceiptPreparation {
        binding: retained_binding,
        completion: Arc::new(()),
    })
}

fn inspect(file: &File, role: RamFileRole) -> Result<FileFact, RamImageError> {
    inspect_before(file, role, None)
}
fn inspect_before(
    file: &File,
    role: RamFileRole,
    deadline: Option<Instant>,
) -> Result<FileFact, RamImageError> {
    if let Some(deadline) = deadline {
        check_deadline(deadline)?;
    }
    let metadata = file
        .metadata()
        .map_err(|e| io_error(RamIoOperation::Metadata, role, e))?;
    if !metadata.is_file() {
        return Err(RamImageError::DescriptorRole {
            role,
            problem: DescriptorProblem::NotRegular,
        });
    }
    if let Some(deadline) = deadline {
        check_deadline(deadline)?;
    }
    let raw_flags = fcntl(file, FcntlArg::F_GETFL).map_err(|e| {
        io_error(
            RamIoOperation::Flags,
            role,
            io::Error::from_raw_os_error(e as i32),
        )
    })?;
    let flags = OFlag::from_bits_retain(raw_flags);
    #[cfg(target_os = "linux")]
    if flags.contains(OFlag::O_PATH) {
        return Err(RamImageError::DescriptorRole {
            role,
            problem: DescriptorProblem::PathOnly,
        });
    }
    #[cfg(target_os = "linux")]
    if flags.contains(OFlag::O_DIRECT) {
        return Err(RamImageError::DescriptorRole {
            role,
            problem: DescriptorProblem::DirectIo,
        });
    }
    if flags.contains(OFlag::O_APPEND) {
        return Err(RamImageError::DescriptorRole {
            role,
            problem: DescriptorProblem::Append,
        });
    }
    let expected = if matches!(role, RamFileRole::OutputRam | RamFileRole::OutputLayout) {
        OFlag::O_RDWR
    } else {
        OFlag::O_RDONLY
    };
    if flags & OFlag::O_ACCMODE != expected {
        return Err(RamImageError::DescriptorRole {
            role,
            problem: DescriptorProblem::WrongAccess,
        });
    }
    Ok(FileFact {
        identity: FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        length: metadata.len(),
    })
}
fn distinct_inputs(ram: FileFact, layout: FileFact) -> Result<(), RamImageError> {
    if ram.identity == layout.identity {
        return Err(RamImageError::Alias {
            output: RamFileRole::InputRam,
            protected: ProtectedRamRole::OtherInput,
        });
    }
    Ok(())
}
fn exact_length(fact: FileFact, expected: u64, role: RamFileRole) -> Result<(), RamImageError> {
    if fact.length != expected {
        return Err(RamImageError::DescriptorRole {
            role,
            problem: DescriptorProblem::Length,
        });
    }
    Ok(())
}
fn read_layout(file: &File, length: u64) -> Result<Box<[u8]>, RamImageError> {
    let length =
        usize::try_from(length).map_err(|_| RamImageError::Codec(utils::state::Error::Limit))?;
    if length == 0 || length > MAX_RAM_LAYOUT_BYTES {
        return Err(RamImageError::Codec(utils::state::Error::Limit));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| RamImageError::Allocation)?;
    bytes.resize(length, 0);
    read_exact_at(file, &mut bytes, 0)?;
    Ok(bytes.into_boxed_slice())
}
fn compare_layout(file: &File, length: u64, expected: &[u8]) -> Result<(), RamImageError> {
    compare_layout_before(file, length, expected, RamFileRole::InputLayout, None)
}
fn compare_layout_before(
    file: &File,
    length: u64,
    expected: &[u8],
    role: RamFileRole,
    deadline: Option<Instant>,
) -> Result<(), RamImageError> {
    if length != expected.len() as u64 {
        return Err(RamImageError::Completion);
    }
    let mut scratch = [0u8; 4096];
    let mut offset = 0usize;
    while offset < expected.len() {
        let count = scratch.len().min(expected.len() - offset);
        read_exact_at_before(file, &mut scratch[..count], offset as u64, role, deadline)?;
        if scratch[..count] != expected[offset..offset + count] {
            return Err(RamImageError::Completion);
        }
        offset += count;
    }
    Ok(())
}
fn read_exact_at(file: &File, bytes: &mut [u8], offset: u64) -> Result<(), RamImageError> {
    read_exact_at_before(file, bytes, offset, RamFileRole::InputLayout, None)
}
fn read_exact_at_before(
    file: &File,
    mut bytes: &mut [u8],
    mut offset: u64,
    role: RamFileRole,
    deadline: Option<Instant>,
) -> Result<(), RamImageError> {
    while !bytes.is_empty() {
        if let Some(deadline) = deadline {
            check_deadline(deadline)?;
        }
        match file.read_at(bytes, offset) {
            Ok(0) => {
                return Err(io_error(
                    RamIoOperation::Read,
                    role,
                    io::Error::from(io::ErrorKind::UnexpectedEof),
                ));
            }
            Ok(count) => {
                offset = offset
                    .checked_add(count as u64)
                    .ok_or(RamImageError::Geometry)?;
                bytes = &mut bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error(RamIoOperation::Read, role, error)),
        }
    }
    Ok(())
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use arch::ArchMemoryInfo;
    use arch::guest_memory::{BackingKind, DomainControl, GuestRange, MemoryCut, MemoryDomain};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

    use crate::vmm::control::{BarrierGeneration, BarrierKey, OperationId};
    use crate::vmm::execution::{
        CpuExecutionState, CpuIdentity, ExecutionEnvelope, ExecutionLane, StateBinding,
        ValidatedExecution, VmExecutionState, host_page_granule, kvm,
    };
    use crate::vmm::memory::AttemptId;
    use crate::vmm::memory::image::writer::write_ram_image;
    use crate::vmm::memory::image::{
        AuthenticatedRamImage, DescriptorProblem, ProtectedRamRole, RamCaptureMode,
        RamCaptureReceipt, RamFileRole, RamImageAuthentication, RamImageEffects, RamImageError,
        RamIoScratch, RamOutputFiles, RamWriteMode, ValidatedRamLayout, inspect, map_restore_ram,
        preflight, seal_completed,
    };

    struct Files(PathBuf);
    impl Files {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("krun-ram-image-{}-{unique}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn create(&self, name: &str, bytes: &[u8]) -> File {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(self.path(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file
        }
        fn readonly(&self, name: &str) -> File {
            File::open(self.path(name)).unwrap()
        }
        fn writable(&self, name: &str) -> File {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.path(name))
                .unwrap()
        }
    }
    impl Drop for Files {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn binding() -> StateBinding {
        StateBinding {
            live_state_schema: crate::api::capabilities::LIVE_STATE_SCHEMA.into(),
            architecture: crate::api::capabilities::guest_architecture().into(),
            profile: [2; 32],
            topology: [3; 32],
            ram_layout: [4; 32],
            source_run: [5; 16],
            pause_generation: 6,
            capture: [7; 16],
        }
    }
    fn auth() -> RamImageAuthentication {
        RamImageAuthentication {
            state: binding(),
            stream: [0; 32],
        }
    }
    fn key() -> BarrierKey {
        BarrierKey {
            operation: OperationId(1),
            generation: BarrierGeneration(1),
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn seal(control: &mut DomainControl) -> MemoryCut {
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("unexpected outstanding memory owner");
        };
        control.seal(&drained).unwrap()
    }
    fn source() -> (Arc<MemoryDomain>, DomainControl, Arc<ValidatedRamLayout>) {
        let g = host_page_granule().unwrap();
        let memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), g as usize),
            (GuestAddress(u64::from(g) * 2), g as usize),
        ])
        .unwrap();
        memory.write_slice(&[0xa5; 16], GuestAddress(0)).unwrap();
        let (domain, construction, mut control) =
            MemoryDomain::construct(memory, g, BackingKind::Boot).unwrap();
        let info = ArchMemoryInfo {
            ram_below_gap: u64::from(g) * 2,
            ram_above_gap: 0,
            ram_last_addr: u64::from(g) * 3,
            shm_start_addr: 1 << 32,
            page_size: g as usize,
            initrd_addr: u64::from(g) * 3,
            firmware_addr: 0,
        };
        let layout = Arc::new(
            ValidatedRamLayout::from_registered(domain.layout(), &info, ExecutionLane::KvmX86)
                .unwrap(),
        );
        let epoch = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, epoch).unwrap();
        (domain, control, layout)
    }

    fn execution(layout: &ValidatedRamLayout) -> ValidatedExecution {
        let mut lapic = vec![0; 1024];
        lapic[0x320..0x324].copy_from_slice(&(2u32 << 17).to_le_bytes());
        let mut xsave = vec![0; 4096];
        xsave[512] = 7;
        let cpu = kvm::X86CpuState {
            id: 0,
            cpuid: vec![
                kvm::CpuidEntry {
                    function: 0,
                    index: 0,
                    flags: 0,
                    values: [0xd, 0x756e6547, 0x6c65746e, 0x49656e69],
                },
                kvm::CpuidEntry {
                    function: 1,
                    index: 0,
                    flags: 0,
                    values: [0, 1 << 16, 0, 0],
                },
                kvm::CpuidEntry {
                    function: 0xd,
                    index: 0,
                    flags: 0,
                    values: [7, 832, 832, 0],
                },
                kvm::CpuidEntry {
                    function: 0xd,
                    index: 2,
                    flags: 0,
                    values: [256, 576, 0, 0],
                },
            ],
            inventory: vec![
                kvm::MsrDescriptor {
                    index: 0x10,
                    class: 3,
                },
                kvm::MsrDescriptor {
                    index: 0x174,
                    class: 0,
                },
                kvm::MsrDescriptor {
                    index: 0x179,
                    class: 1,
                },
            ],
            msrs: vec![
                kvm::MsrValue {
                    index: 0x174,
                    value: 0,
                },
                kvm::MsrValue {
                    index: 0x17a,
                    value: 0,
                },
            ],
            model_msrs: vec![kvm::MsrValue {
                index: 0x179,
                value: 0,
            }],
            mce_cap: 0,
            xstate: vec![kvm::XstateComponent {
                id: 2,
                size: 256,
                offset: 576,
                flags: 0,
            }],
            xsave,
            xcrs: vec![kvm::MsrValue { index: 0, value: 7 }],
            regs: [0; 18],
            special: kvm::X86Special {
                segments: std::array::from_fn(|_| kvm::Segment {
                    base: 0,
                    limit: 0,
                    selector: 0,
                    attributes: [0; 9],
                }),
                gdt: (0, 0),
                idt: (0, 0),
                values: [0; 12],
            },
            debug: [0; 7],
            lapic,
            events: [0; 24],
            mp_state: 3,
            tsc_offset: 7,
            tsc_khz: 3_600_000,
            tsc_observed: 100,
            deadline: 1,
        };
        let vm = kvm::X86VmState {
            clock: 0,
            clock_flags: 10,
            host_tsc: 1,
            realtime: 1,
            host_kernel: "unit-codec".into(),
            host_mode: 0,
            pit: std::array::from_fn(|_| {
                let mut bytes = [0; 10];
                bytes[7] = 255;
                kvm::PitChannel {
                    count: 0,
                    latched_count: 0,
                    bytes,
                    count_load_time: 0,
                }
            }),
            pit_flags: 0,
            pit_profile: 0,
            pic: [[0; 16]; 2],
            ioapic_base: 0xfec00000,
            ioapic_select: 0,
            ioapic_id: 0,
            ioapic_irr: 0,
            ioapic_routes: [0; 24],
        };
        let envelope = ExecutionEnvelope {
            binding: binding(),
            lane: ExecutionLane::KvmX86,
            topology: vec![CpuIdentity {
                logical_id: 0,
                architectural_id: 0,
            }],
            attachments: Vec::new(),
            irq_routes: Vec::new(),
            page_granule: layout.granule(),
            memory_regions: layout
                .regions()
                .iter()
                .map(|r| GuestRange::new(r.guest_start, r.length).unwrap())
                .collect(),
            vm: VmExecutionState::Kvm(kvm::KvmVmState::X86(vm)),
            cpus: vec![CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu))],
            legacy: Vec::new(),
        };
        let bytes = envelope.encode().unwrap();
        ValidatedExecution::decode(
            &bytes,
            &binding(),
            ExecutionLane::KvmX86,
            &envelope.topology,
            &[],
        )
        .unwrap()
    }
    fn image(
        files: &Files,
        prefix: &str,
        layout: &Arc<ValidatedRamLayout>,
    ) -> Arc<AuthenticatedRamImage> {
        let ram_name = format!("{prefix}-ram");
        let layout_name = format!("{prefix}-layout");
        let ram = files.create(&ram_name, &[]);
        ram.set_len(layout.packed_len()).unwrap();
        ram.write_all_at(&[0x5a; 16], 0).unwrap();
        ram.write_all_at(&[0x6b; 16], u64::from(layout.granule()))
            .unwrap();
        drop(ram);
        drop(files.create(&layout_name, layout.canonical_bytes()));
        Arc::new(
            AuthenticatedRamImage::for_restore(
                files.readonly(&ram_name),
                files.readonly(&layout_name),
                auth(),
                &execution(layout),
            )
            .unwrap(),
        )
    }
    fn capture(
        files: &Files,
        prefix: &str,
        cut: &MemoryCut,
        layout: Arc<ValidatedRamLayout>,
        attempt: AttemptId,
    ) -> RamCaptureReceipt {
        let output = RamOutputFiles::new(
            files.create(&format!("{prefix}-ram"), &[]),
            files.create(&format!("{prefix}-layout"), &[]),
        );
        write_ram_image(
            attempt,
            key(),
            cut,
            &binding(),
            layout,
            RamWriteMode::Full,
            output,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap()
    }
    fn read_prefix(path: &Path) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        File::open(path)
            .unwrap()
            .read_exact_at(&mut bytes, 0)
            .unwrap();
        bytes
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn completed_receipt_closes_both_writers_before_authentication() {
        use std::os::fd::AsRawFd;
        let files = Files::new();
        let (_, mut control, layout) = source();
        let cut = seal(&mut control);
        let ram = files.create("closed-ram", &[]);
        let record = files.create("closed-layout", &[]);
        let ram_fd = ram.as_raw_fd();
        let layout_fd = record.as_raw_fd();
        let ram_link = fs::read_link(format!("/proc/self/fd/{ram_fd}")).unwrap();
        let layout_link = fs::read_link(format!("/proc/self/fd/{layout_fd}")).unwrap();
        let receipt = write_ram_image(
            AttemptId::for_test(),
            key(),
            &cut,
            &binding(),
            layout,
            RamWriteMode::Full,
            RamOutputFiles::new(ram, record),
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap();
        assert!(receipt.writers_closed());
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{ram_fd}")).ok(),
            Some(ram_link)
        );
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{layout_fd}")).ok(),
            Some(layout_link)
        );
        let first = seal_completed(
            &receipt,
            files.readonly("closed-ram"),
            files.readonly("closed-layout"),
            auth(),
        )
        .unwrap();
        let second = seal_completed(
            &receipt,
            files.readonly("closed-ram"),
            files.readonly("closed-layout"),
            auth(),
        )
        .unwrap();
        assert!(Arc::ptr_eq(
            first.completion.as_ref().unwrap(),
            second.completion.as_ref().unwrap()
        ));
    }

    #[test]
    fn descriptor_roles_reject_writable_inputs_and_readonly_append_path_direct_outputs() {
        let files = Files::new();
        drop(files.create("regular", b"sentinel"));
        assert!(matches!(
            inspect(&files.readonly("regular"), RamFileRole::OutputRam),
            Err(RamImageError::DescriptorRole {
                problem: DescriptorProblem::WrongAccess,
                ..
            })
        ));
        assert!(matches!(
            inspect(&files.writable("regular"), RamFileRole::InputRam),
            Err(RamImageError::DescriptorRole {
                problem: DescriptorProblem::WrongAccess,
                ..
            })
        ));
        let append = OpenOptions::new()
            .read(true)
            .append(true)
            .open(files.path("regular"))
            .unwrap();
        assert!(matches!(
            inspect(&append, RamFileRole::OutputLayout),
            Err(RamImageError::DescriptorRole {
                problem: DescriptorProblem::Append,
                ..
            })
        ));
        assert!(matches!(
            inspect(&File::open(&files.0).unwrap(), RamFileRole::InputLayout),
            Err(RamImageError::DescriptorRole {
                problem: DescriptorProblem::NotRegular,
                ..
            })
        ));
        #[cfg(target_os = "linux")]
        {
            let path = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH)
                .open(files.path("regular"))
                .unwrap();
            assert!(matches!(
                inspect(&path, RamFileRole::InputRam),
                Err(RamImageError::DescriptorRole {
                    problem: DescriptorProblem::PathOnly,
                    ..
                })
            ));
            if let Ok(direct) = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_DIRECT)
                .open(files.path("regular"))
            {
                assert!(matches!(
                    inspect(&direct, RamFileRole::OutputRam),
                    Err(RamImageError::DescriptorRole {
                        problem: DescriptorProblem::DirectIo,
                        ..
                    })
                ));
            }
        }
        let (pipe_read, pipe_write) = nix::unistd::pipe().unwrap();
        assert!(matches!(
            inspect(&File::from(pipe_read), RamFileRole::InputRam),
            Err(RamImageError::DescriptorRole {
                problem: DescriptorProblem::NotRegular,
                ..
            })
        ));
        drop(pipe_write);
        assert!(matches!(
            inspect(&File::open("/dev/null").unwrap(), RamFileRole::InputRam),
            Err(RamImageError::DescriptorRole {
                problem: DescriptorProblem::NotRegular,
                ..
            })
        ));
        assert_eq!(fs::read(files.path("regular")).unwrap(), b"sentinel");
    }

    #[test]
    fn descriptor_refusal_preserves_both_staging_sentinels() {
        let files = Files::new();
        let (_, mut control, layout) = source();
        let cut = seal(&mut control);
        drop(files.create("ram-sentinel", b"ram-sentinel"));
        drop(files.create("layout-sentinel", b"layout-sentinel"));
        for output in [
            RamOutputFiles::new(
                files.readonly("ram-sentinel"),
                files.writable("layout-sentinel"),
            ),
            RamOutputFiles::new(
                files.writable("ram-sentinel"),
                files.readonly("layout-sentinel"),
            ),
        ] {
            let failure = write_ram_image(
                AttemptId::for_test(),
                key(),
                &cut,
                &binding(),
                layout.clone(),
                RamWriteMode::Full,
                output,
                &mut RamIoScratch::new().unwrap(),
                deadline(),
            )
            .unwrap_err();
            assert!(matches!(
                failure.error,
                RamImageError::DescriptorRole {
                    problem: DescriptorProblem::WrongAccess,
                    ..
                }
            ));
            assert_eq!(failure.effects, RamImageEffects::None);
            assert_eq!(
                fs::read(files.path("ram-sentinel")).unwrap(),
                b"ram-sentinel"
            );
            assert_eq!(
                fs::read(files.path("layout-sentinel")).unwrap(),
                b"layout-sentinel"
            );
        }
    }

    #[test]
    fn cached_source_layout_refuses_stale_metadata_and_equal_size_different_geometry() {
        let (domain, _, layout) = source();
        let mut info = layout.arch_info().unwrap();
        assert!(
            layout
                .validate_source(domain.layout(), &info, ExecutionLane::KvmX86)
                .is_ok()
        );
        info.initrd_addr -= u64::from(layout.granule());
        assert!(
            layout
                .validate_source(domain.layout(), &info, ExecutionLane::KvmX86)
                .is_err()
        );
        let g = layout.granule() as usize;
        let different =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), g), (GuestAddress(g as u64 * 3), g)])
                .unwrap();
        let (other, _, _) =
            MemoryDomain::construct(different, layout.granule(), BackingKind::Boot).unwrap();
        assert_eq!(domain.layout().packed_len(), other.layout().packed_len());
        assert!(layout.validate_registered(other.layout()).is_err());
    }

    #[test]
    fn all_output_aliases_refuse_before_any_truncation_including_full_baseline_fallback() {
        let files = Files::new();
        let (_, mut control, layout) = source();
        let cut = seal(&mut control);
        let baseline = image(&files, "baseline", &layout);
        fs::hard_link(files.path("baseline-ram"), files.path("hardlink")).unwrap();
        for target in ["baseline-ram", "baseline-layout", "hardlink"] {
            for alias_is_ram in [false, true] {
                let sentinel_name = format!("out-{target}-{alias_is_ram}");
                let sentinel = files.create(&sentinel_name, b"output-sentinel");
                let mut output = if alias_is_ram {
                    RamOutputFiles::new(files.writable(target), sentinel)
                } else {
                    RamOutputFiles::new(sentinel, files.writable(target))
                };
                output.protect_baseline(Some(baseline.clone()));
                let failure = write_ram_image(
                    AttemptId::for_test(),
                    key(),
                    &cut,
                    &binding(),
                    layout.clone(),
                    RamWriteMode::Full,
                    output,
                    &mut RamIoScratch::new().unwrap(),
                    deadline(),
                )
                .unwrap_err();
                assert!(matches!(failure.error, RamImageError::Alias { .. }));
                assert_eq!(failure.effects, RamImageEffects::None);
                assert_eq!(
                    fs::read(files.path(&sentinel_name)).unwrap(),
                    b"output-sentinel"
                );
                assert_eq!(read_prefix(&files.path("baseline-ram")), [0x5a; 16]);
                assert_eq!(
                    fs::read(files.path("baseline-layout")).unwrap(),
                    layout.canonical_bytes()
                );
            }
        }
        let same = files.create("same-output", b"same-sentinel");
        let dup = same.try_clone().unwrap();
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &cut,
            &binding(),
            layout,
            RamWriteMode::Full,
            RamOutputFiles::new(same, dup),
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap_err();
        assert!(matches!(
            failure.error,
            RamImageError::Alias {
                protected: ProtectedRamRole::OtherOutput,
                ..
            }
        ));
        assert_eq!(
            fs::read(files.path("same-output")).unwrap(),
            b"same-sentinel"
        );
    }

    #[test]
    fn sealing_and_acceptance_require_exact_completed_inodes_state_and_private_origin() {
        let files = Files::new();
        let (_, mut control, layout) = source();
        let cut = seal(&mut control);
        let attempt = AttemptId::for_test();
        let receipt = capture(&files, "first", &cut, layout.clone(), attempt.clone());
        let mut wrong = auth();
        wrong.state.capture = [9; 16];
        assert!(
            seal_completed(
                &receipt,
                files.readonly("first-ram"),
                files.readonly("first-layout"),
                wrong
            )
            .is_err()
        );
        fs::copy(files.path("first-ram"), files.path("copy-ram")).unwrap();
        assert!(
            seal_completed(
                &receipt,
                files.readonly("copy-ram"),
                files.readonly("first-layout"),
                auth()
            )
            .is_err()
        );
        assert!(
            seal_completed(
                &receipt,
                files.writable("first-ram"),
                files.readonly("first-layout"),
                auth()
            )
            .is_err()
        );
        let external = AuthenticatedRamImage::for_restore(
            files.readonly("first-ram"),
            files.readonly("first-layout"),
            auth(),
            &execution(&layout),
        )
        .unwrap();
        let sealed = seal_completed(
            &receipt,
            files.readonly("first-ram"),
            files.readonly("first-layout"),
            auth(),
        )
        .unwrap();
        assert!(
            receipt
                .matches(&attempt, key(), &cut, &binding(), &layout, &sealed)
                .is_ok()
        );
        assert!(
            receipt
                .matches(&attempt, key(), &cut, &binding(), &layout, &external)
                .is_err()
        );
        assert!(
            receipt
                .matches(
                    &AttemptId::for_test(),
                    key(),
                    &cut,
                    &binding(),
                    &layout,
                    &sealed
                )
                .is_err()
        );
        let wrong_key = BarrierKey {
            operation: OperationId(2),
            generation: BarrierGeneration(1),
        };
        assert!(
            receipt
                .matches(&attempt, wrong_key, &cut, &binding(), &layout, &sealed)
                .is_err()
        );
        let (_, mut foreign_control, _) = source();
        let foreign_cut = seal(&mut foreign_control);
        assert!(
            receipt
                .matches(&attempt, key(), &foreign_cut, &binding(), &layout, &sealed)
                .is_err()
        );
        assert!(
            seal_completed(
                &receipt,
                files.readonly("first-ram"),
                files.readonly("first-layout"),
                auth()
            )
            .is_ok()
        );
        let other = capture(&files, "other", &cut, layout.clone(), attempt.clone());
        let other_sealed = seal_completed(
            &other,
            files.readonly("other-ram"),
            files.readonly("other-layout"),
            auth(),
        )
        .unwrap();
        assert!(
            receipt
                .matches(&attempt, key(), &cut, &binding(), &layout, &other_sealed)
                .is_err()
        );
        assert_eq!(receipt.mode(), RamCaptureMode::Full);
        assert_eq!(receipt.affected_chunks().collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn seal_failure_keeps_closed_writer_completion_and_detects_layout_mutation() {
        let files = Files::new();
        let (_, mut control, layout) = source();
        let cut = seal(&mut control);
        let receipt = capture(
            &files,
            "candidate",
            &cut,
            layout.clone(),
            AttemptId::for_test(),
        );
        files
            .writable("candidate-layout")
            .write_all_at(b"[", 0)
            .unwrap();
        assert!(
            seal_completed(
                &receipt,
                files.readonly("candidate-ram"),
                files.readonly("candidate-layout"),
                auth()
            )
            .is_err()
        );
        assert!(receipt.writers_closed());
        files
            .writable("candidate-layout")
            .write_all_at(layout.canonical_bytes(), 0)
            .unwrap();
        assert!(
            seal_completed(
                &receipt,
                files.readonly("candidate-ram"),
                files.readonly("candidate-layout"),
                auth()
            )
            .is_ok()
        );
        assert!(receipt.writers_closed());
    }

    #[test]
    fn restore_validation_refuses_lengths_geometry_bindings_and_writable_roles() {
        let files = Files::new();
        let (_, _, layout) = source();
        let original = image(&files, "input", &layout);
        let valid_execution = execution(&layout);
        let mut wrong = auth();
        wrong.state.source_run = [8; 16];
        assert!(
            AuthenticatedRamImage::for_restore(
                files.readonly("input-ram"),
                files.readonly("input-layout"),
                wrong,
                &valid_execution
            )
            .is_err()
        );
        assert!(
            AuthenticatedRamImage::for_restore(
                files.writable("input-ram"),
                files.readonly("input-layout"),
                auth(),
                &valid_execution
            )
            .is_err()
        );
        files
            .writable("input-ram")
            .set_len(layout.packed_len() - 1)
            .unwrap();
        assert!(
            AuthenticatedRamImage::for_restore(
                files.readonly("input-ram"),
                files.readonly("input-layout"),
                auth(),
                &valid_execution
            )
            .is_err()
        );
        assert!(map_restore_ram(original, &valid_execution).is_err());
        files
            .writable("input-ram")
            .set_len(layout.packed_len())
            .unwrap();
        let mut changed = String::from_utf8(layout.canonical_bytes().to_vec()).unwrap();
        changed = changed.replace(
            "\"guestPhysicalAddress\":0",
            "\"guestPhysicalAddress\":4096",
        );
        files.writable("input-layout").set_len(0).unwrap();
        files
            .writable("input-layout")
            .write_all_at(changed.as_bytes(), 0)
            .unwrap();
        assert!(
            AuthenticatedRamImage::for_restore(
                files.readonly("input-ram"),
                files.readonly("input-layout"),
                auth(),
                &valid_execution
            )
            .is_err()
        );
    }

    #[test]
    fn consuming_restored_ram_rejects_another_same_geometry_execution() {
        let files = Files::new();
        let (_, _, layout) = source();
        let original = image(&files, "input", &layout);
        let original_execution = execution(&layout);
        let restored = map_restore_ram(original.clone(), &original_execution).unwrap();
        let mut other = original_execution.envelope().clone();
        other.binding.source_run = [8; 16];
        let other_execution = ValidatedExecution::decode(
            &other.encode().unwrap(),
            &other.binding,
            ExecutionLane::KvmX86,
            &other.topology,
            &[],
        )
        .unwrap();
        assert!(layout.validate_execution(&other_execution).is_ok());
        assert!(matches!(
            restored.into_parts(&other_execution),
            Err(RamImageError::ExecutionBinding)
        ));
        let matching = map_restore_ram(original, &original_execution).unwrap();
        assert!(matching.into_parts(&original_execution).is_ok());
    }

    #[test]
    fn explicit_private_mappings_isolate_siblings_and_retain_unlinked_backing_after_owner_drop() {
        let files = Files::new();
        let (_, _, layout) = source();
        let baseline = image(&files, "input", &layout);
        let retained_file = Arc::downgrade(&baseline.ram);
        let exec = execution(&layout);
        let first = map_restore_ram(baseline.clone(), &exec).unwrap();
        let second = map_restore_ram(baseline.clone(), &exec).unwrap();
        let (_, first_authority, _, first_image, _) = first.into_parts(&exec).unwrap();
        let (_, second_authority, _, second_image, _) = second.into_parts(&exec).unwrap();
        let first_memory = first_authority.memory().unwrap();
        for (region, expected) in first_memory.iter().zip(layout.regions()) {
            assert_eq!(region.flags(), libc::MAP_PRIVATE);
            assert_eq!(region.prot(), libc::PROT_READ | libc::PROT_WRITE);
            assert_eq!(
                region.file_offset().unwrap().start(),
                expected.stream_offset
            );
            assert!(inspect(region.file_offset().unwrap().file(), RamFileRole::InputRam).is_ok());
        }
        first_memory
            .write_slice(&[0x11; 16], GuestAddress(0))
            .unwrap();
        let mut bytes = [0; 16];
        let second_gpa = GuestAddress(u64::from(layout.granule()) * 2);
        second_authority
            .memory()
            .unwrap()
            .read_slice(&mut bytes, second_gpa)
            .unwrap();
        assert_eq!(bytes, [0x6b; 16]);
        first_memory.write_slice(&[0x33; 16], second_gpa).unwrap();
        second_authority
            .memory()
            .unwrap()
            .read_slice(&mut bytes, second_gpa)
            .unwrap();
        assert_eq!(bytes, [0x6b; 16]);
        second_authority
            .memory()
            .unwrap()
            .read_slice(&mut bytes, GuestAddress(0))
            .unwrap();
        assert_eq!(bytes, [0x5a; 16]);
        assert_eq!(read_prefix(&files.path("input-ram")), [0x5a; 16]);
        fs::remove_file(files.path("input-ram")).unwrap();
        fs::remove_file(files.path("input-layout")).unwrap();
        drop(baseline);
        drop(first_image);
        drop(second_image);
        assert!(retained_file.upgrade().is_some());
        second_authority
            .memory()
            .unwrap()
            .read_slice(&mut bytes, GuestAddress(0))
            .unwrap();
        assert_eq!(bytes, [0x5a; 16]);
        first_memory
            .read_slice(&mut bytes, GuestAddress(0))
            .unwrap();
        assert_eq!(bytes, [0x11; 16]);
        second_authority
            .memory()
            .unwrap()
            .write_slice(&[0x22; 16], GuestAddress(0))
            .unwrap();
        first_memory
            .read_slice(&mut bytes, GuestAddress(0))
            .unwrap();
        assert_eq!(bytes, [0x11; 16]);
    }

    #[test]
    fn original_mapping_inode_stays_protected_when_new_baseline_owner_replaces_it() {
        let files = Files::new();
        let (_, _, layout) = source();
        let original = image(&files, "original", &layout);
        let restored = map_restore_ram(original.clone(), &execution(&layout)).unwrap();
        let (domain, construction, mut control, old_image, _) =
            restored.into_parts(&execution(&layout)).unwrap();
        let epoch = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, epoch).unwrap();
        let cut = seal(&mut control);
        let newer = image(&files, "newer", &layout);
        drop(old_image);
        drop(original);
        let mut output = RamOutputFiles::new(
            files.writable("original-ram"),
            files.create("layout-output", b"layout-sentinel"),
        );
        output.protect_baseline(Some(newer));
        assert!(matches!(
            preflight(
                &cut,
                &binding(),
                &layout,
                &RamWriteMode::Full,
                &output,
                deadline()
            ),
            Err(RamImageError::Alias {
                protected: ProtectedRamRole::MappedBacking,
                ..
            })
        ));
        assert_eq!(read_prefix(&files.path("original-ram")), [0x5a; 16]);
        assert_eq!(
            fs::read(files.path("layout-output")).unwrap(),
            b"layout-sentinel"
        );
        assert_eq!(domain.backing_kind(), BackingKind::RestoredPrivate);
    }
}
