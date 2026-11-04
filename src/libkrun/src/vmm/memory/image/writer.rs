use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::time::Instant;

use arch::guest_memory::{DirtyPageMap, MemoryCut};
use nix::errno::Errno;
use nix::unistd::{Whence, lseek};
use vm_memory::GuestAddress;

use crate::vmm::control::BarrierKey;
use crate::vmm::execution::StateBinding;
use crate::vmm::memory::AttemptId;
use crate::vmm::memory::image::{
    RAM_IDENTITY_CHUNK_BYTES, RamCaptureMode, RamCaptureReceipt, RamFileRole, RamImageEffects,
    RamImageError, RamImageFailure, RamIoOperation, RamIoScratch, RamIoStats, RamOutputFiles,
    RamWriteMode, ValidatedRamLayout, allocate_chunks, check_deadline, io_error, preflight,
};

// Failure must retain staging owners without a new allocation after output effects.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub fn write_ram_image(
    attempt: AttemptId,
    key: BarrierKey,
    cut: &MemoryCut,
    binding: &StateBinding,
    layout: Arc<ValidatedRamLayout>,
    mode: RamWriteMode<'_>,
    output: RamOutputFiles,
    scratch: &mut RamIoScratch,
    deadline: Instant,
) -> Result<RamCaptureReceipt, RamImageFailure> {
    let mut stats = RamIoStats {
        logical_bytes: layout.packed_len(),
        ..RamIoStats::default()
    };
    let mut effects = RamImageEffects::None;
    let selected = match &mode {
        RamWriteMode::Full => RamCaptureMode::Full,
        RamWriteMode::Incremental { .. } => RamCaptureMode::Incremental,
    };
    let result = (|| {
        check_deadline(deadline)?;
        let preparation = preflight(cut, binding, &layout, &mode, &output, deadline)?;
        let mut chunks = allocate_chunks(&layout)?;
        mark_chunks(&mut chunks, &layout, &mode);
        check_deadline(deadline)?;
        set_length(&output.ram, RamFileRole::OutputRam, 0, deadline)?;
        effects = RamImageEffects::Started;
        set_length(&output.layout, RamFileRole::OutputLayout, 0, deadline)?;
        set_length(
            &output.ram,
            RamFileRole::OutputRam,
            layout.packed_len(),
            deadline,
        )?;
        {
            let mut writer = ImageWriter {
                ram: &output.ram,
                buffer: &mut scratch.buffer,
                stats: &mut stats,
                deadline,
                granule: layout.granule() as usize,
            };
            match &mode {
                RamWriteMode::Full => writer.full(cut, &layout)?,
                RamWriteMode::Incremental { baseline, dirty } => {
                    writer.materialize(&baseline.ram, dirty, layout.packed_len())?;
                    writer.overlay(cut, &layout, dirty)?;
                }
            }
        }
        set_length(
            &output.ram,
            RamFileRole::OutputRam,
            layout.packed_len(),
            deadline,
        )?;
        write_exact_at(
            &output.layout,
            layout.canonical_bytes(),
            0,
            WriteKind::Layout,
            &mut stats,
            deadline,
        )?;
        set_length(
            &output.layout,
            RamFileRole::OutputLayout,
            layout.canonical_bytes().len() as u64,
            deadline,
        )?;
        sync(&output.ram, RamFileRole::OutputRam, deadline)?;
        sync(&output.layout, RamFileRole::OutputLayout, deadline)?;
        check_deadline(deadline)?;
        Ok((preparation, chunks))
    })();
    let (preparation, chunks) = match result {
        Ok(prepared) => prepared,
        Err(error) => {
            return Err(RamImageFailure {
                error,
                stats,
                output,
                effects,
            });
        }
    };
    match RamCaptureReceipt::completed(
        preparation,
        attempt,
        key,
        cut,
        binding,
        layout,
        selected,
        output,
        stats.clone(),
        chunks,
        deadline,
    ) {
        Ok(receipt) => Ok(receipt),
        Err((error, output)) => Err(RamImageFailure {
            error,
            stats,
            output,
            effects,
        }),
    }
}

fn mark_chunks(chunks: &mut [u64], layout: &ValidatedRamLayout, mode: &RamWriteMode<'_>) {
    let mut mark = |start: u64, length: u64| {
        let first = start / RAM_IDENTITY_CHUNK_BYTES;
        let last = (start + length - 1) / RAM_IDENTITY_CHUNK_BYTES;
        for chunk in first..=last {
            chunks[chunk as usize / 64] |= 1 << (chunk as usize % 64);
        }
    };
    match mode {
        RamWriteMode::Full => mark(0, layout.packed_len()),
        RamWriteMode::Incremental { dirty, .. } => {
            for page in dirty.iter_set() {
                mark(
                    page.index() as u64 * u64::from(layout.granule()),
                    u64::from(layout.granule()),
                );
            }
        }
    }
}

struct ImageWriter<'a> {
    ram: &'a File,
    buffer: &'a mut [u8],
    stats: &'a mut RamIoStats,
    deadline: Instant,
    granule: usize,
}

impl ImageWriter<'_> {
    fn full(&mut self, cut: &MemoryCut, layout: &ValidatedRamLayout) -> Result<(), RamImageError> {
        for region in layout.regions() {
            let mut local = 0;
            while local < region.length {
                let len = (region.length - local).min(self.buffer.len() as u64) as usize;
                self.read_live(cut, region.guest_start + local, len)?;
                self.sparse(len, region.stream_offset + local, WriteKind::Full)?;
                local += len as u64;
            }
        }
        Ok(())
    }

    fn read_live(&mut self, cut: &MemoryCut, gpa: u64, len: usize) -> Result<(), RamImageError> {
        check_deadline(self.deadline)?;
        cut.validate_domain(cut.domain())
            .map_err(RamImageError::Authority)?;
        let guard = cut
            .domain()
            .read(GuestAddress(gpa), len)
            .map_err(RamImageError::GuestMemory)?;
        let count = guard
            .read_view(0, len)
            .map_err(RamImageError::GuestMemory)?
            .copy_to(&mut self.buffer[..len]);
        self.stats.live_bytes_read += count as u64;
        if count != len {
            return Err(io_error(
                RamIoOperation::Read,
                RamFileRole::OutputRam,
                io::Error::new(io::ErrorKind::UnexpectedEof, "short live RAM read"),
            ));
        }
        check_deadline(self.deadline)
    }

    fn materialize(
        &mut self,
        baseline: &File,
        dirty: &DirtyPageMap,
        length: u64,
    ) -> Result<(), RamImageError> {
        let mut extents = Extents {
            file: baseline,
            length,
            supported: true,
        };
        let mut clean_start = 0;
        for page in dirty.iter_set() {
            let dirty_start = page.index() as u64 * self.granule as u64;
            self.clean_run(&mut extents, clean_start..dirty_start)?;
            clean_start = dirty_start + self.granule as u64;
        }
        self.clean_run(&mut extents, clean_start..length)
    }

    fn clean_run(
        &mut self,
        extents: &mut Extents<'_>,
        range: Range<u64>,
    ) -> Result<(), RamImageError> {
        let mut cursor = range.start;
        while cursor < range.end {
            let Some(data) = extents.next(cursor, self.stats, self.deadline)? else {
                self.stats.baseline_hole_bytes += range.end - cursor;
                break;
            };
            let start = data.start.min(range.end);
            self.stats.baseline_hole_bytes += start - cursor;
            let end = data.end.min(range.end);
            cursor = start;
            while cursor < end {
                let len = (end - cursor).min(self.buffer.len() as u64) as usize;
                read_exact_at(
                    extents.file,
                    &mut self.buffer[..len],
                    cursor,
                    self.stats,
                    self.deadline,
                )?;
                self.sparse(len, cursor, WriteKind::Baseline)?;
                cursor += len as u64;
            }
        }
        Ok(())
    }

    fn overlay(
        &mut self,
        cut: &MemoryCut,
        layout: &ValidatedRamLayout,
        dirty: &DirtyPageMap,
    ) -> Result<(), RamImageError> {
        let mut pages = dirty.iter_set().peekable();
        let mut regions = layout.regions().iter();
        let mut region = regions.next().ok_or(RamImageError::Geometry)?;
        while let Some(first) = pages.next() {
            while first.index()
                >= region.first_page + (region.length / self.granule as u64) as usize
            {
                region = regions.next().ok_or(RamImageError::Bitmap)?;
            }
            let local = (first.index() - region.first_page) as u64 * self.granule as u64;
            let mut len = self.granule;
            while pages.peek().is_some_and(|page| {
                page.index() == first.index() + len / self.granule
                    && len + self.granule <= self.buffer.len()
                    && local + (len + self.granule) as u64 <= region.length
            }) {
                pages.next();
                len += self.granule;
            }
            self.read_live(cut, region.guest_start + local, len)?;
            write_exact_at(
                self.ram,
                &self.buffer[..len],
                region.stream_offset + local,
                WriteKind::Overlay,
                self.stats,
                self.deadline,
            )?;
        }
        Ok(())
    }

    fn sparse(&mut self, len: usize, offset: u64, kind: WriteKind) -> Result<(), RamImageError> {
        let mut run = None;
        for (index, block) in self.buffer[..len].chunks(self.granule).enumerate() {
            let start = index * self.granule;
            if block.iter().any(|byte| *byte != 0) {
                if run.is_none() {
                    run = Some(start);
                }
            } else {
                self.stats.zero_bytes_omitted += block.len() as u64;
                if let Some(first) = run.take() {
                    write_exact_at(
                        self.ram,
                        &self.buffer[first..start],
                        offset + first as u64,
                        kind,
                        self.stats,
                        self.deadline,
                    )?;
                }
            }
        }
        if let Some(first) = run {
            write_exact_at(
                self.ram,
                &self.buffer[first..len],
                offset + first as u64,
                kind,
                self.stats,
                self.deadline,
            )?;
        }
        Ok(())
    }
}

struct Extents<'a> {
    file: &'a File,
    length: u64,
    supported: bool,
}

impl Extents<'_> {
    fn next(
        &mut self,
        offset: u64,
        stats: &mut RamIoStats,
        deadline: Instant,
    ) -> Result<Option<Range<u64>>, RamImageError> {
        check_deadline(deadline)?;
        if !self.supported {
            return Ok(Some(offset..self.length));
        }
        let data = match self.seek(offset, Whence::SeekData, stats, deadline)? {
            Ok(data) => data,
            Err(Errno::ENXIO) => return Ok(None),
            Err(Errno::EINVAL | Errno::EOPNOTSUPP) => {
                self.supported = false;
                return Ok(Some(offset..self.length));
            }
            Err(error) => {
                return Err(io_error(
                    RamIoOperation::Extent,
                    RamFileRole::InputRam,
                    error.into(),
                ));
            }
        };
        if data < offset || data >= self.length {
            return Err(invalid_extent("SEEK_DATA outside admitted baseline"));
        }
        let hole = match self.seek(data, Whence::SeekHole, stats, deadline)? {
            Ok(hole) => hole,
            Err(Errno::EINVAL | Errno::EOPNOTSUPP) => {
                self.supported = false;
                return Ok(Some(offset..self.length));
            }
            Err(error) => {
                return Err(io_error(
                    RamIoOperation::Extent,
                    RamFileRole::InputRam,
                    error.into(),
                ));
            }
        };
        if hole <= data || hole > self.length {
            return Err(invalid_extent("SEEK_HOLE outside admitted baseline"));
        }
        Ok(Some(data..hole))
    }

    fn seek(
        &self,
        offset: u64,
        whence: Whence,
        stats: &mut RamIoStats,
        deadline: Instant,
    ) -> Result<Result<u64, Errno>, RamImageError> {
        let offset = i64::try_from(offset).map_err(|_| RamImageError::Geometry)?;
        loop {
            check_deadline(deadline)?;
            stats.extent_queries += 1;
            match lseek(self.file, offset, whence) {
                Ok(value) => return Ok(u64::try_from(value).map_err(|_| Errno::EOVERFLOW)),
                Err(Errno::EINTR) => continue,
                Err(error) => return Ok(Err(error)),
            }
        }
    }
}

fn invalid_extent(message: &'static str) -> RamImageError {
    io_error(
        RamIoOperation::Extent,
        RamFileRole::InputRam,
        io::Error::new(io::ErrorKind::InvalidData, message),
    )
}

#[derive(Clone, Copy)]
enum WriteKind {
    Full,
    Baseline,
    Overlay,
    Layout,
}

fn read_exact_at(
    file: &File,
    mut bytes: &mut [u8],
    mut offset: u64,
    stats: &mut RamIoStats,
    deadline: Instant,
) -> Result<(), RamImageError> {
    while !bytes.is_empty() {
        check_deadline(deadline)?;
        match file.read_at(bytes, offset) {
            Ok(0) => {
                return Err(io_error(
                    RamIoOperation::Read,
                    RamFileRole::InputRam,
                    io::Error::new(io::ErrorKind::UnexpectedEof, "short RAM baseline"),
                ));
            }
            Ok(count) => {
                stats.baseline_bytes_read += count as u64;
                offset = offset
                    .checked_add(count as u64)
                    .ok_or(RamImageError::Geometry)?;
                bytes = &mut bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(RamIoOperation::Read, RamFileRole::InputRam, error)),
        }
    }
    Ok(())
}

fn write_exact_at(
    file: &File,
    mut bytes: &[u8],
    mut offset: u64,
    kind: WriteKind,
    stats: &mut RamIoStats,
    deadline: Instant,
) -> Result<(), RamImageError> {
    let role = match kind {
        WriteKind::Layout => RamFileRole::OutputLayout,
        WriteKind::Full | WriteKind::Baseline | WriteKind::Overlay => RamFileRole::OutputRam,
    };
    while !bytes.is_empty() {
        check_deadline(deadline)?;
        match file.write_at(bytes, offset) {
            Ok(count) => {
                account_write(bytes, count, role, kind, stats)?;
                offset = offset
                    .checked_add(count as u64)
                    .ok_or(RamImageError::Geometry)?;
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(RamIoOperation::Write, role, error)),
        }
    }
    Ok(())
}

fn account_write(
    bytes: &[u8],
    count: usize,
    role: RamFileRole,
    kind: WriteKind,
    stats: &mut RamIoStats,
) -> Result<(), RamImageError> {
    if count == 0 {
        return Err(io_error(
            RamIoOperation::Write,
            role,
            io::Error::new(io::ErrorKind::WriteZero, "zero RAM image write"),
        ));
    }
    match kind {
        WriteKind::Full => stats.full_bytes_written += count as u64,
        WriteKind::Baseline => stats.baseline_bytes_written += count as u64,
        WriteKind::Layout => stats.layout_bytes_written += count as u64,
        WriteKind::Overlay => {
            stats.overlay_bytes_written += count as u64;
            stats.explicit_zero_bytes_written +=
                bytes[..count].iter().filter(|byte| **byte == 0).count() as u64;
        }
    }
    Ok(())
}

fn set_length(
    file: &File,
    role: RamFileRole,
    length: u64,
    deadline: Instant,
) -> Result<(), RamImageError> {
    check_deadline(deadline)?;
    file.set_len(length)
        .map_err(|error| io_error(RamIoOperation::SetLength, role, error))
}

fn sync(file: &File, role: RamFileRole, deadline: Instant) -> Result<(), RamImageError> {
    check_deadline(deadline)?;
    file.sync_all()
        .map_err(|error| io_error(RamIoOperation::Sync, role, error))?;
    check_deadline(deadline)
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant};

    use arch::ArchMemoryInfo;
    use arch::guest_memory::{BackingKind, DirtyPageMap, DomainControl, MemoryCut, MemoryDomain};
    use polly::event_manager::{BarrierGeneration, BarrierKey, OperationId};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    use vmm_sys_util::tempfile::TempFile;

    use crate::vmm::execution::{ExecutionLane, StateBinding};
    use crate::vmm::memory::AttemptId;
    use crate::vmm::memory::image::writer::{
        Extents, ImageWriter, WriteKind, account_write, read_exact_at, sync, write_exact_at,
        write_ram_image,
    };
    use crate::vmm::memory::image::{
        AuthenticatedRamImage, RamCaptureReceipt, RamFileRole, RamImageAuthentication,
        RamImageEffects, RamImageError, RamIoScratch, RamIoStats, RamOutputFiles, RamWriteMode,
        ValidatedRamLayout, seal_completed,
    };

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn binding() -> StateBinding {
        StateBinding {
            native_producer: "writer-unit-test".into(),
            silo_producer: [1; 32],
            profile: [2; 32],
            topology: [3; 32],
            ram_layout: [4; 32],
            source_run: [5; 16],
            pause_generation: 1,
            capture: [6; 16],
        }
    }

    fn key() -> BarrierKey {
        BarrierKey {
            operation: OperationId(1),
            generation: BarrierGeneration(1),
        }
    }

    fn tracked(raw: GuestMemoryMmap) -> (Arc<MemoryDomain>, DomainControl) {
        let (domain, construction, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::Boot).unwrap();
        let epoch = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, epoch).unwrap();
        (domain, control)
    }

    fn cut(control: &mut DomainControl) -> MemoryCut {
        let closing = control.close().unwrap();
        let Poll::Ready(Ok(drained)) = control.poll_drained(&closing) else {
            panic!("unexpected outstanding host writer");
        };
        control.seal(&drained).unwrap()
    }

    #[cfg(target_arch = "x86_64")]
    fn layout(domain: &MemoryDomain) -> Arc<ValidatedRamLayout> {
        let end = domain
            .layout()
            .regions()
            .last()
            .unwrap()
            .guest_range()
            .end();
        Arc::new(
            ValidatedRamLayout::from_registered(
                domain.layout(),
                &ArchMemoryInfo {
                    ram_below_gap: end,
                    ram_above_gap: 0,
                    ram_last_addr: end,
                    shm_start_addr: 1 << 32,
                    page_size: 4096,
                    initrd_addr: end,
                    firmware_addr: 0,
                },
                ExecutionLane::KvmX86,
            )
            .unwrap(),
        )
    }

    struct Outputs {
        ram: TempFile,
        layout: TempFile,
    }

    impl Outputs {
        fn new() -> Self {
            Self {
                ram: TempFile::new().unwrap(),
                layout: TempFile::new().unwrap(),
            }
        }
        fn owned(&self) -> RamOutputFiles {
            RamOutputFiles::new(
                self.ram.as_file().try_clone().unwrap(),
                self.layout.as_file().try_clone().unwrap(),
            )
        }
        fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.ram.as_path()).unwrap()
        }
        fn seal(&self, receipt: &mut RamCaptureReceipt) -> Arc<AuthenticatedRamImage> {
            Arc::new(
                seal_completed(
                    receipt,
                    File::open(self.ram.as_path()).unwrap(),
                    File::open(self.layout.as_path()).unwrap(),
                    RamImageAuthentication {
                        state: binding(),
                        stream: [0; 32],
                    },
                )
                .unwrap(),
            )
        }
    }

    fn capture(
        cut: &MemoryCut,
        layout: Arc<ValidatedRamLayout>,
        mode: RamWriteMode<'_>,
        output: RamOutputFiles,
    ) -> RamCaptureReceipt {
        write_ram_image(
            AttemptId::for_test(),
            key(),
            cut,
            &binding(),
            layout,
            mode,
            output,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap_or_else(|failure| panic!("writer failed: {:?}", failure.error))
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn full_incremental_resolve_sparse_regions_zero_updates_and_tail() {
        let raw = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 8 * 1024 * 1024 + 4096),
            (GuestAddress(16 * 1024 * 1024), 3 * 4096),
        ])
        .unwrap();
        for address in [
            0,
            255 * 4096,
            256 * 4096,
            2047 * 4096,
            2048 * 4096,
            16 * 1024 * 1024 + 8192,
        ] {
            raw.write_slice(&[0x5a; 4096], GuestAddress(address))
                .unwrap();
        }
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let first_cut = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &first_cut,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        assert_eq!(full.stats().live_bytes_read, layout.packed_len());
        assert_eq!(full.stats().full_bytes_written, 6 * 4096);
        assert_eq!(full.affected_chunks().collect::<Vec<_>>(), [0, 1]);
        assert_eq!(
            std::fs::read(baseline_files.layout.as_path()).unwrap(),
            layout.canonical_bytes()
        );
        let original = baseline_files.bytes();
        let baseline = baseline_files.seal(&mut full);
        let epoch = first_cut.issue_epoch(2).unwrap();
        control.reopen(&first_cut, &epoch).unwrap();
        for (address, byte) in [
            (0, 0),
            (2048 * 4096, 0x44),
            (16 * 1024 * 1024, 0),
            (16 * 1024 * 1024 + 8192, 0),
        ] {
            domain
                .write(GuestAddress(address), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[byte; 4096], 0)
                .unwrap();
        }
        let second_cut = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&second_cut, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 4);
        let incremental_files = Outputs::new();
        let mut output = incremental_files.owned();
        output.protect_baseline(Some(baseline.clone()));
        let incremental = capture(
            &second_cut,
            layout.clone(),
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        let reference_files = Outputs::new();
        let reference = capture(
            &second_cut,
            layout.clone(),
            RamWriteMode::Full,
            reference_files.owned(),
        );
        assert_eq!(incremental_files.bytes(), reference_files.bytes());
        assert_eq!(incremental_files.bytes().len() as u64, layout.packed_len());
        assert_eq!(incremental.stats().live_bytes_read, 4 * 4096);
        assert_eq!(incremental.stats().overlay_bytes_written, 4 * 4096);
        assert_eq!(incremental.stats().explicit_zero_bytes_written, 3 * 4096);
        assert_eq!(
            incremental.stats().baseline_bytes_read + incremental.stats().baseline_hole_bytes,
            layout.packed_len() - 4 * 4096
        );
        assert_eq!(incremental.stats().baseline_bytes_written, 3 * 4096);
        assert_eq!(incremental.affected_chunks().collect::<Vec<_>>(), [0, 1]);
        assert_eq!(reference.stats().live_bytes_read, layout.packed_len());
        assert_eq!(baseline_files.bytes(), original);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn incremental_never_reads_inaccessible_clean_ram_even_with_no_dirties() {
        use vm_memory::{GuestRegionMmap, MmapRegion};

        let ranges = [
            (GuestAddress(0), 4096),
            (GuestAddress(0x10000), 4096),
            (GuestAddress(0x20000), 4096),
        ];
        let raw = GuestMemoryMmap::from_ranges(&ranges).unwrap();
        for (index, (address, _)) in ranges.iter().enumerate() {
            raw.write_slice(&[index as u8 + 1; 4096], *address).unwrap();
        }
        let (source, mut control) = tracked(raw);
        let layout = layout(&source);
        let source_cut = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut receipt = capture(
            &source_cut,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let baseline = baseline_files.seal(&mut receipt);
        for has_dirty in [false, true] {
            let regions = ranges
                .iter()
                .enumerate()
                .map(|(index, (address, len))| {
                    let protection = if has_dirty && index == 1 {
                        libc::PROT_READ | libc::PROT_WRITE
                    } else {
                        libc::PROT_NONE
                    };
                    let mapping = MmapRegion::<()>::build(
                        None,
                        *len,
                        protection,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    )
                    .unwrap();
                    GuestRegionMmap::new(mapping, *address).unwrap()
                })
                .collect();
            let (domain, mut control) = tracked(GuestMemoryMmap::from_regions(regions).unwrap());
            if has_dirty {
                domain
                    .write(GuestAddress(0x10000), 4096)
                    .unwrap()
                    .write_view(0, 4096)
                    .unwrap()
                    .write_slice(&[0; 4096], 0)
                    .unwrap();
            }
            let current = cut(&mut control);
            let mut dirty = DirtyPageMap::new(domain.layout());
            control.drain_host_dirty(&current, &mut dirty).unwrap();
            let outputs = Outputs::new();
            let mut output = outputs.owned();
            output.protect_baseline(Some(baseline.clone()));
            let receipt = capture(
                &current,
                layout.clone(),
                RamWriteMode::Incremental {
                    baseline: &baseline,
                    dirty: &dirty,
                },
                output,
            );
            let mut expected = baseline_files.bytes();
            if has_dirty {
                expected[4096..8192].fill(0);
            }
            assert_eq!(outputs.bytes(), expected);
            assert_eq!(
                receipt.stats().live_bytes_read,
                if has_dirty { 4096 } else { 0 }
            );
            assert_eq!(
                receipt.stats().overlay_bytes_written,
                if has_dirty { 4096 } else { 0 }
            );
            assert_eq!(receipt.affected_chunks().count(), usize::from(has_dirty));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn alias_and_deadline_refusals_retain_output_owners_and_sentinels() {
        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let layout = layout(&domain);
        let current = cut(&mut control);
        let files = Outputs::new();
        files.ram.as_file().write_at(b"ram sentinel", 0).unwrap();
        files
            .layout
            .as_file()
            .write_at(b"layout sentinel", 0)
            .unwrap();
        let alias = RamOutputFiles::new(
            files.ram.as_file().try_clone().unwrap(),
            files.ram.as_file().try_clone().unwrap(),
        );
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout.clone(),
            RamWriteMode::Full,
            alias,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .expect_err("aliased outputs must fail");
        assert!(matches!(failure.error, RamImageError::Alias { .. }));
        assert!(matches!(failure.effects, RamImageEffects::None));
        assert_eq!(
            failure.output.ram.metadata().unwrap().ino(),
            files.ram.as_file().metadata().unwrap().ino()
        );
        assert_eq!(files.bytes(), b"ram sentinel");
        let expired = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout,
            RamWriteMode::Full,
            files.owned(),
            &mut RamIoScratch::new().unwrap(),
            Instant::now(),
        )
        .expect_err("expired writer must fail");
        assert!(matches!(expired.error, RamImageError::Deadline));
        assert!(matches!(expired.effects, RamImageEffects::None));
        assert_eq!(expired.stats.live_bytes_read, 0);
        assert_eq!(files.bytes(), b"ram sentinel");
        assert_eq!(
            std::fs::read(files.layout.as_path()).unwrap(),
            b"layout sentinel"
        );
    }

    #[test]
    fn positional_read_retains_short_prefix_and_real_errors() {
        let file = TempFile::new().unwrap();
        file.as_file().write_at(b"abc", 0).unwrap();
        let mut stats = RamIoStats::default();
        let mut bytes = [0; 8];
        let error =
            read_exact_at(file.as_file(), &mut bytes, 0, &mut stats, deadline()).unwrap_err();
        assert!(
            matches!(error, RamImageError::Io { source, .. } if source.kind() == io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(stats.baseline_bytes_read, 3);
        assert_eq!(&bytes[..3], b"abc");
        let readonly = File::open(file.as_path()).unwrap();
        let error = write_exact_at(
            &readonly,
            b"changed",
            0,
            WriteKind::Overlay,
            &mut stats,
            deadline(),
        )
        .unwrap_err();
        assert!(matches!(error, RamImageError::Io { .. }));
        assert_eq!(stats.overlay_bytes_written, 0);
        assert_eq!(stats.explicit_zero_bytes_written, 0);
        assert_eq!(std::fs::read(file.as_path()).unwrap(), b"abc");
    }

    #[test]
    fn conservative_baseline_copy_clips_clean_runs_and_counts_real_bytes() {
        let baseline = TempFile::new().unwrap();
        baseline.as_file().set_len(3 * 4096).unwrap();
        baseline.as_file().write_at(&[7; 4096], 4096).unwrap();
        let destination = TempFile::new().unwrap();
        destination.as_file().set_len(3 * 4096).unwrap();
        let mut stats = RamIoStats::default();
        let mut buffer = [0; 4096];
        let mut extents = Extents {
            file: baseline.as_file(),
            length: 3 * 4096,
            supported: false,
        };
        let mut writer = ImageWriter {
            ram: destination.as_file(),
            buffer: &mut buffer,
            stats: &mut stats,
            deadline: deadline(),
            granule: 4096,
        };
        writer.clean_run(&mut extents, 0..4096).unwrap();
        writer.clean_run(&mut extents, 8192..12288).unwrap();
        assert_eq!(stats.baseline_bytes_read, 8192);
        assert_eq!(stats.baseline_bytes_written, 0);
        assert_eq!(stats.zero_bytes_omitted, 8192);
        assert_eq!(stats.extent_queries, 0);
        assert_eq!(
            std::fs::read(destination.as_path()).unwrap(),
            vec![0; 12288]
        );
    }

    #[test]
    fn full_fallback_protects_both_baseline_roles_and_original_mapped_inode() {
        use vm_memory::{FileOffset, GuestRegionMmap, MmapRegion};

        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        raw.write_slice(&[0x5a; 4096], GuestAddress(0)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let current = cut(&mut control);
        let original_files = Outputs::new();
        let mut receipt = capture(
            &current,
            layout.clone(),
            RamWriteMode::Full,
            original_files.owned(),
        );
        let original_image = original_files.seal(&mut receipt);
        let expected = original_files.bytes();
        let expected_layout = std::fs::read(original_files.layout.as_path()).unwrap();
        let scratch_files = Outputs::new();
        scratch_files
            .ram
            .as_file()
            .write_at(b"untouched ram", 0)
            .unwrap();
        scratch_files
            .layout
            .as_file()
            .write_at(b"untouched layout", 0)
            .unwrap();
        for alias_layout in [false, true] {
            let mut output = if alias_layout {
                RamOutputFiles::new(
                    scratch_files.ram.as_file().try_clone().unwrap(),
                    original_files.layout.as_file().try_clone().unwrap(),
                )
            } else {
                RamOutputFiles::new(
                    original_files.ram.as_file().try_clone().unwrap(),
                    scratch_files.layout.as_file().try_clone().unwrap(),
                )
            };
            output.protect_baseline(Some(original_image.clone()));
            let failure = write_ram_image(
                AttemptId::for_test(),
                key(),
                &current,
                &binding(),
                layout.clone(),
                RamWriteMode::Full,
                output,
                &mut RamIoScratch::new().unwrap(),
                deadline(),
            )
            .expect_err("full fallback must protect retained baseline roles");
            assert!(matches!(failure.error, RamImageError::Alias { .. }));
            assert!(matches!(failure.effects, RamImageEffects::None));
        }
        let newer_files = Outputs::new();
        let mut newer_receipt = capture(
            &current,
            layout.clone(),
            RamWriteMode::Full,
            newer_files.owned(),
        );
        let newer_image = newer_files.seal(&mut newer_receipt);
        let offset = FileOffset::from_arc(
            Arc::new(File::open(original_files.ram.as_path()).unwrap()),
            0,
        );
        let mapping = MmapRegion::<()>::build(
            Some(offset),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
        )
        .unwrap();
        let region = GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap();
        let (_, mut mapped_control) = tracked(GuestMemoryMmap::from_regions(vec![region]).unwrap());
        let mapped_cut = cut(&mut mapped_control);
        let mut output = RamOutputFiles::new(
            original_files.ram.as_file().try_clone().unwrap(),
            scratch_files.layout.as_file().try_clone().unwrap(),
        );
        output.protect_baseline(Some(newer_image));
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &mapped_cut,
            &binding(),
            layout,
            RamWriteMode::Full,
            output,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .expect_err("old mapped inode remains protected after baseline replacement");
        assert!(matches!(
            failure.error,
            RamImageError::Alias {
                protected: crate::vmm::memory::image::ProtectedRamRole::MappedBacking,
                ..
            }
        ));
        assert!(matches!(failure.effects, RamImageEffects::None));
        assert_eq!(original_files.bytes(), expected);
        assert_eq!(
            std::fs::read(original_files.layout.as_path()).unwrap(),
            expected_layout
        );
        assert_eq!(scratch_files.bytes(), b"untouched ram");
        assert_eq!(
            std::fs::read(scratch_files.layout.as_path()).unwrap(),
            b"untouched layout"
        );
    }

    #[test]
    fn all_zero_full_and_dirty_run_larger_than_scratch_remain_complete() {
        let length = 3 * 1024 * 1024;
        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap());
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut initial_receipt = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        assert_eq!(initial_receipt.stats().live_bytes_read, length as u64);
        assert_eq!(initial_receipt.stats().full_bytes_written, 0);
        assert_eq!(initial_receipt.stats().zero_bytes_omitted, length as u64);
        assert_eq!(baseline_files.bytes(), vec![0; length]);
        let baseline = baseline_files.seal(&mut initial_receipt);
        let epoch = initial.issue_epoch(2).unwrap();
        control.reopen(&initial, &epoch).unwrap();
        let changed = 2 * 1024 * 1024 + 4096;
        domain
            .write(GuestAddress(0), changed)
            .unwrap()
            .write_view(0, changed)
            .unwrap()
            .write_slice(&vec![0x7f; changed], 0)
            .unwrap();
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let outputs = Outputs::new();
        let mut output = outputs.owned();
        output.protect_baseline(Some(baseline.clone()));
        let receipt = capture(
            &current,
            layout,
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        let mut expected = vec![0; length];
        expected[..changed].fill(0x7f);
        assert_eq!(outputs.bytes(), expected);
        assert_eq!(receipt.stats().live_bytes_read, changed as u64);
        assert_eq!(receipt.stats().overlay_bytes_written, changed as u64);
        assert_eq!(receipt.stats().explicit_zero_bytes_written, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn second_truncation_error_returns_started_effect_and_both_owned_files() {
        use nix::fcntl::{FcntlArg, SealFlag, fcntl};
        use nix::sys::memfd::{MFdFlags, memfd_create};

        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let layout = layout(&domain);
        let current = cut(&mut control);
        let files = Outputs::new();
        files.ram.as_file().write_at(b"old output", 0).unwrap();
        let sealed_layout = File::from(
            memfd_create(c"ram-image-test-layout", MFdFlags::MFD_ALLOW_SEALING).unwrap(),
        );
        sealed_layout.write_at(b"layout sentinel", 0).unwrap();
        fcntl(
            &sealed_layout,
            FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_SHRINK),
        )
        .unwrap();
        let layout_inode = sealed_layout.metadata().unwrap().ino();
        let output = RamOutputFiles::new(files.ram.as_file().try_clone().unwrap(), sealed_layout);
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout,
            RamWriteMode::Full,
            output,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .expect_err("sealed layout truncation must fail after RAM reset");
        assert!(matches!(failure.effects, RamImageEffects::Started));
        assert!(matches!(
            failure.error,
            RamImageError::Io {
                role: RamFileRole::OutputLayout,
                ..
            }
        ));
        assert_eq!(failure.stats.live_bytes_read, 0);
        assert_eq!(failure.output.ram.metadata().unwrap().len(), 0);
        assert_eq!(
            failure.output.layout.metadata().unwrap().ino(),
            layout_inode
        );
        let mut sentinel = [0; 15];
        failure.output.layout.read_at(&mut sentinel, 0).unwrap();
        assert_eq!(&sentinel, b"layout sentinel");
    }

    #[test]
    fn zero_progress_and_successful_prefix_accounting_are_exact() {
        let mut stats = RamIoStats::default();
        let error = account_write(
            &[0, 9, 0, 8],
            0,
            RamFileRole::OutputRam,
            WriteKind::Overlay,
            &mut stats,
        )
        .unwrap_err();
        assert!(matches!(error, RamImageError::Io { source, .. }
            if source.kind() == io::ErrorKind::WriteZero));
        assert_eq!(stats, RamIoStats::default());
        account_write(
            &[0, 9, 0, 8],
            3,
            RamFileRole::OutputRam,
            WriteKind::Overlay,
            &mut stats,
        )
        .unwrap();
        assert_eq!(stats.overlay_bytes_written, 3);
        assert_eq!(stats.explicit_zero_bytes_written, 2);
        assert_eq!(stats.full_bytes_written, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_size_limit_counts_real_short_write_prefix() {
        use std::process::Command;

        const CHILD: &str = "LIBKRUN_RAM_WRITER_RLIMIT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = Command::new("/bin/sh")
                .arg("-c")
                .arg("ulimit -f 1; trap '' XFSZ; exec \"$1\" \"$2\" --test-threads=1 --nocapture")
                .arg("ram-writer-rlimit")
                .arg(std::env::current_exe().unwrap())
                .arg("file_size_limit_counts_real_short_write_prefix")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "limited child failed: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        let output = TempFile::new().unwrap();
        let bytes = [0; 8192];
        let mut stats = RamIoStats::default();
        let error = write_exact_at(
            output.as_file(),
            &bytes,
            0,
            WriteKind::Overlay,
            &mut stats,
            deadline(),
        )
        .unwrap_err();
        assert!(matches!(error, RamImageError::Io { source, .. }
            if source.raw_os_error() == Some(nix::errno::Errno::EFBIG as i32)));
        let prefix = output.as_file().metadata().unwrap().len();
        assert!(prefix > 0 && prefix < bytes.len() as u64);
        assert_eq!(stats.overlay_bytes_written, prefix);
        assert_eq!(stats.explicit_zero_bytes_written, prefix);
        assert_eq!(
            std::fs::read(output.as_path()).unwrap(),
            vec![0; prefix as usize]
        );

        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let current = cut(&mut control);
        let files = Outputs::new();
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout(&domain),
            RamWriteMode::Full,
            files.owned(),
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .expect_err("limited image length must fail without a receipt");
        assert!(matches!(failure.effects, RamImageEffects::Started));
        assert!(matches!(failure.error, RamImageError::Io { source, .. }
            if source.raw_os_error() == Some(nix::errno::Errno::EFBIG as i32)));
        assert_eq!(failure.stats.live_bytes_read, 0);
        assert_eq!(failure.output.ram.metadata().unwrap().len(), 0);
        assert_eq!(failure.output.layout.metadata().unwrap().len(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_enospc_and_each_sync_role_propagate_at_helper_boundary() {
        let full = File::options().write(true).open("/dev/full").unwrap();
        let mut stats = RamIoStats::default();
        let error = write_exact_at(
            &full,
            &[1; 4096],
            0,
            WriteKind::Full,
            &mut stats,
            deadline(),
        )
        .unwrap_err();
        assert!(matches!(error, RamImageError::Io { source, .. }
            if source.raw_os_error() == Some(nix::errno::Errno::ENOSPC as i32)));
        assert_eq!(stats.full_bytes_written, 0);
        let (read, _write) = nix::unistd::pipe().unwrap();
        let nonsyncable = File::from(read);
        for role in [RamFileRole::OutputRam, RamFileRole::OutputLayout] {
            let error = sync(&nonsyncable, role, deadline()).unwrap_err();
            assert!(matches!(error, RamImageError::Io { role: failed_role,
                operation: crate::vmm::memory::image::RamIoOperation::Sync, .. } if failed_role == role));
        }
    }

    #[test]
    fn expired_completion_returns_real_finished_outputs_without_a_receipt() {
        use crate::vmm::memory::image::{allocate_chunks, preflight};

        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let layout = layout(&domain);
        let current = cut(&mut control);
        let files = Outputs::new();
        let mut finished = capture(&current, layout.clone(), RamWriteMode::Full, files.owned());
        let output = finished.output.take().unwrap();
        let preparation = preflight(
            &current,
            &binding(),
            &layout,
            &RamWriteMode::Full,
            &output,
            deadline(),
        )
        .unwrap();
        let (error, output) = RamCaptureReceipt::completed(
            preparation,
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout.clone(),
            finished.mode(),
            output,
            finished.stats().clone(),
            allocate_chunks(&layout).unwrap(),
            Instant::now(),
        )
        .expect_err("expiry at final completion must return owners, never a receipt");
        assert!(matches!(error, RamImageError::Deadline));
        assert_eq!(output.ram.metadata().unwrap().len(), 4096);
        assert_eq!(
            output.layout.metadata().unwrap().len(),
            layout.canonical_bytes().len() as u64
        );
        assert_eq!(files.bytes(), [0; 4096]);
        assert_eq!(
            std::fs::read(files.layout.as_path()).unwrap(),
            layout.canonical_bytes()
        );
    }
}
