use std::fs::File;
use std::io;
use std::ops::Range;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::time::Instant;

use arch::guest_memory::MemoryCut;
use nix::errno::Errno;
use nix::unistd::{Whence, lseek};

use crate::vmm::control::BarrierKey;
use crate::vmm::execution::StateBinding;
use crate::vmm::memory::AttemptId;
use crate::vmm::memory::image::{
    RAM_IDENTITY_CHUNK_BYTES, RamCaptureMode, RamCaptureReceipt, RamFileRole, RamImageEffects,
    RamImageError, RamImageFailure, RamIoOperation, RamIoScratch, RamIoStats, RamOutputFiles,
    RamSeedMethod, RamWriteMode, ValidatedRamLayout, allocate_chunks, check_deadline, io_error,
    preflight,
};

mod pipeline;

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
        let mut digests = pipeline::allocate_digests(layout.packed_len())?;
        check_deadline(deadline)?;
        set_length(&output.ram, RamFileRole::OutputRam, 0, deadline)?;
        effects = RamImageEffects::Started;
        set_length(&output.layout, RamFileRole::OutputLayout, 0, deadline)?;
        if let RamWriteMode::Incremental { baseline, .. } = &mode {
            stats.seed_method =
                seed_incremental(&baseline.ram, &output.ram, layout.packed_len(), deadline)?;
        } else {
            set_length(
                &output.ram,
                RamFileRole::OutputRam,
                layout.packed_len(),
                deadline,
            )?;
        }
        pipeline::write(
            pipeline::Input {
                cut,
                layout: &layout,
                mode: &mode,
                seeded: stats.seed_method == RamSeedMethod::Clone,
                deadline,
            },
            &output.ram,
            scratch,
            &mut stats,
            &chunks,
            &mut digests,
        )?;
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
        check_deadline(deadline)?;
        Ok((preparation, digests, chunks))
    })();
    let (preparation, chunk_digests, chunks) = match result {
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
        chunk_digests,
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

fn seed_incremental(
    baseline: &File,
    output: &File,
    length: u64,
    deadline: Instant,
) -> Result<RamSeedMethod, RamImageError> {
    check_deadline(deadline)?;
    match clone_baseline(baseline, output, length) {
        Ok(()) => {
            check_deadline(deadline)?;
            return Ok(RamSeedMethod::Clone);
        }
        Err(error) => log::debug!("RAM reflink seed unavailable, rebuilding: {error}"),
    }
    // Even a failed clone may have changed the destination. Rebuild only from
    // a fresh sparse file, so omitted zeros can never expose partial seed data.
    set_length(output, RamFileRole::OutputRam, 0, deadline)?;
    set_length(output, RamFileRole::OutputRam, length, deadline)?;
    Ok(RamSeedMethod::Rebuild)
}

#[cfg(target_os = "linux")]
fn clone_baseline(baseline: &File, output: &File, length: u64) -> io::Result<()> {
    // nix 0.30 does not expose FICLONE. The ioctl takes the source fd by value.
    let result = unsafe { libc::ioctl(output.as_raw_fd(), 0x4004_9409, baseline.as_raw_fd()) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result != 0 || output.metadata()?.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete RAM reflink seed",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn clone_baseline(_baseline: &File, _output: &File, _length: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "RAM reflink requires Linux",
    ))
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

#[derive(Default)]
struct Writeback {
    pending: Range<u64>,
}

impl Writeback {
    fn completed(&mut self, file: &File, offset: u64, length: u64) {
        if self.pending.end != offset {
            self.pending.start = offset;
        }
        self.pending.end = offset + length;
        if self.pending.end - self.pending.start >= RAM_IDENTITY_CHUNK_BYTES {
            hint_writeback(file, self.pending.clone());
            self.pending.start = self.pending.end;
        }
    }
}

#[cfg(target_os = "linux")]
fn hint_writeback(file: &File, range: Range<u64>) {
    if let (Ok(offset), Ok(length)) = (
        i64::try_from(range.start),
        i64::try_from(range.end - range.start),
    ) {
        // nix 0.30 has no sync_file_range wrapper. WRITE starts writeback
        // without waiting, avoiding an ext4 ordered-journal drain on resume.
        let _ = unsafe {
            libc::sync_file_range(
                file.as_raw_fd(),
                offset,
                length,
                libc::SYNC_FILE_RANGE_WRITE,
            )
        };
    }
}

#[cfg(not(target_os = "linux"))]
fn hint_writeback(_file: &File, _range: Range<u64>) {}

fn is_all_zero(bytes: &[u8]) -> bool {
    let mut blocks = bytes.chunks_exact(64);
    for block in &mut blocks {
        let combined = block.chunks_exact(8).fold(0_u64, |combined, word| {
            combined
                | u64::from_ne_bytes([
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ])
        });
        if combined != 0 {
            return false;
        }
    }
    blocks.remainder().iter().all(|byte| *byte == 0)
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

#[derive(Clone, Copy, Eq, PartialEq)]
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
            stats.explicit_zero_bytes_written += count_zero_bytes(&bytes[..count]);
        }
    }
    Ok(())
}

fn count_zero_bytes(bytes: &[u8]) -> u64 {
    let mut words = bytes.chunks_exact(8);
    let mut count = 0;
    for word in &mut words {
        let value = u64::from_ne_bytes([
            word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
        ]);
        // Mask each byte's high bit after adding 0x7f to its low seven bits.
        // This detects zero bytes exactly, without cross-byte borrow artifacts.
        let low = value & 0x7f7f_7f7f_7f7f_7f7f;
        let nonzero = (low + 0x7f7f_7f7f_7f7f_7f7f) | value;
        count += ((!nonzero) & 0x8080_8080_8080_8080).count_ones() as u64;
    }
    count + words.remainder().iter().filter(|byte| **byte == 0).count() as u64
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

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use std::fs::File;
    use std::io;
    use std::ops::Range;
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant};

    use arch::ArchMemoryInfo;
    use arch::guest_memory::{BackingKind, DirtyPageMap, DomainControl, MemoryCut, MemoryDomain};
    use polly::event_manager::{BarrierGeneration, BarrierKey, OperationId};
    use sha2::{Digest, Sha256};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    use vmm_sys_util::tempfile::TempFile;

    use crate::vmm::execution::{ExecutionLane, StateBinding};
    use crate::vmm::memory::AttemptId;
    use crate::vmm::memory::image::writer::pipeline;
    use crate::vmm::memory::image::writer::{
        Extents, WriteKind, Writeback, account_write, check_deadline, clone_baseline,
        count_zero_bytes, io_error, is_all_zero, mark_chunks, read_exact_at, seed_incremental,
        write_exact_at, write_ram_image,
    };
    use crate::vmm::memory::image::{
        AuthenticatedRamImage, RAM_IDENTITY_CHUNK_BYTES, RamCaptureReceipt, RamFileRole,
        RamImageAuthentication, RamImageEffects, RamImageError, RamIoOperation, RamIoScratch,
        RamIoStats, RamOutputFiles, RamSeedMethod, RamWriteMode, ValidatedRamLayout,
        allocate_chunks, seal_completed,
    };
    // Affected bytes arrive in stream order, whether rebuilt from baseline/dirty
    // runs or read directly from the frozen guest. Leading zeros stay implicit
    // until a nonzero byte requires a digest.
    struct ChunkDigests<'a> {
        values: Vec<Option<[u8; 32]>>,
        affected: &'a [u64],
        length: u64,
        hasher: Option<Sha256>,
    }

    impl<'a> ChunkDigests<'a> {
        fn new(length: u64, affected: &'a [u64]) -> Result<Self, RamImageError> {
            let count = usize::try_from(length.div_ceil(RAM_IDENTITY_CHUNK_BYTES))
                .map_err(|_| RamImageError::Geometry)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| RamImageError::Allocation)?;
            values.resize(count, None);
            Ok(Self {
                values,
                affected,
                length,
                hasher: None,
            })
        }

        fn update(&mut self, mut offset: u64, mut bytes: &[u8]) {
            while !bytes.is_empty() {
                let index = (offset / RAM_IDENTITY_CHUNK_BYTES) as usize;
                let local = offset % RAM_IDENTITY_CHUNK_BYTES;
                let len = bytes.len().min((RAM_IDENTITY_CHUNK_BYTES - local) as usize);
                if self.affected[index / 64] & (1 << (index % 64)) != 0 {
                    if self.hasher.is_none() && !is_all_zero(&bytes[..len]) {
                        let mut hasher = Sha256::new();
                        Self::hash_zeros(&mut hasher, local);
                        self.hasher = Some(hasher);
                    }
                    if let Some(hasher) = &mut self.hasher {
                        hasher.update(&bytes[..len]);
                    }
                }
                offset += len as u64;
                self.finish_chunk(index, offset);
                bytes = &bytes[len..];
            }
        }

        fn zeros(&mut self, range: Range<u64>) {
            let mut offset = range.start;
            while offset < range.end {
                let index = (offset / RAM_IDENTITY_CHUNK_BYTES) as usize;
                let len = (range.end - offset)
                    .min(RAM_IDENTITY_CHUNK_BYTES - offset % RAM_IDENTITY_CHUNK_BYTES);
                if let Some(hasher) = &mut self.hasher {
                    Self::hash_zeros(hasher, len);
                }
                offset += len;
                self.finish_chunk(index, offset);
            }
        }

        fn hash_zeros(hasher: &mut Sha256, mut length: u64) {
            let zeros = [0; 4096];
            while length > 0 {
                let len = length.min(zeros.len() as u64) as usize;
                hasher.update(&zeros[..len]);
                length -= len as u64;
            }
        }

        fn finish_chunk(&mut self, index: usize, offset: u64) {
            if offset.is_multiple_of(RAM_IDENTITY_CHUNK_BYTES) || offset == self.length {
                self.values[index] = self.hasher.take().map(|hasher| hasher.finalize().into());
            }
        }
    }

    struct ImageWriter<'a> {
        ram: &'a File,
        buffer: &'a mut [u8],
        stats: &'a mut RamIoStats,
        deadline: Instant,
        granule: usize,
        writeback: Writeback,
    }

    impl ImageWriter<'_> {
        fn full(
            &mut self,
            cut: &MemoryCut,
            layout: &ValidatedRamLayout,
            digests: &mut ChunkDigests<'_>,
        ) -> Result<(), RamImageError> {
            for region in layout.regions() {
                let mut local = 0;
                while local < region.length {
                    let len = (region.length - local).min(self.buffer.len() as u64) as usize;
                    self.read_live(cut, region.guest_start + local, len)?;
                    digests.update(region.stream_offset + local, &self.buffer[..len]);
                    self.sparse(len, region.stream_offset + local, WriteKind::Full)?;
                    local += len as u64;
                }
            }
            Ok(())
        }

        fn read_live(
            &mut self,
            cut: &MemoryCut,
            gpa: u64,
            len: usize,
        ) -> Result<(), RamImageError> {
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

        fn clean_run(
            &mut self,
            extents: &mut Extents<'_>,
            range: Range<u64>,
            digests: &mut ChunkDigests<'_>,
        ) -> Result<(), RamImageError> {
            let mut cursor = range.start;
            while cursor < range.end {
                let Some(data) = extents.next(cursor, self.stats, self.deadline)? else {
                    self.stats.baseline_hole_bytes += range.end - cursor;
                    digests.zeros(cursor..range.end);
                    break;
                };
                let start = data.start.min(range.end);
                self.stats.baseline_hole_bytes += start - cursor;
                digests.zeros(cursor..start);
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
                    digests.update(cursor, &self.buffer[..len]);
                    self.sparse(len, cursor, WriteKind::Baseline)?;
                    cursor += len as u64;
                }
            }
            Ok(())
        }

        fn seeded(
            &mut self,
            cut: &MemoryCut,
            layout: &ValidatedRamLayout,
            dirty: &DirtyPageMap,
            digests: &mut ChunkDigests<'_>,
        ) -> Result<(), RamImageError> {
            let mut pages = dirty.iter_set().peekable();
            let mut regions = layout.regions().iter();
            let mut region = regions.next().ok_or(RamImageError::Geometry)?;
            for word_index in 0..digests.affected.len() {
                let mut bits = digests.affected[word_index];
                while bits != 0 {
                    let index = word_index * 64 + bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    let mut offset = index as u64 * RAM_IDENTITY_CHUNK_BYTES;
                    let end = (offset + RAM_IDENTITY_CHUNK_BYTES).min(layout.packed_len());
                    while offset < end {
                        while offset >= region.stream_offset + region.length {
                            region = regions.next().ok_or(RamImageError::Geometry)?;
                        }
                        let local = offset - region.stream_offset;
                        let len = (end - offset)
                            .min(region.length - local)
                            .min(self.buffer.len() as u64)
                            as usize;
                        self.read_live(cut, region.guest_start + local, len)?;
                        digests.update(offset, &self.buffer[..len]);
                        let first_page = (offset / self.granule as u64) as usize;
                        let last_page = first_page + len / self.granule;
                        while pages.peek().is_some_and(|page| page.index() < last_page) {
                            let first = pages.next().ok_or(RamImageError::Bitmap)?.index();
                            let mut last = first + 1;
                            while pages.peek().is_some_and(|page| {
                                page.index() == last && page.index() < last_page
                            }) {
                                pages.next();
                                last += 1;
                            }
                            self.write_buffer(
                                (first - first_page) * self.granule
                                    ..(last - first_page) * self.granule,
                                first as u64 * self.granule as u64,
                                WriteKind::Overlay,
                            )?;
                        }
                        offset += len as u64;
                    }
                }
            }
            Ok(())
        }

        fn write_buffer(
            &mut self,
            range: Range<usize>,
            offset: u64,
            kind: WriteKind,
        ) -> Result<(), RamImageError> {
            write_exact_at(
                self.ram,
                &self.buffer[range.clone()],
                offset,
                kind,
                self.stats,
                self.deadline,
            )?;
            self.writeback
                .completed(self.ram, offset, range.len() as u64);
            Ok(())
        }

        fn incremental(
            &mut self,
            cut: &MemoryCut,
            layout: &ValidatedRamLayout,
            baseline: &File,
            dirty: &DirtyPageMap,
            digests: &mut ChunkDigests<'_>,
        ) -> Result<(), RamImageError> {
            let mut extents = Extents {
                file: baseline,
                length: layout.packed_len(),
                supported: true,
            };
            let mut clean_start = 0;
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
                let stream_offset = region.stream_offset + local;
                self.clean_run(&mut extents, clean_start..stream_offset, digests)?;
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
                digests.update(stream_offset, &self.buffer[..len]);
                self.write_buffer(0..len, stream_offset, WriteKind::Overlay)?;
                clean_start = stream_offset + len as u64;
            }
            self.clean_run(&mut extents, clean_start..layout.packed_len(), digests)
        }

        fn sparse(
            &mut self,
            len: usize,
            offset: u64,
            kind: WriteKind,
        ) -> Result<(), RamImageError> {
            let mut run = None;
            for start in (0..len).step_by(self.granule) {
                let end = (start + self.granule).min(len);
                if !is_all_zero(&self.buffer[start..end]) {
                    if run.is_none() {
                        run = Some(start);
                    }
                } else {
                    self.stats.zero_bytes_omitted += (end - start) as u64;
                    if let Some(first) = run.take() {
                        self.write_buffer(first..start, offset + first as u64, kind)?;
                    }
                }
            }
            if let Some(first) = run {
                self.write_buffer(first..len, offset + first as u64, kind)?;
            }
            Ok(())
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn binding() -> StateBinding {
        StateBinding {
            live_state_schema: crate::api::capabilities::LIVE_STATE_SCHEMA.into(),
            architecture: crate::api::capabilities::guest_architecture().into(),
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

    fn independent_digests(bytes: &[u8]) -> Vec<Option<[u8; 32]>> {
        bytes
            .chunks(RAM_IDENTITY_CHUNK_BYTES as usize)
            .map(|chunk| {
                chunk
                    .iter()
                    .any(|byte| *byte != 0)
                    .then(|| Sha256::digest(chunk).into())
            })
            .collect()
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
        assert_eq!(
            incremental.stats().live_bytes_read,
            if incremental.stats().seed_method == RamSeedMethod::Clone {
                layout.packed_len()
            } else {
                4 * 4096
            }
        );
        assert_eq!(incremental.stats().overlay_bytes_written, 4 * 4096);
        assert_eq!(incremental.stats().explicit_zero_bytes_written, 3 * 4096);
        if incremental.stats().seed_method == RamSeedMethod::Clone {
            assert_eq!(incremental.stats().baseline_bytes_read, 0);
            assert_eq!(incremental.stats().baseline_bytes_written, 0);
            assert_eq!(incremental.stats().extent_queries, 0);
        } else {
            assert_eq!(
                incremental.stats().baseline_bytes_read + incremental.stats().baseline_hole_bytes,
                layout.packed_len() - 4 * 4096
            );
            assert_eq!(incremental.stats().baseline_bytes_written, 3 * 4096);
        }
        assert_eq!(incremental.affected_chunks().collect::<Vec<_>>(), [0, 1]);
        assert_eq!(reference.stats().live_bytes_read, layout.packed_len());
        assert_eq!(baseline_files.bytes(), original);
        assert_eq!(full.chunk_digests(), independent_digests(&original));
        assert_eq!(
            incremental.chunk_digests(),
            independent_digests(&incremental_files.bytes())
        );
        assert_eq!(incremental.chunk_digests(), reference.chunk_digests());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn incremental_discard_writes_explicit_zeros_over_nonzero_baseline() {
        use arch::guest_memory::PageIndex;
        use devices::virtio::RuntimeGuestMemory;

        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4 * 4096)]).unwrap();
        raw.write_slice(&[0x6b; 4 * 4096], GuestAddress(0)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let first = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut receipt = capture(
            &first,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let original = baseline_files.bytes();
        let baseline = baseline_files.seal(&mut receipt);
        let epoch = first.issue_epoch(2).unwrap();
        control.reopen(&first, &epoch).unwrap();
        let memory = RuntimeGuestMemory::new(domain.clone());
        memory
            .try_write_access(2 * 4096, GuestAddress(4096), |_, len, _, view| {
                assert!(domain.host_page_dirty(PageIndex::new(1)).unwrap());
                assert!(domain.host_page_dirty(PageIndex::new(2)).unwrap());
                assert!(!domain.host_page_dirty(PageIndex::new(0)).unwrap());
                assert!(!domain.host_page_dirty(PageIndex::new(3)).unwrap());
                // nix's mman feature is not enabled for this crate.
                assert_eq!(
                    unsafe { libc::madvise(view.as_mut_ptr().cast(), len, libc::MADV_DONTNEED) },
                    0
                );
                Ok(len)
            })
            .unwrap();
        let second = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&second, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 2);
        let incremental_files = Outputs::new();
        let mut output = incremental_files.owned();
        output.protect_baseline(Some(baseline.clone()));
        let incremental = capture(
            &second,
            layout.clone(),
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        assert_eq!(incremental.stats().explicit_zero_bytes_written, 2 * 4096);
        assert_eq!(incremental.stats().overlay_bytes_written, 2 * 4096);
        let reference_files = Outputs::new();
        capture(&second, layout, RamWriteMode::Full, reference_files.owned());
        assert_eq!(incremental_files.bytes(), reference_files.bytes());
        assert_eq!(&incremental_files.bytes()[4096..3 * 4096], &[0; 2 * 4096]);
        assert_eq!(baseline_files.bytes(), original);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn rebuild_never_reads_inaccessible_clean_ram_even_with_no_dirties() {
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
            outputs.ram.as_file().set_len(layout.packed_len()).unwrap();
            let mut stats = RamIoStats::default();
            let affected = [u64::from(has_dirty)];
            let mut digests = pipeline::allocate_digests(layout.packed_len()).unwrap();
            pipeline::write(
                pipeline::Input {
                    cut: &current,
                    layout: &layout,
                    mode: &RamWriteMode::Incremental {
                        baseline: &baseline,
                        dirty: &dirty,
                    },
                    seeded: false,
                    deadline: deadline(),
                },
                outputs.ram.as_file(),
                &mut RamIoScratch::new().unwrap(),
                &mut stats,
                &affected,
                &mut digests,
            )
            .unwrap();
            let mut expected = baseline_files.bytes();
            if has_dirty {
                expected[4096..8192].fill(0);
            }
            assert_eq!(outputs.bytes(), expected);
            assert_eq!(stats.live_bytes_read, if has_dirty { 4096 } else { 0 });
            assert_eq!(
                stats.overlay_bytes_written,
                if has_dirty { 4096 } else { 0 }
            );
            assert_eq!(
                digests,
                if has_dirty {
                    independent_digests(&expected)
                } else {
                    vec![None]
                }
            );
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
            writeback: Writeback::default(),
        };
        let mut digests = ChunkDigests::new(3 * 4096, &[1]).unwrap();
        writer
            .clean_run(&mut extents, 0..4096, &mut digests)
            .unwrap();
        writer
            .clean_run(&mut extents, 8192..12288, &mut digests)
            .unwrap();
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
        assert_eq!(
            receipt.stats().live_bytes_read,
            if receipt.stats().seed_method == RamSeedMethod::Clone {
                length as u64
            } else {
                changed as u64
            }
        );
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
    fn real_enospc_propagates_at_helper_boundary() {
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
    }

    #[test]
    fn expired_completion_returns_real_finished_outputs_without_a_receipt() {
        use crate::vmm::memory::image::{allocate_chunks, preflight};

        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let layout = layout(&domain);
        let current = cut(&mut control);
        let files = Outputs::new();
        let output = files.owned();
        #[cfg(target_os = "linux")]
        let writers = {
            use std::os::fd::AsRawFd;
            [output.ram.as_raw_fd(), output.layout.as_raw_fd()].map(|fd| {
                (
                    fd,
                    std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap(),
                )
            })
        };
        let finished = capture(&current, layout.clone(), RamWriteMode::Full, output);
        assert!(finished.writers_closed());
        #[cfg(target_os = "linux")]
        for (fd, target) in writers {
            assert_ne!(
                std::fs::read_link(format!("/proc/self/fd/{fd}")).ok(),
                Some(target)
            );
        }
        let output = files.owned();
        let completed_facts = finished.output_identities();
        for (file, expected) in [
            (&output.ram, completed_facts[0]),
            (&output.layout, completed_facts[1]),
        ] {
            let metadata = file.metadata().unwrap();
            assert_eq!((metadata.dev(), metadata.ino(), metadata.len()), expected);
        }
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
            finished.chunk_digests().to_vec(),
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

    #[test]
    fn zero_check_classifies_uniform_granules() {
        assert!(is_all_zero(&[0; 4096]));
        assert!(!is_all_zero(&[0xff; 4096]));
    }

    #[test]
    fn zero_check_detects_every_single_byte_position_in_a_granule() {
        let mut granule = [0; 4096];
        for position in 0..granule.len() {
            for byte in [1, 0x80, 0xff] {
                granule[position] = byte;
                assert!(!is_all_zero(&granule), "position {position}, byte {byte}");
            }
            granule[position] = 0;
        }
    }

    #[test]
    fn zero_check_is_exact_for_unaligned_slices_and_every_tail_length() {
        let mut bytes = [0; 136];
        for start in 0..8 {
            for len in 0..=128 {
                assert!(is_all_zero(&bytes[start..start + len]));
                for position in start..start + len {
                    bytes[position] = 0x80;
                    assert!(
                        !is_all_zero(&bytes[start..start + len]),
                        "start {start}, len {len}, position {position}"
                    );
                    bytes[position] = 0;
                }
            }
        }
    }

    #[test]
    fn sparse_round_trip_matches_bytewise_reference_on_random_data() {
        let mut state = 0x49a2_870d_f6bc_315e_u64;
        let mut random = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for case in 0..32 {
            let len = case * 4096 + case * 3;
            let mut bytes = vec![0; len];
            for block in bytes.chunks_mut(4096) {
                match random() % 4 {
                    0 => {}
                    1 => block.fill(0xff),
                    2 => {
                        let position = random() as usize % block.len();
                        block[position] = 1 << (random() % 8);
                    }
                    _ => {
                        for byte in block {
                            *byte = random() as u8;
                        }
                    }
                }
            }
            let offset = if case % 2 == 0 { 0 } else { 8192 + 13 };
            for kind in [WriteKind::Full, WriteKind::Baseline] {
                let output = TempFile::new().unwrap();
                let reference = TempFile::new().unwrap();
                for file in [output.as_file(), reference.as_file()] {
                    file.set_len(offset + len as u64 + 4096).unwrap();
                    file.write_all_at(b"suffix", offset + len as u64).unwrap();
                }
                let mut actual_stats = RamIoStats::default();
                ImageWriter {
                    ram: output.as_file(),
                    buffer: &mut bytes,
                    stats: &mut actual_stats,
                    deadline: deadline(),
                    granule: 4096,
                    writeback: Writeback::default(),
                }
                .sparse(len, offset, kind)
                .unwrap();
                let mut reference_stats = RamIoStats::default();
                let mut run = None;
                for (index, block) in bytes.chunks(4096).enumerate() {
                    let start = index * 4096;
                    if block.iter().any(|byte| *byte != 0) {
                        if run.is_none() {
                            run = Some(start);
                        }
                    } else {
                        reference_stats.zero_bytes_omitted += block.len() as u64;
                        if let Some(first) = run.take() {
                            write_exact_at(
                                reference.as_file(),
                                &bytes[first..start],
                                offset + first as u64,
                                kind,
                                &mut reference_stats,
                                deadline(),
                            )
                            .unwrap();
                        }
                    }
                }
                if let Some(first) = run {
                    write_exact_at(
                        reference.as_file(),
                        &bytes[first..],
                        offset + first as u64,
                        kind,
                        &mut reference_stats,
                        deadline(),
                    )
                    .unwrap();
                }
                let actual = std::fs::read(output.as_path()).unwrap();
                assert_eq!(actual, std::fs::read(reference.as_path()).unwrap());
                assert_eq!(&actual[offset as usize..offset as usize + len], bytes);
                assert_eq!(actual_stats, reference_stats);
            }
        }
    }

    #[test]
    fn chunk_digests_preserve_zero_and_unaffected_chunks_across_regions() {
        let chunk = RAM_IDENTITY_CHUNK_BYTES;
        let raw = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), chunk as usize + 4096),
            (GuestAddress(64 * 1024 * 1024), 3 * chunk as usize),
        ])
        .unwrap();
        let address = |offset: u64| {
            GuestAddress(if offset < chunk + 4096 {
                offset
            } else {
                64 * 1024 * 1024 + offset - chunk - 4096
            })
        };
        for offset in [chunk - 4096, 2 * chunk, 3 * chunk, 4 * chunk] {
            raw.write_slice(&[0x5a; 4096], address(offset)).unwrap();
        }
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let first = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &first,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let expected = independent_digests(&baseline_files.bytes());
        assert_eq!(expected.len(), 5);
        assert_eq!(expected[1], None);
        assert!(expected[2].is_some());
        assert_eq!(full.chunk_digests(), expected);
        assert_eq!(full.affected_chunks().collect::<Vec<_>>(), [0, 1, 2, 3, 4]);
        let baseline = baseline_files.seal(&mut full);
        let epoch = first.issue_epoch(2).unwrap();
        control.reopen(&first, &epoch).unwrap();
        for (offset, byte) in [(chunk - 4096, 0), (3 * chunk + 4096, 0x91), (4 * chunk, 0)] {
            domain
                .write(address(offset), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[byte; 4096], 0)
                .unwrap();
        }
        let second = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&second, &mut dirty).unwrap();
        let outputs = Outputs::new();
        let mut output = outputs.owned();
        output.protect_baseline(Some(baseline.clone()));
        let incremental = capture(
            &second,
            layout.clone(),
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        let affected = incremental.affected_chunks().collect::<Vec<_>>();
        assert_eq!(affected, [0, 3, 4]);
        let bytes = outputs.bytes();
        let actual = independent_digests(&bytes);
        for (index, digest) in incremental.chunk_digests().iter().enumerate() {
            assert_eq!(
                *digest,
                if affected.contains(&index) {
                    actual[index]
                } else {
                    None
                }
            );
        }
        assert_eq!(actual[0], None);
        assert_eq!(actual[4], None);
        assert!(actual[2].is_some());
        assert_eq!(incremental.chunk_digests()[2], None);
        let reference_files = Outputs::new();
        let reference = capture(&second, layout, RamWriteMode::Full, reference_files.owned());
        assert_eq!(bytes, reference_files.bytes());
        assert_eq!(reference.chunk_digests(), actual);
    }

    #[test]
    fn repeated_capture_writes_identical_bytes_and_digests() {
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 3 * 4096)]).unwrap();
        raw.write_slice(&[0x5a; 4096], GuestAddress(4096)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let current = cut(&mut control);
        let sealed_files = Outputs::new();
        let sealed = capture(
            &current,
            layout.clone(),
            RamWriteMode::Full,
            sealed_files.owned(),
        );
        let fork_files = Outputs::new();
        let output = RamOutputFiles::new(
            fork_files.ram.as_file().try_clone().unwrap(),
            fork_files.layout.as_file().try_clone().unwrap(),
        );
        let fork = capture(&current, layout, RamWriteMode::Full, output);
        assert_eq!(fork_files.bytes(), sealed_files.bytes());
        assert_eq!(
            std::fs::read(fork_files.layout.as_path()).unwrap(),
            std::fs::read(sealed_files.layout.as_path()).unwrap()
        );
        assert_eq!(fork.chunk_digests(), sealed.chunk_digests());
        assert_eq!(fork.stats(), sealed.stats());
        assert!(fork.writers_closed());
    }

    #[test]
    fn seeded_and_rebuilt_images_match_across_regions_clean_chunks_and_short_tail() {
        let chunk = RAM_IDENTITY_CHUNK_BYTES;
        let first_length = chunk - 4096;
        let second_start = 64 * 1024 * 1024;
        let raw = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), first_length as usize),
            (GuestAddress(second_start), 2 * chunk as usize + 4 * 4096),
        ])
        .unwrap();
        let address = |offset| {
            GuestAddress(if offset < first_length {
                offset
            } else {
                second_start + offset - first_length
            })
        };
        for offset in [0, chunk - 4096, 2 * chunk + 4096, 3 * chunk + 8192] {
            raw.write_slice(&[0x5a; 4096], address(offset)).unwrap();
        }
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let first = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &first,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let original = baseline_files.bytes();
        let baseline = baseline_files.seal(&mut full);
        let epoch = first.issue_epoch(2).unwrap();
        control.reopen(&first, &epoch).unwrap();
        for (offset, byte) in [
            (0, 0),
            (chunk - 4096, 0x91),
            (chunk + 4096, 0x81),
            (3 * chunk + 8192, 0),
        ] {
            domain
                .write(address(offset), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[byte; 4096], 0)
                .unwrap();
        }
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let mut affected = allocate_chunks(&layout).unwrap();
        mark_chunks(
            &mut affected,
            &layout,
            &RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
        );
        let rebuilt = Outputs::new();
        let seeded = Outputs::new();
        rebuilt.ram.as_file().set_len(layout.packed_len()).unwrap();
        // This unit exercises overlay independently of host reflink support.
        // The syscall and its fallback are covered separately below.
        seeded.ram.as_file().write_all_at(&original, 0).unwrap();
        let mut scratch = RamIoScratch::new().unwrap();
        let mut rebuilt_stats = RamIoStats::default();
        let mut seeded_stats = RamIoStats {
            seed_method: RamSeedMethod::Clone,
            ..Default::default()
        };
        let mut rebuilt_digests = ChunkDigests::new(layout.packed_len(), &affected).unwrap();
        let mut seeded_digests = ChunkDigests::new(layout.packed_len(), &affected).unwrap();
        ImageWriter {
            ram: rebuilt.ram.as_file(),
            buffer: &mut scratch.buffers[0],
            stats: &mut rebuilt_stats,
            deadline: deadline(),
            granule: 4096,
            writeback: Writeback::default(),
        }
        .incremental(
            &current,
            &layout,
            &baseline.ram,
            &dirty,
            &mut rebuilt_digests,
        )
        .unwrap();
        ImageWriter {
            ram: seeded.ram.as_file(),
            buffer: &mut scratch.buffers[0],
            stats: &mut seeded_stats,
            deadline: deadline(),
            granule: 4096,
            writeback: Writeback::default(),
        }
        .seeded(&current, &layout, &dirty, &mut seeded_digests)
        .unwrap();
        let reference = Outputs::new();
        let reference_receipt = capture(&current, layout, RamWriteMode::Full, reference.owned());
        let expected = reference.bytes();
        assert_eq!(seeded.bytes(), rebuilt.bytes());
        assert_eq!(seeded.bytes(), expected);
        assert_eq!(baseline_files.bytes(), original);
        assert_eq!(seeded_digests.values, rebuilt_digests.values);
        for index in [0, 1, 3] {
            assert_eq!(
                seeded_digests.values[index],
                reference_receipt.chunk_digests()[index]
            );
        }
        assert_eq!(seeded_digests.values[2], None);
        assert!(reference_receipt.chunk_digests()[2].is_some());
        assert_eq!(seeded_digests.values[3], None);
        assert_eq!(&expected[..4096], &[0; 4096]);
        assert_eq!(&expected[3 * chunk as usize + 8192..], &[0; 4096]);
        assert_eq!(seeded_stats.live_bytes_read, 2 * chunk + 3 * 4096);
        assert_eq!(seeded_stats.overlay_bytes_written, 4 * 4096);
        assert_eq!(seeded_stats.explicit_zero_bytes_written, 2 * 4096);
        assert_eq!(seeded_stats.baseline_bytes_read, 0);
        assert_eq!(seeded_stats.baseline_bytes_written, 0);
        assert_eq!(seeded_stats.extent_queries, 0);
        assert_eq!(rebuilt_stats.live_bytes_read, 4 * 4096);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clone_failure_resets_destination_before_rebuild() {
        use nix::sys::memfd::{MFdFlags, memfd_create};

        let source = TempFile::new().unwrap();
        source.as_file().write_all_at(&[0x5a; 4096], 0).unwrap();
        let output = File::from(memfd_create(c"ram-rebuild-fallback", MFdFlags::empty()).unwrap());
        output.write_all_at(&[0xff; 8192], 0).unwrap();
        assert!(clone_baseline(source.as_file(), &output, 4096).is_err());
        assert_eq!(
            seed_incremental(source.as_file(), &output, 4096, deadline()).unwrap(),
            RamSeedMethod::Rebuild
        );
        let mut bytes = [0xff; 4096];
        output.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(output.metadata().unwrap().len(), 4096);
        assert_eq!(bytes, [0; 4096]);
        let mut stats = RamIoStats::default();
        let mut scratch = [0; 4096];
        let mut extents = Extents {
            file: source.as_file(),
            length: 4096,
            supported: false,
        };
        let mut digests = ChunkDigests::new(4096, &[1]).unwrap();
        ImageWriter {
            ram: &output,
            buffer: &mut scratch,
            stats: &mut stats,
            deadline: deadline(),
            granule: 4096,
            writeback: Writeback::default(),
        }
        .clean_run(&mut extents, 0..4096, &mut digests)
        .unwrap();
        output.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [0x5a; 4096]);
        assert_eq!(stats.baseline_bytes_read, 4096);
        assert_eq!(stats.baseline_bytes_written, 4096);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn incremental_clone_failure_rebuilds_complete_receipt() {
        use nix::sys::memfd::{MFdFlags, memfd_create};

        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 3 * 4096)]).unwrap();
        raw.write_slice(&[0x5a; 4096], GuestAddress(0)).unwrap();
        raw.write_slice(&[0x7f; 4096], GuestAddress(8192)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let first = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &first,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let original = baseline_files.bytes();
        let baseline = baseline_files.seal(&mut full);
        let epoch = first.issue_epoch(2).unwrap();
        control.reopen(&first, &epoch).unwrap();
        domain
            .write(GuestAddress(0), 4096)
            .unwrap()
            .write_view(0, 4096)
            .unwrap()
            .write_slice(&[0; 4096], 0)
            .unwrap();
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let ram = File::from(memfd_create(c"ram-receipt-fallback", MFdFlags::empty()).unwrap());
        ram.write_all_at(&[0xff; 4 * 4096], 0).unwrap();
        let outputs = Outputs::new();
        let mut output = RamOutputFiles::new(
            ram.try_clone().unwrap(),
            outputs.layout.as_file().try_clone().unwrap(),
        );
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
        let mut actual = vec![0; 3 * 4096];
        ram.read_exact_at(&mut actual, 0).unwrap();
        let mut expected = original.clone();
        expected[..4096].fill(0);
        assert_eq!(ram.metadata().unwrap().len(), expected.len() as u64);
        assert_eq!(actual, expected);
        assert_eq!(receipt.stats().seed_method, RamSeedMethod::Rebuild);
        assert_eq!(receipt.stats().live_bytes_read, 4096);
        assert_eq!(receipt.stats().baseline_bytes_written, 4096);
        assert_eq!(receipt.stats().overlay_bytes_written, 4096);
        assert_eq!(receipt.stats().explicit_zero_bytes_written, 4096);
        assert_eq!(receipt.chunk_digests(), independent_digests(&expected));
        assert_eq!(baseline_files.bytes(), original);
    }

    #[test]
    fn incomplete_clone_seed_is_discarded() {
        let source = TempFile::new().unwrap();
        source.as_file().write_all_at(&[0x5a; 4096], 0).unwrap();
        let output = TempFile::new().unwrap();
        assert_eq!(
            seed_incremental(source.as_file(), output.as_file(), 8192, deadline()).unwrap(),
            RamSeedMethod::Rebuild
        );
        assert_eq!(output.as_file().metadata().unwrap().len(), 8192);
        assert_eq!(std::fs::read(output.as_path()).unwrap(), vec![0; 8192]);
        assert_eq!(std::fs::read(source.as_path()).unwrap(), vec![0x5a; 4096]);
    }

    #[test]
    fn reflink_seed_preserves_source_after_zero_overlay_when_supported() {
        let source = TempFile::new().unwrap();
        source.as_file().set_len(3 * 4096).unwrap();
        source.as_file().write_all_at(&[0x5a; 4096], 4096).unwrap();
        let output = TempFile::new().unwrap();
        let method =
            seed_incremental(source.as_file(), output.as_file(), 3 * 4096, deadline()).unwrap();
        if method == RamSeedMethod::Rebuild {
            eprintln!(
                "reflink unavailable on test filesystem; run with a CoW TMPDIR to exercise clone"
            );
            return;
        }
        assert_ne!(
            source.as_file().metadata().unwrap().ino(),
            output.as_file().metadata().unwrap().ino()
        );
        assert_eq!(
            std::fs::read(source.as_path()).unwrap(),
            std::fs::read(output.as_path()).unwrap()
        );
        output.as_file().write_all_at(&[0; 4096], 4096).unwrap();
        let mut expected = vec![0; 3 * 4096];
        expected[4096..8192].fill(0x5a);
        assert_eq!(std::fs::read(source.as_path()).unwrap(), expected);
        assert_eq!(std::fs::read(output.as_path()).unwrap(), vec![0; 3 * 4096]);
    }

    #[test]
    fn zero_byte_count_matches_bytewise_oracle_for_values_alignment_and_tails() {
        let mut bytes = [0; 48];
        for start in 0..8 {
            for len in 0..=32 {
                for value in 0..=255u8 {
                    bytes.fill(value);
                    for index in (0..bytes.len()).step_by(3) {
                        bytes[index] = 0;
                    }
                    let slice = &bytes[start..start + len];
                    assert_eq!(
                        count_zero_bytes(slice),
                        slice.iter().filter(|byte| **byte == 0).count() as u64
                    );
                }
            }
        }
        for value in 0..=u16::MAX {
            let pair = value.to_ne_bytes();
            let bytes = [pair[0], pair[1], 0, 0x80, 0, 1, 0xff, 0];
            assert_eq!(
                count_zero_bytes(&bytes),
                bytes.iter().filter(|byte| **byte == 0).count() as u64
            );
        }
    }

    #[test]
    fn writeback_accumulates_contiguous_buffers_but_not_unwritten_gaps() {
        let output = TempFile::new().unwrap();
        let chunk = RAM_IDENTITY_CHUNK_BYTES;
        output.as_file().set_len(3 * chunk).unwrap();
        let mut writeback = Writeback::default();
        for index in 0..7 {
            writeback.completed(output.as_file(), index * 1024 * 1024, 1024 * 1024);
        }
        assert_eq!(writeback.pending, 0..7 * 1024 * 1024);
        writeback.completed(output.as_file(), 7 * 1024 * 1024, 1024 * 1024);
        assert_eq!(writeback.pending, chunk..chunk);
        writeback.completed(output.as_file(), chunk, 4096);
        writeback.completed(output.as_file(), 2 * chunk, 4096);
        assert_eq!(writeback.pending, 2 * chunk..2 * chunk + 4096);
    }

    fn compare_pipeline_with_serial(
        current: &MemoryCut,
        layout: &ValidatedRamLayout,
        mode: &RamWriteMode<'_>,
        seeded: bool,
        expected: &[u8],
    ) -> RamIoStats {
        let serial_files = Outputs::new();
        let pipelined_files = Outputs::new();
        for files in [&serial_files, &pipelined_files] {
            files.ram.as_file().set_len(layout.packed_len()).unwrap();
            if seeded && let RamWriteMode::Incremental { baseline, .. } = mode {
                let mut bytes = vec![0; layout.packed_len() as usize];
                baseline.ram.read_exact_at(&mut bytes, 0).unwrap();
                files.ram.as_file().write_all_at(&bytes, 0).unwrap();
            }
        }
        let mut affected = allocate_chunks(layout).unwrap();
        mark_chunks(&mut affected, layout, mode);
        let mut serial_digests = ChunkDigests::new(layout.packed_len(), &affected).unwrap();
        let mut serial_stats = RamIoStats::default();
        let mut buffer = vec![0; 1024 * 1024];
        let mut serial = ImageWriter {
            ram: serial_files.ram.as_file(),
            buffer: &mut buffer,
            stats: &mut serial_stats,
            deadline: deadline(),
            granule: layout.granule() as usize,
            writeback: Writeback::default(),
        };
        match mode {
            RamWriteMode::Full => serial.full(current, layout, &mut serial_digests),
            RamWriteMode::Incremental { baseline, dirty } => {
                if seeded {
                    serial.seeded(current, layout, dirty, &mut serial_digests)
                } else {
                    serial.incremental(current, layout, &baseline.ram, dirty, &mut serial_digests)
                }
            }
        }
        .unwrap();
        let mut digests = pipeline::allocate_digests(layout.packed_len()).unwrap();
        let mut stats = RamIoStats::default();
        pipeline::write(
            pipeline::Input {
                cut: current,
                layout,
                mode,
                seeded,
                deadline: deadline(),
            },
            pipelined_files.ram.as_file(),
            &mut RamIoScratch::new().unwrap(),
            &mut stats,
            &affected,
            &mut digests,
        )
        .unwrap();
        assert_eq!(serial_files.bytes(), expected);
        assert_eq!(pipelined_files.bytes(), expected);
        assert_eq!(digests, serial_digests.values);
        let mut independent = independent_digests(expected);
        for (index, digest) in independent.iter_mut().enumerate() {
            if affected[index / 64] & (1 << (index % 64)) == 0 {
                *digest = None;
            }
        }
        assert_eq!(digests, independent);
        assert_eq!(stats.live_bytes_read, serial_stats.live_bytes_read);
        assert_eq!(stats.full_bytes_written, serial_stats.full_bytes_written);
        assert_eq!(
            stats.baseline_bytes_written,
            serial_stats.baseline_bytes_written
        );
        assert_eq!(
            stats.overlay_bytes_written,
            serial_stats.overlay_bytes_written
        );
        assert_eq!(
            stats.explicit_zero_bytes_written,
            serial_stats.explicit_zero_bytes_written
        );
        stats
    }

    #[test]
    fn pipeline_matches_serial_for_zero_dense_sparse_packs_and_region_gaps() {
        let pack = crate::vmm::memory::image::RAM_IO_BUFFER_BYTES;
        for (dense, sparse, gaps) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, true, true),
        ] {
            let ranges = if gaps {
                vec![
                    (GuestAddress(0), pack + 4096),
                    (GuestAddress((2 * pack) as u64), 2 * pack),
                ]
            } else {
                vec![(GuestAddress(0), 3 * pack + 4096)]
            };
            let raw = GuestMemoryMmap::from_ranges(&ranges).unwrap();
            let mut expected = vec![0; 3 * pack + 4096];
            if dense {
                let mut state = 0x1c73_9a45_ef28_b60d_u64;
                for word in expected.chunks_exact_mut(8) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    word.copy_from_slice(&state.to_ne_bytes());
                }
            }
            if sparse {
                for start in [
                    0,
                    pack - 4096,
                    pack,
                    pack + 4096,
                    2 * pack - 4096,
                    2 * pack,
                    3 * pack,
                ] {
                    expected[start..start + 4096].fill(0x5b);
                }
            }
            if dense || sparse {
                let mut offset = 0;
                for (address, length) in &ranges {
                    raw.write_slice(&expected[offset..offset + length], *address)
                        .unwrap();
                    offset += length;
                }
            }
            let (domain, mut control) = tracked(raw);
            let layout = layout(&domain);
            let current = cut(&mut control);
            let stats = compare_pipeline_with_serial(
                &current,
                &layout,
                &RamWriteMode::Full,
                false,
                &expected,
            );
            assert_eq!(stats.live_bytes_read, layout.packed_len());
            if !dense && !sparse {
                assert_eq!(stats.zero_bytes_omitted, layout.packed_len());
                assert_eq!(stats.full_bytes_written, 0);
            }
        }
    }

    #[test]
    fn pipeline_incremental_matches_serial_for_rebuild_and_seeded_zero_overlays() {
        let pack = crate::vmm::memory::image::RAM_IO_BUFFER_BYTES;
        let ranges = [
            (GuestAddress(0), pack + 4096),
            (GuestAddress((2 * pack) as u64), 2 * pack),
        ];
        let raw = GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let original = vec![0x6d; 3 * pack + 4096];
        let mut offset = 0;
        for (address, length) in ranges {
            raw.write_slice(&original[offset..offset + length], address)
                .unwrap();
            offset += length;
        }
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut receipt = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let baseline = baseline_files.seal(&mut receipt);
        let epoch = initial.issue_epoch(2).unwrap();
        control.reopen(&initial, &epoch).unwrap();
        let mut expected = original.clone();
        for (index, start) in [pack - 4096, pack, pack + 4096, 2 * pack, 3 * pack]
            .into_iter()
            .enumerate()
        {
            let byte = if index == 3 { 0x37 } else { 0 };
            let region = layout
                .regions()
                .iter()
                .find(|region| {
                    start as u64 >= region.stream_offset
                        && (start as u64) < region.stream_offset + region.length
                })
                .unwrap();
            let address = region.guest_start + start as u64 - region.stream_offset;
            domain
                .write(GuestAddress(address), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[byte; 4096], 0)
                .unwrap();
            expected[start..start + 4096].fill(byte);
        }
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 5);
        let mode = RamWriteMode::Incremental {
            baseline: &baseline,
            dirty: &dirty,
        };
        for seeded in [false, true] {
            let stats = compare_pipeline_with_serial(&current, &layout, &mode, seeded, &expected);
            assert_eq!(stats.overlay_bytes_written, 5 * 4096);
            assert_eq!(stats.explicit_zero_bytes_written, 4 * 4096);
            if !seeded {
                assert_eq!(stats.live_bytes_read, 5 * 4096);
            }
        }
        assert_eq!(baseline_files.bytes(), original);
    }

    #[test]
    fn pipeline_read_only_write_error_joins_workers_and_reuses_scratch() {
        let pack = crate::vmm::memory::image::RAM_IO_BUFFER_BYTES;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4 * pack)]).unwrap();
        for offset in (0..4 * pack).step_by(pack) {
            raw.write_slice(&[0x7a; 4096], GuestAddress(offset as u64))
                .unwrap();
        }
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let current = cut(&mut control);
        let file = TempFile::new().unwrap();
        file.as_file().set_len(layout.packed_len()).unwrap();
        let read_only = File::open(file.as_path()).unwrap();
        let mut scratch = RamIoScratch::new().unwrap();
        let affected = [u64::MAX];
        let mut digests = pipeline::allocate_digests(layout.packed_len()).unwrap();
        let mut stats = RamIoStats::default();
        let started = Instant::now();
        let error = pipeline::write(
            pipeline::Input {
                cut: &current,
                layout: &layout,
                mode: &RamWriteMode::Full,
                seeded: false,
                deadline: deadline(),
            },
            &read_only,
            &mut scratch,
            &mut stats,
            &affected,
            &mut digests,
        )
        .unwrap_err();
        assert!(matches!(error, RamImageError::Io {
            operation: RamIoOperation::Write, role: RamFileRole::OutputRam, source,
        } if source.raw_os_error() == Some(nix::errno::Errno::EBADF as i32)));
        assert!(started.elapsed() < Duration::from_secs(30));
        assert_eq!(stats.full_bytes_written, 0);
        pipeline::write(
            pipeline::Input {
                cut: &current,
                layout: &layout,
                mode: &RamWriteMode::Full,
                seeded: false,
                deadline: deadline(),
            },
            file.as_file(),
            &mut scratch,
            &mut stats,
            &affected,
            &mut digests,
        )
        .unwrap();
        assert_eq!(stats.full_bytes_written, 4 * 4096);
        assert_eq!(
            digests,
            independent_digests(&std::fs::read(file.as_path()).unwrap())
        );
    }

    #[test]
    fn pipeline_expired_deadline_joins_idle_workers_without_reading() {
        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let layout = layout(&domain);
        let current = cut(&mut control);
        let output = TempFile::new().unwrap();
        let mut stats = RamIoStats::default();
        let error = pipeline::write(
            pipeline::Input {
                cut: &current,
                layout: &layout,
                mode: &RamWriteMode::Full,
                seeded: false,
                deadline: Instant::now(),
            },
            output.as_file(),
            &mut RamIoScratch::new().unwrap(),
            &mut stats,
            &[1],
            &mut pipeline::allocate_digests(layout.packed_len()).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, RamImageError::Deadline));
        assert_eq!(stats.live_bytes_read, 0);
        assert_eq!(output.as_file().metadata().unwrap().len(), 0);
    }
}
