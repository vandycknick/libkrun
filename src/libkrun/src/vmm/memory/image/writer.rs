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
#[cfg(target_os = "linux")]
use nix::fcntl::{FallocateFlags, fallocate};
use nix::unistd::{Whence, lseek};

use crate::vmm::control::BarrierKey;
use crate::vmm::execution::StateBinding;
use crate::vmm::memory::AttemptId;
use crate::vmm::memory::image::changes::ChangeWriter;
use crate::vmm::memory::image::{
    RAM_IDENTITY_CHUNK_BYTES, RamCaptureIdentity, RamCaptureMode, RamCaptureReceipt, RamFileRole,
    RamHashSelection, RamIdentityAnchor, RamIdentityReceipt, RamImageEffects, RamImageError,
    RamImageFailure, RamIoOperation, RamIoScratch, RamIoStats, RamOutputFiles, RamSeedMethod,
    RamWriteMode, ValidatedRamLayout, check_deadline, io_error, preflight,
};

mod pipeline;

// Smaller interior holes cause extent fragmentation that makes reflink clones costly.
const MIN_ZERO_HOLE_BYTES: usize = RAM_IDENTITY_CHUNK_BYTES as usize;

// Failure must retain staging owners without a new allocation after output effects.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub fn write_ram_image(
    attempt: AttemptId,
    key: BarrierKey,
    cut: &MemoryCut,
    binding: &StateBinding,
    layout: Arc<ValidatedRamLayout>,
    identity: RamCaptureIdentity<'_>,
    mode: RamWriteMode<'_>,
    output: RamOutputFiles,
    scratch: &mut RamIoScratch,
    deadline: Instant,
) -> Result<RamCaptureReceipt, RamImageFailure> {
    let mut stats = RamIoStats {
        logical_bytes: layout.packed_len(),
        identity_dirty_pages: identity.identity_dirty_pages as u64,
        materialization_dirty_pages: identity.materialization_dirty_pages as u64,
        ..RamIoStats::default()
    };
    let mut effects = RamImageEffects::None;
    let selected = match &mode {
        RamWriteMode::Full => RamCaptureMode::Full,
        RamWriteMode::Incremental { .. } => RamCaptureMode::Incremental,
    };
    let result = (|| {
        check_deadline(deadline)?;
        if let RamHashSelection::SinceAnchor { stream, dirty } = identity.selection {
            if identity.anchor != (RamIdentityAnchor::Identified { stream })
                || matches!(
                    identity.anchor_generation,
                    crate::vmm::memory::image::RamIdentityGeneration::Unknown
                )
                || !cut.domain().coverage_valid()
                || dirty.page_count() != cut.domain().layout().page_count()
            {
                return Err(RamImageError::Completion);
            }
            if let RamWriteMode::Incremental { dirty: writes, .. } = &mode
                && writes
                    .words()
                    .iter()
                    .zip(dirty.words())
                    .any(|(writes, hashes)| writes & !hashes != 0)
            {
                return Err(RamImageError::Bitmap);
            }
        }
        let preparation = preflight(cut, binding, &layout, &mode, &output, deadline)?;
        let mut changes = match identity.selection {
            RamHashSelection::None => ChangeWriter::None,
            RamHashSelection::Full => ChangeWriter::new(
                &output.changes,
                RamCaptureMode::Full,
                None,
                layout.packed_len().div_ceil(RAM_IDENTITY_CHUNK_BYTES),
                deadline,
            )?,
            RamHashSelection::SinceAnchor { stream, .. } => ChangeWriter::new(
                &output.changes,
                RamCaptureMode::Incremental,
                Some(stream),
                layout.packed_len().div_ceil(RAM_IDENTITY_CHUNK_BYTES),
                deadline,
            )?,
        };
        check_deadline(deadline)?;
        set_length(&output.ram, RamFileRole::OutputRam, 0, deadline)?;
        effects = RamImageEffects::Started;
        set_length(&output.layout, RamFileRole::OutputLayout, 0, deadline)?;
        set_length(&output.changes, RamFileRole::OutputChanges, 0, deadline)?;
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
                byte_baseline: identity.byte_baseline,
                cut,
                layout: &layout,
                mode: &mode,
                identity: &identity.selection,
                seeded: stats.seed_method == RamSeedMethod::Clone,
                deadline,
            },
            &output.ram,
            scratch,
            &mut stats,
            &mut changes,
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
        Ok((preparation, changes.finish()?))
    })();
    let (preparation, changes) = match result {
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
        RamIdentityReceipt {
            policy: identity.selection.policy(),
            anchor: identity.anchor,
            anchor_generation: identity.anchor_generation,
            predecessor_generation: identity.predecessor_generation,
        },
        output,
        stats.clone(),
        changes,
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

#[cfg(test)]
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
        if self.pending.end - self.pending.start >= 8 * 1024 * 1024 {
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

fn cover_zero(
    file: &File,
    range: Range<u64>,
    seeded: bool,
    stats: &mut RamIoStats,
    deadline: Instant,
) -> Result<(), RamImageError> {
    check_deadline(deadline)?;
    let length = range.end - range.start;
    if seeded {
        if punch_zero(file, range.clone(), deadline)? {
            stats.zero_bytes_punched += length;
        } else {
            let zeros = [0; 65536];
            let mut offset = range.start;
            while offset < range.end {
                let count = (range.end - offset).min(zeros.len() as u64) as usize;
                write_exact_at(
                    file,
                    &zeros[..count],
                    offset,
                    WriteKind::Overlay,
                    stats,
                    deadline,
                )?;
                offset += count as u64;
            }
        }
    } else {
        stats.zero_bytes_omitted += length;
    }
    stats.zero_run_bytes_covered += length;
    Ok(())
}

#[cfg(target_os = "linux")]
fn punch_zero(file: &File, range: Range<u64>, deadline: Instant) -> Result<bool, RamImageError> {
    let offset = i64::try_from(range.start).map_err(|_| RamImageError::Geometry)?;
    let length = i64::try_from(range.end - range.start).map_err(|_| RamImageError::Geometry)?;
    loop {
        check_deadline(deadline)?;
        match fallocate(
            file,
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE,
            offset,
            length,
        ) {
            Ok(()) => return Ok(true),
            Err(Errno::EINTR) => continue,
            Err(Errno::EOPNOTSUPP | Errno::ENOSYS | Errno::EINVAL) => return Ok(false),
            Err(error) => {
                return Err(io_error(
                    RamIoOperation::Write,
                    RamFileRole::OutputRam,
                    error.into(),
                ));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn punch_zero(_file: &File, _range: Range<u64>, _deadline: Instant) -> Result<bool, RamImageError> {
    Ok(false)
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
    use crate::vmm::memory::image::changes::{ChangeWriter, read_test_changes};
    use crate::vmm::memory::image::writer::{
        Extents, MIN_ZERO_HOLE_BYTES, WriteKind, Writeback, account_write, check_deadline,
        clone_baseline, count_zero_bytes, cover_zero, io_error, is_all_zero, mark_chunks, read_exact_at,
        seed_incremental, write_exact_at, write_ram_image,
    };
    use crate::vmm::memory::image::{
        AdmittedRamImage, RAM_IDENTITY_CHUNK_BYTES, RamCaptureIdentity, RamCaptureReceipt,
        RamFileRole, RamHashSelection, RamIdentityAnchor, RamIdentityReceipt,
        RamImageAuthentication, RamImageEffects, RamImageError, RamInputAuthority, RamIoOperation,
        RamIoScratch, RamIoStats, RamOutputFiles, RamSeedMethod, RamWriteMode, ValidatedRamLayout,
        seal_completed,
    };

    fn allocate_chunks(layout: &ValidatedRamLayout) -> Result<Vec<u64>, RamImageError> {
        Ok(vec![
            0;
            layout
                .packed_len()
                .div_ceil(RAM_IDENTITY_CHUNK_BYTES)
                .div_ceil(64) as usize
        ])
    }

    // Only the independent serial oracle expands a dense map in tests.
    mod pipeline {
        use crate::vmm::memory::image::writer::pipeline as native;
        use crate::vmm::memory::image::writer::tests::{ChangeWriter, read_test_changes};
        use crate::vmm::memory::image::{
            RAM_IDENTITY_CHUNK_BYTES, RamCaptureMode, RamIdentityAnchor, RamImageError,
            RamIoScratch, RamIoStats, RamWriteMode,
        };
        pub(crate) use native::Input;
        use std::fs::File;
        use vmm_sys_util::tempfile::TempFile;

        pub(crate) fn allocate_digests(
            length: u64,
        ) -> Result<Vec<Option<[u8; 32]>>, RamImageError> {
            Ok(vec![
                None;
                length.div_ceil(RAM_IDENTITY_CHUNK_BYTES) as usize
            ])
        }

        pub(crate) fn write(
            input: Input<'_>,
            ram: &File,
            scratch: &mut RamIoScratch,
            stats: &mut RamIoStats,
            _affected: &[u64],
            digests: &mut [Option<[u8; 32]>],
        ) -> Result<(), RamImageError> {
            let file = TempFile::new().unwrap();
            let (mode, baseline) = match input.mode {
                RamWriteMode::Full => (RamCaptureMode::Full, None),
                RamWriteMode::Incremental { baseline, .. } => (
                    RamCaptureMode::Incremental,
                    Some(match baseline.authority().identity_anchor() {
                        RamIdentityAnchor::Identified { stream } => stream,
                        RamIdentityAnchor::Unknown => panic!("identified fixture required"),
                    }),
                ),
            };
            let mut changes = ChangeWriter::new(
                file.as_file(),
                mode,
                baseline,
                input.layout.packed_len().div_ceil(RAM_IDENTITY_CHUNK_BYTES),
                input.deadline,
            )?;
            native::write(input, ram, scratch, stats, &mut changes)?;
            changes.finish()?;
            for (index, digest) in read_test_changes(file.as_file()) {
                digests[index as usize] = digest;
            }
            Ok(())
        }
    }
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
            let mut start = 0;
            while start < len {
                let end = (start + self.granule).min(len);
                if !is_all_zero(&self.buffer[start..end]) {
                    if run.is_none() {
                        run = Some(start);
                    }
                    start = end;
                    continue;
                }
                let first_zero = start;
                start = end;
                while start < len
                    && is_all_zero(&self.buffer[start..(start + self.granule).min(len)])
                {
                    start = (start + self.granule).min(len);
                }
                if run.is_some() && start < len && start - first_zero < MIN_ZERO_HOLE_BYTES {
                    continue;
                }
                self.stats.zero_bytes_omitted += (start - first_zero) as u64;
                if let Some(first) = run.take() {
                    self.write_buffer(first..first_zero, offset + first as u64, kind)?;
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
        changes: TempFile,
    }

    impl Outputs {
        fn new() -> Self {
            Self {
                ram: TempFile::new().unwrap(),
                layout: TempFile::new().unwrap(),
                changes: TempFile::new().unwrap(),
            }
        }
        fn owned(&self) -> RamOutputFiles {
            RamOutputFiles::new(
                self.ram.as_file().try_clone().unwrap(),
                self.layout.as_file().try_clone().unwrap(),
                self.changes.as_file().try_clone().unwrap(),
            )
        }
        fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.ram.as_path()).unwrap()
        }
        fn digests(&self) -> Vec<Option<[u8; 32]>> {
            let mut digests = vec![
                None;
                self.ram
                    .as_file()
                    .metadata()
                    .unwrap()
                    .len()
                    .div_ceil(RAM_IDENTITY_CHUNK_BYTES) as usize
            ];
            for (index, digest) in read_test_changes(self.changes.as_file()) {
                digests[index as usize] = digest;
            }
            digests
        }
        fn indices(&self) -> Vec<usize> {
            read_test_changes(self.changes.as_file())
                .keys()
                .map(|index| *index as usize)
                .collect()
        }
        fn seal(&self, receipt: &mut RamCaptureReceipt) -> Arc<AdmittedRamImage> {
            Arc::new(
                seal_completed(
                    receipt,
                    File::open(self.ram.as_path()).unwrap(),
                    File::open(self.layout.as_path()).unwrap(),
                    RamInputAuthority::IdentifiedSnapshot(RamImageAuthentication {
                        state: binding(),
                        stream: [0; 32],
                    }),
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
            RamCaptureIdentity::for_test(&mode),
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
        assert_eq!(
            full.stats().live_bytes_read + full.stats().known_zero_bytes_skipped,
            layout.packed_len()
        );
        assert_eq!(full.stats().full_bytes_written, 8 * 4096);
        assert_eq!(baseline_files.indices(), [0, 15, 16, 127, 128]);
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
                RAM_IDENTITY_CHUNK_BYTES + 2 * 4096
            } else {
                4 * 4096
            }
        );
        assert_eq!(
            incremental.stats().zero_run_bytes_covered,
            if incremental.stats().seed_method == RamSeedMethod::Clone {
                3 * 4096
            } else {
                4 * 4096
            }
        );
        assert_eq!(
            incremental.stats().overlay_bytes_written,
            4096 + incremental.stats().explicit_zero_bytes_written
        );
        assert!(incremental.stats().explicit_zero_bytes_written <= 3 * 4096);
        if incremental.stats().seed_method == RamSeedMethod::Clone {
            assert_eq!(incremental.stats().baseline_bytes_read, 0);
            assert_eq!(incremental.stats().baseline_hole_bytes, 0);
            assert_eq!(incremental.stats().baseline_bytes_written, 0);
            assert_eq!(incremental.stats().extent_queries, 0);
        } else {
            assert_eq!(
                incremental.stats().baseline_bytes_read + incremental.stats().baseline_hole_bytes,
                layout.packed_len() - 4 * 4096
            );
            assert_eq!(incremental.stats().baseline_bytes_written, 3 * 4096);
        }
        assert_eq!(incremental_files.indices(), [0, 128]);
        assert_eq!(
            reference.stats().live_bytes_read + reference.stats().known_zero_bytes_skipped,
            layout.packed_len()
        );
        assert_eq!(baseline_files.bytes(), original);
        assert_eq!(baseline_files.digests(), independent_digests(&original));
        for (index, digest) in read_test_changes(incremental_files.changes.as_file()) {
            assert_eq!(
                digest,
                independent_digests(&incremental_files.bytes())[index as usize]
            );
        }
        let mut resolved = baseline_files.digests();
        for (index, digest) in read_test_changes(incremental_files.changes.as_file()) {
            resolved[index as usize] = digest;
        }
        assert_eq!(resolved, reference_files.digests());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn incremental_discard_covers_zero_runs_over_nonzero_baseline() {
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
        assert_eq!(incremental.stats().zero_run_bytes_covered, 2 * 4096);
        assert_eq!(
            incremental.stats().overlay_bytes_written,
            incremental.stats().explicit_zero_bytes_written
        );
        assert!(incremental.stats().explicit_zero_bytes_written <= 2 * 4096);
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
                    byte_baseline: None,
                    cut: &current,
                    layout: &layout,
                    mode: &RamWriteMode::Incremental {
                        baseline: &baseline,
                        dirty: &dirty,
                    },
                    identity: &RamHashSelection::SinceAnchor {
                        stream: [0; 32],
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
            assert_eq!(stats.overlay_bytes_written, 0);
            assert_eq!(stats.explicit_zero_bytes_written, 0);
            assert_eq!(
                stats.zero_run_bytes_covered,
                if has_dirty { 4096 } else { 0 }
            );
            assert_eq!(stats.zero_bytes_omitted, if has_dirty { 4096 } else { 0 });
            assert_eq!(stats.zero_bytes_punched, 0);
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
            TempFile::new().unwrap().as_file().try_clone().unwrap(),
        );
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout.clone(),
            RamCaptureIdentity::for_test(&RamWriteMode::Full),
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
            RamCaptureIdentity::for_test(&RamWriteMode::Full),
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
                    TempFile::new().unwrap().as_file().try_clone().unwrap(),
                )
            } else {
                RamOutputFiles::new(
                    original_files.ram.as_file().try_clone().unwrap(),
                    scratch_files.layout.as_file().try_clone().unwrap(),
                    TempFile::new().unwrap().as_file().try_clone().unwrap(),
                )
            };
            output.protect_baseline(Some(original_image.clone()));
            let failure = write_ram_image(
                AttemptId::for_test(),
                key(),
                &current,
                &binding(),
                layout.clone(),
                RamCaptureIdentity::for_test(&RamWriteMode::Full),
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
            TempFile::new().unwrap().as_file().try_clone().unwrap(),
        );
        output.protect_baseline(Some(newer_image));
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &mapped_cut,
            &binding(),
            layout,
            RamCaptureIdentity::for_test(&RamWriteMode::Full),
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
        assert_eq!(
            initial_receipt.stats().live_bytes_read
                + initial_receipt.stats().known_zero_bytes_skipped,
            length as u64
        );
        assert_eq!(initial_receipt.stats().full_bytes_written, 0);
        assert_eq!(initial_receipt.stats().zero_bytes_omitted, length as u64);
        assert_eq!(
            initial_receipt
                .changes()
                .identified()
                .unwrap()
                .record_count(),
            0
        );
        assert_eq!(
            initial_receipt.changes().identified().unwrap().byte_len(),
            16
        );
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
        let output = RamOutputFiles::new(
            files.ram.as_file().try_clone().unwrap(),
            sealed_layout,
            TempFile::new().unwrap().as_file().try_clone().unwrap(),
        );
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout,
            RamCaptureIdentity::for_test(&RamWriteMode::Full),
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
            RamCaptureIdentity::for_test(&RamWriteMode::Full),
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
        use crate::vmm::memory::image::preflight;

        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let layout = layout(&domain);
        let current = cut(&mut control);
        let files = Outputs::new();
        let output = files.owned();
        #[cfg(target_os = "linux")]
        let writers = {
            use std::os::fd::AsRawFd;
            [
                output.ram.as_raw_fd(),
                output.layout.as_raw_fd(),
                output.changes.as_raw_fd(),
            ]
            .map(|fd| {
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
            (&output.changes, completed_facts[2]),
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
            RamIdentityReceipt {
                policy: *finished.identity_policy(),
                anchor: finished.identity_anchor(),
                anchor_generation: finished.identity_anchor_generation(),
                predecessor_generation: finished.predecessor_generation(),
            },
            output,
            finished.stats().clone(),
            finished.changes().clone(),
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
                let mut data: Vec<bool> = bytes
                    .chunks(4096)
                    .map(|block| block.iter().any(|byte| *byte != 0))
                    .collect();
                let mut index = 0;
                while index < data.len() {
                    if data[index] {
                        index += 1;
                        continue;
                    }
                    let first = index;
                    while index < data.len() && !data[index] {
                        index += 1;
                    }
                    let end = (index * 4096).min(len);
                    if first > 0 && index < data.len() && end - first * 4096 < MIN_ZERO_HOLE_BYTES {
                        data[first..index].fill(true);
                    }
                }
                for (index, block) in bytes.chunks(4096).enumerate() {
                    if data[index] {
                        write_exact_at(
                            reference.as_file(),
                            block,
                            offset + (index * 4096) as u64,
                            kind,
                            &mut reference_stats,
                            deadline(),
                        )
                        .unwrap();
                    } else {
                        reference_stats.zero_bytes_omitted += block.len() as u64;
                    }
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
        assert_eq!(baseline_files.digests(), expected);
        assert_eq!(baseline_files.indices(), [0, 2, 3, 4]);
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
        let _incremental = capture(
            &second,
            layout.clone(),
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        let affected = outputs.indices();
        assert_eq!(affected, [0, 3, 4]);
        let bytes = outputs.bytes();
        let actual = independent_digests(&bytes);
        for (index, digest) in outputs.digests().iter().enumerate() {
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
        assert_eq!(outputs.digests()[2], None);
        let reference_files = Outputs::new();
        let _reference = capture(&second, layout, RamWriteMode::Full, reference_files.owned());
        assert_eq!(bytes, reference_files.bytes());
        assert_eq!(reference_files.digests(), actual);
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
        let output = fork_files.owned();
        let fork = capture(&current, layout, RamWriteMode::Full, output);
        assert_eq!(fork_files.bytes(), sealed_files.bytes());
        assert_eq!(
            std::fs::read(fork_files.layout.as_path()).unwrap(),
            std::fs::read(sealed_files.layout.as_path()).unwrap()
        );
        assert_eq!(fork_files.digests(), sealed_files.digests());
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
        let _reference_receipt = capture(&current, layout, RamWriteMode::Full, reference.owned());
        let expected = reference.bytes();
        assert_eq!(seeded.bytes(), rebuilt.bytes());
        assert_eq!(seeded.bytes(), expected);
        assert_eq!(baseline_files.bytes(), original);
        assert_eq!(seeded_digests.values, rebuilt_digests.values);
        for index in [0, 1, 3] {
            assert_eq!(seeded_digests.values[index], reference.digests()[index]);
        }
        assert_eq!(seeded_digests.values[2], None);
        assert!(reference.digests()[2].is_some());
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
            outputs.changes.as_file().try_clone().unwrap(),
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
        assert_eq!(receipt.stats().overlay_bytes_written, 0);
        assert_eq!(receipt.stats().explicit_zero_bytes_written, 0);
        assert_eq!(receipt.stats().zero_run_bytes_covered, 2 * 4096);
        assert_eq!(
            read_test_changes(outputs.changes.as_file()).get(&0),
            Some(&independent_digests(&expected)[0])
        );
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
        let allocated = output.as_file().metadata().unwrap().blocks();
        let mut stats = RamIoStats::default();
        cover_zero(output.as_file(), 4096..8192, true, &mut stats, deadline()).unwrap();
        assert_eq!(stats.zero_run_bytes_covered, 4096);
        if stats.zero_bytes_punched != 0 {
            assert_eq!(stats.explicit_zero_bytes_written, 0);
            assert!(output.as_file().metadata().unwrap().blocks() < allocated);
        } else {
            assert_eq!(stats.explicit_zero_bytes_written, 4096);
        }
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
        let chunk = 8 * 1024 * 1024;
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
                byte_baseline: None,
                cut: current,
                layout,
                mode,
                identity: &RamCaptureIdentity::for_test(mode).selection,
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
        assert_eq!(
            stats.live_bytes_read + stats.known_zero_bytes_skipped,
            serial_stats.live_bytes_read
        );
        assert_eq!(stats.full_bytes_written, serial_stats.full_bytes_written);
        assert_eq!(
            stats.baseline_bytes_written,
            serial_stats.baseline_bytes_written
        );
        assert!(stats.overlay_bytes_written <= serial_stats.overlay_bytes_written);
        assert!(stats.explicit_zero_bytes_written <= serial_stats.explicit_zero_bytes_written);
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
            assert_eq!(
                stats.live_bytes_read + stats.known_zero_bytes_skipped,
                layout.packed_len()
            );
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
            assert_eq!(stats.zero_run_bytes_covered, 4 * 4096);
            assert_eq!(
                stats.overlay_bytes_written,
                4096 + stats.explicit_zero_bytes_written
            );
            assert!(stats.explicit_zero_bytes_written <= 4 * 4096);
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
                byte_baseline: None,
                cut: &current,
                layout: &layout,
                mode: &RamWriteMode::Full,
                identity: &RamHashSelection::Full,
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
                byte_baseline: None,
                cut: &current,
                layout: &layout,
                mode: &RamWriteMode::Full,
                identity: &RamHashSelection::Full,
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
                byte_baseline: None,
                cut: &current,
                layout: &layout,
                mode: &RamWriteMode::Full,
                identity: &RamHashSelection::Full,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn full_pagemap_capture_matches_full_read_oracle_before_faulting_untouched_ram() {
        let pack = crate::vmm::memory::image::RAM_IO_BUFFER_BYTES;
        let second = (4 * pack) as u64;
        let raw = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 2 * pack + 4096),
            (GuestAddress(second), 3 * 4096),
        ])
        .unwrap();
        raw.write_slice(&[0x57; 4096], GuestAddress(4096)).unwrap();
        raw.write_slice(&[0; 4096], GuestAddress(8192)).unwrap();
        raw.write_slice(&[0x93; 4096], GuestAddress((2 * pack) as u64))
            .unwrap();
        raw.write_slice(&[0x41; 4096], GuestAddress(second + 8192))
            .unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let current = cut(&mut control);
        let optimized = Outputs::new();
        let receipt = capture(
            &current,
            layout.clone(),
            RamWriteMode::Full,
            optimized.owned(),
        );
        assert!(receipt.stats().known_zero_bytes_skipped > 0);
        assert!(receipt.stats().live_bytes_read >= 4 * 4096);
        assert_eq!(
            receipt.stats().live_bytes_read + receipt.stats().known_zero_bytes_skipped,
            layout.packed_len()
        );
        let oracle = Outputs::new();
        oracle.ram.as_file().set_len(layout.packed_len()).unwrap();
        let mut affected = allocate_chunks(&layout).unwrap();
        mark_chunks(&mut affected, &layout, &RamWriteMode::Full);
        let mut digests = ChunkDigests::new(layout.packed_len(), &affected).unwrap();
        let mut stats = RamIoStats::default();
        let mut buffer = vec![0; 1024 * 1024];
        ImageWriter {
            ram: oracle.ram.as_file(),
            buffer: &mut buffer,
            stats: &mut stats,
            deadline: deadline(),
            granule: 4096,
            writeback: Writeback::default(),
        }
        .full(&current, &layout, &mut digests)
        .unwrap();
        assert_eq!(stats.live_bytes_read, layout.packed_len());
        assert_eq!(optimized.bytes(), oracle.bytes());
        assert_eq!(optimized.digests(), digests.values);
        assert_eq!(optimized.digests(), independent_digests(&oracle.bytes()));
        assert_eq!(
            std::fs::read(optimized.layout.as_path()).unwrap(),
            layout.canonical_bytes()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_file_backed_private_capture_reads_nonresident_baseline_for_both_backing_kinds() {
        use vm_memory::{FileOffset, GuestRegionMmap, MmapRegion};

        let expected = vec![0x79; 2 * 1024 * 1024 + 4096];
        let file = TempFile::new().unwrap();
        file.as_file().write_all_at(&expected, 0).unwrap();
        for backing in [BackingKind::Boot, BackingKind::RestoredPrivate] {
            let mapping = MmapRegion::<()>::build(
                Some(FileOffset::new(file.as_file().try_clone().unwrap(), 0)),
                expected.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
            )
            .unwrap();
            let raw = GuestMemoryMmap::from_regions(vec![
                GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap(),
            ])
            .unwrap();
            let (domain, authority, mut control) =
                MemoryDomain::construct(raw, 4096, backing).unwrap();
            let epoch = authority.issue_epoch(1).unwrap();
            control.finish_tracked(authority, epoch).unwrap();
            let layout = layout(&domain);
            let current = cut(&mut control);
            let files = Outputs::new();
            let receipt = capture(&current, layout, RamWriteMode::Full, files.owned());
            assert_eq!(receipt.stats().live_bytes_read, expected.len() as u64);
            assert_eq!(receipt.stats().known_zero_bytes_skipped, 0);
            assert_eq!(files.bytes(), expected);
            assert_eq!(files.digests(), independent_digests(&expected));
        }
    }

    #[test]
    fn fresh_zero_coverage_keeps_sparse_output_and_real_errors_preserve_baseline() {
        let output = TempFile::new().unwrap();
        let length = 2 * RAM_IDENTITY_CHUNK_BYTES + 4096;
        output.as_file().set_len(length).unwrap();
        let allocated = output.as_file().metadata().unwrap().blocks();
        let mut stats = RamIoStats::default();
        cover_zero(output.as_file(), 0..length, false, &mut stats, deadline()).unwrap();
        assert_eq!(stats.zero_run_bytes_covered, length);
        assert_eq!(stats.zero_bytes_omitted, length);
        assert_eq!(stats.explicit_zero_bytes_written, 0);
        assert_eq!(output.as_file().metadata().unwrap().blocks(), allocated);
        assert_eq!(
            std::fs::read(output.as_path()).unwrap(),
            vec![0; length as usize]
        );

        output.as_file().write_all_at(&[0x73; 4096], 0).unwrap();
        let read_only = File::open(output.as_path()).unwrap();
        let mut failed_stats = RamIoStats::default();
        assert!(cover_zero(&read_only, 0..4096, true, &mut failed_stats, deadline()).is_err());
        assert_eq!(failed_stats.zero_run_bytes_covered, 0);
        assert_eq!(
            &std::fs::read(output.as_path()).unwrap()[..4096],
            &[0x73; 4096]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zero_run_unsupported_punch_overwrites_baseline_on_real_filesystem() {
        let Some(directory) = std::env::var_os("LIBKRUN_NO_PUNCH_TMPDIR") else {
            eprintln!("set LIBKRUN_NO_PUNCH_TMPDIR to a writable filesystem without hole punching");
            return;
        };
        let file = TempFile::new_in(std::path::Path::new(&directory)).unwrap();
        file.as_file().write_all_at(&[0x79; 3 * 4096], 0).unwrap();
        let mut stats = RamIoStats::default();
        cover_zero(file.as_file(), 4096..8192, true, &mut stats, deadline()).unwrap();
        assert_eq!(
            stats.zero_bytes_punched, 0,
            "test filesystem supports punching"
        );
        assert_eq!(stats.zero_run_bytes_covered, 4096);
        assert_eq!(stats.explicit_zero_bytes_written, 4096);
        assert_eq!(stats.overlay_bytes_written, 4096);
        let mut expected = vec![0x79; 3 * 4096];
        expected[4096..8192].fill(0);
        assert_eq!(std::fs::read(file.as_path()).unwrap(), expected);
        assert_eq!(
            independent_digests(&std::fs::read(file.as_path()).unwrap()),
            independent_digests(&expected)
        );
    }

    fn assert_change_binding(files: &Outputs, receipt: &RamCaptureReceipt) {
        let bytes = std::fs::read(files.changes.as_path()).unwrap();
        assert!(bytes.len() >= 16);
        assert_eq!(receipt.identity_chunk_bytes(), 65536);
        assert_eq!(
            receipt.changes().identified().unwrap().byte_len(),
            bytes.len() as u64
        );
        assert_eq!(
            *receipt.changes().identified().unwrap().sha256(),
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert_eq!(
            receipt.changes().identified().unwrap().record_count(),
            (bytes.len() as u64 - 16) / 56
        );
        assert_eq!(
            receipt.output_identities()[2],
            receipt.changes().identified().unwrap().output_identity()
        );
        let _ = read_test_changes(files.changes.as_file());
    }

    #[test]
    fn isolated_dirty_page_and_contiguous_two_mib_hash_only_affected_units() {
        for changed in [4096, 2 * 1024 * 1024] {
            let length = 4 * 1024 * 1024;
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
            raw.write_slice(&vec![0x41; length], GuestAddress(0))
                .unwrap();
            let (domain, mut control) = tracked(raw);
            let layout = layout(&domain);
            let initial = cut(&mut control);
            let baseline_files = Outputs::new();
            let mut full = capture(
                &initial,
                layout.clone(),
                RamWriteMode::Full,
                baseline_files.owned(),
            );
            let baseline = baseline_files.seal(&mut full);
            control
                .reopen(&initial, &initial.issue_epoch(2).unwrap())
                .unwrap();
            domain
                .write(GuestAddress(0), changed)
                .unwrap()
                .write_view(0, changed)
                .unwrap()
                .write_slice(&vec![0x72; changed], 0)
                .unwrap();
            let current = cut(&mut control);
            let mut dirty = DirtyPageMap::new(domain.layout());
            control.drain_host_dirty(&current, &mut dirty).unwrap();
            let files = Outputs::new();
            let mut output = files.owned();
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
            let units = (changed as u64).div_ceil(RAM_IDENTITY_CHUNK_BYTES);
            assert_eq!(
                receipt.changes().identified().unwrap().record_count(),
                units
            );
            assert_eq!(
                receipt.changes().identified().unwrap().baseline_stream(),
                Some([0; 32])
            );
            assert_eq!(
                receipt.stats().identity_bytes_hashed,
                units * RAM_IDENTITY_CHUNK_BYTES
            );
            assert_eq!(
                receipt.stats().live_bytes_read,
                if receipt.stats().seed_method == RamSeedMethod::Clone {
                    units * RAM_IDENTITY_CHUNK_BYTES
                } else {
                    changed as u64
                }
            );
            if receipt.stats().seed_method == RamSeedMethod::Clone {
                assert_eq!(receipt.stats().baseline_bytes_read, 0);
                assert_eq!(receipt.stats().extent_queries, 0);
            }
            let identities = independent_digests(&files.bytes());
            for (index, digest) in read_test_changes(files.changes.as_file()) {
                assert!(digest.is_some());
                assert_eq!(digest, identities[index as usize]);
            }
            assert_change_binding(&files, &receipt);
        }
    }

    #[test]
    fn dirty_zero_unit_and_short_tail_have_unambiguous_changes() {
        let unit = RAM_IDENTITY_CHUNK_BYTES as usize;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 2 * unit + 4096)]).unwrap();
        raw.write_slice(&[0x41; 4096], GuestAddress(0)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        assert_eq!(baseline_files.indices(), [0]);
        assert_eq!(full.changes().identified().unwrap().record_count(), 1);
        assert_change_binding(&baseline_files, &full);
        let baseline = baseline_files.seal(&mut full);
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        for (address, byte) in [(0, 0), (2 * unit, 0x73)] {
            domain
                .write(GuestAddress(address as u64), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[byte; 4096], 0)
                .unwrap();
        }
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let files = Outputs::new();
        let mut output = files.owned();
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
        let changes = read_test_changes(files.changes.as_file());
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[&0], None);
        assert_eq!(changes[&2], Some(Sha256::digest([0x73; 4096]).into()));
        assert_eq!(receipt.stats().identity_bytes_hashed, 4096);
        assert!(files.bytes()[..2 * unit].iter().all(|byte| *byte == 0));
        assert_eq!(&files.bytes()[2 * unit..], &[0x73; 4096]);
        assert_change_binding(&files, &receipt);
    }

    #[test]
    fn no_dirty_incremental_has_only_header_and_no_guest_reads_or_hashes() {
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 2 * 65536)]).unwrap();
        raw.write_slice(&[0x41; 4096], GuestAddress(0)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let baseline = baseline_files.seal(&mut full);
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 0);
        let files = Outputs::new();
        let mut output = files.owned();
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
        assert_eq!(receipt.changes().identified().unwrap().record_count(), 0);
        assert_eq!(receipt.changes().identified().unwrap().byte_len(), 16);
        assert_eq!(receipt.stats().live_bytes_read, 0);
        assert_eq!(receipt.stats().identity_bytes_hashed, 0);
        if receipt.stats().seed_method == RamSeedMethod::Clone {
            assert_eq!(receipt.stats().baseline_bytes_read, 0);
        }
        assert_eq!(files.bytes(), baseline_files.bytes());
        assert_change_binding(&files, &receipt);
    }

    #[test]
    fn sparse_changes_are_sorted_and_deterministic_across_batches_and_workers() {
        use crate::vmm::memory::image::writer::pipeline as native;
        use crate::vmm::memory::image::{RAM_IO_BUFFER_BYTES, RamCaptureMode};

        let unit = RAM_IDENTITY_CHUNK_BYTES as usize;
        let batch = RAM_IO_BUFFER_BYTES;
        let length = 2 * batch + 4096;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
        for offset in [0, unit, batch - unit, batch, batch + unit, 2 * batch] {
            raw.write_slice(&[0x51; 4096], GuestAddress(offset as u64))
                .unwrap();
        }
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let current = cut(&mut control);
        let mut previous = None;
        let mut scratch = RamIoScratch::new().unwrap();
        for workers in [1, 2] {
            let files = Outputs::new();
            files.ram.as_file().set_len(length as u64).unwrap();
            let mut changes = ChangeWriter::new(
                files.changes.as_file(),
                RamCaptureMode::Full,
                None,
                (length as u64).div_ceil(RAM_IDENTITY_CHUNK_BYTES),
                deadline(),
            )
            .unwrap();
            let mut stats = RamIoStats::default();
            native::write_with_workers(
                native::Input {
                    byte_baseline: None,
                    cut: &current,
                    layout: &layout,
                    mode: &RamWriteMode::Full,
                    identity: &RamHashSelection::Full,
                    seeded: false,
                    deadline: deadline(),
                },
                files.ram.as_file(),
                &mut scratch,
                &mut stats,
                &mut changes,
                workers,
            )
            .unwrap();
            let changes = changes.finish().unwrap();
            let receipt = changes.identified().unwrap();
            assert_eq!(receipt.record_count(), 6);
            assert_eq!(files.indices(), [0, 1, 511, 512, 513, 1024]);
            assert_eq!(
                stats.identity_bytes_hashed,
                5 * RAM_IDENTITY_CHUNK_BYTES + 4096
            );
            let encoded = std::fs::read(files.changes.as_path()).unwrap();
            assert_eq!(
                *receipt.sha256(),
                <[u8; 32]>::from(Sha256::digest(&encoded))
            );
            if let Some(previous) = &previous {
                assert_eq!(&encoded, previous);
            }
            previous = Some(encoded);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn change_sink_enospc_retains_started_outputs_without_receipt() {
        let Some(directory) = std::env::var_os("LIBKRUN_ENOSPC_TMPDIR") else {
            eprintln!("set LIBKRUN_ENOSPC_TMPDIR to a small dedicated tmpfs for real ENOSPC");
            return;
        };
        let directory = std::path::Path::new(&directory);
        let filesystem = nix::sys::statvfs::statvfs(directory).unwrap();
        assert!(
            filesystem
                .blocks()
                .saturating_mul(filesystem.fragment_size())
                <= 16 * 1024 * 1024,
            "LIBKRUN_ENOSPC_TMPDIR must be a dedicated tmpfs of at most 16 MiB"
        );
        let changes = TempFile::new_in(directory).unwrap();
        let filler = TempFile::new_in(directory).unwrap();
        let mut offset = 0;
        loop {
            match filler.as_file().write_at(&[0x55; 4096], offset) {
                Ok(count) => {
                    assert_ne!(count, 0);
                    offset += count as u64;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(nix::errno::Errno::ENOSPC as i32));
                    break;
                }
            }
        }
        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let current = cut(&mut control);
        let files = Outputs::new();
        let mut output = files.owned();
        output.changes = changes.as_file().try_clone().unwrap();
        let failure = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout(&domain),
            RamCaptureIdentity::for_test(&RamWriteMode::Full),
            RamWriteMode::Full,
            output,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap_err();
        assert_eq!(failure.effects, RamImageEffects::Started);
        assert!(matches!(failure.error, RamImageError::Io {
            role: RamFileRole::OutputChanges, operation: RamIoOperation::Write, source,
        } if source.raw_os_error() == Some(nix::errno::Errno::ENOSPC as i32)));
        assert_eq!(failure.output.ram.metadata().unwrap().len(), 4096);
        assert!(failure.output.layout.metadata().unwrap().len() > 0);
        assert_eq!(
            failure.output.changes.metadata().unwrap().ino(),
            changes.as_file().metadata().unwrap().ino()
        );
    }

    #[test]
    fn zero_changes_coalesce_across_batches_and_seed_methods() {
        use crate::vmm::memory::image::writer::pipeline as native;
        use crate::vmm::memory::image::{RAM_IO_BUFFER_BYTES, RamCaptureMode};

        let length = RAM_IO_BUFFER_BYTES + RAM_IDENTITY_CHUNK_BYTES as usize;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
        raw.write_slice(&[0x61; 4096], GuestAddress(0)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let baseline = baseline_files.seal(&mut full);
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        domain
            .write(GuestAddress(0), length)
            .unwrap()
            .write_view(0, length)
            .unwrap()
            .write_slice(&vec![0; length], 0)
            .unwrap();
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let mode = RamWriteMode::Incremental {
            baseline: &baseline,
            dirty: &dirty,
        };
        let mut previous = None;
        for seeded in [false, true] {
            let files = Outputs::new();
            files.ram.as_file().set_len(length as u64).unwrap();
            if seeded {
                files
                    .ram
                    .as_file()
                    .write_all_at(&baseline_files.bytes(), 0)
                    .unwrap();
            }
            let mut changes = ChangeWriter::new(
                files.changes.as_file(),
                RamCaptureMode::Incremental,
                Some([0; 32]),
                513,
                deadline(),
            )
            .unwrap();
            let mut stats = RamIoStats::default();
            native::write(
                native::Input {
                    byte_baseline: None,
                    cut: &current,
                    layout: &layout,
                    mode: &mode,
                    identity: &RamCaptureIdentity::for_test(&mode).selection,
                    seeded,
                    deadline: deadline(),
                },
                files.ram.as_file(),
                &mut RamIoScratch::new().unwrap(),
                &mut stats,
                &mut changes,
            )
            .unwrap();
            let receipt = changes.finish().unwrap();
            let receipt = receipt.identified().unwrap();
            assert_eq!(receipt.record_count(), 1);
            assert_eq!(receipt.byte_len(), 72);
            assert_eq!(stats.identity_bytes_hashed, 0);
            assert_eq!(stats.zero_run_bytes_covered, length as u64);
            assert!(files.bytes().iter().all(|byte| *byte == 0));
            let encoded = std::fs::read(files.changes.as_path()).unwrap();
            assert_eq!(u64::from_le_bytes(encoded[24..32].try_into().unwrap()), 513);
            assert_eq!(read_test_changes(files.changes.as_file()).len(), 513);
            if let Some(previous) = &previous {
                assert_eq!(&encoded, previous);
            }
            previous = Some(encoded);
        }
    }

    #[test]
    fn change_sink_alias_and_access_refusals_precede_all_effects() {
        let (domain, mut control) =
            tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let current = cut(&mut control);
        let layout = layout(&domain);
        let files = Outputs::new();
        files
            .ram
            .as_file()
            .write_all_at(b"ram sentinel", 0)
            .unwrap();
        files
            .layout
            .as_file()
            .write_all_at(b"layout sentinel", 0)
            .unwrap();
        for sink in [
            files.ram.as_file().try_clone().unwrap(),
            files.layout.as_file().try_clone().unwrap(),
            File::open(files.changes.as_path()).unwrap(),
        ] {
            let mut output = files.owned();
            output.changes = sink;
            let failure = write_ram_image(
                AttemptId::for_test(),
                key(),
                &current,
                &binding(),
                layout.clone(),
                RamCaptureIdentity::for_test(&RamWriteMode::Full),
                RamWriteMode::Full,
                output,
                &mut RamIoScratch::new().unwrap(),
                deadline(),
            )
            .unwrap_err();
            assert_eq!(failure.effects, RamImageEffects::None);
            assert!(matches!(
                failure.error,
                RamImageError::Alias {
                    output: RamFileRole::OutputChanges,
                    ..
                } | RamImageError::DescriptorRole {
                    role: RamFileRole::OutputChanges,
                    ..
                }
            ));
            assert_eq!(files.bytes(), b"ram sentinel");
            assert_eq!(
                std::fs::read(files.layout.as_path()).unwrap(),
                b"layout sentinel"
            );
        }
    }

    #[test]
    fn unhashed_full_and_incremental_multiregion_images_match_real_byte_oracle() {
        use crate::vmm::memory::image::RamChangeAuthority;
        use crate::vmm::memory::image::writer::pipeline as native;
        let gap = 1 << 20;
        let raw =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536), (GuestAddress(gap), 65536)])
                .unwrap();
        raw.write_slice(&[0x11; 4096], GuestAddress(0)).unwrap();
        raw.write_slice(&[0x22; 4096], GuestAddress(gap + 15 * 4096))
            .unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let files = Outputs::new();
        let receipt = write_ram_image(
            AttemptId::for_test(),
            key(),
            &initial,
            &binding(),
            layout.clone(),
            RamCaptureIdentity {
                selection: RamHashSelection::None,
                anchor: RamIdentityAnchor::Unknown,
                anchor_generation: crate::vmm::memory::image::RamIdentityGeneration::Unknown,
                predecessor_generation: 0,
                identity_dirty_pages: 0,
                materialization_dirty_pages: 0,
                byte_baseline: None,
            },
            RamWriteMode::Full,
            files.owned(),
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap();
        let mut expected = vec![0; 2 * 65536];
        expected[..4096].fill(0x11);
        expected[65536 + 15 * 4096..].fill(0x22);
        assert_eq!(files.bytes(), expected);
        assert!(matches!(receipt.changes(), RamChangeAuthority::None));
        assert_eq!(receipt.stats().identity_bytes_hashed, 0);
        assert_eq!(receipt.stats().identity_zero_bytes_filled, 0);
        assert_eq!(receipt.stats().whole_file_bytes_hashed, 0);
        assert_eq!(receipt.stats().map_nodes_written, 0);
        assert_eq!(files.changes.as_file().metadata().unwrap().len(), 0);
        #[cfg(target_os = "linux")]
        assert!(receipt.stats().known_zero_bytes_skipped > 0);
        let baseline = Arc::new(
            seal_completed(
                &receipt,
                File::open(files.ram.as_path()).unwrap(),
                File::open(files.layout.as_path()).unwrap(),
                RamInputAuthority::OwnedLocalCut {
                    state: binding(),
                    materialization_generation: 1,
                },
            )
            .unwrap(),
        );
        let original = files.bytes();
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        domain
            .write(GuestAddress(0), 4096)
            .unwrap()
            .write_view(0, 4096)
            .unwrap()
            .write_slice(&[0; 4096], 0)
            .unwrap();
        domain
            .write(GuestAddress(gap + 4096 + 7), 1)
            .unwrap()
            .write_view(0, 1)
            .unwrap()
            .write_slice(&[0x33], 0)
            .unwrap();
        expected[..4096].fill(0);
        expected[65536 + 4096 + 7] = 0x33;
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 2);
        let mode = RamWriteMode::Incremental {
            baseline: &baseline,
            dirty: &dirty,
        };
        for seeded in [false, true] {
            let output = Outputs::new();
            output.ram.as_file().set_len(layout.packed_len()).unwrap();
            if seeded {
                output.ram.as_file().write_all_at(&original, 0).unwrap();
            }
            let mut stats = RamIoStats::default();
            let mut changes = ChangeWriter::None;
            native::write(
                native::Input {
                    byte_baseline: None,
                    cut: &current,
                    layout: &layout,
                    mode: &mode,
                    identity: &RamHashSelection::None,
                    seeded,
                    deadline: deadline(),
                },
                output.ram.as_file(),
                &mut RamIoScratch::new().unwrap(),
                &mut stats,
                &mut changes,
            )
            .unwrap();
            assert!(matches!(
                changes.finish().unwrap(),
                RamChangeAuthority::None
            ));
            assert_eq!(output.bytes(), expected);
            assert_eq!(stats.live_bytes_read, 2 * 4096);
            assert_eq!(stats.identity_bytes_hashed, 0);
            assert_eq!(stats.whole_file_bytes_hashed, 0);
            assert_eq!(stats.map_nodes_written, 0);
            assert_eq!(stats.zero_run_bytes_covered, 4096);
            assert_eq!(output.changes.as_file().metadata().unwrap().len(), 0);
            if seeded {
                assert_eq!(stats.baseline_bytes_read, 0);
                assert_eq!(stats.baseline_bytes_written, 0);
                assert_eq!(stats.extent_queries, 0);
            }
        }
        let output = Outputs::new();
        let mut owned = output.owned();
        owned.protect_baseline(Some(baseline.clone()));
        let receipt = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout.clone(),
            RamCaptureIdentity {
                selection: RamHashSelection::None,
                anchor: RamIdentityAnchor::Unknown,
                anchor_generation: crate::vmm::memory::image::RamIdentityGeneration::Unknown,
                predecessor_generation: 1,
                identity_dirty_pages: 2,
                materialization_dirty_pages: 2,
                byte_baseline: Some((&baseline, &dirty)),
            },
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            owned,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap();
        assert_eq!(output.bytes(), expected);
        assert_eq!(receipt.stats().live_bytes_read, 2 * 4096);
        assert_eq!(receipt.stats().identity_bytes_hashed, 0);
        assert!(matches!(receipt.changes(), RamChangeAuthority::None));
        let snapshot = Outputs::new();
        let mut owned = snapshot.owned();
        owned.protect_baseline(Some(baseline.clone()));
        let receipt = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout,
            RamCaptureIdentity {
                selection: RamHashSelection::Full,
                anchor: RamIdentityAnchor::Unknown,
                anchor_generation: crate::vmm::memory::image::RamIdentityGeneration::Unknown,
                predecessor_generation: 1,
                identity_dirty_pages: 2,
                materialization_dirty_pages: 2,
                byte_baseline: Some((&baseline, &dirty)),
            },
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            owned,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap();
        assert_eq!(snapshot.bytes(), expected);
        assert_eq!(snapshot.digests(), independent_digests(&expected));
        assert_eq!(
            receipt.changes().identified().unwrap().coverage(),
            crate::vmm::memory::image::RamCaptureMode::Full
        );
        assert_eq!(
            receipt.changes().identified().unwrap().baseline_stream(),
            None
        );
        assert_eq!(
            receipt.stats().live_bytes_read,
            if receipt.stats().seed_method == RamSeedMethod::Clone {
                3 * 4096
            } else {
                2 * 4096
            }
        );
        assert_eq!(files.bytes(), original);
    }

    #[test]
    fn seeded_snapshot_hashes_retained_dirty_units_live_without_baseline_reads_or_writes() {
        use crate::vmm::memory::image::writer::pipeline as native;
        let unit = RAM_IDENTITY_CHUNK_BYTES as usize;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 3 * unit)]).unwrap();
        raw.write_slice(&vec![0x41; 3 * unit], GuestAddress(0))
            .unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let initial_files = Outputs::new();
        let mut initial_receipt = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            initial_files.owned(),
        );
        let anchor = initial_files.seal(&mut initial_receipt);
        let RamIdentityAnchor::Identified { stream } = anchor.authority().identity_anchor() else {
            panic!("identified initial anchor required")
        };
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        domain
            .write(GuestAddress(0), 4096)
            .unwrap()
            .write_view(0, 4096)
            .unwrap()
            .write_slice(&[0x72; 4096], 0)
            .unwrap();
        let fork_cut = cut(&mut control);
        let mut retained = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&fork_cut, &mut retained).unwrap();
        assert_eq!(retained.count(), 1);
        let mode = RamWriteMode::Incremental {
            baseline: &anchor,
            dirty: &retained,
        };
        let mut identity = RamCaptureIdentity::for_test(&mode);
        identity.selection = RamHashSelection::None;
        let fork_files = Outputs::new();
        let mut output = fork_files.owned();
        output.protect_baseline(Some(anchor.clone()));
        let fork = write_ram_image(
            AttemptId::for_test(),
            key(),
            &fork_cut,
            &binding(),
            layout.clone(),
            identity,
            mode,
            output,
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap();
        let baseline = seal_completed(
            &fork,
            File::open(fork_files.ram.as_path()).unwrap(),
            File::open(fork_files.layout.as_path()).unwrap(),
            RamInputAuthority::OwnedLocalCut {
                state: binding(),
                materialization_generation: 2,
            },
        )
        .unwrap();
        assert_eq!(fork.stats().live_bytes_read, 4096);
        assert_eq!(fork.stats().identity_bytes_hashed, 0);
        control
            .reopen(&fork_cut, &fork_cut.issue_epoch(3).unwrap())
            .unwrap();
        let current = cut(&mut control);
        let mut writes = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut writes).unwrap();
        assert_eq!(writes.count(), 0);
        let expected = fork_files.bytes();
        let snapshot = Outputs::new();
        snapshot.ram.as_file().write_all_at(&expected, 0).unwrap();
        let mut changes = ChangeWriter::new(
            snapshot.changes.as_file(),
            crate::vmm::memory::image::RamCaptureMode::Incremental,
            Some(stream),
            3,
            deadline(),
        )
        .unwrap();
        let mut stats = RamIoStats::default();
        native::write(
            native::Input {
                byte_baseline: None,
                cut: &current,
                layout: &layout,
                mode: &RamWriteMode::Incremental {
                    baseline: &baseline,
                    dirty: &writes,
                },
                identity: &RamHashSelection::SinceAnchor {
                    stream,
                    dirty: &retained,
                },
                seeded: true,
                deadline: deadline(),
            },
            snapshot.ram.as_file(),
            &mut RamIoScratch::new().unwrap(),
            &mut stats,
            &mut changes,
        )
        .unwrap();
        let authority = changes.finish().unwrap();
        assert_eq!(authority.identified().unwrap().record_count(), 1);
        assert_eq!(stats.live_bytes_read, RAM_IDENTITY_CHUNK_BYTES);
        assert_eq!(stats.identity_bytes_hashed, RAM_IDENTITY_CHUNK_BYTES);
        assert_eq!(stats.baseline_bytes_read, 0);
        assert_eq!(stats.baseline_hole_bytes, 0);
        assert_eq!(stats.extent_queries, 0);
        assert_eq!(stats.baseline_bytes_written, 0);
        assert_eq!(stats.overlay_bytes_written, 0);
        assert_eq!(stats.full_bytes_written, 0);
        assert_eq!(snapshot.bytes(), expected);
        let changed = read_test_changes(snapshot.changes.as_file());
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[&0], independent_digests(&expected)[0]);
    }

    fn file_digests(file: &File) -> Vec<Option<[u8; 32]>> {
        let length = file.metadata().unwrap().len();
        let mut buffer = vec![0; RAM_IDENTITY_CHUNK_BYTES as usize];
        (0..length)
            .step_by(buffer.len())
            .map(|offset| {
                let count = (length - offset).min(buffer.len() as u64) as usize;
                file.read_exact_at(&mut buffer[..count], offset).unwrap();
                buffer[..count]
                    .iter()
                    .any(|byte| *byte != 0)
                    .then(|| Sha256::digest(&buffer[..count]).into())
            })
            .collect()
    }

    fn canonical_root(units: &[Option<[u8; 32]>], length: u64) -> [u8; 32] {
        let mut nodes = units.to_vec();
        for height in 0..=4 {
            nodes = nodes
                .chunks(64)
                .map(|children| {
                    let bitmap = children
                        .iter()
                        .enumerate()
                        .fold(0u64, |bits, (slot, child)| {
                            bits | if child.is_some() { 1 << slot } else { 0 }
                        });
                    if bitmap == 0 {
                        return None;
                    }
                    let mut hash = Sha256::new();
                    if height == 0 {
                        hash.update(b"silo:stream-map:leaf:v1\n");
                    } else {
                        hash.update(b"silo:stream-map:branch:v1\n");
                        hash.update([height]);
                    }
                    hash.update(bitmap.to_le_bytes());
                    for child in children.iter().flatten() {
                        hash.update(child);
                    }
                    Some(hash.finalize().into())
                })
                .collect();
        }
        assert!(nodes.len() <= 1);
        let head = nodes.first().copied().flatten();
        let mut root = Sha256::new();
        root.update(b"silo:stream:v1\n");
        root.update([16]);
        root.update(length.to_le_bytes());
        root.update([u8::from(head.is_some())]);
        if let Some(head) = head {
            root.update(head);
        }
        root.finalize().into()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_sparse_gib_capture_never_clears_known_zero_scratch_or_classifies_holes() {
        let length = 3 * 1024 * 1024 * 1024;
        let populated = 2 * 1024 * 1024;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
        raw.write_slice(&vec![0x31; populated], GuestAddress(0))
            .unwrap();
        let (domain, mut control) = tracked(raw);
        let current = cut(&mut control);
        let files = Outputs::new();
        let mut scratch = RamIoScratch::new().unwrap();
        scratch.buffers[0].fill(0xa5);
        let receipt = write_ram_image(
            AttemptId::for_test(),
            key(),
            &current,
            &binding(),
            layout(&domain),
            RamCaptureIdentity::for_test(&RamWriteMode::Full),
            RamWriteMode::Full,
            files.owned(),
            &mut scratch,
            deadline(),
        )
        .unwrap();
        assert_eq!(receipt.stats().live_bytes_read, populated as u64);
        assert_eq!(receipt.stats().identity_bytes_hashed, populated as u64);
        assert_eq!(
            receipt.stats().live_pages_classified,
            (populated / 4096) as u64
        );
        assert_eq!(receipt.stats().identity_zero_bytes_filled, 0);
        assert_eq!(
            receipt.stats().known_zero_bytes_skipped,
            (length - populated) as u64
        );
        assert!(
            scratch.buffers[0][populated..]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        assert_eq!(files.indices(), (0..populated / 65536).collect::<Vec<_>>());
        assert!(
            files.digests()[..populated / 65536]
                .iter()
                .all(|digest| *digest == Some(Sha256::digest([0x31; 65536]).into()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_child_identity_reads_only_baseline_extents_union_dirty_units() {
        use crate::vmm::memory::image::RamCaptureMode;
        use crate::vmm::memory::image::writer::pipeline as native;
        use vm_memory::{FileOffset, GuestRegionMmap, MmapRegion};
        let length = 3 * 1024 * 1024 * 1024;
        let populated = 2 * 1024 * 1024;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
        raw.write_slice(&vec![0x51; populated], GuestAddress(0))
            .unwrap();
        let (source, mut control) = tracked(raw);
        let source_cut = cut(&mut control);
        let layout = layout(&source);
        let baseline_files = Outputs::new();
        let mut identity = RamCaptureIdentity::for_test(&RamWriteMode::Full);
        identity.selection = RamHashSelection::None;
        let owned = write_ram_image(
            AttemptId::for_test(),
            key(),
            &source_cut,
            &binding(),
            layout.clone(),
            identity,
            RamWriteMode::Full,
            baseline_files.owned(),
            &mut RamIoScratch::new().unwrap(),
            deadline(),
        )
        .unwrap();
        let baseline = seal_completed(
            &owned,
            File::open(baseline_files.ram.as_path()).unwrap(),
            File::open(baseline_files.layout.as_path()).unwrap(),
            RamInputAuthority::OwnedLocalCut {
                state: binding(),
                materialization_generation: 1,
            },
        )
        .unwrap();
        let mapping = MmapRegion::<()>::build(
            Some(FileOffset::new(
                File::open(baseline_files.ram.as_path()).unwrap(),
                0,
            )),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
        )
        .unwrap();
        let raw = GuestMemoryMmap::from_regions(vec![
            GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap(),
        ])
        .unwrap();
        let (child, construction, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::RestoredPrivate).unwrap();
        let epoch = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, epoch).unwrap();
        for (offset, value) in [(0, 0), (length - 4096, 0x73)] {
            child
                .write(GuestAddress(offset as u64), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[value; 4096], 0)
                .unwrap();
        }
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(child.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 2);
        let full = RamWriteMode::Full;
        let incremental = RamWriteMode::Incremental {
            baseline: &baseline,
            dirty: &dirty,
        };
        for (mode, seeded) in [(&full, false), (&incremental, false), (&incremental, true)] {
            let files = Outputs::new();
            files.ram.as_file().set_len(length as u64).unwrap();
            if seeded {
                files
                    .ram
                    .as_file()
                    .write_all_at(&vec![0x51; populated], 0)
                    .unwrap();
            }
            let mut changes = ChangeWriter::new(
                files.changes.as_file(),
                RamCaptureMode::Full,
                None,
                length as u64 / 65536,
                deadline(),
            )
            .unwrap();
            let mut stats = RamIoStats::default();
            native::write(
                native::Input {
                    cut: &current,
                    layout: &layout,
                    mode,
                    identity: &RamHashSelection::Full,
                    byte_baseline: Some((&baseline, &dirty)),
                    seeded,
                    deadline: deadline(),
                },
                files.ram.as_file(),
                &mut RamIoScratch::new().unwrap(),
                &mut stats,
                &mut changes,
            )
            .unwrap();
            changes.finish().unwrap();
            let expected_live = if seeded || matches!(mode, RamWriteMode::Full) {
                populated as u64 + RAM_IDENTITY_CHUNK_BYTES
            } else {
                8192
            };
            assert_eq!(stats.live_bytes_read, expected_live);
            assert_eq!(
                stats.identity_bytes_hashed,
                populated as u64 + RAM_IDENTITY_CHUNK_BYTES
            );
            assert_eq!(stats.full_identity_read_fallback, None);
            assert!(stats.live_pages_classified <= (populated / 4096 + 16) as u64);
            assert!(stats.extent_queries <= 10);
            if seeded {
                assert_eq!(stats.baseline_bytes_read, 0);
            }
            let scanned = file_digests(files.ram.as_file());
            assert_eq!(files.digests(), scanned);
            assert_eq!(
                canonical_root(&files.digests(), length as u64),
                canonical_root(&scanned, length as u64)
            );
            let mut page = [0; 4096];
            files.ram.as_file().read_exact_at(&mut page, 0).unwrap();
            assert_eq!(page, [0; 4096]);
            files
                .ram
                .as_file()
                .read_exact_at(&mut page, length as u64 - 4096)
                .unwrap();
            assert_eq!(page, [0x73; 4096]);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn incremental_anonymous_discards_use_cut_residency_across_capture_boundaries() {
        use devices::virtio::RuntimeGuestMemory;
        let unit = RAM_IDENTITY_CHUNK_BYTES as usize;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4 * unit)]).unwrap();
        for index in 0..4 {
            raw.write_slice(&[0x41; 4096], GuestAddress((index * unit) as u64))
                .unwrap();
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
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        let memory = RuntimeGuestMemory::new(domain.clone());
        let discard = |index| {
            memory
                .try_write_access(
                    4096,
                    GuestAddress((index * unit) as u64),
                    |_, len, _, view| {
                        // nix's mman feature is not enabled for this crate.
                        assert_eq!(
                            unsafe {
                                libc::madvise(view.as_mut_ptr().cast(), len, libc::MADV_DONTNEED)
                            },
                            0
                        );
                        Ok(len)
                    },
                )
                .unwrap();
        };
        let write = |index, value| {
            domain
                .write(GuestAddress((index * unit) as u64), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[value; 4096], 0)
                .unwrap();
        };
        discard(0);
        discard(1);
        write(1, 0x52);
        write(2, 0x63);
        discard(2);
        discard(3);
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 4);
        let files = Outputs::new();
        let mut output = files.owned();
        output.protect_baseline(Some(baseline.clone()));
        let first = capture(
            &current,
            layout.clone(),
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        assert_eq!(first.stats().live_bytes_read, 4096);
        assert_eq!(
            first.stats().known_zero_bytes_skipped,
            if first.stats().seed_method == RamSeedMethod::Clone {
                4 * unit as u64 - 4096
            } else {
                3 * 4096
            }
        );
        assert_eq!(
            first.stats().identity_bytes_hashed,
            RAM_IDENTITY_CHUNK_BYTES
        );
        let mut resolved = baseline_files.digests();
        for (index, digest) in read_test_changes(files.changes.as_file()) {
            resolved[index as usize] = digest;
        }
        assert_eq!(resolved, file_digests(files.ram.as_file()));
        assert_eq!(
            canonical_root(&resolved, layout.packed_len()),
            canonical_root(&file_digests(files.ram.as_file()), layout.packed_len())
        );
        assert_eq!(resolved.iter().filter(|digest| digest.is_some()).count(), 1);
        // Abandon the first cut: retain D, then write a previously discarded page.
        control
            .reopen(&current, &current.issue_epoch(3).unwrap())
            .unwrap();
        write(0, 0x74);
        discard(1);
        let current = cut(&mut control);
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let files = Outputs::new();
        let mut output = files.owned();
        output.protect_baseline(Some(baseline.clone()));
        let mut second = capture(
            &current,
            layout.clone(),
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        assert_eq!(second.stats().live_bytes_read, 4096);
        let mut resolved = baseline_files.digests();
        for (index, digest) in read_test_changes(files.changes.as_file()) {
            resolved[index as usize] = digest;
        }
        assert_eq!(resolved, file_digests(files.ram.as_file()));
        assert_eq!(
            canonical_root(&resolved, layout.packed_len()),
            canonical_root(&file_digests(files.ram.as_file()), layout.packed_len())
        );
        // Accept the new B, clear D, and write after that capture boundary.
        let baseline = files.seal(&mut second);
        control
            .reopen(&current, &current.issue_epoch(4).unwrap())
            .unwrap();
        dirty.clear();
        write(3, 0x85);
        let current = cut(&mut control);
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let next = Outputs::new();
        let mut output = next.owned();
        output.protect_baseline(Some(baseline.clone()));
        let third = capture(
            &current,
            layout.clone(),
            RamWriteMode::Incremental {
                baseline: &baseline,
                dirty: &dirty,
            },
            output,
        );
        assert_eq!(third.stats().live_bytes_read, 4096);
        for (index, digest) in read_test_changes(next.changes.as_file()) {
            resolved[index as usize] = digest;
        }
        assert_eq!(resolved, file_digests(next.ram.as_file()));
        assert_eq!(
            canonical_root(&resolved, layout.packed_len()),
            canonical_root(&file_digests(next.ram.as_file()), layout.packed_len())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_identity_untrustworthy_baseline_extents_fall_back_with_reason() {
        use crate::vmm::memory::image::writer::pipeline as native;
        use crate::vmm::memory::image::{RamCaptureMode, RamIdentityReadFallback};
        for reason in [
            RamIdentityReadFallback::CoverageLost,
            RamIdentityReadFallback::BaselineMismatch,
        ] {
            let unit = RAM_IDENTITY_CHUNK_BYTES as usize;
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4 * unit)]).unwrap();
            raw.write_slice(&vec![0x41; 4 * unit], GuestAddress(0))
                .unwrap();
            let (domain, construction, mut control) =
                MemoryDomain::construct(raw, 4096, BackingKind::RestoredPrivate).unwrap();
            let epoch = construction.issue_epoch(1).unwrap();
            control.finish_tracked(construction, epoch).unwrap();
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
            control
                .reopen(&initial, &initial.issue_epoch(2).unwrap())
                .unwrap();
            domain
                .write(GuestAddress((3 * unit) as u64), 4096)
                .unwrap()
                .write_view(0, 4096)
                .unwrap()
                .write_slice(&[0x52; 4096], 0)
                .unwrap();
            let current = cut(&mut control);
            let mut dirty = DirtyPageMap::new(domain.layout());
            control.drain_host_dirty(&current, &mut dirty).unwrap();
            match reason {
                RamIdentityReadFallback::CoverageLost => domain.invalidate_coverage(),
                RamIdentityReadFallback::BaselineMismatch => {
                    let (other, _) =
                        tracked(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
                    dirty = DirtyPageMap::new(other.layout());
                }
                RamIdentityReadFallback::ExtentsUnavailable
                | RamIdentityReadFallback::ExtentLimit => unreachable!(),
            }
            let files = Outputs::new();
            files.ram.as_file().set_len(layout.packed_len()).unwrap();
            let mut changes = ChangeWriter::new(
                files.changes.as_file(),
                RamCaptureMode::Full,
                None,
                4,
                deadline(),
            )
            .unwrap();
            let mut stats = RamIoStats::default();
            native::write(
                native::Input {
                    cut: &current,
                    layout: &layout,
                    mode: &RamWriteMode::Full,
                    identity: &RamHashSelection::Full,
                    byte_baseline: Some((&baseline, &dirty)),
                    seeded: false,
                    deadline: deadline(),
                },
                files.ram.as_file(),
                &mut RamIoScratch::new().unwrap(),
                &mut stats,
                &mut changes,
            )
            .unwrap();
            changes.finish().unwrap();
            assert_eq!(stats.full_identity_read_fallback, Some(reason));
            assert_eq!(stats.live_bytes_read, layout.packed_len());
            assert_eq!(stats.identity_bytes_hashed, layout.packed_len());
            assert_eq!(files.digests(), file_digests(files.ram.as_file()));
            let mut expected = vec![0x41; 4 * unit];
            expected[3 * unit..3 * unit + 4096].fill(0x52);
            assert_eq!(files.bytes(), expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn incremental_file_discard_reads_original_mapping_not_zero_or_newer_baseline() {
        use devices::virtio::RuntimeGuestMemory;
        use vm_memory::{FileOffset, GuestRegionMmap, MmapRegion};
        let unit = RAM_IDENTITY_CHUNK_BYTES as usize;
        let original = TempFile::new().unwrap();
        original
            .as_file()
            .write_all_at(&vec![0x61; 2 * unit], 0)
            .unwrap();
        let mapping = MmapRegion::<()>::build(
            Some(FileOffset::new(File::open(original.as_path()).unwrap(), 0)),
            2 * unit,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
        )
        .unwrap();
        let raw = GuestMemoryMmap::from_regions(vec![
            GuestRegionMmap::new(mapping, GuestAddress(0)).unwrap(),
        ])
        .unwrap();
        let (domain, construction, mut control) =
            MemoryDomain::construct(raw, 4096, BackingKind::RestoredPrivate).unwrap();
        let epoch = construction.issue_epoch(1).unwrap();
        control.finish_tracked(construction, epoch).unwrap();
        domain
            .write(GuestAddress(0), 4096)
            .unwrap()
            .write_view(0, 4096)
            .unwrap()
            .write_slice(&[0x72; 4096], 0)
            .unwrap();
        let initial = cut(&mut control);
        let layout = layout(&domain);
        let baseline_files = Outputs::new();
        let mut receipt = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let baseline = baseline_files.seal(&mut receipt);
        let mut initial_dirty = DirtyPageMap::new(domain.layout());
        control
            .drain_host_dirty(&initial, &mut initial_dirty)
            .unwrap();
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        RuntimeGuestMemory::new(domain.clone())
            .try_write_access(4096, GuestAddress(0), |_, len, _, view| {
                // nix's mman feature is not enabled for this crate.
                assert_eq!(
                    unsafe { libc::madvise(view.as_mut_ptr().cast(), len, libc::MADV_DONTNEED) },
                    0
                );
                Ok(len)
            })
            .unwrap();
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        assert_eq!(dirty.count(), 1);
        let files = Outputs::new();
        let mut output = files.owned();
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
        assert_eq!(receipt.stats().known_zero_bytes_skipped, 0);
        assert_eq!(
            receipt.stats().live_bytes_read,
            if receipt.stats().seed_method == RamSeedMethod::Clone {
                65536
            } else {
                4096
            }
        );
        assert_eq!(files.bytes(), vec![0x61; 2 * unit]);
        let mut resolved = baseline_files.digests();
        for (index, digest) in read_test_changes(files.changes.as_file()) {
            resolved[index as usize] = digest;
        }
        assert_eq!(resolved, file_digests(files.ram.as_file()));
        assert_eq!(
            canonical_root(&resolved, layout.packed_len()),
            canonical_root(&file_digests(files.ram.as_file()), layout.packed_len())
        );
    }

    fn assert_allocation(file: &File, range: Range<u64>, data: bool) {
        use nix::errno::Errno;
        use nix::unistd::{Whence, lseek};

        file.sync_all().unwrap();
        // Some filesystems legally report every byte as data. Probe a real
        // sparse file before requiring holes, rather than assuming support.
        let probe = TempFile::new().unwrap();
        probe.as_file().set_len(3 * 4096).unwrap();
        probe.as_file().write_all_at(&[1; 4096], 8192).unwrap();
        probe.as_file().sync_all().unwrap();
        match lseek(probe.as_file(), 4096, Whence::SeekData) {
            Ok(8192) => {}
            Ok(_) | Err(Errno::EINVAL | Errno::EOPNOTSUPP) => {
                eprintln!("test filesystem does not report sparse extents");
                return;
            }
            Err(error) => panic!("sparse extent probe failed: {error}"),
        }
        let offset = i64::try_from(range.start).unwrap();
        if data {
            assert_eq!(lseek(file, offset, Whence::SeekData).unwrap(), offset);
            assert!(lseek(file, offset, Whence::SeekHole).unwrap() as u64 >= range.end);
        } else {
            assert_eq!(lseek(file, offset, Whence::SeekHole).unwrap(), offset);
            match lseek(file, offset, Whence::SeekData) {
                Ok(next) => assert!(next as u64 >= range.end),
                Err(Errno::ENXIO) => {}
                Err(error) => panic!("data extent query failed: {error}"),
            }
        }
    }

    #[test]
    fn alternating_zero_pages_are_dense_without_changing_identity() {
        let length = 4 * 1024 * 1024 + 4096;
        let mut expected = vec![0; length];
        for start in (0..length).step_by(8192) {
            expected[start..start + 4096].fill(0x59);
        }
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
        raw.write_slice(&expected, GuestAddress(0)).unwrap();
        let (domain, mut control) = tracked(raw);
        let current = cut(&mut control);
        let files = Outputs::new();
        let receipt = capture(&current, layout(&domain), RamWriteMode::Full, files.owned());
        assert_eq!(files.bytes(), expected);
        assert_allocation(files.ram.as_file(), 0..length as u64, true);
        let dense = TempFile::new().unwrap();
        dense.as_file().write_all_at(&expected, 0).unwrap();
        let digests = file_digests(dense.as_file());
        assert_eq!(files.digests(), digests);
        assert_eq!(
            canonical_root(&files.digests(), length as u64),
            canonical_root(&digests, length as u64)
        );
        assert_eq!(receipt.stats().full_bytes_written, length as u64);
        assert_eq!(receipt.stats().zero_bytes_omitted, 0);
        assert_eq!(
            receipt.stats().zero_run_bytes_covered,
            (length / 8192 * 4096) as u64
        );
    }

    #[test]
    fn interior_zero_hole_threshold_is_strict() {
        for zeros in [MIN_ZERO_HOLE_BYTES - 4096, MIN_ZERO_HOLE_BYTES] {
            let length = zeros + 8192;
            let mut expected = vec![0; length];
            expected[..4096].fill(0x51);
            expected[length - 4096..].fill(0x62);
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
            raw.write_slice(&expected, GuestAddress(0)).unwrap();
            let (domain, mut control) = tracked(raw);
            let current = cut(&mut control);
            let files = Outputs::new();
            let receipt = capture(&current, layout(&domain), RamWriteMode::Full, files.owned());
            let promoted = zeros < MIN_ZERO_HOLE_BYTES;
            assert_eq!(files.bytes(), expected);
            assert_eq!(files.digests(), independent_digests(&expected));
            assert_allocation(files.ram.as_file(), 4096..(4096 + zeros) as u64, promoted);
            assert_eq!(
                receipt.stats().full_bytes_written,
                if promoted { length } else { 8192 } as u64
            );
            assert_eq!(
                receipt.stats().zero_bytes_omitted,
                if promoted { 0 } else { zeros } as u64
            );
            assert_eq!(receipt.stats().zero_run_bytes_covered, zeros as u64);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn promoted_known_zero_clears_stale_scratch_with_and_without_hashing() {
        for hashed in [false, true] {
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 3 * 4096)]).unwrap();
            raw.write_slice(&[0x51; 4096], GuestAddress(0)).unwrap();
            raw.write_slice(&[0x62; 4096], GuestAddress(8192)).unwrap();
            let (domain, mut control) = tracked(raw);
            let current = cut(&mut control);
            let files = Outputs::new();
            let mut scratch = RamIoScratch::new().unwrap();
            scratch.buffers[0].fill(0xa5);
            let mut identity = RamCaptureIdentity::for_test(&RamWriteMode::Full);
            if !hashed {
                identity.selection = RamHashSelection::None;
            }
            let receipt = write_ram_image(
                AttemptId::for_test(),
                key(),
                &current,
                &binding(),
                layout(&domain),
                identity,
                RamWriteMode::Full,
                files.owned(),
                &mut scratch,
                deadline(),
            )
            .unwrap();
            let mut expected = vec![0x51; 3 * 4096];
            expected[4096..8192].fill(0);
            expected[8192..].fill(0x62);
            assert_eq!(files.bytes(), expected);
            assert_eq!(receipt.stats().known_zero_bytes_skipped, 4096);
            assert_eq!(
                receipt.stats().identity_zero_bytes_filled,
                if hashed { 4096 } else { 0 }
            );
            assert_eq!(receipt.stats().full_bytes_written, 3 * 4096);
            assert_eq!(receipt.stats().zero_bytes_omitted, 0);
            assert_eq!(receipt.stats().zero_run_bytes_covered, 4096);
            assert_allocation(files.ram.as_file(), 0..3 * 4096, true);
            if hashed {
                assert_eq!(files.digests(), independent_digests(&expected));
            }
        }
    }

    #[test]
    fn seeded_incremental_promotes_zero_between_dirty_data() {
        let length = 3 * 4096;
        let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
        raw.write_slice(&vec![0x71; length], GuestAddress(0)).unwrap();
        let (domain, mut control) = tracked(raw);
        let layout = layout(&domain);
        let initial = cut(&mut control);
        let baseline_files = Outputs::new();
        let mut full = capture(
            &initial,
            layout.clone(),
            RamWriteMode::Full,
            baseline_files.owned(),
        );
        let baseline = baseline_files.seal(&mut full);
        control
            .reopen(&initial, &initial.issue_epoch(2).unwrap())
            .unwrap();
        let mut expected = vec![0x52; length];
        expected[4096..8192].fill(0);
        domain
            .write(GuestAddress(0), length)
            .unwrap()
            .write_view(0, length)
            .unwrap()
            .write_slice(&expected, 0)
            .unwrap();
        let current = cut(&mut control);
        let mut dirty = DirtyPageMap::new(domain.layout());
        control.drain_host_dirty(&current, &mut dirty).unwrap();
        let files = Outputs::new();
        // Keep the seeded-path assertion even on filesystems without reflinks.
        if clone_baseline(baseline_files.ram.as_file(), files.ram.as_file(), length as u64).is_err() {
            files
                .ram
                .as_file()
                .write_all_at(&baseline_files.bytes(), 0)
                .unwrap();
        }
        let mut digests = pipeline::allocate_digests(length as u64).unwrap();
        let mut stats = RamIoStats::default();
        let mode = RamWriteMode::Incremental {
            baseline: &baseline,
            dirty: &dirty,
        };
        pipeline::write(
            pipeline::Input {
                byte_baseline: None,
                cut: &current,
                layout: &layout,
                mode: &mode,
                identity: &RamHashSelection::Full,
                seeded: true,
                deadline: deadline(),
            },
            files.ram.as_file(),
            &mut RamIoScratch::new().unwrap(),
            &mut stats,
            &[1],
            &mut digests,
        )
        .unwrap();
        assert_eq!(files.bytes(), expected);
        assert_eq!(digests, independent_digests(&expected));
        assert_allocation(files.ram.as_file(), 0..length as u64, true);
        assert_eq!(stats.overlay_bytes_written, length as u64);
        assert_eq!(stats.explicit_zero_bytes_written, 4096);
        assert_eq!(stats.zero_run_bytes_covered, 4096);
        assert_eq!(stats.zero_bytes_punched, 0);
        assert_eq!(stats.zero_bytes_omitted, 0);
        assert_eq!(baseline_files.bytes(), vec![0x71; length]);
    }

    #[test]
    fn pack_edge_zero_pages_stay_sparse() {
        let pack = crate::vmm::memory::image::RAM_IO_BUFFER_BYTES;
        for zero in [0, pack - 4096, pack, pack + 4096] {
            let length = pack + 8192;
            let mut expected = vec![0x43; length];
            expected[zero..zero + 4096].fill(0);
            let raw = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), length)]).unwrap();
            raw.write_slice(&expected, GuestAddress(0)).unwrap();
            let (domain, mut control) = tracked(raw);
            let current = cut(&mut control);
            let files = Outputs::new();
            let receipt = capture(&current, layout(&domain), RamWriteMode::Full, files.owned());
            assert_eq!(files.bytes(), expected);
            assert_eq!(files.digests(), independent_digests(&expected));
            assert_allocation(files.ram.as_file(), zero as u64..(zero + 4096) as u64, false);
            assert_eq!(receipt.stats().zero_bytes_omitted, 4096);
            assert_eq!(receipt.stats().full_bytes_written, (length - 4096) as u64);
        }
    }
}
