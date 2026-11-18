use std::fs::File;
use std::io;
use std::iter::Peekable;
use std::ops::Range;
use std::thread;
use std::time::Instant;

use arch::guest_memory::{CutReadKind, CutReader, DirtyPageMap, MemoryCut, PageIndex};
use sha2::{Digest, Sha256};
use vm_memory::GuestAddress;

use crate::vmm::memory::image::changes::ChangeWriter;
use crate::vmm::memory::image::writer::{
    Extents, MIN_ZERO_HOLE_BYTES, WriteKind, Writeback, cover_zero, is_all_zero, read_exact_at,
    write_exact_at,
};
use crate::vmm::memory::image::{
    AdmittedRamImage, RAM_IDENTITY_CHUNK_BYTES, RAM_IO_BUFFER_BYTES, RamFileRole, RamHashSelection,
    RamIdentityReadFallback, RamImageError, RamIoOperation, RamIoScratch, RamIoStats, RamWriteMode,
    ValidatedRamLayout, check_deadline, io_error,
};

const WRITERS: usize = 2;
const CHUNKS_PER_PACK: usize = RAM_IO_BUFFER_BYTES / RAM_IDENTITY_CHUNK_BYTES as usize;

pub(crate) struct Input<'a> {
    pub cut: &'a MemoryCut,
    pub layout: &'a ValidatedRamLayout,
    pub mode: &'a RamWriteMode<'a>,
    pub identity: &'a RamHashSelection<'a>,
    pub byte_baseline: Option<(&'a AdmittedRamImage, &'a DirtyPageMap)>,
    pub seeded: bool,
    pub deadline: Instant,
}

struct Failure;

impl Failure {
    fn check(&self, deadline: Instant) -> Result<(), RamImageError> {
        check_deadline(deadline)
    }
}

fn pipeline_error(message: &'static str) -> RamImageError {
    RamImageError::Pipeline(io::Error::other(message))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WriteAction {
    Data,
    Zero,
}

struct WriteRun {
    range: Range<usize>,
    kind: WriteKind,
    action: WriteAction,
    promoted_zero_bytes: usize,
}

struct Pack<'a> {
    bytes: &'a mut [u8],
    offset: u64,
    length: usize,
    seeded: bool,
    writes: Vec<WriteRun>,
    zeros: Vec<Range<usize>>,
    nonzero: [bool; CHUNKS_PER_PACK],
    digests: [Option<[u8; 32]>; CHUNKS_PER_PACK],
    affected: [bool; CHUNKS_PER_PACK],
}

impl<'a> Pack<'a> {
    fn new(bytes: &'a mut [u8], granule: usize, seeded: bool) -> Result<Self, RamImageError> {
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(bytes.len() / granule.min(4096))
            .map_err(|_| RamImageError::Allocation)?;
        let mut zeros = Vec::new();
        zeros
            .try_reserve_exact(bytes.len() / granule.min(4096))
            .map_err(|_| RamImageError::Allocation)?;
        Ok(Self {
            bytes,
            offset: 0,
            length: 0,
            seeded,
            writes,
            zeros,
            nonzero: [false; CHUNKS_PER_PACK],
            digests: [None; CHUNKS_PER_PACK],
            affected: [false; CHUNKS_PER_PACK],
        })
    }

    fn reset(&mut self, offset: u64, length: usize) {
        self.offset = offset;
        self.length = length;
        self.writes.clear();
        self.zeros.clear();
        self.nonzero.fill(false);
        self.digests.fill(None);
        self.affected.fill(false);
    }

    fn write_run(&mut self, range: Range<usize>, kind: WriteKind, action: WriteAction) {
        if let Some(last) = self.writes.last_mut()
            && last.kind == kind
            && last.action == action
            && last.range.end == range.start
        {
            last.range.end = range.end;
            return;
        }
        self.writes.push(WriteRun {
            range,
            kind,
            action,
            promoted_zero_bytes: 0,
        });
    }

    fn classify(&mut self, range: Range<usize>, kind: Option<WriteKind>, granule: usize) {
        for start in (range.start..range.end).step_by(granule) {
            let end = (start + granule).min(range.end);
            let mut cursor = start;
            let mut nonzero = false;
            while cursor < end {
                let index = cursor / RAM_IDENTITY_CHUNK_BYTES as usize;
                let limit = end.min((index + 1) * RAM_IDENTITY_CHUNK_BYTES as usize);
                let data = !is_all_zero(&self.bytes[cursor..limit]);
                self.nonzero[index] |= data;
                nonzero |= data;
                cursor = limit;
            }
            if let Some(kind) = kind {
                let action = if nonzero {
                    WriteAction::Data
                } else {
                    WriteAction::Zero
                };
                self.write_run(start..end, kind, action);
            }
        }
    }

    fn known_zero(&mut self, range: Range<usize>, kind: Option<WriteKind>) {
        if let Some(kind) = kind {
            self.write_run(range.clone(), kind, WriteAction::Zero);
        }
        self.zeros.push(range);
    }

    fn coalesce_writes(&mut self) {
        // Pack-edge neighbours are unknown, so only bridge zeros bounded by
        // contiguous data of the same kind entirely inside this pack.
        for index in 1..self.writes.len().saturating_sub(1) {
            let left = &self.writes[index - 1];
            let zero = &self.writes[index];
            let right = &self.writes[index + 1];
            if zero.action == WriteAction::Zero
                && zero.range.len() < MIN_ZERO_HOLE_BYTES
                && left.action == WriteAction::Data
                && right.action == WriteAction::Data
                && left.kind == zero.kind
                && right.kind == zero.kind
                && left.range.end == zero.range.start
                && zero.range.end == right.range.start
            {
                let zero = &mut self.writes[index];
                zero.promoted_zero_bytes = zero.range.len();
                zero.action = WriteAction::Data;
            }
        }
        let mut count = 0;
        for index in 0..self.writes.len() {
            if count > 0
                && self.writes[count - 1].kind == self.writes[index].kind
                && self.writes[count - 1].action == self.writes[index].action
                && self.writes[count - 1].range.end == self.writes[index].range.start
            {
                self.writes[count - 1].range.end = self.writes[index].range.end;
                self.writes[count - 1].promoted_zero_bytes += self.writes[index].promoted_zero_bytes;
            } else {
                self.writes.swap(count, index);
                count += 1;
            }
        }
        self.writes.truncate(count);
    }

    fn persist(
        &mut self,
        file: &File,
        stats: &mut RamIoStats,
        writeback: &mut Writeback,
        deadline: Instant,
        hash_workers: usize,
    ) -> Result<(), RamImageError> {
        let failure = Failure;
        self.coalesce_writes();
        let mut writes = self.writes.iter().peekable();
        for range in &self.zeros {
            failure.check(deadline)?;
            let mut start = range.start;
            while start < range.end {
                let chunk = start / RAM_IDENTITY_CHUNK_BYTES as usize;
                let end = range
                    .end
                    .min((chunk + 1) * RAM_IDENTITY_CHUNK_BYTES as usize);
                while writes.peek().is_some_and(|run| run.range.end <= start) {
                    writes.next();
                }
                let end = if let Some(run) = writes.peek() {
                    end.min(if run.range.start > start {
                        run.range.start
                    } else {
                        run.range.end
                    })
                } else {
                    end
                };
                let identity = self.affected[chunk] && self.nonzero[chunk];
                let written = writes.peek().is_some_and(|run| {
                    run.range.start <= start && run.action == WriteAction::Data
                });
                if identity || written {
                    self.bytes[start..end].fill(0);
                }
                if identity {
                    stats.identity_zero_bytes_filled += (end - start) as u64;
                }
                start = end;
            }
        }
        let bytes = &self.bytes[..self.length];
        let affected = &self.affected;
        let nonzero = &self.nonzero;
        let count = self.length.div_ceil(RAM_IDENTITY_CHUNK_BYTES as usize);
        let split = count.div_ceil(hash_workers);
        let hashed = if count == 1 && affected[0] && nonzero[0] {
            check_deadline(deadline)?;
            self.digests[0] = Some(Sha256::digest(bytes).into());
            bytes.len() as u64
        } else if (0..count).any(|index| affected[index] && nonzero[index]) {
            thread::scope(|scope| {
                let mut workers = [None, None];
                for (part, digests) in self.digests[..count].chunks_mut(split).enumerate() {
                    let failure = &failure;
                    workers[part] = Some(thread::Builder::new().spawn_scoped(scope, move || {
                        let mut hashed = 0;
                        for (local, digest) in digests.iter_mut().enumerate() {
                            failure.check(deadline)?;
                            let index = part * split + local;
                            let start = index * RAM_IDENTITY_CHUNK_BYTES as usize;
                            if start >= bytes.len() {
                                break;
                            }
                            if affected[index] && nonzero[index] {
                                let end =
                                    (start + RAM_IDENTITY_CHUNK_BYTES as usize).min(bytes.len());
                                *digest = Some(Sha256::digest(&bytes[start..end]).into());
                                hashed += (end - start) as u64;
                            }
                        }
                        Ok::<u64, RamImageError>(hashed)
                    }));
                }
                let mut total = 0;
                let mut error = None;
                for worker in workers.into_iter().flatten() {
                    match worker {
                        Ok(worker) => match worker.join() {
                            Ok(Ok(count)) => total += count,
                            Ok(Err(cause)) => error = Some(cause),
                            Err(_) => error = Some(pipeline_error("RAM hasher panicked")),
                        },
                        Err(cause) => error = Some(RamImageError::Pipeline(cause)),
                    }
                }
                error.map_or(Ok(total), Err)
            })?
        } else {
            0
        };
        stats.identity_bytes_hashed += hashed;
        for run in &self.writes {
            failure.check(deadline)?;
            let offset = self.offset + run.range.start as u64;
            match run.action {
                WriteAction::Data => {
                    write_exact_at(
                        file,
                        &self.bytes[run.range.clone()],
                        offset,
                        run.kind,
                        stats,
                        deadline,
                    )?;
                    writeback.completed(file, offset, run.range.len() as u64);
                    stats.zero_run_bytes_covered += run.promoted_zero_bytes as u64;
                }
                WriteAction::Zero => cover_zero(
                    file,
                    offset..offset + run.range.len() as u64,
                    self.seeded,
                    stats,
                    deadline,
                )?,
            }
        }
        Ok(())
    }

    fn emit(&self, changes: &mut ChangeWriter<'_>) -> Result<(), RamImageError> {
        let first = self.offset / RAM_IDENTITY_CHUNK_BYTES;
        for local in 0..self.length.div_ceil(RAM_IDENTITY_CHUNK_BYTES as usize) {
            if self.affected[local] {
                changes.push(first + local as u64, self.digests[local])?;
            }
        }
        Ok(())
    }
}

struct Reader<'a> {
    input: Input<'a>,
    region_index: usize,
    cut_reader: Option<CutReader<'a>>,
    extents: Option<Extents<'a>>,
}

impl Reader<'_> {
    fn sparse_live(
        &mut self,
        pack: &mut Pack<'_>,
        range: Range<u64>,
        write_kind: Option<WriteKind>,
        stats: &mut RamIoStats,
        failure: &Failure,
    ) -> Result<(), RamImageError> {
        let mut offset = range.start;
        let end = range.end;
        while offset < end {
            failure.check(self.input.deadline)?;
            let region = self
                .input
                .layout
                .regions()
                .get(self.region_index)
                .ok_or(RamImageError::Geometry)?;
            if offset >= region.stream_offset + region.length {
                self.region_index += 1;
                continue;
            }
            let local = offset - region.stream_offset;
            let length = (end - offset).min(region.length - local) as usize;
            let (kind, length) = self
                .cut_reader
                .as_mut()
                .ok_or(RamImageError::Geometry)?
                .next_range(GuestAddress(region.guest_start + local), length)
                .map_err(RamImageError::Authority)?;
            let start = (offset - pack.offset) as usize;
            let range = start..start + length;
            match kind {
                CutReadKind::Read => {
                    self.live(pack, offset..offset + length as u64, stats, failure)?;
                    pack.classify(range, write_kind, self.input.layout.granule() as usize);
                    stats.live_pages_classified +=
                        length as u64 / u64::from(self.input.layout.granule());
                }
                CutReadKind::KnownZero => {
                    stats.known_zero_bytes_skipped += length as u64;
                    pack.known_zero(range, write_kind);
                }
            }
            offset += length as u64;
        }
        Ok(())
    }

    fn live(
        &mut self,
        pack: &mut Pack<'_>,
        range: Range<u64>,
        stats: &mut RamIoStats,
        failure: &Failure,
    ) -> Result<(), RamImageError> {
        let mut offset = range.start;
        while offset < range.end {
            failure.check(self.input.deadline)?;
            let region = self
                .input
                .layout
                .regions()
                .get(self.region_index)
                .ok_or(RamImageError::Geometry)?;
            if offset >= region.stream_offset + region.length {
                self.region_index += 1;
                continue;
            }
            let local = offset - region.stream_offset;
            let length = (range.end - offset).min(region.length - local) as usize;
            self.input
                .cut
                .validate_domain(self.input.cut.domain())
                .map_err(RamImageError::Authority)?;
            let guard = self
                .input
                .cut
                .domain()
                .read(GuestAddress(region.guest_start + local), length)
                .map_err(RamImageError::GuestMemory)?;
            let start = (offset - pack.offset) as usize;
            let count = guard
                .read_view(0, length)
                .map_err(RamImageError::GuestMemory)?
                .copy_to(&mut pack.bytes[start..start + length]);
            stats.live_bytes_read += count as u64;
            if count != length {
                return Err(io_error(
                    RamIoOperation::Read,
                    RamFileRole::OutputRam,
                    io::Error::new(io::ErrorKind::UnexpectedEof, "short live RAM read"),
                ));
            }
            offset += length as u64;
        }
        failure.check(self.input.deadline)
    }

    fn clean(
        &mut self,
        pack: &mut Pack<'_>,
        range: Range<u64>,
        stats: &mut RamIoStats,
        failure: &Failure,
    ) -> Result<(), RamImageError> {
        let extents = self.extents.as_mut().ok_or(RamImageError::Geometry)?;
        let mut offset = range.start;
        while offset < range.end {
            failure.check(self.input.deadline)?;
            let data = extents.next(offset, stats, self.input.deadline)?;
            let start = data
                .as_ref()
                .map_or(range.end, |data| data.start.min(range.end));
            pack.bytes[(offset - pack.offset) as usize..(start - pack.offset) as usize].fill(0);
            stats.baseline_hole_bytes += start - offset;
            offset = start;
            let Some(data) = data else { break };
            let end = data.end.min(range.end);
            let local = (offset - pack.offset) as usize..(end - pack.offset) as usize;
            read_exact_at(
                extents.file,
                &mut pack.bytes[local.clone()],
                offset,
                stats,
                self.input.deadline,
            )?;
            pack.classify(
                local,
                (!self.input.seeded).then_some(WriteKind::Baseline),
                self.input.layout.granule() as usize,
            );
            offset = end;
        }
        Ok(())
    }

    fn fill(
        &mut self,
        pack: &mut Pack<'_>,
        pages: &mut Peekable<impl Iterator<Item = PageIndex>>,
        stats: &mut RamIoStats,
        failure: &Failure,
    ) -> Result<(), RamImageError> {
        let end = pack.offset + pack.length as u64;
        let granule = self.input.layout.granule() as usize;
        if matches!(self.input.mode, RamWriteMode::Full) {
            return self.sparse_live(
                pack,
                pack.offset..end,
                Some(WriteKind::Full),
                stats,
                failure,
            );
        }
        let live_identity =
            self.input.seeded && !matches!(self.input.identity, RamHashSelection::None);
        let mut clean_start = pack.offset;
        while let Some(page) = pages.peek() {
            let start = page.index() as u64 * granule as u64;
            if start >= end {
                break;
            }
            pages.next();
            let mut stop = start + granule as u64;
            while stop < end
                && pages
                    .peek()
                    .is_some_and(|page| page.index() as u64 * granule as u64 == stop)
            {
                pages.next();
                stop += granule as u64;
            }
            if live_identity {
                self.sparse_live(pack, clean_start..start, None, stats, failure)?;
            } else if !self.input.seeded {
                self.clean(pack, clean_start..start, stats, failure)?;
            }
            self.sparse_live(pack, start..stop, Some(WriteKind::Overlay), stats, failure)?;
            clean_start = stop;
        }
        if live_identity {
            self.sparse_live(pack, clean_start..end, None, stats, failure)?;
        } else if !self.input.seeded {
            self.clean(pack, clean_start..end, stats, failure)?;
        }
        Ok(())
    }
}

// Extents are a byte proof only while B is complete and D covers every writer.
// Bound metadata independently of logical RAM size; unsupported or pathological
// extent maps retain the correct full live-read path.
fn full_identity_extents(
    input: &Input<'_>,
    stats: &mut RamIoStats,
) -> Result<Option<Vec<Range<u64>>>, RamImageError> {
    if !matches!(input.identity, RamHashSelection::Full) {
        return Ok(None);
    }
    let baseline = input.byte_baseline.or(match input.mode {
        RamWriteMode::Full => None,
        RamWriteMode::Incremental { baseline, dirty } => Some((*baseline, *dirty)),
    });
    let Some((baseline, dirty)) = baseline else {
        return Ok(None);
    };
    let fallback = if !input.cut.domain().coverage_valid() {
        Some(RamIdentityReadFallback::CoverageLost)
    } else if baseline.layout().as_ref() != input.layout
        || dirty.page_count() != input.cut.domain().layout().page_count()
        || baseline.recheck_before(Some(input.deadline)).is_err()
    {
        Some(RamIdentityReadFallback::BaselineMismatch)
    } else {
        None
    };
    if let Some(reason) = fallback {
        check_deadline(input.deadline)?;
        stats.full_identity_read_fallback = Some(reason);
        return Ok(None);
    }
    let mut extents = Extents {
        file: &baseline.ram,
        length: input.layout.packed_len(),
        supported: true,
    };
    let mut ranges: Vec<Range<u64>> = Vec::new();
    let mut offset = 0;
    let mut count = 0;
    while offset < extents.length {
        check_deadline(input.deadline)?;
        let data = match extents.next(offset, stats, input.deadline) {
            Ok(data) if extents.supported => data,
            Err(RamImageError::Deadline) => return Err(RamImageError::Deadline),
            _ => {
                stats.full_identity_read_fallback =
                    Some(RamIdentityReadFallback::ExtentsUnavailable);
                return Ok(None);
            }
        };
        let Some(data) = data else { break };
        if count == 65536 {
            stats.full_identity_read_fallback = Some(RamIdentityReadFallback::ExtentLimit);
            return Ok(None);
        }
        count += 1;
        offset = data.end;
        let range = data.start / RAM_IDENTITY_CHUNK_BYTES * RAM_IDENTITY_CHUNK_BYTES
            ..data.end.div_ceil(RAM_IDENTITY_CHUNK_BYTES) * RAM_IDENTITY_CHUNK_BYTES;
        if let Some(last) = ranges.last_mut()
            && range.start <= last.end
        {
            last.end = range.end;
        } else {
            ranges
                .try_reserve(1)
                .map_err(|_| RamImageError::Allocation)?;
            ranges.push(range);
        }
    }
    if baseline.recheck_before(Some(input.deadline)).is_err() {
        check_deadline(input.deadline)?;
        stats.full_identity_read_fallback = Some(RamIdentityReadFallback::BaselineMismatch);
        return Ok(None);
    }
    Ok(Some(ranges))
}

pub(crate) fn write(
    input: Input<'_>,
    ram: &File,
    scratch: &mut RamIoScratch,
    stats: &mut RamIoStats,
    changes: &mut ChangeWriter<'_>,
) -> Result<(), RamImageError> {
    write_with_workers(input, ram, scratch, stats, changes, WRITERS)
}

pub(crate) fn write_with_workers(
    input: Input<'_>,
    ram: &File,
    scratch: &mut RamIoScratch,
    stats: &mut RamIoStats,
    changes: &mut ChangeWriter<'_>,
    hash_workers: usize,
) -> Result<(), RamImageError> {
    if !(1..=WRITERS).contains(&hash_workers) {
        return Err(RamImageError::Geometry);
    }
    let full_extents = full_identity_extents(&input, stats)?;
    let sparse_full = full_extents.is_some();
    let mut reader = Reader {
        cut_reader: Some(input.cut.reader().map_err(RamImageError::Authority)?),
        extents: match input.mode {
            RamWriteMode::Full => None,
            RamWriteMode::Incremental { baseline, .. } => Some(Extents {
                file: &baseline.ram,
                length: input.layout.packed_len(),
                supported: true,
            }),
        },
        input,
        region_index: 0,
    };
    let failure = Failure;
    let deadline = reader.input.deadline;
    let dirty = match reader.input.mode {
        RamWriteMode::Full => None,
        RamWriteMode::Incremental { dirty, .. } => Some(*dirty),
    };
    let mut pages = dirty
        .into_iter()
        .flat_map(|dirty| dirty.iter_set())
        .peekable();
    let granule = u64::from(reader.input.layout.granule());
    let identity_dirty = match reader.input.identity {
        RamHashSelection::SinceAnchor { dirty, .. } => Some(*dirty),
        _ => None,
    };
    let selection = identity_dirty
        .or(dirty)
        .or_else(|| reader.input.byte_baseline.map(|(_, dirty)| dirty));
    let unit_bytes = if matches!(reader.input.identity, RamHashSelection::None) {
        granule
    } else {
        RAM_IDENTITY_CHUNK_BYTES
    };
    let mut dirty_units = selection
        .into_iter()
        .flat_map(|dirty| dirty.iter_set())
        .map(|page| page.index() as u64 * granule / unit_bytes)
        .peekable();
    let mut data_units = full_extents
        .iter()
        .flatten()
        .flat_map(|range| range.start / unit_bytes..range.end / unit_bytes)
        .peekable();
    let mut units =
        std::iter::from_fn(
            || match (dirty_units.peek().copied(), data_units.peek().copied()) {
                (Some(dirty), Some(data)) if dirty == data => {
                    dirty_units.next();
                    data_units.next()
                }
                (Some(dirty), Some(data)) if data < dirty => data_units.next(),
                (Some(_), _) => dirty_units.next(),
                (None, _) => data_units.next(),
            },
        )
        .peekable();
    let selected = sparse_full
        || (reader.input.seeded && !matches!(reader.input.identity, RamHashSelection::Full));
    let mut hash_pages = identity_dirty
        .into_iter()
        .flat_map(|dirty| dirty.iter_set())
        .peekable();
    let mut pack = Pack::new(
        &mut scratch.buffers[0],
        granule as usize,
        reader.input.seeded,
    )?;
    let mut writeback = Writeback::default();
    let mut offset = 0;
    let length = reader.input.layout.packed_len();
    loop {
        failure.check(deadline)?;
        let range = if selected {
            let Some(first) = units.next() else { break };
            let mut end = first + 1;
            while let Some(next) = units.peek().copied() {
                if next >= end
                    && (next != end || (end - first) * unit_bytes >= RAM_IO_BUFFER_BYTES as u64)
                {
                    break;
                }
                units.next();
                end = end.max(next + 1);
            }
            first * unit_bytes..(end * unit_bytes).min(length)
        } else {
            if offset == length {
                break;
            }
            offset..(offset + RAM_IO_BUFFER_BYTES as u64).min(length)
        };
        if sparse_full {
            stats.known_zero_bytes_skipped += range.start - offset;
        }
        pack.reset(range.start, (range.end - range.start) as usize);
        reader.fill(&mut pack, &mut pages, stats, &failure)?;
        match reader.input.identity {
            RamHashSelection::None => {}
            RamHashSelection::Full => pack.affected.fill(true),
            RamHashSelection::SinceAnchor { .. } => {
                while let Some(page) = hash_pages.peek() {
                    let start = page.index() as u64 * granule;
                    if start >= range.end {
                        break;
                    }
                    hash_pages.next();
                    if start >= range.start {
                        pack.affected
                            [((start - range.start) / RAM_IDENTITY_CHUNK_BYTES) as usize] = true;
                    }
                }
            }
        }
        pack.persist(ram, stats, &mut writeback, deadline, hash_workers)?;
        pack.emit(changes)?;
        offset = range.end;
    }
    if sparse_full {
        stats.known_zero_bytes_skipped += length - offset;
    }
    Ok(())
}
