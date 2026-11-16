use std::fs::File;
use std::io;
use std::iter::Peekable;
use std::ops::Range;
use std::thread;
use std::time::Instant;

use arch::guest_memory::{CutReadKind, CutReader, MemoryCut, PageIndex};
use sha2::{Digest, Sha256};
use vm_memory::GuestAddress;

use crate::vmm::memory::image::changes::ChangeWriter;
use crate::vmm::memory::image::writer::{
    Extents, WriteKind, Writeback, cover_zero, is_all_zero, read_exact_at, write_exact_at,
};
use crate::vmm::memory::image::{
    RAM_IDENTITY_CHUNK_BYTES, RAM_IO_BUFFER_BYTES, RamFileRole, RamImageError, RamIoOperation,
    RamIoScratch, RamIoStats, RamWriteMode, ValidatedRamLayout, check_deadline, io_error,
};

const WRITERS: usize = 2;
const CHUNKS_PER_PACK: usize = RAM_IO_BUFFER_BYTES / RAM_IDENTITY_CHUNK_BYTES as usize;

pub(crate) struct Input<'a> {
    pub cut: &'a MemoryCut,
    pub layout: &'a ValidatedRamLayout,
    pub mode: &'a RamWriteMode<'a>,
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
}

struct Pack<'a> {
    bytes: &'a mut [u8],
    offset: u64,
    length: usize,
    seeded: bool,
    writes: Vec<WriteRun>,
    zero_granules: Vec<bool>,
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
        let mut zero_granules = Vec::new();
        if seeded {
            zero_granules
                .try_reserve_exact(bytes.len() / granule)
                .map_err(|_| RamImageError::Allocation)?;
            zero_granules.resize(bytes.len() / granule, false);
        }
        Ok(Self {
            bytes,
            offset: 0,
            length: 0,
            seeded,
            writes,
            zero_granules,
            nonzero: [false; CHUNKS_PER_PACK],
            digests: [None; CHUNKS_PER_PACK],
            affected: [false; CHUNKS_PER_PACK],
        })
    }

    fn reset(&mut self, offset: u64, length: usize) {
        self.offset = offset;
        self.length = length;
        self.writes.clear();
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
            if self.seeded {
                self.zero_granules[start / granule] = !nonzero;
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

    fn overlay(&mut self, range: Range<usize>, granule: usize) {
        for start in (range.start..range.end).step_by(granule) {
            let end = (start + granule).min(range.end);
            let action = if self.zero_granules[start / granule] {
                WriteAction::Zero
            } else {
                WriteAction::Data
            };
            self.write_run(start..end, WriteKind::Overlay, action);
        }
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
        for run in &self.writes {
            failure.check(deadline)?;
            if run.action == WriteAction::Zero {
                let mut start = run.range.start;
                while start < run.range.end {
                    let chunk = start / RAM_IDENTITY_CHUNK_BYTES as usize;
                    let end = run
                        .range
                        .end
                        .min((chunk + 1) * RAM_IDENTITY_CHUNK_BYTES as usize);
                    if self.nonzero[chunk] {
                        self.bytes[start..end].fill(0);
                    }
                    start = end;
                }
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
    fn full(
        &mut self,
        pack: &mut Pack<'_>,
        stats: &mut RamIoStats,
        failure: &Failure,
    ) -> Result<(), RamImageError> {
        let mut offset = pack.offset;
        let end = offset + pack.length as u64;
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
                    pack.classify(
                        range,
                        Some(WriteKind::Full),
                        self.input.layout.granule() as usize,
                    );
                }
                CutReadKind::KnownZero => {
                    stats.known_zero_bytes_skipped += length as u64;
                    pack.write_run(range, WriteKind::Full, WriteAction::Zero);
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
                Some(WriteKind::Baseline),
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
            pack.affected.fill(true);
            return self.full(pack, stats, failure);
        }
        if self.input.seeded {
            self.live(pack, pack.offset..end, stats, failure)?;
            pack.classify(0..pack.length, None, granule);
        }
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
            let local = (start - pack.offset) as usize..(stop - pack.offset) as usize;
            let first = local.start / RAM_IDENTITY_CHUNK_BYTES as usize;
            let last = (local.end - 1) / RAM_IDENTITY_CHUNK_BYTES as usize;
            pack.affected[first..=last].fill(true);
            if self.input.seeded {
                pack.overlay(local, granule);
            } else {
                self.clean(pack, clean_start..start, stats, failure)?;
                self.live(pack, start..stop, stats, failure)?;
                pack.classify(local, Some(WriteKind::Overlay), granule);
            }
            clean_start = stop;
        }
        if !self.input.seeded {
            self.clean(pack, clean_start..end, stats, failure)?;
        }
        Ok(())
    }
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
    let mut reader = Reader {
        cut_reader: if matches!(input.mode, RamWriteMode::Full) {
            Some(input.cut.reader().map_err(RamImageError::Authority)?)
        } else {
            None
        },
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
    let mut units = dirty
        .into_iter()
        .flat_map(|dirty| dirty.iter_set())
        .map(|page| page.index() as u64 * granule / RAM_IDENTITY_CHUNK_BYTES)
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
        let range = if reader.input.seeded {
            let Some(first) = units.next() else { break };
            let mut end = first + 1;
            while let Some(next) = units.peek().copied() {
                if next >= end && (next != end || end - first >= CHUNKS_PER_PACK as u64) {
                    break;
                }
                units.next();
                end = end.max(next + 1);
            }
            first * RAM_IDENTITY_CHUNK_BYTES..(end * RAM_IDENTITY_CHUNK_BYTES).min(length)
        } else {
            if offset == length {
                break;
            }
            offset..(offset + RAM_IO_BUFFER_BYTES as u64).min(length)
        };
        pack.reset(range.start, (range.end - range.start) as usize);
        reader.fill(&mut pack, &mut pages, stats, &failure)?;
        pack.persist(ram, stats, &mut writeback, deadline, hash_workers)?;
        pack.emit(changes)?;
        offset = range.end;
    }
    Ok(())
}
