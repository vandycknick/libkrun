use std::fs::File;
use std::io;
use std::iter::Peekable;
use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Instant;

use arch::guest_memory::{MemoryCut, PageIndex};
use sha2::{Digest, Sha256};
use vm_memory::GuestAddress;

use crate::vmm::memory::image::writer::{
    Extents, WriteKind, Writeback, is_all_zero, read_exact_at, write_exact_at,
};
use crate::vmm::memory::image::{
    RAM_IDENTITY_CHUNK_BYTES, RAM_IO_BUFFER_BYTES, RAM_IO_BUFFER_COUNT, RamFileRole, RamImageError,
    RamIoOperation, RamIoScratch, RamIoStats, RamWriteMode, ValidatedRamLayout, check_deadline,
    io_error,
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

pub(crate) fn allocate_digests(length: u64) -> Result<Vec<Option<[u8; 32]>>, RamImageError> {
    let count = usize::try_from(length.div_ceil(RAM_IDENTITY_CHUNK_BYTES))
        .map_err(|_| RamImageError::Geometry)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| RamImageError::Allocation)?;
    values.resize(count, None);
    Ok(values)
}

#[derive(Default)]
struct Failure {
    cancelled: AtomicBool,
    first: Mutex<Option<RamImageError>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Failure {
    fn record(&self, error: RamImageError) {
        let mut first = lock(&self.first);
        if first.is_none() {
            *first = Some(error);
        }
        self.cancelled.store(true, Ordering::Release);
    }

    fn check(&self, deadline: Instant) -> Result<(), RamImageError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(pipeline_error("RAM capture cancelled"));
        }
        check_deadline(deadline)
    }
}

fn pipeline_error(message: &'static str) -> RamImageError {
    RamImageError::Pipeline(io::Error::other(message))
}

struct WriteRun {
    range: Range<usize>,
    kind: WriteKind,
}

struct Pack<'a> {
    bytes: &'a mut [u8],
    offset: u64,
    length: usize,
    writes: Vec<WriteRun>,
    nonzero: [bool; CHUNKS_PER_PACK],
    digests: [Option<[u8; 32]>; CHUNKS_PER_PACK],
}

impl<'a> Pack<'a> {
    fn new(bytes: &'a mut [u8], granule: usize) -> Result<Self, RamImageError> {
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(bytes.len() / granule)
            .map_err(|_| RamImageError::Allocation)?;
        Ok(Self {
            bytes,
            offset: 0,
            length: 0,
            writes,
            nonzero: [false; CHUNKS_PER_PACK],
            digests: [None; CHUNKS_PER_PACK],
        })
    }

    fn reset(&mut self, offset: u64, length: usize) {
        self.offset = offset;
        self.length = length;
        self.writes.clear();
        self.nonzero.fill(false);
        self.digests.fill(None);
    }

    fn write_run(&mut self, range: Range<usize>, kind: WriteKind) {
        if let Some(last) = self.writes.last_mut()
            && last.kind == kind
            && last.range.end == range.start
        {
            last.range.end = range.end;
            return;
        }
        self.writes.push(WriteRun { range, kind });
    }

    fn classify(
        &mut self,
        range: Range<usize>,
        kind: Option<WriteKind>,
        granule: usize,
        stats: &mut RamIoStats,
    ) {
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
                if nonzero || kind == WriteKind::Overlay {
                    self.write_run(start..end, kind);
                } else {
                    stats.zero_bytes_omitted += (end - start) as u64;
                }
            }
        }
    }

    fn persist(
        &mut self,
        file: &File,
        affected: &[u64],
        stats: &mut RamIoStats,
        writeback: &mut Writeback,
        failure: &Failure,
        deadline: Instant,
    ) -> Result<(), RamImageError> {
        let first = (self.offset / RAM_IDENTITY_CHUNK_BYTES) as usize;
        for (local, bytes) in self.bytes[..self.length]
            .chunks(RAM_IDENTITY_CHUNK_BYTES as usize)
            .enumerate()
        {
            failure.check(deadline)?;
            let index = first + local;
            if self.nonzero[local] && affected[index / 64] & (1 << (index % 64)) != 0 {
                self.digests[local] = Some(Sha256::digest(bytes).into());
            }
        }
        for run in &self.writes {
            failure.check(deadline)?;
            let offset = self.offset + run.range.start as u64;
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
        Ok(())
    }

    fn collect_digests(&self, digests: &mut [Option<[u8; 32]>]) {
        let first = (self.offset / RAM_IDENTITY_CHUNK_BYTES) as usize;
        let count = self.length.div_ceil(RAM_IDENTITY_CHUNK_BYTES as usize);
        digests[first..first + count].copy_from_slice(&self.digests[..count]);
    }
}

struct Reader<'a> {
    input: Input<'a>,
    region_index: usize,
    extents: Option<Extents<'a>>,
}

impl Reader<'_> {
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
                stats,
            );
            offset = end;
        }
        Ok(())
    }

    fn fill(
        &mut self,
        pack: &mut Pack<'_>,
        pages: &mut Peekable<impl Iterator<Item = PageIndex>>,
        affected: &[u64],
        stats: &mut RamIoStats,
        failure: &Failure,
    ) -> Result<(), RamImageError> {
        let end = pack.offset + pack.length as u64;
        let granule = self.input.layout.granule() as usize;
        if matches!(self.input.mode, RamWriteMode::Full) {
            self.live(pack, pack.offset..end, stats, failure)?;
            pack.classify(0..pack.length, Some(WriteKind::Full), granule, stats);
            return Ok(());
        }
        if self.input.seeded {
            let first = (pack.offset / RAM_IDENTITY_CHUNK_BYTES) as usize;
            for local in 0..pack.length.div_ceil(RAM_IDENTITY_CHUNK_BYTES as usize) {
                let index = first + local;
                if affected[index / 64] & (1 << (index % 64)) == 0 {
                    continue;
                }
                let start = local * RAM_IDENTITY_CHUNK_BYTES as usize;
                let limit = (start + RAM_IDENTITY_CHUNK_BYTES as usize).min(pack.length);
                self.live(
                    pack,
                    pack.offset + start as u64..pack.offset + limit as u64,
                    stats,
                    failure,
                )?;
                pack.classify(start..limit, None, granule, stats);
            }
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
            if self.input.seeded {
                pack.write_run(local, WriteKind::Overlay);
            } else {
                self.clean(pack, clean_start..start, stats, failure)?;
                self.live(pack, start..stop, stats, failure)?;
                pack.classify(local, Some(WriteKind::Overlay), granule, stats);
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
    affected: &[u64],
    digests: &mut [Option<[u8; 32]>],
) -> Result<(), RamImageError> {
    let mut free = Vec::new();
    free.try_reserve_exact(RAM_IO_BUFFER_COUNT)
        .map_err(|_| RamImageError::Allocation)?;
    for bytes in &mut scratch.buffers {
        free.push(Pack::new(bytes, input.layout.granule() as usize)?);
    }
    let mut reader = Reader {
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
    let failure = Failure::default();
    let (jobs, queued) = mpsc::sync_channel::<Pack<'_>>(WRITERS);
    let queued = Mutex::new(queued);
    // All three borrowed packs fit even when failure stops the producer receiving.
    let (completed, returned) = mpsc::sync_channel::<Pack<'_>>(RAM_IO_BUFFER_COUNT);
    let deadline = reader.input.deadline;
    thread::scope(|scope| {
        let mut workers = [None, None];
        for slot in &mut workers {
            let queued = &queued;
            let failure = &failure;
            let completed = completed.clone();
            match thread::Builder::new().spawn_scoped(scope, move || {
                let mut stats = RamIoStats::default();
                let mut writeback = Writeback::default();
                loop {
                    let received = lock(queued).recv();
                    let Ok(mut pack) = received else { break };
                    // A failed worker must still return its pack so the reader cannot
                    // wait forever while another worker is blocked on the input queue.
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        pack.persist(ram, affected, &mut stats, &mut writeback, failure, deadline)
                    }));
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => failure.record(error),
                        Err(_) => failure.record(pipeline_error("RAM writer panicked")),
                    }
                    if completed.send(pack).is_err() {
                        break;
                    }
                }
                stats
            }) {
                Ok(worker) => *slot = Some(worker),
                Err(error) => {
                    failure.record(RamImageError::Pipeline(error));
                    break;
                }
            }
        }
        drop(completed);
        let result = (|| {
            let mut pages = match reader.input.mode {
                RamWriteMode::Full => None,
                RamWriteMode::Incremental { dirty, .. } => Some(*dirty),
            }
            .into_iter()
            .flat_map(|dirty| dirty.iter_set())
            .peekable();
            let mut offset = 0;
            let mut in_flight = 0;
            while offset < reader.input.layout.packed_len() {
                failure.check(deadline)?;
                let mut pack = match free.pop() {
                    Some(pack) => pack,
                    None => {
                        let pack = returned
                            .recv()
                            .map_err(|_| pipeline_error("RAM writers disconnected"))?;
                        in_flight -= 1;
                        pack.collect_digests(digests);
                        pack
                    }
                };
                let length = (reader.input.layout.packed_len() - offset)
                    .min(pack.bytes.len() as u64) as usize;
                pack.reset(offset, length);
                reader.fill(&mut pack, &mut pages, affected, stats, &failure)?;
                failure.check(deadline)?;
                offset += length as u64;
                if pack.writes.is_empty() && !pack.nonzero.iter().any(|nonzero| *nonzero) {
                    free.push(pack);
                } else {
                    jobs.send(pack)
                        .map_err(|_| pipeline_error("RAM writers disconnected"))?;
                    in_flight += 1;
                }
            }
            while in_flight != 0 {
                let pack = returned
                    .recv()
                    .map_err(|_| pipeline_error("RAM writers disconnected"))?;
                in_flight -= 1;
                pack.collect_digests(digests);
            }
            failure.check(deadline)
        })();
        if let Err(error) = result {
            failure.record(error);
        }
        drop(jobs);
        drop(returned);
        for worker in workers.into_iter().flatten() {
            match worker.join() {
                Ok(worker_stats) => {
                    stats.full_bytes_written += worker_stats.full_bytes_written;
                    stats.baseline_bytes_written += worker_stats.baseline_bytes_written;
                    stats.overlay_bytes_written += worker_stats.overlay_bytes_written;
                    stats.explicit_zero_bytes_written += worker_stats.explicit_zero_bytes_written;
                }
                Err(_) => failure.record(pipeline_error("RAM writer panicked")),
            }
        }
    });
    match lock(&failure.first).take() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
