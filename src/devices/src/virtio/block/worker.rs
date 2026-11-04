use crate::virtio::descriptor_utils::{DescriptorChainSnapshot, Reader, Writer};

use crate::virtio::DeviceQueue;
use crate::virtio::block::device::{CacheType, DiskProperties};
use crate::virtio::lifecycle::ProviderFault;
use crate::virtio::{InterruptTransport, RuntimeGuestMemory};
use polly::event_manager::BarrierKey;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(feature = "native-device-probe")]
use std::time::{Duration, Instant};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
#[cfg(target_os = "windows")]
use utils::windows::AsRawFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::ByteValued;

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromBackend(io::Error),
    WritingToBackend(io::Error),
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

#[derive(Default)]
pub(crate) struct WorkerAdmission {
    pub barrier: Option<BarrierKey>,
    #[cfg(feature = "native-device-probe")]
    pub pressure_hold_until: Option<Instant>,
    #[cfg(feature = "native-device-probe")]
    pub pressure_owned_hold_until: Option<Instant>,
    #[cfg(feature = "native-device-probe")]
    pub pressure_unpopped_hold_until: Option<Instant>,
    #[cfg(feature = "native-device-probe")]
    pub pressure_owned_head: Option<u16>,
    #[cfg(feature = "native-device-probe")]
    pub pressure_unpopped: u16,
    #[cfg(feature = "native-device-probe")]
    pub pressure_consumed_kicks: u64,
}

pub struct BlockWorker {
    pub(crate) device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: RuntimeGuestMemory,
    pub(crate) disk: DiskProperties,
    stop_fd: Arc<EventFd>,
    pub(crate) admission: Arc<Mutex<WorkerAdmission>>,
    pub(crate) fault: Option<ProviderFault>,
    backend_failed: bool,
    pub(crate) running: Arc<AtomicBool>,
    chain_snapshot: DescriptorChainSnapshot,
    #[cfg(test)]
    acquired: Option<(
        crossbeam_channel::Sender<u16>,
        crossbeam_channel::Receiver<()>,
    )>,
}

impl BlockWorker {
    pub(crate) fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: RuntimeGuestMemory,
        disk: DiskProperties,
        stop_fd: Arc<EventFd>,
        admission: Arc<Mutex<WorkerAdmission>>,
        running: Arc<AtomicBool>,
    ) -> Self {
        let chain_snapshot = DescriptorChainSnapshot::new(device_queue.queue.get_max_size());
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            admission,
            fault: None,
            backend_failed: false,
            running,
            chain_snapshot,
            #[cfg(test)]
            acquired: None,
        }
    }

    pub(crate) fn into_parts(self) -> (DeviceQueue, DiskProperties, Option<ProviderFault>) {
        (
            self.device_queue,
            self.disk,
            self.fault
                .or(self.backend_failed.then_some(ProviderFault::Worker)),
        )
    }

    pub(crate) fn work(mut self) -> Self {
        if let Err(fault) = self.work_inner() {
            self.fail(fault);
        }
        if let Ok(admission) = self.admission.lock() {
            if let Some(key) = admission.barrier
                && self.device_queue.queue.close_admission(key).is_err()
            {
                self.fault.get_or_insert(ProviderFault::QueueState);
            }
        } else {
            self.fault.get_or_insert(ProviderFault::Worker);
        }
        self
    }

    fn work_inner(&mut self) -> Result<(), ProviderFault> {
        let virtq_ev_fd = self.device_queue.event.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();
        let mut epoll = Epoll::new().map_err(|_| ProviderFault::Worker)?;
        for fd in [virtq_ev_fd, stop_ev_fd] {
            epoll
                .ctl(
                    ControlOperation::Add,
                    fd,
                    &EpollEvent::new(EventSet::IN, fd as u64),
                )
                .map_err(|_| ProviderFault::Worker)?;
        }
        let mut events: [EpollEvent; 2] =
            std::array::from_fn(|_| EpollEvent::new(EventSet::empty(), 0));
        // A consumed kick is not the durable record of available work.
        self.process_virtio_queues();
        if self.fault.is_none() {
            self.running.store(true, Ordering::Release);
        }
        loop {
            #[cfg(feature = "native-device-probe")]
            self.wait_pressure_hold()?;
            if self.fault.is_some()
                || self
                    .admission
                    .lock()
                    .map_err(|_| ProviderFault::Worker)?
                    .barrier
                    .is_some()
            {
                return Ok(());
            }
            let count = match epoll.wait(events.len(), -1, &mut events) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ProviderFault::Worker),
            };
            // A stop/quiesce wake wins over cached queue-ready events.
            if events[..count].iter().any(|event| event.fd() == stop_ev_fd) {
                #[cfg(feature = "native-device-probe")]
                self.wait_pressure_hold()?;
                let _ = self.stop_fd.read();
                return Ok(());
            }
            for event in &events[..count] {
                if event.fd() == virtq_ev_fd {
                    self.process_queue_event();
                }
            }
        }
    }

    #[cfg(feature = "native-device-probe")]
    fn wait_pressure_hold(&self) -> Result<(), ProviderFault> {
        loop {
            let held = self
                .admission
                .lock()
                .map_err(|_| ProviderFault::Worker)?
                .pressure_hold_until
                .is_some_and(|until| Instant::now() < until);
            if !held {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn fail(&mut self, fault: ProviderFault) {
        self.fault.get_or_insert(fault);
        self.device_queue.queue.record_processing_failure();
    }

    fn process_queue_event(&mut self) {
        match self.device_queue.event.read() {
            Ok(_) => {
                #[cfg(feature = "native-device-probe")]
                {
                    let failed = self
                        .admission
                        .lock()
                        .map(|mut admission| {
                            admission.pressure_consumed_kicks =
                                admission.pressure_consumed_kicks.saturating_add(1);
                        })
                        .is_err();
                    if failed {
                        self.fail(ProviderFault::Worker);
                        return;
                    }
                }
                self.process_virtio_queues();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => self.fail(ProviderFault::Worker),
        }
    }

    fn process_virtio_queues(&mut self) {
        let mem = self.mem.clone();
        loop {
            if self.fault.is_some() {
                return;
            }
            if self.device_queue.queue.disable_notification(&mem).is_err() {
                self.fail(ProviderFault::Notification);
                return;
            }
            self.process_queue(&mem);
            if self.fault.is_some() {
                return;
            }
            match self.device_queue.queue.enable_notification(&mem) {
                Ok(false) => return,
                Ok(true) => {}
                Err(_) => {
                    self.fail(ProviderFault::Notification);
                    return;
                }
            }
            match self.admission.lock() {
                Ok(admission) if admission.barrier.is_some() => return,
                Ok(_) => {}
                Err(_) => {
                    self.fault.get_or_insert(ProviderFault::Worker);
                    return;
                }
            }
        }
    }

    fn process_queue(&mut self, mem: &RuntimeGuestMemory) {
        loop {
            #[cfg(feature = "native-device-probe")]
            if self.wait_request_pressure(None, mem).is_err() {
                self.fail(ProviderFault::Worker);
                return;
            }
            // The provider closes this same boundary, never a check-then-pop flag.
            let head = {
                let admission = match self.admission.lock() {
                    Ok(admission) => admission,
                    Err(_) => {
                        self.fault.get_or_insert(ProviderFault::Worker);
                        return;
                    }
                };
                if admission.barrier.is_some() || self.fault.is_some() {
                    return;
                }
                self.device_queue.queue.pop(mem)
            };
            let Some(head) = head else {
                if self.device_queue.queue.capture_state().is_err() {
                    self.fail(ProviderFault::QueueState);
                }
                return;
            };
            #[cfg(feature = "native-device-probe")]
            if self.wait_request_pressure(Some(head.index), mem).is_err() {
                self.fail(ProviderFault::Worker);
                return;
            }
            #[cfg(test)]
            if let Some((acquired, proceed)) = &self.acquired
                && (acquired.send(head.index).is_err() || proceed.recv().is_err())
            {
                self.fail(ProviderFault::Worker);
                return;
            }
            let head_index = head.index;
            let chain = match self.chain_snapshot.read(head) {
                Ok(chain) => chain,
                Err(_) => {
                    self.fail(ProviderFault::QueueState);
                    return;
                }
            };
            let mut reader = match Reader::from_validated(mem, &chain) {
                Ok(reader) => reader,
                Err(_) => {
                    self.fail(ProviderFault::QueueState);
                    return;
                }
            };
            let mut writer = match Writer::from_validated(mem, &chain) {
                Ok(writer) => writer,
                Err(_) => {
                    self.fail(ProviderFault::QueueState);
                    return;
                }
            };
            let Some(data_length) = writer.available_bytes().checked_sub(1) else {
                self.fail(ProviderFault::QueueState);
                return;
            };
            let mut status_writer = match writer.split_at(data_length) {
                Ok(writer) => writer,
                Err(_) => {
                    self.fail(ProviderFault::QueueState);
                    return;
                }
            };
            let header: RequestHeader = match reader.read_obj() {
                Ok(header) => header,
                Err(_) => {
                    self.fail(ProviderFault::QueueState);
                    return;
                }
            };
            let mut failed_backend_read = false;
            let status = match self.process_request(header, &mut reader, &mut writer) {
                Ok(_) => VIRTIO_BLK_S_OK as u8,
                Err(RequestError::UnknownRequest) => VIRTIO_BLK_S_UNSUPP as u8,
                Err(RequestError::InvalidDataLength) => {
                    self.fail(ProviderFault::Worker);
                    VIRTIO_BLK_S_IOERR as u8
                }
                Err(error) => {
                    log::error!("block request failed: {error:?}");
                    if self.disk.file.is_poisoned()
                        || matches!(
                            error,
                            RequestError::ReadingFromDescriptor(_)
                                | RequestError::WritingToDescriptor(_)
                        )
                    {
                        self.fail(ProviderFault::Worker);
                        return;
                    }
                    self.backend_failed = true;
                    failed_backend_read = matches!(error, RequestError::ReadingFromBackend(_));
                    VIRTIO_BLK_S_IOERR as u8
                }
            };
            if status_writer.write_obj(status).is_err() {
                self.fail(ProviderFault::QueueState);
                return;
            }
            // imago does not report partial read DMA on failure. The used-ring
            // contract permits an underestimate, but not an unwritten prefix.
            let written = if failed_backend_read {
                0
            } else {
                writer.bytes_written() + 1
            };
            let length = match u32::try_from(written) {
                Ok(length) => length,
                Err(_) => {
                    self.fail(ProviderFault::QueueState);
                    return;
                }
            };
            if self
                .device_queue
                .queue
                .add_used(mem, head_index, length)
                .is_err()
            {
                self.fail(ProviderFault::QueueState);
                return;
            }
            match self.device_queue.queue.needs_notification(mem) {
                Ok(true) if self.interrupt.try_signal_used_queue().is_err() => {
                    self.fail(ProviderFault::Notification);
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    self.fail(ProviderFault::Notification);
                    return;
                }
            }
            #[cfg(feature = "native-device-probe")]
            {
                let failed = self
                    .admission
                    .lock()
                    .map(|mut admission| {
                        admission.pressure_owned_head = None;
                        admission.pressure_unpopped = 0;
                    })
                    .is_err();
                if failed {
                    self.fail(ProviderFault::Worker);
                    return;
                }
            }
        }
    }

    #[cfg(feature = "native-device-probe")]
    fn wait_request_pressure(
        &self,
        owned: Option<u16>,
        memory: &RuntimeGuestMemory,
    ) -> Result<(), ProviderFault> {
        loop {
            let held = {
                let mut admission = self.admission.lock().map_err(|_| ProviderFault::Worker)?;
                let deadline = if let Some(head) = owned {
                    admission.pressure_owned_head = Some(head);
                    admission.pressure_owned_hold_until
                } else {
                    admission.pressure_unpopped = self.device_queue.queue.len(memory);
                    admission.pressure_unpopped_hold_until
                };
                deadline.is_some_and(|until| Instant::now() < until)
                    && (owned.is_some() || admission.pressure_unpopped != 0)
            };
            if !held {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(
                            &self.disk,
                            data_len,
                            self.checked_range(request_header.sector, data_len)?,
                        )
                        .map_err(RequestError::ReadingFromBackend)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    reader
                        .read_to_at(
                            &self.disk,
                            data_len,
                            self.checked_range(request_header.sector, data_len)?,
                        )
                        .map_err(RequestError::WritingToBackend)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    self.disk
                        .checked_sync()
                        .map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = self.disk.image_id();
                if data_len < disk_id.len() {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let length = u64::from(discard_write_data.num_sectors) * 512;
                let length =
                    usize::try_from(length).map_err(|_| RequestError::InvalidDataLength)?;
                let offset = self.checked_range(discard_write_data.sector, length)?;
                if discard_write_data.flags != 0 || reader.available_bytes() != 0 {
                    return Err(RequestError::InvalidDataLength);
                }
                self.disk
                    .file
                    .lock()
                    .map_err(|_| {
                        RequestError::Discarding(io::Error::other("block backend lock poisoned"))
                    })?
                    .discard_to_zero(offset, length as u64)
                    .map_err(RequestError::Discarding)?;
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let length = u64::from(discard_write_data.num_sectors) * 512;
                let length =
                    usize::try_from(length).map_err(|_| RequestError::InvalidDataLength)?;
                let offset = self.checked_range(discard_write_data.sector, length)?;
                if discard_write_data.flags & !VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP != 0
                    || reader.available_bytes() != 0
                {
                    return Err(RequestError::InvalidDataLength);
                }
                let mut disk = self.disk.file.lock().map_err(|_| {
                    RequestError::WritingZeroes(io::Error::other("block backend lock poisoned"))
                })?;
                if discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP != 0 {
                    disk.discard_to_zero(offset, length as u64)
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    disk.write_zeroes(offset, length as u64)
                        .map_err(RequestError::WritingZeroes)?;
                }
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }

    fn checked_range(&self, sector: u64, length: usize) -> Result<u64, RequestError> {
        let offset = sector
            .checked_mul(512)
            .ok_or(RequestError::InvalidDataLength)?;
        let end = offset
            .checked_add(length as u64)
            .ok_or(RequestError::InvalidDataLength)?;
        if end > self.disk.nsectors().saturating_mul(512) {
            return Err(RequestError::InvalidDataLength);
        }
        Ok(offset)
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use std::fs;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use imago::{
        DynStorage, FormatAccess, Storage, StorageOpenOptions, file::File as ImagoFile, raw::Raw,
    };
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use utils::eventfd::{EFD_NONBLOCK, EventFd};
    use utils::tempfile::TempFile;
    use virtio_bindings::virtio_blk::{
        VIRTIO_BLK_S_OK, VIRTIO_BLK_T_DISCARD, VIRTIO_BLK_T_WRITE_ZEROES,
        VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP,
    };
    use vm_memory::GuestAddress;

    use crate::legacy::{IrqChipDevice, KvmIoapic};
    use crate::virtio::block::device::{CacheType, DiskProperties};
    use crate::virtio::block::worker::{BlockWorker, DiscardWriteData, RequestHeader};
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};

    #[derive(Clone, Copy, Debug)]
    enum ZeroRange {
        MiddleSector,
        MiddleEdges,
        MiddleAligned,
        Tail,
        Whole,
    }

    fn open_raw(path: &Path) -> (DiskProperties, usize) {
        let file = ImagoFile::open(StorageOpenOptions::new().filename(path).write(true))
            .expect("open real writable backing");
        let alignment = file.discard_align();
        let storage: Box<dyn DynStorage> = Box::new(file);
        let raw = Raw::open_image(storage, true).expect("open Raw image");
        let disk = DiskProperties::new(
            Arc::new(Mutex::new(FormatAccess::new(raw))),
            b"discard-regression".to_vec(),
            CacheType::Writeback,
        )
        .expect("derive Raw capacity");
        (disk, alignment)
    }

    fn assert_zero_range(request_type: u32, flags: u32, range: ZeroRange) {
        let backing = TempFile::new().expect("private backing");
        backing
            .as_file()
            .set_len(4096)
            .expect("initial backing length");
        let (disk, alignment) = open_raw(backing.as_path());
        assert!(alignment.is_power_of_two() && alignment >= 4096);
        drop(disk);

        let length = 8 * alignment + 512;
        let mut expected = (0..length)
            .map(|index| (index % 251 + 1) as u8)
            .collect::<Vec<_>>();
        fs::write(backing.as_path(), &expected).expect("populate every backing byte");
        let (offset, count) = match range {
            ZeroRange::MiddleSector => (512, 512),
            ZeroRange::MiddleEdges => (512, 2 * alignment),
            ZeroRange::MiddleAligned => (alignment, alignment),
            ZeroRange::Tail => (alignment + 512, length - alignment - 512),
            ZeroRange::Whole => (0, length),
        };
        assert_eq!(offset % 512, 0);
        assert_eq!(count % 512, 0);
        expected[offset..offset + count].fill(0);

        let (disk, _) = open_raw(backing.as_path());
        assert_eq!(disk.nsectors(), length as u64 / 512);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x2000)])
            .expect("real guest memory");
        let queue = VirtQueue::new(GuestAddress(0), &memory, 8);
        queue.dtable[0].set(0x1000, 16, 1, 1);
        queue.dtable[1].set(0x1100, 16, 1, 2);
        queue.dtable[2].set(0x1200, 1, 2, 0);
        queue.avail.ring[0].set(0);
        queue.avail.idx.set(1);
        memory
            .write_obj(
                RequestHeader {
                    request_type,
                    _reserved: 0,
                    sector: 0,
                },
                GuestAddress(0x1000),
            )
            .expect("request header");
        memory
            .write_obj(
                DiscardWriteData {
                    sector: offset as u64 / 512,
                    num_sectors: u32::try_from(count / 512).expect("bounded request"),
                    flags,
                },
                GuestAddress(0x1100),
            )
            .expect("request range");
        memory
            .write_obj(0xff_u8, GuestAddress(0x1200))
            .expect("initial status");

        // This production IRQ implementation only writes eventfd for used-queue
        // notifications; no VM or in-kernel IRQ setup is needed to exercise it.
        let irqchip = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {}))));
        let interrupt = InterruptTransport::new(irqchip, "block-zero-range".into(), None)
            .expect("eventfd interrupt transport");
        let completion = interrupt.event().try_clone().expect("completion event");
        let event = Arc::new(EventFd::new(EFD_NONBLOCK).expect("queue event"));
        let mut worker = BlockWorker::new(
            DeviceQueue::new(queue.create_queue(), event.clone()),
            interrupt,
            memory.clone(),
            disk,
            Arc::new(EventFd::new(EFD_NONBLOCK).expect("stop event")),
            Arc::new(Mutex::new(
                crate::virtio::block::worker::WorkerAdmission::default(),
            )),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        event.write(1).expect("submit request");
        worker.process_queue_event();
        // SAFETY: completion owns this fd and remains alive through poll and
        // the readiness check; the borrowed descriptor never escapes.
        let completion_fd = unsafe { BorrowedFd::borrow_raw(completion.as_raw_fd()) };
        let mut ready = [PollFd::new(completion_fd, PollFlags::POLLIN)];
        assert_eq!(
            poll(&mut ready, PollTimeout::ZERO).expect("completion readiness"),
            1
        );
        assert_eq!(completion.read().expect("real completion notification"), 1);
        assert_eq!(queue.used.idx.get(), 1);
        let status: u8 = memory
            .read_obj(GuestAddress(0x1200))
            .expect("request status");
        assert_eq!(u32::from(status), VIRTIO_BLK_S_OK, "{range:?}");
        {
            let file = worker.disk.file.lock().expect("disk lock");
            file.flush().expect("flush backing");
            file.sync().expect("sync backing");
        }
        assert_eq!(worker.disk.nsectors(), length as u64 / 512);
        assert_eq!(
            backing
                .as_file()
                .metadata()
                .expect("backing metadata")
                .len(),
            length as u64
        );
        drop(worker);

        let (reopened, _) = open_raw(backing.as_path());
        assert_eq!(
            reopened.nsectors(),
            length as u64 / 512,
            "{range:?} reopened capacity"
        );
        drop(reopened);
        let observed = fs::read(backing.as_path()).expect("read reopened backing");
        assert_eq!(observed.len(), length, "{range:?} reopened length");
        if let Some(index) = observed
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected)
        {
            panic!(
                "{range:?} request_type={request_type} flags={flags} host_alignment={alignment} \
                 range={offset}..{} byte={index}: observed={} expected={}",
                offset + count,
                observed[index],
                expected[index],
            );
        }
    }

    #[test]
    fn discard_zero_range_middle_sector_preserves_bytes_and_reopened_capacity() {
        assert_zero_range(VIRTIO_BLK_T_DISCARD, 0, ZeroRange::MiddleSector);
    }

    #[test]
    fn discard_zero_range_middle_edges_preserves_bytes_and_reopened_capacity() {
        assert_zero_range(VIRTIO_BLK_T_DISCARD, 0, ZeroRange::MiddleEdges);
    }

    #[test]
    fn discard_zero_range_aligned_middle_preserves_bytes_and_reopened_capacity() {
        assert_zero_range(VIRTIO_BLK_T_DISCARD, 0, ZeroRange::MiddleAligned);
    }

    #[test]
    fn discard_zero_range_tail_preserves_bytes_and_reopened_capacity() {
        assert_zero_range(VIRTIO_BLK_T_DISCARD, 0, ZeroRange::Tail);
    }

    #[test]
    fn discard_zero_range_whole_preserves_reopened_capacity() {
        assert_zero_range(VIRTIO_BLK_T_DISCARD, 0, ZeroRange::Whole);
    }

    #[test]
    fn write_zeroes_zero_range_preserves_bytes_and_reopened_capacity() {
        for flags in [0, VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP] {
            for range in [
                ZeroRange::MiddleSector,
                ZeroRange::MiddleEdges,
                ZeroRange::MiddleAligned,
                ZeroRange::Tail,
                ZeroRange::Whole,
            ] {
                assert_zero_range(VIRTIO_BLK_T_WRITE_ZEROES, flags, range);
            }
        }
    }

    fn write_request(memory: &RuntimeGuestMemory, ring: &VirtQueue<'_>, slot: usize, byte: u8) {
        let head = slot * 3;
        let base = 0x1000 + slot as u64 * 0x1000;
        ring.dtable[head].set(base, 16, 1, (head + 1) as u16);
        ring.dtable[head + 1].set(base + 0x100, 512, 1, (head + 2) as u16);
        ring.dtable[head + 2].set(base + 0x300, 1, 2, 0);
        memory
            .write_obj(
                RequestHeader {
                    request_type: virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT,
                    _reserved: 0,
                    sector: slot as u64,
                },
                GuestAddress(base),
            )
            .unwrap();
        memory
            .write_slice(&[byte; 512], GuestAddress(base + 0x100))
            .unwrap();
        memory
            .write_obj(0xff_u8, GuestAddress(base + 0x300))
            .unwrap();
        ring.avail.ring[slot].set(head as u16);
        ring.avail.idx.set((slot + 1) as u16);
    }

    fn request_worker(
        memory: &RuntimeGuestMemory,
        ring: &VirtQueue<'_>,
        disk: DiskProperties,
    ) -> (BlockWorker, EventFd) {
        let irqchip = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {}))));
        let interrupt = InterruptTransport::new(
            irqchip,
            "block-provider".into(),
            Some(Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())),
        )
        .unwrap();
        let completion = interrupt.event().try_clone().unwrap();
        let worker = BlockWorker::new(
            DeviceQueue::new(
                ring.create_queue(),
                Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            ),
            interrupt,
            memory.clone(),
            disk,
            Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            Arc::new(Mutex::new(
                crate::virtio::block::worker::WorkerAdmission::default(),
            )),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        (worker, completion)
    }

    #[test]
    fn block_provider_sized_unready_queue_cannot_scan_dma_or_store_notification() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        write_request(&memory, &ring, 0, 0x46);
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        worker.device_queue.queue.ready = false;
        let mut before = [0; 0x4000];
        memory.read_slice(&mut before, GuestAddress(0)).unwrap();
        worker.process_virtio_queues();
        let mut after = [0; 0x4000];
        memory.read_slice(&mut after, GuestAddress(0)).unwrap();
        assert_eq!(before, after);
        assert_eq!(worker.fault, None);
        assert_eq!(
            worker
                .device_queue
                .queue
                .capture_state()
                .unwrap()
                .next_avail,
            0
        );
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0; 512]);
        assert!(completion.read().is_err());
    }

    #[test]
    fn block_provider_write_read_flush_status_used_and_irq_are_actual() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x6000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 16);
        write_request(&memory, &ring, 0, 0x37);
        ring.dtable[3].set(0x2000, 16, 1, 4);
        ring.dtable[4].set(0x2100, 512, 3, 5);
        ring.dtable[5].set(0x2300, 1, 2, 0);
        memory
            .write_obj(
                RequestHeader {
                    request_type: virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN,
                    _reserved: 0,
                    sector: 0,
                },
                GuestAddress(0x2000),
            )
            .unwrap();
        ring.avail.ring[1].set(3);
        ring.dtable[6].set(0x3000, 16, 1, 7);
        ring.dtable[7].set(0x3300, 1, 2, 0);
        memory
            .write_obj(
                RequestHeader {
                    request_type: virtio_bindings::virtio_blk::VIRTIO_BLK_T_FLUSH,
                    _reserved: 0,
                    sector: 0,
                },
                GuestAddress(0x3000),
            )
            .unwrap();
        ring.avail.ring[2].set(6);
        ring.avail.idx.set(3);
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        worker.process_virtio_queues();
        assert_eq!(worker.fault, None);
        assert_eq!(ring.used.idx.get(), 3);
        assert_eq!(ring.used.ring[0].get().len, 1);
        assert_eq!(ring.used.ring[1].get().len, 513);
        assert_eq!(ring.used.ring[2].get().len, 1);
        for status in [0x1300, 0x2300, 0x3300] {
            assert_eq!(
                memory.read_obj::<u8>(GuestAddress(status)).unwrap(),
                VIRTIO_BLK_S_OK as u8
            );
        }
        let mut readback = [0; 512];
        memory
            .read_slice(&mut readback, GuestAddress(0x2100))
            .unwrap();
        assert_eq!(readback, [0x37; 512]);
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0x37; 512]);
        assert_eq!(completion.read().unwrap(), 3);
        assert_eq!(
            worker.device_queue.queue.capture_state().unwrap().next_used,
            3
        );
    }

    #[test]
    fn block_provider_read_data_and_status_share_one_writable_descriptor() {
        let backing = TempFile::new().unwrap();
        let mut bytes = [0; 4096];
        bytes[..512].fill(0x4b);
        fs::write(backing.as_path(), bytes).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x1000, 16, 1, 1);
        ring.dtable[1].set(0x1100, 513, 2, 0);
        memory
            .write_obj(
                RequestHeader {
                    request_type: virtio_bindings::virtio_blk::VIRTIO_BLK_T_IN,
                    _reserved: 0,
                    sector: 0,
                },
                GuestAddress(0x1000),
            )
            .unwrap();
        memory
            .write_slice(&[0x7f; 513], GuestAddress(0x1100))
            .unwrap();
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        worker.process_virtio_queues();
        assert_eq!(worker.fault, None);
        let mut data = [0; 512];
        memory.read_slice(&mut data, GuestAddress(0x1100)).unwrap();
        assert_eq!(data, [0x4b; 512]);
        assert_eq!(
            memory.read_obj::<u8>(GuestAddress(0x1300)).unwrap(),
            VIRTIO_BLK_S_OK as u8
        );
        assert_eq!(ring.used.idx.get(), 1);
        assert_eq!(ring.used.ring[0].get().len, 513);
        assert_eq!(completion.read().unwrap(), 1);
    }

    #[test]
    fn block_provider_used_failure_retains_performed_write_without_replay() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        write_request(&memory, &ring, 0, 0x46);
        let (mut worker, _) = request_worker(&memory, &ring, disk);
        // Notification suppression touches the mapped flags, then used-element
        // publication crosses the actual mapping boundary after the disk write.
        worker.device_queue.queue.used_ring = GuestAddress(0x3ffc);
        worker.process_virtio_queues();
        assert_eq!(
            worker.fault,
            Some(crate::virtio::lifecycle::ProviderFault::QueueState)
        );
        assert_eq!(ring.used.idx.get(), 0);
        assert_eq!(
            memory.read_obj::<u8>(GuestAddress(0x1300)).unwrap(),
            VIRTIO_BLK_S_OK as u8
        );
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0x46; 512]);
        memory
            .write_slice(&[0x99; 512], GuestAddress(0x1100))
            .unwrap();
        worker.process_virtio_queues();
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0x46; 512]);
        assert!(worker.device_queue.queue.capture_state().is_err());
    }

    #[test]
    fn block_provider_real_irq_backpressure_is_sticky_after_used_publication() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        write_request(&memory, &ring, 0, 0x52);
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        completion.write(u64::MAX - 1).unwrap();
        worker.process_virtio_queues();
        assert_eq!(ring.used.idx.get(), 1);
        assert_eq!(
            worker.fault,
            Some(crate::virtio::lifecycle::ProviderFault::Notification)
        );
        assert_eq!(completion.read().unwrap(), u64::MAX - 1);
        assert!(worker.device_queue.queue.capture_state().is_err());
        memory
            .write_slice(&[0x99; 512], GuestAddress(0x1100))
            .unwrap();
        worker.process_virtio_queues();
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0x52; 512]);
    }

    #[test]
    fn block_provider_real_backend_errors_complete_and_keep_serving() {
        use virtio_bindings::virtio_blk::{VIRTIO_BLK_S_IOERR, VIRTIO_BLK_T_IN};

        for failed_read in [true, false] {
            let backing = TempFile::new().unwrap();
            let original = vec![0x27; 128 * 1024];
            fs::write(backing.as_path(), &original).unwrap();
            // Actual descriptor access modes cause preadv/pwritev to return
            // EBADF; no injected errno or synthetic backend is involved.
            let file = fs::OpenOptions::new()
                .read(!failed_read)
                .write(failed_read)
                .open(backing.as_path())
                .unwrap();
            let file = ImagoFile::try_from(file).unwrap();
            let alignment = file.req_align().max(file.mem_align()).max(512);
            assert!(alignment <= original.len());
            let storage: Box<dyn DynStorage> = Box::new(file);
            let raw = Raw::open_image(storage, true).unwrap();
            let disk = DiskProperties::new(
                Arc::new(Mutex::new(FormatAccess::new(raw))),
                b"real-backend-error".to_vec(),
                CacheType::Writeback,
            )
            .unwrap();
            let memory =
                RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000 + alignment)]).unwrap();
            let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
            write_request(&memory, &ring, 0, 0x46);
            if failed_read {
                memory
                    .write_obj(VIRTIO_BLK_T_IN, GuestAddress(0x1000))
                    .unwrap();
                ring.dtable[1].set(0x1100, 512, 3, 2);
            }
            let (mut worker, completion) = request_worker(&memory, &ring, disk);
            worker.process_virtio_queues();
            assert_eq!(worker.fault, None);
            assert!(worker.backend_failed);
            assert_eq!(ring.used.idx.get(), 1);
            assert_eq!(ring.used.ring[0].get().id, 0);
            assert_eq!(ring.used.ring[0].get().len, if failed_read { 0 } else { 1 });
            assert_eq!(
                memory.read_obj::<u8>(GuestAddress(0x1300)).unwrap(),
                VIRTIO_BLK_S_IOERR as u8
            );
            assert_eq!(completion.read().unwrap(), 1);
            assert!(worker.device_queue.queue.capture_state().is_ok());

            // A fresh kick after the error must still execute real I/O.
            // The write-only fd cannot satisfy imago's alignment probe or
            // read-modify-write padding. Use its actual alignment for both
            // offset and length so this operation needs no backend reads.
            write_request(&memory, &ring, 1, 0x58);
            memory
                .write_obj(
                    RequestHeader {
                        request_type: if failed_read {
                            virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT
                        } else {
                            VIRTIO_BLK_T_IN
                        },
                        _reserved: 0,
                        sector: 0,
                    },
                    GuestAddress(0x2000),
                )
                .unwrap();
            ring.dtable[4].set(
                0x10000,
                u32::try_from(alignment).unwrap(),
                if failed_read { 1 } else { 3 },
                5,
            );
            memory
                .write_slice(&vec![0x58; alignment], GuestAddress(0x10000))
                .unwrap();
            worker.device_queue.event.write(1).unwrap();
            worker.process_queue_event();
            assert_eq!(worker.fault, None);
            assert_eq!(ring.used.idx.get(), 2);
            assert_eq!(ring.used.ring[1].get().id, 3);
            assert_eq!(
                ring.used.ring[1].get().len,
                if failed_read {
                    1
                } else {
                    u32::try_from(alignment + 1).unwrap()
                }
            );
            assert_eq!(
                memory.read_obj::<u8>(GuestAddress(0x2300)).unwrap(),
                VIRTIO_BLK_S_OK as u8
            );
            assert_eq!(completion.read().unwrap(), 1);
            if failed_read {
                assert_eq!(
                    &fs::read(backing.as_path()).unwrap()[..alignment],
                    &vec![0x58; alignment]
                );
            } else {
                let mut data = vec![0; alignment];
                memory.read_slice(&mut data, GuestAddress(0x10000)).unwrap();
                assert_eq!(data, vec![0x27; alignment]);
                assert_eq!(fs::read(backing.as_path()).unwrap(), original);
            }
            // Even a successful real flush cannot erase the earlier backend
            // failure when the owner is handed back for capture/terminal drain.
            worker.disk.checked_sync().unwrap();
            let (queue, _, fault) = worker.into_parts();
            assert_eq!(fault, Some(crate::virtio::lifecycle::ProviderFault::Worker));
            let state = queue.queue.capture_state().unwrap();
            assert_eq!((state.next_avail, state.next_used), (2, 2));
        }
    }

    #[test]
    fn block_provider_malformed_header_keeps_owned_head_without_backend_effects() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        write_request(&memory, &ring, 0, 0x46);
        ring.dtable[0].set(0x1000, 8, 1, 2);
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        worker.process_virtio_queues();
        assert_eq!(
            worker.fault,
            Some(crate::virtio::lifecycle::ProviderFault::QueueState)
        );
        assert_eq!(ring.used.idx.get(), 0);
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0; 512]);
        assert!(completion.read().is_err());
        assert!(worker.device_queue.queue.capture_state().is_err());
    }

    #[test]
    fn block_provider_full_chain_rejects_malformed_tail_cycle_flags_and_direction_before_effects() {
        for malformed in 0..4 {
            let backing = TempFile::new().unwrap();
            backing.as_file().set_len(4096).unwrap();
            let (disk, _) = open_raw(backing.as_path());
            let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
            let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
            write_request(&memory, &ring, 0, 0x46);
            match malformed {
                0 => {
                    // The valid status prefix must not hide an invalid NEXT tail.
                    ring.dtable[2].set(0x1300, 1, 3, 3);
                    ring.dtable[3].set(0x1310, 1, 3, 8);
                }
                1 => {
                    // Zero-sized cyclic tails formerly truncated into a valid prefix.
                    ring.dtable[2].set(0x1300, 1, 3, 3);
                    ring.dtable[3].set(0x1310, 0, 3, 3);
                }
                2 => ring.dtable[2].set(0x1300, 1, 6, 0),
                3 => {
                    ring.dtable[2].set(0x1300, 1, 3, 3);
                    ring.dtable[3].set(0x1310, 0, 0, 0);
                }
                _ => unreachable!("bounded cases"),
            }
            let (mut worker, completion) = request_worker(&memory, &ring, disk);
            worker.process_virtio_queues();
            assert_eq!(
                worker.fault,
                Some(crate::virtio::lifecycle::ProviderFault::QueueState),
                "case {malformed}"
            );
            assert_eq!(ring.used.idx.get(), 0, "case {malformed}");
            assert_eq!(
                memory.read_obj::<u8>(GuestAddress(0x1300)).unwrap(),
                0xff,
                "case {malformed}"
            );
            assert_eq!(
                &fs::read(backing.as_path()).unwrap()[..512],
                &[0; 512],
                "case {malformed}"
            );
            assert!(completion.read().is_err(), "case {malformed}");
            assert!(
                worker.device_queue.queue.capture_state().is_err(),
                "case {malformed}"
            );
            ring.dtable[2].set(0x1300, 1, 2, 0);
            worker.process_virtio_queues();
            assert_eq!(
                &fs::read(backing.as_path()).unwrap()[..512],
                &[0; 512],
                "case {malformed} replay"
            );
        }
    }

    #[test]
    fn block_provider_overflowing_sector_is_ioerr_without_wrapped_disk_write() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        write_request(&memory, &ring, 0, 0x46);
        memory.write_obj(u64::MAX, GuestAddress(0x1008)).unwrap();
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        worker.process_virtio_queues();
        assert_eq!(
            worker.fault,
            Some(crate::virtio::lifecycle::ProviderFault::Worker)
        );
        assert_eq!(ring.used.idx.get(), 1);
        assert_eq!(
            memory.read_obj::<u8>(GuestAddress(0x1300)).unwrap(),
            virtio_bindings::virtio_blk::VIRTIO_BLK_S_IOERR as u8
        );
        assert_eq!(ring.used.ring[0].get().len, 1);
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0; 512]);
        assert_eq!(completion.read().unwrap(), 1);
        assert!(worker.device_queue.queue.capture_state().is_err());
    }

    #[test]
    fn block_provider_missing_status_retains_owned_head_and_does_not_write_disk() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        write_request(&memory, &ring, 0, 0x46);
        ring.dtable[1].set(0x1100, 512, 0, 0);
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        worker.process_virtio_queues();
        assert_eq!(
            worker.fault,
            Some(crate::virtio::lifecycle::ProviderFault::QueueState)
        );
        assert_eq!(ring.used.idx.get(), 0);
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..512], &[0; 512]);
        assert!(completion.read().is_err());
        assert!(worker.device_queue.queue.capture_state().is_err());
    }

    #[test]
    fn block_provider_closure_finishes_owned_write_and_leaves_next_head_unpopped() {
        use polly::event_manager::{BarrierGeneration, BarrierKey, OperationId};
        use std::time::Duration;

        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let (disk, _) = open_raw(backing.as_path());
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        write_request(&memory, &ring, 0, 0x61);
        write_request(&memory, &ring, 1, 0x62);
        let (mut worker, completion) = request_worker(&memory, &ring, disk);
        let (owned_tx, owned_rx) = crossbeam_channel::bounded(1);
        let (proceed_tx, proceed_rx) = crossbeam_channel::bounded(1);
        worker.acquired = Some((owned_tx, proceed_rx));
        let admission = worker.admission.clone();
        let thread = std::thread::spawn(move || worker.work());
        assert_eq!(owned_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
        let key = BarrierKey {
            operation: OperationId(19),
            generation: BarrierGeneration(7),
        };
        admission.lock().expect("actual acquisition gate").barrier = Some(key);
        assert!(!thread.is_finished());
        assert_eq!(ring.used.idx.get(), 0);
        assert_eq!(&fs::read(backing.as_path()).unwrap()[..1024], &[0; 1024]);
        proceed_tx.send(()).unwrap();
        let worker = thread.join().unwrap();
        assert_eq!(worker.fault, None);
        let state = worker.device_queue.queue.capture_state().unwrap();
        assert_eq!((state.next_avail, state.next_used), (1, 1));
        assert_eq!(ring.used.idx.get(), 1);
        assert_eq!(completion.read().unwrap(), 1);
        assert_eq!(
            memory.read_obj::<u8>(GuestAddress(0x1300)).unwrap(),
            VIRTIO_BLK_S_OK as u8
        );
        assert_eq!(memory.read_obj::<u8>(GuestAddress(0x2300)).unwrap(), 0xff);
        let bytes = fs::read(backing.as_path()).unwrap();
        assert_eq!(&bytes[..512], &[0x61; 512]);
        assert_eq!(&bytes[512..1024], &[0; 512]);
    }
}
