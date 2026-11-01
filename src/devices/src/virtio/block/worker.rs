use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::device::{CacheType, DiskProperties};

use crate::virtio::{InterruptTransport, RuntimeGuestMemory};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::result;
use std::thread;
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

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: RuntimeGuestMemory,
    disk: DiskProperties,
    stop_fd: EventFd,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: RuntimeGuestMemory,
        disk: DiskProperties,
        stop_fd: EventFd,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_ev_fd = self.device_queue.event.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();

        let mut epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                self.process_queue_event();
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn process_queue_event(&mut self) {
        if let Err(e) = self.device_queue.event.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process device virtio queue(s).
    fn process_virtio_queues(&mut self) {
        let mem = self.mem.clone();
        loop {
            self.device_queue.queue.disable_notification(&mem).unwrap();

            self.process_queue(&mem);

            if !self.device_queue.queue.enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    fn process_queue(&mut self, mem: &RuntimeGuestMemory) {
        while let Some(head) = self.device_queue.queue.pop(mem) {
            let mut reader = match Reader::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let mut writer = match Writer::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let request_header: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    error!("invalid request header: {e:?}");
                    continue;
                }
            };

            let (status, len): (u8, usize) =
                match self.process_request(request_header, &mut reader, &mut writer) {
                    Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                    Err(e) => {
                        error!("error processing request: {e:?}");
                        (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                    }
                };

            if let Err(e) = writer.write_obj(status) {
                error!("Failed to write virtio block status: {e:?}")
            }

            if let Err(e) = self
                .device_queue
                .queue
                .add_used(mem, head.index, len as u32)
            {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if self.device_queue.queue.needs_notification(mem).unwrap()
                && let Err(e) = self.interrupt.try_signal_used_queue()
            {
                error!("error signalling queue: {e:?}");
            }
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
                let data_len = writer.available_bytes() - 1;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(&self.disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    reader
                        .read_to_at(&self.disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::ReadingFromDescriptor)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = self.disk.file.lock().unwrap();
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync().map_err(RequestError::FlushingToDisk)?;
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
                self.disk
                    .file
                    .lock()
                    .unwrap()
                    .discard_to_zero(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::Discarding)?;
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                if unmap {
                    self.disk
                        .file
                        .lock()
                        .unwrap()
                        .discard_to_zero(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    self.disk
                        .file
                        .lock()
                        .unwrap()
                        .write_zeroes(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::WritingZeroes)?;
                }
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
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
        let interrupt = InterruptTransport::new(irqchip, "block-zero-range".into())
            .expect("eventfd interrupt transport");
        let completion = interrupt.event().try_clone().expect("completion event");
        let event = Arc::new(EventFd::new(EFD_NONBLOCK).expect("queue event"));
        let mut worker = BlockWorker::new(
            DeviceQueue::new(queue.create_queue(), event.clone()),
            interrupt,
            memory.clone(),
            disk,
            EventFd::new(EFD_NONBLOCK).expect("stop event"),
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
}
