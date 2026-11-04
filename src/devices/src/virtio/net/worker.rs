use crate::virtio::descriptor_utils::{DescriptorChainSnapshot, ValidatedDescriptorChain};
use crate::virtio::lifecycle::ProviderFault;
use crate::virtio::net::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::net::device::VirtioNetBackend;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, VNET_HDR_LEN};
use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
use polly::event_manager::{BarrierKey, BarrierRequest};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestAddress;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointMode {
    Open,
    ActivationFenced,
}

pub(crate) struct WorkerAdmission {
    pub closed: bool,
    pub stop: bool,
    pub running: bool,
    pub mode: EndpointMode,
    pub release: Option<BarrierRequest>,
    pub released: Option<BarrierKey>,
}

pub(crate) struct ParkedNetWorker {
    pub admission: Arc<Mutex<WorkerAdmission>>,
    pub wake: Arc<EventFd>,
    pub fault: Option<ProviderFault>,
    mem: RuntimeGuestMemory,
    interrupt: InterruptTransport,
    backend: Box<dyn NetBackend + Send>,
    // Keep frame storage out of the movable control/worker handoff objects.
    rx_frame: Box<[u8]>,
    pub rx_len: usize,
    pub rx_deferred: bool,
    tx_frame: Box<[u8]>,
    tx_len: usize,
    tx_deferred: bool,
    rx_chain: Option<DescriptorChainSnapshot>,
    tx_chain: Option<DescriptorChainSnapshot>,
}

pub(crate) struct NetWorker {
    pub rx_q: DeviceQueue,
    pub tx_q: DeviceQueue,
    pub state: ParkedNetWorker,
}

impl ParkedNetWorker {
    pub fn new(
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        features: u64,
        config: VirtioNetBackend,
        mode: EndpointMode,
    ) -> Result<Self, ConnectError> {
        let backend: Box<dyn NetBackend + Send> = match config {
            VirtioNetBackend::UnixstreamFd(fd) => {
                // The public FD constructor transfers ownership to the device.
                Box::new(Unixstream::new(unsafe { OwnedFd::from_raw_fd(fd) }))
            }
            VirtioNetBackend::UnixstreamPath(path) => Box::new(Unixstream::open(path)?),
            VirtioNetBackend::ManagedUnixgram(fd) => Box::new(Unixgram::new(
                nix::unistd::dup(fd.as_ref()).map_err(ConnectError::CreateSocket)?,
            )),
            VirtioNetBackend::UnixgramFd(fd) => {
                Box::new(Unixgram::new(unsafe { OwnedFd::from_raw_fd(fd) }))
            }
            VirtioNetBackend::UnixgramPath(path, magic) => Box::new(Unixgram::open(path, magic)?),
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(name) => Box::new(Tap::new(name, features)?),
        };
        #[cfg(not(target_os = "linux"))]
        let _ = features;
        let wake = Arc::new(
            EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(|_| ConnectError::CreateSocket(nix::Error::EIO))?,
        );
        Ok(Self {
            admission: Arc::new(Mutex::new(WorkerAdmission {
                closed: false,
                stop: false,
                running: false,
                mode,
                release: None,
                released: None,
            })),
            wake,
            fault: None,
            mem,
            interrupt,
            backend,
            rx_frame: vec![0; MAX_BUFFER_SIZE].into_boxed_slice(),
            rx_len: 0,
            rx_deferred: false,
            tx_frame: vec![0; MAX_BUFFER_SIZE].into_boxed_slice(),
            tx_len: 0,
            tx_deferred: false,
            rx_chain: None,
            tx_chain: None,
        })
    }

    pub fn discard_ingress(&mut self, deadline: std::time::Instant) -> Result<bool, ProviderFault> {
        self.rx_len = 0;
        self.rx_deferred = false;
        for _ in 0..256 {
            if std::time::Instant::now() >= deadline {
                return Err(ProviderFault::Deadline);
            }
            match self.backend.read_frame(&mut self.rx_frame) {
                Ok(_) => {}
                Err(ReadError::NothingRead) => return Ok(true),
                Err(_) => return Err(ProviderFault::Worker),
            }
        }
        Ok(false)
    }

    pub fn attach(mut self, rx_q: DeviceQueue, tx_q: DeviceQueue) -> NetWorker {
        self.rx_chain
            .get_or_insert_with(|| DescriptorChainSnapshot::new(rx_q.queue.get_max_size()));
        self.tx_chain
            .get_or_insert_with(|| DescriptorChainSnapshot::new(tx_q.queue.get_max_size()));
        NetWorker {
            rx_q,
            tx_q,
            state: self,
        }
    }
}

impl NetWorker {
    pub fn run(slot: Arc<Mutex<Option<Self>>>) -> std::io::Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(move || {
                let worker = match slot.lock() {
                    Ok(mut slot) => slot.take(),
                    Err(_) => None,
                };
                if let Some(mut worker) = worker {
                    if let Err(fault) = worker.work() {
                        worker.state.fault.get_or_insert(fault);
                    }
                    if let Ok(mut admission) = worker.state.admission.lock() {
                        admission.running = false;
                    }
                    let wake = Arc::clone(&worker.state.wake);
                    if let Ok(mut slot) = slot.lock() {
                        *slot = Some(worker);
                    }
                    let _ = wake.write(1);
                }
            })
    }

    fn closed(&self) -> Result<bool, ProviderFault> {
        let admission = self
            .state
            .admission
            .lock()
            .map_err(|_| ProviderFault::Worker)?;
        Ok(admission.closed || admission.stop)
    }

    fn work(&mut self) -> Result<(), ProviderFault> {
        let mut epoll = Epoll::new().map_err(|_| ProviderFault::Worker)?;
        for (fd, flags) in [
            (self.rx_q.event.as_raw_fd(), EventSet::IN),
            (self.tx_q.event.as_raw_fd(), EventSet::IN),
            (self.state.wake.as_raw_fd(), EventSet::IN),
            (
                self.state.backend.raw_socket_fd(),
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
            ),
        ] {
            epoll
                .ctl(
                    ControlOperation::Add,
                    fd,
                    &EpollEvent::new(flags, fd as u64),
                )
                .map_err(|_| ProviderFault::Worker)?;
        }
        self.process_tx()?;
        self.process_rx()?;
        self.state
            .admission
            .lock()
            .map_err(|_| ProviderFault::Worker)?
            .running = true;
        let mut events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            if self.closed()? {
                return Ok(());
            }
            self.release_activation()?;
            #[cfg(target_os = "macos")]
            if self.state.tx_deferred {
                epoll.add_oneshot_timer(self.state.backend.write_retry_delay_us(), (-2i32) as u64);
            }
            let count = match epoll.wait(events.len(), -1, &mut events) {
                Ok(count) => count,
                Err(error) if error.raw_os_error() == Some(nix::Error::EINTR as i32) => continue,
                Err(_) => return Err(ProviderFault::Worker),
            };
            for event in &events[..count] {
                if self.closed()? {
                    return Ok(());
                }
                let fd = event.fd();
                if fd == self.state.wake.as_raw_fd() {
                    let _ = self.state.wake.read();
                    self.release_activation()?;
                    self.process_tx()?;
                    self.process_rx()?;
                } else if fd == self.rx_q.event.as_raw_fd() {
                    let _ = self.rx_q.event.read();
                    self.process_rx()?;
                } else if fd == self.tx_q.event.as_raw_fd() {
                    let _ = self.tx_q.event.read();
                    self.process_tx()?;
                } else if fd == self.state.backend.raw_socket_fd() {
                    if event
                        .event_set()
                        .intersects(EventSet::HANG_UP | EventSet::READ_HANG_UP)
                    {
                        return Err(ProviderFault::Worker);
                    }
                    if event.event_set().contains(EventSet::IN) {
                        self.process_rx()?;
                    }
                    if event.event_set().contains(EventSet::OUT) {
                        self.process_tx()?;
                    }
                } else {
                    #[cfg(target_os = "macos")]
                    if fd == -2 {
                        self.process_tx()?;
                    }
                }
            }
        }
    }

    fn notify(queue: &mut DeviceQueue, state: &ParkedNetWorker) -> Result<(), ProviderFault> {
        if queue
            .queue
            .needs_notification(&state.mem)
            .map_err(|_| ProviderFault::QueueState)?
        {
            state
                .interrupt
                .try_signal_used_queue()
                .map_err(|_| ProviderFault::Notification)?;
        }
        Ok(())
    }

    fn validate_tx_shape(chain: &ValidatedDescriptorChain<'_>) -> Result<usize, ProviderFault> {
        let mut length = 0usize;
        for descriptor in chain.descriptors() {
            if descriptor.flags & VIRTQ_DESC_F_WRITE != 0 {
                return Err(ProviderFault::QueueState);
            }
            length = length
                .checked_add(descriptor.len as usize)
                .ok_or(ProviderFault::QueueState)?;
            if length > MAX_BUFFER_SIZE {
                return Err(ProviderFault::QueueState);
            }
        }
        if length < VNET_HDR_LEN {
            return Err(ProviderFault::QueueState);
        }
        Ok(length)
    }

    fn process_tx(&mut self) -> Result<(), ProviderFault> {
        self.tx_q
            .queue
            .disable_notification(&self.state.mem)
            .map_err(|_| ProviderFault::QueueState)?;
        loop {
            if self.state.backend.has_unfinished_write() {
                match self
                    .state
                    .backend
                    .try_finish_write(VNET_HDR_LEN, &self.state.tx_frame[..self.state.tx_len])
                {
                    Ok(()) => {
                        self.state.tx_len = 0;
                        self.state.tx_deferred = false;
                    }
                    Err(WriteError::NothingWritten | WriteError::PartialWrite) => break,
                    Err(_) => return Err(ProviderFault::Worker),
                }
            }
            let admission = self
                .state
                .admission
                .lock()
                .map_err(|_| ProviderFault::Worker)?;
            if admission.closed || admission.stop {
                break;
            }
            let mode = admission.mode;
            let head = self.tx_q.queue.pop(&self.state.mem);
            drop(admission);
            let Some(head) = head else {
                self.tx_q
                    .queue
                    .capture_state()
                    .map_err(|_| ProviderFault::QueueState)?;
                break;
            };
            let index = head.index;
            let chain = self
                .state
                .tx_chain
                .as_mut()
                .ok_or(ProviderFault::Worker)?
                .read(head)
                .map_err(|_| ProviderFault::QueueState)?;
            let len = Self::validate_tx_shape(&chain)?;
            if mode != EndpointMode::ActivationFenced {
                let mut copied = 0usize;
                for descriptor in chain.descriptors() {
                    let end = copied + descriptor.len as usize;
                    self.state
                        .mem
                        .read_slice(
                            &mut self.state.tx_frame[copied..end],
                            GuestAddress(descriptor.addr),
                        )
                        .map_err(|_| ProviderFault::DeviceState)?;
                    copied = end;
                }
            }
            self.state.tx_len = len;
            let result = if mode == EndpointMode::ActivationFenced {
                Ok(())
            } else {
                self.state
                    .backend
                    .write_frame(VNET_HDR_LEN, &mut self.state.tx_frame[..len])
            };
            match result {
                Ok(()) => {
                    self.state.tx_len = 0;
                    self.state.tx_deferred = false;
                    self.tx_q
                        .queue
                        .add_used(&self.state.mem, index, 0)
                        .map_err(|_| ProviderFault::QueueState)?;
                    Self::notify(&mut self.tx_q, &self.state)?;
                }
                Err(WriteError::NothingWritten) => {
                    self.tx_q
                        .queue
                        .undo_pop(index)
                        .map_err(|_| ProviderFault::QueueState)?;
                    self.state.tx_deferred = true;
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    self.tx_q
                        .queue
                        .add_used(&self.state.mem, index, 0)
                        .map_err(|_| ProviderFault::QueueState)?;
                    Self::notify(&mut self.tx_q, &self.state)?;
                    self.state.tx_deferred = true;
                    break;
                }
                Err(_) => return Err(ProviderFault::Worker),
            }
        }
        if self
            .tx_q
            .queue
            .enable_notification(&self.state.mem)
            .map_err(|_| ProviderFault::QueueState)?
            && !self.state.tx_deferred
            && !self.closed()?
        {
            self.state
                .wake
                .write(1)
                .map_err(|_| ProviderFault::Worker)?;
        }
        Ok(())
    }

    fn process_rx(&mut self) -> Result<(), ProviderFault> {
        loop {
            let admission = self
                .state
                .admission
                .lock()
                .map_err(|_| ProviderFault::Worker)?;
            if admission.closed || admission.stop {
                return Ok(());
            }
            if !self.state.rx_deferred {
                match self.state.backend.read_frame(&mut self.state.rx_frame) {
                    Ok(len) => {
                        self.state.rx_len = len;
                        self.state.rx_deferred = true;
                    }
                    Err(ReadError::NothingRead) => return Ok(()),
                    Err(_) => return Err(ProviderFault::Worker),
                }
            }
            if admission.mode == EndpointMode::ActivationFenced {
                self.state.rx_deferred = false;
                self.state.rx_len = 0;
                continue;
            }
            let head = self.rx_q.queue.pop(&self.state.mem);
            drop(admission);
            let Some(head) = head else {
                self.rx_q
                    .queue
                    .capture_state()
                    .map_err(|_| ProviderFault::QueueState)?;
                if self
                    .rx_q
                    .queue
                    .enable_notification(&self.state.mem)
                    .map_err(|_| ProviderFault::QueueState)?
                {
                    continue;
                }
                return Ok(());
            };
            let index = head.index;
            let chain = self
                .state
                .rx_chain
                .as_mut()
                .ok_or(ProviderFault::Worker)?
                .read(head)
                .map_err(|_| ProviderFault::QueueState)?;
            let mut capacity = 0usize;
            for descriptor in chain.descriptors() {
                if descriptor.flags & VIRTQ_DESC_F_WRITE == 0 {
                    return Err(ProviderFault::QueueState);
                }
                capacity = capacity
                    .checked_add(descriptor.len as usize)
                    .ok_or(ProviderFault::QueueState)?;
            }
            if capacity < self.state.rx_len {
                return Err(ProviderFault::QueueState);
            }
            let mut written = 0usize;
            for descriptor in chain.descriptors() {
                let count = (descriptor.len as usize).min(self.state.rx_len - written);
                self.state
                    .mem
                    .write_slice(
                        &self.state.rx_frame[written..written + count],
                        GuestAddress(descriptor.addr),
                    )
                    .map_err(|_| ProviderFault::DeviceState)?;
                written += count;
                if written == self.state.rx_len {
                    break;
                }
            }
            self.rx_q
                .queue
                .add_used(&self.state.mem, index, written as u32)
                .map_err(|_| ProviderFault::QueueState)?;
            Self::notify(&mut self.rx_q, &self.state)?;
            self.state.rx_deferred = false;
            self.state.rx_len = 0;
        }
    }

    fn release_activation(&mut self) -> Result<(), ProviderFault> {
        let shared = Arc::clone(&self.state.admission);
        let mut admission = shared.lock().map_err(|_| ProviderFault::Worker)?;
        let Some(request) = admission.release else {
            return Ok(());
        };
        if admission.closed || admission.stop {
            return Ok(());
        }
        if std::time::Instant::now() >= request.deadline {
            return Err(ProviderFault::Deadline);
        }
        if admission.mode != EndpointMode::ActivationFenced {
            return Err(ProviderFault::InvalidTransition);
        }
        // The caller holds the managed reservation's ingress fence through this ACK.
        if !self.state.discard_ingress(request.deadline)? {
            self.state
                .wake
                .write(1)
                .map_err(|_| ProviderFault::Worker)?;
            return Ok(());
        }
        let count = self.tx_q.queue.len(&self.state.mem);
        if count > self.tx_q.queue.actual_size() {
            return Err(ProviderFault::QueueState);
        }
        for _ in 0..count {
            let head = self
                .tx_q
                .queue
                .pop(&self.state.mem)
                .ok_or(ProviderFault::QueueState)?;
            let index = head.index;
            let chain = self
                .state
                .tx_chain
                .as_mut()
                .ok_or(ProviderFault::Worker)?
                .read(head)
                .map_err(|_| ProviderFault::QueueState)?;
            Self::validate_tx_shape(&chain)?;
            self.tx_q
                .queue
                .add_used(&self.state.mem, index, 0)
                .map_err(|_| ProviderFault::QueueState)?;
        }
        Self::notify(&mut self.tx_q, &self.state)?;
        self.state.tx_len = 0;
        self.state.tx_deferred = false;
        if !self.tx_q.queue.is_empty(&self.state.mem) {
            self.state
                .wake
                .write(1)
                .map_err(|_| ProviderFault::Worker)?;
            return Ok(());
        }
        admission.mode = EndpointMode::Open;
        admission.released = Some(request.key);
        admission.release = None;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use crate::legacy::{IrqChipDevice, KvmIoapic};
    use crate::virtio::lifecycle::ProviderFault;
    use crate::virtio::net::VNET_HDR_LEN;
    use crate::virtio::net::device::VirtioNetBackend;
    use crate::virtio::net::worker::{EndpointMode, NetWorker, ParkedNetWorker};
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
    use std::os::unix::net::UnixDatagram;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use utils::eventfd::EventFd;
    use vm_memory::GuestAddress;

    fn worker(
        memory: &RuntimeGuestMemory,
        rx: DeviceQueue,
        tx: DeviceQueue,
        mode: EndpointMode,
    ) -> (NetWorker, UnixDatagram) {
        let (socket, peer) = UnixDatagram::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let interrupt = InterruptTransport::new(
            Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
            "net-provider-unit".into(),
            None,
        )
        .unwrap();
        let state = ParkedNetWorker::new(
            memory.clone(),
            interrupt,
            0,
            VirtioNetBackend::ManagedUnixgram(Arc::new(socket.into())),
            mode,
        )
        .unwrap();
        (state.attach(rx, tx), peer)
    }

    fn queue(ring: &VirtQueue<'_>) -> DeviceQueue {
        DeviceQueue::new(ring.create_queue(), Arc::new(EventFd::new(0).unwrap()))
    }

    fn request() -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(19),
                generation: BarrierGeneration(7),
            },
            deadline: Instant::now() + Duration::from_secs(2),
        }
    }

    #[test]
    fn net_provider_source_retains_starved_ingress_and_closed_acquisition() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let rx_queue = queue(&rx);
        let original_event = Arc::clone(&rx_queue.event);
        let (mut worker, peer) = worker(&memory, rx_queue, queue(&tx), EndpointMode::Open);
        peer.send(b"source-before-pause").unwrap();
        worker.process_rx().unwrap();
        assert!(worker.state.rx_deferred);
        assert_eq!(worker.state.rx_len, VNET_HDR_LEN + 19);
        worker.state.admission.lock().unwrap().closed = true;
        rx.dtable[0].set(0x4000, 128, 2, 0);
        rx.avail.ring[0].set(0);
        rx.avail.idx.set(1);
        worker.process_rx().unwrap();
        assert_eq!(rx.used.idx.get(), 0);
        assert_eq!(worker.rx_q.queue.capture_state().unwrap().next_avail, 0);
        assert!(Arc::ptr_eq(&original_event, &worker.rx_q.event));
        worker.state.admission.lock().unwrap().closed = false;
        worker.process_rx().unwrap();
        assert!(!worker.state.rx_deferred);
        assert_eq!(rx.used.idx.get(), 1);
        let mut bytes = [0; 19];
        memory
            .read_slice(&mut bytes, GuestAddress(0x4000 + VNET_HDR_LEN as u64))
            .unwrap();
        assert_eq!(&bytes, b"source-before-pause");
    }

    #[test]
    fn net_provider_activation_drops_both_directions_and_release_backlog() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        rx.dtable[0].set(0x4000, 128, 2, 0);
        rx.avail.ring[0].set(0);
        rx.avail.idx.set(1);
        tx.dtable[0].set(0x5000, (VNET_HDR_LEN + 5) as u32, 0, 0);
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        memory
            .write_slice(b"stale", GuestAddress(0x5000 + VNET_HDR_LEN as u64))
            .unwrap();
        let (mut worker, peer) = worker(
            &memory,
            queue(&rx),
            queue(&tx),
            EndpointMode::ActivationFenced,
        );
        peer.send(b"fenced-ingress").unwrap();
        worker.process_rx().unwrap();
        worker.process_tx().unwrap();
        assert_eq!(rx.used.idx.get(), 0);
        assert_eq!(tx.used.idx.get(), 1);
        let mut packet = [0; 128];
        assert_eq!(
            peer.recv(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        // These frames arrive after the last worker callback but before release.
        peer.send(b"queued-during-fence").unwrap();
        tx.dtable[1].set(0x5100, (VNET_HDR_LEN + 5) as u32, 0, 0);
        tx.avail.ring[1].set(1);
        tx.avail.idx.set(2);
        memory
            .write_slice(b"older", GuestAddress(0x5100 + VNET_HDR_LEN as u64))
            .unwrap();
        let release = request();
        worker.state.admission.lock().unwrap().release = Some(release);
        worker.release_activation().unwrap();
        assert_eq!(
            worker.state.admission.lock().unwrap().released,
            Some(release.key)
        );
        assert_eq!(tx.used.idx.get(), 2);
        worker.process_rx().unwrap();
        assert_eq!(rx.used.idx.get(), 0);
        assert_eq!(
            peer.recv(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        peer.send(b"fresh").unwrap();
        worker.process_rx().unwrap();
        assert_eq!(rx.used.idx.get(), 1);
        tx.dtable[2].set(0x5200, (VNET_HDR_LEN + 5) as u32, 0, 0);
        tx.avail.ring[2].set(2);
        tx.avail.idx.set(3);
        memory
            .write_slice(b"fresh", GuestAddress(0x5200 + VNET_HDR_LEN as u64))
            .unwrap();
        worker.process_tx().unwrap();
        assert_eq!(peer.recv(&mut packet).unwrap(), 5);
        assert_eq!(&packet[..5], b"fresh");
    }

    #[test]
    fn net_provider_used_publication_failure_cannot_replay_external_send() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        tx.dtable[0].set(0x5000, (VNET_HDR_LEN + 4) as u32, 0, 0);
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        memory
            .write_slice(b"once", GuestAddress(0x5000 + VNET_HDR_LEN as u64))
            .unwrap();
        let (mut worker, peer) = worker(&memory, queue(&rx), queue(&tx), EndpointMode::Open);
        let original_used_ring = worker.tx_q.queue.used_ring;
        // The flags write before pop succeeds; only the post-send used element is unmapped.
        worker.tx_q.queue.used_ring = GuestAddress(0xfffc);
        assert_eq!(worker.process_tx(), Err(ProviderFault::QueueState));
        assert_eq!(
            memory
                .read_obj::<u16>(GuestAddress(0xfffc))
                .expect("notification flags were written"),
            1
        );
        assert_eq!(
            memory
                .read_obj::<u16>(GuestAddress(0xfffe))
                .expect("unpublished used index"),
            0
        );
        let mut packet = [0; 128];
        assert_eq!(peer.recv(&mut packet).unwrap(), 4);
        assert_eq!(&packet[..4], b"once");
        assert_eq!(
            (
                worker.tx_q.queue.next_avail.0,
                worker.tx_q.queue.next_used.0
            ),
            (1, 0)
        );
        assert!(matches!(
            worker.tx_q.queue.capture_state(),
            Err(crate::virtio::queue::Error::Ownership(
                crate::virtio::queue::QueueOwnershipFault::Publication
            )),
        ));
        worker.tx_q.queue.used_ring = original_used_ring;
        assert_eq!(worker.process_tx(), Err(ProviderFault::QueueState));
        assert_eq!(
            tx.used.idx.get(),
            0,
            "repair cannot publish or replay the failed external effect"
        );
        assert_eq!(
            (
                worker.tx_q.queue.next_avail.0,
                worker.tx_q.queue.next_used.0
            ),
            (1, 0)
        );
        assert_eq!(
            peer.recv(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn net_provider_datagram_backpressure_returns_only_unconsumed_head() {
        use crate::virtio::net::backend::WriteError;
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("RAM");
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        tx.dtable[0].set(0x5000, (VNET_HDR_LEN + 5) as u32, 0, 0);
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        memory
            .write_slice(b"later", GuestAddress(0x5000 + VNET_HDR_LEN as u64))
            .expect("TX bytes");
        let (mut worker, peer) = worker(&memory, queue(&rx), queue(&tx), EndpointMode::Open);
        let mut fill = vec![0; VNET_HDR_LEN + 1024];
        let mut blocked = false;
        for _ in 0..10000 {
            match worker.state.backend.write_frame(VNET_HDR_LEN, &mut fill) {
                Ok(()) => {}
                Err(WriteError::NothingWritten) => {
                    blocked = true;
                    break;
                }
                Err(error) => panic!("datagram fill failed: {error:?}"),
            }
        }
        assert!(blocked, "real endpoint must reach backpressure");
        worker.process_tx().expect("unconsumed datagram can defer");
        assert!(worker.state.tx_deferred);
        let state = worker
            .tx_q
            .queue
            .capture_state()
            .expect("no privately retained head");
        assert_eq!((state.next_avail, state.next_used), (0, 0));
        let mut packet = [0; 2048];
        while peer.recv(&mut packet).is_ok() {}
        worker.process_tx().expect("resume scan retries exact head");
        assert_eq!(peer.recv(&mut packet).expect("released endpoint"), 5);
        assert_eq!(&packet[..5], b"later");
        assert_eq!(tx.used.idx.get(), 1);
    }

    #[test]
    fn net_provider_rejects_complete_malformed_tx_tail_before_send_or_fenced_completion() {
        for malformed in 0..5 {
            for release in 0..3 {
                let memory =
                    RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("RAM");
                let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
                let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
                tx.dtable[0].set(0x5000, (VNET_HDR_LEN + 5) as u32, 1, 1);
                let (address, flags, next) = match malformed {
                    0 => (0x6000, 1, 8),
                    1 => (0x6000, 1, 0),
                    2 => (0x6000, 4, 0),
                    3 => (0x6000, 2, 0),
                    _ => (0x10000, 0, 0),
                };
                tx.dtable[1].set(address, 1, flags, next);
                tx.avail.ring[0].set(0);
                tx.avail.idx.set(1);
                memory
                    .write_slice(b"valid", GuestAddress(0x5000 + VNET_HDR_LEN as u64))
                    .expect("valid prefix");
                let mode = if release == 0 {
                    EndpointMode::Open
                } else {
                    EndpointMode::ActivationFenced
                };
                let (mut worker, peer) = worker(&memory, queue(&rx), queue(&tx), mode);
                let result = if release == 2 {
                    worker.state.admission.lock().expect("admission").release = Some(request());
                    worker.release_activation()
                } else {
                    worker.process_tx()
                };
                assert_eq!(
                    result,
                    Err(ProviderFault::QueueState),
                    "malformed={malformed} release={release}"
                );
                assert_eq!(
                    tx.used.idx.get(),
                    0,
                    "invalid tail must not publish prefix completion"
                );
                let mut packet = [0; 128];
                assert_eq!(
                    peer.recv(&mut packet)
                        .expect_err("no externally sent prefix")
                        .kind(),
                    std::io::ErrorKind::WouldBlock
                );
                assert!(
                    worker.tx_q.queue.capture_state().is_err(),
                    "owned failed head must remain sticky"
                );
                if release != 0 {
                    let admission = worker.state.admission.lock().expect("admission");
                    assert_eq!(admission.mode, EndpointMode::ActivationFenced);
                    assert!(admission.released.is_none());
                }
            }
        }
    }

    #[test]
    fn net_provider_rejects_complete_malformed_rx_tail_before_any_dma() {
        for malformed in 0..5 {
            let memory =
                RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("RAM");
            let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
            let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
            rx.dtable[0].set(0x4000, 128, 3, 1);
            let (address, flags, next) = match malformed {
                0 => (0x6000, 3, 8),
                1 => (0x6000, 3, 0),
                2 => (0x6000, 6, 0),
                3 => (0x6000, 0, 0),
                _ => (0x10000, 2, 0),
            };
            rx.dtable[1].set(address, 1, flags, next);
            rx.avail.ring[0].set(0);
            rx.avail.idx.set(1);
            memory
                .write_slice(&[0x7b; 128], GuestAddress(0x4000))
                .expect("untouched DMA target");
            let (mut worker, peer) = worker(&memory, queue(&rx), queue(&tx), EndpointMode::Open);
            peer.send(b"valid").expect("actual incoming frame");
            assert_eq!(
                worker.process_rx(),
                Err(ProviderFault::QueueState),
                "malformed={malformed}"
            );
            let mut target = [0; 128];
            memory
                .read_slice(&mut target, GuestAddress(0x4000))
                .expect("observe guest bytes");
            assert_eq!(
                target, [0x7b; 128],
                "no valid-prefix DMA before malformed tail refusal"
            );
            assert_eq!(rx.used.idx.get(), 0);
            assert!(worker.rx_q.queue.capture_state().is_err());
        }
    }
}
