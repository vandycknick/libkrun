use crate::virtio::console::console_control::MAX_PENDING_BYTES;
use crate::virtio::console::defs::{control_event, uapi};
use crate::virtio::console::device::{AVAIL_FEATURES, Console, VirtioConsoleConfig};
use crate::virtio::console::port_queue_mapping::{QueueDirection, port_id_to_queue_idx};
use crate::virtio::lifecycle::{
    DormantDeviceContext, ProviderBeginError, ProviderFault, ProviderStage, QuiesceCompletion,
    ResumeAcceptance, VirtioStateProvider,
};
use crate::virtio::{DeviceQueue, DeviceState, VirtioDevice};
use polly::event_manager::{BarrierKey, BarrierRequest};
use std::task::Poll;
use std::time::Instant;
use utils::state::{Error, Reader, Writer};
const LIMIT: usize = 262_144;
pub(crate) const CONSOLE_STATE_MAGIC: &[u8; 8] = b"KRUNCONS";
pub(crate) const CONSOLE_STATE_SCHEMA: u16 = 1;
struct SavedPort {
    name: String,
    shape: u8,
    ready: bool,
    opened: bool,
    eof: bool,
    engaged: bool,
}
struct SavedConsole {
    acked: u64,
    config: VirtioConsoleConfig,
    ports: Vec<SavedPort>,
    messages: Vec<Vec<u8>>,
}

fn decode(payload: &[u8]) -> Result<SavedConsole, Error> {
    if payload.len() > LIMIT {
        return Err(Error::Limit);
    }
    let mut reader = Reader::new(payload);
    reader.header(CONSOLE_STATE_MAGIC, CONSOLE_STATE_SCHEMA)?;
    if reader.u16()? != 1
        || reader.u32()? != uapi::VIRTIO_ID_CONSOLE
        || reader.u64()? != AVAIL_FEATURES
    {
        return Err(Error::Invalid("console profile"));
    }
    let acked = reader.u64()?;
    if acked & !AVAIL_FEATURES != 0 {
        return Err(Error::Invalid("console features"));
    }
    let config = VirtioConsoleConfig {
        cols: reader.u16()?,
        rows: reader.u16()?,
        max_nr_ports: reader.u32()?,
        emerg_wr: reader.u32()?,
    };
    let count = reader.count(64, 13)?;
    if count == 0 || config.max_nr_ports as usize != count || config.emerg_wr != 0 {
        return Err(Error::Invalid("console config"));
    }
    let mut ports = Vec::with_capacity(count);
    for id in 0..count {
        if reader.u32()? as usize != id {
            return Err(Error::Invalid("console port order"));
        }
        let name = std::str::from_utf8(reader.bytes(256)?)
            .map_err(|_| Error::Invalid("console port name"))?
            .to_owned();
        let shape = reader.u8()?;
        let (ready, opened, eof, engaged) = (
            reader.bool()?,
            reader.bool()?,
            reader.bool()?,
            reader.bool()?,
        );
        if shape & !7 != 0 || (eof && (shape & 1 == 0 || !engaged)) || (opened && !engaged) {
            return Err(Error::Invalid("console port state"));
        }
        ports.push(SavedPort {
            name,
            shape,
            ready,
            opened,
            eof,
            engaged,
        });
    }
    let count = reader.count(4096, 12)?;
    let mut messages = Vec::with_capacity(count);
    let mut message_bytes = 0usize;
    for _ in 0..count {
        let message = reader.bytes(264)?;
        message_bytes = message_bytes
            .checked_add(message.len())
            .ok_or(Error::Overflow)?;
        if message_bytes > MAX_PENDING_BYTES {
            return Err(Error::Limit);
        }
        let mut control = Reader::new(message);
        let id = control.u32()? as usize;
        let event = control.u16()?;
        let value = control.u16()?;
        if id >= ports.len() {
            return Err(Error::Invalid("console message port"));
        }
        match event {
            control_event::VIRTIO_CONSOLE_PORT_ADD if value == 0 => control.finish()?,
            control_event::VIRTIO_CONSOLE_PORT_OPEN if value <= 1 => control.finish()?,
            control_event::VIRTIO_CONSOLE_CONSOLE_PORT
                if value == 1 && ports[id].shape & 4 != 0 =>
            {
                control.finish()?
            }
            control_event::VIRTIO_CONSOLE_RESIZE if value == 0 => {
                control.u16()?;
                control.u16()?;
                control.finish()?;
            }
            control_event::VIRTIO_CONSOLE_PORT_NAME if value == 1 => {
                if control.take(control.remaining())? != ports[id].name.as_bytes() {
                    return Err(Error::Invalid("console message name"));
                }
                control.finish()?;
            }
            _ => return Err(Error::Invalid("console pending event")),
        }
        messages.push(message.to_vec());
    }
    reader.finish()?;
    Ok(SavedConsole {
        acked,
        config,
        ports,
        messages,
    })
}

impl Console {
    pub fn restore_queue_geometry(ports: usize) -> (usize, u16) {
        (
            crate::virtio::console::port_queue_mapping::num_queues(ports),
            crate::virtio::console::defs::QUEUE_SIZE,
        )
    }

    pub fn inspect_restore_payload(
        payload: &[u8],
    ) -> Result<Vec<(String, bool, bool, bool)>, ProviderFault> {
        let saved = decode(payload).map_err(ProviderFault::from)?;
        Ok(saved
            .ports
            .into_iter()
            .map(|port| {
                (
                    port.name,
                    port.shape & 1 != 0,
                    port.shape & 2 != 0,
                    port.shape & 4 != 0,
                )
            })
            .collect())
    }

    fn checked_saved(&self, payload: &[u8]) -> Result<SavedConsole, ProviderFault> {
        let saved = decode(payload).map_err(ProviderFault::from)?;
        if saved.ports.len() != self.ports.len() || self.avail_features != AVAIL_FEATURES {
            return Err(ProviderFault::DeviceState);
        }
        for (saved, actual) in saved.ports.iter().zip(&self.ports) {
            if saved.name != actual.name() || saved.shape != actual.shape() {
                return Err(ProviderFault::DeviceState);
            }
        }
        Ok(saved)
    }
    fn install_saved(&mut self, saved: SavedConsole) -> Result<(), ProviderFault> {
        self.config = saved.config;
        self.acked_features = saved.acked;
        for (port, saved) in self.ports.iter_mut().zip(saved.ports) {
            port.ready = saved.ready;
            port.opened = saved.opened;
            port.eof = saved.eof;
            port.engaged = saved.engaged;
        }
        self.control.install(saved.messages)
    }
}

impl VirtioStateProvider for Console {
    fn preflight(&self) -> Result<(), ProviderFault> {
        if matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Stopping | ProviderStage::Stopped
        ) {
            return Err(ProviderFault::InvalidTransition);
        }
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if self.ports.is_empty()
            || self.ports.len() > 64
            || self.ports.iter().any(|port| port.name().len() > 256)
        {
            return Err(ProviderFault::Unsupported);
        }
        if self.acked_features & !self.avail_features != 0 {
            return Err(ProviderFault::DeviceState);
        }
        let mut busy = false;
        let mut fault = None;
        for result in self
            .ports
            .iter()
            .map(|port| port.preflight())
            .chain(std::iter::once_with(|| self.control.preflight()))
        {
            match result {
                Ok(()) => {}
                Err(ProviderFault::LockBusy) => busy = true,
                Err(error) => {
                    fault.get_or_insert(error);
                }
            }
        }
        match fault {
            Some(fault) => Err(fault),
            None if busy => Err(ProviderFault::LockBusy),
            None => Ok(()),
        }
    }
    fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError> {
        if !matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Running | ProviderStage::Resuming
        ) {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::InvalidTransition,
            });
        }
        if Instant::now() >= request.deadline {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::Deadline,
            });
        }
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        let mut fault = None;
        for queue in self.queues.iter_mut().flatten() {
            if queue.queue.close_admission(request.key).is_err() {
                fault.get_or_insert(ProviderFault::QueueState);
            }
        }
        for port in &self.ports {
            if let Err(error) = port.close(request.key) {
                fault.get_or_insert(error);
            }
        }
        if let Some(fault) = fault {
            self.fault.get_or_insert(fault);
            return Err(ProviderBeginError {
                accepted: true,
                fault,
            });
        }
        Ok(())
    }
    fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiescing {
            return Err(ProviderFault::InvalidTransition);
        }
        let mut pending = false;
        for (id, port) in self.ports.iter_mut().enumerate() {
            if !port.running() {
                continue;
            }
            match port.poll_queues()? {
                Some(returned) => {
                    self.queues[port_id_to_queue_idx(QueueDirection::Rx, id)] = Some(returned.rx);
                    self.queues[port_id_to_queue_idx(QueueDirection::Tx, id)] = Some(returned.tx);
                    self.fault = self.fault.or(returned.fault);
                }
                None => pending = true,
            }
        }
        if pending {
            return Ok(Poll::Pending);
        }
        self.control.freeze(true)?;
        if let Err(fault) = self.control.check() {
            self.fault.get_or_insert(fault);
        }
        if self.device_state.is_activated() && self.queues.iter().any(Option::is_none) {
            return Err(ProviderFault::QueueCount);
        }
        self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
        let queues = self.queues.iter_mut().filter_map(Option::take).collect();
        Ok(Poll::Ready(QuiesceCompletion {
            queues,
            fault: self.fault,
        }))
    }
    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance {
        let previous = self.lifecycle.snapshot.quiesce_request;
        let expected = if self.device_state.is_activated() {
            self.queue_config().len()
        } else {
            0
        };
        let fault = if self.lifecycle.snapshot.stage != ProviderStage::Quiesced
            || previous.is_none_or(|old| {
                old.key.generation != request.key.generation || old.key == request.key
            }) {
            Some(ProviderFault::InvalidTransition)
        } else if queues.len() != expected {
            Some(ProviderFault::QueueCount)
        } else if Instant::now() >= request.deadline {
            Some(ProviderFault::Deadline)
        } else {
            self.fault
        };
        if let Some(fault) = fault {
            return ResumeAcceptance::Rejected { queues, fault };
        }
        let Some(previous) = previous else {
            return ResumeAcceptance::Rejected {
                queues,
                fault: ProviderFault::ForeignBarrier,
            };
        };
        self.lifecycle.begin(request, ProviderStage::Resuming);
        let register = self.queue_events.is_empty() && !queues.is_empty();
        self.queue_events = queues.iter().map(|queue| queue.event.clone()).collect();
        self.queues = queues.into_iter().map(Some).collect();
        for queue in self.queues.iter_mut().flatten() {
            if queue
                .queue
                .close_admission(previous.key)
                .and_then(|()| queue.queue.reopen_admission(previous.key))
                .is_err()
            {
                self.fault = Some(ProviderFault::QueueState);
                return ResumeAcceptance::AcceptedWithFailure(ProviderFault::QueueState);
            }
        }
        if let Err(fault) = self.control.freeze(false) {
            self.fault = Some(fault);
            return ResumeAcceptance::AcceptedWithFailure(fault);
        }
        if register && self.activate_evt.write(1).is_err() {
            self.fault = Some(ProviderFault::Notification);
            return ResumeAcceptance::AcceptedWithFailure(ProviderFault::Notification);
        }
        for id in 0..self.ports.len() {
            if self.ports[id].engaged
                && let Err(fault) = self.start_port(id)
            {
                self.fault = Some(fault);
                return ResumeAcceptance::AcceptedWithFailure(fault);
            }
        }
        // The common owner has prepared time/routes before this release scan.
        if self.device_state.is_activated() {
            self.process_control_tx();
            self.process_control_rx();
        }
        if let Some(fault) = self.fault {
            return ResumeAcceptance::AcceptedWithFailure(fault);
        }
        ResumeAcceptance::Accepted
    }
    fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if !matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Resuming | ProviderStage::Running
        ) {
            return Err(ProviderFault::InvalidTransition);
        }
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        for port in &self.ports {
            if !port.started()? {
                return Ok(Poll::Pending);
            }
        }
        self.lifecycle.snapshot.stage = ProviderStage::Running;
        Ok(Poll::Ready(()))
    }
    fn begin_terminal_stop(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError> {
        if matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Stopping | ProviderStage::Stopped
        ) {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::InvalidTransition,
            });
        }
        if Instant::now() >= request.deadline {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::Deadline,
            });
        }
        self.lifecycle.begin(request, ProviderStage::Stopping);
        Ok(())
    }

    fn poll_terminal_stop(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if self.lifecycle.snapshot.stage == ProviderStage::Stopped {
            return self.fault.map_or(Ok(Poll::Ready(())), Err);
        }
        if self.lifecycle.snapshot.stage != ProviderStage::Stopping {
            return Err(ProviderFault::InvalidTransition);
        }
        let mut pending = false;
        for port in &mut self.ports {
            match port.poll_terminal_stop() {
                Poll::Pending => pending = true,
                Poll::Ready(Err(fault)) => {
                    self.fault.get_or_insert(fault);
                }
                Poll::Ready(Ok(())) => {}
            }
        }
        match self.control.preflight() {
            Err(ProviderFault::LockBusy) => pending = true,
            Err(fault) => {
                self.fault.get_or_insert(fault);
            }
            Ok(()) => {}
        }
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if pending {
            return Ok(Poll::Pending);
        }
        // Abandoned heads stay with their direction owners. They are not
        // validated or transferred into the reversible queue escrow.
        self.lifecycle.snapshot.stage = ProviderStage::Stopped;
        Ok(Poll::Ready(()))
    }
    fn state_limit(&self) -> u32 {
        LIMIT as u32
    }
    fn capture_payload(&self, key: BarrierKey) -> Result<Vec<u8>, ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced {
            return Err(ProviderFault::InvalidTransition);
        }
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        let messages = self.control.snapshot()?;
        let result = (|| -> Result<Vec<u8>, Error> {
            let mut writer = Writer::new(LIMIT);
            writer.header(CONSOLE_STATE_MAGIC, CONSOLE_STATE_SCHEMA)?;
            writer.u16(1)?;
            writer.u32(uapi::VIRTIO_ID_CONSOLE)?;
            writer.u64(self.avail_features)?;
            writer.u64(self.acked_features)?;
            writer.u16(self.config.cols)?;
            writer.u16(self.config.rows)?;
            writer.u32(self.config.max_nr_ports)?;
            writer.u32(self.config.emerg_wr)?;
            writer.count(self.ports.len(), 64)?;
            for port in &self.ports {
                writer.u32(port.port_id)?;
                writer.bytes(port.name().as_bytes(), 256)?;
                writer.u8(port.shape())?;
                writer.bool(port.ready)?;
                writer.bool(port.opened)?;
                writer.bool(port.eof)?;
                writer.bool(port.engaged)?;
            }
            writer.count(messages.len(), 4096)?;
            for message in messages {
                writer.bytes(&message, 264)?;
            }
            Ok(writer.finish())
        })();
        result.map_err(|_| ProviderFault::DeviceState)
    }
    fn validate_payload(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.checked_saved(payload).map(|_| ())
    }
    fn validate_restore(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        if self.device_state.is_activated() || self.ports.iter().any(|port| port.running()) {
            return Err(ProviderFault::InvalidTransition);
        }
        self.validate_payload(payload)
    }
    fn apply_payload(&mut self, payload: &[u8]) -> Result<(), ProviderFault> {
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced
            || self.ports.iter().any(|port| port.running())
        {
            return Err(ProviderFault::InvalidTransition);
        }
        let saved = self.checked_saved(payload)?;
        self.install_saved(saved)
    }
    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        let saved = self.checked_saved(payload)?;
        if !context.activated
            && saved
                .ports
                .iter()
                .any(|port| port.engaged || port.opened || port.ready || port.eof)
        {
            return Err(ProviderFault::DeviceState);
        }
        self.install_saved(saved)?;
        if context.activated {
            self.device_state = DeviceState::Activated(context.memory, context.interrupt);
        }
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use crate::legacy::{IrqChipDevice, KvmIoapic};
    use crate::virtio::console::port_io;
    use crate::virtio::console::state::decode;
    use crate::virtio::lifecycle::{
        DormantDeviceContext, ProviderFault, RestoredReclaimPolicy, ResumeAcceptance,
        VirtioStateProvider,
    };
    use crate::virtio::{
        Console, DeviceQueue, InterruptTransport, PortDescription, Queue, RuntimeGuestMemory,
        VirtioDevice,
    };
    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
    use std::borrow::Cow;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::time::{Duration, Instant};
    use utils::eventfd::{EFD_NONBLOCK, EventFd};
    use vm_memory::GuestAddress;

    fn request(operation: u64) -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }
    fn interrupt() -> InterruptTransport {
        // This is the actual production eventfd producer; no KVM VM is constructed.
        InterruptTransport::new(
            Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
            "console-test".into(),
            None,
        )
        .unwrap()
    }
    fn memory() -> RuntimeGuestMemory {
        RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 4 << 20)]).unwrap()
    }
    fn queues(count: usize) -> Vec<DeviceQueue> {
        (0..count)
            .map(|index| {
                let base = 0x1000 * index as u64;
                let mut queue = Queue::new(32);
                queue.size = 32;
                queue.ready = true;
                queue.desc_table = GuestAddress(base);
                queue.avail_ring = GuestAddress(base + 0x400);
                queue.used_ring = GuestAddress(base + 0x800);
                DeviceQueue {
                    queue,
                    event: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                }
            })
            .collect()
    }
    fn post(memory: &RuntimeGuestMemory, queue: usize, address: u64, length: u32, writable: bool) {
        let base = queue as u64 * 0x1000;
        memory.write_obj(address, GuestAddress(base)).unwrap();
        memory.write_obj(length, GuestAddress(base + 8)).unwrap();
        memory
            .write_obj(if writable { 2u16 } else { 0u16 }, GuestAddress(base + 12))
            .unwrap();
        memory.write_obj(0u16, GuestAddress(base + 0x404)).unwrap();
        memory.write_obj(1u16, GuestAddress(base + 0x402)).unwrap();
    }
    fn empty_port(name: &'static str) -> PortDescription {
        PortDescription {
            name: Cow::Borrowed(name),
            input: None,
            output: None,
            terminal: None,
        }
    }
    fn finish_pause(console: &mut Console, request: BarrierRequest) -> Vec<DeviceQueue> {
        loop {
            match console.poll_quiesce(request.key).unwrap() {
                Poll::Ready(result) => {
                    assert_eq!(result.fault, None);
                    return result.queues;
                }
                Poll::Pending => {
                    assert!(Instant::now() < request.deadline);
                    std::thread::yield_now();
                }
            }
        }
    }
    fn finish_resume(console: &mut Console, request: BarrierRequest) {
        while console.poll_resume(request.key).unwrap().is_pending() {
            assert!(Instant::now() < request.deadline);
            std::thread::yield_now();
        }
    }

    #[test]
    fn console_provider_unopened_and_absent_directions_return_exact_queues_once() {
        let mut console = Console::new(vec![empty_port("absent"), empty_port("unopened")]).unwrap();
        let mem = memory();
        let original = queues(console.queue_config().len());
        let identities: Vec<_> = original
            .iter()
            .map(|queue| (queue.queue.identity(), queue.event.clone()))
            .collect();
        console
            .activate(mem.clone(), interrupt(), original)
            .unwrap();
        console.ports[0].opened = true;
        console.start_port(0).unwrap();
        let pause = request(1);
        console.begin_quiesce(pause).unwrap();
        let returned = finish_pause(&mut console, pause);
        assert_eq!(returned.len(), identities.len());
        for (queue, (identity, event)) in returned.iter().zip(identities) {
            assert!(Arc::ptr_eq(&queue.queue.identity(), &identity));
            assert!(Arc::ptr_eq(&queue.event, &event));
        }
        assert!(console.poll_quiesce(pause.key).is_err());
        let saved = decode(&console.capture_payload(pause.key).unwrap()).unwrap();
        assert!(saved.ports[0].engaged);
        assert!(!saved.ports[1].engaged);
        let resume = request(2);
        assert!(matches!(
            console.begin_resume(resume, returned),
            ResumeAcceptance::Accepted
        ));
        finish_resume(&mut console, resume);
        console.begin_quiesce(request(3)).unwrap();
        finish_pause(&mut console, request(3));
    }

    #[test]
    fn console_provider_control_order_and_dormant_restore_do_not_handshake() {
        let mut source = Console::new(vec![empty_port("stable")]).unwrap();
        source.control.port_add(0).unwrap();
        source.control.port_name(0, "stable").unwrap();
        source.control.port_open(0, true).unwrap();
        source.update_console_size(0, 132, 48);
        let expected = source.control.snapshot().unwrap();
        let cut = request(1);
        source.begin_quiesce(cut).unwrap();
        assert!(finish_pause(&mut source, cut).is_empty());
        let payload = source.capture_payload(cut.key).unwrap();
        use utils::state::StateHeaderError;
        assert_eq!(&payload[..10], b"KRUNCONS\x01\x00");
        let mut wrong_magic = payload.clone();
        wrong_magic[0] ^= 1;
        assert!(matches!(
            source.validate_payload(&wrong_magic),
            Err(ProviderFault::StateHeader(StateHeaderError::Magic { .. }))
        ));
        let mut wrong_schema = payload.clone();
        wrong_schema[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            source.validate_payload(&wrong_schema),
            Err(ProviderFault::StateHeader(StateHeaderError::Schema { expected: 1, found: 2 }))
        );
        assert_eq!(source.capture_payload(cut.key).unwrap(), payload);
        source.update_console_size(0, 1, 1);
        assert_eq!(source.control.snapshot().unwrap(), expected);
        let mut destination = Console::new(vec![empty_port("stable")]).unwrap();
        let irq = interrupt();
        destination
            .prepare_restore(
                cut,
                &payload,
                DormantDeviceContext {
                    memory: memory(),
                    interrupt: irq.clone(),
                    activated: false,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert_eq!(destination.control.snapshot().unwrap(), expected);
        assert_eq!(destination.capture_payload(cut.key).unwrap(), payload);
        assert_eq!(irq.status().load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(destination.queue_events.is_empty());
        assert!(!destination.ports[0].running());
        let wrong = Console::new(vec![empty_port("other")]).unwrap();
        assert_eq!(
            wrong.validate_restore(&payload),
            Err(ProviderFault::DeviceState)
        );
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(destination.validate_payload(&trailing).is_err());
        for end in 0..payload.len() {
            assert!(destination.validate_payload(&payload[..end]).is_err());
        }
    }

    #[cfg(feature = "native-device-probe")]
    #[test]
    fn console_terminal_reset_reaps_blocked_output_without_reader_drain() {
        const CHILD: &str = "LIBKRUN_CONSOLE_TERMINAL_RESET_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "virtio::console::state::tests::console_terminal_reset_reaps_blocked_output_without_reader_drain",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "terminal reset child failed: {status}");
                    return;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("terminal reset did not reap blocked TX within ten seconds");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        let (host, peer) = UnixStream::pair().unwrap();
        let mut console = Console::new(vec![PortDescription::output_pipe(
            "output",
            port_io::output_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
        )])
        .unwrap();
        let mem = memory();
        let payload = vec![0x5au8; 2 << 20];
        mem.write_slice(&payload, GuestAddress(0x10000)).unwrap();
        post(&mem, 1, 0x10000, payload.len() as u32, false);
        let irq = interrupt();
        console
            .activate(mem.clone(), irq.clone(), queues(4))
            .unwrap();
        console.ports[0].opened = true;
        console.start_port(0).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let observation = match console.ports[0].output_observation() {
                Ok(observation) => observation,
                Err(ProviderFault::LockBusy) => {
                    assert!(Instant::now() < deadline, "TX owner remained busy");
                    std::thread::yield_now();
                    continue;
                }
                Err(error) => panic!("TX observation failed: {error:?}"),
            };
            if observation.blocked_head == Some(0) {
                assert!(observation.worker_handle_retained);
                assert!(!observation.worker_finished);
                assert!(observation.bytes_written > 0);
                assert!(observation.write_remaining > 0);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "TX did not reach real backpressure"
            );
            std::thread::yield_now();
        }
        assert!(console.reset());
        assert!(!console.ports[0].running());
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x1802)).unwrap(), 0);
        assert_eq!(irq.status().load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(peer);
    }

    #[test]
    fn console_output_partial_backpressure_retains_owner_then_resumes_without_replay() {
        let (host, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut console = Console::new(vec![PortDescription::output_pipe(
            "output",
            port_io::output_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
        )])
        .unwrap();
        let mem = memory();
        let payload: Vec<u8> = (0..2 << 20).map(|index| (index % 251) as u8).collect();
        mem.write_slice(&payload, GuestAddress(0x10000)).unwrap();
        post(&mem, 1, 0x10000, payload.len() as u32, false);
        console
            .activate(mem.clone(), interrupt(), queues(4))
            .unwrap();
        console.ports[0].opened = true;
        console.start_port(0).unwrap();
        let mut sink = Vec::new();
        let mut buffer = [0u8; 4096];
        let cut = request(1);
        while sink.is_empty() {
            match peer.read(&mut buffer) {
                Ok(n) => sink.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < cut.deadline);
                    std::thread::yield_now();
                }
                result => panic!("unexpected socket read: {result:?}"),
            }
        }
        console.begin_quiesce(cut).unwrap();
        assert!(console.poll_quiesce(cut.key).unwrap().is_pending());
        let returned = loop {
            loop {
                match peer.read(&mut buffer) {
                    Ok(0) => panic!("unexpected socket EOF"),
                    Ok(n) => sink.extend_from_slice(&buffer[..n]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    result => panic!("unexpected socket read: {result:?}"),
                }
            }
            match console.poll_quiesce(cut.key).unwrap() {
                Poll::Ready(result) => {
                    assert_eq!(result.fault, None);
                    break result.queues;
                }
                Poll::Pending => {
                    assert!(Instant::now() < cut.deadline);
                    std::thread::yield_now();
                }
            }
        };
        while sink.len() < payload.len() {
            match peer.read(&mut buffer) {
                Ok(n) => sink.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < cut.deadline);
                    std::thread::yield_now();
                }
                result => panic!("unexpected socket read: {result:?}"),
            }
        }
        assert_eq!(sink, payload);
        assert_eq!(returned[1].queue.capture_state().unwrap().next_avail, 1);
        assert_eq!(returned[1].queue.capture_state().unwrap().next_used, 1);
        let saved = console.capture_payload(cut.key).unwrap();
        let resume = request(2);
        assert!(matches!(
            console.begin_resume(resume, returned),
            ResumeAcceptance::Accepted
        ));
        finish_resume(&mut console, resume);
        assert_eq!(
            peer.read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        console.begin_quiesce(request(3)).unwrap();
        let retained = finish_pause(&mut console, request(3));
        let (new_host, mut new_peer) = UnixStream::pair().unwrap();
        new_peer.set_nonblocking(true).unwrap();
        let mut destination = Console::new(vec![PortDescription::output_pipe(
            "output",
            port_io::output_to_raw_fd_dup(new_host.as_raw_fd()).unwrap(),
        )])
        .unwrap();
        destination
            .prepare_restore(
                cut,
                &saved,
                DormantDeviceContext {
                    memory: mem,
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert_eq!(
            new_peer.read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let fresh = retained
            .into_iter()
            .map(|old| {
                let mut queue = Queue::new(32);
                queue.apply_state(&old.queue.capture_state().unwrap());
                DeviceQueue {
                    queue,
                    event: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                }
            })
            .collect();
        assert!(matches!(
            destination.begin_resume(resume, fresh),
            ResumeAcceptance::Accepted
        ));
        finish_resume(&mut destination, resume);
        assert_eq!(
            new_peer.read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        destination.begin_quiesce(request(3)).unwrap();
        finish_pause(&mut destination, request(3));
    }

    #[test]
    fn console_provider_input_eof_preserves_close_notification_and_absent_output() {
        let (host, mut peer) = UnixStream::pair().unwrap();
        let mut console = Console::new(vec![PortDescription::input_pipe(
            "input",
            port_io::input_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
        )])
        .unwrap();
        let mem = memory();
        post(&mem, 0, 0x10000, 32, true);
        peer.write_all(b"input").unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        console
            .activate(mem.clone(), interrupt(), queues(4))
            .unwrap();
        console.ports[0].opened = true;
        console.start_port(0).unwrap();
        let cut = request(1);
        loop {
            match console.control.snapshot() {
                Ok(messages) if !messages.is_empty() => break,
                Ok(_) | Err(ProviderFault::LockBusy) => {
                    assert!(Instant::now() < cut.deadline);
                    std::thread::yield_now();
                }
                Err(fault) => panic!("unexpected control fault before EOF: {fault:?}"),
            }
        }
        console.begin_quiesce(cut).unwrap();
        let returned = finish_pause(&mut console, cut);
        let mut bytes = [0; 5];
        mem.read_slice(&mut bytes, GuestAddress(0x10000)).unwrap();
        assert_eq!(&bytes, b"input");
        assert_eq!(returned.len(), 4);
        assert!(
            decode(&console.capture_payload(cut.key).unwrap())
                .unwrap()
                .ports[0]
                .eof
        );
    }

    #[test]
    fn console_output_broken_pipe_retains_sticky_owned_head_without_rewind() {
        let (host, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut console = Console::new(vec![PortDescription::output_pipe(
            "output",
            port_io::output_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
        )])
        .unwrap();
        let mem = memory();
        mem.write_slice(&vec![0x5a; 2 << 20], GuestAddress(0x10000))
            .unwrap();
        post(&mem, 1, 0x10000, 2 << 20, false);
        console.activate(mem, interrupt(), queues(4)).unwrap();
        console.ports[0].opened = true;
        console.start_port(0).unwrap();
        let cut = request(1);
        let mut prefix = [0; 4096];
        loop {
            match peer.read(&mut prefix) {
                Ok(n) => {
                    assert!(n > 0);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < cut.deadline);
                    std::thread::yield_now();
                }
                result => panic!("unexpected socket read: {result:?}"),
            }
        }
        console.begin_quiesce(cut).unwrap();
        assert!(console.poll_quiesce(cut.key).unwrap().is_pending());
        drop(peer);
        let returned = loop {
            match console.poll_quiesce(cut.key).unwrap() {
                Poll::Ready(result) => {
                    assert_eq!(result.fault, Some(ProviderFault::Worker));
                    break result.queues;
                }
                Poll::Pending => {
                    assert!(Instant::now() < cut.deadline);
                    std::thread::yield_now();
                }
            }
        };
        assert!(returned[1].queue.capture_state().is_err());
        assert!(console.capture_payload(cut.key).is_err());
        match console.begin_resume(request(2), returned) {
            ResumeAcceptance::Rejected { queues, fault } => {
                assert_eq!(fault, ProviderFault::Worker);
                assert_eq!(queues.len(), 4);
                assert!(queues[1].queue.capture_state().is_err());
            }
            _ => panic!("partial external output must never resume/replay"),
        }
    }

    #[test]
    fn console_provider_host_input_and_resize_fenced_until_source_resume_scan() {
        let (host, mut peer) = UnixStream::pair().unwrap();
        let mut console = Console::new(vec![PortDescription::input_pipe(
            "input",
            port_io::input_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
        )])
        .unwrap();
        let mem = memory();
        console
            .activate(mem.clone(), interrupt(), queues(4))
            .unwrap();
        console.ports[0].opened = true;
        console.start_port(0).unwrap();
        let cut = request(1);
        console.begin_quiesce(cut).unwrap();
        let returned = finish_pause(&mut console, cut);
        let payload = console.capture_payload(cut.key).unwrap();
        peer.write_all(b"after-cut").unwrap();
        post(&mem, 0, 0x10000, 64, true);
        console.sigwinch_evt.write(1).unwrap();
        console.update_console_size(0, 200, 60);
        assert_eq!(console.capture_payload(cut.key).unwrap(), payload);
        assert_eq!(mem.read_obj::<u64>(GuestAddress(0x10000)).unwrap(), 0);
        let resume = request(2);
        assert!(matches!(
            console.begin_resume(resume, returned),
            ResumeAcceptance::Accepted
        ));
        finish_resume(&mut console, resume);
        while mem.read_obj::<u16>(GuestAddress(0x802)).unwrap() == 0 {
            assert!(Instant::now() < resume.deadline);
            std::thread::yield_now();
        }
        let mut bytes = [0; 9];
        mem.read_slice(&mut bytes, GuestAddress(0x10000)).unwrap();
        assert_eq!(&bytes, b"after-cut");
        let next = request(3);
        console.begin_quiesce(next).unwrap();
        finish_pause(&mut console, next);
    }

    #[test]
    fn console_provider_malformed_control_fault_still_returns_real_ownership_for_stop() {
        let mut console = Console::new(vec![empty_port("stable")]).unwrap();
        let mem = memory();
        post(&mem, 3, 0x10000, 8, false);
        mem.write_slice(&[255, 255, 255, 255, 6, 0, 1, 0], GuestAddress(0x10000))
            .unwrap();
        console.activate(mem, interrupt(), queues(4)).unwrap();
        console.process_control_tx();
        assert_eq!(console.preflight(), Err(ProviderFault::DeviceState));
        let cut = request(1);
        console.begin_quiesce(cut).unwrap();
        let Poll::Ready(returned) = console.poll_quiesce(cut.key).unwrap() else {
            panic!("callback owner must settle without a worker join");
        };
        assert_eq!(returned.fault, Some(ProviderFault::DeviceState));
        assert_eq!(returned.queues.len(), 4);
        assert!(returned.queues[3].queue.capture_state().is_err());
        assert!(console.capture_payload(cut.key).is_err());
    }

    #[test]
    fn console_provider_global_device_ready_accepts_linux_bad_id() {
        let mut console = Console::new(vec![empty_port("stable")]).unwrap();
        let mem = memory();
        post(&mem, 3, 0x10000, 8, false);
        mem.write_slice(&[255, 255, 255, 255, 0, 0, 1, 0], GuestAddress(0x10000))
            .unwrap();
        console.activate(mem, interrupt(), queues(4)).unwrap();
        console.process_control_tx();
        assert_eq!(console.preflight(), Ok(()));
        let messages = console.control.snapshot().unwrap();
        assert_eq!(messages, vec![vec![0, 0, 0, 0, 1, 0, 0, 0]]);
        let cut = request(1);
        console.begin_quiesce(cut).unwrap();
        let returned = finish_pause(&mut console, cut);
        assert_eq!(returned[3].queue.capture_state().unwrap().next_used, 1);
    }

    #[test]
    fn console_provider_malformed_tail_and_cycle_retain_rx_tx_heads_without_effects() {
        for input in [false, true] {
            for cycle in [false, true] {
                let (mut host, mut peer) = UnixStream::pair().unwrap();
                peer.set_nonblocking(true).unwrap();
                let description = if input {
                    peer.write_all(b"unconsumed").unwrap();
                    PortDescription::input_pipe(
                        "input",
                        port_io::input_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
                    )
                } else {
                    PortDescription::output_pipe(
                        "output",
                        port_io::output_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
                    )
                };
                let mut console = Console::new(vec![description]).unwrap();
                let mem = memory();
                let index = usize::from(!input);
                let base = index as u64 * 0x1000;
                post(&mem, index, 0x10000, 8, input);
                if !input {
                    mem.write_slice(b"neveremit", GuestAddress(0x10000))
                        .unwrap();
                }
                let flags = if input { 3u16 } else { 1u16 };
                mem.write_obj(flags, GuestAddress(base + 12)).unwrap();
                mem.write_obj(if cycle { 0u16 } else { 1u16 }, GuestAddress(base + 14))
                    .unwrap();
                if !cycle {
                    mem.write_obj(0x10008u64, GuestAddress(base + 16)).unwrap();
                    mem.write_obj(1u32, GuestAddress(base + 24)).unwrap();
                    mem.write_obj(flags, GuestAddress(base + 28)).unwrap();
                    mem.write_obj(32u16, GuestAddress(base + 30)).unwrap();
                }
                console
                    .activate(mem.clone(), interrupt(), queues(4))
                    .unwrap();
                console.ports[0].opened = true;
                console.start_port(0).unwrap();
                let cut = request(1);
                loop {
                    match console.ports[0].started() {
                        Err(ProviderFault::QueueState) => break,
                        Ok(_) => {
                            assert!(Instant::now() < cut.deadline);
                            std::thread::yield_now();
                        }
                        result => panic!("unexpected worker state: {result:?}"),
                    }
                }
                console.begin_quiesce(cut).unwrap();
                let returned = loop {
                    match console.poll_quiesce(cut.key).unwrap() {
                        Poll::Ready(result) => {
                            assert_eq!(result.fault, Some(ProviderFault::QueueState));
                            break result.queues;
                        }
                        Poll::Pending => {
                            assert!(Instant::now() < cut.deadline);
                            std::thread::yield_now();
                        }
                    }
                };
                assert!(returned[index].queue.capture_state().is_err());
                assert_eq!(mem.read_obj::<u16>(GuestAddress(base + 0x802)).unwrap(), 0);
                if input {
                    assert_eq!(mem.read_obj::<u64>(GuestAddress(0x10000)).unwrap(), 0);
                    let mut pending = [0; 10];
                    host.read_exact(&mut pending).unwrap();
                    assert_eq!(&pending, b"unconsumed");
                } else {
                    let mut bytes = [0; 8];
                    assert_eq!(
                        peer.read(&mut bytes).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                }
                assert!(console.capture_payload(cut.key).is_err());
            }
        }
    }

    #[test]
    fn console_provider_refuses_pending_controls_beyond_live_byte_budget() {
        let name = "x".repeat(256);
        let mut source = Console::new(vec![PortDescription {
            name: Cow::Owned(name.clone()),
            input: None,
            output: None,
            terminal: None,
        }])
        .unwrap();
        let cut = request(1);
        source.begin_quiesce(cut).unwrap();
        finish_pause(&mut source, cut);
        let empty = source.capture_payload(cut.key).unwrap();
        let mut writer = utils::state::Writer::new(262_144);
        writer.fixed(&empty[..empty.len() - 4]).unwrap();
        writer.count(900, 4096).unwrap();
        let mut message = vec![0, 0, 0, 0, 7, 0, 1, 0];
        message.extend_from_slice(name.as_bytes());
        for _ in 0..900 {
            writer.bytes(&message, 264).unwrap();
        }
        let payload = writer.finish();
        assert!(payload.len() < 262_144);
        assert!(source.validate_payload(&payload).is_err());
        assert!(source.control.snapshot().unwrap().is_empty());
    }

    #[test]
    fn console_provider_stop_redrains_accepted_resume_before_running_ack() {
        let (host, _peer) = UnixStream::pair().unwrap();
        let mut console = Console::new(vec![PortDescription::input_pipe(
            "input",
            port_io::input_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
        )])
        .unwrap();
        console.activate(memory(), interrupt(), queues(4)).unwrap();
        console.ports[0].opened = true;
        console.start_port(0).unwrap();
        let cut = request(1);
        console.begin_quiesce(cut).unwrap();
        let returned = finish_pause(&mut console, cut);
        let resume = request(2);
        assert!(matches!(
            console.begin_resume(resume, returned),
            ResumeAcceptance::Accepted
        ));
        let stop = request(3);
        console.begin_quiesce(stop).unwrap();
        let returned = finish_pause(&mut console, stop);
        assert_eq!(returned.len(), 4);
        assert!(console.ports.iter().all(|port| !port.running()));
    }

    #[test]
    fn console_provider_control_commands_require_exact_header_length() {
        for length in [7, 9] {
            let mut console = Console::new(vec![empty_port("stable")]).unwrap();
            let mem = memory();
            post(&mem, 3, 0x10000, length, false);
            mem.write_slice(&[255, 255, 255, 255, 0, 0, 1, 0, 0], GuestAddress(0x10000))
                .unwrap();
            console
                .activate(mem.clone(), interrupt(), queues(4))
                .unwrap();
            console.process_control_tx();
            assert_eq!(console.preflight(), Err(ProviderFault::QueueState));
            assert_eq!(mem.read_obj::<u16>(GuestAddress(0x3802)).unwrap(), 0);
            let cut = request(1);
            console.begin_quiesce(cut).unwrap();
            let Poll::Ready(returned) = console.poll_quiesce(cut.key).unwrap() else {
                panic!("control owner must settle synchronously");
            };
            assert_eq!(returned.fault, Some(ProviderFault::QueueState));
            assert!(returned.queues[3].queue.capture_state().is_err());
        }
    }
}
