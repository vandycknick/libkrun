#[cfg(feature = "native-device-probe")]
use crate::virtio::console::ConsoleOutputObservation;
use crate::virtio::console::console_control::{
    ConsoleControl, VirtioConsoleControl, VirtioConsoleResize,
};
use crate::virtio::console::defs::{QUEUE_SIZE, control_event, uapi};
use crate::virtio::console::port::Port;
use crate::virtio::console::port_queue_mapping::{
    QueueDirection, num_queues, port_id_to_queue_idx,
};
use crate::virtio::console::{ConsoleError, Result, defs};
use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::lifecycle::{
    LifecycleJournal, ProviderFault, ProviderStage, VirtioStateProvider,
};
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, PortDescription,
    QueueConfig, RuntimeGuestMemory, VirtioDevice, VmmExitObserver,
};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use utils::eventfd::EventFd;
#[cfg(windows)]
use utils::windows::{AsRawFd, RawFd};
use vm_memory::{ByteValued, GuestAddress};

pub(crate) const CONTROL_RXQ_INDEX: usize = 2;
pub(crate) const CONTROL_TXQ_INDEX: usize = 3;
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_CONSOLE_F_SIZE as u64)
    | (1 << uapi::VIRTIO_CONSOLE_F_MULTIPORT as u64)
    | (1 << uapi::VIRTIO_F_VERSION_1 as u64);

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleConfig {
    pub(crate) cols: u16,
    pub(crate) rows: u16,
    pub(crate) max_nr_ports: u32,
    pub(crate) emerg_wr: u32,
}
unsafe impl ByteValued for VirtioConsoleConfig {}

pub struct Console {
    pub(crate) device_state: DeviceState,
    pub(crate) control: Arc<ConsoleControl>,
    pub(crate) ports: Vec<Port>,
    queue_config: Vec<QueueConfig>,
    pub(crate) queues: Vec<Option<DeviceQueue>>,
    pub(crate) queue_events: Vec<Arc<EventFd>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,
    pub(crate) config: VirtioConsoleConfig,
    pub(crate) lifecycle: LifecycleJournal,
    pub(crate) fault: Option<ProviderFault>,
    descriptor_snapshot: DescriptorChainSnapshot,
}

impl Console {
    pub fn new(ports: Vec<PortDescription>) -> Result<Console> {
        if ports.is_empty() || u32::try_from(ports.len()).is_err() {
            return Err(ConsoleError::InvalidConfiguration);
        }
        let queue_config = (0..num_queues(ports.len()))
            .map(|_| QueueConfig::new(QUEUE_SIZE))
            .collect();
        let ports: Vec<_> = ports
            .into_iter()
            .enumerate()
            .map(|(id, description)| Port::new(id as u32, description))
            .collect();
        let (cols, rows) = ports[0]
            .terminal()
            .map(|term| term.get_win_size())
            .unwrap_or((0, 0));
        let config = VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports: ports.len() as u32,
            emerg_wr: 0,
        };
        Ok(Self {
            device_state: DeviceState::Inactive,
            control: ConsoleControl::new().map_err(ConsoleError::EventFd)?,
            ports,
            queue_config,
            queues: Vec::new(),
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            config,
            lifecycle: LifecycleJournal::new(),
            fault: None,
            descriptor_snapshot: DescriptorChainSnapshot::new(QUEUE_SIZE),
        })
    }
    #[cfg(feature = "native-device-probe")]
    pub fn output_observations(
        &self,
    ) -> std::result::Result<Vec<ConsoleOutputObservation>, ProviderFault> {
        self.ports.iter().map(Port::output_observation).collect()
    }

    pub fn id(&self) -> &str {
        defs::CONSOLE_DEV_ID
    }
    pub fn get_sigwinch_fd(&self) -> RawFd {
        self.sigwinch_evt.as_raw_fd()
    }
    pub(crate) fn ingress_open(&self) -> bool {
        self.lifecycle.snapshot.stage == ProviderStage::Running && self.fault.is_none()
    }
    pub fn update_console_size(&mut self, port_id: u32, cols: u16, rows: u16) {
        if !self.ingress_open() {
            return;
        }
        if port_id as usize >= self.ports.len() {
            self.fault = Some(ProviderFault::DeviceState);
            return;
        }
        if port_id == 0 {
            self.config.cols = cols;
            self.config.rows = rows;
        }
        if let Err(fault) = self
            .control
            .console_resize(port_id, VirtioConsoleResize { rows, cols })
        {
            self.fault.get_or_insert(fault);
        }
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        if let Err(fault) = self.control_rx() {
            self.fault.get_or_insert(fault);
        }
        false
    }
    fn control_rx(&mut self) -> std::result::Result<(), ProviderFault> {
        let DeviceState::Activated(mem, interrupt) = &self.device_state else {
            return Err(ProviderFault::DeviceState);
        };
        let queue = self
            .queues
            .get_mut(CONTROL_RXQ_INDEX)
            .and_then(Option::as_mut)
            .ok_or(ProviderFault::QueueCount)?;
        if !queue.queue.ready {
            return Ok(());
        }
        let snapshot = &mut self.descriptor_snapshot;
        while self.control.deliver_front(|message| {
            let Some(head) = queue.queue.pop(mem) else {
                return Ok(false);
            };
            let index = head.index;
            let chain = snapshot.read(head).map_err(|_| {
                queue.queue.record_processing_failure();
                ProviderFault::QueueState
            })?;
            if chain
                .descriptors()
                .iter()
                .any(|descriptor| descriptor.flags & 2 == 0)
            {
                queue.queue.record_processing_failure();
                return Err(ProviderFault::QueueState);
            }
            let mut written = 0;
            for descriptor in chain.descriptors() {
                let length = (message.len() - written).min(descriptor.len as usize);
                if mem
                    .write_slice(
                        &message[written..written + length],
                        GuestAddress(descriptor.addr),
                    )
                    .is_err()
                {
                    queue.queue.record_processing_failure();
                    return Err(ProviderFault::QueueState);
                }
                written += length;
                if written == message.len() {
                    break;
                }
            }
            if written != message.len() {
                queue.queue.record_processing_failure();
                return Err(ProviderFault::QueueState);
            }
            queue
                .queue
                .add_used(mem, index, message.len() as u32)
                .map_err(|_| ProviderFault::QueueState)?;
            if queue
                .queue
                .needs_notification(mem)
                .map_err(|_| ProviderFault::QueueState)?
            {
                interrupt
                    .try_signal_used_queue()
                    .map_err(|_| ProviderFault::Notification)?;
            }
            Ok(true)
        })? {}
        queue
            .queue
            .capture_state()
            .map_err(|_| ProviderFault::QueueState)?;
        Ok(())
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        if let Err(fault) = self.control_tx() {
            self.fault.get_or_insert(fault);
        }
        false
    }
    fn control_tx(&mut self) -> std::result::Result<(), ProviderFault> {
        let DeviceState::Activated(mem, interrupt) = &self.device_state else {
            return Err(ProviderFault::DeviceState);
        };
        let (mem, interrupt) = (mem.clone(), interrupt.clone());
        loop {
            let queue = self
                .queues
                .get_mut(CONTROL_TXQ_INDEX)
                .and_then(Option::as_mut)
                .ok_or(ProviderFault::QueueCount)?;
            if !queue.queue.ready {
                return Ok(());
            }
            let Some(head) = queue.queue.pop(&mem) else {
                queue
                    .queue
                    .capture_state()
                    .map_err(|_| ProviderFault::QueueState)?;
                break;
            };
            let index = head.index;
            let chain = self.descriptor_snapshot.read(head).map_err(|_| {
                queue.queue.record_processing_failure();
                ProviderFault::QueueState
            })?;
            let control_length = chain
                .descriptors()
                .iter()
                .try_fold(0u64, |length, descriptor| {
                    if descriptor.flags & 2 != 0 {
                        None
                    } else {
                        length.checked_add(u64::from(descriptor.len))
                    }
                });
            if control_length != Some(8) {
                queue.queue.record_processing_failure();
                return Err(ProviderFault::QueueState);
            }
            let mut bytes = [0u8; 8];
            let mut read = 0;
            for descriptor in chain.descriptors() {
                let length = (bytes.len() - read).min(descriptor.len as usize);
                if mem
                    .read_slice(
                        &mut bytes[read..read + length],
                        GuestAddress(descriptor.addr),
                    )
                    .is_err()
                {
                    queue.queue.record_processing_failure();
                    return Err(ProviderFault::QueueState);
                }
                read += length;
                if read == bytes.len() {
                    break;
                }
            }
            if read != bytes.len() {
                queue.queue.record_processing_failure();
                return Err(ProviderFault::QueueState);
            }
            let cmd = VirtioConsoleControl {
                id: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                event: u16::from_le_bytes([bytes[4], bytes[5]]),
                value: u16::from_le_bytes([bytes[6], bytes[7]]),
            };
            if (cmd.event != control_event::VIRTIO_CONSOLE_DEVICE_READY
                && cmd.id as usize >= self.ports.len())
                || cmd.value > 1
                || !matches!(
                    cmd.event,
                    control_event::VIRTIO_CONSOLE_DEVICE_READY
                        | control_event::VIRTIO_CONSOLE_PORT_READY
                        | control_event::VIRTIO_CONSOLE_PORT_OPEN
                )
            {
                queue.queue.record_processing_failure();
                return Err(ProviderFault::DeviceState);
            }
            // Apply before publication; any later fault is sticky and cannot replay this command.
            match cmd.event {
                control_event::VIRTIO_CONSOLE_DEVICE_READY => {
                    if cmd.value == 1 {
                        for port in &self.ports {
                            self.control.port_add(port.port_id)?;
                        }
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    let port = &mut self.ports[cmd.id as usize];
                    port.ready = cmd.value == 1;
                    if port.ready {
                        if let Some(term) = port.terminal() {
                            self.control.mark_console_port(&mem, cmd.id)?;
                            let (cols, rows) = term.get_win_size();
                            self.control
                                .console_resize(cmd.id, VirtioConsoleResize { cols, rows })?;
                        }
                        self.control.port_open(cmd.id, true)?;
                        if !port.name().is_empty() {
                            self.control.port_name(cmd.id, port.name())?;
                        }
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_OPEN => {
                    self.ports[cmd.id as usize].opened = cmd.value == 1;
                }
                _ => return Err(ProviderFault::DeviceState),
            }
            let queue = self
                .queues
                .get_mut(CONTROL_TXQ_INDEX)
                .and_then(Option::as_mut)
                .ok_or(ProviderFault::QueueCount)?;
            queue
                .queue
                .add_used(&mem, index, 0)
                .map_err(|_| ProviderFault::QueueState)?;
            if queue
                .queue
                .needs_notification(&mem)
                .map_err(|_| ProviderFault::QueueState)?
            {
                interrupt
                    .try_signal_used_queue()
                    .map_err(|_| ProviderFault::Notification)?;
            }
            if cmd.event == control_event::VIRTIO_CONSOLE_PORT_OPEN && cmd.value == 1 {
                self.start_port(cmd.id as usize)?;
            }
        }
        Ok(())
    }

    pub(crate) fn start_port(&mut self, id: usize) -> std::result::Result<(), ProviderFault> {
        if self.ports[id].running() {
            return Ok(());
        }
        let DeviceState::Activated(mem, interrupt) = &self.device_state else {
            return Err(ProviderFault::DeviceState);
        };
        let rx = port_id_to_queue_idx(QueueDirection::Rx, id);
        let tx = port_id_to_queue_idx(QueueDirection::Tx, id);
        if self.queues.get(rx).is_none_or(Option::is_none)
            || self.queues.get(tx).is_none_or(Option::is_none)
        {
            return Err(ProviderFault::QueueCount);
        }
        let Some(rx_queue) = self.queues[rx].take() else {
            return Err(ProviderFault::QueueCount);
        };
        let Some(tx_queue) = self.queues[tx].take() else {
            self.queues[rx] = Some(rx_queue);
            return Err(ProviderFault::QueueCount);
        };
        self.ports[id].start(
            mem.clone(),
            rx_queue,
            tx_queue,
            interrupt.clone(),
            self.control.clone(),
        )
    }
}

impl VirtioDevice for Console {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }
    fn acked_features(&self) -> u64 {
        self.acked_features
    }
    fn set_acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }
    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_CONSOLE
    }
    fn device_name(&self) -> &str {
        "console"
    }
    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_config
    }
    fn state_provider(&self) -> Option<&dyn VirtioStateProvider> {
        Some(self)
    }
    fn state_provider_mut(&mut self) -> Option<&mut dyn VirtioStateProvider> {
        Some(self)
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let Ok(start) = usize::try_from(offset) else {
            return;
        };
        let config = self.config.as_slice();
        if let Some(bytes) = config.get(start..) {
            let length = bytes.len().min(data.len());
            data[..length].copy_from_slice(&bytes[..length]);
        }
    }
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "console guest config write offset={offset:x} len={:x}",
            data.len()
        );
    }
    fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        // Ownership is retained even when the accepted activation wake fails.
        self.queue_events = queues.iter().map(|queue| queue.event.clone()).collect();
        self.queues = queues.into_iter().map(Some).collect();
        self.device_state = DeviceState::Activated(mem, interrupt);
        self.activate_evt
            .write(1)
            .map_err(|_| ActivateError::BadActivate)
    }
    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
    fn reset(&mut self) -> bool {
        let mut fault = None;
        for port in &mut self.ports {
            if let Err(error) = port.shutdown() {
                fault.get_or_insert(error);
            }
        }
        if let Some(fault) = fault {
            self.fault = Some(fault);
            return false;
        }
        self.queues.clear();
        self.queue_events.clear();
        self.device_state = DeviceState::Inactive;
        if self.control.reset().is_err() {
            return false;
        }
        self.fault = None;
        self.lifecycle = LifecycleJournal::new();
        self.acked_features = 0;
        true
    }
}
impl VmmExitObserver for Console {
    fn on_vmm_exit(&mut self) {
        if !self.reset() {
            log::error!("console terminal shutdown failed: {:?}", self.fault);
        }
    }
}
