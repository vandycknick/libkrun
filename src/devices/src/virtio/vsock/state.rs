use std::mem;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Instant;

use polly::event_manager::{BarrierKey, BarrierRequest};
use utils::state::{Reader, Writer};

use crate::virtio::lifecycle::{
    DormantDeviceContext, LifecycleJournal, ProviderBeginError, ProviderFault, ProviderStage,
    QuiesceCompletion, ResumeAcceptance, VirtioStateProvider,
};
use crate::virtio::vsock::Vsock;
use crate::virtio::vsock::defs::uapi;
use crate::virtio::vsock::packet::PacketQueue;
use crate::virtio::{DeviceQueue, DeviceState, Queue, VirtioDevice};

const LIMIT: u32 = 65536;
const MAX_PORTS: usize = 4096;

pub(crate) struct ProviderState {
    pub journal: LifecycleJournal,
    pub dormant: bool,
    pub discard_tx: bool,
    activation: Option<BarrierRequest>,
    resume_queues: Option<Vec<DeviceQueue>>,
    effect_fault: Option<ProviderFault>,
    activation_fault: Option<ProviderFault>,
    reconciling_queue_key: Option<BarrierKey>,
    activation_done: bool,
}

impl ProviderState {
    pub fn new() -> Self {
        Self {
            journal: LifecycleJournal::new(),
            dormant: false,
            discard_tx: false,
            activation: None,
            resume_queues: None,
            effect_fault: None,
            activation_fault: None,
            reconciling_queue_key: None,
            activation_done: false,
        }
    }

    pub fn callback_allowed(&self) -> bool {
        self.journal.snapshot.stage == ProviderStage::Running
            && !self.dormant
            && self.effect_fault.is_none()
    }

    pub fn processing_allowed(&self) -> bool {
        matches!(
            self.journal.snapshot.stage,
            ProviderStage::Running | ProviderStage::Resuming
        ) && self.effect_fault.is_none()
    }

    pub fn retain_fault(&mut self, fault: ProviderFault) {
        self.effect_fault.get_or_insert(fault);
    }

    #[cfg(feature = "native-device-probe")]
    pub fn effect_fault(&self) -> Option<ProviderFault> {
        self.effect_fault
    }
}

struct Saved {
    available: u64,
    acknowledged: u64,
    cid: u64,
    reset_pending: bool,
    listeners: Vec<(u32, bool)>,
    retired_ports: Vec<u32>,
}

impl Saved {
    fn encode(&self) -> Result<Vec<u8>, ProviderFault> {
        let mut writer = Writer::new(LIMIT as usize);
        let result = (|| {
            writer.u16(1)?;
            writer.u32(uapi::VIRTIO_ID_VSOCK)?;
            writer.u64(self.available)?;
            writer.u64(self.acknowledged)?;
            writer.u64(self.cid)?;
            writer.bool(self.reset_pending)?;
            writer.count(self.listeners.len(), MAX_PORTS)?;
            for (port, listening) in &self.listeners {
                writer.u32(*port)?;
                writer.bool(*listening)?;
            }
            writer.count(self.retired_ports.len(), MAX_PORTS)?;
            for port in &self.retired_ports {
                writer.u32(*port)?;
            }
            Ok::<_, utils::state::Error>(writer.finish())
        })();
        result.map_err(|_| ProviderFault::DeviceState)
    }

    fn decode(payload: &[u8]) -> Result<Self, ProviderFault> {
        if payload.len() > LIMIT as usize {
            return Err(ProviderFault::DeviceState);
        }
        let mut reader = Reader::new(payload);
        let result = (|| {
            if reader.u16()? != 1 || reader.u32()? != uapi::VIRTIO_ID_VSOCK {
                return Err(utils::state::Error::Invalid("vsock payload kind"));
            }
            let available = reader.u64()?;
            let acknowledged = reader.u64()?;
            let cid = reader.u64()?;
            let reset_pending = reader.bool()?;
            let count = reader.count(MAX_PORTS, 5)?;
            let mut listeners = Vec::with_capacity(count);
            for _ in 0..count {
                let entry = (reader.u32()?, reader.bool()?);
                if listeners
                    .last()
                    .is_some_and(|last: &(u32, bool)| last.0 >= entry.0)
                {
                    return Err(utils::state::Error::Invalid("vsock duplicate listener"));
                }
                listeners.push(entry);
            }
            let count = reader.count(MAX_PORTS, 4)?;
            let mut retired_ports = Vec::with_capacity(count);
            for _ in 0..count {
                let port = reader.u32()?;
                if retired_ports.last().is_some_and(|last| *last >= port) {
                    return Err(utils::state::Error::Invalid("vsock duplicate retired port"));
                }
                retired_ports.push(port);
            }
            reader.finish()?;
            Ok(Self {
                available,
                acknowledged,
                cid,
                reset_pending,
                listeners,
                retired_ports,
            })
        })();
        result.map_err(|_| ProviderFault::DeviceState)
    }
}

impl Vsock {
    pub fn bind_restore_control_service(&mut self, port: u32) -> Result<(), ProviderFault> {
        if port == 0 || self.is_activated() || self.provider.dormant {
            return Err(ProviderFault::InvalidTransition);
        }
        self.muxer.activation_service = Some(port);
        Ok(())
    }

    fn saved(&self) -> Result<Saved, ProviderFault> {
        Ok(Saved {
            available: self.avail_features,
            acknowledged: self.acked_features,
            cid: self.cid,
            reset_pending: self.pending_reset,
            listeners: self.muxer.listener_shape(),
            retired_ports: self.muxer.retired_ports()?,
        })
    }

    fn check_retained_faults(&self) -> Result<(), ProviderFault> {
        if let Some(fault) = self.provider.effect_fault {
            return Err(fault);
        }
        if let Some(error) = self.provider.journal.snapshot.failure {
            return Err(error.fault);
        }
        if let Some(fault) = self.muxer.worker_control.retained_fault() {
            return Err(fault);
        }
        if self
            .muxer
            .workers
            .iter()
            .any(|(_, worker)| worker.is_finished())
        {
            return Err(ProviderFault::Worker);
        }
        Ok(())
    }

    fn check_saved(&self, saved: &Saved) -> Result<(), ProviderFault> {
        self.check_retained_faults()?;
        if !self.muxer.live_profile() {
            return Err(ProviderFault::Unsupported);
        }
        if saved.available != self.avail_features
            || saved.acknowledged & !saved.available != 0
            || saved.cid != self.cid
            || saved.listeners != self.muxer.listener_shape()
        {
            return Err(ProviderFault::DeviceState);
        }
        Ok(())
    }

    fn resume_owned(&mut self, request: BarrierRequest) -> Result<(), ProviderFault> {
        let (memory, interrupt) = match &self.device_state {
            DeviceState::Activated(memory, interrupt) => (memory.clone(), interrupt.clone()),
            DeviceState::Inactive => {
                self.provider.resume_queues = None;
                self.provider.dormant = false;
                return Ok(());
            }
        };
        let source_rx = if self.provider.dormant {
            None
        } else {
            self.queue_rx.clone()
        };
        let source_tx = if self.provider.dormant {
            None
        } else {
            self.queue_tx.clone()
        };
        let mut rx_lock = source_rx
            .as_ref()
            .map(|slot| slot.try_lock().map_err(|_| ProviderFault::DeviceLock))
            .transpose()?;
        let mut tx_lock = source_tx
            .as_ref()
            .map(|slot| slot.try_lock().map_err(|_| ProviderFault::DeviceLock))
            .transpose()?;
        if !self.provider.dormant && (rx_lock.is_none() || tx_lock.is_none()) {
            return Err(ProviderFault::QueueState);
        }
        let queues = self
            .provider
            .resume_queues
            .take()
            .ok_or(ProviderFault::QueueCount)?;
        let [rx, tx, ev]: [DeviceQueue; 3] = queues.try_into().map_err(|queues| {
            self.provider.resume_queues = Some(queues);
            ProviderFault::QueueCount
        })?;
        self.queue_events = vec![rx.event, tx.event, ev.event];
        self.queue_ev = Some(ev.queue);
        if self.provider.dormant {
            let mut packet_queue = PacketQueue::from_queue(rx.queue);
            packet_queue.bind_admission(self.muxer.worker_control.clone());
            self.queue_rx = Some(Arc::new(Mutex::new(packet_queue)));
            self.queue_tx = Some(Arc::new(Mutex::new(tx.queue)));
        } else if let (Some(rx_slot), Some(tx_slot)) = (&mut rx_lock, &mut tx_lock) {
            self.parked_slots = [
                Some(mem::replace(&mut rx_slot.queue, rx.queue)),
                Some(mem::replace(&mut **tx_slot, tx.queue)),
            ];
            let key = self
                .provider
                .journal
                .snapshot
                .quiesce_request
                .ok_or(ProviderFault::ForeignBarrier)?
                .key;
            rx_slot
                .reopen_admission(key)
                .map_err(|_| ProviderFault::QueueState)?;
            tx_slot
                .reopen_admission(key)
                .map_err(|_| ProviderFault::QueueState)?;
        }
        if !self.provider.dormant {
            let key = self
                .provider
                .journal
                .snapshot
                .quiesce_request
                .ok_or(ProviderFault::ForeignBarrier)?
                .key;
            self.queue_ev
                .as_mut()
                .ok_or(ProviderFault::QueueState)?
                .reopen_admission(key)
                .map_err(|_| ProviderFault::QueueState)?;
        }
        drop(rx_lock);
        drop(tx_lock);
        self.provider
            .journal
            .begin(request, ProviderStage::Resuming);
        if self.provider.dormant {
            self.provider.discard_tx = true;
            let used = self.process_stream_tx();
            self.provider.discard_tx = false;
            let used = self.process_transport_reset() | used;
            if used {
                self.signal_used_queue();
            }
            self.preflight()?;
            self.muxer
                .activate(
                    memory,
                    self.queue_rx
                        .as_ref()
                        .ok_or(ProviderFault::QueueState)?
                        .clone(),
                    interrupt,
                )
                .map_err(|_| ProviderFault::Worker)?;
            self.provider.dormant = false;
            self.activate_evt
                .write(1)
                .map_err(|_| ProviderFault::Notification)?;
        } else {
            self.muxer
                .worker_control
                .resume()
                .map_err(|_| ProviderFault::Worker)?;
        }
        Ok(())
    }
}

impl VirtioStateProvider for Vsock {
    fn preflight(&self) -> Result<(), ProviderFault> {
        if let Some(fault) = self.provider.effect_fault {
            return Err(fault);
        }
        if !self.muxer.live_profile() {
            return Err(ProviderFault::Unsupported);
        }
        if self
            .muxer
            .workers
            .iter()
            .any(|(_, worker)| worker.is_finished())
        {
            return Err(ProviderFault::Worker);
        }
        self.muxer.worker_control.preflight(
            !self.muxer.workers.is_empty() || self.is_activated() && !self.provider.dormant,
        )
    }

    fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError> {
        let snapshot = self.provider.journal.snapshot;
        if snapshot.request == Some(request)
            && matches!(
                snapshot.stage,
                ProviderStage::Quiescing | ProviderStage::Quiesced
            )
        {
            return Ok(());
        }
        if !matches!(
            snapshot.stage,
            ProviderStage::Running | ProviderStage::Resuming
        ) || Instant::now() >= request.deadline
        {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::InvalidTransition,
            });
        }
        self.provider.reconciling_queue_key = if snapshot.stage == ProviderStage::Resuming {
            snapshot.quiesce_request.map(|request| request.key)
        } else {
            None
        };
        self.provider
            .journal
            .begin(request, ProviderStage::Quiescing);
        if !self.muxer.workers.is_empty() && self.muxer.worker_control.pause().is_err() {
            return Err(ProviderBeginError {
                accepted: true,
                fault: ProviderFault::Worker,
            });
        }
        Ok(())
    }

    fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.provider
            .journal
            .check(key)
            .map_err(|error| error.fault)?;
        if self.provider.journal.snapshot.stage == ProviderStage::Quiescing {
            self.provider.journal.expired(Instant::now());
        }
        if self.provider.journal.snapshot.stage == ProviderStage::Quiesced {
            return Ok(Poll::Pending);
        }
        if self.provider.journal.snapshot.stage != ProviderStage::Quiescing {
            return Err(ProviderFault::InvalidTransition);
        }
        let mut owner_fault = self
            .muxer
            .worker_control
            .failed()
            .then_some(ProviderFault::Worker);
        for (owner, worker) in &self.muxer.workers {
            if worker.is_finished() {
                self.muxer.worker_control.exited(*owner);
                owner_fault = Some(ProviderFault::Worker);
            }
        }
        if !self.muxer.workers.is_empty() && !self.muxer.worker_control.parked() {
            return Ok(Poll::Pending);
        }
        if !self.muxer.producers_released()? {
            return Ok(Poll::Pending);
        }
        let mut returned = Vec::with_capacity(3);
        let mut fault = self.provider.effect_fault.or(owner_fault);
        if let Some(mut queues) = self.provider.resume_queues.take() {
            for queue in &mut queues {
                if close_queue(&mut queue.queue, key, self.provider.reconciling_queue_key).is_err()
                    || queue.queue.capture_state().is_err()
                {
                    fault = Some(ProviderFault::QueueState);
                }
            }
            if let Some(fault) = fault {
                self.provider.effect_fault.get_or_insert(fault);
            }
            let fault = fault.or(self
                .provider
                .journal
                .snapshot
                .failure
                .map(|error| error.fault));
            self.provider.journal.snapshot.stage = ProviderStage::Quiesced;
            return Ok(Poll::Ready(QuiesceCompletion { queues, fault }));
        }
        if self.queue_rx.is_some() {
            let Some(rx) = &self.queue_rx else {
                return Err(ProviderFault::QueueState);
            };
            let Some(tx) = &self.queue_tx else {
                return Err(ProviderFault::QueueState);
            };
            let mut rx = match rx.try_lock() {
                Ok(queue) => queue,
                Err(std::sync::TryLockError::WouldBlock) => return Ok(Poll::Pending),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(ProviderFault::DeviceLock),
            };
            let mut tx = match tx.try_lock() {
                Ok(queue) => queue,
                Err(std::sync::TryLockError::WouldBlock) => return Ok(Poll::Pending),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(ProviderFault::DeviceLock),
            };
            let ev = self.queue_ev.as_mut().ok_or(ProviderFault::QueueState)?;
            for queue in [&mut rx.queue, &mut *tx, ev] {
                if close_queue(queue, key, self.provider.reconciling_queue_key).is_err()
                    || queue.capture_state().is_err()
                {
                    fault = Some(ProviderFault::QueueState);
                }
            }
            let empty_rx = self.parked_slots[0]
                .take()
                .ok_or(ProviderFault::QueueState)?;
            let empty_tx = self.parked_slots[1]
                .take()
                .ok_or(ProviderFault::QueueState)?;
            returned.push(DeviceQueue::new(
                mem::replace(&mut rx.queue, empty_rx),
                self.queue_events[0].clone(),
            ));
            returned.push(DeviceQueue::new(
                mem::replace(&mut *tx, empty_tx),
                self.queue_events[1].clone(),
            ));
            returned.push(DeviceQueue::new(
                self.queue_ev.take().ok_or(ProviderFault::QueueState)?,
                self.queue_events[2].clone(),
            ));
        }
        if let Some(fault) = fault {
            self.provider.effect_fault.get_or_insert(fault);
        }
        let fault = fault.or(self
            .provider
            .journal
            .snapshot
            .failure
            .map(|error| error.fault));
        self.provider.journal.snapshot.stage = ProviderStage::Quiesced;
        Ok(Poll::Ready(QuiesceCompletion {
            queues: returned,
            fault,
        }))
    }

    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance {
        let snapshot = self.provider.journal.snapshot;
        if let Some(fault) = self.provider.effect_fault {
            return ResumeAcceptance::Rejected { queues, fault };
        }
        if snapshot.stage != ProviderStage::Quiesced
            || self.provider.resume_queues.is_some()
            || snapshot.quiesce_request.is_none_or(|cut| {
                cut.key == request.key || cut.key.generation != request.key.generation
            })
        {
            return ResumeAcceptance::Rejected {
                queues,
                fault: ProviderFault::InvalidTransition,
            };
        }
        if Instant::now() >= request.deadline {
            return ResumeAcceptance::Rejected {
                queues,
                fault: ProviderFault::Deadline,
            };
        }
        if queues.len() != if self.is_activated() { 3 } else { 0 } {
            return ResumeAcceptance::Rejected {
                queues,
                fault: ProviderFault::QueueCount,
            };
        }
        self.provider
            .journal
            .begin(request, ProviderStage::Resuming);
        self.provider.resume_queues = Some(queues);
        match self.resume_owned(request) {
            Ok(()) => ResumeAcceptance::Accepted,
            Err(fault) => {
                self.provider.journal.fail(request.key, fault);
                ResumeAcceptance::AcceptedWithFailure(fault)
            }
        }
    }

    fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        self.provider
            .journal
            .check(key)
            .map_err(|error| error.fault)?;
        if self.provider.journal.snapshot.stage == ProviderStage::Running {
            return Ok(Poll::Ready(()));
        }
        if self.provider.journal.snapshot.stage != ProviderStage::Resuming {
            return Err(ProviderFault::InvalidTransition);
        }
        self.provider.journal.expired(Instant::now());
        if let Some(error) = self.provider.journal.snapshot.failure {
            return Err(error.fault);
        }
        let result = (|| {
            self.preflight()?;
            if self.is_activated() && !self.muxer.worker_control.poll_running()? {
                return Ok(Poll::Pending);
            }
            if self.is_activated() {
                let used = self.process_transport_reset()
                    | self.process_stream_tx()
                    | self.process_stream_rx();
                if used {
                    self.signal_used_queue();
                }
            }
            self.preflight()?;
            self.provider.journal.expired(Instant::now());
            if let Some(error) = self.provider.journal.snapshot.failure {
                return Err(error.fault);
            }
            Ok(Poll::Ready(()))
        })();
        match result {
            Ok(Poll::Ready(())) => {
                self.provider.journal.snapshot.stage = ProviderStage::Running;
                Ok(Poll::Ready(()))
            }
            Ok(Poll::Pending) | Err(ProviderFault::LockBusy) => Ok(Poll::Pending),
            Err(fault) => {
                self.provider.journal.fail(key, fault);
                Err(fault)
            }
        }
    }

    fn state_limit(&self) -> u32 {
        LIMIT
    }

    fn capture_payload(&self, key: BarrierKey) -> Result<Vec<u8>, ProviderFault> {
        self.check_retained_faults()?;
        if self
            .provider
            .journal
            .snapshot
            .quiesce_request
            .is_none_or(|request| request.key != key)
            || self.provider.journal.snapshot.stage != ProviderStage::Quiesced
        {
            return Err(ProviderFault::ForeignBarrier);
        }
        self.saved()?.encode()
    }

    fn validate_payload(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.check_saved(&Saved::decode(payload)?)
    }

    fn validate_restore(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.preflight()?;
        self.validate_payload(payload)?;
        if self.is_activated()
            || !self.muxer.workers.is_empty()
            || self.muxer.activation_service.is_none()
        {
            return Err(ProviderFault::DeviceState);
        }
        Ok(())
    }

    fn apply_payload(&mut self, payload: &[u8]) -> Result<(), ProviderFault> {
        let saved = Saved::decode(payload)?;
        self.check_saved(&saved)?;
        if self.provider.journal.snapshot.stage != ProviderStage::Quiesced {
            return Err(ProviderFault::InvalidTransition);
        }
        self.acked_features = saved.acknowledged;
        self.pending_reset = if self.provider.dormant {
            true
        } else {
            saved.reset_pending
        };
        Ok(())
    }

    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        let saved = Saved::decode(payload)?;
        self.muxer.prepare_listeners()?;
        self.muxer
            .worker_control
            .bind_activation(
                self.muxer
                    .activation_service
                    .ok_or(ProviderFault::DeviceState)?,
            )
            .map_err(|_| ProviderFault::Worker)?;
        self.muxer.retired_source_ports = saved.retired_ports;
        self.provider
            .journal
            .begin(request, ProviderStage::Quiescing);
        self.provider.journal.snapshot.stage = ProviderStage::Quiesced;
        self.provider.dormant = true;
        self.acked_features = saved.acknowledged;
        self.pending_reset = true;
        if context.activated {
            self.device_state = DeviceState::Activated(context.memory, context.interrupt);
        }
        Ok(())
    }

    fn begin_activation_release(
        &mut self,
        request: BarrierRequest,
    ) -> Result<(), ProviderBeginError> {
        if self.provider.activation == Some(request) {
            return self.provider.activation_fault.map_or(Ok(()), |fault| {
                Err(ProviderBeginError {
                    accepted: true,
                    fault,
                })
            });
        }
        if self.provider.activation.is_some()
            || self.provider.journal.snapshot.stage != ProviderStage::Running
            || self
                .provider
                .journal
                .snapshot
                .quiesce_request
                .is_none_or(|cut| cut.key.generation != request.key.generation)
            || self.pending_reset
            || !self.muxer.worker_control.activation_fenced()
            || Instant::now() >= request.deadline
        {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::InvalidTransition,
            });
        }
        self.provider.activation = Some(request);
        let result = self
            .muxer
            .worker_control
            .release_activation()
            .and_then(|()| self.muxer.worker_control.resume());
        result.map_err(|_| {
            self.provider.activation_fault = Some(ProviderFault::Worker);
            ProviderBeginError {
                accepted: true,
                fault: ProviderFault::Worker,
            }
        })
    }

    fn poll_activation_release(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        if self
            .provider
            .activation
            .is_none_or(|request| request.key != key)
        {
            return Err(ProviderFault::ForeignBarrier);
        }
        if self.provider.activation_done {
            return Ok(Poll::Ready(()));
        }
        if let Some(fault) = self.provider.activation_fault {
            return Err(fault);
        }
        let request = self
            .provider
            .activation
            .ok_or(ProviderFault::ForeignBarrier)?;
        if Instant::now() >= request.deadline {
            self.provider.activation_fault = Some(ProviderFault::Deadline);
            return Err(ProviderFault::Deadline);
        }
        match self
            .preflight()
            .and_then(|()| self.muxer.worker_control.poll_running())
        {
            Ok(true) => {
                self.provider.activation_done = true;
                Ok(Poll::Ready(()))
            }
            Ok(false) | Err(ProviderFault::LockBusy) => Ok(Poll::Pending),
            Err(fault) => {
                self.provider.activation_fault = Some(fault);
                Err(fault)
            }
        }
    }
}

fn close_queue(
    queue: &mut Queue,
    key: BarrierKey,
    previous: Option<BarrierKey>,
) -> Result<(), ProviderFault> {
    if queue.close_admission(key).is_ok() {
        return Ok(());
    }
    let previous = previous.ok_or(ProviderFault::ForeignBarrier)?;
    queue
        .reopen_admission(previous)
        .map_err(|_| ProviderFault::ForeignBarrier)?;
    queue
        .close_admission(key)
        .map_err(|_| ProviderFault::ForeignBarrier)
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::IoSlice;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant};

    use nix::errno::Errno;
    use nix::sys::socket::{ControlMessage, MsgFlags, recv, sendmsg};
    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
    use utils::eventfd::{EFD_NONBLOCK, EventFd};
    use vm_memory::GuestAddress;

    use crate::legacy::DummyIrqChip;
    use crate::virtio::lifecycle::{
        DormantDeviceContext, ProviderFault, QuiesceCompletion, RestoredReclaimPolicy,
        ResumeAcceptance, VirtioStateProvider,
    };
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::{TsiFlags, Vsock};
    use crate::virtio::{DeviceQueue, InterruptTransport, Queue, RuntimeGuestMemory, VirtioDevice};

    fn request(operation: u64) -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(7),
            },
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    fn interrupt() -> InterruptTransport {
        InterruptTransport::new(
            DummyIrqChip::new().into(),
            "vsock-provider-test".into(),
            None,
        )
        .unwrap()
    }

    fn queue(queue: Queue) -> DeviceQueue {
        DeviceQueue::new(queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
    }

    fn bound() -> (Vsock, UnixStream, UnixStream) {
        let (local, peer) = UnixStream::pair().unwrap();
        let observer = local.try_clone().unwrap();
        let mut device = Vsock::new(3, None, None, TsiFlags::empty()).unwrap();
        device.set_unix_mux_fd(local.into()).unwrap();
        (device, peer, observer)
    }

    fn until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !predicate() {
            assert!(
                Instant::now() < deadline,
                "real vsock owner did not reach its boundary"
            );
            std::thread::yield_now();
        }
    }

    fn quiesce(device: &mut Vsock, request: BarrierRequest) -> QuiesceCompletion {
        device.begin_quiesce(request).unwrap();
        let mut completion = None;
        until(|| match device.poll_quiesce(request.key).unwrap() {
            Poll::Pending => false,
            Poll::Ready(value) => {
                completion = Some(value);
                true
            }
        });
        completion.unwrap()
    }

    fn resume(device: &mut Vsock, request: BarrierRequest, queues: Vec<DeviceQueue>) {
        assert!(matches!(
            device.begin_resume(request, queues),
            ResumeAcceptance::Accepted
        ));
        until(|| device.poll_resume(request.key).unwrap().is_ready());
    }

    fn activation_destination() -> (Vsock, UnixStream) {
        let (mut source, _control, _) = bound();
        let cut = request(1);
        quiesce(&mut source, cut);
        let payload = source.capture_payload(cut.key).unwrap();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let ev = VirtQueue::new(GuestAddress(0x2000), &memory, 8);
        ev.dtable[0].set(0x6000, 4, 2, 0);
        ev.avail.ring[0].set(0);
        ev.avail.idx.set(1);
        let (mut destination, control, _) = bound();
        destination.bind_restore_control_service(1027).unwrap();
        destination
            .prepare_restore(
                cut,
                &payload,
                DormantDeviceContext {
                    memory: memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        resume(
            &mut destination,
            request(2),
            vec![
                queue(rx.create_queue()),
                queue(tx.create_queue()),
                queue(ev.create_queue()),
            ],
        );
        assert!(destination.pending_reset);
        assert_eq!(ev.used.idx.get(), 1);
        ev.dtable[1].set(0x6000, 4, 2, 0);
        ev.avail.ring[1].set(1);
        ev.avail.idx.set(2);
        assert!(!destination.process_transport_reset());
        assert!(!destination.pending_reset);
        (destination, control)
    }

    #[test]
    fn provider_vsock_resume_owner_contention_retains_request_and_terminal_faults() {
        for fault in [
            None,
            Some(ProviderFault::DeviceLock),
            Some(ProviderFault::Worker),
            Some(ProviderFault::Deadline),
        ] {
            let (mut destination, _control) = activation_destination();
            let cut = request(4);
            let completed = quiesce(&mut destination, cut);
            assert_eq!(completed.fault, None);
            assert_eq!(completed.queues.len(), 3);
            let events: Vec<_> = completed
                .queues
                .iter()
                .map(|queue| queue.event.clone())
                .collect();
            let resume = if fault == Some(ProviderFault::Deadline) {
                BarrierRequest {
                    deadline: Instant::now() + Duration::from_millis(100),
                    ..request(5)
                }
            } else {
                request(5)
            };
            assert!(matches!(
                destination.begin_resume(resume, completed.queues),
                ResumeAcceptance::Accepted
            ));
            let gate = destination.muxer.worker_control.clone();
            let epoch = gate.epoch();
            let held_gate = gate.clone();
            let poison = fault == Some(ProviderFault::DeviceLock);
            let (held_sender, held_receiver) = std::sync::mpsc::sync_channel(1);
            let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
            let mut holder = Some(std::thread::spawn(move || {
                held_gate
                    .admit(|| {
                        held_sender.send(()).unwrap();
                        release_receiver.recv().unwrap();
                        assert!(!poison, "poison the actual resuming owner gate");
                    })
                    .expect("the actual resuming owner gate admits the holder");
            }));
            held_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
            match fault {
                Some(ProviderFault::DeviceLock) => {
                    release_sender.send(()).unwrap();
                    assert!(holder.take().unwrap().join().is_err());
                }
                Some(ProviderFault::Worker) => gate.fail(),
                Some(ProviderFault::Deadline) => {
                    while Instant::now() < resume.deadline {
                        std::thread::yield_now();
                    }
                }
                _ => {}
            }
            let (observed_sender, observed_receiver) = std::sync::mpsc::sync_channel(1);
            let polling = std::thread::spawn(move || {
                observed_sender
                    .send((
                        destination.poll_resume(request(6).key),
                        destination.poll_resume(resume.key),
                        destination.poll_resume(resume.key),
                    ))
                    .unwrap();
                destination
            });
            let observed = observed_receiver.recv_timeout(Duration::from_secs(1));
            if !poison {
                release_sender.send(()).unwrap();
                holder.take().unwrap().join().unwrap();
            }
            let mut destination = polling.join().unwrap();
            let (foreign, first, repeated) = observed.unwrap();
            assert_eq!(foreign, Err(ProviderFault::ForeignBarrier));
            if poison {
                // A worker can observe the poisoned gate and exit before polling.
                assert!(first.is_err());
            } else {
                assert_eq!(first, fault.map_or(Ok(Poll::Pending), Err));
            }
            assert_eq!(repeated, first);
            assert_eq!(destination.provider.journal.snapshot.request, Some(resume));
            assert_eq!(
                destination.provider.journal.snapshot.stage,
                crate::virtio::lifecycle::ProviderStage::Resuming
            );
            for (actual, original) in destination.queue_events.iter().zip(events) {
                assert!(Arc::ptr_eq(actual, &original));
            }
            if fault.is_some() {
                let fault = first.unwrap_err();
                let retained = destination.provider.journal.snapshot.failure.unwrap();
                assert_eq!(retained.key, resume.key);
                assert_eq!(retained.fault, fault);
                assert!(retained.accepted);
                assert_eq!(destination.poll_resume(resume.key), Err(fault));
            } else {
                until(|| destination.poll_resume(resume.key).unwrap().is_ready());
                assert_eq!(gate.epoch(), epoch, "accepted resume must not be replayed");
                gate.fail();
                assert_eq!(destination.poll_resume(resume.key), Ok(Poll::Ready(())));
                assert_eq!(
                    destination.poll_resume(request(6).key),
                    Err(ProviderFault::ForeignBarrier)
                );
            }
        }
    }

    #[test]
    fn provider_vsock_activation_owner_contention_retains_request_until_ready() {
        let (mut destination, control) = activation_destination();
        let release = request(3);
        destination.begin_activation_release(release).unwrap();
        let gate = destination.muxer.worker_control.clone();
        let epoch = gate.epoch();
        let held_gate = gate.clone();
        let (held_sender, held_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let holder = std::thread::spawn(move || {
            held_gate
                .admit(|| {
                    held_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                })
                .unwrap();
        });
        held_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let (observed_sender, observed_receiver) = std::sync::mpsc::sync_channel(1);
        let polling = std::thread::spawn(move || {
            let stale = destination.poll_activation_release(request(4).key);
            let first = destination.poll_activation_release(release.key);
            let second = destination.poll_activation_release(release.key);
            observed_sender.send((stale, first, second)).unwrap();
            destination
        });
        let observed = observed_receiver.recv_timeout(Duration::from_secs(1));
        release_sender.send(()).unwrap();
        holder.join().unwrap();
        let mut destination = polling.join().unwrap();
        assert_eq!(
            observed.unwrap(),
            (
                Err(ProviderFault::ForeignBarrier),
                Ok(Poll::Pending),
                Ok(Poll::Pending),
            )
        );
        assert_eq!(destination.provider.activation, Some(release));
        until(|| {
            destination
                .poll_activation_release(release.key)
                .unwrap()
                .is_ready()
        });
        assert_eq!(gate.epoch(), epoch, "accepted release must not be replayed");
        let released = connect(&control, 1028);
        until(|| {
            destination
                .muxer
                .retired_ports()
                .is_ok_and(|ports| ports.len() == 1)
        });
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                gate.admit(|| panic!("poison the actual completed owner gate"))
                    .expect("the completed owner gate remains admissible");
            }))
            .is_err()
        );
        assert_eq!(
            destination.poll_activation_release(release.key),
            Ok(Poll::Ready(()))
        );
        assert_eq!(
            destination.poll_activation_release(request(4).key),
            Err(ProviderFault::ForeignBarrier)
        );
        drop(released);
    }

    #[test]
    fn provider_vsock_activation_owner_faults_and_deadline_are_sticky() {
        for expected in [
            ProviderFault::Deadline,
            ProviderFault::DeviceLock,
            ProviderFault::Worker,
        ] {
            let poison = expected == ProviderFault::DeviceLock;
            let (mut destination, _control) = activation_destination();
            let release = if expected == ProviderFault::Deadline {
                BarrierRequest {
                    deadline: Instant::now() + Duration::from_millis(100),
                    ..request(3)
                }
            } else {
                request(3)
            };
            destination.begin_activation_release(release).unwrap();
            let gate = destination.muxer.worker_control.clone();
            let held_gate = gate.clone();
            let (held_sender, held_receiver) = std::sync::mpsc::sync_channel(1);
            let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
            let mut holder = Some(std::thread::spawn(move || {
                held_gate
                    .admit(|| {
                        held_sender.send(()).unwrap();
                        release_receiver.recv().unwrap();
                        assert!(!poison, "poison the actual pending owner gate");
                    })
                    .expect("the actual pending owner gate admits the holder");
            }));
            held_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
            if poison {
                release_sender.send(()).unwrap();
                assert!(holder.take().unwrap().join().is_err());
            } else if expected == ProviderFault::Deadline {
                while Instant::now() < release.deadline {
                    std::thread::yield_now();
                }
            } else {
                gate.fail();
            }
            let (observed_sender, observed_receiver) = std::sync::mpsc::sync_channel(1);
            let polling = std::thread::spawn(move || {
                observed_sender
                    .send(destination.poll_activation_release(release.key))
                    .unwrap();
                destination
            });
            let observed = observed_receiver.recv_timeout(Duration::from_secs(1));
            if !poison {
                release_sender.send(()).unwrap();
                holder.take().unwrap().join().unwrap();
            }
            let mut destination = polling.join().unwrap();
            let observed_fault = observed.unwrap().unwrap_err();
            if !poison {
                assert_eq!(observed_fault, expected);
            }
            assert_eq!(destination.provider.activation, Some(release));
            assert_eq!(
                destination.poll_activation_release(release.key),
                Err(observed_fault)
            );
            let repeated = destination.begin_activation_release(release).unwrap_err();
            assert!(repeated.accepted);
            assert_eq!(repeated.fault, observed_fault);
            assert_eq!(
                destination.poll_activation_release(request(4).key),
                Err(ProviderFault::ForeignBarrier)
            );
        }
    }

    fn connect(peer: &UnixStream, port: u32) -> UnixStream {
        let (passed, stream) = UnixStream::pair().unwrap();
        let frame = format!("CONNECT {port}\n");
        sendmsg::<()>(
            peer.as_raw_fd(),
            &[IoSlice::new(frame.as_bytes())],
            &[ControlMessage::ScmRights(&[passed.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        stream
    }

    #[test]
    fn provider_vsock_partial_rights_and_all_original_queues_survive_source_pause() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut source, control_peer, observer) = bound();
        let original: Vec<_> = (0..3).map(|_| queue(Queue::new(256))).collect();
        let identities: Vec<_> = original
            .iter()
            .map(|queue| (queue.queue.identity(), queue.event.clone()))
            .collect();
        source.activate(memory, interrupt(), original).unwrap();
        let (passed, stream_peer) = UnixStream::pair().unwrap();
        sendmsg::<()>(
            control_peer.as_raw_fd(),
            &[IoSlice::new(b"CONN")],
            &[ControlMessage::ScmRights(&[passed.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(passed);
        until(|| {
            recv(
                observer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
            ) == Err(Errno::EAGAIN)
        });

        let shared_rx = source.queue_rx.as_ref().unwrap().clone();
        let held_rx = shared_rx.lock().expect("original RX queue");
        let pause = request(1);
        source.begin_quiesce(pause).unwrap();
        assert!(source.poll_quiesce(pause.key).unwrap().is_pending());
        drop(held_rx);
        let completed = quiesce(&mut source, pause);
        assert_eq!(completed.fault, None);
        assert_eq!(completed.queues.len(), 3);
        for (queue, (identity, event)) in completed.queues.iter().zip(identities) {
            assert!(Arc::ptr_eq(&queue.queue.identity(), &identity));
            assert!(Arc::ptr_eq(&queue.event, &event));
        }
        assert!(source.poll_quiesce(pause.key).unwrap().is_pending());
        let payload = source.capture_payload(pause.key).unwrap();
        assert_eq!(source.capture_payload(pause.key).unwrap(), payload);
        nix::unistd::write(&control_peer, b"ECT 1027\n").unwrap();
        assert!(source.muxer.retired_ports().unwrap().is_empty());
        assert!(!source.process_stream_rx());
        assert!(!source.process_stream_tx());
        resume(&mut source, request(2), completed.queues);
        until(|| {
            source
                .muxer
                .retired_ports()
                .is_ok_and(|ports| ports.len() == 1)
        });
        assert_eq!(
            recv(
                stream_peer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_DONTWAIT
            ),
            Err(Errno::EAGAIN)
        );
        let mut second_request = request(3);
        second_request.key.generation = BarrierGeneration(8);
        let second = quiesce(&mut source, second_request);
        assert_eq!(second.fault, None);
        assert_eq!(source.muxer.retired_ports().unwrap().len(), 1);
        assert_eq!(
            recv(
                stream_peer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_DONTWAIT
            ),
            Err(Errno::EAGAIN)
        );
    }

    #[test]
    fn provider_vsock_restore_waits_for_reset_buffer_repost_and_retains_first_connect() {
        let source_memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &source_memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &source_memory, 8);
        let ev = VirtQueue::new(GuestAddress(0x2000), &source_memory, 8);
        tx.dtable[0].set(0x5000, 44, 0, 0);
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        let (mut source, _source_control, _) = bound();
        source
            .activate(
                source_memory.clone(),
                interrupt(),
                vec![
                    queue(rx.create_queue()),
                    queue(tx.create_queue()),
                    queue(ev.create_queue()),
                ],
            )
            .unwrap();
        let cut = request(1);
        let completed = quiesce(&mut source, cut);
        assert_eq!(completed.fault, None);
        let payload = source.capture_payload(cut.key).unwrap();
        let states: Vec<_> = completed
            .queues
            .iter()
            .map(|queue| queue.queue.capture_state().unwrap())
            .collect();
        let fresh_queues: Vec<_> = states
            .iter()
            .map(|state| {
                let mut restored = Queue::new(state.max_size);
                restored.apply_state(state);
                queue(restored)
            })
            .collect();
        let destination_memory =
            RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut bytes = vec![0u8; 0x10000];
        source_memory
            .read_slice(&mut bytes, GuestAddress(0))
            .unwrap();
        destination_memory
            .write_slice(&bytes, GuestAddress(0))
            .unwrap();
        let (mut destination, destination_control, observer) = bound();
        destination.bind_restore_control_service(1027).unwrap();
        destination
            .prepare_restore(
                cut,
                &payload,
                DormantDeviceContext {
                    memory: destination_memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        let mut installed = vec![0u8; bytes.len()];
        destination_memory
            .read_slice(&mut installed, GuestAddress(0))
            .unwrap();
        assert_eq!(installed, bytes);
        assert!(destination.muxer.workers.is_empty());
        assert!(destination.pending_reset);
        assert!(!destination.process_stream_tx());
        assert!(!destination.process_transport_reset());
        resume(&mut destination, request(2), fresh_queues);
        assert!(destination.pending_reset);
        assert_eq!(
            destination
                .queue_tx
                .as_ref()
                .unwrap()
                .lock()
                .expect("restored TX queue")
                .next_used
                .0,
            1
        );
        let first_connect = connect(&destination_control, 1027);
        assert_eq!(
            recv(
                first_connect.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_DONTWAIT
            ),
            Err(Errno::EAGAIN)
        );
        assert_eq!(
            recv(
                observer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT
            ),
            Ok(1)
        );
        assert!(destination.muxer.retired_ports().unwrap().is_empty());

        let destination_ev = VirtQueue::new(GuestAddress(0x2000), &destination_memory, 8);
        destination_ev.dtable[0].set(0x6000, 4, 2, 0);
        destination_ev.avail.ring[0].set(0);
        destination_ev.dtable[1].set(0x6010, 4, 2, 0);
        destination_ev.avail.ring[1].set(1);
        destination_ev.avail.idx.set(2);
        destination.queue_ev.as_mut().unwrap().set_event_idx(true);
        assert!(destination.process_transport_reset());
        destination.signal_used_queue();
        assert!(destination.pending_reset);
        assert!(!destination.muxer.worker_control.transport_ready());
        assert_eq!(destination_ev.used.idx.get(), 1);
        assert_eq!(destination_ev.used.ring[0].get().len, 4);
        assert_eq!(
            destination_memory
                .read_obj::<u32>(GuestAddress(0x6000))
                .unwrap(),
            0
        );
        assert!(!destination.process_transport_reset());
        assert!(
            destination.pending_reset,
            "preposted buffers are not reset completion"
        );
        assert!(destination.begin_activation_release(request(3)).is_err());
        destination_ev.dtable[2].set(0x6020, 4, 2, 0);
        destination_ev.avail.ring[2].set(2);
        destination_ev.avail.idx.set(3);
        assert!(!destination.process_transport_reset());
        assert!(
            destination.pending_reset,
            "unrelated repost is not reset completion"
        );
        assert_eq!(
            recv(
                observer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT
            ),
            Ok(1)
        );
        let paused = quiesce(&mut destination, request(4));
        assert_eq!(paused.fault, None);
        let pending_payload = destination.capture_payload(request(4).key).unwrap();
        destination.apply_payload(&pending_payload).unwrap();
        resume(&mut destination, request(5), paused.queues);
        assert_eq!(
            destination_ev.used.idx.get(),
            1,
            "source resume must not replay reset"
        );
        assert!(destination.pending_reset);
        destination_ev.dtable[3].set(0x6000, 4, 2, 0);
        destination_ev.avail.ring[3].set(3);
        destination_ev.avail.idx.set(4);
        assert!(!destination.process_transport_reset());
        assert!(
            !destination.pending_reset,
            "IN_ORDER may change the descriptor head"
        );
        assert!(destination.muxer.worker_control.transport_ready());
        until(|| {
            destination
                .muxer
                .retired_ports()
                .is_ok_and(|ports| ports.len() == 1)
        });
        assert_eq!(
            recv(
                first_connect.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_DONTWAIT
            ),
            Err(Errno::EAGAIN),
            "the original stream is retained without an early ACK"
        );
        let denied = connect(&destination_control, 1028);
        until(|| recv(denied.as_raw_fd(), &mut [0u8; 1], MsgFlags::MSG_DONTWAIT) == Ok(0));
        let release = request(6);
        destination.begin_activation_release(release).unwrap();
        until(|| {
            destination
                .poll_activation_release(release.key)
                .unwrap()
                .is_ready()
        });
        let _released = connect(&destination_control, 1028);
        until(|| {
            destination
                .muxer
                .retired_ports()
                .is_ok_and(|ports| ports.len() == 2)
        });
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn provider_vsock_terminal_mmio_capture_does_not_lock_live_owner_gate() {
        let (source, _control, _) = bound();
        let gate = source.muxer.worker_control.clone();
        let source = Arc::new(std::sync::Mutex::new(source));
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut transport = crate::virtio::mmio::MmioTransport::new(
            memory,
            DummyIrqChip::new().into(),
            source.clone(),
            None,
        )
        .unwrap();
        transport.set_attachment_address(0x1000).unwrap();
        let cut = request(1);
        transport.begin_quiesce(cut).unwrap();
        assert!(transport.poll_quiesce(cut.key).unwrap().is_ready());
        let expected = transport.capture_device_state(cut.key).unwrap();
        let (held_sender, held_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let holder = std::thread::spawn(move || {
            gate.admit(|| {
                held_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
            })
            .expect("inactive owner gate admits the actual holder");
        });
        held_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let (captured_sender, captured_receiver) = std::sync::mpsc::sync_channel(1);
        let capture = std::thread::spawn(move || {
            captured_sender
                .send(transport.capture_device_state(cut.key))
                .unwrap();
        });
        let observed = captured_receiver.recv_timeout(Duration::from_secs(1));
        // Always release the real mutex and reap both owners before asserting,
        // including when a blocking capture dependency regresses.
        release_sender.send(()).unwrap();
        holder.join().unwrap();
        capture.join().unwrap();
        assert_eq!(observed.unwrap(), Ok(expected));
    }

    #[test]
    fn provider_vsock_static_payload_validation_retains_known_cut_and_effect_faults() {
        let (mut source, _control, _) = bound();
        let cut = request(1);
        quiesce(&mut source, cut);
        let payload = source.capture_payload(cut.key).unwrap();
        source
            .provider
            .journal
            .fail(cut.key, ProviderFault::Deadline);
        assert_eq!(
            source.validate_payload(&payload),
            Err(ProviderFault::Deadline)
        );
        source.provider.retain_fault(ProviderFault::Notification);
        assert_eq!(
            source.validate_payload(&payload),
            Err(ProviderFault::Notification)
        );
    }

    #[test]
    fn provider_vsock_payload_rejects_malformed_and_unbound_resources() {
        let (mut source, _control, _) = bound();
        let cut = request(1);
        let completed = quiesce(&mut source, cut);
        assert!(completed.queues.is_empty());
        let payload = source.capture_payload(cut.key).unwrap();
        let (mut destination, _destination_control, _) = bound();
        assert_eq!(
            destination.validate_restore(&payload),
            Err(ProviderFault::DeviceState)
        );
        destination.bind_restore_control_service(1027).unwrap();
        destination.validate_restore(&payload).unwrap();
        for length in 0..payload.len() {
            assert!(destination.validate_payload(&payload[..length]).is_err());
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(destination.validate_payload(&trailing).is_err());
        let mut wrong_cid = payload.clone();
        wrong_cid[22] ^= 1;
        assert!(destination.validate_restore(&wrong_cid).is_err());
        let unsupported = Vsock::new(3, None, None, TsiFlags::HIJACK_INET).unwrap();
        assert_eq!(unsupported.preflight(), Err(ProviderFault::Unsupported));
    }

    #[test]
    fn provider_vsock_effect_fault_retains_all_queues_but_never_certifies_capture() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        rx.dtable[0].set(0xffff, 44, 2, 0);
        rx.avail.ring[0].set(0);
        rx.avail.idx.set(1);
        let (mut source, control, _) = bound();
        source
            .activate(
                memory.clone(),
                interrupt(),
                vec![
                    queue(rx.create_queue()),
                    queue(Queue::new(256)),
                    queue(Queue::new(256)),
                ],
            )
            .unwrap();
        let _stream = connect(&control, 1027);
        until(|| {
            source
                .queue_rx
                .as_ref()
                .unwrap()
                .lock()
                .expect("RX queue")
                .capture_state()
                .is_err()
        });
        let cut = request(1);
        let completed = quiesce(&mut source, cut);
        assert_eq!(completed.queues.len(), 3);
        assert_eq!(completed.fault, Some(ProviderFault::QueueState));
        assert_eq!(
            source.capture_payload(cut.key),
            Err(ProviderFault::QueueState)
        );
        assert!(matches!(
            source.begin_resume(request(2), completed.queues),
            ResumeAcceptance::Rejected {
                fault: ProviderFault::QueueState,
                ..
            }
        ));
    }

    #[test]
    fn provider_vsock_unready_partial_queue_restore_never_scans_guest_addresses() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut source, _source_control, _) = bound();
        let cut = request(1);
        quiesce(&mut source, cut);
        let payload = source.capture_payload(cut.key).unwrap();
        let (mut destination, _destination_control, _) = bound();
        destination.bind_restore_control_service(1027).unwrap();
        destination
            .prepare_restore(
                cut,
                &payload,
                DormantDeviceContext {
                    memory,
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        let queues = (0..3)
            .map(|_| {
                let mut partial = Queue::new(256);
                partial.size = 8;
                partial.ready = false;
                partial.desc_table = GuestAddress(u64::MAX - 15);
                partial.avail_ring = GuestAddress(u64::MAX - 15);
                partial.used_ring = GuestAddress(u64::MAX - 15);
                queue(partial)
            })
            .collect();
        resume(&mut destination, request(2), queues);
        assert!(destination.pending_reset);
        let rx = destination
            .queue_rx
            .as_ref()
            .unwrap()
            .lock()
            .expect("unready RX queue");
        let tx = destination
            .queue_tx
            .as_ref()
            .unwrap()
            .lock()
            .expect("unready TX queue");
        for guard in [&rx.queue, &*tx] {
            assert_eq!(guard.capture_state().unwrap().next_avail, 0);
            assert!(!guard.ready);
        }
        assert_eq!(
            destination
                .queue_ev
                .as_ref()
                .unwrap()
                .capture_state()
                .unwrap()
                .next_used,
            0
        );
    }

    #[test]
    fn provider_vsock_expired_and_stale_resume_retain_dormant_queues_without_effects() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let ev = VirtQueue::new(GuestAddress(0x2000), &memory, 8);
        tx.dtable[0].set(0x5000, 44, 0, 0);
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        let mut queues = vec![
            queue(rx.create_queue()),
            queue(tx.create_queue()),
            queue(ev.create_queue()),
        ];
        let identities: Vec<_> = queues
            .iter()
            .map(|queue| (queue.queue.identity(), queue.event.clone()))
            .collect();
        let (mut source, _source_control, _) = bound();
        let cut = request(1);
        quiesce(&mut source, cut);
        let payload = source.capture_payload(cut.key).unwrap();
        let (mut destination, _destination_control, _) = bound();
        destination.bind_restore_control_service(1027).unwrap();
        destination
            .prepare_restore(
                cut,
                &payload,
                DormantDeviceContext {
                    memory: memory.clone(),
                    interrupt: interrupt(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        let mut before = vec![0; 0x10000];
        memory.read_slice(&mut before, GuestAddress(0)).unwrap();
        let mut expired = request(2);
        expired.deadline = Instant::now() - Duration::from_millis(1);
        let mut foreign = request(2);
        foreign.key.generation = BarrierGeneration(8);
        for (attempt, expected) in [
            (expired, ProviderFault::Deadline),
            (cut, ProviderFault::InvalidTransition),
            (foreign, ProviderFault::InvalidTransition),
        ] {
            queues = match destination.begin_resume(attempt, queues) {
                ResumeAcceptance::Rejected { queues, fault } => {
                    assert_eq!(fault, expected);
                    queues
                }
                _ => panic!("invalid resume accepted dormant ownership"),
            };
            assert!(destination.provider.dormant);
            assert!(destination.provider.resume_queues.is_none());
            assert!(destination.muxer.workers.is_empty());
            assert!(destination.queue_rx.is_none());
            assert!(destination.queue_tx.is_none());
            assert!(destination.queue_ev.is_none());
            assert!(destination.pending_reset);
            assert_eq!(
                destination.provider.journal.snapshot.stage,
                crate::virtio::lifecycle::ProviderStage::Quiesced
            );
            assert_eq!(destination.provider.journal.snapshot.request, Some(cut));
            assert!(destination.provider.journal.snapshot.failure.is_none());
            for (queue, (identity, event)) in queues.iter().zip(&identities) {
                assert!(Arc::ptr_eq(&queue.queue.identity(), identity));
                assert!(Arc::ptr_eq(&queue.event, event));
                assert_eq!(queue.queue.next_avail.0, 0);
                assert_eq!(queue.queue.next_used.0, 0);
            }
            let mut after = vec![0; before.len()];
            memory.read_slice(&mut after, GuestAddress(0)).unwrap();
            assert_eq!(after, before);
        }
        resume(&mut destination, request(2), queues);
        assert!(!destination.muxer.workers.is_empty());
        assert_eq!(
            destination
                .queue_tx
                .as_ref()
                .unwrap()
                .lock()
                .expect("restored TX queue")
                .next_used
                .0,
            1
        );
        assert!(destination.pending_reset);
    }

    #[test]
    fn provider_vsock_stop_reconciles_accepted_resume_queues_after_owner_lock_failure() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut source, _control, _) = bound();
        source
            .activate(
                memory,
                interrupt(),
                (0..3).map(|_| queue(Queue::new(256))).collect(),
            )
            .unwrap();
        let completed = quiesce(&mut source, request(1));
        let identities: Vec<_> = completed
            .queues
            .iter()
            .map(|queue| queue.queue.identity())
            .collect();
        let shared = source.queue_rx.as_ref().unwrap().clone();
        let held = shared.lock().expect("parked queue slot");
        assert!(matches!(
            source.begin_resume(request(2), completed.queues),
            ResumeAcceptance::AcceptedWithFailure(ProviderFault::DeviceLock)
        ));
        drop(held);
        let stopped = quiesce(&mut source, request(3));
        assert_eq!(stopped.fault, None);
        assert_eq!(stopped.queues.len(), 3);
        for (queue, identity) in stopped.queues.iter().zip(identities) {
            assert!(Arc::ptr_eq(&queue.queue.identity(), &identity));
        }
        assert_eq!(
            source
                .provider
                .journal
                .snapshot
                .previous_failure
                .unwrap()
                .fault,
            ProviderFault::DeviceLock
        );
    }

    #[test]
    fn provider_vsock_terminal_capture_rejects_late_sticky_owner_failure() {
        let (mut source, _control, _) = bound();
        let cut = request(1);
        quiesce(&mut source, cut);
        let payload = source.capture_payload(cut.key).unwrap();
        source.muxer.worker_control.fail();
        assert_eq!(source.capture_payload(cut.key), Err(ProviderFault::Worker));
        assert_eq!(
            source.validate_payload(&payload),
            Err(ProviderFault::Worker)
        );
    }

    #[test]
    fn provider_vsock_terminal_capture_rejects_real_parked_owner_exit() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut source, _control, _) = bound();
        source
            .activate(
                memory,
                interrupt(),
                (0..3).map(|_| queue(Queue::new(256))).collect(),
            )
            .unwrap();
        let cut = request(1);
        let _completion = quiesce(&mut source, cut);
        let payload = source.capture_payload(cut.key).unwrap();
        source.muxer.worker_control.stop();
        until(|| {
            source
                .muxer
                .workers
                .iter()
                .all(|(_, worker)| worker.is_finished())
        });
        assert_eq!(source.capture_payload(cut.key), Err(ProviderFault::Worker));
        assert_eq!(
            source.validate_payload(&payload),
            Err(ProviderFault::Worker)
        );
    }
}
