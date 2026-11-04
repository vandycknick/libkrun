// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::virtio::lifecycle::{
    DormantDeviceContext, LifecycleJournal, ProviderBeginError, ProviderFault, ProviderStage,
    QuiesceCompletion, ResumeAcceptance, VirtioStateProvider,
};
use crate::virtio::net::worker::{EndpointMode, NetWorker, ParkedNetWorker, WorkerAdmission};
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG, Result};
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    RuntimeGuestMemory, TYPE_NET, VirtioDevice,
};
use polly::event_manager::{BarrierKey, BarrierRequest};
use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, TryLockError};
use std::task::Poll;
use std::thread::JoinHandle;
use std::time::Instant;
use utils::eventfd::EventFd;
use utils::state::{Reader, Writer};
use virtio_bindings::virtio_net::VIRTIO_NET_F_MAC;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::ByteValued;

const STATE_LIMIT: usize = 131072;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

#[derive(Clone)]
pub enum VirtioNetBackend {
    UnixstreamFd(RawFd),
    UnixstreamPath(PathBuf),
    UnixgramFd(RawFd),
    UnixgramPath(PathBuf, bool),
    ManagedUnixgram(Arc<OwnedFd>),
    #[cfg(target_os = "linux")]
    Tap(String),
}

struct NetPayload {
    available: u64,
    acknowledged: u64,
    config: VirtioNetConfig,
}

impl NetPayload {
    fn decode(payload: &[u8]) -> std::result::Result<Self, ProviderFault> {
        let decode = || -> std::result::Result<Self, utils::state::Error> {
            if payload.len() > STATE_LIMIT {
                return Err(utils::state::Error::Limit);
            }
            let mut reader = Reader::new(payload);
            if reader.u16()? != 1 || reader.u32()? != TYPE_NET {
                return Err(utils::state::Error::Invalid("net framing"));
            }
            let available = reader.u64()?;
            let acknowledged = reader.u64()?;
            if acknowledged & !available != 0 || reader.u8()? != 1 {
                return Err(utils::state::Error::Invalid("net backend/features"));
            }
            let config = VirtioNetConfig {
                mac: reader.fixed()?,
                status: reader.u16()?,
                max_virtqueue_pairs: reader.u16()?,
            };
            if !valid_mac(config.mac) {
                return Err(utils::state::Error::Invalid("net MAC"));
            }
            reader.finish()?;
            Ok(Self {
                available,
                acknowledged,
                config,
            })
        };
        decode().map_err(|_| ProviderFault::DeviceState)
    }
}

fn valid_mac(mac: [u8; 6]) -> bool {
    mac[0] & 1 == 0 && mac != [0; 6]
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,
    avail_features: u64,
    acked_features: u64,
    pub(crate) device_state: DeviceState,
    config: VirtioNetConfig,
    destination_mac: Option<[u8; 6]>,
    lifecycle: LifecycleJournal,
    worker: Option<JoinHandle<()>>,
    slot: Arc<Mutex<Option<NetWorker>>>,
    parked: Option<ParkedNetWorker>,
    control: Option<(Arc<Mutex<WorkerAdmission>>, Arc<EventFd>)>,
    restored: bool,
    activation: Option<BarrierRequest>,
    activation_fault: Option<ProviderFault>,
    activation_done: bool,
    terminal_wake_attempted: bool,
}

impl Net {
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
    ) -> Result<Self> {
        Ok(Self {
            id,
            cfg_backend,
            avail_features: u64::from(features)
                | (1 << VIRTIO_NET_F_MAC)
                | (1 << VIRTIO_RING_F_EVENT_IDX)
                | (1 << 32),
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config: VirtioNetConfig {
                mac,
                status: 0,
                max_virtqueue_pairs: 0,
            },
            destination_mac: None,
            lifecycle: LifecycleJournal::new(),
            worker: None,
            slot: Arc::new(Mutex::new(None)),
            parked: None,
            control: None,
            restored: false,
            activation: None,
            activation_fault: None,
            activation_done: false,
            terminal_wake_attempted: false,
        })
    }

    /// The caller supplies the managed reservation authority; generic datagram
    /// paths and unqualified descriptors remain cold-only backends.
    pub fn new_managed(id: String, fd: OwnedFd, mac: [u8; 6], features: u32) -> Result<Self> {
        if !valid_mac(mac) {
            return Err(crate::virtio::net::Error::EventFd(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid managed network MAC",
            )));
        }
        crate::virtio::net::unixgram::Unixgram::prepare_managed(&fd)
            .map_err(|error| crate::virtio::net::Error::EventFd(std::io::Error::from(error)))?;
        Self::new(
            id,
            VirtioNetBackend::ManagedUnixgram(Arc::new(fd)),
            mac,
            features,
        )
    }

    /// Bind a fresh destination socket and explicit device-visible MAC override.
    /// The caller retains its reservation ingress fence through the provider's
    /// activation-release acknowledgement, including for an inactive transport.
    pub fn new_restore_binding(
        id: String,
        fd: OwnedFd,
        mac: [u8; 6],
        features: u32,
    ) -> Result<Self> {
        let mut net = Self::new_managed(id, fd, mac, features)?;
        net.destination_mac = Some(mac);
        Ok(net)
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn backend(&self) -> &VirtioNetBackend {
        &self.cfg_backend
    }

    fn start(&mut self, queues: Vec<DeviceQueue>) -> std::result::Result<(), ProviderFault> {
        let [rx_q, tx_q]: [_; NUM_QUEUES] =
            queues.try_into().map_err(|_| ProviderFault::QueueCount)?;
        let parked = self.parked.take().ok_or(ProviderFault::Worker)?;
        self.control = Some((Arc::clone(&parked.admission), Arc::clone(&parked.wake)));
        let worker = parked.attach(rx_q, tx_q);
        match self.slot.lock() {
            Ok(mut slot) => *slot = Some(worker),
            Err(poisoned) => {
                *poisoned.into_inner() = Some(worker);
                return Err(ProviderFault::Worker);
            }
        }
        self.worker =
            Some(NetWorker::run(Arc::clone(&self.slot)).map_err(|_| ProviderFault::Worker)?);
        Ok(())
    }

    fn reap(&mut self) -> std::result::Result<bool, ProviderFault> {
        if let Some(worker) = self.worker.as_ref() {
            if !worker.is_finished() {
                return Ok(false);
            }
        } else {
            return Ok(true);
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| ProviderFault::Worker)?;
        }
        Ok(true)
    }

    fn checked_payload(
        &self,
        bytes: &[u8],
        restoring: bool,
    ) -> std::result::Result<NetPayload, ProviderFault> {
        self.preflight()?;
        let saved = NetPayload::decode(bytes)?;
        if saved.available != self.avail_features
            || saved.config.status != self.config.status
            || saved.config.max_virtqueue_pairs != self.config.max_virtqueue_pairs
            || (!restoring && self.destination_mac.is_none() && saved.config.mac != self.config.mac)
            || (restoring && self.destination_mac.is_none())
        {
            return Err(ProviderFault::DeviceState);
        }
        Ok(saved)
    }
}

impl VirtioDevice for Net {
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
        TYPE_NET
    }
    fn device_name(&self) -> &str {
        "net"
    }
    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let Ok(offset) = usize::try_from(offset) else {
            return;
        };
        let Some(config) = self.config.as_slice().get(offset..) else {
            return;
        };
        let count = config.len().min(data.len());
        data[..count].copy_from_slice(&config[..count]);
    }
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest attempted config write (offset={offset:x}, len={:x})",
            data.len()
        );
    }
    fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker.is_some() || self.is_activated() {
            return Err(ActivateError::BadActivate);
        }
        if self.parked.is_none() {
            self.parked = Some(
                ParkedNetWorker::new(
                    mem.clone(),
                    interrupt.clone(),
                    self.acked_features,
                    self.cfg_backend.clone(),
                    if self.restored {
                        EndpointMode::ActivationFenced
                    } else {
                        EndpointMode::Open
                    },
                )
                .map_err(|_| ActivateError::BadActivate)?,
            );
        }
        if let Some(state) = &self.parked {
            state
                .admission
                .lock()
                .map_err(|_| ActivateError::BadActivate)?
                .closed = false;
        }
        self.start(queues).map_err(|_| ActivateError::BadActivate)?;
        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }
    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
    fn state_provider(&self) -> Option<&dyn VirtioStateProvider> {
        Some(self)
    }
    fn state_provider_mut(&mut self) -> Option<&mut dyn VirtioStateProvider> {
        Some(self)
    }
}

impl VirtioStateProvider for Net {
    fn preflight(&self) -> std::result::Result<(), ProviderFault> {
        if matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Stopping | ProviderStage::Stopped
        ) {
            return Err(ProviderFault::InvalidTransition);
        }
        match &self.cfg_backend {
            VirtioNetBackend::ManagedUnixgram(fd) => {
                crate::virtio::net::unixgram::Unixgram::validate_managed(fd)
                    .map_err(|_| ProviderFault::DeviceState)
            }
            _ => Err(ProviderFault::Unsupported),
        }
    }
    fn begin_terminal_stop(
        &mut self,
        request: BarrierRequest,
    ) -> std::result::Result<(), ProviderBeginError> {
        // Managed endpoints keep their reversible accepted-work drain contract.
        // Cold-only endpoints use the same terminal ownership boundary as Drop,
        // without granting them capture/restore admission.
        let fault = if matches!(&self.cfg_backend, VirtioNetBackend::ManagedUnixgram(_)) {
            Some(ProviderFault::Unsupported)
        } else if matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Stopping | ProviderStage::Stopped
        ) {
            Some(ProviderFault::InvalidTransition)
        } else if Instant::now() >= request.deadline {
            Some(ProviderFault::Deadline)
        } else {
            None
        };
        if let Some(fault) = fault {
            return Err(ProviderBeginError {
                accepted: false,
                fault,
            });
        }
        self.lifecycle.begin(request, ProviderStage::Stopping);
        Ok(())
    }

    fn poll_terminal_stop(
        &mut self,
        key: BarrierKey,
    ) -> std::result::Result<Poll<()>, ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if self.lifecycle.snapshot.stage == ProviderStage::Stopped {
            return self
                .lifecycle
                .snapshot
                .failure
                .map_or(Ok(Poll::Ready(())), |error| Err(error.fault));
        }
        if self.lifecycle.snapshot.stage != ProviderStage::Stopping {
            return Err(ProviderFault::InvalidTransition);
        }
        // Wake/poison failures retain the original owner and are never retried.
        if let Some(error) = self.lifecycle.snapshot.failure {
            return Err(error.fault);
        }
        if !self.terminal_wake_attempted {
            if let Some((admission, wake)) = &self.control {
                let mut admission = match admission.try_lock() {
                    Ok(admission) => admission,
                    Err(TryLockError::WouldBlock) => return Ok(Poll::Pending),
                    Err(TryLockError::Poisoned(_)) => {
                        return Err(self.lifecycle.fail(key, ProviderFault::DeviceLock).fault);
                    }
                };
                admission.closed = true;
                admission.stop = true;
                drop(admission);
                self.terminal_wake_attempted = true;
                if wake.write(1).is_err() {
                    return Err(self.lifecycle.fail(key, ProviderFault::Notification).fault);
                }
            } else if self.worker.is_some() {
                return Err(self.lifecycle.fail(key, ProviderFault::Worker).fault);
            }
        }
        match self.reap() {
            Ok(false) => return Ok(Poll::Pending),
            Err(fault) => return Err(self.lifecycle.fail(key, fault).fault),
            Ok(true) => {}
        }
        let slot = match self.slot.try_lock() {
            Ok(slot) => slot,
            Err(TryLockError::WouldBlock) => return Ok(Poll::Pending),
            Err(TryLockError::Poisoned(_)) => {
                return Err(self.lifecycle.fail(key, ProviderFault::DeviceLock).fault);
            }
        };
        let fault = if let Some(worker) = slot.as_ref() {
            worker.state.fault
        } else if let Some(parked) = &self.parked {
            parked.fault
        } else if self.device_state.is_activated() {
            Some(ProviderFault::Worker)
        } else {
            None
        };
        if let Some(fault) = fault {
            return Err(self.lifecycle.fail(key, fault).fault);
        }
        // Queues and any partial backend frame remain in their original owner,
        // not in a serializable cut and not discarded by transport cleanup.
        self.lifecycle.snapshot.stage = ProviderStage::Stopped;
        Ok(Poll::Ready(()))
    }

    fn begin_quiesce(
        &mut self,
        request: BarrierRequest,
    ) -> std::result::Result<(), ProviderBeginError> {
        self.preflight().map_err(|fault| ProviderBeginError {
            accepted: false,
            fault,
        })?;
        if let Some(previous) = self.lifecycle.snapshot.request {
            if previous.key == request.key
                && matches!(
                    self.lifecycle.snapshot.stage,
                    ProviderStage::Quiescing | ProviderStage::Quiesced
                )
            {
                if previous != request {
                    return Err(ProviderBeginError {
                        accepted: true,
                        fault: ProviderFault::ForeignBarrier,
                    });
                }
                return Ok(());
            }
            if !matches!(
                self.lifecycle.snapshot.stage,
                ProviderStage::Running | ProviderStage::Resuming
            ) {
                return Err(ProviderBeginError {
                    accepted: false,
                    fault: ProviderFault::InvalidTransition,
                });
            }
        }
        if Instant::now() >= request.deadline {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::Deadline,
            });
        }
        if let Some((control, _)) = &self.control {
            let mut control = control.lock().map_err(|_| ProviderBeginError {
                accepted: false,
                fault: ProviderFault::Worker,
            })?;
            control.closed = true;
        }
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        if let Some((_, wake)) = &self.control {
            wake.write(1).map_err(|_| ProviderBeginError {
                accepted: true,
                fault: ProviderFault::Worker,
            })?;
        }
        Ok(())
    }
    fn poll_quiesce(
        &mut self,
        key: BarrierKey,
    ) -> std::result::Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.lifecycle
            .check(key)
            .map_err(|_| ProviderFault::ForeignBarrier)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiescing {
            return Err(ProviderFault::InvalidTransition);
        }
        if !self.reap()? {
            return Ok(Poll::Pending);
        }
        let returned = self.slot.lock().map_err(|_| ProviderFault::Worker)?.take();
        let (queues, fault) = if let Some(worker) = returned {
            let NetWorker { rx_q, tx_q, state } = worker;
            let mut fault = state.fault.or(self
                .lifecycle
                .snapshot
                .previous_failure
                .map(|error| error.fault));
            if rx_q.queue.capture_state().is_err() || tx_q.queue.capture_state().is_err() {
                fault.get_or_insert(ProviderFault::QueueState);
            }
            self.parked = Some(state);
            (vec![rx_q, tx_q], fault)
        } else if !self.device_state.is_activated() {
            (
                Vec::new(),
                self.parked.as_ref().and_then(|state| state.fault),
            )
        } else {
            return Err(ProviderFault::Worker);
        };
        self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
        if let Some(fault) = fault {
            self.lifecycle.fail(key, fault);
        }
        Ok(Poll::Ready(QuiesceCompletion { queues, fault }))
    }
    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance {
        let reject = |queues, fault| ResumeAcceptance::Rejected { queues, fault };
        let Some(cut) = self.lifecycle.snapshot.quiesce_request else {
            return reject(queues, ProviderFault::InvalidTransition);
        };
        if cut.key.generation != request.key.generation
            || !matches!(
                self.lifecycle.snapshot.stage,
                ProviderStage::Quiesced | ProviderStage::Quiescing
            )
        {
            return reject(queues, ProviderFault::ForeignBarrier);
        }
        if self.lifecycle.snapshot.failure.is_some() {
            return reject(queues, ProviderFault::Worker);
        }
        let active = self.device_state.is_activated();
        if queues.len() != if active { NUM_QUEUES } else { 0 } {
            return reject(queues, ProviderFault::QueueCount);
        }
        if active && self.parked.is_none() {
            return reject(queues, ProviderFault::Worker);
        }
        if Instant::now() >= request.deadline {
            return reject(queues, ProviderFault::Deadline);
        }
        if let Some(parked) = &self.parked {
            match parked.admission.lock() {
                Ok(mut admission) => {
                    admission.closed = false;
                    admission.running = false;
                }
                Err(_) => return reject(queues, ProviderFault::Worker),
            }
        }
        self.lifecycle.begin(request, ProviderStage::Resuming);
        if active && let Err(fault) = self.start(queues) {
            self.lifecycle.fail(request.key, fault);
            return ResumeAcceptance::AcceptedWithFailure(fault);
        }
        ResumeAcceptance::Accepted
    }
    fn poll_resume(&mut self, key: BarrierKey) -> std::result::Result<Poll<()>, ProviderFault> {
        self.lifecycle
            .check(key)
            .map_err(|_| ProviderFault::ForeignBarrier)?;
        if self.lifecycle.snapshot.stage == ProviderStage::Running {
            return Ok(Poll::Ready(()));
        }
        if self.lifecycle.snapshot.stage != ProviderStage::Resuming {
            return Err(ProviderFault::InvalidTransition);
        }
        if let Some(worker) = &self.worker {
            if worker.is_finished() {
                return Err(ProviderFault::Worker);
            }
            let (control, _) = self.control.as_ref().ok_or(ProviderFault::Worker)?;
            if !control.lock().map_err(|_| ProviderFault::Worker)?.running {
                return Ok(Poll::Pending);
            }
        }
        self.lifecycle.snapshot.stage = ProviderStage::Running;
        Ok(Poll::Ready(()))
    }
    fn state_limit(&self) -> u32 {
        STATE_LIMIT as u32
    }
    fn capture_payload(&self, key: BarrierKey) -> std::result::Result<Vec<u8>, ProviderFault> {
        self.lifecycle
            .check(key)
            .map_err(|_| ProviderFault::ForeignBarrier)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced
            || self.lifecycle.snapshot.failure.is_some()
        {
            return Err(ProviderFault::InvalidTransition);
        }
        self.preflight()?;
        let mut writer = Writer::new(STATE_LIMIT);
        let encode = || -> std::result::Result<Vec<u8>, utils::state::Error> {
            writer.u16(1)?;
            writer.u32(TYPE_NET)?;
            writer.u64(self.avail_features)?;
            writer.u64(self.acked_features)?;
            writer.u8(1)?;
            writer.fixed(&self.config.mac)?;
            writer.u16(self.config.status)?;
            writer.u16(self.config.max_virtqueue_pairs)?;
            Ok(writer.finish())
        };
        encode().map_err(|_| ProviderFault::DeviceState)
    }
    fn validate_payload(&self, payload: &[u8]) -> std::result::Result<(), ProviderFault> {
        self.checked_payload(payload, false).map(|_| ())
    }
    fn validate_restore(&self, payload: &[u8]) -> std::result::Result<(), ProviderFault> {
        if self.is_activated() || self.worker.is_some() || self.parked.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.checked_payload(payload, true).map(|_| ())
    }
    fn apply_payload(&mut self, payload: &[u8]) -> std::result::Result<(), ProviderFault> {
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced {
            return Err(ProviderFault::InvalidTransition);
        }
        let saved = self.checked_payload(payload, false)?;
        self.acked_features = saved.acknowledged;
        Ok(())
    }
    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> std::result::Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        let saved = self.checked_payload(payload, true)?;
        self.acked_features = saved.acknowledged;
        self.config = saved.config;
        self.config.mac = self.destination_mac.ok_or(ProviderFault::DeviceState)?;
        self.restored = true;
        let state = ParkedNetWorker::new(
            context.memory.clone(),
            context.interrupt.clone(),
            self.acked_features,
            self.cfg_backend.clone(),
            EndpointMode::ActivationFenced,
        )
        .map_err(|_| ProviderFault::Worker)?;
        state
            .admission
            .lock()
            .map_err(|_| ProviderFault::Worker)?
            .closed = true;
        self.control = Some((Arc::clone(&state.admission), Arc::clone(&state.wake)));
        self.parked = Some(state);
        if context.activated {
            self.device_state = DeviceState::Activated(context.memory, context.interrupt);
        }
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
        Ok(())
    }
    fn begin_activation_release(
        &mut self,
        request: BarrierRequest,
    ) -> std::result::Result<(), ProviderBeginError> {
        if self.activation == Some(request) {
            return self.activation_fault.map_or(Ok(()), |fault| {
                Err(ProviderBeginError {
                    accepted: true,
                    fault,
                })
            });
        }
        if self.activation.is_some()
            || !self.restored
            || self.lifecycle.snapshot.stage != ProviderStage::Running
        {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::InvalidTransition,
            });
        }
        let cut = self
            .lifecycle
            .snapshot
            .quiesce_request
            .ok_or(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::ForeignBarrier,
            })?;
        if request.key.generation != cut.key.generation {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::ForeignBarrier,
            });
        }
        let (control, wake) = self.control.as_ref().ok_or(ProviderBeginError {
            accepted: false,
            fault: ProviderFault::InvalidTransition,
        })?;
        let mut control = control.try_lock().map_err(|error| ProviderBeginError {
            accepted: false,
            fault: match error {
                TryLockError::WouldBlock => ProviderFault::LockBusy,
                TryLockError::Poisoned(_) => ProviderFault::Worker,
            },
        })?;
        if control.release.is_some()
            || control.mode != EndpointMode::ActivationFenced
            || Instant::now() >= request.deadline
        {
            return Err(ProviderBeginError {
                accepted: false,
                fault: ProviderFault::InvalidTransition,
            });
        }
        self.activation = Some(request);
        control.release = Some(request);
        drop(control);
        wake.write(1).map_err(|_| {
            self.activation_fault = Some(ProviderFault::Worker);
            ProviderBeginError {
                accepted: true,
                fault: ProviderFault::Worker,
            }
        })
    }
    fn poll_activation_release(
        &mut self,
        key: BarrierKey,
    ) -> std::result::Result<Poll<()>, ProviderFault> {
        let request = self
            .activation
            .filter(|request| request.key == key)
            .ok_or(ProviderFault::ForeignBarrier)?;
        if self.activation_done {
            return Ok(Poll::Ready(()));
        }
        if let Some(fault) = self.activation_fault {
            return Err(fault);
        }
        if Instant::now() >= request.deadline {
            self.activation_fault = Some(ProviderFault::Deadline);
            return Err(ProviderFault::Deadline);
        }
        let active = self.is_activated();
        let result = (|| {
            let (control, _) = self
                .control
                .as_ref()
                .ok_or(ProviderFault::InvalidTransition)?;
            let mut control = match control.try_lock() {
                Ok(control) => control,
                Err(TryLockError::WouldBlock) => return Ok(Poll::Pending),
                Err(TryLockError::Poisoned(_)) => return Err(ProviderFault::Worker),
            };
            if control.released == Some(key) {
                return Ok(Poll::Ready(()));
            }
            if control.release != Some(request) {
                return Err(ProviderFault::ForeignBarrier);
            }
            if !active {
                let state = self.parked.as_mut().ok_or(ProviderFault::Worker)?;
                if let Some(fault) = state.fault {
                    return Err(fault);
                }
                match state.discard_ingress(request.deadline) {
                    Ok(true) => {
                        control.mode = EndpointMode::Open;
                        control.released = Some(key);
                        control.release = None;
                        return Ok(Poll::Ready(()));
                    }
                    Ok(false) => return Ok(Poll::Pending),
                    Err(fault) => {
                        state.fault = Some(fault);
                        return Err(fault);
                    }
                }
            }
            if self.worker.as_ref().is_none_or(JoinHandle::is_finished) {
                return Err(ProviderFault::Worker);
            }
            Ok(Poll::Pending)
        })();
        match result {
            Ok(Poll::Ready(())) => self.activation_done = true,
            Err(fault) => self.activation_fault = Some(fault),
            Ok(Poll::Pending) => {}
        }
        result
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Some((control, wake)) = &self.control {
            match control.lock() {
                Ok(mut control) => control.stop = true,
                Err(poisoned) => poisoned.into_inner().stop = true,
            }
            loop {
                match wake.write(1) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    _ => break,
                }
            }
        }
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            log::error!("virtio-net owner panicked during terminal cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn net_provider_ownership_handoffs_have_bounded_stack_footprint() {
        use crate::virtio::net::worker::{NetWorker, ParkedNetWorker};
        for (owner, size) in [
            ("device", std::mem::size_of::<Net>()),
            ("parked backend", std::mem::size_of::<ParkedNetWorker>()),
            ("worker", std::mem::size_of::<NetWorker>()),
        ] {
            assert!(
                size < 4096,
                "{owner} inlines frame storage into stack handoffs: {size} bytes"
            );
        }
    }

    use crate::virtio::lifecycle::{ProviderFault, VirtioStateProvider};
    use crate::virtio::net::device::{Net, VirtioNetBackend};
    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::time::{Duration, Instant};

    fn request() -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(21),
                generation: BarrierGeneration(9),
            },
            deadline: Instant::now() + Duration::from_secs(2),
        }
    }

    fn saved_payload() -> Vec<u8> {
        let (socket, _peer) = UnixDatagram::pair().expect("real datagram pair");
        let mut source = Net::new_managed("eth0".into(), socket.into(), [2, 0, 0, 0, 0, 1], 0)
            .expect("managed source");
        let cut = request();
        source.begin_quiesce(cut).expect("close inactive source");
        assert!(
            source
                .poll_quiesce(cut.key)
                .expect("complete inactive cut")
                .is_ready()
        );
        source
            .capture_payload(cut.key)
            .expect("explicit network payload")
    }

    fn inactive_activation_net() -> (Net, UnixDatagram, BarrierRequest) {
        use crate::legacy::DummyIrqChip;
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance,
        };
        use crate::virtio::{InterruptTransport, RuntimeGuestMemory};
        use vm_memory::GuestAddress;

        let (socket, peer) = UnixDatagram::pair().unwrap();
        let mut net =
            Net::new_restore_binding("eth0".into(), socket.into(), [2, 0, 0, 0, 0, 2], 0).unwrap();
        let cut = request();
        net.prepare_restore(
            cut,
            &saved_payload(),
            DormantDeviceContext {
                memory: RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
                interrupt: InterruptTransport::new(
                    DummyIrqChip::new().into(),
                    "net-activation-contention".into(),
                    None,
                )
                .unwrap(),
                activated: false,
                reclaim_policy: RestoredReclaimPolicy::Disabled,
            },
        )
        .unwrap();
        let resume = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(22),
                generation: cut.key.generation,
            },
            deadline: cut.deadline,
        };
        assert!(matches!(
            net.begin_resume(resume, Vec::new()),
            ResumeAcceptance::Accepted
        ));
        assert!(net.poll_resume(resume.key).unwrap().is_ready());
        let release = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(23),
                generation: cut.key.generation,
            },
            deadline: cut.deadline,
        };
        (net, peer, release)
    }

    #[test]
    fn net_provider_activation_retains_request_across_owner_contention_and_terminals() {
        use crate::virtio::net::worker::EndpointMode;
        use std::sync::{Arc, mpsc};
        use std::task::Poll;

        for (poison, expire) in [(false, false), (true, false), (false, true)] {
            let (mut net, peer, mut release) = inactive_activation_net();
            if expire {
                release.deadline = Instant::now() + Duration::from_millis(100);
            }
            let admission = Arc::clone(&net.control.as_ref().unwrap().0);
            let held = admission
                .lock()
                .expect("hold the unaccepted network owner gate");
            let rejected = net.begin_activation_release(release).unwrap_err();
            assert!(!rejected.accepted);
            assert_eq!(rejected.fault, ProviderFault::LockBusy);
            assert_eq!(net.activation, None);
            assert_eq!(held.release, None);
            drop(held);
            net.begin_activation_release(release).unwrap();
            let held = admission
                .lock()
                .expect("hold the actual network owner gate");
            let observed = std::thread::scope(|scope| {
                let (sender, receiver) = mpsc::sync_channel(1);
                let device = &mut net;
                scope.spawn(move || {
                    sender
                        .send((
                            device.poll_activation_release(release.key),
                            device.poll_activation_release(release.key),
                        ))
                        .unwrap();
                });
                let observed = receiver.recv_timeout(Duration::from_secs(1));
                drop(held);
                observed
            });
            assert_eq!(observed.unwrap(), (Ok(Poll::Pending), Ok(Poll::Pending)));
            assert_eq!(net.activation, Some(release));
            assert_eq!(
                admission.lock().expect("actual network owner gate").release,
                Some(release)
            );
            let stale = BarrierKey {
                operation: OperationId(24),
                ..release.key
            };
            assert_eq!(
                net.poll_activation_release(stale),
                Err(ProviderFault::ForeignBarrier)
            );
            if poison {
                let poisoned = Arc::clone(&admission);
                assert!(
                    std::thread::spawn(move || {
                        let _held = poisoned
                            .lock()
                            .expect("poison the actual network owner gate");
                        panic!("poison the actual pending network owner gate");
                    })
                    .join()
                    .is_err()
                );
            } else if expire {
                let held = admission
                    .lock()
                    .expect("hold the actual network owner gate");
                while Instant::now() < release.deadline {
                    std::thread::yield_now();
                }
                assert_eq!(
                    net.poll_activation_release(release.key),
                    Err(ProviderFault::Deadline)
                );
                assert_eq!(held.release, Some(release));
                assert_eq!(held.mode, EndpointMode::ActivationFenced);
                drop(held);
            } else {
                peer.send(b"fenced backlog").unwrap();
                while net
                    .poll_activation_release(release.key)
                    .unwrap()
                    .is_pending()
                {
                    assert!(Instant::now() < release.deadline);
                }
                let held = admission
                    .lock()
                    .expect("hold the completed network owner gate");
                assert_eq!(held.release, None);
                assert_eq!(held.released, Some(release.key));
                assert_eq!(held.mode, EndpointMode::Open);
                while Instant::now() < release.deadline {
                    std::thread::yield_now();
                }
                assert_eq!(
                    net.poll_activation_release(release.key),
                    Ok(Poll::Ready(()))
                );
                assert_eq!(
                    net.poll_activation_release(stale),
                    Err(ProviderFault::ForeignBarrier)
                );
                drop(held);
                continue;
            }
            let expected = if poison {
                ProviderFault::Worker
            } else {
                ProviderFault::Deadline
            };
            assert_eq!(net.poll_activation_release(release.key), Err(expected));
            assert_eq!(net.poll_activation_release(release.key), Err(expected));
            let repeated = net.begin_activation_release(release).unwrap_err();
            assert!(repeated.accepted);
            assert_eq!(repeated.fault, expected);
            assert_eq!(net.activation, Some(release));
        }
    }

    #[test]
    fn net_provider_refuses_generic_and_stream_resources_before_worker_creation() {
        let source = Net::new(
            "eth0".into(),
            VirtioNetBackend::UnixgramPath("/not/opened".into(), false),
            [2, 0, 0, 0, 0, 1],
            0,
        )
        .expect("cold generic backend");
        assert_eq!(source.preflight(), Err(ProviderFault::Unsupported));
        assert!(source.worker.is_none());
        assert!(source.parked.is_none());
        #[cfg(target_os = "linux")]
        {
            let tap = Net::new(
                "eth0".into(),
                VirtioNetBackend::Tap("not-created".into()),
                [2, 0, 0, 0, 0, 1],
                0,
            )
            .expect("cold TAP configuration");
            assert_eq!(tap.preflight(), Err(ProviderFault::Unsupported));
            assert!(tap.worker.is_none());
        }
        let (socket, _peer) = UnixStream::pair().expect("real stream pair");
        let fd: std::os::fd::OwnedFd = socket.into();
        let observer = nix::unistd::dup(&fd).expect("retain actual stream flags");
        let before =
            nix::fcntl::fcntl(&observer, nix::fcntl::FcntlArg::F_GETFL).expect("original flags");
        assert!(Net::new_managed("eth0".into(), fd, [2, 0, 0, 0, 0, 1], 0).is_err());
        assert_eq!(
            nix::fcntl::fcntl(&observer, nix::fcntl::FcntlArg::F_GETFL)
                .expect("refused stream flags"),
            before
        );
    }

    #[test]
    fn net_provider_restore_requires_explicit_validated_mac_and_exact_framing() {
        let saved = saved_payload();
        let (socket, _peer) = UnixDatagram::pair().expect("real destination pair");
        let destination =
            Net::new_restore_binding("eth0".into(), socket.into(), [2, 0, 0, 0, 0, 2], 0)
                .expect("explicit destination");
        destination
            .validate_restore(&saved)
            .expect("only destination MAC differs");
        let (socket, _peer) = UnixDatagram::pair().expect("real source pair");
        let source_only = Net::new_managed("eth0".into(), socket.into(), [2, 0, 0, 0, 0, 1], 0)
            .expect("not a destination binding");
        assert_eq!(
            source_only.validate_restore(&saved),
            Err(ProviderFault::DeviceState)
        );
        for length in 0..saved.len() {
            assert!(destination.validate_restore(&saved[..length]).is_err());
        }
        let mut trailing = saved.clone();
        trailing.push(0);
        assert!(destination.validate_restore(&trailing).is_err());
        let mut unknown = saved.clone();
        unknown[22] = 2;
        assert!(destination.validate_restore(&unknown).is_err());
        let mut features = saved;
        features[6] ^= 1;
        assert!(destination.validate_restore(&features).is_err());
        let (socket, _peer) = UnixDatagram::pair().expect("real bad MAC pair");
        assert!(
            Net::new_restore_binding("eth0".into(), socket.into(), [1, 0, 0, 0, 0, 1], 0).is_err()
        );
        let (socket, _peer) = UnixDatagram::pair().expect("real zero MAC pair");
        assert!(Net::new_restore_binding("eth0".into(), socket.into(), [0; 6], 0).is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn net_provider_real_worker_escrows_two_queues_and_resumes_without_kick() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::lifecycle::ResumeAcceptance;
        use crate::virtio::net::VNET_HDR_LEN;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory, VirtioDevice};
        use std::sync::{Arc, Mutex};
        use std::task::Poll;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        let memory =
            RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("guest RAM");
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let rx_event = Arc::new(EventFd::new(0).expect("RX event"));
        let tx_event = Arc::new(EventFd::new(0).expect("TX event"));
        let (socket, peer) = UnixDatagram::pair().expect("connected managed endpoint");
        peer.set_nonblocking(true).expect("nonblocking observation");
        let mut net = Net::new_managed("eth0".into(), socket.into(), [2, 0, 0, 0, 0, 1], 0)
            .expect("managed source");
        let irq = InterruptTransport::new(
            Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
            "net-provider-lifecycle".into(),
            None,
        )
        .expect("real eventfd notifier");
        net.activate(
            memory.clone(),
            irq,
            vec![
                DeviceQueue::new(rx.create_queue(), Arc::clone(&rx_event)),
                DeviceQueue::new(tx.create_queue(), Arc::clone(&tx_event)),
            ],
        )
        .expect("real worker activation");
        let cut = request();
        net.begin_quiesce(cut).expect("accepted close");
        let completion = loop {
            match net.poll_quiesce(cut.key).expect("real owner completion") {
                Poll::Ready(completion) => break completion,
                Poll::Pending => {
                    assert!(Instant::now() < cut.deadline, "real worker did not return");
                    std::thread::yield_now();
                }
            }
        };
        assert!(completion.fault.is_none());
        assert_eq!(completion.queues.len(), 2);
        assert!(Arc::ptr_eq(&completion.queues[0].event, &rx_event));
        assert!(Arc::ptr_eq(&completion.queues[1].event, &tx_event));
        let first = net.capture_payload(cut.key).expect("capture parked source");
        assert_eq!(
            first,
            net.capture_payload(cut.key).expect("same retained cut")
        );
        assert!(
            net.poll_quiesce(cut.key).is_err(),
            "queue transfer is not repeatable"
        );
        tx.dtable[0].set(0x5000, (VNET_HDR_LEN + 6) as u32, 0, 0);
        memory
            .write_slice(b"resume", GuestAddress(0x5000 + VNET_HDR_LEN as u64))
            .expect("queued frame");
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        let resume = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(22),
                generation: cut.key.generation,
            },
            deadline: cut.deadline,
        };
        assert!(matches!(
            net.begin_resume(resume, completion.queues),
            ResumeAcceptance::Accepted
        ));
        while net
            .poll_resume(resume.key)
            .expect("real running acknowledgement")
            .is_pending()
        {
            assert!(Instant::now() < resume.deadline);
            std::thread::yield_now();
        }
        let mut frame = [0; 64];
        let count = loop {
            match peer.recv(&mut frame) {
                Ok(count) => break count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < resume.deadline);
                    std::thread::yield_now();
                }
                Err(error) => panic!("endpoint receive: {error}"),
            }
        };
        assert_eq!(&frame[..count], b"resume");
        let next = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(23),
                generation: BarrierGeneration(10),
            },
            deadline: Instant::now() + Duration::from_secs(2),
        };
        net.begin_quiesce(next).expect("new cut");
        let completion = loop {
            match net
                .poll_quiesce(next.key)
                .expect("repeated actual owner completion")
            {
                Poll::Ready(completion) => break completion,
                Poll::Pending => {
                    assert!(Instant::now() < next.deadline);
                    std::thread::yield_now();
                }
            }
        };
        assert!(completion.fault.is_none());
        let saved_tx = completion.queues[1]
            .queue
            .capture_state()
            .expect("terminal TX");
        assert_eq!((saved_tx.next_avail, saved_tx.next_used), (1, 1));
        assert!(Arc::ptr_eq(&completion.queues[1].event, &tx_event));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn net_provider_inactive_restore_discards_backlog_before_late_activation() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance,
        };
        use crate::virtio::net::worker::EndpointMode;
        use crate::virtio::{InterruptTransport, RuntimeGuestMemory};
        use std::sync::{Arc, Mutex};
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        let saved = saved_payload();
        let (socket, peer) = UnixDatagram::pair().expect("fresh endpoint");
        let mut net = Net::new_restore_binding("eth0".into(), socket.into(), [2, 0, 0, 0, 0, 2], 0)
            .expect("trusted binding");
        let cut = request();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("RAM");
        let interrupt = InterruptTransport::new(
            Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
            "net-provider-inactive".into(),
            Some(Arc::new(EventFd::new(0).expect("IRQ event"))),
        )
        .expect("interrupt transport");
        net.prepare_restore(
            cut,
            &saved,
            DormantDeviceContext {
                memory,
                interrupt,
                activated: false,
                reclaim_policy: RestoredReclaimPolicy::Disabled,
            },
        )
        .expect("dormant inactive install");
        assert!(net.worker.is_none());
        peer.send(b"old-ingress-before-release")
            .expect("queued ingress");
        let resume = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(22),
                generation: cut.key.generation,
            },
            deadline: cut.deadline,
        };
        assert!(matches!(
            net.begin_resume(resume, Vec::new()),
            ResumeAcceptance::Accepted
        ));
        assert!(
            net.poll_resume(resume.key)
                .expect("inactive resume")
                .is_ready()
        );
        let release = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(23),
                generation: cut.key.generation,
            },
            deadline: cut.deadline,
        };
        net.begin_activation_release(release)
            .expect("explicit activation release");
        while net
            .poll_activation_release(release.key)
            .expect("bounded discard")
            .is_pending()
        {
            assert!(Instant::now() < release.deadline);
        }
        assert!(net.worker.is_none());
        use std::os::fd::AsRawFd;
        if let VirtioNetBackend::ManagedUnixgram(fd) = &net.cfg_backend {
            let mut stale = [0; 128];
            assert_eq!(
                nix::sys::socket::recv(
                    fd.as_raw_fd(),
                    &mut stale,
                    nix::sys::socket::MsgFlags::MSG_DONTWAIT
                ),
                Err(nix::Error::EAGAIN),
                "release must consume backlog before acknowledging",
            );
        } else {
            panic!("managed binding lost");
        }
        let state = net.parked.as_ref().expect("retained dormant endpoint");
        assert_eq!(
            state.admission.lock().expect("admission").mode,
            EndpointMode::Open
        );
        assert!(!state.rx_deferred);
        assert_eq!(state.rx_len, 0);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn net_provider_cold_stream_drop_reaps_owner_with_partial_ingress() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory, VirtioDevice};
        use nix::sys::socket::{MsgFlags, recv};
        use std::io::Write;
        use std::os::fd::{AsRawFd, IntoRawFd};
        use std::sync::{Arc, Mutex, mpsc};
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        for prefix in [&[0, 0][..], &[0, 0, 0, 8, b'a', b'b'][..]] {
            let memory =
                RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("RAM");
            let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
            let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
            let (socket, mut peer) = UnixStream::pair().expect("real cold stream");
            let observer = nix::unistd::dup(&socket).expect("observe receive consumption");
            let mut net = Net::new(
                "cold-stream".into(),
                VirtioNetBackend::UnixstreamFd(socket.into_raw_fd()),
                [2, 0, 0, 0, 0, 1],
                0,
            )
            .expect("cold backend");
            let interrupt = InterruptTransport::new(
                Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
                "net-stream-terminal-drop".into(),
                None,
            )
            .expect("eventfd notifier");
            net.activate(
                memory.clone(),
                interrupt,
                vec![
                    DeviceQueue::new(
                        rx.create_queue(),
                        Arc::new(EventFd::new(0).expect("RX kick")),
                    ),
                    DeviceQueue::new(
                        tx.create_queue(),
                        Arc::new(EventFd::new(0).expect("TX kick")),
                    ),
                ],
            )
            .expect("cold worker");
            let retained_owner = Arc::clone(&net.slot);
            peer.write_all(prefix).expect("partial ingress");
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut peek = [0; 32];
            loop {
                match recv(
                    observer.as_raw_fd(),
                    &mut peek,
                    MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
                ) {
                    Err(nix::Error::EAGAIN) => break,
                    Ok(_) => {
                        assert!(
                            Instant::now() < deadline,
                            "worker did not consume the real partial frame"
                        );
                        std::thread::yield_now();
                    }
                    Err(error) => panic!("receive observation failed: {error}"),
                }
            }
            let (completed, completion) = mpsc::sync_channel(1);
            let drop_owner = std::thread::spawn(move || {
                drop(net);
                completed.send(()).expect("report terminal cleanup");
            });
            let result = completion.recv_timeout(Duration::from_secs(2));
            if result.is_err() {
                let mut full = vec![0, 0, 0, 8];
                full.extend_from_slice(b"abcdefgh");
                let _ = peer.write_all(&full[prefix.len()..]);
                let _ = completion.recv_timeout(Duration::from_secs(2));
            }
            drop_owner.join().expect("Drop owner did not panic");
            assert!(
                result.is_ok(),
                "partial stream receive prevented terminal Drop"
            );
            let slot = retained_owner.lock().expect("retained owner slot");
            let worker = slot
                .as_ref()
                .expect("Drop joined actual worker before releasing resources");
            assert!(
                !worker
                    .state
                    .admission
                    .lock()
                    .expect("terminal admission")
                    .running
            );
            assert!(worker.state.fault.is_none());
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn net_provider_activated_child_source_resume_retains_open_endpoint_and_ingress() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::lifecycle::{
            DormantDeviceContext, RestoredReclaimPolicy, ResumeAcceptance,
        };
        use crate::virtio::net::VNET_HDR_LEN;
        use crate::virtio::net::worker::EndpointMode;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{DeviceQueue, InterruptTransport, RuntimeGuestMemory};
        use nix::sys::socket::{MsgFlags, recv};
        use std::os::fd::AsRawFd;
        use std::sync::{Arc, Mutex};
        use std::task::Poll;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        fn wait_for(deadline: Instant, mut observed: impl FnMut() -> bool) {
            while !observed() {
                assert!(
                    Instant::now() < deadline,
                    "actual network owner did not make progress"
                );
                std::thread::yield_now();
            }
        }

        fn resume(net: &mut Net, request: BarrierRequest, queues: Vec<DeviceQueue>) {
            assert!(matches!(
                net.begin_resume(request, queues),
                ResumeAcceptance::Accepted
            ));
            wait_for(request.deadline, || {
                net.poll_resume(request.key)
                    .expect("running ownership")
                    .is_ready()
            });
        }

        let saved = saved_payload();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).expect("RAM");
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let rx_event = Arc::new(EventFd::new(0).expect("RX event"));
        let tx_event = Arc::new(EventFd::new(0).expect("TX event"));
        rx.dtable[0].set(0x4000, 128, 2, 0);
        rx.avail.ring[0].set(0);
        rx.avail.idx.set(1);
        tx.dtable[0].set(0x5000, (VNET_HDR_LEN + 4) as u32, 0, 0);
        memory
            .write_slice(b"drop", GuestAddress(0x5000 + VNET_HDR_LEN as u64))
            .expect("fenced TX");
        tx.avail.ring[0].set(0);
        tx.avail.idx.set(1);
        let (socket, peer) = UnixDatagram::pair().expect("fresh actual endpoint");
        peer.set_nonblocking(true)
            .expect("bounded peer observation");
        let mut net = Net::new_restore_binding("eth0".into(), socket.into(), [2, 0, 0, 0, 0, 2], 0)
            .expect("fresh binding");
        let endpoint = match &net.cfg_backend {
            VirtioNetBackend::ManagedUnixgram(fd) => Arc::clone(fd),
            _ => panic!("managed binding"),
        };
        let interrupt = InterruptTransport::new(
            Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
            "net-activated-child-source".into(),
            None,
        )
        .expect("real eventfd notifier");
        let cut = request();
        net.prepare_restore(
            cut,
            &saved,
            DormantDeviceContext {
                memory: memory.clone(),
                interrupt,
                activated: true,
                reclaim_policy: RestoredReclaimPolicy::Disabled,
            },
        )
        .expect("dormant restore");
        let admission = Arc::clone(&net.control.as_ref().expect("retained endpoint gate").0);
        resume(
            &mut net,
            BarrierRequest {
                key: BarrierKey {
                    operation: OperationId(22),
                    generation: cut.key.generation,
                },
                deadline: cut.deadline,
            },
            vec![
                DeviceQueue::new(rx.create_queue(), Arc::clone(&rx_event)),
                DeviceQueue::new(tx.create_queue(), Arc::clone(&tx_event)),
            ],
        );
        peer.send(b"fenced").expect("fenced ingress");
        wait_for(cut.deadline, || tx.used.idx.get() == 1);
        let mut packet = [0; 128];
        assert_eq!(
            peer.recv(&mut packet)
                .expect_err("fenced TX never escapes")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(rx.used.idx.get(), 0);
        let activation = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(23),
                generation: cut.key.generation,
            },
            deadline: cut.deadline,
        };
        wait_for(activation.deadline, || {
            match net.begin_activation_release(activation) {
                Ok(()) => true,
                Err(error) if !error.accepted && error.fault == ProviderFault::LockBusy => false,
                Err(error) => panic!("explicit activation failed: {error:?}"),
            }
        });
        wait_for(cut.deadline, || {
            net.poll_activation_release(activation.key)
                .expect("discard boundary")
                .is_ready()
        });
        peer.send(b"before").expect("open endpoint ingress");
        wait_for(cut.deadline, || rx.used.idx.get() == 1);
        memory
            .read_slice(&mut packet[..6], GuestAddress(0x4000 + VNET_HDR_LEN as u64))
            .expect("fresh DMA");
        assert_eq!(
            &packet[..6],
            b"before",
            "fenced backlog must not become the first delivered frame"
        );

        peer.send(b"retained").expect("source-starved ingress");
        wait_for(cut.deadline, || {
            matches!(
                recv(
                    endpoint.as_raw_fd(),
                    &mut packet,
                    MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT
                ),
                Err(nix::Error::EAGAIN)
            )
        });
        let source_cut = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(24),
                generation: BarrierGeneration(10),
            },
            deadline: Instant::now() + Duration::from_secs(2),
        };
        net.begin_quiesce(source_cut)
            .expect("activated child becomes a source");
        let completion = loop {
            match net
                .poll_quiesce(source_cut.key)
                .expect("actual source owner return")
            {
                Poll::Ready(completion) => break completion,
                Poll::Pending => {
                    assert!(Instant::now() < source_cut.deadline);
                    std::thread::yield_now();
                }
            }
        };
        assert!(completion.fault.is_none());
        assert!(Arc::ptr_eq(&completion.queues[0].event, &rx_event));
        assert!(Arc::ptr_eq(&completion.queues[1].event, &tx_event));
        let parked = net.parked.as_ref().expect("same parked source");
        assert!(parked.rx_deferred);
        assert_eq!(parked.rx_len, VNET_HDR_LEN + 8);
        assert!(Arc::ptr_eq(&parked.admission, &admission));
        assert_eq!(
            admission.lock().expect("source gate").mode,
            EndpointMode::Open
        );
        assert_eq!(
            admission.lock().expect("retained activation ACK").released,
            Some(activation.key)
        );
        let recaptured = net
            .capture_payload(source_cut.key)
            .expect("activated child recapture");
        net.validate_payload(&recaptured)
            .expect("same source config and features");
        assert_eq!(
            recaptured,
            net.capture_payload(source_cut.key)
                .expect("retained child cut")
        );
        rx.dtable[1].set(0x4100, 128, 2, 0);
        rx.avail.ring[1].set(1);
        rx.avail.idx.set(2);
        tx.dtable[1].set(0x5100, (VNET_HDR_LEN + 5) as u32, 0, 0);
        memory
            .write_slice(b"after", GuestAddress(0x5100 + VNET_HDR_LEN as u64))
            .expect("source TX");
        tx.avail.ring[1].set(1);
        tx.avail.idx.set(2);
        resume(
            &mut net,
            BarrierRequest {
                key: BarrierKey {
                    operation: OperationId(25),
                    generation: source_cut.key.generation,
                },
                deadline: source_cut.deadline,
            },
            completion.queues,
        );
        wait_for(source_cut.deadline, || {
            rx.used.idx.get() == 2 && tx.used.idx.get() == 2
        });
        assert_eq!(
            peer.recv(&mut packet)
                .expect("same endpoint TX after source resume"),
            5
        );
        assert_eq!(&packet[..5], b"after");
        memory
            .read_slice(&mut packet[..8], GuestAddress(0x4100 + VNET_HDR_LEN as u64))
            .expect("retained source ingress DMA");
        assert_eq!(&packet[..8], b"retained");
        assert!(Arc::ptr_eq(
            &net.control.as_ref().expect("running gate").0,
            &admission
        ));
        assert_eq!(
            admission.lock().expect("ordinary source resume mode").mode,
            EndpointMode::Open
        );
        rx.dtable[2].set(0x4200, 128, 2, 0);
        rx.avail.ring[2].set(2);
        rx.avail.idx.set(3);
        peer.send(b"fresh")
            .expect("new source ingress without reactivation");
        wait_for(source_cut.deadline, || rx.used.idx.get() == 3);
        memory
            .read_slice(&mut packet[..5], GuestAddress(0x4200 + VNET_HDR_LEN as u64))
            .expect("fresh source DMA");
        assert_eq!(&packet[..5], b"fresh");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
    #[test]
    fn net_provider_cold_stream_transport_stop_retains_partial_ingress_and_reaps_owner() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::lifecycle::ProviderStage;
        use crate::virtio::queue::tests::VirtQueue;
        use crate::virtio::{
            DeviceQueue, InterruptTransport, MmioTransport, RuntimeGuestMemory, VirtioDevice,
        };
        use nix::sys::socket::{MsgFlags, recv};
        use std::io::Write;
        use std::os::fd::{AsRawFd, IntoRawFd};
        use std::sync::{Arc, Mutex};
        use utils::eventfd::{EFD_NONBLOCK, EventFd};
        use vm_memory::GuestAddress;

        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0), &memory, 8);
        let tx = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let observer = nix::unistd::dup(&socket).unwrap();
        let net = Arc::new(Mutex::new(
            Net::new(
                "cold-stream".into(),
                VirtioNetBackend::UnixstreamFd(socket.into_raw_fd()),
                [2, 0, 0, 0, 0, 1],
                0,
            )
            .unwrap(),
        ));
        let irq = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {}))));
        let mut transport =
            MmioTransport::new(memory.clone(), irq.clone(), net.clone(), None).unwrap();
        net.lock()
            .expect("actual net owner")
            .activate(
                memory.clone(),
                InterruptTransport::new(irq, "terminal-net".into(), None).unwrap(),
                vec![
                    DeviceQueue::new(
                        rx.create_queue(),
                        Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                    ),
                    DeviceQueue::new(
                        tx.create_queue(),
                        Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                    ),
                ],
            )
            .unwrap();
        assert_eq!(
            net.lock().expect("actual net owner").preflight(),
            Err(ProviderFault::Unsupported)
        );
        peer.write_all(&[0, 0, 0, 8, b'a', b'b']).unwrap();
        let stop = request();
        let mut peek = [0; 32];
        loop {
            match recv(
                observer.as_raw_fd(),
                &mut peek,
                MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
            ) {
                Err(nix::Error::EAGAIN) => break,
                Ok(_) => {
                    assert!(Instant::now() < stop.deadline);
                    std::thread::yield_now();
                }
                Err(error) => panic!("actual partial ingress observation failed: {error}"),
            }
        }
        assert!(transport.poll_stop(stop).unwrap().is_pending());
        while transport.poll_stop(stop).unwrap().is_pending() {
            assert!(
                Instant::now() < stop.deadline,
                "cold network owner was not reaped"
            );
            std::thread::yield_now();
        }
        assert_eq!(transport.lifecycle_snapshot().stage, ProviderStage::Stopped);
        assert!(transport.capture_device_state(stop.key).is_err());
        assert!(transport.capture_transport(stop.key).is_err());
        assert!(transport.poll_stop(stop).unwrap().is_ready());
        let net = net.lock().expect("actual net owner");
        assert!(net.worker.is_none());
        assert_eq!(net.lifecycle.snapshot.stage, ProviderStage::Stopped);
        let slot = net.slot.lock().expect("actual returned owner slot");
        let worker = slot
            .as_ref()
            .expect("terminal stop retains backend and queues");
        assert!(worker.state.fault.is_none());
        assert!(
            worker
                .state
                .admission
                .lock()
                .expect("actual admission")
                .stop
        );
        assert_eq!(worker.rx_q.queue.capture_state().unwrap().next_used, 0);
        assert_eq!(worker.tx_q.queue.capture_state().unwrap().next_used, 0);
        assert!(net.capture_payload(stop.key).is_err());
    }
}
