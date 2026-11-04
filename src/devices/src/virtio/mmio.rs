// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(feature = "native-device-probe")]
use std::collections::VecDeque;
#[cfg(feature = "native-device-probe")]
use std::sync::atomic::AtomicU64;

use std::fmt::{Display, Formatter};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::Poll;
use std::time::Instant;

use crate::virtio::lifecycle::{
    LifecycleError, LifecycleJournal, LifecycleSnapshot, ProviderFault, ProviderStage,
    QueueBinding, QueueEscrow, ResumeAcceptance,
};
use polly::event_manager::{BarrierKey, BarrierRequest};

use utils::eventfd::EFD_NONBLOCK;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

use crate::bus::BusDevice;
use crate::legacy::IrqChip;
use crate::virtio::*;
use utils::{byte_order, eventfd::EventFd};
use vm_memory::GuestAddress;

//TODO crosvm uses 0 here, but IIRC virtio specified some other vendor id that should be used
const VENDOR_ID: u32 = 0;

//required by the virtio mmio device register layout at offset 0 from base
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

//current version specified by the mmio standard (legacy devices used 1 here)
const MMIO_VERSION: u32 = 2;

#[derive(Debug)]
pub enum CreateMmioTransportError {
    CreateInterruptEventFd(io::Error),
}

impl Display for CreateMmioTransportError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            CreateMmioTransportError::CreateInterruptEventFd(err) => {
                write!(f, "failed to create interrupt eventfd: {err}")
            }
        }
    }
}

/// Internal exact transport record, not a persistent or compatibility codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmioTransportState {
    pub device_type: u32,
    pub device_name: String,
    pub attachment_address: u64,
    pub irq_line: Option<u32>,
    pub avail_features: u64,
    pub acked_features: u64,
    pub features_select: u32,
    pub acked_features_select: u32,
    pub queue_select: u32,
    pub device_status: u32,
    pub config_generation: u32,
    pub shm_region_select: u32,
    pub interrupt_status: u32,
    pub activated: bool,
    pub queues: Vec<QueueState>,
}

impl MmioTransportState {
    pub fn validate_payload_binding(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        let mut reader = utils::state::Reader::new(payload);
        let valid = (|| {
            Ok::<_, utils::state::Error>(
                reader.u16()? == 1
                    && reader.u32()? == self.device_type
                    && reader.u64()? == self.avail_features
                    && reader.u64()? == self.acked_features,
            )
        })()
        .map_err(|_| ProviderFault::DeviceState)?;
        if !valid || self.acked_features & !self.avail_features != 0 {
            return Err(ProviderFault::DeviceState);
        }
        Ok(())
    }
}

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
///    base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
///    is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioTransport {
    device: Arc<Mutex<dyn VirtioDevice>>,
    // The register where feature bits are stored.
    pub(crate) features_select: u32,
    // The register where features page is selected.
    pub(crate) acked_features_select: u32,
    pub(crate) queue_select: u32,
    pub(crate) device_status: u32,
    pub(crate) config_generation: u32,
    mem: RuntimeGuestMemory,
    // Queues owned by the transport during negotiation.
    // These are moved to the device on activation.
    queues: Option<Vec<Queue>>,
    // Queue eventfds - kept by transport to send notifications.
    // Arc clones are passed to the device on activation.
    queue_evts: Vec<Arc<EventFd>>,
    // Stored queue config from device for recreating queues after reset.
    queue_config: Vec<QueueConfig>,
    shm_region_select: u32,
    interrupt: InterruptTransport,
    attachment_address: Option<u64>,
    lifecycle: LifecycleJournal,
    escrow: QueueEscrow,
    quiesced_active: bool,
    stop_drain: Option<StopDrain>,
    #[cfg(feature = "native-device-probe")]
    irq_ack_hold: bool,
    #[cfg(feature = "native-device-probe")]
    held_irq_acks: VecDeque<u32>,
}
#[derive(Clone, Copy)]
struct StopDrain {
    provider_key: BarrierKey,
    complete: bool,
    reconcile_failure: bool,
    completion_fault: Option<ProviderFault>,
}

enum InterruptEvent {
    Exclusive(EventFd),
    Shared(Arc<EventFd>),
}

struct InterruptTransportInner {
    log_target: String,
    status: AtomicUsize,
    notification_failed: AtomicBool,
    event: InterruptEvent,
    intc: IrqChip,
    irq_line: Option<u32>,
    #[cfg(feature = "native-device-probe")]
    probe: IrqProbeCounters,
}

#[cfg(feature = "native-device-probe")]
const MAX_HELD_IRQ_ACKS: usize = 4096;

#[cfg(feature = "native-device-probe")]
#[derive(Default)]
struct IrqProbeCounters {
    signal_attempts: AtomicU64,
    signal_successes: AtomicU64,
    ack_writes: AtomicU64,
    ack_applied: AtomicU64,
    overflow: AtomicBool,
    // A delayed ACK may clear only causes not signalled again since a guest ACK.
    held_ack_mask: Mutex<u32>,
}

#[cfg(feature = "native-device-probe")]
impl IrqProbeCounters {
    fn lock_held_ack_mask(&self) -> MutexGuard<'_, u32> {
        match self.held_ack_mask.lock() {
            Ok(held) => held,
            Err(error) => {
                self.overflow.store(true, Ordering::SeqCst);
                let mut held = error.into_inner();
                // Cleanup may complete original writes, but poisoned ownership
                // must never authorize clearing a cause.
                *held = 0;
                held
            }
        }
    }

    fn increment(&self, counter: &AtomicU64) {
        if counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .is_err()
        {
            self.overflow.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(feature = "native-device-probe")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmioIrqProbeSnapshot {
    pub status: u32,
    pub signal_attempts: u64,
    /// Accepted native signal calls, not a native IRQ delivery counter.
    pub signal_successes: u64,
    pub ack_writes: u64,
    pub ack_applied: u64,
    pub held_acks: usize,
    pub ack_hold: bool,
    pub overflow: bool,
}

#[derive(Clone)]
pub struct InterruptTransport(Arc<InterruptTransportInner>);

impl InterruptTransport {
    pub fn new(
        intc: IrqChip,
        log_target: String,
        shared_event: Option<Arc<EventFd>>,
    ) -> Result<Self, CreateMmioTransportError> {
        Ok(Self(Arc::new(InterruptTransportInner {
            log_target,
            status: AtomicUsize::new(0),
            notification_failed: AtomicBool::new(false),
            event: match shared_event {
                Some(event) => InterruptEvent::Shared(event),
                None => InterruptEvent::Exclusive(
                    EventFd::new(0).map_err(CreateMmioTransportError::CreateInterruptEventFd)?,
                ),
            },
            intc,
            irq_line: None,
            #[cfg(feature = "native-device-probe")]
            probe: IrqProbeCounters::default(),
        })))
    }

    pub fn status(&self) -> &AtomicUsize {
        &self.0.status
    }

    pub fn event(&self) -> &EventFd {
        match &self.0.event {
            InterruptEvent::Exclusive(event) => event,
            InterruptEvent::Shared(event) => event,
        }
    }

    pub fn intc(&self) -> &IrqChip {
        &self.0.intc
    }

    pub fn irq_line(&self) -> Option<u32> {
        self.0.irq_line
    }

    fn set_irq_line(&mut self, irq_line: u32) {
        debug!(target: &self.0.log_target, "set_irq_line: {irq_line}");
        match Arc::get_mut(&mut self.0) {
            None => {
                error!("Cannot change irq_line of activated device");
            }
            Some(interrupt) => {
                interrupt.irq_line = Some(irq_line);
            }
        }
    }

    fn publish_cause(&self, status: u32) {
        #[cfg(feature = "native-device-probe")]
        {
            let mut held = self.0.probe.lock_held_ack_mask();
            *held &= !status;
            self.status().fetch_or(status as usize, Ordering::SeqCst);
        }
        #[cfg(not(feature = "native-device-probe"))]
        self.status().fetch_or(status as usize, Ordering::SeqCst);
    }

    fn try_signal(&self, status: u32) -> Result<(), crate::Error> {
        #[cfg(feature = "native-device-probe")]
        self.0.probe.increment(&self.0.probe.signal_attempts);
        self.publish_cause(status);
        let result = self
            .intc()
            .lock()
            .map_err(|_| crate::Error::IoError(io::Error::other("poisoned interrupt controller")))
            .and_then(|intc| intc.set_irq(self.0.irq_line, Some(self.event())));
        if result.is_err() {
            self.0.notification_failed.store(true, Ordering::SeqCst);
        }
        #[cfg(feature = "native-device-probe")]
        if result.is_ok() {
            self.0.probe.increment(&self.0.probe.signal_successes);
        }
        result
    }

    pub fn try_signal_used_queue(&self) -> Result<(), crate::Error> {
        debug!(target: &self.0.log_target, "interrupt: signal_used_queue");
        self.try_signal(VIRTIO_MMIO_INT_VRING)
    }

    pub fn try_signal_config_change(&self) -> Result<(), crate::Error> {
        debug!(target: &self.0.log_target, "interrupt: signal_config_change");
        self.try_signal(VIRTIO_MMIO_INT_CONFIG)
    }

    pub fn signal_used_queue(&self) {
        if let Err(e) = self.try_signal_used_queue() {
            warn!(target: &self.0.log_target, "Failed to signal used queue: {e:?}");
        }
    }

    pub fn signal_config_change(&self) {
        if let Err(e) = self.try_signal_config_change() {
            warn!(target: &self.0.log_target, "Failed to signal config change: {e:?}");
        }
    }
}

impl MmioTransport {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new<M: Into<RuntimeGuestMemory>>(
        mem: M,
        intc: IrqChip,
        device: Arc<Mutex<dyn VirtioDevice>>,
        shared_interrupt_event: Option<Arc<EventFd>>,
    ) -> Result<MmioTransport, CreateMmioTransportError> {
        let locked = device
            .try_lock()
            .expect("Mutex of VirtioDevice should not be locked when calling MmioTransport::new");

        let debug_log_target = format!("{}[{}]", module_path!(), locked.device_name());
        let queue_config: Vec<QueueConfig> = locked.queue_config().to_vec();
        drop(locked);

        let queues = Self::create_queues(&queue_config);
        let queue_evts = Self::create_queue_evts(queue_config.len())?;

        let bindings = queues
            .iter()
            .zip(&queue_evts)
            .map(|(queue, event)| QueueBinding::new(queue, event))
            .collect();
        Ok(MmioTransport {
            interrupt: InterruptTransport::new(intc, debug_log_target, shared_interrupt_event)?,
            device,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            device_status: device_status::INIT,
            config_generation: 0,
            mem: mem.into(),
            queues: Some(queues),
            queue_evts,
            queue_config,
            shm_region_select: 0,
            attachment_address: None,
            lifecycle: LifecycleJournal::new(),
            escrow: QueueEscrow::new(bindings),
            quiesced_active: false,
            stop_drain: None,
            #[cfg(feature = "native-device-probe")]
            irq_ack_hold: false,
            #[cfg(feature = "native-device-probe")]
            held_irq_acks: VecDeque::with_capacity(MAX_HELD_IRQ_ACKS),
        })
    }

    /// Create queues from queue configuration.
    fn create_queues(queue_config: &[QueueConfig]) -> Vec<Queue> {
        queue_config.iter().map(|c| Queue::new(c.size)).collect()
    }

    /// Create eventfds for queue notifications.
    fn create_queue_evts(count: usize) -> Result<Vec<Arc<EventFd>>, CreateMmioTransportError> {
        let mut queue_evts = Vec::with_capacity(count);
        for _ in 0..count {
            queue_evts.push(Arc::new(
                EventFd::new(EFD_NONBLOCK)
                    .map_err(CreateMmioTransportError::CreateInterruptEventFd)?,
            ));
        }
        Ok(queue_evts)
    }

    /// Set the irq line for the device.
    /// NOTE: Can only be called when the device is not activated
    pub fn set_irq_line(&mut self, irq_line: u32) {
        self.interrupt.set_irq_line(irq_line);
    }

    pub fn interrupt_evt(&self) -> &EventFd {
        self.interrupt.event()
    }

    pub fn locked_device(&self) -> MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned device lock")
    }

    // Gets the encapsulated VirtioDevice.
    pub fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    /// Returns a reference to the queue eventfds. Used by the VMM to register
    /// queue notifications with KVM.
    pub fn queue_evts(&self) -> &[Arc<EventFd>] {
        &self.queue_evts
    }

    pub fn set_attachment_address(&mut self, address: u64) -> Result<(), ProviderFault> {
        if self.attachment_address.is_some() || self.lifecycle.snapshot.request.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.attachment_address = Some(address);
        Ok(())
    }

    pub fn lifecycle_snapshot(&self) -> LifecycleSnapshot {
        self.lifecycle.snapshot
    }

    pub fn interrupt_transport(&self) -> &InterruptTransport {
        &self.interrupt
    }

    #[cfg(feature = "native-device-probe")]
    pub fn diagnostic_irq_snapshot(&self) -> MmioIrqProbeSnapshot {
        let probe = &self.interrupt.0.probe;
        MmioIrqProbeSnapshot {
            status: self.interrupt.status().load(Ordering::SeqCst) as u32,
            signal_attempts: probe.signal_attempts.load(Ordering::SeqCst),
            signal_successes: probe.signal_successes.load(Ordering::SeqCst),
            ack_writes: probe.ack_writes.load(Ordering::SeqCst),
            ack_applied: probe.ack_applied.load(Ordering::SeqCst),
            held_acks: self.held_irq_acks.len(),
            ack_hold: self.irq_ack_hold,
            overflow: probe.overflow.load(Ordering::SeqCst),
        }
    }

    #[cfg(feature = "native-device-probe")]
    fn diagnostic_apply_irq_ack(&self, value: u32) {
        self.interrupt
            .status()
            .fetch_and(!(value as usize), Ordering::SeqCst);
        self.interrupt
            .0
            .probe
            .increment(&self.interrupt.0.probe.ack_applied);
    }

    #[cfg(feature = "native-device-probe")]
    fn diagnostic_apply_held_irq_ack(&self, value: u32) {
        let mut held = self.interrupt.0.probe.lock_held_ack_mask();
        self.diagnostic_apply_irq_ack(value & *held);
        *held &= !value;
    }

    #[cfg(feature = "native-device-probe")]
    pub fn diagnostic_hold_irq_acks(&mut self, hold: bool) -> Result<(), ProviderFault> {
        if hold && self.interrupt.0.probe.overflow.load(Ordering::SeqCst) {
            return Err(ProviderFault::DeviceState);
        }
        if hold && self.lifecycle.snapshot.stage != ProviderStage::Running {
            return Err(ProviderFault::InvalidTransition);
        }
        self.irq_ack_hold = hold;
        if !hold {
            while let Some(value) = self.held_irq_acks.pop_front() {
                self.diagnostic_apply_held_irq_ack(value);
            }
        }
        if self.interrupt.0.probe.overflow.load(Ordering::SeqCst) {
            return Err(ProviderFault::DeviceState);
        }
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    fn diagnostic_observe_irq_ack(&mut self, value: u32) {
        self.interrupt
            .0
            .probe
            .increment(&self.interrupt.0.probe.ack_writes);
        if self.irq_ack_hold && self.held_irq_acks.len() < MAX_HELD_IRQ_ACKS {
            *self.interrupt.0.probe.lock_held_ack_mask() |= value;
            self.held_irq_acks.push_back(value);
            return;
        }
        if self.irq_ack_hold {
            *self.interrupt.0.probe.lock_held_ack_mask() |= value;
            self.interrupt
                .0
                .probe
                .overflow
                .store(true, Ordering::SeqCst);
            self.irq_ack_hold = false;
            while let Some(pending) = self.held_irq_acks.pop_front() {
                self.diagnostic_apply_held_irq_ack(pending);
            }
            self.diagnostic_apply_held_irq_ack(value);
            return;
        }
        self.diagnostic_apply_irq_ack(value);
    }

    pub fn preflight_quiesce(&self) -> Result<(), ProviderFault> {
        #[cfg(feature = "native-device-probe")]
        if !self.held_irq_acks.is_empty() || self.interrupt.0.probe.overflow.load(Ordering::SeqCst)
        {
            return Err(ProviderFault::DeviceState);
        }
        if self.attachment_address.is_none() {
            return Err(ProviderFault::Unsupported);
        }
        if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
            return Err(ProviderFault::Notification);
        }
        let device = self.device.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => ProviderFault::LockBusy,
            TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
        })?;
        let provider = device.state_provider().ok_or(ProviderFault::Unsupported)?;
        if device.shm_region().is_some() {
            return Err(ProviderFault::Unsupported);
        }
        provider.preflight()
    }

    pub fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), LifecycleError> {
        self.begin_quiesce_inner(request, true)
    }

    fn begin_quiesce_inner(
        &mut self,
        request: BarrierRequest,
        preflight: bool,
    ) -> Result<(), LifecycleError> {
        if self.lifecycle.snapshot.stage != ProviderStage::Running
            && (preflight || self.lifecycle.snapshot.stage != ProviderStage::Resuming)
            || (preflight
                && self.lifecycle.snapshot.accepted
                && self.lifecycle.snapshot.failure.is_some())
            || self
                .lifecycle
                .snapshot
                .request
                .is_some_and(|previous| previous.key == request.key)
        {
            return Err(self
                .lifecycle
                .error(request.key, ProviderFault::InvalidTransition));
        }
        if preflight {
            self.preflight_quiesce()
                .map_err(|fault| self.lifecycle.error(request.key, fault))?;
        }
        if Instant::now() >= request.deadline {
            return Err(self.lifecycle.error(request.key, ProviderFault::Deadline));
        }
        let device = Arc::clone(&self.device);
        let mut locked = device.try_lock().map_err(|error| {
            self.lifecycle.error(
                request.key,
                match error {
                    TryLockError::WouldBlock => ProviderFault::LockBusy,
                    TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
                },
            )
        })?;
        self.quiesced_active = locked.is_activated();
        let provider = locked.state_provider_mut().ok_or_else(|| {
            self.lifecycle
                .error(request.key, ProviderFault::Unsupported)
        })?;
        // The journal precedes the provider call, including a delivered command
        // whose subsequent worker wake fails.
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        match provider.begin_quiesce(request) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.lifecycle.snapshot.accepted = error.accepted;
                self.lifecycle.snapshot.quiesce_accepted = error.accepted;
                if !error.accepted {
                    self.lifecycle.snapshot.stage = ProviderStage::Running;
                }
                Err(self.lifecycle.fail(request.key, error.fault))
            }
        }
    }

    pub fn poll_stop(&mut self, request: BarrierRequest) -> Result<Poll<()>, LifecycleError> {
        #[cfg(feature = "native-device-probe")]
        {
            // Terminal cleanup completes original callbacks even if the
            // diagnostic sample overflowed; it does not certify a coherent cut.
            let _ = self.diagnostic_hold_irq_acks(false);
        }
        let snapshot = self.lifecycle.snapshot;
        if matches!(
            snapshot.stage,
            ProviderStage::Stopping | ProviderStage::Stopped
        ) {
            return self.poll_terminal_stop(request);
        }
        if Instant::now() >= request.deadline {
            return Err(self.lifecycle.error(request.key, ProviderFault::Deadline));
        }
        let device = Arc::clone(&self.device);
        let mut locked = match device.try_lock() {
            Ok(locked) => locked,
            Err(TryLockError::WouldBlock) => return Ok(Poll::Pending),
            Err(TryLockError::Poisoned(_)) => {
                return Err(self.lifecycle.error(request.key, ProviderFault::DeviceLock));
            }
        };
        if let Some(provider) = locked.state_provider_mut() {
            // Journal before the provider can accept any irreversible effect.
            self.lifecycle.begin(request, ProviderStage::Stopping);
            match provider.begin_terminal_stop(request) {
                Ok(()) => return Ok(Poll::Pending),
                Err(error) if !error.accepted && error.fault == ProviderFault::Unsupported => {
                    self.lifecycle.snapshot = snapshot;
                }
                Err(error) => {
                    self.lifecycle.snapshot.accepted = error.accepted;
                    return Err(self.lifecycle.fail(request.key, error.fault));
                }
            }
        }
        let supported = locked
            .state_provider()
            .is_some_and(|provider| provider.preflight() != Err(ProviderFault::Unsupported));
        if !supported {
            self.lifecycle.begin(request, ProviderStage::Stopping);
            // Inactive devices have no worker-owned queues to reset. Active
            // legacy devices must explicitly acknowledge their existing reset.
            if locked.is_activated() && !locked.reset() {
                return Err(self.lifecycle.fail(request.key, ProviderFault::Unsupported));
            }
            self.lifecycle.expired(Instant::now());
            self.lifecycle.snapshot.stage = ProviderStage::Stopped;
            return match self.lifecycle.snapshot.failure {
                Some(error) => Err(error),
                None => Ok(Poll::Ready(())),
            };
        }
        drop(locked);
        match snapshot.stage {
            ProviderStage::Running | ProviderStage::Resuming => {
                self.begin_quiesce_inner(request, false)?;
                self.begin_terminal_drain(request)?;
                Ok(Poll::Pending)
            }
            ProviderStage::Quiescing | ProviderStage::Quiesced => {
                self.begin_terminal_drain(request)?;
                self.poll_terminal_drain(request)
            }
            ProviderStage::Stopping | ProviderStage::Stopped => Err(self
                .lifecycle
                .error(request.key, ProviderFault::InvalidTransition)),
        }
    }

    fn begin_terminal_drain(&mut self, request: BarrierRequest) -> Result<(), LifecycleError> {
        let snapshot = self.lifecycle.snapshot;
        let original = snapshot.request.ok_or_else(|| {
            self.lifecycle
                .error(request.key, ProviderFault::ForeignBarrier)
        })?;
        if original.key == request.key && original != request {
            return Err(self
                .lifecycle
                .error(request.key, ProviderFault::ForeignBarrier));
        }
        let same_request = original.key == request.key;
        self.stop_drain = Some(StopDrain {
            provider_key: original.key,
            complete: snapshot.stage == ProviderStage::Quiesced,
            reconcile_failure: !same_request && snapshot.failure.is_some(),
            completion_fault: None,
        });
        self.lifecycle.begin(request, ProviderStage::Stopping);
        if same_request {
            self.lifecycle.snapshot.failure = snapshot.failure;
        }
        Ok(())
    }

    fn poll_terminal_drain(&mut self, request: BarrierRequest) -> Result<Poll<()>, LifecycleError> {
        self.lifecycle.expired(Instant::now());
        let mut drain = self.stop_drain.ok_or_else(|| {
            self.lifecycle
                .error(request.key, ProviderFault::InvalidTransition)
        })?;
        let device = Arc::clone(&self.device);
        let mut locked = match device.try_lock() {
            Ok(locked) => locked,
            Err(TryLockError::WouldBlock) => {
                return self
                    .lifecycle
                    .snapshot
                    .failure
                    .map_or(Ok(Poll::Pending), Err);
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(self.lifecycle.fail(request.key, ProviderFault::DeviceLock));
            }
        };
        let provider = locked
            .state_provider_mut()
            .ok_or_else(|| self.lifecycle.fail(request.key, ProviderFault::Unsupported))?;
        if !drain.complete {
            // Poll the original accepted owner, not its first-failure journal.
            // Every fresh poll error belongs to this stop, even if its kind
            // happens to equal the historical command/wake failure.
            match provider.poll_quiesce(drain.provider_key) {
                Ok(Poll::Pending) => {}
                Ok(Poll::Ready(completion)) => {
                    let returned = if self.quiesced_active {
                        self.escrow.receive(completion.queues, &self.mem)
                    } else if completion.queues.is_empty() {
                        Ok(())
                    } else {
                        self.escrow
                            .receive(completion.queues, &self.mem)
                            .and(Err(ProviderFault::QueueCount))
                    };
                    if let Err(fault) = returned {
                        self.lifecycle.fail(request.key, fault);
                    }
                    drain.complete = true;
                    drain.completion_fault = completion.fault;
                    self.stop_drain = Some(drain);
                }
                Err(fault) => {
                    self.lifecycle.fail(request.key, fault);
                }
            }
        }
        let mut pending = !drain.complete;
        let mut clean = true;
        if drain.complete {
            if drain.reconcile_failure
                || (drain.provider_key != request.key && drain.completion_fault.is_some())
            {
                // A provider must independently prove real cleanup before a
                // historical operation failure can remain history only.
                match provider.validate_terminal_drain(drain.provider_key) {
                    Ok(()) => {
                        if let Some(fault) = drain.completion_fault {
                            self.lifecycle.snapshot.previous_failure.get_or_insert(
                                LifecycleError {
                                    key: drain.provider_key,
                                    stage: ProviderStage::Quiescing,
                                    accepted: true,
                                    fault,
                                },
                            );
                        }
                    }
                    Err(ProviderFault::LockBusy) => pending = true,
                    Err(fault) => {
                        self.lifecycle.fail(request.key, fault);
                        clean = false;
                    }
                }
            } else if let Some(fault) = drain.completion_fault {
                self.lifecycle.fail(request.key, fault);
                clean = false;
            }
            let retained = if self.quiesced_active {
                self.escrow.validate_retained(&self.mem)
            } else {
                self.queues
                    .as_ref()
                    .ok_or(ProviderFault::QueueCount)
                    .and_then(|queues| {
                        for queue in queues {
                            let state = queue
                                .capture_state()
                                .map_err(|_| ProviderFault::QueueState)?;
                            queue
                                .validate_state(&self.mem, &state)
                                .map_err(|_| ProviderFault::QueueState)?;
                        }
                        Ok(())
                    })
            };
            if let Err(fault) = retained {
                self.lifecycle.fail(request.key, fault);
                clean = false;
            }
        }
        if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
            self.lifecycle
                .fail(request.key, ProviderFault::Notification);
            clean = false;
        }
        self.lifecycle.expired(Instant::now());
        if !pending && clean {
            self.lifecycle.snapshot.stage = ProviderStage::Stopped;
        }
        match self.lifecycle.snapshot.failure {
            Some(error) => Err(error),
            None => Ok(if pending {
                Poll::Pending
            } else {
                Poll::Ready(())
            }),
        }
    }

    fn poll_terminal_stop(&mut self, request: BarrierRequest) -> Result<Poll<()>, LifecycleError> {
        if self.lifecycle.check(request.key)? != request {
            return Err(self
                .lifecycle
                .error(request.key, ProviderFault::ForeignBarrier));
        }
        if self.lifecycle.snapshot.stage == ProviderStage::Stopped {
            return match self.lifecycle.snapshot.failure {
                Some(error) => Err(error),
                None => Ok(Poll::Ready(())),
            };
        }
        if !self.lifecycle.snapshot.accepted {
            return Err(self.lifecycle.snapshot.failure.unwrap_or_else(|| {
                self.lifecycle
                    .error(request.key, ProviderFault::InvalidTransition)
            }));
        }
        if self.stop_drain.is_some() {
            return self.poll_terminal_drain(request);
        }
        self.lifecycle.expired(Instant::now());
        let device = Arc::clone(&self.device);
        let mut locked = match device.try_lock() {
            Ok(locked) => locked,
            Err(TryLockError::WouldBlock) => {
                return match self.lifecycle.snapshot.failure {
                    Some(error) => Err(error),
                    None => Ok(Poll::Pending),
                };
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(self.lifecycle.fail(request.key, ProviderFault::DeviceLock));
            }
        };
        let result = match locked.state_provider_mut() {
            Some(provider) => provider.poll_terminal_stop(request.key),
            None => Err(ProviderFault::Unsupported),
        };
        match result {
            Ok(Poll::Ready(())) => self.lifecycle.snapshot.stage = ProviderStage::Stopped,
            Ok(Poll::Pending) => {}
            Err(fault) => {
                self.lifecycle.fail(request.key, fault);
            }
        }
        if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
            self.lifecycle
                .fail(request.key, ProviderFault::Notification);
        }
        self.lifecycle.expired(Instant::now());
        match self.lifecycle.snapshot.failure {
            Some(error) => Err(error),
            None => result.map_err(|fault| self.lifecycle.error(request.key, fault)),
        }
    }

    pub fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<()>, LifecycleError> {
        self.lifecycle.check(key)?;
        if !matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Quiescing | ProviderStage::Quiesced
        ) {
            return Err(self.lifecycle.error(key, ProviderFault::InvalidTransition));
        }
        if self.lifecycle.snapshot.stage == ProviderStage::Quiescing {
            // Expiration is not cancellation: continue accepting late ownership.
            self.lifecycle.expired(Instant::now());
            let device = Arc::clone(&self.device);
            let mut locked = match device.try_lock() {
                Ok(locked) => locked,
                Err(TryLockError::WouldBlock) => return Ok(Poll::Pending),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(self.lifecycle.error(key, ProviderFault::DeviceLock));
                }
            };
            let provider = locked
                .state_provider_mut()
                .ok_or_else(|| self.lifecycle.error(key, ProviderFault::Unsupported))?;
            match provider.poll_quiesce(key) {
                Ok(Poll::Pending) => {}
                Ok(Poll::Ready(completion)) => {
                    let result = if self.quiesced_active {
                        self.escrow.receive(completion.queues, &self.mem)
                    } else {
                        // Inactive queues never left the transport. A provider
                        // returning any queue here is still retained in escrow.
                        if completion.queues.is_empty() {
                            Ok(())
                        } else {
                            self.escrow
                                .receive(completion.queues, &self.mem)
                                .and(Err(ProviderFault::QueueCount))
                        }
                    };
                    if let Err(fault) = result {
                        self.lifecycle.fail(key, fault);
                    }
                    if let Some(fault) = completion.fault {
                        self.lifecycle.fail(key, fault);
                    }
                    self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
                }
                Err(fault) => {
                    self.lifecycle.fail(key, fault);
                }
            }
            self.lifecycle.expired(Instant::now());
        }
        if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
            self.lifecycle.fail(key, ProviderFault::Notification);
        }
        if let Some(error) = self.lifecycle.snapshot.failure {
            return Err(error);
        }
        Ok(
            if self.lifecycle.snapshot.stage == ProviderStage::Quiesced {
                Poll::Ready(())
            } else {
                Poll::Pending
            },
        )
    }

    pub fn begin_resume(&mut self, request: BarrierRequest) -> Result<(), LifecycleError> {
        let snapshot = self.lifecycle.snapshot;
        if snapshot.stage != ProviderStage::Quiesced
            || snapshot.request.is_none_or(|previous| {
                previous.key.generation != request.key.generation || previous.key == request.key
            })
        {
            return Err(self
                .lifecycle
                .error(request.key, ProviderFault::InvalidTransition));
        }
        if Instant::now() >= request.deadline {
            return Err(self.lifecycle.error(request.key, ProviderFault::Deadline));
        }
        if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
            return Err(self
                .lifecycle
                .error(request.key, ProviderFault::Notification));
        }
        let device = Arc::clone(&self.device);
        let mut locked = device.try_lock().map_err(|error| {
            self.lifecycle.error(
                request.key,
                match error {
                    TryLockError::WouldBlock => ProviderFault::LockBusy,
                    TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
                },
            )
        })?;
        let provider = locked.state_provider_mut().ok_or_else(|| {
            self.lifecycle
                .error(request.key, ProviderFault::Unsupported)
        })?;
        let queues = if self.quiesced_active {
            self.escrow
                .take_for_resume()
                .map_err(|fault| self.lifecycle.error(request.key, fault))?
        } else {
            Vec::new()
        };
        self.lifecycle.begin(request, ProviderStage::Resuming);
        match provider.begin_resume(request, queues) {
            ResumeAcceptance::Accepted => Ok(()),
            ResumeAcceptance::AcceptedWithFailure(fault) => {
                Err(self.lifecycle.fail(request.key, fault))
            }
            ResumeAcceptance::Rejected { queues, fault } => {
                if self.quiesced_active {
                    if let Err(return_fault) = self.escrow.receive(queues, &self.mem) {
                        self.lifecycle.fail(request.key, return_fault);
                    }
                } else if !queues.is_empty() {
                    let _ = self.escrow.receive(queues, &self.mem);
                    self.lifecycle.fail(request.key, ProviderFault::QueueCount);
                }
                self.lifecycle.snapshot.accepted = false;
                self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
                Err(self.lifecycle.fail(request.key, fault))
            }
        }
    }

    pub fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, LifecycleError> {
        self.lifecycle.check(key)?;
        if self.lifecycle.snapshot.stage == ProviderStage::Running
            && self.lifecycle.snapshot.accepted
        {
            // A completed same-key acknowledgement is terminal, even while peers
            // are still pending. Preserve its existing late/fault outcome and
            // current IRQ fault without re-running the provider or its queues.
            if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
                self.lifecycle.fail(key, ProviderFault::Notification);
            }
            return match self.lifecycle.snapshot.failure {
                Some(error) => Err(error),
                None => Ok(Poll::Ready(())),
            };
        }
        if self.lifecycle.snapshot.stage != ProviderStage::Resuming {
            return Err(self.lifecycle.error(key, ProviderFault::InvalidTransition));
        }
        self.lifecycle.expired(Instant::now());
        let device = Arc::clone(&self.device);
        let mut locked = match device.try_lock() {
            Ok(locked) => locked,
            Err(TryLockError::WouldBlock) => return Ok(Poll::Pending),
            Err(TryLockError::Poisoned(_)) => {
                return Err(self.lifecycle.error(key, ProviderFault::DeviceLock));
            }
        };
        let provider = locked
            .state_provider_mut()
            .ok_or_else(|| self.lifecycle.error(key, ProviderFault::Unsupported))?;
        let result = provider.poll_resume(key);
        if let Err(fault) = result {
            self.lifecycle.fail(key, fault);
        }
        if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
            self.lifecycle.fail(key, ProviderFault::Notification);
        }
        self.lifecycle.expired(Instant::now());
        if matches!(result, Ok(Poll::Ready(()))) {
            // Late running acknowledgement is recorded, never backdated.
            self.lifecycle.snapshot.stage = ProviderStage::Running;
        }
        if let Some(error) = self.lifecycle.snapshot.failure {
            return Err(error);
        }
        result.map_err(|fault| self.lifecycle.error(key, fault))
    }

    /// Serialize the retained terminal cut, not admission of running workers.
    pub fn capture_transport(&self, key: BarrierKey) -> Result<MmioTransportState, LifecycleError> {
        self.lifecycle.check(key)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced {
            return Err(self.lifecycle.error(key, ProviderFault::InvalidTransition));
        }
        #[cfg(feature = "native-device-probe")]
        if !self.held_irq_acks.is_empty() || self.interrupt.0.probe.overflow.load(Ordering::SeqCst)
        {
            return Err(self.lifecycle.error(key, ProviderFault::DeviceState));
        }
        if let Some(error) = self.lifecycle.snapshot.failure {
            return Err(error);
        }
        if self.interrupt.0.notification_failed.load(Ordering::SeqCst) {
            return Err(self.lifecycle.error(key, ProviderFault::Notification));
        }
        let device = self.device.try_lock().map_err(|error| {
            self.lifecycle.error(
                key,
                match error {
                    TryLockError::WouldBlock => ProviderFault::LockBusy,
                    TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
                },
            )
        })?;
        if device.shm_region().is_some() {
            return Err(self.lifecycle.error(key, ProviderFault::Unsupported));
        }
        let queues = if self.quiesced_active {
            self.escrow.states()
        } else {
            self.queues
                .as_ref()
                .ok_or(ProviderFault::QueueCount)
                .and_then(|queues| {
                    queues
                        .iter()
                        .map(|queue| queue.capture_state().map_err(|_| ProviderFault::QueueState))
                        .collect()
                })
        }
        .map_err(|fault| self.lifecycle.error(key, fault))?;
        let state = MmioTransportState {
            device_type: device.device_type(),
            device_name: device.device_name().to_owned(),
            attachment_address: self
                .attachment_address
                .ok_or_else(|| self.lifecycle.error(key, ProviderFault::DeviceState))?,
            irq_line: self.interrupt.irq_line(),
            avail_features: device.avail_features(),
            acked_features: device.acked_features(),
            features_select: self.features_select,
            acked_features_select: self.acked_features_select,
            queue_select: self.queue_select,
            device_status: self.device_status,
            config_generation: self.config_generation,
            shm_region_select: self.shm_region_select,
            interrupt_status: self.interrupt.status().load(Ordering::SeqCst) as u32,
            activated: self.quiesced_active,
            queues,
        };
        drop(device);
        self.validate_transport(&state)
            .map_err(|fault| self.lifecycle.error(key, fault))?;
        Ok(state)
    }

    pub fn validate_transport(&self, state: &MmioTransportState) -> Result<(), ProviderFault> {
        self.validate_transport_install(state, false)
    }

    fn validate_transport_install(
        &self,
        state: &MmioTransportState,
        restoring: bool,
    ) -> Result<(), ProviderFault> {
        let device = self.device.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => ProviderFault::LockBusy,
            TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
        })?;
        if state.device_type != device.device_type()
            || state.device_name != device.device_name()
            || Some(state.attachment_address) != self.attachment_address
            || state.irq_line != self.interrupt.irq_line()
            || state.avail_features != device.avail_features()
            || state.acked_features & !state.avail_features != 0
            || state.interrupt_status & !(VIRTIO_MMIO_INT_VRING | VIRTIO_MMIO_INT_CONFIG) != 0
            || device.shm_region().is_some()
            || state.device_status
                & !(device_status::ACKNOWLEDGE
                    | device_status::DRIVER
                    | device_status::FEATURES_OK
                    | device_status::DRIVER_OK
                    | device_status::FAILED)
                != 0
            || state.activated != (state.device_status & device_status::DRIVER_OK != 0)
            || (!restoring && state.activated != self.quiesced_active)
        {
            return Err(ProviderFault::DeviceState);
        }
        let base = state.device_status & !device_status::FAILED;
        if !matches!(base, 0 | 1 | 3 | 11 | 15) {
            return Err(ProviderFault::DeviceState);
        }
        let count = if let Some(returned) = &self.escrow.returned {
            if !self.escrow.validated || self.escrow.rejected.is_some() {
                return Err(ProviderFault::QueueState);
            }
            returned.len()
        } else {
            self.queues.as_ref().ok_or(ProviderFault::QueueCount)?.len()
        };
        if count != state.queues.len() || count != self.queue_config.len() {
            return Err(ProviderFault::QueueCount);
        }
        let event_idx = state.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX) != 0;
        for (index, saved) in state.queues.iter().enumerate() {
            let queue = self
                .escrow
                .returned
                .as_ref()
                .and_then(|queues| queues.get(index).map(|queue| &queue.queue))
                .or_else(|| self.queues.as_ref().and_then(|queues| queues.get(index)))
                .ok_or(ProviderFault::QueueCount)?;
            queue
                .capture_state()
                .map_err(|_| ProviderFault::QueueState)?;
            queue
                .validate_state(&self.mem, saved)
                .map_err(|_| ProviderFault::QueueState)?;
            if saved.event_idx_enabled != (state.activated && event_idx) {
                return Err(ProviderFault::QueueState);
            }
        }
        Ok(())
    }

    pub fn apply_transport(&mut self, state: &MmioTransportState) -> Result<(), ProviderFault> {
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced
            || self.lifecycle.snapshot.failure.is_some()
        {
            return Err(ProviderFault::InvalidTransition);
        }
        self.validate_transport(state)?;
        let device = Arc::clone(&self.device);
        let mut locked = device.try_lock().map_err(|_| ProviderFault::DeviceLock)?;
        locked.set_acked_features(state.acked_features);
        if let Some(queues) = &mut self.escrow.returned {
            for (queue, saved) in queues.iter_mut().zip(&state.queues) {
                queue.queue.apply_state(saved);
            }
        } else if let Some(queues) = &mut self.queues {
            for (queue, saved) in queues.iter_mut().zip(&state.queues) {
                queue.apply_state(saved);
            }
        }
        self.features_select = state.features_select;
        self.acked_features_select = state.acked_features_select;
        self.queue_select = state.queue_select;
        self.device_status = state.device_status;
        self.config_generation = state.config_generation;
        self.shm_region_select = state.shm_region_select;
        self.interrupt
            .status()
            .store(state.interrupt_status as usize, Ordering::SeqCst);
        self.quiesced_active = state.activated;
        Ok(())
    }

    pub fn flush_for_capture(&self, key: BarrierKey) -> Result<(), LifecycleError> {
        self.capture_transport(key)?;
        let device = self
            .device
            .try_lock()
            .map_err(|_| self.lifecycle.error(key, ProviderFault::DeviceLock))?;
        let provider = device
            .state_provider()
            .ok_or_else(|| self.lifecycle.error(key, ProviderFault::Unsupported))?;
        provider
            .flush_for_capture(key)
            .map_err(|fault| self.lifecycle.error(key, fault))
    }

    pub fn capture_device_state(&self, key: BarrierKey) -> Result<Vec<u8>, LifecycleError> {
        self.lifecycle.check(key)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced {
            return Err(self.lifecycle.error(key, ProviderFault::InvalidTransition));
        }
        if let Some(error) = self.lifecycle.snapshot.failure {
            return Err(error);
        }
        let state = self.capture_transport(key)?;
        let device = self.device.try_lock().map_err(|error| {
            self.lifecycle.error(
                key,
                match error {
                    TryLockError::WouldBlock => ProviderFault::LockBusy,
                    TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
                },
            )
        })?;
        let provider = device
            .state_provider()
            .ok_or_else(|| self.lifecycle.error(key, ProviderFault::Unsupported))?;
        let payload = provider
            .capture_payload(key)
            .map_err(|fault| self.lifecycle.error(key, fault))?;
        if payload.len() > provider.state_limit() as usize {
            return Err(self.lifecycle.error(key, ProviderFault::DeviceState));
        }
        provider
            .validate_payload(&payload)
            .map_err(|fault| self.lifecycle.error(key, fault))?;
        state
            .validate_payload_binding(&payload)
            .map_err(|fault| self.lifecycle.error(key, fault))?;
        Ok(payload)
    }

    pub fn validate_device_state(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        let device = self
            .device
            .try_lock()
            .map_err(|_| ProviderFault::DeviceLock)?;
        let provider = device.state_provider().ok_or(ProviderFault::Unsupported)?;
        if payload.len() > provider.state_limit() as usize {
            return Err(ProviderFault::DeviceState);
        }
        provider.validate_payload(payload)
    }

    pub fn apply_device_state(
        &mut self,
        key: BarrierKey,
        payload: &[u8],
    ) -> Result<(), LifecycleError> {
        self.lifecycle.check(key)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced {
            return Err(self.lifecycle.error(key, ProviderFault::InvalidTransition));
        }
        if let Some(error) = self.lifecycle.snapshot.failure {
            return Err(error);
        }
        self.validate_device_state(payload)
            .map_err(|fault| self.lifecycle.error(key, fault))?;
        let device = Arc::clone(&self.device);
        let mut locked = device
            .try_lock()
            .map_err(|_| self.lifecycle.error(key, ProviderFault::DeviceLock))?;
        let provider = locked
            .state_provider_mut()
            .ok_or_else(|| self.lifecycle.error(key, ProviderFault::Unsupported))?;
        provider
            .apply_payload(payload)
            .map_err(|fault| self.lifecycle.fail(key, fault))
    }

    pub fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        state: &MmioTransportState,
        payload: &[u8],
    ) -> Result<(), LifecycleError> {
        if self.lifecycle.snapshot.request.is_some() || self.locked_device().is_activated() {
            return Err(self
                .lifecycle
                .error(request.key, ProviderFault::InvalidTransition));
        }
        self.validate_transport_install(state, true)
            .map_err(|fault| self.lifecycle.error(request.key, fault))?;
        state
            .validate_payload_binding(payload)
            .map_err(|fault| self.lifecycle.error(request.key, fault))?;
        self.validate_device_state(payload)
            .map_err(|fault| self.lifecycle.error(request.key, fault))?;
        let device = self.device.clone();
        let mut device = device
            .try_lock()
            .map_err(|_| self.lifecycle.error(request.key, ProviderFault::DeviceLock))?;
        device.set_acked_features(state.acked_features);
        let provider = device.state_provider_mut().ok_or_else(|| {
            self.lifecycle
                .error(request.key, ProviderFault::Unsupported)
        })?;
        provider
            .validate_restore(payload)
            .map_err(|fault| self.lifecycle.error(request.key, fault))?;
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        provider
            .prepare_restore(
                request,
                payload,
                crate::virtio::lifecycle::DormantDeviceContext {
                    memory: self.mem.clone(),
                    interrupt: self.interrupt.clone(),
                    activated: state.activated,
                    reclaim_policy: crate::virtio::lifecycle::RestoredReclaimPolicy::Disabled,
                },
            )
            .map_err(|fault| self.lifecycle.fail(request.key, fault))?;
        drop(device);
        self.quiesced_active = state.activated;
        if state.activated {
            let queues = self
                .queues
                .take()
                .ok_or_else(|| self.lifecycle.fail(request.key, ProviderFault::QueueCount))?;
            let queues = queues
                .into_iter()
                .zip(&self.queue_evts)
                .zip(&state.queues)
                .map(|((mut queue, event), saved)| {
                    queue.apply_state(saved);
                    crate::virtio::device::DeviceQueue {
                        queue,
                        event: event.clone(),
                    }
                })
                .collect();
            self.escrow
                .receive(queues, &self.mem)
                .map_err(|fault| self.lifecycle.fail(request.key, fault))?;
        }
        self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
        self.apply_transport(state)
            .map_err(|fault| self.lifecycle.fail(request.key, fault))
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match &self.queues {
            Some(queues) => match queues.get(self.queue_select as usize) {
                Some(queue) => f(queue),
                None => d,
            },
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        match &mut self.queues {
            Some(queues) => {
                if let Some(queue) = queues.get_mut(self.queue_select as usize) {
                    f(queue);
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        if self.check_device_status(device_status::FEATURES_OK, device_status::FAILED) {
            // FIXME: check if activated!
            self.with_queue_mut(f);
        } else {
            warn!(
                "update virtio queue in invalid state 0x{:x}",
                self.device_status
            );
        }
    }

    fn reset(&mut self) {
        #[cfg(feature = "native-device-probe")]
        {
            let _ = self.diagnostic_hold_irq_acks(false);
        }
        if self.locked_device().is_activated() {
            debug!("reset device while it's still in active state");
        }
        self.features_select = 0;
        self.acked_features_select = 0;
        self.queue_select = 0;
        self.interrupt.0.status.store(0, Ordering::SeqCst);
        self.interrupt
            .0
            .notification_failed
            .store(false, Ordering::SeqCst);
        self.device_status = device_status::INIT;
        // Do not reset config_generation and keep it monotonically increasing.
        // Recreate queues from queue_config for the next negotiation cycle.
        // Keep queue_evts as is - they are reused across reset cycles.
        // TODO: consider resting the events when we refactor event handling
        self.queues = Some(Self::create_queues(&self.queue_config));
        self.escrow = QueueEscrow::new(
            self.queues
                .as_ref()
                .into_iter()
                .flatten()
                .zip(&self.queue_evts)
                .map(|(queue, event)| QueueBinding::new(queue, event))
                .collect(),
        );
        // . Do not reset config_generation and keep it monotonically increasing
    }

    fn activate(&mut self) {
        let Some(queues) = self.queues.take() else {
            return;
        };

        let mut device_queues: Vec<DeviceQueue> = queues
            .into_iter()
            .zip(self.queue_evts.iter().cloned())
            .map(|(queue, event)| DeviceQueue::new(queue, event))
            .collect();

        let mut locked_device = self.locked_device();
        let event_idx_enabled =
            (locked_device.acked_features() & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        for dq in &mut device_queues {
            dq.queue.set_event_idx(event_idx_enabled);
        }
        locked_device
            .activate(self.mem.clone(), self.interrupt.clone(), device_queues)
            .expect("Failed to activate device");
    }

    /// Update device status according to the state machine defined by VirtIO Spec 1.0.
    /// Please refer to VirtIO Spec 1.0, section 2.1.1 and 3.1.1.
    ///
    /// The driver MUST update device status, setting bits to indicate the completed steps
    /// of the driver initialization sequence specified in 3.1. The driver MUST NOT clear
    /// a device status bit. If the driver sets the FAILED bit, the driver MUST later reset
    /// the device before attempting to re-initialize.
    #[allow(unused_assignments)]
    fn set_device_status(&mut self, status: u32) {
        use device_status::*;
        // match changed bits
        match !self.device_status & status {
            ACKNOWLEDGE if self.device_status == INIT => {
                self.device_status = status;
            }
            DRIVER if self.device_status == ACKNOWLEDGE => {
                self.device_status = status;
            }
            FEATURES_OK if self.device_status == (ACKNOWLEDGE | DRIVER) => {
                self.device_status = status;
            }
            DRIVER_OK if self.device_status == (ACKNOWLEDGE | DRIVER | FEATURES_OK) => {
                self.device_status = status;
                let device_activated = self.locked_device().is_activated();
                if !device_activated {
                    self.activate();
                }
            }
            _ if (status & FAILED) != 0 => {
                // TODO: notify backend driver to stop the device
                self.device_status |= FAILED;
            }
            _ if status == 0 => {
                if self.locked_device().is_activated() && !self.locked_device().reset() {
                    self.device_status |= FAILED;
                }

                // If the backend device driver doesn't support reset,
                // just leave the device marked as FAILED.
                if self.device_status & FAILED == 0 {
                    self.reset();
                }
            }
            _ => {
                warn!(
                    "invalid virtio driver status transition: 0x{:x} -> 0x{:x}",
                    self.device_status, status
                );
            }
        }
    }
}

impl BusDevice for MmioTransport {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.locked_device().device_type(),
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        let mut features = self
                            .locked_device()
                            .avail_features_by_page(self.features_select);
                        if self.features_select == 1 {
                            features |= 0x1; // enable support of VirtIO Version 1
                        }
                        features
                    }
                    0x34 => self
                        .queue_config
                        .get(self.queue_select as usize)
                        .map_or(0, |c| c.size as u32),
                    0x44 => self.with_queue(0, |q| q.ready as u32),
                    0x60 => self.interrupt.status().load(Ordering::SeqCst) as u32,
                    0x70 => self.device_status,
                    0xfc => self.config_generation,
                    0xb0..=0xbc => {
                        // For no SHM region or invalid region the kernel looks for length of -1
                        let (shm_base, shm_len) = if self.shm_region_select > 1 {
                            (0, !0)
                        } else {
                            match self.locked_device().shm_region() {
                                Some(region) => (region.guest_addr, region.size as u64),
                                None => (0, !0),
                            }
                        };
                        match offset {
                            0xb0 => shm_len as u32,
                            0xb4 => (shm_len >> 32) as u32,
                            0xb8 => shm_base as u32,
                            0xbc => (shm_base >> 32) as u32,
                            _ => {
                                error!("invalid shm region offset");
                                0
                            }
                        }
                    }
                    _ => {
                        warn!("unknown virtio mmio register read: 0x{offset:x}");
                        return;
                    }
                };
                byte_order::write_le_u32(data, v);
            }
            0x100..=0xfff => self.locked_device().read_config(offset - 0x100, data),
            _ => {
                warn!(
                    "invalid virtio mmio read: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if self.lifecycle.snapshot.stage != ProviderStage::Running
            || (self.lifecycle.snapshot.accepted && self.lifecycle.snapshot.failure.is_some())
        {
            log::warn!("refusing guest MMIO mutation during retained live transition");
            return;
        }
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => {
                        if self.check_device_status(
                            device_status::DRIVER,
                            device_status::FEATURES_OK | device_status::FAILED,
                        ) {
                            self.locked_device()
                                .ack_features_by_page(self.acked_features_select, v);
                        } else {
                            warn!(
                                "ack virtio features in invalid state 0x{:x}",
                                self.device_status
                            );
                        }
                    }
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => self.update_queue_field(|q| q.size = v as u16),
                    0x44 => self.update_queue_field(|q| q.ready = v == 1),
                    0x50 => {
                        // Queue notification - write to the eventfd for the specified queue.
                        if let Some(eventfd) = self.queue_evts.get(v as usize) {
                            eventfd.write(1).unwrap();
                        } else {
                            warn!("invalid queue index for notification: {v}");
                        }
                    }
                    0x64 => {
                        if self.check_device_status(device_status::DRIVER_OK, 0) {
                            #[cfg(feature = "native-device-probe")]
                            self.diagnostic_observe_irq_ack(v);
                            #[cfg(not(feature = "native-device-probe"))]
                            self.interrupt
                                .status()
                                .fetch_and(!(v as usize), Ordering::SeqCst);
                        }
                    }
                    0x70 => self.set_device_status(v),
                    0x80 => self.update_queue_field(|q| lo(&mut q.desc_table, v)),
                    0x84 => self.update_queue_field(|q| hi(&mut q.desc_table, v)),
                    0x90 => self.update_queue_field(|q| lo(&mut q.avail_ring, v)),
                    0x94 => self.update_queue_field(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => self.update_queue_field(|q| lo(&mut q.used_ring, v)),
                    0xa4 => self.update_queue_field(|q| hi(&mut q.used_ring, v)),
                    0xac => self.shm_region_select = v,
                    _ => {
                        warn!("unknown virtio mmio register write: 0x{offset:x}");
                    }
                }
            }
            0x100..=0xfff => {
                if self.check_device_status(device_status::DRIVER, device_status::FAILED) {
                    self.locked_device().write_config(offset - 0x100, data)
                } else {
                    warn!("can not write to device config data area before driver is ready");
                }
            }
            _ => {
                warn!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        }
    }

    fn interrupt(&self, irq_mask: u32) -> std::io::Result<()> {
        #[cfg(feature = "native-device-probe")]
        self.interrupt
            .0
            .probe
            .increment(&self.interrupt.0.probe.signal_attempts);
        self.interrupt.publish_cause(irq_mask);
        let result = self.interrupt.event().write(1);
        if result.is_err() {
            self.interrupt
                .0
                .notification_failed
                .store(true, Ordering::SeqCst);
        }
        #[cfg(feature = "native-device-probe")]
        if result.is_ok() {
            self.interrupt
                .0
                .probe
                .increment(&self.interrupt.0.probe.signal_successes);
        }
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use utils::byte_order::{read_le_u32, write_le_u32};

    use crate::legacy::DummyIrqChip;
    use crate::virtio::mmio::*;
    use vm_memory::GuestMemoryMmap;

    static QUEUE_CONFIG: [QueueConfig; 2] = [QueueConfig::new(16), QueueConfig::new(32)];

    pub(crate) struct DummyDevice {
        acked_features: u64,
        avail_features: u64,
        device_activated: bool,
        config_bytes: [u8; 0xeff],
    }

    impl DummyDevice {
        pub(crate) fn new() -> Self {
            DummyDevice {
                acked_features: 0,
                avail_features: 0,
                device_activated: false,
                config_bytes: [0; 0xeff],
            }
        }

        fn set_avail_features(&mut self, avail_features: u64) {
            self.avail_features = avail_features;
        }
    }

    impl VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            123
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            data.copy_from_slice(&self.config_bytes[offset as usize..]);
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            for (i, item) in data.iter().enumerate() {
                self.config_bytes[offset as usize + i] = *item;
            }
        }

        fn avail_features(&self) -> u64 {
            self.avail_features
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn set_acked_features(&mut self, acked_features: u64) {
            self.acked_features = acked_features;
        }

        fn queue_config(&self) -> &[QueueConfig] {
            &QUEUE_CONFIG
        }

        fn activate(
            &mut self,
            _mem: RuntimeGuestMemory,
            _interrupt: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            self.device_activated = true;
            Ok(())
        }

        fn is_activated(&self) -> bool {
            self.device_activated
        }
    }

    fn set_device_status(d: &mut MmioTransport, status: u32) {
        let mut buf = [0; 4];
        write_le_u32(&mut buf[..], status);
        d.write(0, 0x70, &buf[..]);
    }

    #[test]
    fn test_new() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let dummy = DummyDevice::new();
        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(dummy)),
            None,
        )
        .unwrap();

        // We just make sure here that the implementation of a mmio device behaves as we expect,
        // given a known virtio device implementation (the dummy device).

        // Transport now owns the queue_evts.
        assert_eq!(d.queue_evts().len(), 2);

        d.queue_select = 0;
        assert_eq!(d.with_queue(0, Queue::get_max_size), 16);
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(d.queues.as_ref().unwrap()[d.queue_select as usize].size, 16);

        d.queue_select = 1;
        assert_eq!(d.with_queue(0, Queue::get_max_size), 32);
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(d.queues.as_ref().unwrap()[d.queue_select as usize].size, 16);

        d.queue_select = 2;
        assert_eq!(d.with_queue(0, Queue::get_max_size), 0);
        assert!(!d.with_queue_mut(|q| q.size = 16));
    }

    #[test]
    fn test_bus_device_read() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
            None,
        )
        .unwrap();

        let mut buf = vec![0xff, 0, 0xfe, 0];
        let buf_copy = buf.to_vec();

        // The following read shouldn't be valid, because the length of the buf is not 4.
        buf.push(0);
        d.read(0, 0, &mut buf[..]);
        assert_eq!(buf[..4], buf_copy[..]);

        // the length is ok again
        buf.pop();

        // Now we test that reading at various predefined offsets works as intended.

        d.read(0, 0, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), MMIO_MAGIC_VALUE);

        d.read(0, 0x04, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), MMIO_VERSION);

        d.read(0, 0x08, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), d.locked_device().device_type());

        d.read(0, 0x0c, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), VENDOR_ID);

        d.features_select = 0;
        d.read(0, 0x10, &mut buf[..]);
        assert_eq!(
            read_le_u32(&buf[..]),
            d.locked_device().avail_features_by_page(0)
        );

        d.features_select = 1;
        d.read(0, 0x10, &mut buf[..]);
        assert_eq!(
            read_le_u32(&buf[..]),
            d.locked_device().avail_features_by_page(0) | 0x1
        );

        d.read(0, 0x34, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 16);

        d.read(0, 0x44, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), false as u32);

        d.interrupt.status().store(111, Ordering::SeqCst);
        d.read(0, 0x60, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 111);

        d.read(0, 0x70, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 0);

        d.config_generation = 5;
        d.read(0, 0xfc, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 5);

        // This read shouldn't do anything, as it's past the readable generic registers, and
        // before the device specific configuration space. Btw, reads from the device specific
        // conf space are going to be tested a bit later, alongside writes.
        buf = buf_copy.to_vec();
        d.read(0, 0xfd, &mut buf[..]);
        assert_eq!(buf[..], buf_copy[..]);

        // Read from an invalid address in generic register range.
        d.read(0, 0xfb, &mut buf[..]);
        assert_eq!(buf[..], buf_copy[..]);

        // Read from an invalid length in generic register range.
        d.read(0, 0xfc, &mut buf[..3]);
        assert_eq!(buf[..], buf_copy[..]);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_bus_device_write() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let dummy_dev = Arc::new(Mutex::new(DummyDevice::new()));
        let mut d =
            MmioTransport::new(m, DummyIrqChip::new().into(), dummy_dev.clone(), None).unwrap();
        let mut buf = vec![0; 5];
        write_le_u32(&mut buf[..4], 1);

        // Nothing should happen, because the slice len > 4.
        d.features_select = 0;
        d.write(0, 0x14, &buf[..]);
        assert_eq!(d.features_select, 0);

        buf.pop();

        assert_eq!(d.device_status, device_status::INIT);
        set_device_status(&mut d, device_status::ACKNOWLEDGE);

        // Acking features in invalid state shouldn't take effect.
        assert_eq!(d.locked_device().acked_features(), 0x0);
        d.acked_features_select = 0x0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x0);

        // Write to device specific configuration space should be ignored before setting device_status::DRIVER
        let buf1 = vec![1; 0xeff];
        for i in (0..0xeff).rev() {
            let mut buf2 = vec![0; 0xeff];

            d.write(0, 0x100 + i as u64, &buf1[i..]);
            d.read(0, 0x100, &mut buf2[..]);

            for item in buf2.iter().take(0xeff) {
                assert_eq!(*item, 0);
            }
        }

        set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        // now writes should work
        d.features_select = 0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x14, &buf[..]);
        assert_eq!(d.features_select, 1);

        // Test acknowledging features on bus.
        d.acked_features_select = 0;
        write_le_u32(&mut buf[..], 0x124);

        // Set the device available features in order to make acknowledging possible.
        dummy_dev.lock().unwrap().set_avail_features(0x124);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x124);

        d.acked_features_select = 0;
        write_le_u32(&mut buf[..], 2);
        d.write(0, 0x24, &buf[..]);
        assert_eq!(d.acked_features_select, 2);
        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );

        // Acking features in invalid state shouldn't take effect.
        assert_eq!(d.locked_device().acked_features(), 0x124);
        d.acked_features_select = 0x0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x124);

        // Setup queues
        d.queue_select = 0;
        write_le_u32(&mut buf[..], 3);
        d.write(0, 0x30, &buf[..]);
        assert_eq!(d.queue_select, 3);

        d.queue_select = 0;
        assert_eq!(d.queues.as_ref().unwrap()[0].size, 0);
        write_le_u32(&mut buf[..], 16);
        d.write(0, 0x38, &buf[..]);
        assert_eq!(d.queues.as_ref().unwrap()[0].size, 16);

        assert!(!d.queues.as_ref().unwrap()[0].ready);
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x44, &buf[..]);
        assert!(d.queues.as_ref().unwrap()[0].ready);

        assert_eq!(d.queues.as_ref().unwrap()[0].desc_table.0, 0);
        write_le_u32(&mut buf[..], 123);
        d.write(0, 0x80, &buf[..]);
        assert_eq!(d.queues.as_ref().unwrap()[0].desc_table.0, 123);
        d.write(0, 0x84, &buf[..]);
        assert_eq!(
            d.queues.as_ref().unwrap()[0].desc_table.0,
            123 + (123 << 32)
        );

        assert_eq!(d.queues.as_ref().unwrap()[0].avail_ring.0, 0);
        write_le_u32(&mut buf[..], 124);
        d.write(0, 0x90, &buf[..]);
        assert_eq!(d.queues.as_ref().unwrap()[0].avail_ring.0, 124);
        d.write(0, 0x94, &buf[..]);
        assert_eq!(
            d.queues.as_ref().unwrap()[0].avail_ring.0,
            124 + (124 << 32)
        );

        assert_eq!(d.queues.as_ref().unwrap()[0].used_ring.0, 0);
        write_le_u32(&mut buf[..], 125);
        d.write(0, 0xa0, &buf[..]);
        assert_eq!(d.queues.as_ref().unwrap()[0].used_ring.0, 125);
        d.write(0, 0xa4, &buf[..]);
        assert_eq!(d.queues.as_ref().unwrap()[0].used_ring.0, 125 + (125 << 32));

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );

        d.interrupt.status().store(0b10_1010, Ordering::Relaxed);
        write_le_u32(&mut buf[..], 0b111);
        d.write(0, 0x64, &buf[..]);
        assert_eq!(d.interrupt.status().load(Ordering::Relaxed), 0b10_1000);

        // Write to an invalid address in generic register range.
        write_le_u32(&mut buf[..], 0xf);
        d.config_generation = 0;
        d.write(0, 0xfb, &buf[..]);
        assert_eq!(d.config_generation, 0);

        // Write to an invalid length in generic register range.
        d.write(0, 0xfc, &buf[..2]);
        assert_eq!(d.config_generation, 0);

        // Here we test writes/read into/from the device specific configuration space.
        let buf1 = vec![1; 0xeff];
        for i in (0..0xeff).rev() {
            let mut buf2 = vec![0; 0xeff];

            d.write(0, 0x100 + i as u64, &buf1[i..]);
            d.read(0, 0x100, &mut buf2[..]);

            for item in buf2.iter().take(i) {
                assert_eq!(*item, 0);
            }

            assert_eq!(buf1[i..], buf2[i..]);
        }
    }

    #[test]
    fn test_bus_device_activate() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
            None,
        )
        .unwrap();

        assert!(!d.locked_device().is_activated());
        assert_eq!(d.device_status, device_status::INIT);

        set_device_status(&mut d, device_status::ACKNOWLEDGE);
        set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        // invalid state transition should have no effect
        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK
        );

        let mut buf = [0; 4];
        let queue_len = d.queues.as_ref().unwrap().len();
        for q in 0..queue_len {
            d.queue_select = q as u32;
            write_le_u32(&mut buf[..], 16);
            d.write(0, 0x38, &buf[..]);
            write_le_u32(&mut buf[..], 1);
            d.write(0, 0x44, &buf[..]);
        }
        assert!(!d.locked_device().is_activated());

        // Device should be ready for activation now.

        // A couple of invalid writes; will trigger warnings; shouldn't activate the device.
        d.write(0, 0xa8, &buf[..]);
        d.write(0, 0x1000, &buf[..]);
        assert!(!d.locked_device().is_activated());

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK
        );
        assert!(d.locked_device().is_activated());
    }

    fn activate_device(d: &mut MmioTransport) {
        set_device_status(d, device_status::ACKNOWLEDGE);
        set_device_status(d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        set_device_status(
            d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );

        // Setup queue data structures
        let mut buf = [0; 4];
        let queues_count = d.queues.as_ref().unwrap().len();
        for q in 0..queues_count {
            d.queue_select = q as u32;
            write_le_u32(&mut buf[..], 16);
            d.write(0, 0x38, &buf[..]);
            write_le_u32(&mut buf[..], 1);
            d.write(0, 0x44, &buf[..]);
        }
        assert!(!d.locked_device().is_activated());

        // Device should be ready for activation now.
        set_device_status(
            d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK
        );
        assert!(d.locked_device().is_activated());
    }

    #[test]
    fn test_bus_device_reset() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
            None,
        )
        .unwrap();
        let mut buf = [0; 4];

        assert!(!d.locked_device().is_activated());
        assert_eq!(d.device_status, 0);
        activate_device(&mut d);

        // Marking device as FAILED should not affect device_activated state
        write_le_u32(&mut buf[..], 0x8f);
        d.write(0, 0x70, &buf[..]);
        assert_eq!(d.device_status, 0x8f);
        assert!(d.locked_device().is_activated());

        // Nothing happens when backend driver doesn't support reset
        write_le_u32(&mut buf[..], 0x0);
        d.write(0, 0x70, &buf[..]);
        assert_eq!(d.device_status, 0x8f);
        assert!(d.locked_device().is_activated());
    }

    #[test]
    fn test_get_avail_features() {
        let dummy_dev = DummyDevice::new();
        assert_eq!(dummy_dev.avail_features(), dummy_dev.avail_features);
    }

    #[test]
    fn test_get_acked_features() {
        let dummy_dev = DummyDevice::new();
        assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
    }

    #[test]
    fn test_set_acked_features() {
        let mut dummy_dev = DummyDevice::new();

        assert_eq!(dummy_dev.acked_features(), 0);
        dummy_dev.set_acked_features(16);
        assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
    }

    #[test]
    fn test_ack_features_by_page() {
        let mut dummy_dev = DummyDevice::new();
        dummy_dev.set_acked_features(16);
        dummy_dev.set_avail_features(8);
        dummy_dev.ack_features_by_page(0, 8);
        assert_eq!(dummy_dev.acked_features(), 24);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "blk"))]
    #[test]
    fn shared_irq_raw_workers_keep_independent_ack_and_survive_device_drop() {
        use std::fs;
        use std::os::fd::{AsRawFd, BorrowedFd};
        use std::path::{Path, PathBuf};
        use std::sync::Barrier;
        use std::time::{Duration, Instant};

        use nix::poll::{PollFd, PollFlags, poll};
        use utils::tempfile::TempFile;
        use virtio_bindings::virtio_blk::{VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};

        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::RuntimeGuestMemory;
        use crate::virtio::block::{Block, CacheType, DiskFormat, SyncMode};
        use crate::virtio::queue::tests::VirtQueue;

        struct RunningRaw {
            transport: MmioTransport,
            block: Arc<Mutex<Block>>,
            memory: RuntimeGuestMemory,
            kick: Arc<EventFd>,
            used_index: GuestAddress,
            available_index: GuestAddress,
            available_ring: GuestAddress,
            path: PathBuf,
        }

        impl RunningRaw {
            fn new(path: &Path, shared: Arc<EventFd>) -> Self {
                fs::write(path, [0xa5; 4096]).expect("populate real Raw backing");
                let block = Arc::new(Mutex::new(
                    Block::new(
                        "shared-irq-raw".into(),
                        None,
                        CacheType::Writeback,
                        path.to_str().expect("fixture UTF-8").into(),
                        DiskFormat::Raw,
                        false,
                        false,
                        SyncMode::Relaxed,
                    )
                    .expect("open real Raw device"),
                ));
                let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x3000)])
                    .expect("real guest memory");
                let queue = VirtQueue::new(GuestAddress(0), &memory, 8);
                queue.dtable[0].set(0x1000, 16, 1, 1);
                queue.dtable[1].set(0x1100, 512, 1, 2);
                queue.dtable[2].set(0x1400, 1, 2, 0);
                let configured = queue.create_queue();
                let used_index = queue.used.idx.location;
                let available_index = queue.avail.idx.location;
                let available_ring = queue.avail.ring[0].location;
                let irqchip = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {}))));
                let mut transport =
                    MmioTransport::new(memory.clone(), irqchip, block.clone(), Some(shared))
                        .expect("real shared-notification MMIO transport");
                transport.set_irq_line(15);
                set_device_status(&mut transport, device_status::ACKNOWLEDGE);
                set_device_status(
                    &mut transport,
                    device_status::ACKNOWLEDGE | device_status::DRIVER,
                );
                set_device_status(
                    &mut transport,
                    device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
                );
                for (offset, value) in [
                    (0x38, 8_u32),
                    (0x80, configured.desc_table.0 as u32),
                    (0x90, configured.avail_ring.0 as u32),
                    (0xa0, configured.used_ring.0 as u32),
                    (0x44, 1_u32),
                ] {
                    transport.write(0, offset, &value.to_le_bytes());
                }
                let kick = transport.queue_evts()[0].clone();
                set_device_status(
                    &mut transport,
                    device_status::ACKNOWLEDGE
                        | device_status::DRIVER
                        | device_status::FEATURES_OK
                        | device_status::DRIVER_OK,
                );
                assert!(block.lock().expect("block").is_activated());
                Self {
                    transport,
                    block,
                    memory,
                    kick,
                    used_index,
                    available_index,
                    available_ring,
                    path: path.to_owned(),
                }
            }

            fn prepare(&self, index: u16, request: u32, fill: u8) {
                self.memory
                    .write_obj(request, GuestAddress(0x1000))
                    .expect("request type");
                self.memory
                    .write_obj(0_u32, GuestAddress(0x1004))
                    .expect("reserved");
                self.memory
                    .write_obj(0_u64, GuestAddress(0x1008))
                    .expect("sector");
                let flags = if request == VIRTIO_BLK_T_IN {
                    3_u16
                } else {
                    1_u16
                };
                self.memory
                    .write_obj(flags, GuestAddress(28))
                    .expect("data descriptor direction");
                self.memory
                    .write_slice(&[fill; 512], GuestAddress(0x1100))
                    .expect("request payload");
                self.memory
                    .write_obj(0xff_u8, GuestAddress(0x1400))
                    .expect("initial status");
                self.memory
                    .write_obj(
                        0_u16,
                        GuestAddress(self.available_ring.0 + u64::from((index - 1) % 8) * 2),
                    )
                    .expect("available head");
                self.memory
                    .write_obj(index, self.available_index)
                    .expect("publish request");
            }

            fn wait(&self, index: u16) {
                let deadline = Instant::now() + Duration::from_secs(5);
                while self
                    .memory
                    .read_obj::<u16>(self.used_index)
                    .expect("used index")
                    != index
                    || self.transport.interrupt.status().load(Ordering::SeqCst) & 1 == 0
                {
                    assert!(
                        Instant::now() < deadline,
                        "real block request did not complete"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(
                    self.memory
                        .read_obj::<u8>(GuestAddress(0x1400))
                        .expect("status"),
                    0
                );
            }

            fn status(&mut self) -> u32 {
                let mut bytes = [0; 4];
                self.transport.read(0, 0x60, &mut bytes);
                u32::from_le_bytes(bytes)
            }

            fn acknowledge(&mut self) {
                self.transport.write(0, 0x64, &1_u32.to_le_bytes());
            }
        }

        impl Drop for RunningRaw {
            fn drop(&mut self) {
                self.block
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reset();
            }
        }

        fn notification(line: &EventFd) {
            // SAFETY: line owns the descriptor throughout poll and read, and
            // the borrowed descriptor does not escape this function.
            let descriptor = unsafe { BorrowedFd::borrow_raw(line.as_raw_fd()) };
            let mut ready = [PollFd::new(descriptor, PollFlags::POLLIN)];
            assert_eq!(
                poll(&mut ready, 5000_u16).expect("shared line readiness"),
                1
            );
            assert!(line.read().expect("one shared notification source") > 0);
        }

        let backing = [
            TempFile::new().expect("first backing"),
            TempFile::new().expect("second backing"),
        ];
        let line_owner = Arc::new(EventFd::new(EFD_NONBLOCK).expect("manager-owned shared line"));
        let mut devices = [
            RunningRaw::new(backing[0].as_path(), line_owner.clone()),
            RunningRaw::new(backing[1].as_path(), line_owner.clone()),
        ];
        for index in 1..=32_u16 {
            for (device_index, device) in devices.iter().enumerate() {
                device.prepare(index, VIRTIO_BLK_T_OUT, index as u8 + device_index as u8);
            }
            let first = devices[0].kick.clone();
            let second = devices[1].kick.clone();
            let barrier = Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    first.write(1).expect("first concurrent request");
                });
                scope.spawn(|| {
                    barrier.wait();
                    second.write(1).expect("second concurrent request");
                });
            });
            for device in &devices {
                device.wait(index);
            }
            notification(&line_owner);
            assert_eq!(devices[0].status(), 1);
            assert_eq!(devices[1].status(), 1);
            devices[0].acknowledge();
            assert_eq!(devices[0].status(), 0);
            assert_eq!(
                devices[1].status(),
                1,
                "ACK of first device must not clear second"
            );
            devices[1].acknowledge();
            assert_eq!(devices[1].status(), 0);
            for (device_index, device) in devices.iter().enumerate() {
                let mut expected = [0xa5; 4096];
                expected[..512].fill(index as u8 + device_index as u8);
                assert_eq!(fs::read(&device.path).expect("actual Raw bytes"), expected);
            }
        }
        let [first, mut survivor] = devices;
        drop(first);
        survivor.prepare(33, VIRTIO_BLK_T_IN, 0xcc);
        survivor.kick.write(1).expect("surviving device request");
        survivor.wait(33);
        notification(&line_owner);
        let mut read_back = [0; 512];
        survivor
            .memory
            .read_slice(&mut read_back, GuestAddress(0x1100))
            .expect("Raw read response");
        assert_eq!(read_back, [33; 512]);
        survivor.acknowledge();
        assert_eq!(survivor.status(), 0);
        drop(survivor);
        for file in &backing {
            assert_eq!(
                fs::metadata(file.as_path())
                    .expect("reopened backing")
                    .len(),
                4096
            );
        }
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn lifecycle_real_rng_quiesces_inactive_provider_without_activation() {
        use polly::event_manager::{BarrierGeneration, OperationId};
        use std::time::Duration;
        let mem = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let rng = Arc::new(Mutex::new(Rng::new().unwrap()));
        let mut transport =
            MmioTransport::new(mem, DummyIrqChip::new().into(), rng.clone(), None).unwrap();
        transport.set_attachment_address(0x1000).unwrap();
        let original = transport.queues.as_ref().unwrap()[0]
            .capture_state()
            .unwrap();
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(1),
        };
        transport.preflight_quiesce().unwrap();
        transport.begin_quiesce(request).unwrap();
        assert!(transport.poll_quiesce(request.key).unwrap().is_ready());
        assert_eq!(
            transport.lifecycle_snapshot().stage,
            ProviderStage::Quiesced
        );
        assert_eq!(transport.device_status, device_status::INIT);
        assert_eq!(
            transport.queues.as_ref().unwrap()[0]
                .capture_state()
                .unwrap(),
            original
        );
        assert!(!rng.try_lock().expect("uncontended RNG").is_activated());
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn lifecycle_shared_notifier_keeps_independent_status_and_ack() {
        let mem = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut first = MmioTransport::new(
            mem.clone(),
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            Some(Arc::clone(&line)),
        )
        .unwrap();
        let mut second = MmioTransport::new(
            mem,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            Some(Arc::clone(&line)),
        )
        .unwrap();
        first.device_status = 15;
        second.device_status = 15;
        first.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        second.interrupt(VIRTIO_MMIO_INT_CONFIG).unwrap();
        assert_eq!(line.read().unwrap(), 2);
        first.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        assert_eq!(first.interrupt.status().load(Ordering::SeqCst), 0);
        assert_eq!(
            second.interrupt.status().load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_CONFIG as usize
        );
        drop(first);
        second.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        assert_eq!(line.read().unwrap(), 1);
        second.write(0, 0x64, &VIRTIO_MMIO_INT_CONFIG.to_le_bytes());
        assert_eq!(
            second.interrupt.status().load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_VRING as usize
        );
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn lifecycle_transport_validation_preserves_negotiating_registers() {
        let mem = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let mut transport = MmioTransport::new(
            mem,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            None,
        )
        .unwrap();
        transport.set_attachment_address(0x1000).unwrap();
        let original = transport.queues.as_ref().unwrap()[0]
            .capture_state()
            .unwrap();
        let mut state = MmioTransportState {
            device_type: 4,
            device_name: "rng".into(),
            attachment_address: 0x1000,
            irq_line: None,
            avail_features: transport.locked_device().avail_features(),
            acked_features: 0,
            features_select: u32::MAX,
            acked_features_select: u32::MAX,
            queue_select: u32::MAX,
            device_status: 0,
            config_generation: 9,
            shm_region_select: u32::MAX,
            interrupt_status: 0,
            activated: false,
            queues: vec![original.clone()],
        };
        state.queues[0].size = 3;
        state.queues[0].desc_table = u64::MAX;
        transport.validate_transport(&state).unwrap();
        state.irq_line = Some(15);
        assert_eq!(
            transport.validate_transport(&state),
            Err(ProviderFault::DeviceState)
        );
        assert!(transport.apply_transport(&state).is_err());
        assert_eq!(
            transport.queues.as_ref().unwrap()[0]
                .capture_state()
                .unwrap(),
            original
        );
        assert_eq!(transport.features_select, 0);
        assert_eq!(transport.device_status, 0);
        assert_eq!(
            transport.validate_device_state(&[]),
            Err(ProviderFault::DeviceState)
        );
    }

    #[cfg(all(target_os = "linux", not(feature = "tee")))]
    #[test]
    fn lifecycle_failed_eventfd_publication_survives_status_ack() {
        let mem = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut transport = MmioTransport::new(
            mem,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            Some(Arc::clone(&line)),
        )
        .unwrap();
        transport.device_status = 15;
        line.write(u64::MAX - 1).unwrap();
        assert!(transport.interrupt(VIRTIO_MMIO_INT_VRING).is_err());
        assert!(
            transport
                .interrupt
                .0
                .notification_failed
                .load(Ordering::SeqCst)
        );
        transport.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        assert_eq!(transport.interrupt.status().load(Ordering::SeqCst), 0);
        assert!(
            transport
                .interrupt
                .0
                .notification_failed
                .load(Ordering::SeqCst)
        );
        assert_eq!(line.read().unwrap(), u64::MAX - 1);
    }

    #[cfg(all(target_os = "linux", not(feature = "tee")))]
    #[test]
    fn lifecycle_resume_refuses_real_irq_failure_after_provider_acceptance() {
        use polly::event_manager::{BarrierGeneration, OperationId};
        use std::time::Duration;
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut transport = MmioTransport::new(
            memory,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            Some(line.clone()),
        )
        .unwrap();
        transport.set_attachment_address(0x1000).unwrap();
        let cut = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(5),
        };
        transport.begin_quiesce(cut).unwrap();
        assert!(transport.poll_quiesce(cut.key).unwrap().is_ready());
        let resume = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(2),
                ..cut.key
            },
            ..cut
        };
        transport.begin_resume(resume).unwrap();
        line.write(u64::MAX - 1).unwrap();
        assert!(transport.interrupt(VIRTIO_MMIO_INT_VRING).is_err());
        assert_eq!(
            transport.poll_resume(resume.key).unwrap_err().fault,
            ProviderFault::Notification
        );
        assert!(transport.lifecycle_snapshot().accepted);
        assert!(transport.lifecycle_snapshot().failure.is_some());
    }

    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        not(feature = "tee")
    ))]
    fn irq_probe_rng_transport(line: Arc<EventFd>) -> MmioTransport {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let mut transport = MmioTransport::new(
            memory,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            Some(line),
        )
        .unwrap();
        transport.set_attachment_address(0x1000).unwrap();
        transport.set_irq_line(5);
        for (offset, value) in [
            (0x70, 1_u32),
            (0x70, 3),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x30, 0),
            (0x38, 8),
            (0x80, 0),
            (0x90, 0x1000),
            (0xa0, 0x2000),
            (0x44, 1),
            (0x70, 15),
        ] {
            transport.write(0, offset, &value.to_le_bytes());
        }
        assert!(transport.locked_device().is_activated());
        transport
    }

    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        not(feature = "tee")
    ))]
    #[test]
    fn irq_probe_held_original_ack_keeps_peer_status_independent_and_refuses_cut() {
        use polly::event_manager::{BarrierGeneration, OperationId};
        use std::time::Duration;
        let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut first = irq_probe_rng_transport(line.clone());
        let mut peer = irq_probe_rng_transport(line.clone());
        first.diagnostic_hold_irq_acks(true).unwrap();
        first.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        peer.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        first.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        peer.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        let held = first.diagnostic_irq_snapshot();
        let completed = peer.diagnostic_irq_snapshot();
        assert_eq!(
            (
                held.status,
                held.ack_writes,
                held.ack_applied,
                held.held_acks
            ),
            (1, 1, 0, 1)
        );
        assert_eq!(
            (
                completed.status,
                completed.ack_writes,
                completed.ack_applied
            ),
            (0, 1, 1)
        );
        assert_eq!((held.signal_attempts, held.signal_successes), (1, 1));
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let failure = first.begin_quiesce(request).unwrap_err();
        assert_eq!(failure.fault, ProviderFault::DeviceState);
        assert!(!failure.accepted);
        first.diagnostic_hold_irq_acks(false).unwrap();
        first.diagnostic_hold_irq_acks(false).unwrap();
        let released = first.diagnostic_irq_snapshot();
        assert_eq!(
            (
                released.status,
                released.ack_writes,
                released.ack_applied,
                released.held_acks
            ),
            (0, 1, 1, 0)
        );
        first.preflight_quiesce().unwrap();
        assert_eq!(line.read().unwrap(), 2);
    }

    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        not(feature = "tee")
    ))]
    #[test]
    fn irq_probe_release_preserves_newer_cause_without_replaying_irq() {
        let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut transport = irq_probe_rng_transport(line.clone());
        let mut peer = irq_probe_rng_transport(line.clone());
        transport.diagnostic_hold_irq_acks(true).unwrap();
        transport.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        transport.interrupt(VIRTIO_MMIO_INT_CONFIG).unwrap();
        transport.write(
            0,
            0x64,
            &(VIRTIO_MMIO_INT_VRING | VIRTIO_MMIO_INT_CONFIG).to_le_bytes(),
        );
        transport.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        transport.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        peer.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        assert_eq!(line.read().unwrap(), 4);

        transport.diagnostic_hold_irq_acks(false).unwrap();
        transport.diagnostic_hold_irq_acks(false).unwrap();
        let released = transport.diagnostic_irq_snapshot();
        assert_eq!(released.status, VIRTIO_MMIO_INT_VRING);
        assert_eq!(
            (
                released.ack_writes,
                released.ack_applied,
                released.held_acks
            ),
            (2, 2, 0)
        );
        assert_eq!(
            (released.signal_attempts, released.signal_successes),
            (3, 3)
        );
        assert_eq!(peer.diagnostic_irq_snapshot().status, VIRTIO_MMIO_INT_VRING);
        assert_eq!(line.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);

        transport.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        assert_eq!(transport.diagnostic_irq_snapshot().status, 0);
        assert_eq!(peer.diagnostic_irq_snapshot().status, VIRTIO_MMIO_INT_VRING);

        transport.diagnostic_hold_irq_acks(true).unwrap();
        transport.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        transport.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        transport.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        transport.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        transport.diagnostic_hold_irq_acks(false).unwrap();
        let acknowledged = transport.diagnostic_irq_snapshot();
        assert_eq!(acknowledged.status, 0);
        assert_eq!((acknowledged.ack_writes, acknowledged.ack_applied), (5, 5));
        assert_eq!(line.read().unwrap(), 2);
        assert_eq!(line.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        not(feature = "tee")
    ))]
    #[test]
    fn irq_probe_poisoned_hold_completes_without_clearing_causes() {
        let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut transport = irq_probe_rng_transport(line.clone());
        transport.diagnostic_hold_irq_acks(true).unwrap();
        transport.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        transport.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        assert_eq!(line.read().unwrap(), 1);
        let interrupt = transport.interrupt.clone();
        assert!(
            std::thread::spawn(move || {
                let _held = interrupt.0.probe.lock_held_ack_mask();
                panic!("poison diagnostic ACK ownership");
            })
            .join()
            .is_err()
        );

        assert_eq!(
            transport.diagnostic_hold_irq_acks(false),
            Err(ProviderFault::DeviceState)
        );
        let snapshot = transport.diagnostic_irq_snapshot();
        assert!(snapshot.overflow);
        assert_eq!(snapshot.status, VIRTIO_MMIO_INT_VRING);
        assert_eq!(
            (
                snapshot.ack_writes,
                snapshot.ack_applied,
                snapshot.held_acks
            ),
            (1, 1, 0)
        );
        assert_eq!(
            transport.diagnostic_hold_irq_acks(false),
            Err(ProviderFault::DeviceState)
        );
        assert_eq!(
            transport.diagnostic_irq_snapshot().status,
            VIRTIO_MMIO_INT_VRING
        );
        assert_eq!(
            transport.preflight_quiesce(),
            Err(ProviderFault::DeviceState)
        );
        assert_eq!(line.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        not(feature = "tee")
    ))]
    #[test]
    fn irq_probe_hold_bound_completes_originals_and_marks_invalid_observation() {
        let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let mut transport = irq_probe_rng_transport(line);
        transport.diagnostic_hold_irq_acks(true).unwrap();
        transport.interrupt(VIRTIO_MMIO_INT_VRING).unwrap();
        for _ in 0..=crate::virtio::mmio::MAX_HELD_IRQ_ACKS {
            transport.write(0, 0x64, &VIRTIO_MMIO_INT_VRING.to_le_bytes());
        }
        let snapshot = transport.diagnostic_irq_snapshot();
        assert!(snapshot.overflow);
        assert_eq!(snapshot.held_acks, 0);
        assert_eq!(snapshot.status, 0);
        assert_eq!(
            snapshot.ack_writes,
            (crate::virtio::mmio::MAX_HELD_IRQ_ACKS + 1) as u64
        );
        assert_eq!(snapshot.ack_applied, snapshot.ack_writes);
        assert_eq!(
            transport.preflight_quiesce(),
            Err(ProviderFault::DeviceState)
        );
    }

    #[cfg(all(
        feature = "native-device-probe",
        target_os = "linux",
        target_arch = "x86_64",
        not(feature = "tee")
    ))]
    #[test]
    fn terminal_transport_console_reaps_blocked_tx_from_every_lifecycle_stage_without_drain() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::console::port_io;
        use crate::virtio::lifecycle::VirtioStateProvider;
        use polly::event_manager::{BarrierGeneration, OperationId};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        for (stage, unsupported_shape) in [
            (ProviderStage::Running, false),
            (ProviderStage::Running, true),
            (ProviderStage::Quiescing, false),
            (ProviderStage::Quiesced, false),
            (ProviderStage::Resuming, false),
        ] {
            let (host, peer) = UnixStream::pair().unwrap();
            let console = Arc::new(Mutex::new(
                Console::new(vec![PortDescription::output_pipe(
                    if unsupported_shape {
                        "x".repeat(257)
                    } else {
                        "output".into()
                    },
                    port_io::output_to_raw_fd_dup(host.as_raw_fd()).unwrap(),
                )])
                .unwrap(),
            ));
            let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 4 << 20)]).unwrap();
            let mut transport = MmioTransport::new(
                memory.clone(),
                Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
                console.clone(),
                None,
            )
            .unwrap();
            transport.set_attachment_address(0x1000).unwrap();
            if unsupported_shape {
                assert_eq!(
                    transport.preflight_quiesce(),
                    Err(ProviderFault::Unsupported)
                );
            }
            for (index, queue) in transport.queues.as_mut().unwrap().iter_mut().enumerate() {
                let base = index as u64 * 0x1000;
                queue.size = 32;
                queue.ready = true;
                queue.desc_table = GuestAddress(base);
                queue.avail_ring = GuestAddress(base + 0x400);
                queue.used_ring = GuestAddress(base + 0x800);
            }
            let request = |operation| BarrierRequest {
                key: BarrierKey {
                    operation: OperationId(operation),
                    generation: BarrierGeneration(1),
                },
                deadline: Instant::now() + Duration::from_secs(5),
            };
            transport.activate();
            transport.device_status = 15;
            {
                let mut console = console.lock().expect("actual console owner");
                console.ports[0].opened = true;
                console.start_port(0).unwrap();
            }
            if matches!(stage, ProviderStage::Quiesced | ProviderStage::Resuming) {
                let pause = request(1);
                transport.begin_quiesce_inner(pause, false).unwrap();
                while transport.poll_quiesce(pause.key).unwrap().is_pending() {
                    assert!(Instant::now() < pause.deadline);
                    std::thread::yield_now();
                }
            }
            if stage != ProviderStage::Quiesced {
                memory
                    .write_slice(&vec![0x5a; 2 << 20], GuestAddress(0x10000))
                    .unwrap();
                memory.write_obj(0x10000u64, GuestAddress(0x1000)).unwrap();
                memory.write_obj(2u32 << 20, GuestAddress(0x1008)).unwrap();
                memory.write_obj(0u16, GuestAddress(0x100c)).unwrap();
                memory.write_obj(0u16, GuestAddress(0x1404)).unwrap();
                memory.write_obj(1u16, GuestAddress(0x1402)).unwrap();
                if stage == ProviderStage::Resuming {
                    transport.begin_resume(request(2)).unwrap();
                } else {
                    console.lock().expect("actual console owner").ports[0].notify_tx();
                }
                let observation_deadline = request(3).deadline;
                loop {
                    let observation = match console
                        .lock()
                        .expect("actual console owner")
                        .output_observations()
                    {
                        Ok(observations) => observations[0],
                        Err(ProviderFault::LockBusy) => {
                            assert!(Instant::now() < observation_deadline);
                            std::thread::yield_now();
                            continue;
                        }
                        Err(fault) => panic!("actual output observation failed: {fault:?}"),
                    };
                    if observation.blocked_head == Some(0) {
                        assert!(observation.worker_handle_retained);
                        assert!(!observation.worker_finished);
                        assert!(observation.bytes_written > 0);
                        assert!(observation.write_remaining > 0);
                        break;
                    }
                    assert!(Instant::now() < observation_deadline, "TX did not block");
                    std::thread::yield_now();
                }
                if stage == ProviderStage::Quiescing {
                    let mut pause = request(4);
                    pause.deadline = Instant::now() + Duration::from_millis(40);
                    transport.begin_quiesce_inner(pause, false).unwrap();
                    assert!(transport.poll_quiesce(pause.key).unwrap().is_pending());
                    while Instant::now() < pause.deadline {
                        std::thread::yield_now();
                    }
                    assert_eq!(
                        transport.poll_quiesce(pause.key).unwrap_err().fault,
                        ProviderFault::Deadline
                    );
                }
            }
            assert_eq!(transport.lifecycle_snapshot().stage, stage);
            let stop = request(5);
            assert!(transport.poll_stop(stop).unwrap().is_pending());
            assert_eq!(
                transport.lifecycle_snapshot().stage,
                ProviderStage::Stopping
            );
            assert!(transport.capture_transport(stop.key).is_err());
            assert!(transport.capture_device_state(stop.key).is_err());
            assert!(transport.begin_resume(request(6)).is_err());
            while transport.poll_stop(stop).unwrap().is_pending() {
                assert!(Instant::now() < stop.deadline, "terminal TX did not reap");
                std::thread::yield_now();
            }
            assert_eq!(transport.lifecycle_snapshot().stage, ProviderStage::Stopped);
            assert!(transport.poll_stop(stop).unwrap().is_ready());
            assert!(transport.capture_transport(stop.key).is_err());
            assert!(transport.capture_device_state(stop.key).is_err());
            let console = console.lock().expect("actual console owner");
            assert!(console.capture_payload(stop.key).is_err());
            assert!(console.preflight().is_err());
            let observation = console.output_observations().unwrap()[0];
            assert!(!observation.worker_handle_retained);
            assert_eq!(memory.read_obj::<u16>(GuestAddress(0x1802)).unwrap(), 0);
            assert_eq!(transport.interrupt.status().load(Ordering::SeqCst), 0);
            assert!(transport.escrow.returned.is_none() || stage == ProviderStage::Quiesced);
            drop(console);
            // The reader is never touched while terminal cleanup owns TX.
            drop(peer);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
    #[test]
    fn terminal_transport_drained_provider_rebinds_stop_key_and_blocks_capture() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use polly::event_manager::{BarrierGeneration, OperationId};
        use std::time::Duration;

        for already_quiesced in [false, true] {
            let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
            let rng = Arc::new(Mutex::new(Rng::new().unwrap()));
            let mut transport = MmioTransport::new(
                memory,
                Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
                rng,
                None,
            )
            .unwrap();
            transport.set_attachment_address(0x1000).unwrap();
            let pause = BarrierRequest {
                key: BarrierKey {
                    operation: OperationId(1),
                    generation: BarrierGeneration(1),
                },
                deadline: Instant::now() + Duration::from_secs(5),
            };
            transport.begin_quiesce(pause).unwrap();
            if already_quiesced {
                assert!(transport.poll_quiesce(pause.key).unwrap().is_ready());
                transport.capture_transport(pause.key).unwrap();
            }
            let stop = BarrierRequest {
                key: BarrierKey {
                    operation: OperationId(2),
                    ..pause.key
                },
                ..pause
            };
            assert!(transport.poll_stop(stop).unwrap().is_ready());
            assert_eq!(transport.lifecycle_snapshot().stage, ProviderStage::Stopped);
            assert!(transport.poll_stop(stop).unwrap().is_ready());
            assert!(transport.capture_transport(stop.key).is_err());
            assert!(transport.capture_transport(pause.key).is_err());
            let changed_deadline = BarrierRequest {
                deadline: stop.deadline + Duration::from_secs(1),
                ..stop
            };
            assert_eq!(
                transport.poll_stop(changed_deadline).unwrap_err().fault,
                ProviderFault::ForeignBarrier
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
    #[test]
    fn terminal_transport_active_unsupported_reset_false_retains_owner_and_failure() {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use polly::event_manager::{BarrierGeneration, OperationId};
        use std::time::Duration;

        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vsock = Arc::new(Mutex::new(
            Vsock::new(3, None, None, TsiFlags::HIJACK_INET).unwrap(),
        ));
        let mut transport = MmioTransport::new(
            memory,
            Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
            vsock.clone(),
            None,
        )
        .unwrap();
        transport.activate();
        assert!(vsock.lock().expect("actual vsock owner").is_activated());
        let stop = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let failure = transport.poll_stop(stop).unwrap_err();
        assert_eq!(failure.fault, ProviderFault::Unsupported);
        assert_eq!(
            transport.lifecycle_snapshot().stage,
            ProviderStage::Stopping
        );
        assert_eq!(transport.poll_stop(stop).unwrap_err(), failure);
        assert!(vsock.lock().expect("retained vsock owner").is_activated());
        assert!(transport.capture_device_state(stop.key).is_err());
        assert!(transport.capture_transport(stop.key).is_err());
    }
}
