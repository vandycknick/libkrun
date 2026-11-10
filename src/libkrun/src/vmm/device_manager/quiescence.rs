// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Attachment ownership, not a whole-machine barrier: CPUs, callbacks, legacy
//! providers, maintenance and native IRQ routes must also acknowledge the cut.

use std::sync::{Arc, Mutex, TryLockError};
use std::task::Poll;
use std::time::Instant;

use devices::DeviceType;
use devices::virtio::MmioTransport;
use devices::virtio::lifecycle::{LifecycleError, LifecycleSnapshot, ProviderFault, ProviderStage};
use polly::event_manager::{BarrierKey, BarrierRequest};

use devices::legacy::state::{LegacyPayload, LegacyState};
type LiveDevice = (
    AttachmentIdentity,
    Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
);

#[derive(Clone)]
pub enum LegacyHandle {
    Serial(Arc<Mutex<devices::legacy::Serial>>),
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    InterruptController(devices::legacy::IrqChip),
    #[cfg(target_arch = "x86_64")]
    Cmos(Arc<Mutex<devices::legacy::Cmos>>),
    #[cfg(target_arch = "x86_64")]
    I8042(Arc<Mutex<devices::legacy::I8042Device>>),
    #[cfg(target_arch = "aarch64")]
    Rtc(Arc<Mutex<devices::legacy::RTC>>),
    #[cfg(target_arch = "aarch64")]
    Gpio(Arc<Mutex<devices::legacy::Gpio>>),
}

pub struct LegacyParticipant {
    pub identity: LegacyAttachment,
    pub handle: Option<LegacyHandle>,
}

impl LegacyHandle {
    pub fn preflight(&self) -> Result<Poll<()>, String> {
        match self {
            Self::Serial(serial) => Self::preflight_locked(serial, |serial| {
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                {
                    serial.preflight_state().map_err(|error| error.to_string())
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    let _ = serial;
                    Err("unsupported legacy serial architecture".into())
                }
            }),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::InterruptController(controller) => {
                Self::preflight_locked(controller, |controller| {
                    if controller.execution_state_supported() {
                        Ok(())
                    } else {
                        Err("native interrupt controller provider unavailable".into())
                    }
                })
            }
            #[cfg(target_arch = "x86_64")]
            Self::Cmos(device) => Self::preflight_locked(device, |_| Ok(())),
            #[cfg(target_arch = "x86_64")]
            Self::I8042(device) => Self::preflight_locked(device, |device| {
                device
                    .capture_state()
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }),
            #[cfg(target_arch = "aarch64")]
            Self::Rtc(device) => Self::preflight_locked(device, |device| {
                device
                    .capture_state()
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }),
            #[cfg(target_arch = "aarch64")]
            Self::Gpio(device) => Self::preflight_locked(device, |_| Ok(())),
        }
    }

    fn preflight_locked<T: ?Sized>(
        device: &Arc<Mutex<T>>,
        check: impl FnOnce(&T) -> Result<(), String>,
    ) -> Result<Poll<()>, String> {
        match device.try_lock() {
            Ok(device) => check(&device).map(Poll::Ready),
            Err(TryLockError::WouldBlock) => Ok(Poll::Pending),
            Err(TryLockError::Poisoned(_)) => Err("legacy participant lock poisoned".into()),
        }
    }

    pub fn capture(&self) -> Result<LegacyPayload, String> {
        match self {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::InterruptController(_) => {
                Err("controller state belongs to the native execution cut".into())
            }
            Self::Serial(device) => {
                let device = device.try_lock().map_err(|_| "serial lock")?;
                #[cfg(target_arch = "x86_64")]
                {
                    device
                        .capture_state()
                        .map(LegacyPayload::Uart)
                        .map_err(|error| error.to_string())
                }
                #[cfg(target_arch = "aarch64")]
                {
                    device
                        .capture_state()
                        .map(LegacyPayload::Pl011)
                        .map_err(|error| error.to_string())
                }
                #[cfg(target_arch = "riscv64")]
                {
                    let _ = device;
                    Err("riscv execution state unsupported".into())
                }
            }
            #[cfg(target_arch = "x86_64")]
            Self::Cmos(device) => Ok(LegacyPayload::Cmos(
                device.try_lock().map_err(|_| "CMOS lock")?.capture_state(),
            )),
            #[cfg(target_arch = "x86_64")]
            Self::I8042(device) => device
                .try_lock()
                .map_err(|_| "i8042 lock")?
                .capture_state()
                .map(LegacyPayload::I8042)
                .map_err(|error| error.to_string()),
            #[cfg(target_arch = "aarch64")]
            Self::Rtc(device) => device
                .try_lock()
                .map_err(|_| "RTC lock")?
                .capture_state()
                .map(LegacyPayload::Rtc)
                .map_err(|error| error.to_string()),
            #[cfg(target_arch = "aarch64")]
            Self::Gpio(device) => Ok(LegacyPayload::Gpio(
                device.try_lock().map_err(|_| "GPIO lock")?.capture_state(),
            )),
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn install(&self, _payload: &LegacyPayload) -> Result<(), String> {
        Err("execution state excluded for this architecture".into())
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn install(&self, payload: &LegacyPayload) -> Result<(), String> {
        let result = match (self, payload) {
            #[cfg(target_arch = "x86_64")]
            (Self::Serial(device), LegacyPayload::Uart(state)) => device
                .try_lock()
                .map_err(|_| "serial lock")?
                .install_state(state),
            #[cfg(target_arch = "aarch64")]
            (Self::Serial(device), LegacyPayload::Pl011(state)) => device
                .try_lock()
                .map_err(|_| "serial lock")?
                .install_state(state),
            #[cfg(target_arch = "x86_64")]
            (Self::Cmos(device), LegacyPayload::Cmos(state)) => device
                .try_lock()
                .map_err(|_| "CMOS lock")?
                .install_state(state),
            #[cfg(target_arch = "x86_64")]
            (Self::I8042(device), LegacyPayload::I8042(state)) => device
                .try_lock()
                .map_err(|_| "i8042 lock")?
                .install_state(state),
            #[cfg(target_arch = "aarch64")]
            (Self::Rtc(device), LegacyPayload::Rtc(state)) => device
                .try_lock()
                .map_err(|_| "RTC lock")?
                .install_state(state),
            #[cfg(target_arch = "aarch64")]
            (Self::Gpio(device), LegacyPayload::Gpio(state)) => device
                .try_lock()
                .map_err(|_| "GPIO lock")?
                .install_state(state),
            _ => return Err("legacy payload kind mismatch".into()),
        };
        result.map_err(|error| error.to_string())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentIdentity {
    pub device_type: DeviceType,
    pub configured_id: String,
    pub address: u64,
    pub irq: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyKind {
    #[cfg(target_arch = "x86_64")]
    Cmos,
    #[cfg(target_arch = "x86_64")]
    I8042,
    Serial,
    #[cfg(target_arch = "aarch64")]
    Rtc,
    #[cfg(target_arch = "aarch64")]
    Gpio,
    InterruptController,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyAttachment {
    pub kind: LegacyKind,
    pub address: u64,
    pub irq: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum ManagerFault {
    Provider(ProviderFault),
    Lifecycle(LifecycleError),
    MissingLegacyProvider(LegacyAttachment),
    LegacyState(LegacyAttachment, String),
    ForeignBarrier,
    InvalidTransition,
    Deadline,
    LockBusy,
    LockPoisoned,
}

impl std::fmt::Display for ManagerFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provider(fault) => write!(f, "provider admission failed: {fault:?}"),
            Self::Lifecycle(error) => write!(f, "provider transition failed: {error}"),
            Self::MissingLegacyProvider(attachment) => write!(
                f,
                "missing {:?} provider at {:#x}, IRQ {:?}",
                attachment.kind, attachment.address, attachment.irq
            ),
            Self::LegacyState(attachment, error) => write!(
                f,
                "legacy {:?} at {:#x}, IRQ {:?}: {error}",
                attachment.kind, attachment.address, attachment.irq
            ),
            Self::ForeignBarrier => write!(f, "foreign barrier"),
            Self::InvalidTransition => write!(f, "invalid transition"),
            Self::Deadline => write!(f, "deadline expired"),
            Self::LockBusy => write!(f, "participant lock busy"),
            Self::LockPoisoned => write!(f, "participant lock poisoned"),
        }
    }
}

impl std::error::Error for ManagerFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lifecycle(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ManagerError {
    pub key: Option<BarrierKey>,
    pub attachment: Option<AttachmentIdentity>,
    pub fault: ManagerFault,
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "device barrier {:?}: {} at {:?}",
            self.key, self.fault, self.attachment
        )
    }
}

impl std::error::Error for ManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.fault)
    }
}

pub struct TransportAttachment {
    pub identity: AttachmentIdentity,
    pub transport: Arc<Mutex<MmioTransport>>,
    // The transport's device binding is immutable. Retain it before vCPUs can
    // own the transport, so live activation never needs the MMIO bus lock.
    device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
    /// A begin attempt is retained before entering a fallible provider operation.
    pub attempted: bool,
    pub accepted: bool,
    pub resume_attempted: bool,
    pub resume_accepted: bool,
    pub failure: Option<LifecycleError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transition {
    Quiesce,
    Resume,
}

pub struct DeviceQuiescence {
    attachments: Vec<TransportAttachment>,
    legacy: Vec<LegacyParticipant>,
    request: Option<BarrierRequest>,
    /// Original cut authority while a bounded resume begin is still progressing.
    resume_fenced: Option<BarrierKey>,
    transition: Transition,
}

impl Default for DeviceQuiescence {
    fn default() -> Self {
        Self {
            attachments: Vec::new(),
            legacy: Vec::new(),
            request: None,
            resume_fenced: None,
            transition: Transition::Quiesce,
        }
    }
}

impl DeviceQuiescence {
    pub fn request(&self) -> Option<BarrierRequest> {
        self.request
    }

    pub fn legacy_attachments(&self) -> Vec<LegacyAttachment> {
        self.legacy
            .iter()
            .map(|participant| participant.identity)
            .collect()
    }

    pub fn has_transports(&self) -> bool {
        !self.attachments.is_empty()
    }

    pub fn attachment_identities(&self) -> Vec<AttachmentIdentity> {
        self.attachments
            .iter()
            .map(|attachment| attachment.identity.clone())
            .collect()
    }
    pub(crate) fn live_devices(&self) -> Vec<LiveDevice> {
        self.attachments
            .iter()
            .map(|attachment| (attachment.identity.clone(), attachment.device.clone()))
            .collect()
    }

    pub(crate) fn has_attachment_conflict(&self, device_type: u32, configured_id: &str) -> bool {
        self.attachments.iter().any(|entry| {
            entry.identity.device_type == DeviceType::Virtio(device_type)
                || entry.identity.configured_id == configured_id
        })
    }

    pub(crate) fn interrupt_binding(
        &self,
        device_type: u32,
        configured_id: &str,
    ) -> Result<devices::virtio::InterruptTransport, ManagerError> {
        let mut matches = self.attachments.iter().enumerate().filter(|(_, entry)| {
            entry.identity.device_type == DeviceType::Virtio(device_type)
                && entry.identity.configured_id == configured_id
        });
        let (index, attachment) = matches
            .next()
            .ok_or_else(|| self.error(None, ManagerFault::InvalidTransition))?;
        if matches.next().is_some() {
            return Err(self.error(None, ManagerFault::InvalidTransition));
        }
        let transport = attachment
            .transport
            .try_lock()
            .map_err(|error| self.lock_error(index, error))?;
        Ok(transport.interrupt_transport().clone())
    }

    pub fn lifecycle_snapshots(
        &self,
    ) -> Result<Vec<(AttachmentIdentity, LifecycleSnapshot)>, ManagerError> {
        self.attachments
            .iter()
            .enumerate()
            .map(|(index, attachment)| {
                let transport = attachment
                    .transport
                    .try_lock()
                    .map_err(|error| self.lock_error(index, error))?;
                Ok((attachment.identity.clone(), transport.lifecycle_snapshot()))
            })
            .collect()
    }

    #[cfg(feature = "native-device-probe")]
    pub fn diagnostic_irq_snapshots(
        &self,
    ) -> Result<Vec<(AttachmentIdentity, devices::virtio::MmioIrqProbeSnapshot)>, ManagerError>
    {
        self.attachments
            .iter()
            .enumerate()
            .map(|(index, attachment)| {
                let transport = attachment
                    .transport
                    .try_lock()
                    .map_err(|error| self.lock_error(index, error))?;
                Ok((
                    attachment.identity.clone(),
                    transport.diagnostic_irq_snapshot(),
                ))
            })
            .collect()
    }

    #[cfg(feature = "native-device-probe")]
    pub fn diagnostic_hold_irq_acks(&self, address: u64, hold: bool) -> Result<(), ManagerError> {
        let (index, attachment) = self
            .attachments
            .iter()
            .enumerate()
            .find(|(_, attachment)| attachment.identity.address == address)
            .ok_or_else(|| self.error(None, ManagerFault::InvalidTransition))?;
        attachment
            .transport
            .try_lock()
            .map_err(|error| self.lock_error(index, error))?
            .diagnostic_hold_irq_acks(hold)
            .map_err(|fault| self.error(Some(index), ManagerFault::Provider(fault)))
    }

    pub fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        states: &[crate::vmm::execution::device_restore::RestoreDeviceBinding],
    ) -> Result<(), String> {
        if self.request.is_some()
            || self.attachments.len() != states.len()
            || self
                .attachments
                .iter()
                .zip(states)
                .any(|(actual, saved)| actual.identity != saved.identity)
        {
            return Err("restore attachment inventory mismatch".into());
        }
        self.request = Some(request);
        self.transition = Transition::Quiesce;
        for (attachment, saved) in self.attachments.iter_mut().zip(states) {
            attachment.attempted = true;
            attachment.accepted = true;
            attachment
                .transport
                .try_lock()
                .map_err(|_| "restore transport lock")?
                .prepare_restore(request, &saved.state, &saved.payload)
                .map_err(|error| format!("restore {:?}: {error}", saved.identity))?;
        }
        Ok(())
    }

    pub fn register_legacy_events(
        &self,
        events: &mut polly::event_manager::EventManager,
    ) -> Result<(), String> {
        for participant in &self.legacy {
            match &participant.handle {
                Some(LegacyHandle::Serial(serial)) => {
                    events.add_subscriber(serial.clone()).map_err(|error| {
                        format!("legacy callback {:?}: {error:?}", participant.identity)
                    })?
                }
                #[cfg(target_arch = "aarch64")]
                Some(LegacyHandle::Gpio(gpio)) => {
                    events.add_subscriber(gpio.clone()).map_err(|error| {
                        format!("legacy callback {:?}: {error:?}", participant.identity)
                    })?
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn flush_for_capture(&self, key: BarrierKey) -> Result<(), ManagerError> {
        if !self.fully_quiesced(key)? {
            return Err(self.error(None, ManagerFault::InvalidTransition));
        }
        for (index, attachment) in self.attachments.iter().enumerate() {
            attachment
                .transport
                .try_lock()
                .map_err(|error| self.lock_error(index, error))?
                .flush_for_capture(key)
                .map_err(|error| self.error(Some(index), ManagerFault::Lifecycle(error)))?;
        }
        Ok(())
    }

    pub fn capture_devices(
        &self,
        key: BarrierKey,
    ) -> Result<Vec<crate::vmm::execution::device_restore::DeviceRecord>, ManagerError> {
        if !self.fully_quiesced(key)? {
            return Err(self.error(None, ManagerFault::InvalidTransition));
        }
        let mut records = Vec::with_capacity(self.attachments.len());
        for (index, attachment) in self.attachments.iter().enumerate() {
            let transport = attachment
                .transport
                .try_lock()
                .map_err(|error| self.lock_error(index, error))?;
            let state = transport
                .capture_transport(key)
                .map_err(|error| self.error(Some(index), ManagerFault::Lifecycle(error)))?;
            let payload = transport
                .capture_device_state(key)
                .map_err(|error| self.error(Some(index), ManagerFault::Lifecycle(error)))?;
            records.push(crate::vmm::execution::device_restore::DeviceRecord {
                identity: attachment.identity.clone(),
                state,
                payload,
            });
        }
        Ok(records)
    }

    pub fn retain_legacy_device(&mut self, identity: LegacyAttachment, handle: LegacyHandle) {
        self.legacy.push(LegacyParticipant {
            identity,
            handle: Some(handle),
        });
    }

    pub fn capture_legacy(&self) -> Result<Vec<LegacyState>, String> {
        let mut states = Vec::with_capacity(self.legacy.len());
        for participant in &self.legacy {
            if participant.identity.kind == LegacyKind::InterruptController {
                continue;
            }
            let payload = participant
                .handle
                .as_ref()
                .ok_or_else(|| {
                    format!(
                        "missing {:?} provider at {:#x}",
                        participant.identity.kind, participant.identity.address
                    )
                })?
                .capture()
                .map_err(|error| {
                    format!(
                        "{:?} at {:#x}: {error}",
                        participant.identity.kind, participant.identity.address
                    )
                })?;
            states.push(LegacyState {
                address: participant.identity.address,
                irq: participant.identity.irq,
                payload,
            });
        }
        states.sort_by_key(|state| (state.payload.tag(), state.address));
        Ok(states)
    }

    pub fn install_legacy(&self, states: &[LegacyState]) -> Result<(), String> {
        let expected = self.capture_legacy()?;
        if expected.len() != states.len()
            || expected.iter().zip(states).any(|(current, saved)| {
                (current.payload.tag(), current.address, current.irq)
                    != (saved.payload.tag(), saved.address, saved.irq)
            })
        {
            return Err("legacy installation inventory mismatch".into());
        }
        for state in states {
            let participant = self
                .legacy
                .iter()
                .find(|participant| {
                    participant.identity.address == state.address
                        && participant.identity.irq == state.irq
                })
                .ok_or("missing legacy participant")?;
            participant
                .handle
                .as_ref()
                .ok_or("missing legacy provider")?
                .install(&state.payload)?;
        }
        Ok(())
    }

    pub fn retain_transport(
        &mut self,
        identity: AttachmentIdentity,
        transport: Arc<Mutex<MmioTransport>>,
        device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
    ) {
        self.attachments.push(TransportAttachment {
            identity,
            transport,
            device,
            attempted: false,
            accepted: false,
            resume_attempted: false,
            resume_accepted: false,
            failure: None,
        });
    }

    pub fn retain_legacy(&mut self, attachment: LegacyAttachment) {
        self.legacy.push(LegacyParticipant {
            identity: attachment,
            handle: None,
        });
    }

    pub fn preflight_legacy(&self) -> Result<(), ManagerError> {
        if let Some(legacy) = self
            .legacy
            .iter()
            .find(|participant| participant.handle.is_none())
        {
            return Err(self.error(None, ManagerFault::MissingLegacyProvider(legacy.identity)));
        }
        let mut busy = false;
        for legacy in &self.legacy {
            if let Some(handle) = &legacy.handle {
                match handle.preflight().map_err(|error| {
                    self.error(None, ManagerFault::LegacyState(legacy.identity, error))
                })? {
                    Poll::Ready(()) => {}
                    Poll::Pending => busy = true,
                }
            }
        }
        if busy {
            Err(self.error(None, ManagerFault::LockBusy))
        } else {
            Ok(())
        }
    }

    pub fn preflight_quiesce(&self) -> Result<(), ManagerError> {
        let mut busy = match self.preflight_legacy() {
            Ok(()) => None,
            Err(error) if matches!(error.fault, ManagerFault::LockBusy) => Some(error),
            Err(error) => return Err(error),
        };
        for (index, attachment) in self.attachments.iter().enumerate() {
            let transport = match attachment.transport.try_lock() {
                Ok(transport) => transport,
                Err(TryLockError::WouldBlock) => {
                    busy.get_or_insert_with(|| self.error(Some(index), ManagerFault::LockBusy));
                    continue;
                }
                Err(error) => return Err(self.lock_error(index, error)),
            };
            match transport.preflight_quiesce() {
                Ok(()) => {}
                Err(ProviderFault::LockBusy) => {
                    busy.get_or_insert_with(|| self.error(Some(index), ManagerFault::LockBusy));
                }
                Err(fault) => return Err(self.error(Some(index), ManagerFault::Provider(fault))),
            }
        }
        match busy {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn admit_quiesce(&mut self, request: BarrierRequest) -> Result<Poll<()>, ManagerError> {
        self.check_deadline(request)?;
        match self.request {
            None => {
                match self.preflight_quiesce() {
                    Ok(()) => {}
                    Err(error) if matches!(error.fault, ManagerFault::LockBusy) => {
                        return Ok(Poll::Pending);
                    }
                    Err(error) => return Err(error),
                }
                self.request = Some(request);
                self.transition = Transition::Quiesce;
            }
            Some(previous) if previous == request && self.transition == Transition::Quiesce => {}
            Some(_) => return Err(self.error(None, ManagerFault::InvalidTransition)),
        }
        Ok(Poll::Ready(()))
    }

    /// Each call makes at most one nonblocking admission attempt per untouched
    /// attachment. Accepted transitions remain owned and are never resubmitted.
    pub fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<Poll<()>, ManagerError> {
        if self.admit_quiesce(request)?.is_pending() {
            return Ok(Poll::Pending);
        }
        let mut pending = false;
        for index in 0..self.attachments.len() {
            if self.attachments[index].attempted {
                continue;
            }
            self.check_deadline(request)?;
            let handle = self.attachments[index].transport.clone();
            let mut transport = match handle.try_lock() {
                Ok(transport) => transport,
                Err(TryLockError::WouldBlock) => {
                    pending = true;
                    continue;
                }
                Err(error) => return Err(self.lock_error(index, error)),
            };
            self.attachments[index].attempted = true;
            let result = transport.begin_quiesce(request);
            let snapshot = transport.lifecycle_snapshot();
            if result.as_ref().is_err_and(|error| {
                error.fault == ProviderFault::LockBusy
                    && !error.accepted
                    && snapshot
                        .quiesce_request
                        .is_none_or(|prior| prior.key != request.key)
            }) {
                self.attachments[index].attempted = false;
                pending = true;
                continue;
            }
            self.record(index, snapshot);
            result.map_err(|error| self.error(Some(index), ManagerFault::Lifecycle(error)))?;
        }
        self.check_deadline(request)?;
        Ok(if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        })
    }

    /// Late polling reconciles actual ownership even after the original deadline.
    /// Errors are retained; settled ownership is observable separately below.
    pub fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<()>, ManagerError> {
        self.poll(key, Transition::Quiesce)
    }

    pub fn quiescence_settled(&self, key: BarrierKey) -> Result<bool, ManagerError> {
        self.check_key(key, Transition::Quiesce)?;
        for (index, attachment) in self.attachments.iter().enumerate() {
            if attachment.accepted {
                let transport = match attachment.transport.try_lock() {
                    Ok(transport) => transport,
                    Err(TryLockError::WouldBlock) => return Ok(false),
                    Err(error) => return Err(self.lock_error(index, error)),
                };
                let snapshot = transport.lifecycle_snapshot();
                if snapshot.stage != ProviderStage::Quiesced
                    || snapshot
                        .quiesce_request
                        .is_none_or(|request| request.key != key)
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub fn fully_quiesced(&self, key: BarrierKey) -> Result<bool, ManagerError> {
        self.check_key(key, Transition::Quiesce)?;
        if self
            .legacy
            .iter()
            .any(|participant| participant.handle.is_none())
            || self
                .attachments
                .iter()
                .any(|attachment| !attachment.accepted)
        {
            return Ok(false);
        }
        self.quiescence_settled(key)
    }

    /// Also used for explicit cancellation, but only after every accepted old
    /// transition has settled. Untouched attachments are never reset or restarted.
    pub fn begin_resume(
        &mut self,
        fenced: BarrierKey,
        request: BarrierRequest,
    ) -> Result<Poll<()>, ManagerError> {
        self.check_deadline(request)?;
        if request.key.generation != fenced.generation || request.key.operation == fenced.operation
        {
            return Err(self.error(None, ManagerFault::InvalidTransition));
        }
        if self.transition != Transition::Resume || self.request != Some(request) {
            self.check_key(fenced, Transition::Quiesce)?;
            if !self.quiescence_settled(fenced)? {
                return Ok(Poll::Pending);
            }
            self.request = Some(request);
            self.transition = Transition::Resume;
            self.resume_fenced = Some(fenced);
        } else if self.resume_fenced != Some(fenced) {
            return Err(self.error(None, ManagerFault::ForeignBarrier));
        }
        let mut pending = false;
        for index in 0..self.attachments.len() {
            if !self.attachments[index].accepted || self.attachments[index].resume_attempted {
                continue;
            }
            self.check_deadline(request)?;
            let handle = self.attachments[index].transport.clone();
            let mut transport = match handle.try_lock() {
                Ok(transport) => transport,
                Err(TryLockError::WouldBlock) => {
                    pending = true;
                    continue;
                }
                Err(error) => return Err(self.lock_error(index, error)),
            };
            self.attachments[index].resume_attempted = true;
            let result = transport.begin_resume(request);
            let snapshot = transport.lifecycle_snapshot();
            if result.as_ref().is_err_and(|error| {
                error.fault == ProviderFault::LockBusy
                    && !error.accepted
                    && snapshot
                        .request
                        .is_none_or(|prior| prior.key != request.key)
            }) {
                self.attachments[index].resume_attempted = false;
                pending = true;
                continue;
            }
            self.record(index, snapshot);
            result.map_err(|error| self.error(Some(index), ManagerFault::Lifecycle(error)))?;
        }
        self.check_deadline(request)?;
        Ok(if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        })
    }

    pub fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ManagerError> {
        self.poll(key, Transition::Resume)
    }

    pub fn poll_stop(&mut self, request: BarrierRequest) -> Result<Poll<()>, ManagerError> {
        self.poll_stop_inner(request, false)
    }

    pub fn poll_cleanup(&mut self, request: BarrierRequest) -> Result<Poll<()>, ManagerError> {
        self.poll_stop_inner(request, true)
    }

    fn poll_stop_inner(
        &mut self,
        request: BarrierRequest,
        cleanup: bool,
    ) -> Result<Poll<()>, ManagerError> {
        let mut pending = false;
        let mut failure = None;
        for (index, attachment) in self.attachments.iter().enumerate() {
            let mut transport = match attachment.transport.try_lock() {
                Ok(transport) => transport,
                Err(TryLockError::WouldBlock) => {
                    pending = true;
                    continue;
                }
                Err(error) => {
                    failure.get_or_insert_with(|| self.lock_error(index, error));
                    continue;
                }
            };
            let stopped = if cleanup {
                transport.poll_cleanup(request)
            } else {
                transport.poll_stop(request)
            };
            match stopped {
                Ok(Poll::Ready(())) => {}
                Ok(Poll::Pending) => pending = true,
                Err(error) => {
                    failure.get_or_insert_with(|| {
                        self.error(Some(index), ManagerFault::Lifecycle(error))
                    });
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        })
    }

    fn poll(&mut self, key: BarrierKey, transition: Transition) -> Result<Poll<()>, ManagerError> {
        let request = self.check_key(key, transition)?;
        let mut pending = false;
        let mut failure = None;
        for index in 0..self.attachments.len() {
            if !self.attachments[index].accepted {
                if transition == Transition::Quiesce {
                    pending = true;
                }
                continue;
            }
            if transition == Transition::Resume && !self.attachments[index].resume_accepted {
                pending = true;
                continue;
            }
            let handle = self.attachments[index].transport.clone();
            let mut transport = match handle.try_lock() {
                Ok(transport) => transport,
                Err(TryLockError::WouldBlock) => {
                    pending = true;
                    continue;
                }
                Err(error) => return Err(self.lock_error(index, error)),
            };
            let result = match transition {
                Transition::Quiesce => transport.poll_quiesce(key),
                Transition::Resume => transport.poll_resume(key),
            };
            self.record(index, transport.lifecycle_snapshot());
            match result {
                Ok(Poll::Pending) => pending = true,
                Ok(Poll::Ready(())) => {}
                Err(error) => {
                    failure.get_or_insert_with(|| {
                        self.error(Some(index), ManagerFault::Lifecycle(error))
                    });
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        self.check_deadline(request)?;
        if pending {
            return Ok(Poll::Pending);
        }
        if transition == Transition::Resume {
            self.request = None;
            self.resume_fenced = None;
            for attachment in &mut self.attachments {
                attachment.attempted = false;
                attachment.accepted = false;
                attachment.resume_attempted = false;
                attachment.resume_accepted = false;
            }
        }
        Ok(Poll::Ready(()))
    }

    fn record(&mut self, index: usize, snapshot: LifecycleSnapshot) {
        let attachment = &mut self.attachments[index];
        match self.transition {
            Transition::Quiesce => {
                if snapshot.quiesce_request == self.request {
                    attachment.accepted |= snapshot.quiesce_accepted;
                }
            }
            Transition::Resume => {
                if snapshot.request == self.request {
                    attachment.resume_accepted |= snapshot.accepted;
                }
            }
        }
        if let Some(error) = snapshot.failure {
            attachment.failure.get_or_insert(error);
        }
    }

    fn check_key(
        &self,
        key: BarrierKey,
        transition: Transition,
    ) -> Result<BarrierRequest, ManagerError> {
        match self.request {
            Some(request) if request.key == key && self.transition == transition => Ok(request),
            _ => Err(self.error(None, ManagerFault::ForeignBarrier)),
        }
    }

    fn check_deadline(&self, request: BarrierRequest) -> Result<(), ManagerError> {
        if Instant::now() >= request.deadline {
            return Err(self.error(None, ManagerFault::Deadline));
        }
        Ok(())
    }

    fn lock_error<T>(&self, index: usize, error: TryLockError<T>) -> ManagerError {
        self.error(
            Some(index),
            match error {
                TryLockError::WouldBlock => ManagerFault::LockBusy,
                TryLockError::Poisoned(_) => ManagerFault::LockPoisoned,
            },
        )
    }

    fn error(&self, index: Option<usize>, fault: ManagerFault) -> ManagerError {
        ManagerError {
            key: self.request.map(|request| request.key),
            attachment: index.map(|index| self.attachments[index].identity.clone()),
            fault,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use crate::vmm::device_manager::quiescence::{
        DeviceQuiescence, LegacyAttachment, LegacyKind, ManagerFault,
    };

    #[test]
    #[cfg(not(feature = "tee"))]
    fn live_inventory_retains_actual_vsock_while_mmio_owner_holds_transport() {
        use crate::vmm::device_manager::quiescence::AttachmentIdentity;
        use devices::legacy::DummyIrqChip;
        use devices::virtio::vsock::{TsiFlags, Vsock};
        use devices::virtio::{MmioTransport, VirtioDevice};
        use std::sync::{Arc, Mutex};
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let device: Arc<Mutex<dyn VirtioDevice>> = Arc::new(Mutex::new(
            Vsock::new(3, None, None, TsiFlags::empty()).unwrap(),
        ));
        let transport = Arc::new(Mutex::new(
            MmioTransport::new(
                crate::vmm::memory::runtime_memory_for_test(
                    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
                ),
                DummyIrqChip::new().into(),
                device.clone(),
                None,
            )
            .unwrap(),
        ));
        let identity = AttachmentIdentity {
            device_type: devices::DeviceType::Virtio(19),
            configured_id: "vsock".into(),
            address: 0xd000_0000,
            irq: 7,
        };
        let mut inventory = DeviceQuiescence::default();
        inventory.retain_transport(identity.clone(), transport.clone(), device.clone());
        let held = transport.try_lock().unwrap();
        let actual = inventory.live_devices();
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].0, identity);
        assert!(Arc::ptr_eq(&actual[0].1, &device));
        assert!(Arc::ptr_eq(&actual[0].1, &held.device()));
        assert!(actual[0].1.try_lock().is_ok());
    }

    #[test]
    fn missing_legacy_provider_names_actual_attachment() {
        let mut inventory = DeviceQuiescence::default();
        let serial = LegacyAttachment {
            kind: LegacyKind::Serial,
            address: 0x3e8,
            irq: Some(4),
        };
        inventory.retain_legacy(serial);
        assert!(matches!(inventory.preflight_quiesce().unwrap_err().fault,
            ManagerFault::MissingLegacyProvider(actual) if actual == serial));
    }

    #[test]
    #[cfg(not(feature = "tee"))]
    fn inactive_rng_provider_retains_exact_attachment_and_transport_cut() {
        use crate::vmm::device_manager::quiescence::AttachmentIdentity;
        use devices::DeviceType;
        use devices::legacy::DummyIrqChip;
        use devices::virtio::{MmioTransport, Rng};
        use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut transport = MmioTransport::new(
            crate::vmm::memory::runtime_memory_for_test(memory),
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            None,
        )
        .unwrap();
        transport.set_attachment_address(0xd000_0000).unwrap();
        transport.set_irq_line(5);
        let mut inventory = DeviceQuiescence::default();
        let identity = AttachmentIdentity {
            device_type: DeviceType::Virtio(4),
            configured_id: "entropy0".into(),
            address: 0xd000_0000,
            irq: 5,
        };
        let device = transport.device();
        inventory.retain_transport(identity.clone(), Arc::new(Mutex::new(transport)), device);
        let interrupt = inventory.interrupt_binding(4, "entropy0").unwrap();
        if let Ok(transport) = inventory.attachments[0].transport.try_lock() {
            assert!(interrupt.same_binding(transport.interrupt_transport()));
        } else {
            panic!("uncontended transport binding lock");
        }
        assert!(inventory.interrupt_binding(4, "foreign-id").is_err());
        assert!(inventory.interrupt_binding(0x5347, "entropy0").is_err());
        {
            let Ok(_guard) = inventory.attachments[0].transport.try_lock() else {
                panic!("uncontended transport binding lock");
            };
            assert!(matches!(inventory.interrupt_binding(4, "entropy0"),
                Err(error) if matches!(error.fault, ManagerFault::LockBusy)));
        }
        inventory.preflight_quiesce().unwrap();
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(10),
        };
        assert!(inventory.begin_quiesce(request).unwrap().is_ready());
        assert!(inventory.poll_quiesce(request.key).unwrap().is_ready());
        assert!(inventory.attachments[0].attempted);
        assert!(inventory.attachments[0].accepted);
        let records = inventory.capture_devices(request.key).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].identity, identity);
        assert!(!records[0].state.activated);
        assert_eq!(records[0].payload.len(), 32);
        let transport = inventory.attachments[0].transport.clone();
        let device = inventory.attachments[0].device.clone();
        inventory.retain_transport(identity, transport, device);
        assert!(matches!(inventory.interrupt_binding(4, "entropy0"),
            Err(error) if matches!(error.fault, ManagerFault::InvalidTransition)));
    }

    #[test]
    fn manager_errors_preserve_nested_transition_and_attachment_details() {
        use crate::vmm::device_manager::quiescence::ManagerError;
        use devices::virtio::lifecycle::{LifecycleError, ProviderFault, ProviderStage};
        use polly::event_manager::{BarrierGeneration, BarrierKey, OperationId};
        use std::error::Error;

        let lifecycle = LifecycleError {
            key: BarrierKey {
                operation: OperationId(7),
                generation: BarrierGeneration(3),
            },
            stage: ProviderStage::Quiescing,
            accepted: true,
            fault: ProviderFault::Worker,
        };
        let error = ManagerError {
            key: Some(lifecycle.key),
            attachment: None,
            fault: ManagerFault::Lifecycle(lifecycle),
        };
        assert!(error.to_string().contains(&lifecycle.to_string()));
        assert_eq!(
            error.source().unwrap().source().unwrap().to_string(),
            lifecycle.to_string()
        );
        let legacy = ManagerFault::MissingLegacyProvider(LegacyAttachment {
            kind: LegacyKind::Serial,
            address: 0x3e8,
            irq: Some(4),
        });
        let detail = legacy.to_string();
        assert!(detail.contains("Serial"));
        assert!(detail.contains("0x3e8"));
        assert!(detail.contains("Some(4)"));
        assert!(
            ManagerFault::Provider(ProviderFault::Unsupported)
                .to_string()
                .contains("Unsupported")
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn legacy_resume_preflight_retains_real_closed_output_fault() {
        use crate::vmm::device_manager::quiescence::LegacyHandle;
        use devices::{BusDevice, legacy::Serial};
        use std::os::unix::net::UnixStream;
        use std::sync::{Arc, Mutex};
        use utils::eventfd::{EFD_NONBLOCK, EventFd};
        let (output, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let serial = Arc::new(Mutex::new(Serial::new_out(
            EventFd::new(EFD_NONBLOCK).unwrap(),
            Box::new(output),
        )));
        let identity = LegacyAttachment {
            kind: LegacyKind::Serial,
            address: 0x3f8,
            irq: Some(4),
        };
        let mut inventory = DeviceQuiescence::default();
        inventory.retain_legacy_device(identity, LegacyHandle::Serial(serial.clone()));
        inventory.preflight_legacy().unwrap();
        let Ok(held) = serial.lock() else {
            panic!("real UART lock poisoned");
        };
        assert!(matches!(
            inventory.preflight_legacy().unwrap_err().fault,
            ManagerFault::LockBusy
        ));
        drop(held);
        let Ok(mut device) = serial.lock() else {
            panic!("real UART lock poisoned");
        };
        device.write(0, 0, b"x");
        drop(device);
        assert!(matches!(
            inventory.preflight_legacy().unwrap_err().fault,
            ManagerFault::LegacyState(actual, _) if actual == identity
        ));
        let Ok(device) = serial.lock() else {
            panic!("real UART lock poisoned");
        };
        assert!(device.capture_state().is_err());
    }

    #[cfg(not(feature = "tee"))]
    struct AdmissionRng {
        inventory: DeviceQuiescence,
        transport: std::sync::Arc<std::sync::Mutex<devices::virtio::MmioTransport>>,
        device: std::sync::Arc<std::sync::Mutex<devices::virtio::Rng>>,
    }

    #[cfg(not(feature = "tee"))]
    fn admission_rng(address: u64, bound: bool) -> AdmissionRng {
        use crate::vmm::device_manager::quiescence::AttachmentIdentity;
        use devices::legacy::DummyIrqChip;
        use devices::virtio::{MmioTransport, Rng};
        use std::sync::{Arc, Mutex};
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let device = Arc::new(Mutex::new(Rng::new().unwrap()));
        let mut transport = MmioTransport::new(
            crate::vmm::memory::runtime_memory_for_test(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
            ),
            DummyIrqChip::new().into(),
            device.clone(),
            None,
        )
        .unwrap();
        if bound {
            transport.set_attachment_address(address).unwrap();
        }
        transport.set_irq_line(5);
        let transport = Arc::new(Mutex::new(transport));
        let mut inventory = DeviceQuiescence::default();
        inventory.retain_transport(
            AttachmentIdentity {
                device_type: devices::DeviceType::Virtio(4),
                configured_id: format!("rng-{address:x}"),
                address,
                irq: 5,
            },
            transport.clone(),
            device.clone(),
        );
        AdmissionRng {
            inventory,
            transport,
            device,
        }
    }

    #[cfg(not(feature = "tee"))]
    fn admission_request(operation: u64) -> polly::event_manager::BarrierRequest {
        use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(1),
            },
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
        }
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn device_admission_contention_completes_same_owned_request_without_replay() {
        let AdmissionRng {
            mut inventory,
            transport,
            device,
        } = admission_rng(0xd000_0000, true);
        let request = admission_request(1);
        let Ok(held) = transport.lock() else {
            panic!("real transport poisoned");
        };
        assert!(matches!(
            inventory.preflight_quiesce().unwrap_err().fault,
            ManagerFault::LockBusy
        ));
        assert!(inventory.begin_quiesce(request).unwrap().is_pending());
        assert!(inventory.request().is_none());
        assert!(!inventory.attachments[0].attempted);
        drop(held);
        let Ok(held) = device.lock() else {
            panic!("real RNG poisoned");
        };
        assert!(inventory.begin_quiesce(request).unwrap().is_pending());
        assert!(inventory.request().is_none());
        assert!(!inventory.attachments[0].accepted);
        drop(held);
        assert!(inventory.begin_quiesce(request).unwrap().is_ready());
        let Ok(held) = transport.lock() else {
            panic!("real transport poisoned");
        };
        assert!(inventory.poll_quiesce(request.key).unwrap().is_pending());
        drop(held);
        assert!(inventory.poll_quiesce(request.key).unwrap().is_ready());
        assert!(inventory.fully_quiesced(request.key).unwrap());
        let resume = admission_request(2);
        let Ok(held) = device.lock() else {
            panic!("real RNG poisoned");
        };
        assert!(
            inventory
                .begin_resume(request.key, resume)
                .unwrap()
                .is_pending()
        );
        assert!(!inventory.attachments[0].resume_attempted);
        assert!(!inventory.attachments[0].resume_accepted);
        let wrong_fenced = polly::event_manager::BarrierKey {
            operation: polly::event_manager::OperationId(99),
            ..request.key
        };
        assert!(matches!(
            inventory
                .begin_resume(wrong_fenced, resume)
                .unwrap_err()
                .fault,
            ManagerFault::ForeignBarrier
        ));
        drop(held);
        assert!(
            inventory
                .begin_resume(request.key, resume)
                .unwrap()
                .is_ready()
        );
        assert!(inventory.attachments[0].resume_accepted);
        // Re-polling admission cannot reissue an already accepted provider begin.
        assert!(
            inventory
                .begin_resume(request.key, resume)
                .unwrap()
                .is_ready()
        );
        assert!(inventory.poll_resume(resume.key).unwrap().is_ready());
        assert!(inventory.request().is_none());
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn device_admission_contention_does_not_hide_real_unsupported_inventory() {
        let AdmissionRng {
            mut inventory,
            transport,
            ..
        } = admission_rng(0xd000_0000, true);
        let mut unsupported = admission_rng(0xd000_1000, false);
        inventory
            .attachments
            .append(&mut unsupported.inventory.attachments);
        let Ok(unbound_held) = unsupported.device.lock() else {
            panic!("real unbound RNG poisoned");
        };
        let Ok(held) = transport.lock() else {
            panic!("real transport poisoned");
        };
        assert!(matches!(
            inventory.preflight_quiesce().unwrap_err().fault,
            ManagerFault::Provider(devices::virtio::lifecycle::ProviderFault::Unsupported)
        ));
        assert!(inventory.begin_quiesce(admission_request(1)).is_err());
        assert!(inventory.request().is_none());
        assert!(
            inventory
                .attachments
                .iter()
                .all(|attachment| !attachment.attempted)
        );
        drop(held);
        drop(unbound_held);
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn device_admission_contention_does_not_hide_real_poisoned_transport() {
        let AdmissionRng {
            mut inventory,
            transport,
            ..
        } = admission_rng(0xd000_0000, true);
        let mut poisoned = admission_rng(0xd000_1000, true);
        inventory
            .attachments
            .append(&mut poisoned.inventory.attachments);
        let poison = poisoned.transport.clone();
        assert!(
            std::thread::spawn(move || {
                let Ok(_held) = poison.lock() else {
                    panic!("unexpected earlier poison");
                };
                panic!("poison actual transport mutex");
            })
            .join()
            .is_err()
        );
        let Ok(held) = transport.lock() else {
            panic!("real transport poisoned");
        };
        let error = inventory.preflight_quiesce().unwrap_err();
        assert!(matches!(error.fault, ManagerFault::LockPoisoned));
        assert_eq!(error.attachment.unwrap().address, 0xd000_1000);
        assert!(inventory.request().is_none());
        drop(held);
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn device_admission_expired_request_never_starts_contended_attachment() {
        let AdmissionRng {
            mut inventory,
            transport,
            ..
        } = admission_rng(0xd000_0000, true);
        let mut request = admission_request(1);
        request.deadline = std::time::Instant::now();
        let Ok(held) = transport.lock() else {
            panic!("real transport poisoned");
        };
        assert!(matches!(
            inventory.begin_quiesce(request).unwrap_err().fault,
            ManagerFault::Deadline
        ));
        assert!(inventory.request().is_none());
        assert!(!inventory.attachments[0].attempted);
        assert!(!inventory.attachments[0].accepted);
        drop(held);
    }

    #[cfg(not(feature = "tee"))]
    fn admission_snapshot(
        transport: &std::sync::Arc<std::sync::Mutex<devices::virtio::MmioTransport>>,
    ) -> devices::virtio::lifecycle::LifecycleSnapshot {
        let Ok(transport) = transport.lock() else {
            panic!("actual transport poisoned");
        };
        transport.lifecycle_snapshot()
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn device_admission_two_real_rng_staggered_resume_is_terminal_for_same_key() {
        use devices::virtio::lifecycle::ProviderStage;
        for inner_contention in [false, true] {
            let AdmissionRng {
                mut inventory,
                transport,
                ..
            } = admission_rng(0xd000_0000, true);
            let mut second = admission_rng(0xd000_1000, true);
            inventory
                .attachments
                .append(&mut second.inventory.attachments);
            let pause = admission_request(1);
            assert!(inventory.begin_quiesce(pause).unwrap().is_ready());
            assert!(inventory.poll_quiesce(pause.key).unwrap().is_ready());
            let resume = admission_request(2);
            assert!(
                inventory
                    .begin_resume(pause.key, resume)
                    .unwrap()
                    .is_ready()
            );
            let mut observe_pending = || {
                assert!(inventory.poll_resume(resume.key).unwrap().is_pending());
                let snapshot = admission_snapshot(&transport);
                assert_eq!(snapshot.stage, ProviderStage::Running);
                assert_eq!(snapshot.request, Some(resume));
                snapshot
            };
            let completed = if inner_contention {
                let Ok(held) = second.device.lock() else {
                    panic!("actual RNG poisoned");
                };
                let completed = observe_pending();
                drop(held);
                completed
            } else {
                let Ok(held) = second.transport.lock() else {
                    panic!("actual transport poisoned");
                };
                let completed = observe_pending();
                drop(held);
                completed
            };
            assert!(inventory.poll_resume(resume.key).unwrap().is_ready());
            assert!(inventory.request().is_none());
            assert_eq!(admission_snapshot(&transport), completed);
            assert_eq!(
                admission_snapshot(&second.transport).stage,
                ProviderStage::Running
            );
        }
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn cleanup_two_real_transports_retains_accepted_stop_and_admits_unstarted_after_timeout() {
        use devices::virtio::lifecycle::{ProviderFault, ProviderStage};
        use std::time::{Duration, Instant};
        for admitted_second in [true, false] {
            let AdmissionRng {
                mut inventory,
                transport,
                ..
            } = admission_rng(0xd000_0000, true);
            let mut second = admission_rng(0xd000_1000, true);
            inventory
                .attachments
                .append(&mut second.inventory.attachments);
            let mut request = admission_request(70);
            request.deadline = Instant::now() + Duration::from_millis(40);
            if admitted_second {
                assert!(inventory.poll_cleanup(request).unwrap().is_pending());
            }
            let held = match second.transport.lock() {
                Ok(held) => held,
                Err(error) => panic!("actual second transport poisoned: {error}"),
            };
            let limit = Instant::now() + Duration::from_secs(5);
            loop {
                assert!(inventory.poll_cleanup(request).unwrap().is_pending());
                if admission_snapshot(&transport).stage == ProviderStage::Stopped {
                    break;
                }
                assert!(Instant::now() < limit);
                std::thread::yield_now();
            }
            let completed = admission_snapshot(&transport);
            assert_eq!(completed.request, Some(request));
            assert_eq!(held.lifecycle_snapshot().accepted, admitted_second);
            if admitted_second {
                assert_eq!(held.lifecycle_snapshot().request, Some(request));
                assert_eq!(held.lifecycle_snapshot().stage, ProviderStage::Stopping);
            } else {
                assert_eq!(held.lifecycle_snapshot().request, None);
                assert_eq!(held.lifecycle_snapshot().stage, ProviderStage::Running);
            }
            while Instant::now() < request.deadline {
                std::thread::yield_now();
            }
            assert!(inventory.poll_cleanup(request).unwrap().is_pending());
            assert_eq!(admission_snapshot(&transport), completed);
            drop(held);
            loop {
                match inventory.poll_cleanup(request) {
                    Ok(Poll::Ready(())) => break,
                    Ok(Poll::Pending) => {}
                    Err(error) => panic!("actual transport cleanup failed: {error:?}"),
                }
                assert!(Instant::now() < limit);
                std::thread::yield_now();
            }
            assert_eq!(admission_snapshot(&transport), completed);
            let final_second = admission_snapshot(&second.transport);
            assert_eq!(final_second.stage, ProviderStage::Stopped);
            let accepted = final_second.request.unwrap();
            assert_eq!(accepted.key, request.key);
            let mut second_transport = match second.transport.lock() {
                Ok(held) => held,
                Err(error) => panic!("actual second transport poisoned: {error}"),
            };
            if admitted_second {
                assert_eq!(accepted, request);
                assert_eq!(final_second.failure.unwrap().fault, ProviderFault::Deadline);
                assert_eq!(
                    second_transport.poll_stop(request).unwrap_err().fault,
                    ProviderFault::Deadline
                );
            } else {
                assert!(accepted.deadline > request.deadline);
                assert_eq!(
                    second_transport.poll_stop(request).unwrap_err().fault,
                    ProviderFault::ForeignBarrier
                );
            }
            assert!(second_transport.capture_transport(accepted.key).is_err());
            assert!(second_transport.capture_device_state(accepted.key).is_err());
        }
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn device_admission_partial_real_begins_resume_and_new_key_never_replay_owners() {
        use devices::virtio::lifecycle::ProviderStage;
        let AdmissionRng {
            mut inventory,
            transport,
            device,
        } = admission_rng(0xd000_0000, true);
        let mut second = admission_rng(0xd000_1000, true);
        inventory
            .attachments
            .append(&mut second.inventory.attachments);
        let pause = admission_request(1);
        // Use the actual production admission step, then introduce contention
        // before entering providers; no fabricated provider or acceptance state.
        assert!(inventory.admit_quiesce(pause).unwrap().is_ready());
        let Ok(held) = second.device.lock() else {
            panic!("actual RNG poisoned");
        };
        assert!(inventory.begin_quiesce(pause).unwrap().is_pending());
        assert_eq!(inventory.request(), Some(pause));
        assert!(inventory.attachments[0].accepted);
        assert!(!inventory.attachments[1].attempted);
        assert!(!inventory.attachments[1].accepted);
        let first_owned = admission_snapshot(&transport);
        assert_eq!(first_owned.stage, ProviderStage::Quiescing);
        assert!(inventory.begin_quiesce(pause).unwrap().is_pending());
        assert_eq!(admission_snapshot(&transport), first_owned);
        drop(held);
        assert!(inventory.begin_quiesce(pause).unwrap().is_ready());
        assert_eq!(admission_snapshot(&transport), first_owned);
        assert!(inventory.poll_quiesce(pause.key).unwrap().is_ready());

        let resume = admission_request(2);
        let Ok(held) = second.device.lock() else {
            panic!("actual RNG poisoned");
        };
        assert!(
            inventory
                .begin_resume(pause.key, resume)
                .unwrap()
                .is_pending()
        );
        assert!(inventory.attachments[0].resume_accepted);
        assert!(!inventory.attachments[1].resume_attempted);
        let first_released = admission_snapshot(&transport);
        assert!(
            inventory
                .begin_resume(pause.key, resume)
                .unwrap()
                .is_pending()
        );
        assert_eq!(admission_snapshot(&transport), first_released);
        drop(held);
        assert!(
            inventory
                .begin_resume(pause.key, resume)
                .unwrap()
                .is_ready()
        );
        assert!(inventory.poll_resume(resume.key).unwrap().is_ready());

        let previous = admission_snapshot(&transport);
        assert!(previous.accepted);
        assert_eq!(previous.request, Some(resume));
        let next = admission_request(3);
        assert!(inventory.admit_quiesce(next).unwrap().is_ready());
        let Ok(held) = device.lock() else {
            panic!("actual RNG poisoned");
        };
        assert!(inventory.begin_quiesce(next).unwrap().is_pending());
        assert!(!inventory.attachments[0].attempted);
        assert!(!inventory.attachments[0].accepted);
        assert!(inventory.attachments[1].accepted);
        assert_eq!(admission_snapshot(&transport), previous);
        drop(held);
        assert!(inventory.begin_quiesce(next).unwrap().is_ready());
        assert!(inventory.poll_quiesce(next.key).unwrap().is_ready());
        assert_eq!(admission_snapshot(&transport).quiesce_request, Some(next));
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn device_admission_partial_expiry_drains_and_cancels_only_actual_accepted_owner() {
        use devices::BusDevice;
        use devices::virtio::lifecycle::ProviderStage;
        use std::time::{Duration, Instant};
        let AdmissionRng {
            mut inventory,
            transport,
            ..
        } = admission_rng(0xd000_0000, true);
        let mut second = admission_rng(0xd000_1000, true);
        inventory
            .attachments
            .append(&mut second.inventory.attachments);
        {
            let Ok(mut transport) = second.transport.lock() else {
                panic!("actual transport poisoned");
            };
            for (offset, value) in [
                (0x70, 1u32),
                (0x70, 3),
                (0x24, 1),
                (0x20, 1),
                (0x70, 11),
                (0x30, 0),
                (0x38, 8),
                (0x80, 0x1234),
                (0x90, 0x5678),
                (0xa0, 0x9abc),
            ] {
                transport.write(0, offset, &value.to_le_bytes());
            }
        }
        // Queue size/addresses are write-only MMIO registers. Negotiate
        // FEATURES_OK above, then obtain the real complete queue baseline at
        // an ordinary completed cut rather than reading those registers as 0.
        let baseline = admission_request(1);
        assert!(inventory.begin_quiesce(baseline).unwrap().is_ready());
        assert!(inventory.poll_quiesce(baseline.key).unwrap().is_ready());
        let queue_before = {
            let Ok(transport) = second.transport.lock() else {
                panic!("actual transport poisoned");
            };
            transport.capture_transport(baseline.key).unwrap().queues
        };
        assert_eq!(queue_before.len(), 1);
        assert_eq!(queue_before[0].size, 8);
        assert!(!queue_before[0].ready);
        assert_eq!(queue_before[0].desc_table, 0x1234);
        assert_eq!(queue_before[0].avail_ring, 0x5678);
        assert_eq!(queue_before[0].used_ring, 0x9abc);
        let baseline_resume = admission_request(2);
        assert!(
            inventory
                .begin_resume(baseline.key, baseline_resume)
                .unwrap()
                .is_ready()
        );
        assert!(
            inventory
                .poll_resume(baseline_resume.key)
                .unwrap()
                .is_ready()
        );
        let untouched = admission_snapshot(&second.transport);
        let mut pause = admission_request(3);
        pause.deadline = Instant::now() + Duration::from_secs(1);
        assert!(inventory.admit_quiesce(pause).unwrap().is_ready());
        let Ok(held) = second.transport.lock() else {
            panic!("actual transport poisoned");
        };
        assert!(inventory.begin_quiesce(pause).unwrap().is_pending());
        assert!(inventory.attachments[0].accepted);
        assert!(!inventory.attachments[1].attempted);
        std::thread::sleep(pause.deadline.saturating_duration_since(Instant::now()));
        assert!(matches!(
            inventory.begin_quiesce(pause).unwrap_err().fault,
            ManagerFault::Deadline
        ));
        assert!(inventory.poll_quiesce(pause.key).is_err());
        assert_eq!(
            admission_snapshot(&transport).stage,
            ProviderStage::Quiesced
        );
        assert!(inventory.quiescence_settled(pause.key).unwrap());
        assert!(!inventory.attachments[1].attempted);
        assert_eq!(held.lifecycle_snapshot(), untouched);

        let cancel = admission_request(4);
        assert!(
            inventory
                .begin_resume(pause.key, cancel)
                .unwrap()
                .is_ready()
        );
        assert!(inventory.poll_resume(cancel.key).unwrap().is_ready());
        assert_eq!(admission_snapshot(&transport).stage, ProviderStage::Running);
        assert_eq!(held.lifecycle_snapshot(), untouched);
        drop(held);
        let next = admission_request(5);
        assert!(inventory.begin_quiesce(next).unwrap().is_ready());
        assert!(inventory.poll_quiesce(next.key).unwrap().is_ready());
        let resume = admission_request(6);
        assert!(inventory.begin_resume(next.key, resume).unwrap().is_ready());
        assert!(inventory.poll_resume(resume.key).unwrap().is_ready());
        let final_cut = admission_request(7);
        assert!(inventory.begin_quiesce(final_cut).unwrap().is_ready());
        assert!(inventory.poll_quiesce(final_cut.key).unwrap().is_ready());
        let Ok(transport) = second.transport.lock() else {
            panic!("actual transport poisoned");
        };
        assert_eq!(
            transport.capture_transport(final_cut.key).unwrap().queues,
            queue_before
        );
    }
}
