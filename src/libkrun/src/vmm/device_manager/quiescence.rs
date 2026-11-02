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
    transition: Transition,
}

impl Default for DeviceQuiescence {
    fn default() -> Self {
        Self {
            attachments: Vec::new(),
            legacy: Vec::new(),
            request: None,
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
    ) {
        self.attachments.push(TransportAttachment {
            identity,
            transport,
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

    pub fn preflight_quiesce(&self) -> Result<(), ManagerError> {
        if let Some(legacy) = self
            .legacy
            .iter()
            .find(|participant| participant.handle.is_none())
        {
            return Err(self.error(None, ManagerFault::MissingLegacyProvider(legacy.identity)));
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        for legacy in &self.legacy {
            if let Some(LegacyHandle::InterruptController(controller)) = &legacy.handle {
                let controller = controller
                    .try_lock()
                    .map_err(|_| self.error(None, ManagerFault::LockBusy))?;
                if !controller.execution_state_supported() {
                    return Err(
                        self.error(None, ManagerFault::MissingLegacyProvider(legacy.identity))
                    );
                }
            }
        }
        for (index, attachment) in self.attachments.iter().enumerate() {
            let transport = attachment
                .transport
                .try_lock()
                .map_err(|error| self.lock_error(index, error))?;
            transport
                .preflight_quiesce()
                .map_err(|fault| self.error(Some(index), ManagerFault::Provider(fault)))?;
        }
        Ok(())
    }

    pub fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ManagerError> {
        if self.request.is_some() {
            return Err(self.error(None, ManagerFault::InvalidTransition));
        }
        self.check_deadline(request)?;
        self.preflight_quiesce()?;
        self.request = Some(request);
        self.transition = Transition::Quiesce;
        for index in 0..self.attachments.len() {
            self.attachments[index].attempted = true;
            let handle = self.attachments[index].transport.clone();
            let mut transport = handle
                .try_lock()
                .map_err(|error| self.lock_error(index, error))?;
            let result = transport.begin_quiesce(request);
            let snapshot = transport.lifecycle_snapshot();
            self.record(index, snapshot);
            result.map_err(|error| self.error(Some(index), ManagerFault::Lifecycle(error)))?;
        }
        self.check_deadline(request)
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
                let transport = attachment
                    .transport
                    .try_lock()
                    .map_err(|error| self.lock_error(index, error))?;
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
    ) -> Result<(), ManagerError> {
        self.check_key(fenced, Transition::Quiesce)?;
        self.check_deadline(request)?;
        if request.key.generation != fenced.generation
            || request.key.operation == fenced.operation
            || !self.quiescence_settled(fenced)?
        {
            return Err(self.error(None, ManagerFault::InvalidTransition));
        }
        self.request = Some(request);
        self.transition = Transition::Resume;
        for index in 0..self.attachments.len() {
            if !self.attachments[index].accepted {
                continue;
            }
            self.attachments[index].resume_attempted = true;
            let handle = self.attachments[index].transport.clone();
            let mut transport = handle
                .try_lock()
                .map_err(|error| self.lock_error(index, error))?;
            let result = transport.begin_resume(request);
            let snapshot = transport.lifecycle_snapshot();
            self.record(index, snapshot);
            result.map_err(|error| self.error(Some(index), ManagerFault::Lifecycle(error)))?;
        }
        self.check_deadline(request)
    }

    pub fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ManagerError> {
        self.poll(key, Transition::Resume)
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
            Transition::Quiesce => attachment.accepted |= snapshot.quiesce_accepted,
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
    use crate::vmm::device_manager::quiescence::{
        DeviceQuiescence, LegacyAttachment, LegacyKind, ManagerFault,
    };

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
    fn inactive_rng_refusal_retains_exact_attachment_and_no_accepted_work() {
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
            memory,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(Rng::new().unwrap())),
            None,
        )
        .unwrap();
        transport.set_attachment_address(0xd000_0000).unwrap();
        let mut inventory = DeviceQuiescence::default();
        let identity = AttachmentIdentity {
            device_type: DeviceType::Virtio(4),
            configured_id: "entropy0".into(),
            address: 0xd000_0000,
            irq: 5,
        };
        inventory.retain_transport(identity.clone(), Arc::new(Mutex::new(transport)));
        let error = inventory.preflight_quiesce().unwrap_err();
        assert_eq!(error.attachment, Some(identity.clone()));
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let error = inventory.begin_quiesce(request).unwrap_err();
        assert_eq!(error.attachment, Some(identity));
        assert!(!inventory.attachments[0].attempted);
        assert!(!inventory.attachments[0].accepted);
        assert!(inventory.request.is_none());
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
}
