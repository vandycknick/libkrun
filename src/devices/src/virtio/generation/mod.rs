// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Acknowledged config-only generation protocol. The unused queue belongs to
//! the transport escrow; neither entropy nor acknowledgements travel through it.
//! Once a generation is published, guest reset is terminal and unacknowledged.
//! The original queues and callback journal remain owned until native stop.

use std::cell::Cell;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use polly::event_manager::{BarrierKey, BarrierRequest};
use rand::{TryRng, rngs::SysRng};
use utils::state::{Reader, Writer};

use crate::virtio::lifecycle::{
    CallbackState, DormantDeviceContext, ProviderBeginError, ProviderFault, QuiesceCompletion,
    ResumeAcceptance, VirtioStateProvider,
};
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    RuntimeGuestMemory, VirtioDevice,
};

pub const DEVICE_TYPE: u32 = 0x5347;
pub const DEVICE_ID: &str = "silo-vmgenid";
pub const STATE_LIMIT: u32 = 256;
const FEATURES: u64 = 1 << 32;
const QUEUES: [QueueConfig; 1] = [QueueConfig::new(1)];
const VERSION: u32 = 1;
const READY: u32 = 1;
const ERROR: u32 = 2;
const CLOCK: u32 = 4;
const CLOCK_ONLY_CAP: u32 = 8;
const STATUS_MASK: u32 = READY | ERROR | CLOCK | CLOCK_ONLY_CAP;
const SYNC_CLOCK: u32 = 1;
const CLOCK_ONLY: u32 = 2;
const CONFIG_WORDS: usize = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationRequest {
    FreshIdentity([u8; 16]),
    ClockOnly,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GenerationTuple {
    pub sequence: u64,
    pub id: [u8; 16],
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessedGeneration {
    pub sequence: u64,
    pub id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationFailure {
    Deadline,
    DriverError,
    InvalidStatus,
    Notification,
    Reset,
    Stopped,
    Release,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationReceipt {
    pub request: GenerationTuple,
    pub completed_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationObservation {
    Pending,
    Acknowledged(GenerationReceipt),
    Failed(GenerationFailure),
}

#[derive(Clone, Debug)]
pub struct GenerationAttempt(Arc<AttemptRecord>);

#[derive(Debug)]
struct AttemptRecord {
    cut: BarrierKey,
    request: GenerationTuple,
    deadline: Instant,
    outcome: Mutex<GenerationObservation>,
}

impl GenerationAttempt {
    pub fn request(&self) -> GenerationTuple {
        self.0.request
    }

    pub fn deadline(&self) -> Instant {
        self.0.deadline
    }

    pub fn cut(&self) -> BarrierKey {
        self.0.cut
    }

    pub fn same_attempt(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub fn observe(&self, now: Instant) -> GenerationObservation {
        self.transition(now, None)
    }

    fn transition(
        &self,
        now: Instant,
        proposed: Option<GenerationObservation>,
    ) -> GenerationObservation {
        let mut outcome = match self.0.outcome.lock() {
            Ok(outcome) => outcome,
            Err(error) => {
                let mut outcome = error.into_inner();
                if *outcome == GenerationObservation::Pending {
                    *outcome = GenerationObservation::Failed(GenerationFailure::Poisoned);
                }
                return *outcome;
            }
        };
        if *outcome == GenerationObservation::Pending {
            if now >= self.0.deadline {
                *outcome = GenerationObservation::Failed(GenerationFailure::Deadline);
            } else if let Some(proposed) = proposed {
                *outcome = proposed;
            }
        }
        *outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationError {
    Provider(ProviderFault),
    Entropy,
    Failed(GenerationFailure),
    PendingAttempt,
    IdentityCollision,
    SequenceExhausted,
    UnboundInterrupt,
    AlreadyBound,
    ForeignAttempt,
}

/// Samples identity bytes only; publication still requires the exact stopped cut.
pub fn fresh_identity() -> Result<[u8; 16], GenerationError> {
    let mut id = [0; 16];
    SysRng
        .try_fill_bytes(&mut id)
        .map_err(|_| GenerationError::Entropy)?;
    Ok(id)
}

impl fmt::Display for GenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "generation: {self:?}")
    }
}

impl std::error::Error for GenerationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationSnapshot {
    pub request: GenerationTuple,
    pub processed: ProcessedGeneration,
    pub driver_status: u32,
    pub clock_latch: u64,
    pub config_generation: Option<u32>,
    pub committed: Option<GenerationTuple>,
    pub attempt: Option<GenerationObservation>,
    pub protocol_failure: Option<GenerationFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtocolHistory {
    Empty,
    Pending,
    Acknowledged,
    Failed(GenerationFailure),
}

struct DecodedPayload {
    acked_features: u64,
    words: [u32; CONFIG_WORDS],
    committed: Option<GenerationTuple>,
    history: ProtocolHistory,
}

pub struct Generation {
    acked_features: u64,
    driver_status: u32,
    request: GenerationTuple,
    processed: ProcessedGeneration,
    clock_latch: Cell<u64>,
    committed: Option<GenerationTuple>,
    history: ProtocolHistory,
    attempt: Option<GenerationAttempt>,
    interrupt: Option<InterruptTransport>,
    queues: Option<Vec<DeviceQueue>>,
    device_state: DeviceState,
    callbacks: CallbackState,
    reset_failed: bool,
}

impl Default for Generation {
    fn default() -> Self {
        Self::new()
    }
}

impl Generation {
    pub fn validate_live_restore_payload(payload: &[u8]) -> Result<(), ProviderFault> {
        let saved = Self::decode_payload(payload)?;
        if saved.words[1] != 0x0d {
            return Err(ProviderFault::DeviceState);
        }
        Ok(())
    }

    pub fn new() -> Self {
        Self {
            acked_features: 0,
            driver_status: 0,
            request: GenerationTuple::default(),
            processed: ProcessedGeneration::default(),
            clock_latch: Cell::new(0),
            committed: None,
            history: ProtocolHistory::Empty,
            attempt: None,
            interrupt: None,
            queues: None,
            device_state: DeviceState::Inactive,
            callbacks: CallbackState::new(),
            reset_failed: false,
        }
    }

    pub fn bind_interrupt(&mut self, interrupt: InterruptTransport) -> Result<(), GenerationError> {
        if let Some(bound) = &self.interrupt {
            if !bound.same_binding(&interrupt) {
                return Err(GenerationError::AlreadyBound);
            }
        } else {
            self.interrupt = Some(interrupt);
        }
        Ok(())
    }

    pub fn prepare(
        &mut self,
        cut: BarrierKey,
        request: GenerationRequest,
        deadline: Instant,
    ) -> Result<GenerationAttempt, GenerationError> {
        self.prepare_at(cut, request, deadline, Instant::now())
    }

    fn prepare_at(
        &mut self,
        cut: BarrierKey,
        request: GenerationRequest,
        deadline: Instant,
        now: Instant,
    ) -> Result<GenerationAttempt, GenerationError> {
        self.callbacks
            .require_cut(cut)
            .map_err(GenerationError::Provider)?;
        if self.reset_failed {
            return Err(GenerationError::Failed(GenerationFailure::Reset));
        }
        if let Some(attempt) = &self.attempt {
            match attempt.observe(now) {
                GenerationObservation::Pending => {
                    if request == GenerationRequest::ClockOnly
                        && attempt.request().flags == SYNC_CLOCK | CLOCK_ONLY
                    {
                        return Ok(attempt.clone());
                    }
                    return Err(GenerationError::PendingAttempt);
                }
                GenerationObservation::Failed(cause) => return Err(GenerationError::Failed(cause)),
                GenerationObservation::Acknowledged(_) => {}
            }
        }
        if self.attempt.is_none()
            && request == GenerationRequest::ClockOnly
            && self.history == ProtocolHistory::Pending
        {
            return Err(GenerationError::PendingAttempt);
        }
        if now >= deadline {
            return Err(GenerationError::Failed(GenerationFailure::Deadline));
        }
        if self.driver_status & ERROR != 0 {
            return Err(GenerationError::Failed(GenerationFailure::DriverError));
        }
        let (id, flags) = match request {
            GenerationRequest::FreshIdentity(id) => {
                if id == [0; 16]
                    || id == self.request.id
                    || self.committed.is_some_and(|committed| committed.id == id)
                {
                    return Err(GenerationError::IdentityCollision);
                }
                (id, SYNC_CLOCK)
            }
            GenerationRequest::ClockOnly => (
                self.committed.map_or([0; 16], |committed| committed.id),
                SYNC_CLOCK | CLOCK_ONLY,
            ),
        };
        let sequence = self
            .request
            .sequence
            .checked_add(1)
            .ok_or(GenerationError::SequenceExhausted)?;
        let interrupt = self
            .interrupt
            .as_ref()
            .ok_or(GenerationError::UnboundInterrupt)?;
        let tuple = GenerationTuple {
            sequence,
            id,
            flags,
        };
        let attempt = GenerationAttempt(Arc::new(AttemptRecord {
            cut,
            request: tuple,
            deadline,
            outcome: Mutex::new(GenerationObservation::Pending),
        }));
        self.request = tuple;
        self.history = ProtocolHistory::Pending;
        self.attempt = Some(attempt.clone());
        interrupt.publish_config_change();
        Ok(attempt)
    }

    pub fn notify(&mut self, attempt: &GenerationAttempt) -> Result<(), GenerationError> {
        if self
            .attempt
            .as_ref()
            .is_none_or(|current| !current.same_attempt(attempt))
        {
            return Err(GenerationError::ForeignAttempt);
        }
        let now = Instant::now();
        if let GenerationObservation::Failed(cause) = attempt.observe(now) {
            return Err(GenerationError::Failed(cause));
        }
        if self.reset_failed {
            return Err(GenerationError::Failed(GenerationFailure::Reset));
        }
        if now >= attempt.deadline() {
            return Err(GenerationError::Failed(GenerationFailure::Deadline));
        }
        let interrupt = self
            .interrupt
            .as_ref()
            .ok_or(GenerationError::UnboundInterrupt)?;
        if interrupt.try_signal_config_change().is_err() {
            self.fail_attempt(GenerationFailure::Notification);
            self.callbacks.retain_fault(ProviderFault::Notification);
            return Err(GenerationError::Failed(GenerationFailure::Notification));
        }
        Ok(())
    }

    pub fn fail_attempt(&mut self, cause: GenerationFailure) {
        if let Some(attempt) = &self.attempt {
            attempt.transition(Instant::now(), Some(GenerationObservation::Failed(cause)));
        }
    }

    pub fn snapshot(&self) -> GenerationSnapshot {
        let attempt = self
            .attempt
            .as_ref()
            .map(|attempt| attempt.observe(Instant::now()));
        let protocol_failure = match attempt {
            Some(GenerationObservation::Failed(cause)) => Some(cause),
            None => match self.history {
                ProtocolHistory::Failed(cause) => Some(cause),
                _ => None,
            },
            _ => None,
        };
        GenerationSnapshot {
            request: self.request,
            processed: self.processed,
            driver_status: self.driver_status,
            clock_latch: self.clock_latch.get(),
            config_generation: self
                .interrupt
                .as_ref()
                .map(InterruptTransport::config_generation),
            committed: self.committed,
            attempt,
            protocol_failure,
        }
    }

    fn protocol_history(&self) -> ProtocolHistory {
        self.attempt.as_ref().map_or(self.history, |attempt| {
            match attempt.observe(Instant::now()) {
                GenerationObservation::Pending => ProtocolHistory::Pending,
                GenerationObservation::Acknowledged(_) => ProtocolHistory::Acknowledged,
                GenerationObservation::Failed(cause) => ProtocolHistory::Failed(cause),
            }
        })
    }

    fn commit_low(&mut self, now: Instant) {
        let Some(attempt) = &self.attempt else { return };
        if attempt.observe(now) != GenerationObservation::Pending {
            return;
        }
        let required = READY
            | if self.request.flags & SYNC_CLOCK != 0 {
                CLOCK
            } else {
                0
            }
            | if self.request.flags & CLOCK_ONLY != 0 {
                CLOCK_ONLY_CAP
            } else {
                0
            };
        if self.driver_status & ERROR != 0 {
            attempt.transition(
                now,
                Some(GenerationObservation::Failed(
                    GenerationFailure::DriverError,
                )),
            );
        } else if self.driver_status & required == required
            && self.request.sequence != 0
            && self.processed.sequence == self.request.sequence
            && self.processed.id == self.request.id
        {
            let receipt = GenerationReceipt {
                request: self.request,
                completed_at: now,
            };
            if attempt.transition(now, Some(GenerationObservation::Acknowledged(receipt)))
                == GenerationObservation::Acknowledged(receipt)
            {
                self.committed = Some(self.request);
            }
        }
    }

    fn read_word(&self, index: usize) -> u32 {
        match index {
            0 => VERSION,
            1 => self.driver_status,
            2 => self.request.sequence as u32,
            3 => (self.request.sequence >> 32) as u32,
            4..=7 => id_word(&self.request.id, index - 4),
            8 => self.processed.sequence as u32,
            9 => (self.processed.sequence >> 32) as u32,
            10..=13 => id_word(&self.processed.id, index - 10),
            14 => self.request.flags,
            15 => self.clock_latch.get() as u32,
            16 => (self.clock_latch.get() >> 32) as u32,
            _ => 0,
        }
    }

    fn latch_clock(&self, sample: u64) -> u32 {
        self.clock_latch.set(sample);
        sample as u32
    }

    fn write_at(&mut self, offset: u64, data: &[u8], now: Instant) {
        let Some(index) = config_index(offset, data.len()) else {
            return;
        };
        let Ok(bytes) = <[u8; 4]>::try_from(data) else {
            return;
        };
        let value = u32::from_le_bytes(bytes);
        match index {
            1 => {
                // Keep invalid status canonical and non-authorizing in captures.
                self.driver_status = value & STATUS_MASK;
                let failure = if value & !STATUS_MASK != 0 {
                    self.driver_status |= ERROR;
                    Some(GenerationFailure::InvalidStatus)
                } else if value & ERROR != 0 {
                    Some(GenerationFailure::DriverError)
                } else {
                    None
                };
                if let (Some(attempt), Some(cause)) = (&self.attempt, failure) {
                    attempt.transition(now, Some(GenerationObservation::Failed(cause)));
                }
            }
            8 => {
                self.processed.sequence =
                    (self.processed.sequence & !u64::from(u32::MAX)) | u64::from(value);
                self.commit_low(now);
            }
            9 => {
                self.processed.sequence =
                    u64::from(self.processed.sequence as u32) | (u64::from(value) << 32)
            }
            10..=13 => {
                let start = (index - 10) * 4;
                if let Some(word) = self.processed.id.get_mut(start..start + 4) {
                    word.copy_from_slice(&bytes);
                }
            }
            _ => {}
        }
    }

    fn decode_payload(payload: &[u8]) -> Result<DecodedPayload, ProviderFault> {
        fn decode(payload: &[u8]) -> Result<DecodedPayload, utils::state::Error> {
            if payload.len() > STATE_LIMIT as usize {
                return Err(utils::state::Error::Limit);
            }
            let mut reader = Reader::new(payload);
            if reader.u16()? != 1 || reader.u32()? != DEVICE_TYPE || reader.u64()? != FEATURES {
                return Err(utils::state::Error::Invalid("generation profile"));
            }
            let acked_features = reader.u64()?;
            if acked_features & !FEATURES != 0 {
                return Err(utils::state::Error::Invalid("generation features"));
            }
            let mut words = [0; CONFIG_WORDS];
            for word in &mut words {
                *word = reader.u32()?;
            }
            let committed = if reader.bool()? {
                Some(GenerationTuple {
                    sequence: reader.u64()?,
                    id: reader.fixed()?,
                    flags: reader.u32()?,
                })
            } else {
                None
            };
            let history = match reader.u8()? {
                0 => ProtocolHistory::Empty,
                1 => ProtocolHistory::Pending,
                2 => ProtocolHistory::Acknowledged,
                3 => ProtocolHistory::Failed(GenerationFailure::Deadline),
                4 => ProtocolHistory::Failed(GenerationFailure::DriverError),
                5 => ProtocolHistory::Failed(GenerationFailure::InvalidStatus),
                6 => ProtocolHistory::Failed(GenerationFailure::Notification),
                7 => ProtocolHistory::Failed(GenerationFailure::Reset),
                8 => ProtocolHistory::Failed(GenerationFailure::Stopped),
                9 => ProtocolHistory::Failed(GenerationFailure::Release),
                10 => ProtocolHistory::Failed(GenerationFailure::Poisoned),
                _ => return Err(utils::state::Error::Invalid("generation outcome")),
            };
            reader.finish()?;
            let request = tuple_from_words(&words);
            if words[0] != VERSION || words[1] & !STATUS_MASK != 0 || !valid_tuple(request) {
                return Err(utils::state::Error::Invalid("generation config"));
            }
            if let Some(committed) = committed
                && (committed.sequence == 0
                    || !valid_tuple(committed)
                    || committed.sequence > request.sequence
                    || (committed.sequence == request.sequence && committed != request))
            {
                return Err(utils::state::Error::Invalid("generation committed tuple"));
            }
            if (history == ProtocolHistory::Empty) != (request.sequence == 0)
                || (history == ProtocolHistory::Acknowledged && committed != Some(request))
            {
                return Err(utils::state::Error::Invalid("generation history"));
            }
            if request.flags & CLOCK_ONLY != 0
                && history != ProtocolHistory::Failed(GenerationFailure::Reset)
                && request.id != committed.map_or([0; 16], |tuple| tuple.id)
            {
                return Err(utils::state::Error::Invalid(
                    "generation clock-only identity",
                ));
            }
            Ok(DecodedPayload {
                acked_features,
                words,
                committed,
                history,
            })
        }
        decode(payload).map_err(|_| ProviderFault::DeviceState)
    }

    fn install_payload(&mut self, decoded: DecodedPayload) {
        self.acked_features = decoded.acked_features;
        self.driver_status = decoded.words[1];
        self.request = tuple_from_words(&decoded.words);
        self.processed.sequence = u64::from(decoded.words[8]) | (u64::from(decoded.words[9]) << 32);
        for (index, word) in decoded.words[10..14].iter().enumerate() {
            self.processed.id[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        self.clock_latch
            .set(u64::from(decoded.words[15]) | (u64::from(decoded.words[16]) << 32));
        self.committed = decoded.committed;
        self.history = decoded.history;
        self.attempt = None;
    }
}

fn config_index(offset: u64, length: usize) -> Option<usize> {
    if length != 4 || !offset.is_multiple_of(4) || offset >= (CONFIG_WORDS * 4) as u64 {
        return None;
    }
    usize::try_from(offset / 4).ok()
}

fn id_word(id: &[u8; 16], index: usize) -> u32 {
    id.get(index * 4..index * 4 + 4)
        .and_then(|word| <[u8; 4]>::try_from(word).ok())
        .map_or(0, u32::from_le_bytes)
}

fn tuple_from_words(words: &[u32; CONFIG_WORDS]) -> GenerationTuple {
    let mut id = [0; 16];
    for (index, word) in words[4..8].iter().enumerate() {
        id[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    GenerationTuple {
        sequence: u64::from(words[2]) | (u64::from(words[3]) << 32),
        id,
        flags: words[14],
    }
}

fn valid_tuple(tuple: GenerationTuple) -> bool {
    if tuple.sequence == 0 {
        tuple.id == [0; 16] && tuple.flags == 0
    } else {
        matches!(tuple.flags, 0 | SYNC_CLOCK | 3)
            && (tuple.flags & CLOCK_ONLY != 0 || tuple.id != [0; 16])
    }
}

impl VirtioDevice for Generation {
    fn avail_features(&self) -> u64 {
        FEATURES
    }
    fn acked_features(&self) -> u64 {
        self.acked_features
    }
    fn set_acked_features(&mut self, features: u64) {
        self.acked_features = features & FEATURES;
    }
    fn device_type(&self) -> u32 {
        DEVICE_TYPE
    }
    fn device_name(&self) -> &str {
        DEVICE_ID
    }
    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        let Some(index) = config_index(offset, data.len()) else {
            return;
        };
        let value = if index == 15 {
            let sample = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
                .unwrap_or(0);
            self.latch_clock(sample)
        } else {
            self.read_word(index)
        };
        data.copy_from_slice(&value.to_le_bytes());
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.write_at(offset, data, Instant::now());
    }

    fn activate(
        &mut self,
        memory: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.is_activated()
            || self.reset_failed
            || queues.len() != QUEUES.len()
            || !self.callbacks.admission_open()
            || queues.iter().any(|queue| queue.queue.get_max_size() != 1)
            || self.bind_interrupt(interrupt.clone()).is_err()
        {
            return Err(ActivateError::BadActivate);
        }
        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(memory, interrupt);
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

    fn reset_required(&self) -> bool {
        self.is_activated() || self.request.sequence != 0 || self.reset_failed
    }

    fn reset(&mut self) -> bool {
        if self.reset_failed || self.request.sequence != 0 {
            self.fail_attempt(GenerationFailure::Reset);
            self.reset_failed = true;
            return false;
        }
        self.fail_attempt(GenerationFailure::Reset);
        self.attempt = None;
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        self.acked_features = 0;
        self.driver_status = 0;
        self.processed = ProcessedGeneration::default();
        self.clock_latch.set(0);
        self.committed = None;
        self.history = ProtocolHistory::Empty;
        self.callbacks = CallbackState::new();
        true
    }
}

impl VirtioStateProvider for Generation {
    fn preflight(&self) -> Result<(), ProviderFault> {
        self.callbacks.preflight(&self.queues)?;
        if self
            .queues
            .as_ref()
            .is_some_and(|queues| queues.len() != QUEUES.len())
        {
            return Err(ProviderFault::QueueCount);
        }
        if self
            .queues
            .as_ref()
            .is_some_and(|queues| queues.iter().any(|queue| queue.queue.get_max_size() != 1))
        {
            return Err(ProviderFault::QueueState);
        }
        Ok(())
    }

    fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError> {
        self.callbacks.begin_quiesce(request, &mut self.queues)
    }

    fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.callbacks.poll_quiesce(key, &mut self.queues)
    }
    fn validate_terminal_drain(&self, key: BarrierKey) -> Result<(), ProviderFault> {
        self.callbacks.validate_terminal_drain(key, &self.queues)?;
        self.preflight()
    }

    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance {
        let count = if self.is_activated() { QUEUES.len() } else { 0 };
        if queues.iter().any(|queue| queue.queue.get_max_size() != 1) {
            return ResumeAcceptance::Rejected {
                queues,
                fault: ProviderFault::QueueState,
            };
        }
        self.callbacks
            .begin_resume(request, queues, &mut self.queues, count)
    }

    fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        self.preflight()?;
        self.callbacks.poll_resume(key)
    }

    fn state_limit(&self) -> u32 {
        STATE_LIMIT
    }

    fn capture_payload(&self, key: BarrierKey) -> Result<Vec<u8>, ProviderFault> {
        self.callbacks.require_cut(key)?;
        // Failed reset retains native cleanup ownership, not portable continuation.
        if self.reset_failed {
            return Err(ProviderFault::InvalidTransition);
        }
        let encode = || -> Result<Vec<u8>, utils::state::Error> {
            let mut writer = Writer::new(STATE_LIMIT as usize);
            writer.u16(1)?;
            writer.u32(DEVICE_TYPE)?;
            writer.u64(FEATURES)?;
            writer.u64(self.acked_features)?;
            for index in 0..CONFIG_WORDS {
                writer.u32(self.read_word(index))?;
            }
            writer.bool(self.committed.is_some())?;
            if let Some(committed) = self.committed {
                writer.u64(committed.sequence)?;
                writer.fixed(&committed.id)?;
                writer.u32(committed.flags)?;
            }
            writer.u8(match self.protocol_history() {
                ProtocolHistory::Empty => 0,
                ProtocolHistory::Pending => 1,
                ProtocolHistory::Acknowledged => 2,
                ProtocolHistory::Failed(GenerationFailure::Deadline) => 3,
                ProtocolHistory::Failed(GenerationFailure::DriverError) => 4,
                ProtocolHistory::Failed(GenerationFailure::InvalidStatus) => 5,
                ProtocolHistory::Failed(GenerationFailure::Notification) => 6,
                ProtocolHistory::Failed(GenerationFailure::Reset) => 7,
                ProtocolHistory::Failed(GenerationFailure::Stopped) => 8,
                ProtocolHistory::Failed(GenerationFailure::Release) => 9,
                ProtocolHistory::Failed(GenerationFailure::Poisoned) => 10,
            })?;
            Ok(writer.finish())
        };
        encode().map_err(|_| ProviderFault::DeviceState)
    }

    fn validate_payload(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        Self::decode_payload(payload).map(|_| ())
    }

    fn validate_restore(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        if self.is_activated() || self.queues.is_some() || self.attempt.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.validate_payload(payload)
    }

    fn apply_payload(&mut self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.callbacks.require_quiesced()?;
        if self.attempt.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        let decoded = Self::decode_payload(payload)?;
        self.install_payload(decoded);
        Ok(())
    }

    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        let decoded = Self::decode_payload(payload)?;
        if self
            .interrupt
            .as_ref()
            .is_some_and(|bound| !bound.same_binding(&context.interrupt))
        {
            return Err(ProviderFault::DeviceState);
        }
        self.callbacks.prepare_restore(request)?;
        self.install_payload(decoded);
        self.interrupt = Some(context.interrupt.clone());
        self.device_state = if context.activated {
            DeviceState::Activated(context.memory, context.interrupt)
        } else {
            DeviceState::Inactive
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use polly::event_manager::{BarrierGeneration, OperationId};
    use utils::eventfd::EventFd;
    use vm_memory::GuestAddress;

    use crate::legacy::DummyIrqChip;
    use crate::virtio::generation::*;
    use crate::virtio::lifecycle::RestoredReclaimPolicy;
    use crate::virtio::{Queue, VIRTIO_MMIO_INT_CONFIG};

    fn barrier(operation: u64) -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(7),
            },
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    fn interrupt() -> InterruptTransport {
        InterruptTransport::new(DummyIrqChip::new().into(), DEVICE_ID.into(), None).unwrap()
    }

    fn cut(device: &mut Generation, operation: u64) -> Vec<DeviceQueue> {
        let request = barrier(operation);
        device.begin_quiesce(request).unwrap();
        let Poll::Ready(completion) = device.poll_quiesce(request.key).unwrap() else {
            panic!("synchronous provider failed to return queues");
        };
        assert_eq!(completion.fault, None);
        assert!(matches!(
            device.poll_quiesce(request.key).unwrap(),
            Poll::Pending
        ));
        completion.queues
    }

    fn stopped() -> Generation {
        let mut device = Generation::new();
        device.bind_interrupt(interrupt()).unwrap();
        device.write_config(4, &13u32.to_le_bytes());
        assert!(cut(&mut device, 1).is_empty());
        device
    }

    #[test]
    fn generation_live_restore_requires_saved_ready_clock_capable_driver() {
        let mut source = stopped();
        let payload = source.capture_payload(barrier(1).key).unwrap();
        assert!(Generation::validate_live_restore_payload(&payload).is_ok());
        for status in [0, 1, 5, 9, 15] {
            source.driver_status = status;
            let payload = source.capture_payload(barrier(1).key).unwrap();
            assert!(Generation::validate_live_restore_payload(&payload).is_err());
        }
        assert!(Generation::validate_live_restore_payload(&[]).is_err());
    }

    fn prepare(device: &mut Generation, id: [u8; 16], now: Instant) -> GenerationAttempt {
        device
            .prepare_at(
                barrier(1).key,
                GenerationRequest::FreshIdentity(id),
                now + Duration::from_secs(10),
                now,
            )
            .unwrap()
    }

    fn stage(device: &mut Generation, tuple: GenerationTuple, now: Instant) {
        for index in 0..4 {
            device.write_at(
                40 + index as u64 * 4,
                &id_word(&tuple.id, index).to_le_bytes(),
                now,
            );
        }
        device.write_at(36, &((tuple.sequence >> 32) as u32).to_le_bytes(), now);
    }

    fn low(device: &mut Generation, sequence: u64, now: Instant) {
        device.write_at(32, &(sequence as u32).to_le_bytes(), now);
    }

    fn word(device: &Generation, offset: u64) -> u32 {
        let mut value = [0; 4];
        device.read_config(offset, &mut value);
        u32::from_le_bytes(value)
    }

    #[test]
    fn generation_snapshot_observes_only_the_retained_interrupt_counter() {
        assert_eq!(Generation::new().snapshot().config_generation, None);
        let mut device = stopped();
        assert_eq!(device.snapshot().config_generation, Some(0));
        let route = device.interrupt.as_ref().unwrap().clone();
        let attempt = prepare(&mut device, [42; 16], Instant::now());
        assert_eq!(device.snapshot().config_generation, Some(1));
        route.publish_config_change();
        assert_eq!(device.snapshot().config_generation, Some(2));
        assert_eq!(device.snapshot().request, attempt.request());
        assert_eq!(
            device.snapshot().config_generation,
            Some(route.config_generation())
        );
    }

    #[test]
    fn generation_layout_endian_bounds_and_read_only_words() {
        let mut device = stopped();
        device.request.sequence = 0x12345678_abcdef00;
        let id = std::array::from_fn(|index| index as u8);
        let attempt = prepare(&mut device, id, Instant::now());
        assert_eq!(device.device_type(), 0x5347);
        assert_eq!(device.device_name(), "silo-vmgenid");
        assert_eq!(device.avail_features(), 1 << 32);
        assert_eq!(device.queue_config().len(), 1);
        assert_eq!(device.queue_config()[0].size, 1);
        assert_eq!(word(&device, 0), 1);
        assert_eq!(word(&device, 8), 0xabcdef01);
        assert_eq!(word(&device, 12), 0x12345678);
        for index in 0..4 {
            assert_eq!(word(&device, 16 + index as u64 * 4), id_word(&id, index));
        }
        assert_eq!(word(&device, 56), SYNC_CLOCK);
        let before = device.snapshot();
        for offset in [0, 8, 12, 16, 20, 24, 28, 56, 60, 64, 1, 33, 68, u64::MAX] {
            device.write_config(offset, &[255; 4]);
        }
        for length in [0, 1, 3, 5, 68] {
            device.write_config(32, &vec![255; length]);
            let mut output = vec![255; length];
            device.read_config(0, &mut output);
            assert_eq!(output, vec![0; length]);
        }
        for offset in [1, 65, 68, u64::MAX] {
            let mut output = [255; 4];
            device.read_config(offset, &mut output);
            assert_eq!(output, [0; 4]);
        }
        assert_eq!(device.snapshot(), before);
        assert_eq!(
            attempt.observe(Instant::now()),
            GenerationObservation::Pending
        );
    }

    #[test]
    fn generation_only_low_event_commits_full_sequence_and_identity() {
        let now = Instant::now();
        let mut device = stopped();
        device.request.sequence = u64::from(u32::MAX);
        let attempt = prepare(&mut device, [0xa5; 16], now);
        assert_eq!(attempt.request().sequence, 1 << 32);
        stage(&mut device, attempt.request(), now);
        assert_eq!(device.processed.sequence, attempt.request().sequence);
        assert_eq!(device.processed.id, attempt.request().id);
        assert_eq!(attempt.observe(now), GenerationObservation::Pending);
        device.write_at(4, &13u32.to_le_bytes(), now);
        assert_eq!(attempt.observe(now), GenerationObservation::Pending);
        for wrong in [
            GenerationTuple {
                sequence: 0,
                ..attempt.request()
            },
            GenerationTuple {
                sequence: 1,
                ..attempt.request()
            },
            GenerationTuple {
                sequence: (2 << 32),
                ..attempt.request()
            },
            GenerationTuple {
                id: [0x5a; 16],
                ..attempt.request()
            },
        ] {
            stage(&mut device, wrong, now);
            low(&mut device, wrong.sequence, now);
            assert_eq!(attempt.observe(now), GenerationObservation::Pending);
            assert_eq!(device.committed, None);
            assert_eq!(device.processed.id, wrong.id);
        }
        stage(&mut device, attempt.request(), now);
        let committed_at = now + Duration::from_millis(1);
        low(&mut device, attempt.request().sequence, committed_at);
        let expected = GenerationObservation::Acknowledged(GenerationReceipt {
            request: attempt.request(),
            completed_at: committed_at,
        });
        assert_eq!(
            attempt.observe(attempt.deadline() + Duration::from_secs(1)),
            expected
        );
        low(&mut device, attempt.request().sequence, attempt.deadline());
        device.fail_attempt(GenerationFailure::Stopped);
        assert_eq!(attempt.observe(attempt.deadline()), expected);
        assert_eq!(device.committed, Some(attempt.request()));
    }

    #[test]
    fn generation_deadline_at_commit_is_absolute_and_terminal() {
        for late_by in [Duration::ZERO, Duration::from_nanos(1)] {
            let now = Instant::now();
            let mut device = stopped();
            let attempt = prepare(&mut device, [3; 16], now);
            stage(&mut device, attempt.request(), now);
            low(
                &mut device,
                attempt.request().sequence,
                attempt.deadline() + late_by,
            );
            assert_eq!(
                attempt.observe(now),
                GenerationObservation::Failed(GenerationFailure::Deadline)
            );
            device.write_at(4, &13u32.to_le_bytes(), now);
            low(&mut device, attempt.request().sequence, now);
            assert_eq!(device.committed, None);
            assert_eq!(
                device.notify(&attempt),
                Err(GenerationError::Failed(GenerationFailure::Deadline))
            );
        }
        let now = Instant::now();
        let mut device = stopped();
        let attempt = prepare(&mut device, [4; 16], now);
        assert_eq!(
            attempt.observe(attempt.deadline()),
            GenerationObservation::Failed(GenerationFailure::Deadline)
        );
        stage(&mut device, attempt.request(), now);
        low(&mut device, attempt.request().sequence, now);
        assert_eq!(device.committed, None);
    }

    #[test]
    fn generation_driver_error_invalid_status_and_stop_never_revive() {
        for (status, failure) in [
            (15, GenerationFailure::DriverError),
            (0x10d, GenerationFailure::InvalidStatus),
        ] {
            let now = Instant::now();
            let mut device = stopped();
            let attempt = prepare(&mut device, [9; 16], now);
            device.write_at(4, &u32::to_le_bytes(status), now);
            device.write_at(4, &13u32.to_le_bytes(), now);
            stage(&mut device, attempt.request(), now);
            low(&mut device, attempt.request().sequence, now);
            assert_eq!(attempt.observe(now), GenerationObservation::Failed(failure));
            assert_eq!(device.committed, None);
            let payload = device.capture_payload(barrier(1).key).unwrap();
            assert!(device.validate_payload(&payload).is_ok());
        }
        let now = Instant::now();
        let mut device = stopped();
        let attempt = prepare(&mut device, [8; 16], now);
        device.fail_attempt(GenerationFailure::Stopped);
        low(&mut device, attempt.request().sequence, now);
        assert_eq!(
            attempt.observe(now),
            GenerationObservation::Failed(GenerationFailure::Stopped)
        );
    }

    #[test]
    fn generation_failed_reset_retains_cut_and_cannot_reopen() {
        let now = Instant::now();
        let mut device = stopped();
        device.set_acked_features(FEATURES);
        let attempt = prepare(&mut device, [7; 16], now);
        stage(&mut device, attempt.request(), now);
        device.latch_clock(0x12345678_abcdef00);
        let route = device.interrupt.as_ref().unwrap().clone();
        for _ in 0..3 {
            let before = device.snapshot();
            assert!(!device.reset());
            assert_eq!(
                attempt.observe(now),
                GenerationObservation::Failed(GenerationFailure::Reset)
            );
            let after = device.snapshot();
            assert_eq!(after.request, before.request);
            assert_eq!(after.processed, before.processed);
            assert_eq!(after.driver_status, before.driver_status);
            assert_eq!(after.clock_latch, before.clock_latch);
            assert_eq!(device.acked_features(), FEATURES);
            assert!(device.interrupt.as_ref().unwrap().same_binding(&route));
            assert_eq!(
                device.capture_payload(barrier(1).key),
                Err(ProviderFault::InvalidTransition)
            );
            assert!(matches!(
                device.prepare(
                    barrier(1).key,
                    GenerationRequest::ClockOnly,
                    now + Duration::from_secs(10)
                ),
                Err(GenerationError::Failed(GenerationFailure::Reset))
            ));
            device.write_at(4, &13u32.to_le_bytes(), now);
            low(&mut device, attempt.request().sequence, now);
            assert_eq!(device.committed, None);
        }
    }

    #[test]
    fn generation_reset_preserves_prior_failure_and_completed_receipt() {
        for failure in [
            GenerationFailure::DriverError,
            GenerationFailure::Notification,
            GenerationFailure::Stopped,
        ] {
            let now = Instant::now();
            let mut device = stopped();
            let attempt = prepare(&mut device, [8; 16], now);
            device.fail_attempt(failure);
            assert!(!device.reset());
            assert!(!device.reset());
            assert_eq!(attempt.observe(now), GenerationObservation::Failed(failure));
            assert_eq!(
                device.notify(&attempt),
                Err(GenerationError::Failed(failure))
            );
            assert_eq!(
                device.capture_payload(barrier(1).key),
                Err(ProviderFault::InvalidTransition)
            );
        }

        let now = Instant::now();
        let mut device = stopped();
        let attempt = prepare(&mut device, [9; 16], now);
        stage(&mut device, attempt.request(), now);
        low(&mut device, attempt.request().sequence, now);
        let receipt = attempt.observe(now);
        assert!(matches!(receipt, GenerationObservation::Acknowledged(_)));
        assert!(!device.reset());
        assert!(!device.reset());
        assert_eq!(attempt.observe(now), receipt);
        assert_eq!(
            device.notify(&attempt),
            Err(GenerationError::Failed(GenerationFailure::Reset))
        );
        assert!(matches!(
            device.prepare(
                barrier(1).key,
                GenerationRequest::ClockOnly,
                now + Duration::from_secs(10)
            ),
            Err(GenerationError::Failed(GenerationFailure::Reset))
        ));
        assert_eq!(
            device.capture_payload(barrier(1).key),
            Err(ProviderFault::InvalidTransition)
        );
    }

    #[test]
    fn generation_publication_is_once_and_notification_failure_is_sticky() {
        let now = Instant::now();
        let mut device = stopped();
        let interrupt = device.interrupt.as_ref().unwrap().clone();
        let attempt = prepare(&mut device, [6; 16], now);
        assert_eq!(interrupt.config_generation(), 1);
        assert_eq!(
            interrupt.status().load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_CONFIG as usize
        );
        device.notify(&attempt).unwrap();
        device.notify(&attempt).unwrap();
        assert_eq!(interrupt.config_generation(), 1);
        interrupt.status().store(0, Ordering::SeqCst);
        assert_eq!(attempt.observe(now), GenerationObservation::Pending);
        let controller = interrupt.intc().clone();
        let _ = std::thread::spawn(move || {
            let _guard = controller.lock().unwrap();
            panic!("poison native notification route");
        })
        .join();
        assert_eq!(
            device.notify(&attempt),
            Err(GenerationError::Failed(GenerationFailure::Notification))
        );
        assert_eq!(
            attempt.observe(now),
            GenerationObservation::Failed(GenerationFailure::Notification)
        );
        assert_eq!(device.preflight(), Err(ProviderFault::Notification));
    }

    #[test]
    fn generation_clock_only_retains_original_attempt_and_committed_identity() {
        let now = Instant::now();
        let mut device = stopped();
        let zero = device
            .prepare_at(
                barrier(1).key,
                GenerationRequest::ClockOnly,
                now + Duration::from_secs(10),
                now,
            )
            .unwrap();
        assert_eq!(zero.request().id, [0; 16]);
        assert_eq!(zero.request().flags, 3);
        let retained = device
            .prepare_at(
                barrier(1).key,
                GenerationRequest::ClockOnly,
                now + Duration::from_secs(20),
                now,
            )
            .unwrap();
        assert!(zero.same_attempt(&retained));
        assert_eq!(zero.deadline(), retained.deadline());
        assert_eq!(device.interrupt.as_ref().unwrap().config_generation(), 1);
        stage(&mut device, zero.request(), now);
        low(&mut device, zero.request().sequence, now);
        let fresh = prepare(&mut device, [11; 16], now);
        assert!(matches!(
            device.prepare_at(
                barrier(1).key,
                GenerationRequest::ClockOnly,
                now + Duration::from_secs(20),
                now
            ),
            Err(GenerationError::PendingAttempt)
        ));
        stage(&mut device, zero.request(), now);
        low(&mut device, zero.request().sequence, now);
        assert_eq!(fresh.observe(now), GenerationObservation::Pending);
        stage(&mut device, fresh.request(), now);
        low(&mut device, fresh.request().sequence, now);
        let clock = device
            .prepare_at(
                barrier(1).key,
                GenerationRequest::ClockOnly,
                now + Duration::from_secs(10),
                now,
            )
            .unwrap();
        assert_eq!(clock.request().id, fresh.request().id);
        assert_eq!(clock.request().sequence, fresh.request().sequence + 1);
        assert_eq!(clock.request().flags, 3);
        assert_eq!(device.notify(&fresh), Err(GenerationError::ForeignAttempt));
    }

    #[test]
    fn generation_preparation_refusals_have_no_publication_effects() {
        let now = Instant::now();
        let mut device = stopped();
        let before = device.snapshot();
        assert!(matches!(
            device.prepare_at(
                barrier(2).key,
                GenerationRequest::FreshIdentity([1; 16]),
                now + Duration::from_secs(10),
                now
            ),
            Err(GenerationError::Provider(_))
        ));
        assert_eq!(
            device
                .prepare_at(
                    barrier(1).key,
                    GenerationRequest::FreshIdentity([0; 16]),
                    now + Duration::from_secs(10),
                    now
                )
                .unwrap_err(),
            GenerationError::IdentityCollision
        );
        assert_eq!(
            device
                .prepare_at(barrier(1).key, GenerationRequest::ClockOnly, now, now)
                .unwrap_err(),
            GenerationError::Failed(GenerationFailure::Deadline)
        );
        assert_eq!(device.snapshot(), before);
        assert_eq!(device.interrupt.as_ref().unwrap().config_generation(), 0);
        device.request.sequence = u64::MAX;
        assert_eq!(
            device
                .prepare_at(
                    barrier(1).key,
                    GenerationRequest::FreshIdentity([1; 16]),
                    now + Duration::from_secs(10),
                    now
                )
                .unwrap_err(),
            GenerationError::SequenceExhausted
        );
        assert_eq!(device.request.sequence, u64::MAX);
        assert_eq!(device.interrupt.as_ref().unwrap().config_generation(), 0);
        let foreign = interrupt();
        assert_eq!(
            device.bind_interrupt(foreign),
            Err(GenerationError::AlreadyBound)
        );
    }

    #[test]
    fn generation_partial_ack_payload_preserves_raw_words_without_receipt() {
        let now = Instant::now();
        let mut source = stopped();
        let attempt = prepare(&mut source, [12; 16], now);
        source.latch_clock(0x12345678_ffffffff);
        for step in 0..7 {
            let payload = source.capture_payload(barrier(1).key).unwrap();
            let mut restored = stopped();
            restored.apply_payload(&payload).unwrap();
            assert_eq!(restored.request, source.request);
            assert_eq!(restored.processed, source.processed);
            assert_eq!(restored.committed, source.committed);
            assert_eq!(restored.clock_latch.get(), source.clock_latch.get());
            assert!(restored.attempt.is_none());
            assert_eq!(restored.capture_payload(barrier(1).key).unwrap(), payload);
            if step < 4 {
                source.write_at(
                    40 + step * 4,
                    &id_word(&attempt.request().id, step as usize).to_le_bytes(),
                    now,
                );
            } else if step == 4 {
                source.write_at(36, &0u32.to_le_bytes(), now);
            } else if step == 5 {
                low(&mut source, attempt.request().sequence, now);
            }
        }
        let payload = source.capture_payload(barrier(1).key).unwrap();
        let mut restored = stopped();
        restored.apply_payload(&payload).unwrap();
        assert!(restored.attempt.is_none());
        assert_eq!(restored.committed, Some(attempt.request()));
        let destination = prepare(&mut restored, [13; 16], now);
        stage(&mut restored, attempt.request(), now);
        low(&mut restored, attempt.request().sequence, now);
        assert_eq!(destination.observe(now), GenerationObservation::Pending);
    }

    #[test]
    fn generation_clock_latch_survives_low_high_carry_and_restore() {
        let source = stopped();
        assert_eq!(word(&source, 64), 0);
        assert_eq!(source.latch_clock(0x100000000), 0);
        assert_eq!(word(&source, 64), 1);
        let payload = source.capture_payload(barrier(1).key).unwrap();
        let mut restored = stopped();
        restored.apply_payload(&payload).unwrap();
        assert_eq!(word(&restored, 64), 1);
        assert_eq!(restored.latch_clock(0x200000001), 1);
        assert_eq!(word(&restored, 64), 2);
        assert_eq!(restored.latch_clock(0), 0);
        assert_eq!(word(&restored, 64), 0);
    }

    #[test]
    fn generation_payload_is_bounded_canonical_and_validated_before_apply() {
        let mut source = stopped();
        let payload = source.capture_payload(barrier(1).key).unwrap();
        assert_eq!(&payload[..6], &[1, 0, 0x47, 0x53, 0, 0]);
        assert_eq!(payload.len(), 92);
        for length in 0..payload.len() {
            assert!(source.validate_payload(&payload[..length]).is_err());
        }
        let mut malformed = Vec::new();
        for (offset, value) in [
            (0, 2),
            (2, 1),
            (6, 1),
            (14, 1),
            (22, 2),
            (26, 0x80),
            (78, 2),
            (90, 2),
            (91, 255),
        ] {
            let mut bytes = payload.clone();
            bytes[offset] = value;
            malformed.push(bytes);
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        malformed.push(trailing);
        malformed.push(vec![0; STATE_LIMIT as usize + 1]);
        for bytes in malformed {
            let before = source.snapshot();
            assert_eq!(
                source.apply_payload(&bytes),
                Err(ProviderFault::DeviceState)
            );
            assert_eq!(source.snapshot(), before);
        }
        assert!(!valid_tuple(GenerationTuple {
            sequence: 1,
            id: [1; 16],
            flags: 2
        }));
        assert!(!valid_tuple(GenerationTuple {
            sequence: 1,
            id: [1; 16],
            flags: 4
        }));
    }

    #[test]
    fn generation_provider_escrows_unused_queue_and_restores_dormant() {
        let now = Instant::now();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let mut source = Generation::new();
        source.write_config(4, &13u32.to_le_bytes());
        let route = interrupt();
        let event = Arc::new(EventFd::new(0).unwrap());
        source
            .activate(
                memory.clone(),
                route.clone(),
                vec![DeviceQueue::new(Queue::new(1), event.clone())],
            )
            .unwrap();
        let queues = cut(&mut source, 1);
        assert_eq!(queues.len(), 1);
        assert!(Arc::ptr_eq(&queues[0].event, &event));
        let attempt = prepare(&mut source, [14; 16], now);
        stage(&mut source, attempt.request(), now);
        let payload = source.capture_payload(barrier(1).key).unwrap();
        assert!(source.capture_payload(barrier(2).key).is_err());
        let mut destination = Generation::new();
        let destination_route = interrupt();
        destination
            .prepare_restore(
                barrier(1),
                &payload,
                DormantDeviceContext {
                    memory,
                    interrupt: destination_route.clone(),
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert!(destination.is_activated());
        assert!(destination.queues.is_none());
        assert!(destination.attempt.is_none());
        assert_eq!(destination_route.config_generation(), 0);
        assert_eq!(destination_route.status().load(Ordering::SeqCst), 0);
        assert_eq!(destination.processed, source.processed);
        assert_eq!(
            destination
                .prepare(
                    barrier(1).key,
                    GenerationRequest::ClockOnly,
                    now + Duration::from_secs(10)
                )
                .unwrap_err(),
            GenerationError::PendingAttempt
        );
        let child = prepare(&mut destination, [15; 16], now);
        assert_eq!(child.request().sequence, attempt.request().sequence + 1);
        assert!(matches!(
            source.begin_resume(barrier(2), queues),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            source.poll_resume(barrier(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(source.request, attempt.request());
        assert_eq!(source.processed, destination.processed);
        assert_eq!(route.config_generation(), 1);
        assert_eq!(attempt.deadline(), now + Duration::from_secs(10));
        assert!(matches!(
            destination.begin_resume(barrier(2), Vec::new()),
            ResumeAcceptance::Rejected {
                fault: ProviderFault::QueueCount,
                ..
            }
        ));
        assert!(matches!(
            destination.begin_resume(
                barrier(2),
                vec![DeviceQueue::new(
                    Queue::new(1),
                    Arc::new(EventFd::new(0).unwrap())
                )]
            ),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(barrier(2).key).unwrap(),
            Poll::Ready(())
        ));
        assert_eq!(destination_route.config_generation(), 1);
    }

    #[test]
    fn generation_guest_bracket_rejects_request_replaced_at_every_read_boundary() {
        for boundary in 0..11 {
            let mut device = stopped();
            let old = GenerationTuple {
                sequence: u64::from(u32::MAX),
                id: [0x11; 16],
                flags: 1,
            };
            let new = GenerationTuple {
                sequence: 1 << 32,
                id: [0x22; 16],
                flags: 3,
            };
            device.request = old;
            let offsets = [8, 12, 0, 16, 20, 24, 28, 56, 8, 12];
            let mut values = [0; 10];
            for (index, offset) in offsets.into_iter().enumerate() {
                if index == boundary {
                    device.request = new;
                }
                values[index] = word(&device, offset);
            }
            let before = u64::from(values[0]) | (u64::from(values[1]) << 32);
            let after = u64::from(values[8]) | (u64::from(values[9]) << 32);
            if before == after {
                let expected = if after == old.sequence { old } else { new };
                assert_eq!(values[7], expected.flags);
                for index in 0..4 {
                    assert_eq!(values[index + 3], id_word(&expected.id, index));
                }
            }
        }
    }

    #[test]
    fn generation_equal_raw_payload_is_history_not_destination_authority() {
        let now = Instant::now();
        let mut source = stopped();
        source.request.sequence = u64::from(u32::MAX);
        let attempt = prepare(&mut source, [16; 16], now);
        stage(&mut source, attempt.request(), now);
        assert_eq!(source.processed.sequence, source.request.sequence);
        assert_eq!(source.processed.id, source.request.id);
        let payload = source.capture_payload(barrier(1).key).unwrap();
        let mut destination = stopped();
        destination.apply_payload(&payload).unwrap();
        low(&mut destination, attempt.request().sequence, now);
        assert_eq!(destination.committed, None);
        assert_eq!(destination.snapshot().attempt, None);
        let child = prepare(&mut destination, [17; 16], now);
        stage(&mut destination, attempt.request(), now);
        low(&mut destination, attempt.request().sequence, now);
        assert_eq!(child.observe(now), GenerationObservation::Pending);
        assert_eq!(
            attempt.observe(attempt.deadline()),
            GenerationObservation::Failed(GenerationFailure::Deadline)
        );
        assert_eq!(source.request, attempt.request());
        assert_eq!(source.processed, destination.processed);
        assert_eq!(
            source.snapshot().protocol_failure,
            Some(GenerationFailure::Deadline)
        );
    }

    #[test]
    fn generation_required_capabilities_are_checked_at_low_event() {
        for status in [0u32, READY, READY | CLOCK, READY | CLOCK_ONLY_CAP] {
            let now = Instant::now();
            let mut device = stopped();
            let attempt = device
                .prepare_at(
                    barrier(1).key,
                    GenerationRequest::ClockOnly,
                    now + Duration::from_secs(10),
                    now,
                )
                .unwrap();
            device.write_at(4, &status.to_le_bytes(), now);
            stage(&mut device, attempt.request(), now);
            low(&mut device, attempt.request().sequence, now);
            assert_eq!(attempt.observe(now), GenerationObservation::Pending);
            device.write_at(4, &13u32.to_le_bytes(), now);
            assert_eq!(attempt.observe(now), GenerationObservation::Pending);
            low(&mut device, attempt.request().sequence, now);
            assert!(matches!(
                attempt.observe(now),
                GenerationObservation::Acknowledged(_)
            ));
        }
    }

    #[test]
    fn generation_dormant_inactive_restore_and_queue_topology_are_fail_closed() {
        let source = stopped();
        let payload = source.capture_payload(barrier(1).key).unwrap();
        let mut destination = Generation::new();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let route = interrupt();
        destination
            .prepare_restore(
                barrier(1),
                &payload,
                DormantDeviceContext {
                    memory: memory.clone(),
                    interrupt: route.clone(),
                    activated: false,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert!(!destination.is_activated());
        assert!(destination.queues.is_none());
        assert_eq!(route.config_generation(), 0);
        assert_eq!(route.status().load(Ordering::SeqCst), 0);
        assert!(destination.capture_payload(barrier(2).key).is_err());
        assert!(matches!(
            destination.begin_resume(barrier(2), Vec::new()),
            ResumeAcceptance::Accepted
        ));
        assert!(matches!(
            destination.poll_resume(barrier(2).key).unwrap(),
            Poll::Ready(())
        ));
        let mut fresh = Generation::new();
        assert!(
            fresh
                .activate(
                    memory.clone(),
                    interrupt(),
                    vec![DeviceQueue::new(
                        Queue::new(2),
                        Arc::new(EventFd::new(0).unwrap())
                    )]
                )
                .is_err()
        );
        assert!(!fresh.is_activated());
        assert!(fresh.interrupt.is_none());
        fresh
            .activate(
                memory,
                interrupt(),
                vec![DeviceQueue::new(
                    Queue::new(1),
                    Arc::new(EventFd::new(0).unwrap()),
                )],
            )
            .unwrap();
        cut(&mut fresh, 1);
        assert!(matches!(
            fresh.begin_resume(
                barrier(2),
                vec![DeviceQueue::new(
                    Queue::new(2),
                    Arc::new(EventFd::new(0).unwrap())
                )]
            ),
            ResumeAcceptance::Rejected {
                fault: ProviderFault::QueueState,
                ..
            }
        ));
    }
}
