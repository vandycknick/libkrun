// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Internal, nonblocking provider contracts. No concrete device is admitted by default.

use std::fmt;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use polly::event_manager::{BarrierKey, BarrierRequest};
use utils::eventfd::EventFd;

use crate::virtio::RuntimeGuestMemory;
use crate::virtio::device::DeviceQueue;
use crate::virtio::queue::QueueState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFault {
    Unsupported,
    Deadline,
    DeviceLock,
    InvalidTransition,
    ForeignBarrier,
    QueueCount,
    QueueIdentity,
    QueueState,
    DeviceState,
    Worker,
    Notification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStage {
    Running,
    Quiescing,
    Quiesced,
    Resuming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleError {
    pub key: BarrierKey,
    pub stage: ProviderStage,
    /// Accepted work remains provider/transport owned, including after timeout.
    pub accepted: bool,
    pub fault: ProviderFault,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} at {:?} for {:?} (accepted={})",
            self.fault, self.stage, self.key, self.accepted
        )
    }
}

impl std::error::Error for LifecycleError {}

#[derive(Debug)]
pub struct ProviderBeginError {
    pub accepted: bool,
    pub fault: ProviderFault,
}

pub struct QuiesceCompletion {
    pub queues: Vec<DeviceQueue>,
    /// Queue return does not erase a status/notification/backend failure.
    pub fault: Option<ProviderFault>,
}

pub enum ResumeAcceptance {
    Accepted,
    AcceptedWithFailure(ProviderFault),
    /// Legal only before any acceptance/effect. Return every input queue.
    /// After acceptance use AcceptedWithFailure and retain queues/backend.
    Rejected {
        queues: Vec<DeviceQueue>,
        fault: ProviderFault,
    },
}

/// A provider retains backend, worker handles and faults until terminal cleanup.
/// Begin/poll must not wait for workers or join an unfinished thread. An accepted
/// send is recorded before a fallible wake. Ready transfers queues exactly once;
/// subsequent polling must not manufacture another queue vector.
///
/// Quiescence closes admission at the queue-pop/host-ingress synchronization
/// boundary and completes owned effects through status, used ring and IRQ.
/// Resume reuses the same resources, rearms notifications and scans retained
/// available work even if its original kick was consumed. It never resets.
pub trait VirtioStateProvider: Send {
    fn preflight(&self) -> Result<(), ProviderFault>;
    fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError>;
    fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<QuiesceCompletion>, ProviderFault>;
    /// Rejection returns every input queue; accepted failure retains them.
    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance;
    /// Ready acknowledges actual running ownership, not just thread creation.
    fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault>;
    /// Device payloads are explicit and bounded, never an implicit empty state.
    fn state_limit(&self) -> u32;
    fn capture_payload(&self, key: BarrierKey) -> Result<Vec<u8>, ProviderFault>;
    fn validate_payload(&self, payload: &[u8]) -> Result<(), ProviderFault>;
    /// Called only after complete transport and device validation, while dormant.
    fn apply_payload(&mut self, payload: &[u8]) -> Result<(), ProviderFault>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshot {
    pub request: Option<BarrierRequest>,
    /// Original cut remains correlated across explicit resume/reconciliation.
    pub quiesce_request: Option<BarrierRequest>,
    pub quiesce_accepted: bool,
    pub stage: ProviderStage,
    pub accepted: bool,
    pub failure: Option<LifecycleError>,
    pub previous_failure: Option<LifecycleError>,
}

pub(crate) struct LifecycleJournal {
    pub snapshot: LifecycleSnapshot,
}

impl LifecycleJournal {
    pub fn new() -> Self {
        Self {
            snapshot: LifecycleSnapshot {
                request: None,
                stage: ProviderStage::Running,
                accepted: false,
                failure: None,
                previous_failure: None,
                quiesce_request: None,
                quiesce_accepted: false,
            },
        }
    }

    pub fn error(&self, key: BarrierKey, fault: ProviderFault) -> LifecycleError {
        LifecycleError {
            key,
            stage: self.snapshot.stage,
            accepted: self.snapshot.accepted
                && self
                    .snapshot
                    .request
                    .is_some_and(|request| request.key == key),
            fault,
        }
    }

    pub fn begin(&mut self, request: BarrierRequest, stage: ProviderStage) {
        self.snapshot.previous_failure = self.snapshot.previous_failure.or(self.snapshot.failure);
        if stage == ProviderStage::Quiescing {
            self.snapshot.quiesce_request = Some(request);
            self.snapshot.quiesce_accepted = true;
        }
        self.snapshot.request = Some(request);
        self.snapshot.stage = stage;
        self.snapshot.accepted = true;
        self.snapshot.failure = None;
    }

    pub fn fail(&mut self, key: BarrierKey, fault: ProviderFault) -> LifecycleError {
        let error = self.error(key, fault);
        *self.snapshot.failure.get_or_insert(error)
    }

    pub fn check(&self, key: BarrierKey) -> Result<BarrierRequest, LifecycleError> {
        match self.snapshot.request {
            Some(request) if request.key == key => Ok(request),
            _ => Err(self.error(key, ProviderFault::ForeignBarrier)),
        }
    }

    pub fn expired(&mut self, now: Instant) {
        if let Some(request) = self.snapshot.request
            && now >= request.deadline
        {
            self.fail(request.key, ProviderFault::Deadline);
        }
    }
}

pub(crate) struct QueueBinding {
    identity: Arc<()>,
    event: Arc<EventFd>,
    max_size: u16,
}

impl QueueBinding {
    pub fn new(queue: &crate::virtio::Queue, event: &Arc<EventFd>) -> Self {
        Self {
            identity: queue.identity(),
            event: Arc::clone(event),
            max_size: queue.get_max_size(),
        }
    }
}

/// Returned resources enter escrow before any validation can fail.
pub(crate) struct QueueEscrow {
    bindings: Vec<QueueBinding>,
    pub returned: Option<Vec<DeviceQueue>>,
    pub rejected: Option<Vec<DeviceQueue>>,
    pub validated: bool,
}

impl QueueEscrow {
    pub fn new(bindings: Vec<QueueBinding>) -> Self {
        Self {
            bindings,
            returned: None,
            rejected: None,
            validated: false,
        }
    }

    pub fn receive(
        &mut self,
        queues: Vec<DeviceQueue>,
        mem: &RuntimeGuestMemory,
    ) -> Result<(), ProviderFault> {
        if self.returned.is_some() || self.rejected.is_some() {
            // Retain both returns on a protocol violation; no queue is dropped.
            if let Some(existing) = &mut self.rejected {
                existing.extend(queues);
            } else {
                self.rejected = Some(queues);
            }
            return Err(ProviderFault::InvalidTransition);
        }
        self.returned = Some(queues);
        self.validate(mem)?;
        self.validated = true;
        Ok(())
    }

    fn validate(&self, mem: &RuntimeGuestMemory) -> Result<(), ProviderFault> {
        let queues = self.returned.as_ref().ok_or(ProviderFault::QueueCount)?;
        if queues.len() != self.bindings.len() {
            return Err(ProviderFault::QueueCount);
        }
        for (queue, binding) in queues.iter().zip(&self.bindings) {
            if !Arc::ptr_eq(&queue.queue.identity(), &binding.identity)
                || !Arc::ptr_eq(&queue.event, &binding.event)
                || queue.queue.get_max_size() != binding.max_size
            {
                return Err(ProviderFault::QueueIdentity);
            }
            let state = queue
                .queue
                .capture_state()
                .map_err(|_| ProviderFault::QueueState)?;
            queue
                .queue
                .validate_state(mem, &state)
                .map_err(|_| ProviderFault::QueueState)?;
        }
        Ok(())
    }

    pub fn states(&self) -> Result<Vec<QueueState>, ProviderFault> {
        if !self.validated || self.rejected.is_some() {
            return Err(ProviderFault::QueueState);
        }
        self.returned
            .as_ref()
            .ok_or(ProviderFault::QueueCount)?
            .iter()
            .map(|queue| {
                queue
                    .queue
                    .capture_state()
                    .map_err(|_| ProviderFault::QueueState)
            })
            .collect()
    }

    pub fn take_for_resume(&mut self) -> Result<Vec<DeviceQueue>, ProviderFault> {
        if !self.validated || self.rejected.is_some() {
            return Err(ProviderFault::QueueState);
        }
        self.validated = false;
        self.returned.take().ok_or(ProviderFault::QueueCount)
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::Queue;
    use crate::virtio::lifecycle::*;
    use crate::virtio::queue::tests::VirtQueue;
    use polly::event_manager::{BarrierGeneration, OperationId};
    use std::time::Duration;
    use vm_memory::GuestAddress;

    fn request() -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(9),
                generation: BarrierGeneration(3),
            },
            deadline: Instant::now() + Duration::from_secs(1),
        }
    }

    #[test]
    fn lifecycle_escrow_retains_foreign_and_duplicate_queue_returns() {
        let mem = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let event = Arc::new(EventFd::new(0).unwrap());
        let queue = Queue::new(8);
        let mut escrow = QueueEscrow::new(vec![QueueBinding::new(&queue, &event)]);
        let foreign = DeviceQueue::new(Queue::new(8), Arc::clone(&event));
        assert_eq!(
            escrow.receive(vec![foreign], &mem),
            Err(ProviderFault::QueueIdentity)
        );
        assert_eq!(escrow.returned.as_ref().unwrap().len(), 1);
        assert!(escrow.take_for_resume().is_err());
        assert_eq!(
            escrow.receive(vec![DeviceQueue::new(queue, event)], &mem),
            Err(ProviderFault::InvalidTransition)
        );
        assert_eq!(escrow.rejected.as_ref().unwrap().len(), 1);
        assert_eq!(escrow.returned.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn lifecycle_escrow_checks_event_object_and_queue_order() {
        let mem = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let event = Arc::new(EventFd::new(0).unwrap());
        let first = Queue::new(8);
        let second = Queue::new(8);
        let mut escrow = QueueEscrow::new(vec![
            QueueBinding::new(&first, &event),
            QueueBinding::new(&second, &event),
        ]);
        assert_eq!(
            escrow.receive(
                vec![
                    DeviceQueue::new(second, Arc::clone(&event)),
                    DeviceQueue::new(first, Arc::clone(&event)),
                ],
                &mem
            ),
            Err(ProviderFault::QueueIdentity)
        );

        let queue = Queue::new(8);
        let mut escrow = QueueEscrow::new(vec![QueueBinding::new(&queue, &event)]);
        // Even a dup fd is not the original Arc-owned event object.
        let duplicate = Arc::new(event.try_clone().unwrap());
        assert_eq!(
            escrow.receive(vec![DeviceQueue::new(queue, duplicate)], &mem),
            Err(ProviderFault::QueueIdentity)
        );
        assert!(escrow.returned.is_some());
    }

    #[test]
    fn lifecycle_real_channel_drain_retains_late_queue_and_failure() {
        let request = request();
        let mem = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &mem, 8);
        ring.dtable[0].set(0x1000, 16, 0, 0);
        ring.dtable[1].set(0x1100, 16, 0, 0);
        ring.avail.ring[0].set(0);
        ring.avail.ring[1].set(1);
        ring.avail.idx.set(2);
        let mut queue = ring.create_queue();
        let head = queue.pop(&mem).unwrap().index;
        queue.close_admission(request.key).unwrap();
        let event = Arc::new(EventFd::new(0).unwrap());
        let mut escrow = QueueEscrow::new(vec![QueueBinding::new(&queue, &event)]);
        let (complete_tx, complete_rx) = crossbeam_channel::bounded::<()>(1);
        let (return_tx, return_rx) = crossbeam_channel::bounded(1);
        let worker_mem = mem.clone();
        let worker = std::thread::spawn(move || {
            complete_rx.recv().unwrap();
            worker_mem
                .write_slice(&[0x5a; 16], GuestAddress(0x1000))
                .unwrap();
            queue.add_used(&worker_mem, head, 16).unwrap();
            assert!(queue.pop(&worker_mem).is_none());
            return_tx
                .send(DeviceQueue::new(queue, event))
                .unwrap_or_else(|_| panic!("return receiver retained"));
        });
        let mut journal = LifecycleJournal::new();
        journal.begin(request, ProviderStage::Quiescing);
        assert!(return_rx.try_recv().is_err());
        journal.expired(request.deadline);
        assert!(journal.snapshot.accepted);
        complete_tx.send(()).unwrap();
        let returned = return_rx.recv().unwrap();
        escrow.receive(vec![returned], &mem).unwrap();
        journal.snapshot.stage = ProviderStage::Quiesced;
        assert_eq!(
            journal.snapshot.failure.unwrap().fault,
            ProviderFault::Deadline
        );
        assert!(
            journal
                .check(BarrierKey {
                    operation: OperationId(10),
                    ..request.key
                })
                .is_err()
        );
        assert_eq!(escrow.states().unwrap()[0].next_avail, 1);
        assert_eq!(escrow.states().unwrap()[0].next_used, 1);
        let mut queues = escrow.take_for_resume().unwrap();
        assert!(escrow.take_for_resume().is_err());
        queues[0].queue.reopen_admission(request.key).unwrap();
        assert_eq!(queues[0].queue.pop(&mem).unwrap().index, 1);
        worker.join().unwrap();
    }

    #[test]
    fn lifecycle_journal_retains_accepted_wake_failure_and_shared_deadline() {
        let request = request();
        let mut journal = LifecycleJournal::new();
        journal.begin(request, ProviderStage::Quiescing);
        let failure = journal.fail(request.key, ProviderFault::Worker);
        journal.expired(request.deadline + Duration::from_secs(1));
        assert_eq!(journal.snapshot.failure, Some(failure));
        assert!(journal.snapshot.accepted);
        assert_eq!(
            journal.check(request.key).unwrap().deadline,
            request.deadline
        );
        let resume = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(10),
                ..request.key
            },
            deadline: request.deadline + Duration::from_secs(2),
        };
        journal.begin(resume, ProviderStage::Resuming);
        assert_eq!(journal.snapshot.previous_failure, Some(failure));
        assert_eq!(journal.snapshot.failure, None);
        assert_eq!(journal.snapshot.quiesce_request, Some(request));
        assert!(journal.snapshot.quiesce_accepted);
        assert!(
            !journal
                .error(request.key, ProviderFault::ForeignBarrier)
                .accepted
        );
        journal.snapshot.accepted = false;
        journal.fail(resume.key, ProviderFault::DeviceState);
        let retry = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(11),
                ..resume.key
            },
            ..resume
        };
        journal.begin(retry, ProviderStage::Resuming);
        assert_eq!(journal.snapshot.previous_failure, Some(failure));
        assert_eq!(journal.snapshot.quiesce_request, Some(request));
    }
}
