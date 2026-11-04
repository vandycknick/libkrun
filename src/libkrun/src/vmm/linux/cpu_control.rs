use polly::event_manager::{BarrierGeneration, BarrierKey, OperationId};

use crate::vmm::control::{CpuAck, CpuAckKind, CpuCommand, CpuCommandKind, CpuSubmission};

pub(crate) fn submit_command(
    sender: &crossbeam_channel::Sender<CpuCommand>,
    command: CpuCommand,
    kick: impl FnOnce() -> Result<(), String>,
) -> CpuSubmission {
    if sender.send(command).is_err() {
        return CpuSubmission::Rejected("vCPU command channel closed".to_owned());
    }
    CpuSubmission::Accepted {
        kick_error: kick().err(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CpuDisposition {
    Parked,
    Prepared,
    Running,
    Stopped,
}

/// Only the vCPU owner mutates this ledger, at a completed KVM_RUN boundary.
pub(crate) struct CpuMailbox {
    key: BarrierKey,
    disposition: CpuDisposition,
    prepared: Option<BarrierKey>,
}

impl CpuMailbox {
    pub(crate) fn new() -> Self {
        Self {
            key: BarrierKey {
                operation: OperationId(0),
                generation: BarrierGeneration(0),
            },
            disposition: CpuDisposition::Parked,
            prepared: None,
        }
    }

    pub(crate) fn disposition(&self) -> CpuDisposition {
        self.disposition
    }

    pub(crate) fn halt(&mut self) {
        self.prepared = None;
        self.disposition = CpuDisposition::Stopped;
    }

    pub(crate) fn preparation_failed(&mut self) {
        self.disposition = CpuDisposition::Parked;
        self.prepared = None;
    }

    pub(crate) fn apply(&mut self, cpu_id: u8, command: CpuCommand) -> CpuAck {
        let key = command.barrier.key;
        let kind = match command.kind {
            CpuCommandKind::Park => CpuAckKind::Parked,
            CpuCommandKind::PrepareResume { .. } => CpuAckKind::Prepared,
            CpuCommandKind::Release => CpuAckKind::Released,
            CpuCommandKind::Stop => CpuAckKind::Stopped,
            CpuCommandKind::CaptureExecution => CpuAckKind::Captured,
            CpuCommandKind::InstallExecution => CpuAckKind::Installed,
            CpuCommandKind::PrepareExecutionTime => CpuAckKind::TimePrepared,
            #[cfg(all(feature = "native-device-probe", target_arch = "x86_64"))]
            CpuCommandKind::InitializeDeviceWitness => CpuAckKind::DeviceWitnessInitialized,
        };
        let result = match command.kind {
            CpuCommandKind::Stop => {
                self.disposition = CpuDisposition::Stopped;
                Ok(())
            }
            _ if self.disposition == CpuDisposition::Stopped => Err("vCPU is stopped".to_owned()),
            CpuCommandKind::Park => {
                if key == self.key && self.disposition != CpuDisposition::Running {
                    self.disposition = CpuDisposition::Parked;
                    self.prepared = None;
                    Ok(())
                } else if key.generation.0 > self.key.generation.0
                    && self.disposition == CpuDisposition::Running
                {
                    self.key = key;
                    self.disposition = CpuDisposition::Parked;
                    self.prepared = None;
                    Ok(())
                } else {
                    Err("stale or foreign vCPU park".to_owned())
                }
            }
            #[cfg(all(feature = "native-device-probe", target_arch = "x86_64"))]
            CpuCommandKind::InitializeDeviceWitness => {
                if cpu_id == 2 && key == self.key && self.disposition == CpuDisposition::Parked {
                    Ok(())
                } else {
                    Err("source witness requires its exact parked AP2".into())
                }
            }
            CpuCommandKind::CaptureExecution
            | CpuCommandKind::InstallExecution
            | CpuCommandKind::PrepareExecutionTime => {
                if (self.disposition == CpuDisposition::Parked
                    || (self.disposition == CpuDisposition::Prepared
                        && command.kind == CpuCommandKind::CaptureExecution))
                    && (key.generation == self.key.generation
                        || (self.key.generation.0 == 0
                            && command.kind == CpuCommandKind::InstallExecution))
                {
                    self.key = key;
                    self.disposition = CpuDisposition::Parked;
                    self.prepared = None;
                    Ok(())
                } else {
                    Err("execution operation requires the exact parked CPU".to_owned())
                }
            }
            CpuCommandKind::PrepareResume { .. } => {
                if key.generation == self.key.generation
                    && (self.disposition == CpuDisposition::Parked
                        || (self.disposition == CpuDisposition::Prepared
                            && self.prepared == Some(key)))
                {
                    self.disposition = CpuDisposition::Prepared;
                    self.prepared = Some(key);
                    Ok(())
                } else {
                    Err("vCPU preparation requires the exact parked barrier".to_owned())
                }
            }
            CpuCommandKind::Release => {
                if self.prepared == Some(key)
                    && matches!(
                        self.disposition,
                        CpuDisposition::Prepared | CpuDisposition::Running
                    )
                {
                    self.disposition = CpuDisposition::Running;
                    Ok(())
                } else {
                    Err("vCPU release requires the exact prepared barrier".to_owned())
                }
            }
        };
        CpuAck {
            request: command.request,
            key,
            cpu_id,
            kind,
            result,
            execution: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use polly::event_manager::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};

    use crate::vmm::control::{CpuCommand, CpuCommandKind, CpuSubmission, RequestId};
    use crate::vmm::linux::cpu_control::{CpuDisposition, CpuMailbox, submit_command};

    fn command(request: u64, generation: u64, kind: CpuCommandKind) -> CpuCommand {
        CpuCommand {
            request: RequestId(request),
            barrier: BarrierRequest {
                key: BarrierKey {
                    operation: OperationId(generation),
                    generation: BarrierGeneration(generation),
                },
                deadline: Instant::now(),
            },
            kind,
            execution: None,
        }
    }

    #[test]
    fn kvm_mailbox_initial_release_requires_preparation() {
        let mut mailbox = CpuMailbox::new();
        assert!(
            mailbox
                .apply(1, command(1, 0, CpuCommandKind::Release))
                .result
                .is_err()
        );
        assert_eq!(mailbox.disposition(), CpuDisposition::Parked);
        assert!(
            mailbox
                .apply(
                    1,
                    command(2, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 })
                )
                .result
                .is_ok()
        );
        assert!(
            mailbox
                .apply(1, command(3, 0, CpuCommandKind::Release))
                .result
                .is_ok()
        );
        assert_eq!(mailbox.disposition(), CpuDisposition::Running);
    }

    #[test]
    fn kvm_mailbox_late_park_reconciles_exact_generation() {
        let mut mailbox = CpuMailbox::new();
        mailbox.apply(
            0,
            command(1, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 }),
        );
        mailbox.apply(0, command(2, 0, CpuCommandKind::Release));
        let park = mailbox.apply(0, command(3, 1, CpuCommandKind::Park));
        assert!(park.result.is_ok());
        assert_eq!(park.request, RequestId(3));
        assert_eq!(park.cpu_id, 0);
        assert!(
            mailbox
                .apply(0, command(4, 1, CpuCommandKind::Park))
                .result
                .is_ok()
        );
        let mut foreign = command(5, 1, CpuCommandKind::Park);
        foreign.barrier.key.operation = OperationId(9);
        assert!(mailbox.apply(0, foreign).result.is_err());
        assert!(
            mailbox
                .apply(
                    0,
                    command(6, 1, CpuCommandKind::PrepareResume { paused_ticks: 0 })
                )
                .result
                .is_ok()
        );
        assert!(
            mailbox
                .apply(0, command(7, 1, CpuCommandKind::Release))
                .result
                .is_ok()
        );
        assert!(
            mailbox
                .apply(0, command(3, 1, CpuCommandKind::Park))
                .result
                .is_err()
        );
        assert_eq!(mailbox.disposition(), CpuDisposition::Running);
    }

    #[test]
    fn kvm_mailbox_expired_command_is_owned_until_reconciliation() {
        let (sender, receiver) = crossbeam_channel::unbounded();
        sender.send(command(1, 0, CpuCommandKind::Park)).unwrap();
        drop(sender);
        let mut mailbox = CpuMailbox::new();
        let ack = mailbox.apply(2, receiver.recv().unwrap());
        assert!(ack.result.is_ok());
        assert_eq!(mailbox.disposition(), CpuDisposition::Parked);
        assert!(
            mailbox
                .apply(2, command(2, 99, CpuCommandKind::Stop))
                .result
                .is_ok()
        );
        assert_eq!(mailbox.disposition(), CpuDisposition::Stopped);
        assert!(
            mailbox
                .apply(2, command(3, 0, CpuCommandKind::Release))
                .result
                .is_err()
        );
    }

    #[test]
    fn kvm_mailbox_enqueue_precedes_failed_kick_and_keeps_ownership() {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let submission = submit_command(&sender, command(1, 0, CpuCommandKind::Park), || {
            assert_eq!(receiver.len(), 1);
            Err("kick failed".to_owned())
        });
        assert!(matches!(
            submission,
            CpuSubmission::Accepted {
                kick_error: Some(_)
            }
        ));
        drop(sender);
        let mut mailbox = CpuMailbox::new();
        let ack = mailbox.apply(4, receiver.recv().unwrap());
        assert_eq!(ack.request, RequestId(1));
        assert!(ack.result.is_ok());
        assert_eq!(mailbox.disposition(), CpuDisposition::Parked);
    }

    #[test]
    fn kvm_mailbox_disconnected_command_never_kicks() {
        let (sender, receiver) = crossbeam_channel::unbounded();
        drop(receiver);
        let submission = submit_command(&sender, command(1, 0, CpuCommandKind::Park), || {
            panic!("rejected submission must not kick");
        });
        assert!(matches!(submission, CpuSubmission::Rejected(_)));
    }

    #[test]
    fn kvm_mailbox_resume_new_operation_keeps_exact_release_key() {
        let mut mailbox = CpuMailbox::new();
        let mut prepare = command(1, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 });
        prepare.barrier.key.operation = OperationId(12);
        assert!(mailbox.apply(0, prepare.clone()).result.is_ok());
        assert!(
            mailbox
                .apply(0, command(1, 0, CpuCommandKind::Release))
                .result
                .is_err()
        );
        let mut release = prepare.clone();
        release.kind = CpuCommandKind::Release;
        assert!(mailbox.apply(0, release).result.is_ok());
        assert!(mailbox.apply(0, prepare).result.is_err());
    }

    #[test]
    fn kvm_mailbox_stop_from_every_disposition() {
        for state in [
            CpuDisposition::Parked,
            CpuDisposition::Prepared,
            CpuDisposition::Running,
        ] {
            let mut mailbox = CpuMailbox::new();
            if state != CpuDisposition::Parked {
                mailbox.apply(
                    0,
                    command(1, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 }),
                );
            }
            if state == CpuDisposition::Running {
                mailbox.apply(0, command(2, 0, CpuCommandKind::Release));
            }
            assert_eq!(mailbox.disposition(), state);
            assert!(
                mailbox
                    .apply(0, command(3, 100, CpuCommandKind::Stop))
                    .result
                    .is_ok()
            );
            assert_eq!(mailbox.disposition(), CpuDisposition::Stopped);
        }
    }

    #[test]
    fn kvm_mailbox_guest_halt_cannot_be_released() {
        let mut mailbox = CpuMailbox::new();
        mailbox.halt();
        assert!(
            mailbox
                .apply(0, command(1, 0, CpuCommandKind::Park))
                .result
                .is_err()
        );
        assert!(
            mailbox
                .apply(
                    0,
                    command(2, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 })
                )
                .result
                .is_err()
        );
        assert!(
            mailbox
                .apply(0, command(3, 0, CpuCommandKind::Release))
                .result
                .is_err()
        );
        assert!(
            mailbox
                .apply(0, command(4, 0, CpuCommandKind::Stop))
                .result
                .is_ok()
        );
    }

    #[test]
    fn kvm_execution_mailbox_refence_invalidates_prepared_release() {
        let mut mailbox = CpuMailbox::new();
        assert!(
            mailbox
                .apply(
                    0,
                    command(1, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 })
                )
                .result
                .is_ok()
        );
        assert!(
            mailbox
                .apply(0, command(2, 0, CpuCommandKind::InstallExecution))
                .result
                .is_err()
        );
        assert!(
            mailbox
                .apply(0, command(3, 0, CpuCommandKind::CaptureExecution))
                .result
                .is_ok()
        );
        assert_eq!(mailbox.disposition(), CpuDisposition::Parked);
        assert!(
            mailbox
                .apply(0, command(4, 0, CpuCommandKind::Release))
                .result
                .is_err()
        );
    }

    #[test]
    fn kvm_execution_mailbox_native_failure_cannot_certify_prepared() {
        let mut mailbox = CpuMailbox::new();
        assert!(
            mailbox
                .apply(
                    0,
                    command(1, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 })
                )
                .result
                .is_ok()
        );
        mailbox.preparation_failed();
        assert_eq!(mailbox.disposition(), CpuDisposition::Parked);
        assert!(
            mailbox
                .apply(0, command(2, 0, CpuCommandKind::Release))
                .result
                .is_err()
        );
    }

    #[cfg(all(feature = "native-device-probe", target_arch = "x86_64"))]
    #[test]
    fn kvm_device_witness_mailbox_requires_exact_parked_ap2() {
        let mut mailbox = CpuMailbox::new();
        let kind = CpuCommandKind::InitializeDeviceWitness;
        assert!(mailbox.apply(0, command(1, 0, kind)).result.is_err());
        assert!(mailbox.apply(3, command(1, 0, kind)).result.is_err());
        let mut foreign = command(1, 0, kind);
        foreign.barrier.key.operation = OperationId(1);
        assert!(mailbox.apply(2, foreign).result.is_err());
        assert!(mailbox.apply(2, command(1, 0, kind)).result.is_ok());
        assert_eq!(mailbox.disposition(), CpuDisposition::Parked);
        assert!(
            mailbox
                .apply(
                    2,
                    command(2, 0, CpuCommandKind::PrepareResume { paused_ticks: 0 })
                )
                .result
                .is_ok()
        );
        assert!(mailbox.apply(2, command(3, 0, kind)).result.is_err());
        assert!(
            mailbox
                .apply(2, command(4, 0, CpuCommandKind::Release))
                .result
                .is_ok()
        );
        assert!(mailbox.apply(2, command(5, 0, kind)).result.is_err());
    }
}
