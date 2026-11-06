use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;

use crate::api::live::LiveError;
use crate::api::live::irq_probe::{ProbeObservation, ProbeRequest};
use crate::api::vmm_builder::native_device_probe::witness::{self, Witness};
use crate::vmm::Vmm;
use crate::vmm::control::live::LiveReply;
use crate::vmm::control::{ControlFailure, ControlReply, ControlState, OperationId};
use crate::vmm::execution::CpuExecutionInput;

type Reply = Sender<Result<ControlReply, ControlFailure>>;

pub(crate) struct ProbeOwner {
    witness: Arc<Witness>,
    pending: Option<PendingInitialization>,
}
struct PendingInitialization {
    bootstrap: Arc<CpuExecutionInput>,
    reply: Option<Reply>,
    failed: bool,
}
impl ProbeOwner {
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }
}
fn answer(reply: &Reply, result: Result<ProbeObservation, LiveError>) {
    let _ = reply.try_send(Ok(ControlReply::Live(result.map(LiveReply::IrqProbe))));
}
fn command_allowed(state: &ControlState, words: &[u64; 23]) -> Result<(), LiveError> {
    if !matches!(state, ControlState::Running) {
        return Err(ControlFailure::Busy.into());
    }
    if words[0] != 0x53494c4f || words[1] != 1 {
        return Err(LiveError::Execution(
            "original initialized witness absent".into(),
        ));
    }
    Ok(())
}
impl Vmm {
    fn fail_irq_probe(&mut self) {
        if let Some(active) = &mut self.control.active {
            active.failed = true;
        }
        self.execution.failed_install = true;
        self.control.state = ControlState::FailedFenced;
    }
    pub(crate) fn dispatch_irq_probe(
        &mut self,
        request: ProbeRequest,
        operation: OperationId,
        deadline: Instant,
        reply: &Reply,
    ) -> Result<Option<LiveReply>, LiveError> {
        match request {
            ProbeRequest::Observe => Ok(Some(LiveReply::IrqProbe(
                witness::observe(self).map_err(LiveError::Execution)?,
            ))),
            ProbeRequest::Command(command) => {
                if self.control.live.pending() {
                    return Err(ControlFailure::Busy.into());
                }
                let observation = witness::observe(self).map_err(LiveError::Execution)?;
                command_allowed(&self.control.state, &observation.words)?;
                self.control.reserve(operation)?;
                // A restored child uses only the retained guest's command word.
                // It never needs observer registration or a source context.
                witness::write_command(self, command.word()).map_err(LiveError::Execution)?;
                Ok(Some(LiveReply::IrqProbe(
                    witness::observe(self).map_err(LiveError::Execution)?,
                )))
            }
            ProbeRequest::Initialize { pause, fixture } => {
                if !self.control.validate_token(&pause) {
                    return Err(ControlFailure::InvalidToken.into());
                }
                if self.control.live.pending()
                    || self.control.live.unresolved()
                    || self.memory.has_attempt()
                    || self.control.live.irq_probe.is_some()
                {
                    return Err(ControlFailure::Busy.into());
                }
                witness::validate_source(self).map_err(LiveError::Execution)?;
                self.control.reserve(operation)?;
                let witness = Arc::new(Witness::default());
                witness.attach(self).map_err(LiveError::Execution)?;
                let result = witness.begin_initialize(
                    self,
                    fixture,
                    deadline.min(Instant::now() + Duration::from_secs(5)),
                );
                let bootstrap = match result {
                    Ok(bootstrap) => bootstrap,
                    Err(error) => {
                        self.fail_irq_probe();
                        return Err(LiveError::Execution(error));
                    }
                };
                self.control.live.irq_probe = Some(ProbeOwner {
                    witness,
                    pending: Some(PendingInitialization {
                        bootstrap,
                        reply: Some(reply.clone()),
                        failed: false,
                    }),
                });
                Ok(None)
            }
        }
    }

    pub(crate) fn poll_irq_probe(&mut self) {
        let Some(mut owner) = self.control.live.irq_probe.take() else {
            return;
        };
        if let Some(mut pending) = owner.pending.take() {
            if matches!(
                self.control.state,
                ControlState::Stopping | ControlState::Stopped
            ) {
                if let Some(reply) = pending.reply.take() {
                    answer(&reply, Err(ControlFailure::InvalidOperation.into()));
                }
                pending.failed = true;
            } else if !pending.failed {
                match owner.witness.poll_initialize(self, &pending.bootstrap) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(())) => {
                        if let Some(reply) = pending.reply.take() {
                            answer(&reply, witness::observe(self).map_err(LiveError::Execution));
                        }
                        self.control.live.irq_probe = Some(owner);
                        return;
                    }
                    Poll::Ready(Err(error)) => {
                        if let Some(reply) = pending.reply.take() {
                            answer(&reply, Err(LiveError::Execution(error)));
                        }
                        self.fail_irq_probe();
                        pending.failed = true;
                    }
                }
            }
            if pending.failed {
                let _ = self.control.cpus.poll(&mut self.vcpus_handles);
            }
            if !pending.failed
                || (!self.control.cpus.reconciled()
                    && !self.vcpus_handles.iter().all(|handle| handle.is_finished()))
            {
                owner.pending = Some(pending);
            }
        }
        self.control.live.irq_probe = Some(owner);
    }
}

#[cfg(test)]
mod tests {
    use crate::vmm::control::ControlState;
    use crate::vmm::control::irq_probe::command_allowed;

    #[test]
    fn commands_refuse_uninitialized_and_nonrunning_owners_without_kvm() {
        let mut words = [0; 23];
        assert!(command_allowed(&ControlState::Running, &words).is_err());
        words[0] = 0x53494c4f;
        words[1] = 1;
        assert!(command_allowed(&ControlState::Running, &words).is_ok());
        assert!(command_allowed(&ControlState::Stopping, &words).is_err());
        assert!(command_allowed(&ControlState::Stopped, &words).is_err());
        assert!(command_allowed(&ControlState::FailedFenced, &words).is_err());
        words[1] = 2;
        assert!(command_allowed(&ControlState::Running, &words).is_err());
    }
}
