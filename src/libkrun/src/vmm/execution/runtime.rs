use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use crate::vmm::Vmm;
#[cfg(all(
    not(feature = "tee"),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
use crate::vmm::control::CpuCommandKind;
use crate::vmm::control::{BarrierKey, BarrierRequest, RequestId};
#[cfg(all(
    not(feature = "tee"),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
use crate::vmm::execution::{CpuExecutionInput, CpuIdentity};
use crate::vmm::execution::{
    CpuExecutionState, CpuTimePlan, ExecutionEnvelope, StateBinding, VmExecutionState,
};
use devices::legacy::state::LegacyState;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use crate::vmm::linux::execution::KvmCaptureProfile;

#[derive(Clone)]
pub(crate) struct RetainedCut {
    pub key: BarrierKey,
    pub vm: VmExecutionState,
    pub cpus: Vec<CpuExecutionState>,
    pub legacy: Vec<LegacyState>,
}

struct PendingCut {
    key: BarrierKey,
    vm: Option<VmExecutionState>,
    legacy: Vec<LegacyState>,
    cpu_dispatched: bool,
}

#[derive(Clone, Debug)]
pub struct TimePreparation {
    pub key: BarrierKey,
    pub plans: Vec<CpuTimePlan>,
    pub deadline: Instant,
}

impl TimePreparation {
    fn admits(&self, barrier: BarrierRequest) -> bool {
        self.key == barrier.key
            && self.deadline == barrier.deadline
            && Instant::now() < self.deadline
    }
}

#[derive(Default)]
pub(crate) struct ExecutionOwner {
    pub retained: Option<RetainedCut>,
    pending: Option<PendingCut>,
    pub(crate) envelope: Option<Arc<ExecutionEnvelope>>,
    devices: Option<Arc<crate::vmm::execution::device_restore::DeviceEnvelope>>,
    pub(crate) binding: Option<StateBinding>,
    pub failed_install: bool,
    pub prepared_time: Option<BarrierKey>,
    preparation: Option<TimePreparation>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub profile: Option<KvmCaptureProfile>,
}

impl ExecutionOwner {
    pub(crate) fn captured_envelope(&self) -> Option<&Arc<ExecutionEnvelope>> {
        self.envelope.as_ref()
    }
    pub(crate) fn retire_serialization(&mut self) {
        self.binding = None;
        self.envelope = None;
        self.devices = None;
    }
    pub fn preparation_observation(&self) -> Option<&TimePreparation> {
        self.preparation.as_ref()
    }

    pub fn has_cut_work(&self) -> bool {
        self.pending.is_some() || self.retained.is_some()
    }

    fn retire_unmodified_vm_refusal(&mut self, key: BarrierKey, vm_fence_started: bool) -> bool {
        if !vm_fence_started
            && self.retained.is_none()
            && self.pending.as_ref().is_some_and(|pending| {
                pending.key == key && pending.vm.is_none() && !pending.cpu_dispatched
            })
        {
            self.pending = None;
            true
        } else {
            false
        }
    }
}

#[cfg(all(
    not(feature = "tee"),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
impl Vmm {
    pub(crate) fn begin_execution_cut(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
    ) -> Result<(), String> {
        if self
            .execution
            .retained
            .as_ref()
            .is_some_and(|cut| cut.key.generation == barrier.key.generation)
        {
            return Ok(());
        }
        let native = self.memory.native()?;
        native
            .validate_domain(&self.memory_domain)
            .map_err(|error| error.to_string())?;
        if let Some(pending) = &self.execution.pending {
            if pending.key.generation != barrier.key.generation {
                return Err("foreign pending execution cut".into());
            }
        } else {
            let legacy = self.mmio_device_manager.quiescence.capture_legacy()?;
            self.execution.pending = Some(PendingCut {
                key: barrier.key,
                vm: None,
                legacy,
                cpu_dispatched: false,
            });
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if self
            .execution
            .pending
            .as_ref()
            .is_some_and(|pending| pending.vm.is_none())
        {
            let profile = self
                .execution
                .profile
                .as_ref()
                .ok_or("execution clock/PIT profile not admitted")?;
            let vm = match self.vm.capture_execution(profile, &native) {
                Ok(vm) => vm,
                Err(error) => {
                    self.execution.retire_unmodified_vm_refusal(
                        barrier.key,
                        self.vm.execution_fence_started(),
                    );
                    return Err(error);
                }
            };
            if let Some(pending) = &mut self.execution.pending {
                pending.vm = Some(VmExecutionState::Kvm(vm));
            }
        }
        #[cfg(target_os = "macos")]
        if self
            .execution
            .pending
            .as_ref()
            .is_some_and(|pending| pending.vm.is_none())
        {
            let clock = hvf::capture_clock_cut().map_err(|error| error.to_string())?;
            let gic = self
                .execution_controller
                .try_lock()
                .map_err(|_| "GIC lock")?
                .capture_hvf_state()
                .map_err(|error| error.to_string())?;
            if let Some(pending) = &mut self.execution.pending {
                pending.vm = Some(VmExecutionState::Hvf(crate::vmm::execution::HvfVmState {
                    clock,
                    gic,
                }));
            }
        }
        if let Some(pending) = &mut self.execution.pending {
            pending.cpu_dispatched = true;
        }
        self.control
            .cpus
            .begin_native(
                request,
                barrier,
                CpuCommandKind::CaptureExecution,
                &self.vcpus_handles,
                native,
            )
            .map_err(|error| error.to_string())
    }

    pub(crate) fn poll_execution_cut_for_rollback(
        &mut self,
        fenced: BarrierKey,
        rollback: BarrierRequest,
    ) -> Poll<Result<(), String>> {
        if Instant::now() >= rollback.deadline {
            return Poll::Ready(Err("execution rollback deadline expired".into()));
        }
        if rollback.key.generation != fenced.generation
            || rollback.key.operation == fenced.operation
            || self
                .execution
                .pending
                .as_ref()
                .is_some_and(|cut| cut.key != fenced)
            || self
                .execution
                .retained
                .as_ref()
                .is_some_and(|cut| cut.key != fenced)
            || !self.control.cpus.capture_owned(fenced)
        {
            return Poll::Ready(Err("foreign execution capture rollback".into()));
        }
        self.poll_execution_cut_inner(Some((fenced, rollback)))
    }

    pub(crate) fn poll_execution_cut(&mut self) -> Poll<Result<(), String>> {
        self.poll_execution_cut_inner(None)
    }

    fn poll_execution_cut_inner(
        &mut self,
        rollback: Option<(BarrierKey, BarrierRequest)>,
    ) -> Poll<Result<(), String>> {
        if self.execution.pending.is_none() {
            return Poll::Ready(if self.execution.retained.is_some() {
                Ok(())
            } else {
                Err("no retained execution cut".into())
            });
        }
        let cpu_poll = match rollback {
            Some((fenced, rollback)) => self.control.cpus.poll_capture_for_rollback(
                &mut self.vcpus_handles,
                fenced,
                rollback,
            ),
            None => self.control.cpus.poll(&mut self.vcpus_handles),
        };
        match cpu_poll {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.to_string())),
            Poll::Ready(Ok(())) => {}
        }
        let cpus = match self.control.cpus.captured() {
            Ok(cpus) => cpus
                .iter()
                .map(|state| state.as_ref().clone())
                .collect::<Vec<_>>(),
            Err(error) => return Poll::Ready(Err(error.to_string())),
        };
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            let cpu_states = cpus
                .iter()
                .filter_map(|cpu| match cpu {
                    CpuExecutionState::Kvm(state) => Some(state.clone()),
                    _ => None,
                })
                .collect();
            let profile = crate::vmm::linux::execution::KvmCaptureProfile {
                controller: self.execution_controller.clone(),
                cpus: cpu_states,
            };
            let native = self.memory.native()?;
            match self.vm.capture_execution(&profile, &native) {
                Ok(vm) => {
                    if let Some(pending) = &mut self.execution.pending {
                        pending.vm = Some(VmExecutionState::Kvm(vm));
                    }
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        let Some(mut pending) = self.execution.pending.take() else {
            return Poll::Ready(Err("missing pending execution cut".into()));
        };
        let Some(vm) = pending.vm.take() else {
            self.execution.pending = Some(pending);
            return Poll::Ready(Err("missing captured VM state".into()));
        };
        self.execution.retained = Some(RetainedCut {
            key: pending.key,
            vm,
            cpus,
            legacy: pending.legacy,
        });
        self.execution.envelope = None;
        Poll::Ready(Ok(()))
    }

    pub(crate) fn begin_execution_capture(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
        binding: StateBinding,
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))] profile: &KvmCaptureProfile,
        cpu_only_fixture: bool,
    ) -> Result<(), String> {
        use crate::api::capabilities::execution_state_producer;
        binding.validate().map_err(|error| error.to_string())?;
        if binding.pause_generation != barrier.key.generation.0 {
            return Err("capture pause generation mismatch".into());
        }
        if binding.native_producer != execution_state_producer()? {
            return Err("capture exact native producer mismatch".into());
        }
        if cpu_only_fixture {
            if !cfg!(feature = "native-execution-probe")
                || !binding.native_producer.starts_with("diagnostic-only;")
                || self.mmio_device_manager.quiescence.has_transports()
                || !self
                    .mmio_device_manager
                    .quiescence
                    .legacy_attachments()
                    .is_empty()
            {
                return Err(
                    "diagnostic capture requires an explicitly empty CPU-only inventory".into(),
                );
            }
            if self.execution.retained.is_none() && !self.control.cpus.parked(barrier.key) {
                return Err("diagnostic capture requires exact completed CPU park".into());
            }
        } else if !matches!(
            self.control.state,
            crate::vmm::control::ControlState::Paused(_)
        ) || !self
            .mmio_device_manager
            .quiescence
            .fully_quiesced(barrier.key)
            .map_err(|error| error.to_string())?
        {
            return Err("capture requires exact admitted whole-machine pause".into());
        }
        if let Some(previous) = &self.execution.binding
            && self
                .execution
                .retained
                .as_ref()
                .is_some_and(|cut| cut.key.generation == barrier.key.generation)
            && previous != &binding
        {
            return Err("capture binding conflicts with retained cut".into());
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.execution.profile = Some(profile.clone());
        }
        if cpu_only_fixture && self.execution.retained.is_none() {
            self.memory
                .begin_close(barrier.key)
                .map_err(|error| error.to_string())?;
            match self.memory.poll_drained() {
                Poll::Pending => return Err("diagnostic host writers remain outstanding".into()),
                Poll::Ready(result) => result.map_err(|error| error.to_string())?,
            }
        }
        self.execution.binding = Some(binding);
        if !cpu_only_fixture && self.execution.devices.is_none() {
            let records = self
                .mmio_device_manager
                .quiescence
                .capture_devices(barrier.key)
                .map_err(|error| error.to_string())?;
            let devices = crate::vmm::execution::device_restore::DeviceEnvelope {
                binding: self
                    .execution
                    .binding
                    .clone()
                    .ok_or("device cut binding absent")?,
                records,
            };
            devices.validate().map_err(|error| error.to_string())?;
            self.execution.devices = Some(Arc::new(devices));
        }
        self.begin_execution_cut(request, barrier)
    }

    pub(crate) fn flush_devices_for_capture(&self, key: BarrierKey) -> Result<(), String> {
        if !matches!(
            self.control.state,
            crate::vmm::control::ControlState::Paused(_)
        ) {
            return Err("device flush requires whole-machine pause".into());
        }
        self.mmio_device_manager
            .quiescence
            .flush_for_capture(key)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn captured_devices(
        &self,
    ) -> Result<Arc<crate::vmm::execution::device_restore::DeviceEnvelope>, String> {
        self.execution
            .devices
            .clone()
            .ok_or("device cut not captured".into())
    }

    pub(crate) fn poll_execution_capture(
        &mut self,
    ) -> Poll<Result<Arc<ExecutionEnvelope>, String>> {
        match self.poll_execution_cut() {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let key = self
            .execution
            .retained
            .as_ref()
            .ok_or("capture cut absent")?
            .key;
        if !self
            .finish_memory_cut(key)
            .map_err(|error| error.to_string())?
        {
            return Poll::Pending;
        }
        if let Some(envelope) = &self.execution.envelope {
            return Poll::Ready(Ok(envelope.clone()));
        }
        let Some(cut) = &self.execution.retained else {
            return Poll::Ready(Err("capture cut absent".into()));
        };
        let Some(binding) = &self.execution.binding else {
            return Poll::Ready(Err("capture binding absent".into()));
        };
        let Some(first) = cut.cpus.first() else {
            return Poll::Ready(Err("capture CPU inventory empty".into()));
        };
        let mut topology = Vec::with_capacity(cut.cpus.len());
        for cpu in &cut.cpus {
            let architectural_id = match cpu.architectural_id() {
                Ok(id) => id,
                Err(error) => return Poll::Ready(Err(error.to_string())),
            };
            topology.push(CpuIdentity {
                logical_id: cpu.id(),
                architectural_id,
            });
        }
        let page_granule = self.memory_domain.layout().granule();
        let memory_regions = self
            .memory_domain
            .layout()
            .regions()
            .iter()
            .map(|region| region.guest_range())
            .collect();
        #[cfg(target_os = "linux")]
        let irq_routes = match self.mmio_device_manager.execution_irq_routes() {
            Ok(value) => value,
            Err(error) => return Poll::Ready(Err(error)),
        };
        #[cfg(target_os = "macos")]
        let irq_routes = Vec::new();
        let envelope = Arc::new(ExecutionEnvelope {
            binding: binding.clone(),
            lane: first.lane(),
            topology,
            attachments: self.mmio_device_manager.quiescence.attachment_identities(),
            page_granule,
            memory_regions,
            irq_routes,
            vm: cut.vm.clone(),
            cpus: cut.cpus.clone(),
            legacy: cut.legacy.clone(),
        });
        if let Err(error) = envelope.validate() {
            return Poll::Ready(Err(error.to_string()));
        }
        self.execution.envelope = Some(envelope.clone());
        Poll::Ready(Ok(envelope))
    }

    pub(crate) fn begin_execution_refence(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
    ) -> Result<(), String> {
        if self.execution.failed_install || Instant::now() >= barrier.deadline {
            return Err("execution refence is stop-only or expired".into());
        }
        if self.execution.prepared_time == Some(barrier.key) {
            return if self
                .execution
                .preparation
                .as_ref()
                .is_some_and(|plan| plan.admits(barrier))
            {
                Ok(())
            } else {
                Err("conflicting or expired time preparation".into())
            };
        }
        let cut = self
            .execution
            .retained
            .as_ref()
            .ok_or("missing retained execution cut")?;
        if cut.key.generation != barrier.key.generation {
            return Err("execution refence generation mismatch".into());
        }
        self.control
            .cpus
            .begin_native(
                request,
                barrier,
                CpuCommandKind::CaptureExecution,
                &self.vcpus_handles,
                self.memory.native()?,
            )
            .map_err(|error| error.to_string())
    }

    pub(crate) fn begin_execution_time(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
    ) -> Result<(), String> {
        let native = self.memory.native()?;
        native
            .validate_domain(&self.memory_domain)
            .map_err(|error| error.to_string())?;
        if self.execution.failed_install {
            return Err("execution attempt is stop-only".into());
        }
        let cut = self
            .execution
            .retained
            .as_ref()
            .ok_or("missing retained time/controller cut")?;
        if cut.key.generation != barrier.key.generation {
            return Err("time preparation generation mismatch".into());
        }
        if self.execution.prepared_time == Some(barrier.key) {
            return if self
                .execution
                .preparation
                .as_ref()
                .is_some_and(|plan| plan.admits(barrier))
            {
                Ok(())
            } else {
                Err("conflicting or expired time preparation".into())
            };
        }
        if Instant::now() >= barrier.deadline {
            return Err("time preparation deadline expired".into());
        }
        if !self.control.cpus.capture_complete(request, barrier.key) {
            return Err(
                "clock/controller preparation requires completed owner timer refence".into(),
            );
        }
        self.mmio_device_manager
            .quiescence
            .install_legacy(&cut.legacy)?;
        #[cfg(target_os = "linux")]
        let plans = {
            let VmExecutionState::Kvm(vm) = &cut.vm else {
                return Err("wrong VM backend".into());
            };
            self.vm.install_execution(vm, &native)?;
            let cpus = cut
                .cpus
                .iter()
                .map(|cpu| match cpu {
                    CpuExecutionState::Kvm(state) => Ok(state.clone()),
                    _ => Err("wrong CPU backend".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.vm
                .prepare_execution_time(vm, &cpus, &native)?
                .into_iter()
                .map(CpuTimePlan::Kvm)
                .collect::<Vec<_>>()
        };
        #[cfg(target_os = "macos")]
        let plans = {
            let VmExecutionState::Hvf(vm) = &cut.vm else {
                return Err("wrong VM backend".into());
            };
            let destination = hvf::capture_clock_cut().map_err(|error| error.to_string())?;
            if destination.frequency != vm.clock.frequency
                || destination.timebase_numer != vm.clock.timebase_numer
                || destination.timebase_denom != vm.clock.timebase_denom
            {
                return Err("HVF clock profile mismatch".into());
            }
            self.execution_controller
                .try_lock()
                .map_err(|_| "GIC lock")?
                .install_hvf_state(&vm.gic)
                .map_err(|error| error.to_string())?;
            cut.cpus
                .iter()
                .map(|cpu| match cpu {
                    CpuExecutionState::Hvf(cpu) => {
                        Ok(CpuTimePlan::Hvf(crate::vmm::execution::HvfCpuTimePlan {
                            logical_id: cpu.logical_id,
                            timer: cpu.timer,
                            absolute_offset: vm
                                .clock
                                .destination_offset(cpu.timer.offset, destination.host_counter),
                        }))
                    }
                    _ => Err("wrong CPU backend".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let inputs = plans
            .iter()
            .cloned()
            .map(|plan| Some(Arc::new(CpuExecutionInput::PrepareTime(plan))))
            .collect::<Vec<_>>();
        self.execution.preparation = Some(TimePreparation {
            key: barrier.key,
            plans,
            deadline: barrier.deadline,
        });
        self.control
            .cpus
            .begin_execution(
                request,
                barrier,
                CpuCommandKind::PrepareExecutionTime,
                &inputs,
                &self.vcpus_handles,
                Some(native),
            )
            .map_err(|error| error.to_string())?;
        self.execution.prepared_time = Some(barrier.key);
        Ok(())
    }

    pub(crate) fn prepare_execution_release(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
    ) -> Result<(), String> {
        if self.memory.has_attempt() {
            return Err("RAM capture attempt is unresolved".into());
        }
        let cut_key = self
            .execution
            .retained
            .as_ref()
            .ok_or("missing retained memory cut")?
            .key;
        if cut_key.generation != barrier.key.generation {
            return Err("memory resume generation mismatch".into());
        }
        while !self
            .reopen_memory_for_resume(cut_key)
            .map_err(|error| error.to_string())?
        {
            if Instant::now() >= barrier.deadline {
                return Err("native writer drain deadline".into());
            }
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        self.begin_execution_refence(request, barrier)?;
        self.wait_execution_command(barrier)?;
        self.begin_execution_time(request, barrier)?;
        self.wait_execution_command(barrier)?;
        self.control
            .cpus
            .begin(
                request,
                barrier,
                CpuCommandKind::PrepareResume { paused_ticks: 0 },
                &self.vcpus_handles,
            )
            .map_err(|error| error.to_string())?;
        self.wait_execution_command(barrier)
    }

    pub(crate) fn release_prepared_execution(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
    ) -> Result<(), String> {
        if self.memory.has_attempt() {
            return Err("RAM capture attempt is unresolved".into());
        }
        if self.mmio_device_manager.quiescence.has_transports()
            || !self
                .mmio_device_manager
                .quiescence
                .legacy_attachments()
                .is_empty()
        {
            return Err(
                "CPU-only release cannot bypass device, route and callback barriers".into(),
            );
        }
        if self.execution.prepared_time != Some(barrier.key)
            || self.execution.failed_install
            || !self
                .execution
                .preparation
                .as_ref()
                .is_some_and(|plan| plan.admits(barrier))
        {
            return Err("execution release is not prepared".into());
        }
        self.memory.retire_native();
        self.control
            .cpus
            .begin(
                request,
                barrier,
                CpuCommandKind::Release,
                &self.vcpus_handles,
            )
            .map_err(|error| {
                self.execution.failed_install = true;
                error.to_string()
            })?;
        if let Err(error) = self.wait_execution_command(barrier) {
            self.execution.failed_install = true;
            return Err(error);
        }
        self.finish_execution_release();
        self.control.state = crate::vmm::control::ControlState::Running;
        Ok(())
    }

    pub(crate) fn finish_execution_release(&mut self) {
        self.execution.retained = None;
        self.execution.pending = None;
        self.execution.envelope = None;
        self.execution.devices = None;
        self.execution.binding = None;
        self.execution.prepared_time = None;
        #[cfg(target_os = "linux")]
        self.vm.finish_execution_release();
    }

    pub(crate) fn wait_execution_command(&mut self, barrier: BarrierRequest) -> Result<(), String> {
        loop {
            match self.control.cpus.poll(&mut self.vcpus_handles) {
                Poll::Ready(result) => {
                    return result.map_err(|error| error.to_string()).and_then(|()| {
                        if Instant::now() >= barrier.deadline {
                            Err("execution owner completed after deadline".into())
                        } else {
                            Ok(())
                        }
                    });
                }
                Poll::Pending if Instant::now() >= barrier.deadline => {
                    return Err("execution owner deadline".into());
                }
                Poll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
    }

    pub(crate) fn stop_execution_attempt(
        &mut self,
        request: RequestId,
        barrier: BarrierRequest,
    ) -> Poll<Result<(), String>> {
        self.execution.failed_install = true;
        if !self.vcpus_handles.is_empty() {
            if !self
                .control
                .cpus
                .active_request()
                .is_some_and(|(id, key, kind)| {
                    id == request && key.key == barrier.key && kind == CpuCommandKind::Stop
                })
                && let Err(error) = self.control.cpus.begin(
                    request,
                    barrier,
                    CpuCommandKind::Stop,
                    &self.vcpus_handles,
                )
            {
                return Poll::Ready(Err(error.to_string()));
            }
            match self.control.cpus.poll(&mut self.vcpus_handles) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.to_string())),
                Poll::Ready(Ok(())) => {}
            }
        }
        match self.mmio_device_manager.quiescence.poll_stop(barrier) {
            Ok(Poll::Pending) => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error.to_string())),
            Ok(Poll::Ready(())) => {}
        }
        if !self.mmio_device_manager.poll_irq_cleanup() {
            return Poll::Pending;
        }
        if Instant::now() >= barrier.deadline {
            return Poll::Ready(Err("terminal cleanup completed after deadline".into()));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(not(all(
    not(feature = "tee"),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64")
    )
)))]
impl Vmm {
    pub(crate) fn begin_execution_cut(
        &mut self,
        _request: RequestId,
        _barrier: BarrierRequest,
    ) -> Result<(), String> {
        Err("execution state excluded for this build/backend".into())
    }
    pub(crate) fn poll_execution_cut(&mut self) -> Poll<Result<(), String>> {
        Poll::Ready(Err("execution state excluded for this build/backend".into()))
    }
    pub(crate) fn poll_execution_cut_for_rollback(
        &mut self,
        _fenced: BarrierKey,
        _rollback: BarrierRequest,
    ) -> Poll<Result<(), String>> {
        self.poll_execution_cut()
    }
    pub(crate) fn begin_execution_refence(
        &mut self,
        _request: RequestId,
        _barrier: BarrierRequest,
    ) -> Result<(), String> {
        Err("execution state excluded for this build/backend".into())
    }
    pub(crate) fn begin_execution_time(
        &mut self,
        _request: RequestId,
        _barrier: BarrierRequest,
    ) -> Result<(), String> {
        Err("execution state excluded for this build/backend".into())
    }
    pub(crate) fn finish_execution_release(&mut self) {
        self.execution.retained = None;
        self.execution.pending = None;
        self.execution.prepared_time = None;
    }
}

#[cfg(test)]
mod tests {
    use crate::vmm::control::{BarrierGeneration, BarrierKey, BarrierRequest, OperationId};
    use crate::vmm::execution::runtime::TimePreparation;
    use std::time::{Duration, Instant};

    #[test]
    fn execution_preparation_binds_original_deadline_and_generation() {
        let key = BarrierKey {
            operation: OperationId(9),
            generation: BarrierGeneration(4),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        let plan = TimePreparation {
            key,
            plans: Vec::new(),
            deadline,
        };
        assert!(plan.admits(BarrierRequest { key, deadline }));
        assert!(!plan.admits(BarrierRequest {
            key,
            deadline: deadline + Duration::from_secs(1)
        }));
        let foreign = BarrierKey {
            generation: BarrierGeneration(5),
            ..key
        };
        assert!(!plan.admits(BarrierRequest {
            key: foreign,
            deadline
        }));
        let expired = TimePreparation {
            key,
            plans: Vec::new(),
            deadline: Instant::now() - Duration::from_secs(1),
        };
        assert!(!expired.admits(BarrierRequest {
            key,
            deadline: expired.deadline
        }));
    }

    #[test]
    fn execution_prefence_vm_refusal_retires_only_unmodified_pre_dispatch_bookkeeping() {
        use crate::vmm::execution::runtime::{ExecutionOwner, PendingCut};
        let key = BarrierKey {
            operation: OperationId(11),
            generation: BarrierGeneration(7),
        };
        let pending = |cpu_dispatched| PendingCut {
            key,
            vm: None,
            legacy: Vec::new(),
            cpu_dispatched,
        };
        let mut owner = ExecutionOwner {
            pending: Some(pending(false)),
            ..ExecutionOwner::default()
        };
        assert!(!owner.retire_unmodified_vm_refusal(key, true));
        assert!(owner.pending.is_some());
        let foreign = BarrierKey {
            operation: OperationId(12),
            ..key
        };
        assert!(!owner.retire_unmodified_vm_refusal(foreign, false));
        assert!(owner.pending.is_some());
        owner.pending = Some(pending(true));
        assert!(!owner.retire_unmodified_vm_refusal(key, false));
        assert!(owner.pending.is_some());
        owner.pending = Some(pending(false));
        assert!(owner.retire_unmodified_vm_refusal(key, false));
        assert!(!owner.has_cut_work());
    }
}
