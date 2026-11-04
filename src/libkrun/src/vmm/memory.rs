use std::sync::Arc;
use std::task::Poll;

use crate::vmm::Vmm;
use crate::vmm::control::{BarrierKey, ControlState, PauseToken};
use arch::guest_memory::{
    ClosingMemory, ConstructionAuthority, CpuTrackingEpoch, DirtyPageMap, DomainControl,
    DrainedMemory, MemoryCut, MemoryError, NativeEffectsPermit, TrackingMode,
};

pub struct MemoryCoordinator {
    pub(crate) control: DomainControl,
    pub(crate) construction: Option<ConstructionAuthority>,
    pending: Option<DirtyPageMap>,
    key: Option<BarrierKey>,
    pause: Option<PauseToken>,
    closing: Option<ClosingMemory>,
    drained: Option<DrainedMemory>,
    native: Option<Arc<NativeEffectsPermit>>,
    cut: Option<MemoryCut>,
    next: Option<CpuTrackingEpoch>,
}
impl MemoryCoordinator {
    pub(crate) fn has_closing(&self) -> bool {
        self.closing.is_some()
    }
    pub fn new(control: DomainControl, construction: ConstructionAuthority) -> Self {
        Self {
            control,
            construction: Some(construction),
            pending: None,
            key: None,
            pause: None,
            closing: None,
            drained: None,
            native: None,
            cut: None,
            next: None,
        }
    }
    pub(crate) fn finish_untracked(&mut self) -> Result<(), MemoryError> {
        self.control
            .finish_untracked(self.construction.take().ok_or(MemoryError::State)?)
    }
    #[cfg(not(feature = "tee"))]
    pub(crate) fn finish_tracked(&mut self, epoch: CpuTrackingEpoch) -> Result<(), MemoryError> {
        self.control
            .finish_tracked(self.construction.take().ok_or(MemoryError::State)?, epoch)?;
        self.pending = Some(DirtyPageMap::new(self.control.domain().layout()));
        Ok(())
    }
    pub(crate) fn begin_close(&mut self, key: BarrierKey) -> Result<(), MemoryError> {
        if self.key.is_some_and(|current| current != key) {
            return Err(MemoryError::Authority);
        }
        if self.key.is_none() {
            self.closing = Some(self.control.close()?);
            self.key = Some(key);
        }
        Ok(())
    }
    pub(crate) fn poll_drained(&mut self) -> Poll<Result<(), MemoryError>> {
        if self.drained.is_some() {
            return Poll::Ready(Ok(()));
        }
        let Some(closing) = self.closing.as_ref() else {
            return Poll::Ready(Err(MemoryError::State));
        };
        match self.control.poll_drained(closing) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(drained)) => {
                match self.control.native_effects(&drained) {
                    Ok(permit) => self.native = Some(Arc::new(permit)),
                    Err(error) => return Poll::Ready(Err(error)),
                }
                self.drained = Some(drained);
                Poll::Ready(Ok(()))
            }
        }
    }
    pub(crate) fn native(&self) -> Result<Arc<NativeEffectsPermit>, String> {
        self.native
            .clone()
            .ok_or("native memory authority absent".into())
    }
    pub(crate) fn begin_runtime_native(&mut self) -> Result<(), MemoryError> {
        if self.native.is_none() {
            self.native = Some(Arc::new(self.control.runtime_native_effects()?));
        }
        Ok(())
    }
    pub(crate) fn retire_native(&mut self) {
        self.native = None;
    }
    pub(crate) fn bind_pause(
        &mut self,
        key: BarrierKey,
        pause: &PauseToken,
    ) -> Result<(), MemoryError> {
        if self.key != Some(key) || self.cut.is_none() || self.next.is_none() {
            return Err(MemoryError::Authority);
        }
        self.pause = Some(pause.clone());
        Ok(())
    }
    pub(crate) fn reopen(&mut self, key: BarrierKey) -> Result<(), MemoryError> {
        if self.key != Some(key) {
            return Err(MemoryError::Authority);
        }
        self.control.reopen(
            self.cut.take().ok_or(MemoryError::State)?,
            self.next.take().ok_or(MemoryError::State)?,
        )?;
        self.key = None;
        self.pause = None;
        self.closing = None;
        self.drained = None;
        Ok(())
    }
}

impl Vmm {
    pub fn memory_dirty_pages(&self, token: &PauseToken) -> Result<&DirtyPageMap, String> {
        if !matches!(&self.control.state, ControlState::Paused(current) if current == token)
            || self.memory.pause.as_ref() != Some(token)
        {
            return Err("memory observation requires exact retained pause".into());
        }
        self.memory
            .pending
            .as_ref()
            .ok_or("memory tracking disabled".into())
    }
    pub(crate) fn finalize_source_memory(
        &mut self,
        structural_lane: bool,
    ) -> Result<(), crate::vmm::Error> {
        #[cfg(not(feature = "tee"))]
        {
            use crate::vmm::device_manager::quiescence::ManagerFault;
            use devices::virtio::lifecycle::ProviderFault;
            let mut eligible = structural_lane
                && !self.memory_domain.external_mapping_exported()
                && self.memory_domain.layout().validate_capture().is_ok()
                && cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));
            if eligible {
                let controller = self.execution_controller.try_lock().map_err(|error| {
                    crate::vmm::Error::Control(crate::vmm::control::ControlFailure::Participant(
                        error.to_string(),
                    ))
                })?;
                eligible = controller.execution_state_supported();
            }
            if eligible {
                match self.mmio_device_manager.preflight_quiesce() {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.fault,
                            ManagerFault::Provider(ProviderFault::Unsupported)
                                | ManagerFault::MissingLegacyProvider(_)
                        ) =>
                    {
                        eligible = false
                    }
                    Err(error) => {
                        return Err(crate::vmm::Error::Control(
                            crate::vmm::control::ControlFailure::Participant(error.to_string()),
                        ));
                    }
                }
            }
            if eligible {
                let epoch = self
                    .vm
                    .arm_initial(
                        self.memory
                            .construction
                            .as_ref()
                            .ok_or(crate::vmm::Error::Memory(MemoryError::State))?,
                    )
                    .map_err(crate::vmm::Error::DirtyMemory)?;
                return self
                    .memory
                    .finish_tracked(epoch)
                    .map_err(crate::vmm::Error::Memory);
            }
        }
        #[cfg(feature = "tee")]
        let _ = structural_lane;
        self.memory
            .finish_untracked()
            .map_err(crate::vmm::Error::Memory)
    }
    #[cfg(not(feature = "tee"))]
    pub(crate) fn finish_memory_cut(&mut self, key: BarrierKey) -> Result<bool, String> {
        if self.memory.key != Some(key) {
            return Err("memory cut barrier mismatch".into());
        }
        if self.memory.cut.is_some() {
            return Ok(true);
        }
        if !self.control.cpus.reconciled() {
            return Ok(false);
        }
        self.memory.retire_native();
        let drained = self
            .memory
            .drained
            .as_ref()
            .ok_or("memory writers not drained")?;
        match self.memory.control.poll_native_drained(drained) {
            Poll::Pending => return Ok(false),
            Poll::Ready(result) => result.map_err(|error| error.to_string())?,
        }
        let cut = self
            .memory
            .control
            .seal(
                self.memory
                    .drained
                    .as_ref()
                    .ok_or("memory writers not drained")?,
            )
            .map_err(|error| error.to_string())?;
        let pending = self
            .memory
            .pending
            .as_mut()
            .ok_or("memory tracking disabled")?;
        self.memory
            .control
            .drain_host_dirty(&cut, pending)
            .map_err(|error| error.to_string())?;
        let harvested = match self.vm.collect_cpu_dirty(&cut, pending) {
            Ok(harvested) => harvested,
            Err(error) => {
                self.memory_domain.invalidate_coverage();
                return Err(error.to_string());
            }
        };
        let next = match self.vm.rearm_cpu_dirty(&cut, harvested) {
            Ok(next) => next,
            Err(error) => {
                self.memory_domain.invalidate_coverage();
                return Err(error.to_string());
            }
        };
        self.memory.cut = Some(cut);
        self.memory.next = Some(next);
        Ok(true)
    }
    #[cfg(feature = "tee")]
    pub(crate) fn finish_memory_cut(&mut self, _key: BarrierKey) -> Result<bool, String> {
        Err("tracked memory is unsupported for confidential VMs".into())
    }
    pub(crate) fn reopen_memory_for_resume(&mut self, key: BarrierKey) -> Result<bool, String> {
        if self.memory_domain.tracking_mode() != Some(TrackingMode::Capture) {
            return Err("memory tracking disabled".into());
        }
        if self.memory.key.is_some() {
            if self.memory.cut.is_none() && !self.finish_memory_cut(key)? {
                return Ok(false);
            }
            self.memory.reopen(key).map_err(|error| error.to_string())?;
        }
        self.memory
            .begin_runtime_native()
            .map_err(|error| error.to_string())?;
        Ok(true)
    }
}

#[cfg(test)]
pub(crate) fn runtime_memory_for_test(
    memory: vm_memory::GuestMemoryMmap,
) -> devices::virtio::RuntimeGuestMemory {
    let (domain, construction, mut control) = arch::guest_memory::MemoryDomain::construct(
        memory,
        4096,
        arch::guest_memory::BackingKind::Boot,
    )
    .unwrap();
    control.finish_untracked(construction).unwrap();
    devices::virtio::RuntimeGuestMemory::new(domain)
}
