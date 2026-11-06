use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::time::Instant;

use crate::api::live::{RamImageAuthentication, StateBinding};
use crate::api::vmm_builder::Vmm;
pub use crate::vmm::control::RestoreToken;
pub use devices::virtio::block::{ReadonlyVmdk, RestoreBlockBacking, VmdkExtent};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateObjectIdentity {
    pub length: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreIdentity {
    pub binding: StateBinding,
    pub ram_image: RamImageAuthentication,
    pub execution_object: StateObjectIdentity,
    pub devices_object: StateObjectIdentity,
}

/// Trust and immutable-inode leases remain the caller's responsibility.
/// The native boundary independently checks descriptors, metadata and bindings.
pub struct RestoreInputs {
    pub ram: File,
    pub layout: File,
    pub execution: File,
    pub devices: File,
    pub expected: RestoreIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreAttachment {
    pub configured_id: String,
    pub address: u64,
    pub irq: u32,
}

/// The backing variant is the destination format and must equal the format
/// captured for this attachment: raw is never substituted for a saved VMDK.
pub struct RestoreBlock {
    pub attachment: RestoreAttachment,
    pub backing: RestoreBlockBacking,
}
impl RestoreBlock {
    pub fn raw(attachment: RestoreAttachment, file: File, read_only: bool) -> Self {
        Self {
            attachment,
            backing: RestoreBlockBacking::Raw { file, read_only },
        }
    }

    /// `descriptor` is the manager-generated launch descriptor; `extents`
    /// holds one validated handle per distinct `FLAT` path it names.
    pub fn readonly_vmdk(
        attachment: RestoreAttachment,
        descriptor: File,
        extents: Vec<VmdkExtent>,
    ) -> Self {
        Self {
            attachment,
            backing: RestoreBlockBacking::ReadonlyVmdk(ReadonlyVmdk {
                descriptor,
                extents,
            }),
        }
    }
}
pub struct RestoreNetwork {
    pub attachment: RestoreAttachment,
    /// Must already be protected by the caller's reservation ingress fence.
    pub socket: UnixDatagram,
    pub mac: [u8; 6],
}
pub struct RestoreVsock {
    pub attachment: RestoreAttachment,
    pub mux: OwnedFd,
    pub cid: u64,
    pub agent_port: NonZeroU32,
}
pub struct RestoreConsolePort {
    pub name: String,
    pub input: Option<File>,
    pub output: Option<File>,
    pub terminal: bool,
}
pub struct RestoreConsole {
    pub attachment: RestoreAttachment,
    pub ports: Vec<RestoreConsolePort>,
}
pub struct RestoreSerial {
    pub address: u64,
    pub input: Option<File>,
    pub output: Option<File>,
}

#[derive(Default)]
pub struct RestoreResources {
    pub blocks: Vec<RestoreBlock>,
    pub networks: Vec<RestoreNetwork>,
    pub vsocks: Vec<RestoreVsock>,
    pub consoles: Vec<RestoreConsole>,
    pub serial: Vec<RestoreSerial>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreRole {
    Ram,
    Layout,
    Execution,
    Devices,
    Block,
    VmdkDescriptor,
    VmdkExtent,
    Network,
    Vsock,
    Console,
    Serial,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreProblem {
    NotRegular,
    Access,
    CloseOnExec,
    Alias,
    Length,
    Digest,
    Inventory,
    ColdConfiguration,
    Topology,
    Generation,
    Deadline,
    /// Destination backing format differs from the captured format.
    Format,
    /// A read-only VMDK descriptor/extent closure is not the admitted one.
    Closure,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreStage {
    Validation,
    Reconstruction,
    NativeInstall,
    DispatchRegistration,
    Cleanup,
}

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("restore {role:?}: {problem:?}")]
    Descriptor {
        role: RestoreRole,
        problem: RestoreProblem,
    },
    #[error("restore refused: {0:?}")]
    Refused(RestoreProblem),
    #[error("restore metadata: {0}")]
    Codec(#[from] utils::state::Error),
    #[error("restore RAM: {0}")]
    Ram(#[from] crate::vmm::memory::image::RamImageError),
    #[error("restore {role:?} I/O: {source}")]
    Io {
        role: RestoreRole,
        source: std::io::Error,
    },
    #[error("restore {stage:?}: {cause}")]
    Native { stage: RestoreStage, cause: String },
    #[error("restore control: {0:?}")]
    Control(crate::vmm::control::ControlFailure),
}

pub struct RestoreBuildFailure<'a> {
    pub reason: RestoreError,
    pub failed: Option<FailedRestore<'a>>,
}
impl std::fmt::Debug for RestoreBuildFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreBuildFailure")
            .field("reason", &self.reason)
            .field("owner_retained", &self.failed.is_some())
            .finish()
    }
}
impl std::fmt::Display for RestoreBuildFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for RestoreBuildFailure<'_> {}

#[derive(Default)]
pub(crate) struct RestoreCleanup {
    started: bool,
}

impl RestoreCleanup {
    pub(crate) fn ensure_started(
        &mut self,
        client: &crate::vmm::control::ControlClient,
        deadline: Instant,
    ) -> Result<(), crate::vmm::control::ControlFailure> {
        if self.started {
            return Ok(());
        }
        match client.begin_restore_cleanup(deadline) {
            Ok(()) | Err(crate::vmm::control::ControlFailure::WakeUnknown(_)) => {
                self.started = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

/// Owns the complete dispatch and backing lifetime of a failed install.
#[must_use]
pub struct FailedRestore<'a> {
    pub(crate) vm: Option<Box<Vmm<'a>>>,
    pub(crate) cleanup: RestoreCleanup,
}
impl<'a> FailedRestore<'a> {
    /// A caller deadline is never permission to destroy an accepted native user.
    pub fn cleanup(mut self, deadline: Instant) -> Result<(), Self> {
        if let Some(vm) = self.vm.as_mut()
            && !crate::api::vmm_builder::restored::cleanup(vm, &mut self.cleanup, deadline)
        {
            return Err(self);
        }
        self.vm.take();
        Ok(())
    }
}
impl Drop for FailedRestore<'_> {
    fn drop(&mut self) {
        if let Some(mut vm) = self.vm.take() {
            let deadline = Instant::now() + std::time::Duration::from_secs(1);
            if !crate::api::vmm_builder::restored::cleanup(&mut vm, &mut self.cleanup, deadline) {
                // An uncooperative accepted native user must not observe freed RAM.
                // Explicit cleanup returns this owner instead; Drop cannot return it.
                log::error!("retaining failed restore ownership after nonterminal cleanup");
                std::mem::forget(vm);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api::live::restore::RestoreCleanup;
    use crate::vmm::control::{ControlClient, ControlFailure, RequestKind};
    use std::time::{Duration, Instant};

    #[test]
    fn retained_restore_cleanup_enqueues_once_without_renewing_native_deadline() {
        let (client, receiver) = ControlClient::channel().unwrap();
        let original_deadline = Instant::now() + Duration::from_secs(60);
        let mut cleanup = RestoreCleanup::default();
        cleanup.ensure_started(&client, original_deadline).unwrap();
        let request = receiver.try_recv().unwrap().unwrap();
        assert!(matches!(request.kind, RequestKind::CleanupRestore));
        assert_eq!(request.deadline, original_deadline);
        cleanup
            .ensure_started(&client, Instant::now() - Duration::from_secs(1))
            .unwrap();
        cleanup
            .ensure_started(&client, original_deadline + Duration::from_secs(60))
            .unwrap();
        assert!(receiver.try_recv().unwrap().is_none());
        assert_eq!(request.deadline, original_deadline);
    }

    #[test]
    fn refused_restore_cleanup_does_not_claim_command_ownership() {
        let (client, receiver) = ControlClient::channel().unwrap();
        let mut cleanup = RestoreCleanup::default();
        assert!(matches!(
            cleanup.ensure_started(&client, Instant::now() - Duration::from_secs(1)),
            Err(ControlFailure::Deadline),
        ));
        assert!(receiver.try_recv().unwrap().is_none());
        cleanup
            .ensure_started(&client, Instant::now() + Duration::from_secs(60))
            .unwrap();
        assert!(matches!(
            receiver.try_recv().unwrap().unwrap().kind,
            RequestKind::CleanupRestore
        ));
    }
}
