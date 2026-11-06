//! Candidate-only access to the existing native AP2 hardware IRQ witness.
//!
//! Initialization is source construction, never a restore operation. Observation
//! reads owner RAM and the retained native cut; commands use the guest protocol.
use std::time::{Duration, Instant};

use crate::api::live::LiveError;
use crate::api::vmm_builder::VmmHandle;
use crate::api::vmm_builder::native_device_probe::witness::fixture_layout;
use crate::vmm::control::live::{LiveReply, LiveRequest};
use crate::vmm::control::{ControlFailure, OperationId, PauseToken};

#[derive(Debug)]
pub struct Fixture {
    pub(crate) code: Vec<u8>,
    pub(crate) layout: FixtureLayout,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct FixtureLayout {
    pub handler: u64,
    pub idt: u64,
    pub completion_ips: [u64; 2],
}
impl Fixture {
    pub fn new(code: Vec<u8>, symbols: String) -> Result<Self, String> {
        if code.is_empty() || code.len() > 0x3000 || symbols.len() > 65536 {
            return Err("bounded witness fixture code/symbols".into());
        }
        let layout = fixture_layout(&code, &symbols)?;
        Ok(Self { code, layout })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeCommand {
    Pending,
    Reset,
    Accept,
    Unmask,
}
impl ProbeCommand {
    pub(crate) fn word(self) -> u64 {
        match self {
            Self::Pending => 2,
            Self::Reset => 12,
            Self::Accept => 11,
            Self::Unmask => 10,
        }
    }
}
#[derive(Debug)]
pub enum ProbeRequest {
    Initialize { pause: PauseToken, fixture: Fixture },
    Command(ProbeCommand),
    Observe,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeObservation {
    pub words: [u64; 23],
    pub irq_publication: [u64; 2],
    /// Native vector 224 state from the retained AP2 cut, not a live estimate.
    pub pending: Option<bool>,
    pub in_service: Option<bool>,
    pub deadline: Option<u64>,
}
impl VmmHandle {
    pub fn irq_probe(
        &self,
        request: ProbeRequest,
        operation: OperationId,
        deadline: Instant,
    ) -> Result<ProbeObservation, LiveError> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
        self.live_call(operation, deadline, LiveRequest::IrqProbe(request))
            .and_then(|reply| match reply {
                LiveReply::IrqProbe(observation) => Ok(observation),
                _ => Err(ControlFailure::OwnerUnavailable.into()),
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::api::live::irq_probe::{Fixture, ProbeCommand};

    #[test]
    fn fixture_rejects_empty_oversized_and_missing_symbols_without_native_vm() {
        assert!(Fixture::new(Vec::new(), String::new()).is_err());
        assert!(Fixture::new(vec![0; 0x3001], String::new()).is_err());
        assert!(Fixture::new(vec![0; 1], "x".repeat(65537)).is_err());
        assert!(Fixture::new(vec![0; 0x3000], String::new()).is_err());
    }

    #[test]
    fn fixture_requires_unique_symbols_inside_the_supplied_code() {
        let symbols = "1c001000 T _start\n1c001010 T witness_interrupt\n1c001020 T witness_io_complete\n1c001030 T witness_mmio_complete\n1c001100 T witness_idt\n";
        assert!(Fixture::new(vec![0; 0x100], symbols.into()).is_err());
        assert!(Fixture::new(vec![0; 0x3000], symbols.into()).is_ok());
        assert!(
            Fixture::new(
                vec![0; 0x3000],
                format!("{symbols}1c001011 T witness_interrupt\n")
            )
            .is_err()
        );
    }

    #[test]
    fn commands_use_the_original_guest_protocol() {
        assert_eq!(ProbeCommand::Pending.word(), 2);
        assert_eq!(ProbeCommand::Reset.word(), 12);
        assert_eq!(ProbeCommand::Accept.word(), 11);
        assert_eq!(ProbeCommand::Unmask.word(), 10);
    }
}
