//! Explicitly invoked ordinary-kernel/provider driver, never a Cargo VM test.
use std::process::ExitCode;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(any(feature = "tee", feature = "aws-nitro"))
))]
fn main() -> ExitCode {
    match krun::api::vmm_builder::native_device_probe::run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("whole-machine-production driver: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(any(feature = "tee", feature = "aws-nitro"))
)))]
fn main() -> ExitCode {
    eprintln!(
        "whole-machine production driver requires ordinary KVM x86_64; other runtime lanes remain unqualified"
    );
    ExitCode::FAILURE
}
