//! This target is explicitly invoked, never a guest-executing Cargo test.
use std::process::ExitCode;

#[cfg(all(
    feature = "native-execution-probe",
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee")
))]
fn main() -> ExitCode {
    match krun::api::native_execution_probe::run(std::env::args_os().skip(1).collect()) {
        Ok(record) => {
            println!("{}", record.json());
            ExitCode::SUCCESS
        }
        Err(record) => {
            println!("{}", record.json());
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(
    feature = "native-execution-probe",
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee")
)))]
fn main() -> ExitCode {
    println!(
        "{{\"schema\":1,\"scope\":\"cpu-execution-only\",\"status\":\"unsupported\",\"qualification_eligible\":false,\"error\":\"requires native-execution-probe on non-TEE Linux x86_64; actual KVM arm64/HVF runtime pending\"}}"
    );
    ExitCode::FAILURE
}
