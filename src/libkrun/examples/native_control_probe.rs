//! Deliberately standalone: no machine execution is reachable from a Cargo test.

use std::process::ExitCode;

#[cfg(all(
    feature = "native-control-probe",
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee")
))]
fn main() -> ExitCode {
    match krun::api::native_control_probe::run() {
        Ok(result) => {
            println!("{}", result.json());
            ExitCode::SUCCESS
        }
        Err(result) => {
            println!("{}", result.json());
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(
    feature = "native-control-probe",
    target_os = "linux",
    target_arch = "x86_64",
    not(feature = "tee")
)))]
fn main() -> ExitCode {
    println!(
        "{{\"schema\":1,\"scope\":\"cpu-sub-barrier-only\",\"status\":\"unsupported\",\"error\":\"requires native-control-probe on non-TEE Linux x86_64\"}}"
    );
    ExitCode::FAILURE
}
