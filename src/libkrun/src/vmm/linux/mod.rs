pub(crate) mod cpu_control;
#[cfg(not(feature = "tee"))]
pub(crate) mod dirty;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) mod execution;

#[cfg(feature = "tee")]
pub mod tee;

pub mod vstate;
