// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Package-local compiled feature and build-input observations.
pub mod build_facts {
    include!(concat!(env!("OUT_DIR"), "/live_build.rs"));
}

#[allow(clippy::all)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
