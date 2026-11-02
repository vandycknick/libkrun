// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Package-local compiled feature and build-input observations.
pub mod build_facts {
    include!(concat!(env!("OUT_DIR"), "/live_build.rs"));
}

pub mod event_manager;
