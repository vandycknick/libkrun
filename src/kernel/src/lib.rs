// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// Package-local compiled feature and build-input observations.
pub mod build_facts {
    include!(concat!(env!("OUT_DIR"), "/live_build.rs"));
}

pub mod cmdline;
pub mod loader;
