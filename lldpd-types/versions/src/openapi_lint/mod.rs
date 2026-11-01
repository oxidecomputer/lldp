// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Oxide Computer Company

//! Version `OPENAPI_LINT` of the LLDP daemon API.
//!
//! Makes the API conform to openapi-lint: chassis ID, port ID, and system
//! capability names are serialized in snake_case, paths use kebab-case, and
//! adding an interface returns no content.

pub mod interfaces;
pub mod neighbor;
pub mod system_info;
