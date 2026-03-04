// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Oxide Computer Company

//! Version `SWITCH_IDENTIFIERS` of the LLDP daemon API.
//!
//! Adds the `/switch/identifiers` endpoint, which reports the switch slot
//! being managed by this lldpd instance.

pub mod switch;
