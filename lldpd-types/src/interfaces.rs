// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

use protocol::types::{ChassisId, PortId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::system_info::SystemInfo;

/// A local interface on which we are listening for, and dispatching, LLDPDUs
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Interface {
    pub port: String,
    pub iface: String,
    pub disabled: bool,
    pub system_info: SystemInfo,
}

/// Optional arguments when adding an interface to LLDPD.  Any argument left
/// unspecified will be assigned the default values for this system.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct InterfaceAdd {
    pub chassis_id: Option<ChassisId>,
    pub port_id: Option<PortId>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,
}
