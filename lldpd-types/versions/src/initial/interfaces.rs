// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

use std::net::IpAddr;

use protocol::types::{ChassisId, PortId, SystemCapabilities};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::system_info::SystemInfo;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct InterfacePathParams {
    /// The switch port on which to operate.
    pub iface: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct InterfaceCapabilityPathParams {
    /// The switch port on which to operate.
    pub iface: String,
    pub capability: SystemCapabilities,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct InterfaceAddressPathParams {
    /// The switch port on which to operate.
    pub iface: String,
    /// Management Address to advertise on this port
    // TODO-completeness: this should allow non-IP addresses to be specified (as
    // per the standard) and should include an optional interface number.
    pub address: IpAddr,
}

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
