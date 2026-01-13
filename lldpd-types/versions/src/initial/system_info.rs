// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

use std::net::IpAddr;

use protocol::types::{
    ChassisId, ManagementAddress, PortId, SystemCapabilities,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SystemCapabilityPathParams {
    pub capability: SystemCapabilities,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SystemAddressPathParams {
    pub address: IpAddr,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct SystemInfo {
    pub chassis_id: ChassisId,
    pub port_id: PortId,
    pub ttl: u16,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub capabilities_available: Vec<SystemCapabilities>,
    pub capabilities_enabled: Vec<SystemCapabilities>,
    pub management_addresses: Vec<ManagementAddress>,
    pub organizationally_specific: Vec<String>,
}
