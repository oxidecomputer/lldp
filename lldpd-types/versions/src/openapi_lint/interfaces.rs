// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::system_info::{ChassisId, PortId, SystemCapabilities, SystemInfo};
use crate::v1;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct InterfaceCapabilityPathParams {
    /// The switch port on which to operate.
    pub iface: String,
    pub capability: SystemCapabilities,
}

impl From<v1::interfaces::InterfaceCapabilityPathParams>
    for InterfaceCapabilityPathParams
{
    fn from(old: v1::interfaces::InterfaceCapabilityPathParams) -> Self {
        InterfaceCapabilityPathParams {
            iface: old.iface,
            capability: SystemCapabilities::from(old.capability),
        }
    }
}

/// A local interface on which we are listening for, and dispatching, LLDPDUs
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Interface {
    pub port: String,
    pub iface: String,
    pub disabled: bool,
    pub system_info: SystemInfo,
}

impl From<Interface> for v1::interfaces::Interface {
    fn from(new: Interface) -> Self {
        v1::interfaces::Interface {
            port: new.port,
            iface: new.iface,
            disabled: new.disabled,
            system_info: new.system_info.into(),
        }
    }
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

impl From<v1::interfaces::InterfaceAdd> for InterfaceAdd {
    fn from(old: v1::interfaces::InterfaceAdd) -> Self {
        InterfaceAdd {
            chassis_id: old.chassis_id.map(ChassisId::from),
            port_id: old.port_id.map(PortId::from),
            system_name: old.system_name,
            system_description: old.system_description,
            port_description: old.port_description,
        }
    }
}
