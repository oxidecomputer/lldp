// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;

use protocol::macaddr::MacAddr;
use protocol::types::InterfaceNum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

#[derive(
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    JsonSchema,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAddress {
    //  IPv4 or IPv6
    IpAddr(IpAddr),
    // 802 (includes all 802 media plus Ethernet "canonical format")".
    // This suggests that we need to be prepared for any 802 address, not just
    // MAC addresses.
    Ieee802(Vec<u8>),
}

impl From<protocol::types::NetworkAddress> for NetworkAddress {
    fn from(old: protocol::types::NetworkAddress) -> Self {
        match old {
            protocol::types::NetworkAddress::IpAddr(ip) => {
                NetworkAddress::IpAddr(ip)
            }
            protocol::types::NetworkAddress::IEEE802(addr) => {
                NetworkAddress::Ieee802(addr)
            }
        }
    }
}

impl From<NetworkAddress> for protocol::types::NetworkAddress {
    fn from(new: NetworkAddress) -> Self {
        match new {
            NetworkAddress::IpAddr(ip) => {
                protocol::types::NetworkAddress::IpAddr(ip)
            }
            NetworkAddress::Ieee802(addr) => {
                protocol::types::NetworkAddress::IEEE802(addr)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, JsonSchema, Serialize)]
pub struct ManagementAddress {
    pub addr: NetworkAddress,
    pub interface_num: InterfaceNum,
    pub oid: Option<Vec<u8>>,
}

impl From<protocol::types::ManagementAddress> for ManagementAddress {
    fn from(old: protocol::types::ManagementAddress) -> Self {
        ManagementAddress {
            addr: NetworkAddress::from(old.addr),
            interface_num: old.interface_num,
            oid: old.oid,
        }
    }
}

impl From<ManagementAddress> for protocol::types::ManagementAddress {
    fn from(new: ManagementAddress) -> Self {
        protocol::types::ManagementAddress {
            addr: protocol::types::NetworkAddress::from(new.addr),
            interface_num: new.interface_num,
            oid: new.oid,
        }
    }
}

#[derive(
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    JsonSchema,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ChassisId {
    ChassisComponent(String), // RFC 6993
    InterfaceAlias(String),   // RFC 2863
    PortComponent(String),    // RFC 6993
    MacAddress(MacAddr),
    NetworkAddress(NetworkAddress),
    InterfaceName(String), // RFC 2863
    LocallyAssigned(String),
}

impl From<protocol::types::ChassisId> for ChassisId {
    fn from(old: protocol::types::ChassisId) -> Self {
        match old {
            protocol::types::ChassisId::ChassisComponent(s) => {
                ChassisId::ChassisComponent(s)
            }
            protocol::types::ChassisId::InterfaceAlias(s) => {
                ChassisId::InterfaceAlias(s)
            }
            protocol::types::ChassisId::PortComponent(s) => {
                ChassisId::PortComponent(s)
            }
            protocol::types::ChassisId::MacAddress(mac) => {
                ChassisId::MacAddress(mac)
            }
            protocol::types::ChassisId::NetworkAddress(addr) => {
                ChassisId::NetworkAddress(NetworkAddress::from(addr))
            }
            protocol::types::ChassisId::InterfaceName(s) => {
                ChassisId::InterfaceName(s)
            }
            protocol::types::ChassisId::LocallyAssigned(s) => {
                ChassisId::LocallyAssigned(s)
            }
        }
    }
}

impl From<ChassisId> for protocol::types::ChassisId {
    fn from(new: ChassisId) -> Self {
        match new {
            ChassisId::ChassisComponent(s) => {
                protocol::types::ChassisId::ChassisComponent(s)
            }
            ChassisId::InterfaceAlias(s) => {
                protocol::types::ChassisId::InterfaceAlias(s)
            }
            ChassisId::PortComponent(s) => {
                protocol::types::ChassisId::PortComponent(s)
            }
            ChassisId::MacAddress(mac) => {
                protocol::types::ChassisId::MacAddress(mac)
            }
            ChassisId::NetworkAddress(addr) => {
                protocol::types::ChassisId::NetworkAddress(addr.into())
            }
            ChassisId::InterfaceName(s) => {
                protocol::types::ChassisId::InterfaceName(s)
            }
            ChassisId::LocallyAssigned(s) => {
                protocol::types::ChassisId::LocallyAssigned(s)
            }
        }
    }
}

#[derive(
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    JsonSchema,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PortId {
    InterfaceAlias(String), // RFC 2863
    PortComponent(String),  //  RFC 6933
    MacAddress(MacAddr),
    NetworkAddress(NetworkAddress),
    InterfaceName(String),  // RFC 2863
    AgentCircuitId(String), // RFC 3046
    LocallyAssigned(String),
}

impl From<protocol::types::PortId> for PortId {
    fn from(old: protocol::types::PortId) -> Self {
        match old {
            protocol::types::PortId::InterfaceAlias(s) => {
                PortId::InterfaceAlias(s)
            }
            protocol::types::PortId::PortComponent(s) => {
                PortId::PortComponent(s)
            }
            protocol::types::PortId::MacAddress(mac) => PortId::MacAddress(mac),
            protocol::types::PortId::NetworkAddress(addr) => {
                PortId::NetworkAddress(NetworkAddress::from(addr))
            }
            protocol::types::PortId::InterfaceName(s) => {
                PortId::InterfaceName(s)
            }
            protocol::types::PortId::AgentCircuitId(s) => {
                PortId::AgentCircuitId(s)
            }
            protocol::types::PortId::LocallyAssigned(s) => {
                PortId::LocallyAssigned(s)
            }
        }
    }
}

impl From<PortId> for protocol::types::PortId {
    fn from(new: PortId) -> Self {
        match new {
            PortId::InterfaceAlias(s) => {
                protocol::types::PortId::InterfaceAlias(s)
            }
            PortId::PortComponent(s) => {
                protocol::types::PortId::PortComponent(s)
            }
            PortId::MacAddress(mac) => protocol::types::PortId::MacAddress(mac),
            PortId::NetworkAddress(addr) => {
                protocol::types::PortId::NetworkAddress(addr.into())
            }
            PortId::InterfaceName(s) => {
                protocol::types::PortId::InterfaceName(s)
            }
            PortId::AgentCircuitId(s) => {
                protocol::types::PortId::AgentCircuitId(s)
            }
            PortId::LocallyAssigned(s) => {
                protocol::types::PortId::LocallyAssigned(s)
            }
        }
    }
}

/// System Capabilities are defined by table 8-4.  In an LLDPDU a
/// system's available and enabled capabilities are represented by bitmasks,
/// with the value below acting as the index into that bitmask.
#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Deserialize,
    JsonSchema,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SystemCapabilities {
    Other,
    Repeater,
    MacBridgeComponent,
    AccessPoint,
    Router,
    Telephone,
    Docsis,
    StationOnly,
    CVlanComponent,
    SVlanComponent,
    MacRelayComponent,
}

impl From<protocol::types::SystemCapabilities> for SystemCapabilities {
    fn from(old: protocol::types::SystemCapabilities) -> Self {
        match old {
            protocol::types::SystemCapabilities::Other => {
                SystemCapabilities::Other
            }
            protocol::types::SystemCapabilities::Repeater => {
                SystemCapabilities::Repeater
            }
            protocol::types::SystemCapabilities::MacBridgeComponent => {
                SystemCapabilities::MacBridgeComponent
            }
            protocol::types::SystemCapabilities::AccessPoint => {
                SystemCapabilities::AccessPoint
            }
            protocol::types::SystemCapabilities::Router => {
                SystemCapabilities::Router
            }
            protocol::types::SystemCapabilities::Telephone => {
                SystemCapabilities::Telephone
            }
            protocol::types::SystemCapabilities::Docsis => {
                SystemCapabilities::Docsis
            }
            protocol::types::SystemCapabilities::StationOnly => {
                SystemCapabilities::StationOnly
            }
            protocol::types::SystemCapabilities::CVlanComponent => {
                SystemCapabilities::CVlanComponent
            }
            protocol::types::SystemCapabilities::SVlanComponent => {
                SystemCapabilities::SVlanComponent
            }
            protocol::types::SystemCapabilities::MacRelayComponent => {
                SystemCapabilities::MacRelayComponent
            }
        }
    }
}

impl From<SystemCapabilities> for protocol::types::SystemCapabilities {
    fn from(new: SystemCapabilities) -> Self {
        match new {
            SystemCapabilities::Other => {
                protocol::types::SystemCapabilities::Other
            }
            SystemCapabilities::Repeater => {
                protocol::types::SystemCapabilities::Repeater
            }
            SystemCapabilities::MacBridgeComponent => {
                protocol::types::SystemCapabilities::MacBridgeComponent
            }
            SystemCapabilities::AccessPoint => {
                protocol::types::SystemCapabilities::AccessPoint
            }
            SystemCapabilities::Router => {
                protocol::types::SystemCapabilities::Router
            }
            SystemCapabilities::Telephone => {
                protocol::types::SystemCapabilities::Telephone
            }
            SystemCapabilities::Docsis => {
                protocol::types::SystemCapabilities::Docsis
            }
            SystemCapabilities::StationOnly => {
                protocol::types::SystemCapabilities::StationOnly
            }
            SystemCapabilities::CVlanComponent => {
                protocol::types::SystemCapabilities::CVlanComponent
            }
            SystemCapabilities::SVlanComponent => {
                protocol::types::SystemCapabilities::SVlanComponent
            }
            SystemCapabilities::MacRelayComponent => {
                protocol::types::SystemCapabilities::MacRelayComponent
            }
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SystemCapabilityPathParams {
    pub capability: SystemCapabilities,
}

impl From<v1::system_info::SystemCapabilityPathParams>
    for SystemCapabilityPathParams
{
    fn from(old: v1::system_info::SystemCapabilityPathParams) -> Self {
        SystemCapabilityPathParams {
            capability: SystemCapabilities::from(old.capability),
        }
    }
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

impl From<SystemInfo> for v1::system_info::SystemInfo {
    fn from(new: SystemInfo) -> Self {
        v1::system_info::SystemInfo {
            chassis_id: new.chassis_id.into(),
            port_id: new.port_id.into(),
            ttl: new.ttl,
            port_description: new.port_description,
            system_name: new.system_name,
            system_description: new.system_description,
            capabilities_available: new
                .capabilities_available
                .into_iter()
                .map(protocol::types::SystemCapabilities::from)
                .collect(),
            capabilities_enabled: new
                .capabilities_enabled
                .into_iter()
                .map(protocol::types::SystemCapabilities::from)
                .collect(),
            management_addresses: new
                .management_addresses
                .into_iter()
                .map(protocol::types::ManagementAddress::from)
                .collect(),
            organizationally_specific: new.organizationally_specific,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use protocol::macaddr::MacAddr;
    use protocol::types::{InterfaceNum, NetworkAddress};

    use super::{ChassisId, ManagementAddress, PortId, SystemCapabilities};

    #[test]
    fn management_address_conversions_preserve_variant() {
        let all = [
            protocol::types::ManagementAddress {
                addr: NetworkAddress::IpAddr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                interface_num: InterfaceNum::IfIndex(1),
                oid: None,
            },
            protocol::types::ManagementAddress {
                addr: NetworkAddress::IEEE802(vec![1, 2, 3, 4, 5, 6]),
                interface_num: InterfaceNum::PortNumber(2),
                oid: Some(vec![7, 8]),
            },
        ];
        for old in all {
            let new = ManagementAddress::from(old.clone());
            assert_eq!(protocol::types::ManagementAddress::from(new), old);
        }
    }

    #[test]
    fn network_address_wire_keys() {
        let ip = super::NetworkAddress::IpAddr(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let ieee = super::NetworkAddress::Ieee802(vec![1, 2]);
        assert_eq!(
            serde_json::to_value(&ip).expect("serialized NetworkAddress"),
            serde_json::json!({ "ip_addr": "127.0.0.1" }),
        );
        assert_eq!(
            serde_json::to_value(&ieee).expect("serialized NetworkAddress"),
            serde_json::json!({ "ieee802": [1, 2] }),
        );
    }

    #[test]
    fn system_capabilities_conversions_preserve_variant() {
        for raw in 1u16..=11 {
            let old = protocol::types::SystemCapabilities::try_from(raw)
                .expect("capability index is in range");
            let new = SystemCapabilities::from(old);
            assert_eq!(format!("{new:?}"), format!("{old:?}"));
            assert_eq!(protocol::types::SystemCapabilities::from(new), old);
        }
    }

    fn wire_key<T: serde::Serialize>(value: &T) -> String {
        let json = serde_json::to_value(value).expect("serialized value");
        let object = json.as_object().expect("externally tagged enum");
        assert_eq!(object.len(), 1, "exactly one tag key in {json}");
        object.keys().next().expect("one key").clone()
    }

    #[test]
    fn chassis_id_conversions_preserve_variant() {
        let all = [
            (
                protocol::types::ChassisId::ChassisComponent("a".to_string()),
                "chassis_component",
            ),
            (
                protocol::types::ChassisId::InterfaceAlias("b".to_string()),
                "interface_alias",
            ),
            (
                protocol::types::ChassisId::PortComponent("c".to_string()),
                "port_component",
            ),
            (
                protocol::types::ChassisId::MacAddress(MacAddr::new(
                    1, 2, 3, 4, 5, 6,
                )),
                "mac_address",
            ),
            (
                protocol::types::ChassisId::NetworkAddress(
                    NetworkAddress::IEEE802(vec![1, 2, 3]),
                ),
                "network_address",
            ),
            (
                protocol::types::ChassisId::InterfaceName("d".to_string()),
                "interface_name",
            ),
            (
                protocol::types::ChassisId::LocallyAssigned("e".to_string()),
                "locally_assigned",
            ),
        ];
        for (old, expected_key) in all {
            let new = ChassisId::from(old.clone());
            assert_eq!(wire_key(&new), expected_key);
            assert_eq!(protocol::types::ChassisId::from(new), old);
        }
    }

    #[test]
    fn port_id_conversions_preserve_variant() {
        let all = [
            (
                protocol::types::PortId::InterfaceAlias("a".to_string()),
                "interface_alias",
            ),
            (
                protocol::types::PortId::PortComponent("b".to_string()),
                "port_component",
            ),
            (
                protocol::types::PortId::MacAddress(MacAddr::new(
                    1, 2, 3, 4, 5, 6,
                )),
                "mac_address",
            ),
            (
                protocol::types::PortId::NetworkAddress(
                    NetworkAddress::IpAddr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ),
                "network_address",
            ),
            (
                protocol::types::PortId::InterfaceName("c".to_string()),
                "interface_name",
            ),
            (
                protocol::types::PortId::AgentCircuitId("d".to_string()),
                "agent_circuit_id",
            ),
            (
                protocol::types::PortId::LocallyAssigned("e".to_string()),
                "locally_assigned",
            ),
        ];
        for (old, expected_key) in all {
            let new = PortId::from(old.clone());
            assert_eq!(wire_key(&new), expected_key);
            assert_eq!(protocol::types::PortId::from(new), old);
        }
    }
}
