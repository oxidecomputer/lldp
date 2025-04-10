// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::BTreeSet;
use std::convert::Into;
use std::fmt;
use std::net::IpAddr;

use anyhow::anyhow;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::macaddr::MacAddr;
use crate::packet::LldpTlv;

pub type Error = anyhow::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, JsonSchema, Serialize)]
pub struct Lldpdu {
    pub chassis_id: ChassisId,
    pub port_id: PortId,
    pub ttl: u16,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub system_capabilities:
        Option<(BTreeSet<SystemCapabilities>, BTreeSet<SystemCapabilities>)>,
    pub management_addresses: Vec<ManagementAddress>,
    pub organizationally_specific: Vec<OrganizationallySpecific>,
}

impl fmt::Display for Lldpdu {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Chassis ID: {}", self.chassis_id)?;
        writeln!(f, "Port ID: {}", self.port_id)?;
        writeln!(f, "Time To Live: {} seconds", self.ttl)?;
        if let Some(pd) = &self.port_description {
            writeln!(f, "Port description: {pd}")?;
        }
        if let Some(sn) = &self.system_name {
            writeln!(f, "System name: {sn}")?;
        }
        if let Some(sd) = &self.system_description {
            writeln!(f, "System description: {sd}")?;
        }
        // system_capabilities: Option<(BTreeSet<SystemCapabilities>, BTreeSet<SystemCapabilities>)>,
        for ma in &self.management_addresses {
            writeln!(f, "Management address: {ma}")?;
        }
        for os in &self.organizationally_specific {
            writeln!(f, "Organizationally Specific: {os}")?;
        }
        Ok(())
    }
}

impl TryFrom<&Lldpdu> for Vec<LldpTlv> {
    type Error = Error;

    fn try_from(lldpdu: &Lldpdu) -> Result<Self> {
        let mut lldp_data: Vec<LldpTlv> = Vec::new();
        lldp_data.push((&lldpdu.chassis_id).try_into()?);
        lldp_data.push((&lldpdu.port_id).try_into()?);
        lldp_data.push(ttl_to_tlv(lldpdu.ttl));
        if let Some(pd) = &lldpdu.port_description {
            lldp_data.push(string_to_tlv(TlvType::PortDescription, pd)?);
        }
        if let Some(sn) = &lldpdu.system_name {
            lldp_data.push(string_to_tlv(TlvType::SystemName, sn)?);
        }
        if let Some(sd) = &lldpdu.system_description {
            lldp_data.push(string_to_tlv(TlvType::SystemDescription, sd)?);
        }
        if let Some((avail, enabled)) = &lldpdu.system_capabilities {
            lldp_data.push(capabilities_to_tlv(avail, enabled)?);
        }
        for ma in &lldpdu.management_addresses {
            lldp_data.push(ma.try_into()?);
        }
        for os in &lldpdu.organizationally_specific {
            lldp_data.push(os.try_into()?)
        }
        lldp_data.push(LldpTlv::new(TlvType::EndOfLLDPDU as u8, &[0u8; 0])?);

        Ok(lldp_data)
    }
}

// TODO-completeness: We should pass back a more meaningful error code, so the
// consumer can keep proper counts of each failure reason.
impl TryFrom<&Vec<LldpTlv>> for Lldpdu {
    type Error = Error;

    fn try_from(data: &Vec<LldpTlv>) -> Result<Self> {
        let cnt = data.len();

        let chassis_id: ChassisId = if cnt >= 1 {
            (&data[0]).try_into()
        } else {
            Err(anyhow!("LLDP packet has no ChassisId"))
        }?;

        let port_id: PortId = if cnt >= 2 {
            (&data[1]).try_into()
        } else {
            Err(anyhow!("LLDP packet has no PortId"))
        }?;

        let ttl = if cnt >= 3 {
            ttl_from_tlv(&data[2])
        } else {
            Err(anyhow!("LLDP packet has no TTL"))
        }?;

        let mut port_description = None;
        let mut system_name = None;
        let mut system_description = None;
        let mut system_capabilities = None;
        let mut management_addresses = Vec::new();
        let mut organizationally_specific = Vec::new();
        let mut _tlvs_unrecognized = 0;

        for tlv in data.iter().skip(3) {
            let tlv_type = match tlv.lldp_tlv_type.try_into() {
                Ok(t) => t,
                Err(_) => {
                    _tlvs_unrecognized += 1;
                    continue;
                }
            };
            tlv_sanity_check(tlv, tlv_type)?;

            match tlv_type {
                TlvType::EndOfLLDPDU => break,
                TlvType::ChassisId => {
                    return Err(anyhow!(
                        "LLDP packet has multiple ChassisId TLVs`",
                    ))
                }
                TlvType::PortId => {
                    return Err(anyhow!(
                        "LLDP packet has multiple PortId TLVs`",
                    ))
                }
                TlvType::Ttl => {
                    return Err(anyhow!("LLDP packet has multiple TTL TLVs`",))
                }
                TlvType::PortDescription => {
                    port_description = Some(string_from_octets(
                        "PortDescription",
                        &tlv.lldp_tlv_octets,
                    )?)
                }
                TlvType::SystemName => {
                    system_name = Some(string_from_octets(
                        "SystemName",
                        &tlv.lldp_tlv_octets,
                    )?)
                }
                TlvType::SystemDescription => {
                    system_description = Some(string_from_octets(
                        "SystemDescription",
                        &tlv.lldp_tlv_octets,
                    )?)
                }
                TlvType::ManagementAddress => {
                    management_addresses.push(tlv.try_into()?)
                }
                TlvType::SystemCapabilities => {
                    system_capabilities = Some(capabilities_from_tlv(tlv)?)
                }
                TlvType::OrganizationallySpecific => {
                    // We don't currently recognized any of these
                    _tlvs_unrecognized += 1;
                    organizationally_specific.push(tlv.try_into()?)
                }
            }
        }
        Ok(Lldpdu {
            chassis_id,
            port_id,
            ttl,
            port_description,
            system_name,
            system_description,
            system_capabilities,
            management_addresses,
            organizationally_specific,
        })
    }
}

impl TryFrom<&[u8]> for Lldpdu {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let (hdr, _size) = crate::packet::LldpHdr::parse(data)?;
        Lldpdu::try_from(&hdr.lldp_data)
    }
}

fn tlv_sanity_check(tlv: &LldpTlv, expected_type: TlvType) -> Result<()> {
    let l = tlv.lldp_tlv_octets.len() as u16;

    if tlv.lldp_tlv_type != expected_type as u8 {
        Err(anyhow!("TLV does not have the expected type"))
    } else if tlv.lldp_tlv_size < l {
        Err(anyhow!("TLV payload is larger than expected"))
    } else if tlv.lldp_tlv_size > l {
        Err(anyhow!("TLV payload is smaller than expected"))
    } else {
        Ok(())
    }
}

fn hex2str(data: &[u8]) -> String {
    if data.is_empty() {
        "null".to_string()
    } else {
        data.iter()
            .map(|a| format!("{a:02x}"))
            .collect::<Vec<String>>()
            .join(":")
    }
}

// IANA Address Family Numbers for the address types we currently support as
// seen in:
// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
const IANA_IPV4: u8 = 1;
const IANA_IPV6: u8 = 2;
const IANA_802: u8 = 6;

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
pub enum NetworkAddress {
    //  IPv4 or IPv6
    IpAddr(IpAddr),
    // 802 (includes all 802 media plus Ethernet "canonical format")".
    // This suggests that we need to be prepared for any 802 address, not just
    // MAC addresses.
    IEEE802(Vec<u8>),
}

impl From<IpAddr> for NetworkAddress {
    fn from(addr: IpAddr) -> Self {
        NetworkAddress::IpAddr(addr)
    }
}

impl From<Vec<u8>> for NetworkAddress {
    fn from(addr: Vec<u8>) -> Self {
        NetworkAddress::IEEE802(addr)
    }
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetworkAddress::IpAddr(ip) => write!(f, "IpAddr({ip})"),
            NetworkAddress::IEEE802(addr) => {
                write!(f, "IEEE802({})", hex2str(addr))
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
pub enum ChassisId {
    ChassisComponent(String), // RFC 6993
    InterfaceAlias(String),   // RFC 2863
    PortComponent(String),    // RFC 6993
    MacAddress(MacAddr),
    NetworkAddress(NetworkAddress),
    InterfaceName(String), // RFC 2863
    LocallyAssigned(String),
}

impl fmt::Display for ChassisId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChassisId::ChassisComponent(s) => {
                write!(f, "Chassis Component - {s}")
            }
            ChassisId::InterfaceAlias(s) => write!(f, "Interface Alias- {s}"),
            ChassisId::PortComponent(s) => write!(f, "Port Component - {s}"),
            ChassisId::MacAddress(mac) => write!(f, "Mac Address - {mac}"),
            ChassisId::NetworkAddress(ip) => {
                write!(f, "Network Address - {ip}")
            }
            ChassisId::InterfaceName(s) => write!(f, "Interface Name - {s}"),
            ChassisId::LocallyAssigned(s) => {
                write!(f, "Locally assigned - {s}")
            }
        }
    }
}

// An address is represented as a string of octets, where the first two contain
// the IANA registered number for the address type, and the remaining octects
// contain address itself.
fn addr_to_octets(addr: &NetworkAddress) -> Vec<u8> {
    let mut v = vec![];
    match addr {
        NetworkAddress::IpAddr(ip) => match ip {
            IpAddr::V4(ip) => {
                v.push(IANA_IPV4);
                v.extend(ip.octets())
            }
            IpAddr::V6(ip) => {
                v.push(IANA_IPV6);
                v.extend(ip.octets())
            }
        },
        NetworkAddress::IEEE802(addr) => {
            v.push(IANA_802);
            v.extend(addr)
        }
    }
    v
}

fn addr_from_octets(data: &[u8]) -> Result<NetworkAddress> {
    let len = data.len();
    if len == 0 {
        return Err(anyhow!("address TLV has no payload"));
    }
    match data[0] {
        IANA_IPV4 => match len {
            5 => {
                let a: [u8; 4] = (&data[1..])
                    .try_into()
                    .expect("size validated by the match");
                Ok(NetworkAddress::IpAddr(IpAddr::from(a)))
            }
            _ => Err(anyhow!("invalid sized IPv4 address in TLV")),
        },
        IANA_IPV6 => match len {
            17 => {
                let a: [u8; 16] = (&data[1..])
                    .try_into()
                    .expect("size validated by the match");
                Ok(NetworkAddress::IpAddr(IpAddr::from(a)))
            }
            _ => Err(anyhow!("invalid sized IPv6 address in TLV")),
        },
        IANA_802 => Ok(NetworkAddress::IEEE802(data[1..].to_vec())),
        x => Err(anyhow!(format!(
            "unsupported address type {x} in TLV - len {len}"
        ))),
    }
}

impl TryFrom<&ChassisId> for LldpTlv {
    type Error = Error;

    fn try_from(id: &ChassisId) -> Result<Self> {
        let (tlv_subtype, tlv_octets) = match id {
            ChassisId::ChassisComponent(tlvdata) => (
                ChassisIdSubtype::ChassisComponent,
                tlvdata.as_bytes().to_vec(),
            ),
            ChassisId::InterfaceAlias(tlvdata) => (
                ChassisIdSubtype::InterfaceAlias,
                tlvdata.as_bytes().to_vec(),
            ),
            ChassisId::PortComponent(tlvdata) => {
                (ChassisIdSubtype::PortComponent, tlvdata.as_bytes().to_vec())
            }
            ChassisId::MacAddress(mac) => {
                (ChassisIdSubtype::MacAddress, mac.to_vec())
            }
            ChassisId::NetworkAddress(addr) => (
                ChassisIdSubtype::NetworkAddress,
                addr_to_octets(addr).to_vec(),
            ),
            ChassisId::InterfaceName(tlvdata) => {
                (ChassisIdSubtype::InterfaceName, tlvdata.as_bytes().to_vec())
            }
            ChassisId::LocallyAssigned(tlvdata) => (
                ChassisIdSubtype::LocallyAssigned,
                tlvdata.as_bytes().to_vec(),
            ),
        };
        let tlv_size = tlv_octets.len() as u16;
        if tlv_size < 1 {
            Err(anyhow!("0-length ChassisID"))
        } else if tlv_size > 255 {
            Err(anyhow!("ChassisID exceeds 255 octets"))
        } else {
            let mut lldp_tlv_octets = vec![tlv_subtype as u8];
            lldp_tlv_octets.extend(tlv_octets);
            Ok(LldpTlv {
                lldp_tlv_type: TlvType::ChassisId.into(),
                lldp_tlv_size: tlv_size + 1,
                lldp_tlv_octets,
            })
        }
    }
}

impl TryFrom<&LldpTlv> for ChassisId {
    type Error = Error;

    fn try_from(tlv: &LldpTlv) -> Result<Self> {
        tlv_sanity_check(tlv, TlvType::ChassisId)?;
        if tlv.lldp_tlv_size < 2 {
            return Err(anyhow!("ChassisId TLV has no payload"));
        }

        let subtype = ChassisIdSubtype::try_from(tlv.lldp_tlv_octets[0])?;
        let data = &tlv.lldp_tlv_octets[1..];
        match subtype {
            ChassisIdSubtype::Reserved => {
                Err(anyhow!("found ChassisId with Reserved subtype"))
            }
            ChassisIdSubtype::ChassisComponent => {
                Ok(ChassisId::ChassisComponent(string_from_octets(
                    "ChassisId",
                    data,
                )?))
            }
            ChassisIdSubtype::InterfaceAlias => Ok(ChassisId::InterfaceAlias(
                string_from_octets("ChassisId", data)?,
            )),
            ChassisIdSubtype::PortComponent => Ok(ChassisId::PortComponent(
                string_from_octets("ChassisId", data)?,
            )),
            ChassisIdSubtype::MacAddress => {
                Ok(ChassisId::MacAddress(MacAddr::from_slice(data)))
            }
            ChassisIdSubtype::NetworkAddress => {
                Ok(ChassisId::NetworkAddress(addr_from_octets(data)?))
            }
            ChassisIdSubtype::InterfaceName => Ok(ChassisId::InterfaceName(
                string_from_octets("ChassisId", data)?,
            )),
            ChassisIdSubtype::LocallyAssigned => {
                Ok(ChassisId::LocallyAssigned(string_from_octets(
                    "ChassisId",
                    data,
                )?))
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
pub enum PortId {
    InterfaceAlias(String), // RFC 2863
    PortComponent(String),  //  RFC 6933
    MacAddress(MacAddr),
    NetworkAddress(NetworkAddress),
    InterfaceName(String),  // RFC 2863
    AgentCircuitId(String), // RFC 3046
    LocallyAssigned(String),
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortId::InterfaceAlias(s) => write!(f, "Interface Alias- {s}"),
            PortId::PortComponent(s) => write!(f, "Port Component - {s}"),
            PortId::MacAddress(mac) => write!(f, "Mac Address - {mac}"),
            PortId::NetworkAddress(ip) => {
                write!(f, "Network Address - {ip}")
            }
            PortId::InterfaceName(s) => write!(f, "Interface Name - {s}"),
            PortId::AgentCircuitId(s) => write!(f, "Agent Circuit ID - {s}"),
            PortId::LocallyAssigned(s) => {
                write!(f, "Locally assigned - {s}")
            }
        }
    }
}
impl TryFrom<&PortId> for LldpTlv {
    type Error = Error;

    fn try_from(id: &PortId) -> Result<Self> {
        let (tlv_subtype, tlv_octets) = match id {
            PortId::InterfaceAlias(tlvdata) => {
                (PortIdSubtype::InterfaceAlias, tlvdata.as_bytes().to_vec())
            }
            PortId::PortComponent(tlvdata) => {
                (PortIdSubtype::PortComponent, tlvdata.as_bytes().to_vec())
            }
            PortId::MacAddress(mac) => {
                (PortIdSubtype::MacAddress, mac.to_vec())
            }
            PortId::NetworkAddress(addr) => {
                (PortIdSubtype::NetworkAddress, addr_to_octets(addr).to_vec())
            }
            PortId::InterfaceName(tlvdata) => {
                (PortIdSubtype::InterfaceName, tlvdata.as_bytes().to_vec())
            }
            PortId::AgentCircuitId(tlvdata) => {
                (PortIdSubtype::AgentCircuitId, tlvdata.as_bytes().to_vec())
            }
            PortId::LocallyAssigned(tlvdata) => {
                (PortIdSubtype::LocallyAssigned, tlvdata.as_bytes().to_vec())
            }
        };

        let tlv_size = tlv_octets.len() as u16;
        if tlv_size < 1 {
            Err(anyhow!("0-length PortID"))
        } else if tlv_size > 255 {
            Err(anyhow!("PortID exceeds 255 octets"))
        } else {
            let mut lldp_tlv_octets = vec![tlv_subtype as u8];
            lldp_tlv_octets.extend(tlv_octets);
            Ok(LldpTlv {
                lldp_tlv_type: TlvType::PortId.into(),
                lldp_tlv_size: tlv_size + 1,
                lldp_tlv_octets,
            })
        }
    }
}

impl TryFrom<&LldpTlv> for PortId {
    type Error = Error;

    fn try_from(tlv: &LldpTlv) -> Result<Self> {
        tlv_sanity_check(tlv, TlvType::PortId)?;
        if tlv.lldp_tlv_size < 2 {
            return Err(anyhow!("PortId TLV has no payload"));
        }

        let subtype = PortIdSubtype::try_from(tlv.lldp_tlv_octets[0])?;
        let data = &tlv.lldp_tlv_octets[1..];
        match subtype {
            PortIdSubtype::Reserved => {
                Err(anyhow!("found PortId with Reserved subtype"))
            }
            PortIdSubtype::InterfaceAlias => {
                Ok(PortId::InterfaceAlias(string_from_octets("PortId", data)?))
            }
            PortIdSubtype::PortComponent => {
                Ok(PortId::PortComponent(string_from_octets("PortId", data)?))
            }
            PortIdSubtype::MacAddress => {
                Ok(PortId::MacAddress(MacAddr::from_slice(data)))
            }
            PortIdSubtype::NetworkAddress => {
                Ok(PortId::NetworkAddress(addr_from_octets(data)?))
            }
            PortIdSubtype::InterfaceName => {
                Ok(PortId::InterfaceName(string_from_octets("PortId", data)?))
            }
            PortIdSubtype::AgentCircuitId => {
                Ok(PortId::AgentCircuitId(string_from_octets("PortId", data)?))
            }
            PortIdSubtype::LocallyAssigned => {
                Ok(PortId::LocallyAssigned(string_from_octets("PortId", data)?))
            }
        }
    }
}

pub fn ttl_to_tlv(ttl: u16) -> LldpTlv {
    LldpTlv {
        lldp_tlv_type: TlvType::Ttl.into(),
        lldp_tlv_size: 2,
        lldp_tlv_octets: vec![(ttl >> 8) as u8, (ttl & 0xff) as u8],
    }
}

pub fn ttl_from_tlv(tlv: &LldpTlv) -> Result<u16> {
    let d = &tlv.lldp_tlv_octets;

    if tlv.lldp_tlv_type != TlvType::Ttl as u8 {
        Err(anyhow!("Not a TTL TLV"))
    } else if tlv.lldp_tlv_size != 2 {
        Err(anyhow!("Payload is the wrong size for a TTL"))
    } else if tlv.lldp_tlv_size != d.len() as u16 {
        Err(anyhow!("Payload size doesn't match the TLV size"))
    } else {
        Ok((d[0] as u16) << 8 | d[1] as u16)
    }
}

fn capabilities_to_u16(all: &BTreeSet<SystemCapabilities>) -> u16 {
    let mut rval = 0;
    for c in all {
        rval |= 1u16 << (*c as u16 - 1);
    }
    rval
}

pub fn capabilities_to_tlv(
    avail: &BTreeSet<SystemCapabilities>,
    enabled: &BTreeSet<SystemCapabilities>,
) -> Result<LldpTlv> {
    if !avail.is_superset(enabled) {
        return Err(anyhow!(
            "cannot enable capabilities that aren't available",
        ));
    }
    let avail = capabilities_to_u16(avail);
    let enabled = capabilities_to_u16(enabled);
    let mut capabilities = avail.to_be_bytes().to_vec();
    capabilities.extend_from_slice(enabled.to_be_bytes().as_ref());
    Ok(LldpTlv {
        lldp_tlv_type: TlvType::SystemCapabilities.into(),
        lldp_tlv_size: 4,
        lldp_tlv_octets: capabilities,
    })
}

pub fn capabilities_from_tlv(
    tlv: &LldpTlv,
) -> Result<(BTreeSet<SystemCapabilities>, BTreeSet<SystemCapabilities>)> {
    let d = &tlv.lldp_tlv_octets;
    if d.len() != 4 {
        return Err(anyhow!("capabilities field is not 4 octets"));
    }
    let avail_bits = (d[0] as u16) << 8 | d[1] as u16;
    let enabled_bits = (d[2] as u16) << 8 | d[3] as u16;

    let mut avail = BTreeSet::new();
    let mut enabled = BTreeSet::new();
    for bit in 0u16..16u16 {
        if avail_bits & 1 << bit != 0 {
            avail.insert((bit + 1).try_into()?);
        }
        if enabled_bits & 1 << bit != 0 {
            enabled.insert((bit + 1).try_into()?);
        }
    }
    Ok((avail, enabled))
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, JsonSchema, Serialize)]
pub enum InterfaceNum {
    Unknown(u32),
    IfIndex(u32),
    PortNumber(u32),
}

impl fmt::Display for InterfaceNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InterfaceNum::Unknown(id) => write!(f, "Unknown ({id})"),
            InterfaceNum::IfIndex(id) => write!(f, "IfIndex ({id})"),
            InterfaceNum::PortNumber(id) => write!(f, "PortNumber ({id})"),
        }
    }
}

#[derive(Debug, Clone)]
#[repr(u8)]
enum InterfaceNumSubtype {
    Unknown = 1,
    IfIndex,
    PortNumber,
}

impl TryFrom<u8> for InterfaceNumSubtype {
    type Error = Error;

    fn try_from(t: u8) -> Result<Self> {
        match t {
            1 => Ok(InterfaceNumSubtype::Unknown),
            2 => Ok(InterfaceNumSubtype::IfIndex),
            3 => Ok(InterfaceNumSubtype::PortNumber),
            x => Err(anyhow!(format!("invalid Interface Number subtype: {x}"))),
        }
    }
}

impl From<InterfaceNumSubtype> for u8 {
    fn from(x: InterfaceNumSubtype) -> u8 {
        x as u8
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, JsonSchema, Serialize)]
pub struct ManagementAddress {
    pub addr: NetworkAddress,
    pub interface_num: InterfaceNum,
    pub oid: Option<Vec<u8>>,
}

impl fmt::Display for ManagementAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.oid {
            Some(oid) => {
                write!(
                    f,
                    "{} {} (OID: {})",
                    self.addr,
                    self.interface_num,
                    hex2str(oid)
                )
            }
            None => write!(f, "{} ({})", self.addr, self.interface_num),
        }
    }
}

impl TryFrom<&ManagementAddress> for LldpTlv {
    type Error = Error;

    fn try_from(from: &ManagementAddress) -> Result<Self> {
        let (oid, oid_len) = match &from.oid {
            Some(oid) => (Some(oid.clone()), oid.len()),
            None => (None, 0),
        };

        if oid_len > 128 {
            return Err(anyhow!("OID must be no more than 128 bytes long",));
        }
        let mut addr = addr_to_octets(&from.addr);

        let (iface_num_subtype, iface_num) = match from.interface_num {
            InterfaceNum::Unknown(num) => (InterfaceNumSubtype::Unknown, num),
            InterfaceNum::IfIndex(num) => (InterfaceNumSubtype::IfIndex, num),
            InterfaceNum::PortNumber(num) => {
                (InterfaceNumSubtype::PortNumber, num)
            }
        };
        let mut iface_num = iface_num.to_be_bytes().to_vec();

        let mut payload = Vec::new();
        payload.push(addr.len() as u8);
        payload.append(&mut addr);
        payload.push(iface_num_subtype.into());
        payload.append(&mut iface_num);
        payload.push(oid_len as u8);
        if let Some(mut oid) = oid {
            payload.append(&mut oid);
        }

        Ok(LldpTlv {
            lldp_tlv_type: TlvType::ManagementAddress.into(),
            lldp_tlv_size: payload.len() as u16,
            lldp_tlv_octets: payload,
        })
    }
}

impl TryFrom<&LldpTlv> for ManagementAddress {
    type Error = Error;

    fn try_from(tlv: &LldpTlv) -> Result<Self> {
        tlv_sanity_check(tlv, TlvType::ManagementAddress)?;
        let d = &tlv.lldp_tlv_octets;

        if d.is_empty() {
            return Err(anyhow!("Management address is empty"));
        }
        let addr_len = d[0] as usize;
        if d.len() < addr_len {
            return Err(anyhow!("Management TLV is short"));
        }
        let addr_start = 1;
        let iface_start = addr_start + addr_len;
        let iface_len = 5; // subtype + 4 bytes of data
        let oid_start = iface_start + iface_len;
        let oid_len = d[oid_start] as usize;
        if d.len() < oid_start + 1 {
            return Err(anyhow!("Management address TLV is too short"));
        }
        let addr = addr_from_octets(&d[addr_start..iface_start])?;
        let iface_subtype = InterfaceNumSubtype::try_from(d[iface_start])?;
        let mut num = 0u32;
        for byte in d[iface_start + 1..oid_start].iter() {
            num = num << 8 | (*byte as u32);
        }
        let interface_num = match iface_subtype {
            InterfaceNumSubtype::Unknown => InterfaceNum::Unknown(num),
            InterfaceNumSubtype::IfIndex => InterfaceNum::IfIndex(num),
            InterfaceNumSubtype::PortNumber => InterfaceNum::PortNumber(num),
        };

        let oid = match oid_len {
            0 => None,
            _ => Some(d[oid_start..].to_vec()),
        };

        Ok(ManagementAddress {
            addr,
            interface_num,
            oid,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, JsonSchema, Serialize)]
pub struct OrganizationallySpecific {
    pub oui: [u8; 3],
    pub subtype: u8,
    pub info: Vec<u8>,
}

impl fmt::Display for OrganizationallySpecific {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let data = self
            .info
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<String>>()
            .join(" ");
        write!(
            f,
            "oiu: {:02x}{:02x}{:02x} subtype: {:x}  data: {}",
            self.oui[0], self.oui[1], self.oui[2], self.subtype, data
        )
    }
}

impl TryFrom<&OrganizationallySpecific> for LldpTlv {
    type Error = Error;

    fn try_from(from: &OrganizationallySpecific) -> Result<Self> {
        let mut payload = from.oui.to_vec();
        payload.push(from.subtype);
        payload.extend_from_slice(&from.info);

        Ok(LldpTlv {
            lldp_tlv_type: TlvType::OrganizationallySpecific.into(),
            lldp_tlv_size: payload.len() as u16,
            lldp_tlv_octets: payload,
        })
    }
}

impl TryFrom<&LldpTlv> for OrganizationallySpecific {
    type Error = Error;

    fn try_from(tlv: &LldpTlv) -> Result<Self> {
        tlv_sanity_check(tlv, TlvType::OrganizationallySpecific)?;
        let d = &tlv.lldp_tlv_octets;
        if d.len() < 4 {
            Err(anyhow!("OrganizationallySpecific TLV is too short"))
        } else {
            Ok(OrganizationallySpecific {
                oui: [d[0], d[1], d[2]],
                subtype: d[3],
                info: d[4..].to_vec(),
            })
        }
    }
}

pub fn string_to_tlv(tlv_type: TlvType, data: &String) -> Result<LldpTlv> {
    let lldp_tlv_type = match tlv_type {
        TlvType::EndOfLLDPDU
        | TlvType::ChassisId
        | TlvType::PortId
        | TlvType::Ttl
        | TlvType::SystemCapabilities
        | TlvType::ManagementAddress => {
            Err(anyhow!("TLV type doesn't contain string data"))
        }
        x => Ok(x as u8),
    }?;

    let lldp_tlv_octets = data.as_bytes().to_vec();
    let lldp_tlv_size = lldp_tlv_octets.len() as u16;
    if lldp_tlv_size < 1 {
        Err(anyhow!("0-length string"))
    } else if lldp_tlv_size > 255 {
        Err(anyhow!("string exceeds 255 octets"))
    } else {
        Ok(LldpTlv {
            lldp_tlv_type,
            lldp_tlv_size,
            lldp_tlv_octets,
        })
    }
}

#[allow(dead_code)]
pub fn addr_to_tlv(
    tlv_type: TlvType,
    addr: &NetworkAddress,
) -> Result<LldpTlv> {
    let lldp_tlv_type = tlv_type.into();
    let lldp_tlv_octets = addr_to_octets(addr);
    let lldp_tlv_size = lldp_tlv_octets.len() as u16;
    Ok(LldpTlv {
        lldp_tlv_type,
        lldp_tlv_size,
        lldp_tlv_octets,
    })
}

fn string_from_octets(label: &str, data: &[u8]) -> Result<String> {
    let s = String::from_utf8(data.to_vec())
        .map_err(|_| anyhow!(format!("invalid bytes in {label}")))?;
    if s.is_empty() {
        Err(anyhow!(format!("found empty payload for {label}")))
    } else if s.len() > 255 {
        Err(anyhow!(format!(
            "payload for {label} exceeded 255 characters"
        )))
    } else {
        Ok(s)
    }
}

/// The propagation scope, and associated MAC addresses, is defined by
/// section 7.1.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, JsonSchema, Serialize)]
pub enum Scope {
    Bridge,
    NonTPMRBridge,
    CustomerBridge,
}

impl From<Scope> for MacAddr {
    fn from(s: Scope) -> MacAddr {
        match s {
            Scope::Bridge => MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x0E),
            Scope::NonTPMRBridge => {
                MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03)
            }
            Scope::CustomerBridge => {
                MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
            }
        }
    }
}

/// TLV Type values as defined in table 8-1
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Deserialize, JsonSchema, Serialize,
)]
#[repr(u8)]
pub enum TlvType {
    EndOfLLDPDU = 0,
    ChassisId,
    PortId,
    Ttl,
    PortDescription,
    SystemName,
    SystemDescription,
    SystemCapabilities,
    ManagementAddress,
    OrganizationallySpecific = 127,
}

impl TryFrom<u8> for TlvType {
    type Error = Error;

    fn try_from(t: u8) -> Result<Self> {
        match t {
            0 => Ok(TlvType::EndOfLLDPDU),
            1 => Ok(TlvType::ChassisId),
            2 => Ok(TlvType::PortId),
            3 => Ok(TlvType::Ttl),
            4 => Ok(TlvType::PortDescription),
            5 => Ok(TlvType::SystemName),
            6 => Ok(TlvType::SystemDescription),
            7 => Ok(TlvType::SystemCapabilities),
            8 => Ok(TlvType::ManagementAddress),
            127 => Ok(TlvType::OrganizationallySpecific),
            _ => Err(anyhow!("invalid ChassisId subtype")),
        }
    }
}

impl From<TlvType> for u8 {
    fn from(x: TlvType) -> u8 {
        x as u8
    }
}

/// Chassis ID Subtype values as defined in table 8-2.
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Deserialize, JsonSchema, Serialize,
)]
#[repr(u8)]
pub enum ChassisIdSubtype {
    Reserved = 0,
    ChassisComponent,
    InterfaceAlias,
    PortComponent,
    MacAddress,
    NetworkAddress,
    InterfaceName,
    LocallyAssigned,
}

impl TryFrom<u8> for ChassisIdSubtype {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self> {
        match id {
            0 => Ok(ChassisIdSubtype::Reserved),
            1 => Ok(ChassisIdSubtype::ChassisComponent),
            2 => Ok(ChassisIdSubtype::InterfaceAlias),
            3 => Ok(ChassisIdSubtype::PortComponent),
            4 => Ok(ChassisIdSubtype::MacAddress),
            5 => Ok(ChassisIdSubtype::NetworkAddress),
            6 => Ok(ChassisIdSubtype::InterfaceName),
            7 => Ok(ChassisIdSubtype::LocallyAssigned),
            _ => Err(anyhow!("invalid ChassisId subtype")),
        }
    }
}

#[test]
fn verify_chassis_subtype() -> Result<()> {
    assert_eq!(
        ChassisIdSubtype::try_from(1)?,
        ChassisIdSubtype::ChassisComponent
    );
    assert_eq!(
        ChassisIdSubtype::try_from(2)?,
        ChassisIdSubtype::InterfaceAlias
    );
    assert_eq!(
        ChassisIdSubtype::try_from(3)?,
        ChassisIdSubtype::PortComponent
    );
    assert_eq!(ChassisIdSubtype::try_from(4)?, ChassisIdSubtype::MacAddress);
    assert_eq!(
        ChassisIdSubtype::try_from(5)?,
        ChassisIdSubtype::NetworkAddress
    );
    assert_eq!(
        ChassisIdSubtype::try_from(6)?,
        ChassisIdSubtype::InterfaceName
    );
    assert_eq!(
        ChassisIdSubtype::try_from(7)?,
        ChassisIdSubtype::LocallyAssigned
    );
    Ok(())
}

impl From<ChassisIdSubtype> for u8 {
    fn from(x: ChassisIdSubtype) -> u8 {
        x as u8
    }
}

/// Port ID Subtype values as defined by table 8-3.
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Deserialize, JsonSchema, Serialize,
)]
#[repr(u8)]
pub enum PortIdSubtype {
    Reserved = 0,
    InterfaceAlias,
    PortComponent,
    MacAddress,
    NetworkAddress,
    InterfaceName,
    AgentCircuitId,
    LocallyAssigned,
}

impl TryFrom<u8> for PortIdSubtype {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self> {
        match id {
            0 => Ok(PortIdSubtype::Reserved),
            1 => Ok(PortIdSubtype::InterfaceAlias),
            2 => Ok(PortIdSubtype::PortComponent),
            3 => Ok(PortIdSubtype::MacAddress),
            4 => Ok(PortIdSubtype::NetworkAddress),
            5 => Ok(PortIdSubtype::InterfaceName),
            6 => Ok(PortIdSubtype::AgentCircuitId),
            7 => Ok(PortIdSubtype::LocallyAssigned),
            _ => Err(anyhow!("invalid PortId subtype")),
        }
    }
}

#[test]
fn verify_port_subtype() -> Result<()> {
    assert_eq!(PortIdSubtype::try_from(0)?, PortIdSubtype::Reserved);
    assert_eq!(PortIdSubtype::try_from(1)?, PortIdSubtype::InterfaceAlias);
    assert_eq!(PortIdSubtype::try_from(2)?, PortIdSubtype::PortComponent);
    assert_eq!(PortIdSubtype::try_from(3)?, PortIdSubtype::MacAddress);
    assert_eq!(PortIdSubtype::try_from(4)?, PortIdSubtype::NetworkAddress);
    assert_eq!(PortIdSubtype::try_from(5)?, PortIdSubtype::InterfaceName);
    assert_eq!(PortIdSubtype::try_from(6)?, PortIdSubtype::AgentCircuitId);
    assert_eq!(PortIdSubtype::try_from(7)?, PortIdSubtype::LocallyAssigned);
    Ok(())
}

impl From<PortIdSubtype> for u8 {
    fn from(x: PortIdSubtype) -> u8 {
        x as u8
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
#[repr(u8)]
pub enum SystemCapabilities {
    Other = 1,
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

impl TryFrom<u16> for SystemCapabilities {
    type Error = Error;

    fn try_from(c: u16) -> Result<Self> {
        match c {
            1 => Ok(SystemCapabilities::Other),
            2 => Ok(SystemCapabilities::Repeater),
            3 => Ok(SystemCapabilities::MacBridgeComponent),
            4 => Ok(SystemCapabilities::AccessPoint),
            5 => Ok(SystemCapabilities::Router),
            6 => Ok(SystemCapabilities::Telephone),
            7 => Ok(SystemCapabilities::Docsis),
            8 => Ok(SystemCapabilities::StationOnly),
            9 => Ok(SystemCapabilities::CVlanComponent),
            10 => Ok(SystemCapabilities::SVlanComponent),
            11 => Ok(SystemCapabilities::MacRelayComponent),
            x => Err(anyhow!(format!("invalid capability: {x}"))),
        }
    }
}

impl From<SystemCapabilities> for u16 {
    fn from(x: SystemCapabilities) -> u16 {
        // The RFD defines the bit indices starting at 1 rather than 0, so
        // we need to subtract one from the index when computing the bitmask.
        1u16 << (x as u16 - 1)
    }
}
