use std::convert::TryFrom;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use rand::prelude::*;

// Given an IPv6 multicast address, generate the associated synthetic mac
// address
pub fn multicast_mac_addr(ip: Ipv6Addr) -> MacAddr {
    let o = ip.octets();
    MacAddr::new(0x33, 0x33, o[12], o[13], o[14], o[15])
}

/// Generate an IPv6 adddress within the provided `cidr`, using the EUI-64
/// transfrom of `mac`.
pub fn generate_ipv6_addr(cidr: Ipv6Cidr, mac: MacAddr) -> Ipv6Addr {
    let prefix: u128 = cidr.prefix.into();
    let mac = u128::from(u64::from_be_bytes(mac.to_eui64()));
    let mask = ((1u128 << cidr.prefix_len) - 1) << (128 - cidr.prefix_len);
    let ipv6 = (prefix & mask) | (mac & !mask);
    ipv6.into()
}

/// Generate a link-local IPv6 address using the EUI-64 transform of `mac`.
pub fn generate_ipv6_link_local(mac: MacAddr) -> Ipv6Addr {
    const LINK_LOCAL_PREFIX: Ipv6Cidr = Ipv6Cidr {
        prefix: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        prefix_len: 64,
    };

    generate_ipv6_addr(LINK_LOCAL_PREFIX, mac)
}

/// An IP subnet with a network prefix and prefix length.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize)]
#[serde(untagged, rename_all = "snake_case")]
pub enum Cidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

// NOTE: We don't derive JsonSchema. That's intended so that we can use an
// untagged enum for `Cidr`, and use this method to annotate schemars output
// for client-generators (e.g., progenitor) to use in generating a better
// client.
impl JsonSchema for Cidr {
    fn schema_name() -> String {
        "Cidr".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            subschemas: Some(Box::new(schemars::schema::SubschemaValidation {
                one_of: Some(vec![
                    label_schema("v4", gen.subschema_for::<Ipv4Cidr>()),
                    label_schema("v6", gen.subschema_for::<Ipv6Cidr>()),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

// Insert another level of schema indirection in order to provide an
// additional title for a subschema. This allows generators to infer a better
// variant name for an "untagged" enum.
fn label_schema(label: &str, schema: schemars::schema::Schema) -> schemars::schema::Schema {
    schemars::schema::SchemaObject {
        metadata: Some(
            schemars::schema::Metadata {
                title: Some(label.to_string()),
                ..Default::default()
            }
            .into(),
        ),
        subschemas: Some(
            schemars::schema::SubschemaValidation {
                all_of: Some(vec![schema]),
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    }
    .into()
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Cidr::V4(c) => write!(f, "{c}"),
            Cidr::V6(c) => write!(f, "{c}"),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum CidrError {
    /// Doesn't parse as an IPv4 CIDR
    #[error("Invalid IPv4 CIDR: {}", .0)]
    InvalidIpv4Cidr(String),
    /// Doesn't parse as an IPv6 CIDR
    #[error("Invalid IPv6 CIDR: {}", .0)]
    InvalidIpv6Cidr(String),
    /// Doesn't parse as either an IPv4 or IPv6 CIDR
    #[error("Invalid CIDR: {}", .0)]
    InvalidCidr(String),
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, CidrError> {
        if let Ok(cidr) = s.parse() {
            Ok(Cidr::V4(cidr))
        } else if let Ok(cidr) = s.parse() {
            Ok(Cidr::V6(cidr))
        } else {
            Err(CidrError::InvalidCidr(s.to_string()))
        }
    }
}

/// An IPv4 subnet with prefix and prefix length.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Cidr {
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
}

// NOTE
//
// We implement the serde and JsonSchema traits manually. This emitted schema is
// never actually used to generate the client, because we instead ask
// `progenitor` to use the "real" `common::network::Ipv4Cidr` in its place. We
// do however include _some_ schema for this type so that it shows up in the
// document. Rather than provide a regular expression for the format of an IPv4
// or v6 CIDR block, which is complicated, we just provide a human-friendly
// format name of "ipv4cidr" or "ipv6cidr".
impl<'de> serde::Deserialize<'de> for Ipv4Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .as_str()
            .parse()
            .map_err(|e: <Self as FromStr>::Err| <D::Error as serde::de::Error>::custom(e))
    }
}

impl Serialize for Ipv4Cidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{self}"))
    }
}

impl JsonSchema for Ipv4Cidr {
    fn schema_name() -> String {
        String::from("Ipv4Cidr")
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            metadata: Some(Box::new(schemars::schema::Metadata {
                title: Some("An IPv4 subnet".to_string()),
                description: Some("An IPv4 subnet, including prefix and subnet mask".to_string()),
                examples: vec!["192.168.1.0/24".into()],
                ..Default::default()
            })),
            format: Some(String::from("ipv4cidr")),
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            ..Default::default()
        }
        .into()
    }
}

impl Ipv4Cidr {
    /// Return `true` if the IP address is within the network.
    pub fn contains(&self, ipv4: Ipv4Addr) -> bool {
        let prefix: u32 = self.prefix.into();
        let mask = ((1u32 << self.prefix_len) - 1) << (32 - self.prefix_len);
        let addr: u32 = ipv4.into();

        (addr & mask) == prefix
    }
}

impl Ord for Ipv4Cidr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.prefix.cmp(&other.prefix) {
            std::cmp::Ordering::Equal => self.prefix_len.cmp(&other.prefix_len),
            o => o,
        }
    }
}

impl PartialOrd for Ipv4Cidr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod ipv4_tests {
    use super::Ipv4Cidr;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cidrv4_contains() {
        let cidr: Ipv4Cidr = "172.16.10.0/24".parse().unwrap();
        let a: Ipv4Addr = "172.16.10.1".parse().unwrap();
        let b: Ipv4Addr = "172.16.10.0".parse().unwrap();
        let c: Ipv4Addr = "172.16.10.192".parse().unwrap();
        let d: Ipv4Addr = "172.16.11.1".parse().unwrap();
        let e: Ipv4Addr = "172.16.0.0".parse().unwrap();
        let f: Ipv4Addr = "192.168.1.1".parse().unwrap();

        assert!(cidr.contains(a));
        assert!(cidr.contains(b));
        assert!(cidr.contains(c));
        assert!(!cidr.contains(d));
        assert!(!cidr.contains(e));
        assert!(!cidr.contains(f));
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.prefix, self.prefix_len)
    }
}

impl From<u64> for Ipv4Cidr {
    fn from(x: u64) -> Self {
        let prefix: u32 = (x >> 32) as u32;
        let prefix_len: u8 = (x & 0xff) as u8;
        Ipv4Cidr {
            prefix: prefix.into(),
            prefix_len,
        }
    }
}

impl From<Ipv4Cidr> for u64 {
    fn from(x: Ipv4Cidr) -> Self {
        let prefix: u32 = x.prefix.into();
        ((prefix as u64) << 32) | (x.prefix_len as u64)
    }
}

impl From<&Ipv4Cidr> for u64 {
    fn from(x: &Ipv4Cidr) -> Self {
        (*x).into()
    }
}

impl FromStr for Ipv4Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, CidrError> {
        let Some((maybe_prefix, maybe_prefix_len)) = s.split_once('/') else {
            return Err(CidrError::InvalidIpv4Cidr(s.to_string()));
        };
        let prefix = maybe_prefix
            .parse()
            .map_err(|_| CidrError::InvalidIpv4Cidr(format!("bad prefix: {maybe_prefix}")))?;
        let prefix_len = maybe_prefix_len.parse().map_err(|_| {
            CidrError::InvalidIpv4Cidr(format!("bad prefix len: {maybe_prefix_len}"))
        })?;
        if prefix_len <= 32 {
            Ok(Ipv4Cidr { prefix, prefix_len })
        } else {
            Err(CidrError::InvalidIpv4Cidr(format!(
                "bad prefix len: {prefix_len}"
            )))
        }
    }
}

impl From<Ipv4Cidr> for Cidr {
    fn from(cidr: Ipv4Cidr) -> Self {
        Cidr::V4(cidr)
    }
}

impl TryFrom<Cidr> for Ipv4Cidr {
    type Error = CidrError;

    fn try_from(cidr: Cidr) -> Result<Self, Self::Error> {
        match cidr {
            Cidr::V4(c) => Ok(c),
            Cidr::V6(_) => Err(CidrError::InvalidIpv4Cidr(format!("{cidr} is IPv6"))),
        }
    }
}

/// An IPv6 subnet with prefix and prefix length.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv6Cidr {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
}

// NOTE: See above about why we manually implement serialization and JsonSchema.
impl<'de> serde::Deserialize<'de> for Ipv6Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(|e: <Self as FromStr>::Err| <D::Error as serde::de::Error>::custom(e))
    }
}

impl Serialize for Ipv6Cidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{self}"))
    }
}
impl JsonSchema for Ipv6Cidr {
    fn schema_name() -> String {
        String::from("Ipv6Cidr")
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            metadata: Some(Box::new(schemars::schema::Metadata {
                title: Some("An IPv6 subnet".to_string()),
                description: Some("An IPv6 subnet, including prefix and subnet mask".to_string()),
                examples: vec!["fe80::/10".into()],
                ..Default::default()
            })),
            format: Some(String::from("ipv6cidr")),
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            ..Default::default()
        }
        .into()
    }
}

impl Ipv6Cidr {
    /// Return `true` if the address is within the subnet.
    pub fn contains(&self, ipv6: Ipv6Addr) -> bool {
        let prefix: u128 = self.prefix.into();
        let mask = ((1u128 << self.prefix_len) - 1) << (128 - self.prefix_len);
        let addr: u128 = ipv6.into();

        (addr & mask) == prefix
    }
}

#[cfg(test)]
mod ipv6_tests {
    use super::Ipv6Cidr;
    use std::net::Ipv6Addr;

    #[test]
    fn test_cidrv6_contains() {
        let cidr: Ipv6Cidr = "fc00:aabb:ccdd:18::/64".parse().unwrap();
        let a: Ipv6Addr = "fc00:aabb:ccdd:18:240:54ff:fe08:808".parse().unwrap();
        let b: Ipv6Addr = "fc00:aabb:ccdd:18:240:54ff::0".parse().unwrap();
        let c: Ipv6Addr = "fc00:aabb:ccdd:18::0".parse().unwrap();
        let d: Ipv6Addr = "fc00:aabb:cc::0".parse().unwrap();
        let e: Ipv6Addr = "ff02::0".parse().unwrap();

        assert!(cidr.contains(a));
        assert!(cidr.contains(b));
        assert!(cidr.contains(c));
        assert!(!cidr.contains(d));
        assert!(!cidr.contains(e));
    }
}

impl Ord for Ipv6Cidr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.prefix.cmp(&other.prefix) {
            std::cmp::Ordering::Equal => self.prefix_len.cmp(&other.prefix_len),
            o => o,
        }
    }
}

impl PartialOrd for Ipv6Cidr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.prefix, self.prefix_len)
    }
}

impl FromStr for Ipv6Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, CidrError> {
        let Some((mut maybe_prefix, maybe_prefix_len)) = s.split_once('/') else {
            return Err(CidrError::InvalidIpv6Cidr(s.to_string()));
        };
        // strip out any link name in the prefix
        if maybe_prefix.contains('%') {
            (maybe_prefix, _) = maybe_prefix.split_once('%').unwrap();
        }
        let prefix = maybe_prefix
            .parse()
            .map_err(|_| CidrError::InvalidIpv6Cidr(format!("bad prefix: {maybe_prefix}")))?;
        let prefix_len = maybe_prefix_len.parse().map_err(|_| {
            CidrError::InvalidIpv6Cidr(format!("bad prefix len: {maybe_prefix_len}"))
        })?;
        if prefix_len <= 128 {
            Ok(Ipv6Cidr { prefix, prefix_len })
        } else {
            Err(CidrError::InvalidIpv6Cidr(format!(
                "bad prefix len: {prefix_len}"
            )))
        }
    }
}

impl TryFrom<Cidr> for Ipv6Cidr {
    type Error = CidrError;

    fn try_from(cidr: Cidr) -> Result<Self, Self::Error> {
        match cidr {
            Cidr::V6(c) => Ok(c),
            Cidr::V4(_) => Err(CidrError::InvalidIpv6Cidr(format!("{cidr} is IPv4"))),
        }
    }
}

impl From<Ipv6Cidr> for Cidr {
    fn from(cidr: Ipv6Cidr) -> Self {
        Cidr::V6(cidr)
    }
}

/// An EUI-48 MAC address, used for layer-2 addressing.
#[derive(Copy, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MacAddr {
    a: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    fn from(a: [u8; 6]) -> Self {
        Self { a }
    }
}

impl MacAddr {
    /// Oxide's Organizationally Unique Identifier.
    pub const OXIDE_OUI: [u8; 3] = [0xa8, 0x40, 0x25];
    pub const ZERO: Self = MacAddr {
        a: [0, 0, 0, 0, 0, 0],
    };

    /// Create a new MAC address from octets in network byte order.
    pub fn new(o0: u8, o1: u8, o2: u8, o3: u8, o4: u8, o5: u8) -> MacAddr {
        MacAddr {
            a: [o0, o1, o2, o3, o4, o5],
        }
    }

    /// Create a new MAC address from a slice of bytes in network byte order.
    ///
    /// # Panics
    ///
    /// Panics if the slice is fewer than 6 octets.
    ///
    /// Note that any further octets are ignored.
    pub fn from_slice(s: &[u8]) -> MacAddr {
        MacAddr::new(s[0], s[1], s[2], s[3], s[4], s[5])
    }

    /// Convert `self` to an array of bytes in network byte order.
    pub fn to_vec(self) -> Vec<u8> {
        vec![
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5],
        ]
    }

    /// Return `true` if `self` is the null MAC address, all zeros.
    pub fn is_null(self) -> bool {
        const EMPTY: MacAddr = MacAddr {
            a: [0, 0, 0, 0, 0, 0],
        };

        self == EMPTY
    }

    /// Generate a random MAC address.
    pub fn random() -> MacAddr {
        let mut rng = rand::thread_rng();
        let mut m = MacAddr { a: [0; 6] };
        for octet in m.a.iter_mut() {
            *octet = rng.gen();
        }
        m
    }

    /// Generate a random MAC address with the Oxide OUI.
    pub fn random_oxide() -> MacAddr {
        let mut rng = rand::thread_rng();
        let mut octets = [0; 6];
        octets[..3].copy_from_slice(&Self::OXIDE_OUI);
        rng.fill(&mut octets[3..]);

        // Ensure that this MAC is appropriate for a _physical_ device. See RFD
        // 174 section 3.2.
        octets[3] &= 0b0111_1111;

        MacAddr { a: octets }
    }

    /// Generate an EUI-64 ID from the mac address, following the process
    /// desribed in RFC 2464, section 4.
    pub fn to_eui64(self) -> [u8; 8] {
        [
            self.a[0] ^ 0x2,
            self.a[1],
            self.a[2],
            0xff,
            0xfe,
            self.a[3],
            self.a[4],
            self.a[5],
        ]
    }
}

#[derive(Error, Debug, Clone)]
pub enum MacError {
    /// Too few octets to be a valid MAC address
    #[error("Too few octets")]
    TooShort,
    /// Too many octets to be a valid MAC address
    #[error("Too many octets")]
    TooLong,
    /// Found an octet with a non-hexadecimal character or invalid separator
    #[error("Invalid octect")]
    InvalidOctet,
}

impl FromStr for MacAddr {
    type Err = MacError;

    fn from_str(s: &str) -> Result<Self, MacError> {
        let v: Vec<&str> = s.split(':').collect();

        match v.len().cmp(&6) {
            std::cmp::Ordering::Less => Err(MacError::TooShort),
            std::cmp::Ordering::Greater => Err(MacError::TooLong),
            std::cmp::Ordering::Equal => {
                let mut m = MacAddr { a: [0u8; 6] };
                for (i, octet) in v.iter().enumerate() {
                    m.a[i] = u8::from_str_radix(octet, 16).map_err(|_| MacError::InvalidOctet)?;
                }
                Ok(m)
            }
        }
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5]
        )
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> [u8; 6] {
        mac.a
    }
}

impl From<MacAddr> for u64 {
    fn from(mac: MacAddr) -> u64 {
        ((mac.a[0] as u64) << 40)
            | ((mac.a[1] as u64) << 32)
            | ((mac.a[2] as u64) << 24)
            | ((mac.a[3] as u64) << 16)
            | ((mac.a[4] as u64) << 8)
            | (mac.a[5] as u64)
    }
}

impl From<&MacAddr> for u64 {
    fn from(mac: &MacAddr) -> u64 {
        From::from(*mac)
    }
}

impl From<u64> for MacAddr {
    fn from(x: u64) -> Self {
        MacAddr {
            a: [
                ((x >> 40) & 0xff) as u8,
                ((x >> 32) & 0xff) as u8,
                ((x >> 24) & 0xff) as u8,
                ((x >> 16) & 0xff) as u8,
                ((x >> 8) & 0xff) as u8,
                (x & 0xff) as u8,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::generate_ipv6_link_local;
    use super::Ipv6Addr;
    use super::MacAddr;

    #[test]
    fn test_into() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let u: u64 = (&a).into();
        assert_eq!(u, 0x123456789abc);
    }

    #[test]
    fn test_equal() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        assert_eq!(a, b);
    }

    #[test]
    fn test_not_equal() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbb);
        assert_ne!(a, b);
    }

    #[test]
    fn test_parse() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = "12:34:56:78:9a:bc".parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_to_string() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = format!("{a}");
        assert_eq!(b, "12:34:56:78:9a:bc");
    }
    #[test]
    fn test_eui64() {
        let expected = [0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE];
        let a = MacAddr::new(0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE);
        let eui = a.to_eui64();
        assert_eq!(eui, expected);
    }

    #[test]
    fn test_generate_ipv6_link_local() {
        let mac = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0xab, 0xcd);
        let addr = generate_ipv6_link_local(mac);
        assert_eq!(
            addr,
            "fe80::1034:56ff:fe78:abcd".parse::<Ipv6Addr>().unwrap()
        );
    }
}
