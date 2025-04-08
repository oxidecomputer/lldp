// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// An EUI-48 MAC address, used for layer-2 addressing.
#[derive(
    Clone,
    Copy,
    Deserialize,
    JsonSchema,
    Serialize,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
)]
pub struct MacAddr {
    a: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    fn from(a: [u8; 6]) -> Self {
        Self { a }
    }
}

impl MacAddr {
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
                    m.a[i] = u8::from_str_radix(octet, 16)
                        .map_err(|_| MacError::InvalidOctet)?;
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
