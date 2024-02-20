use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

macro_rules! make_port_type {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
        pub struct $name(pub(crate) u8);

        impl From<u8> for $name {
            fn from(index: u8) -> Self {
                Self(index)
            }
        }

        impl std::str::FromStr for $name {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s.len() <= $prefix.len() {
                    return Err("Invalid port kind");
                }
                let (head, tail) = s.split_at($prefix.len());
                if head.eq_ignore_ascii_case($prefix) {
                    tail.parse::<u8>()
                        .map_err(|_| "Invalid port index")
                        .map(Self::from)
                } else {
                    Err("Invalid port kind")
                }
            }
        }

        impl TryFrom<String> for $name {
            type Error = <Self as FromStr>::Err;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::try_from(s.as_str())
            }
        }

        impl TryFrom<&str> for $name {
            type Error = &'static str;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        impl From<$name> for String {
            fn from(n: $name) -> String {
                format!("{n}")
            }
        }
    };
}

make_port_type!(RearPort, "rear");
make_port_type!(QsfpPort, "qsfp");
make_port_type!(InternalPort, "int");

/// An identifier for a physical switch port.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PortId {
    Internal(InternalPort),
    Rear(RearPort),
    Qsfp(QsfpPort),
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortId::Internal(inner) => write!(f, "{inner}"),
            PortId::Rear(inner) => write!(f, "{inner}"),
            PortId::Qsfp(inner) => write!(f, "{inner}"),
        }
    }
}

impl FromStr for PortId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(internal) = s.parse() {
            Ok(PortId::Internal(internal))
        } else if let Ok(rear) = s.parse() {
            Ok(PortId::Rear(rear))
        } else if let Ok(qsfp) = s.parse() {
            Ok(PortId::Qsfp(qsfp))
        } else if let Ok(internal) = s.parse() {
            Ok(PortId::Internal(internal))
        } else {
            Err("Invalid switch port ID")
        }
    }
}

impl TryFrom<String> for PortId {
    type Error = <Self as FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&str> for PortId {
    type Error = <Self as FromStr>::Err;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<PortId> for String {
    fn from(p: PortId) -> String {
        format!("{p}")
    }
}
