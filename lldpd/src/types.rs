use std::convert;
use std::fmt;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::protocol;

pub type LldpdResult<T> = Result<T, LldpdError>;

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct SystemInfo {
    pub chassis_id: protocol::ChassisId,
    pub port_id: protocol::PortId,
    pub ttl: u16,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub capabilities_available: Vec<protocol::SystemCapabilities>,
    pub capabilities_enabled: Vec<protocol::SystemCapabilities>,
    pub management_addresses: Vec<protocol::ManagementAddress>,
    pub organizationally_specific: Vec<String>,
}

impl fmt::Display for SystemInfo {
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

impl From<&protocol::Lldpdu> for SystemInfo {
    fn from(lldpdu: &protocol::Lldpdu) -> SystemInfo {
        let (capabilities_available, capabilities_enabled) =
            match &lldpdu.system_capabilities {
                Some((a, e)) => {
                    (a.iter().cloned().collect(), e.iter().cloned().collect())
                }
                None => (Vec::new(), Vec::new()),
            };

        SystemInfo {
            chassis_id: lldpdu.chassis_id.clone(),
            port_id: lldpdu.port_id.clone(),
            ttl: lldpdu.ttl,
            port_description: lldpdu.port_description.clone(),
            system_name: lldpdu.system_name.clone(),
            system_description: lldpdu.system_description.clone(),
            capabilities_available,
            capabilities_enabled,
            management_addresses: lldpdu.management_addresses.to_vec(),
            organizationally_specific: lldpdu
                .organizationally_specific
                .iter()
                .map(|os| os.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LldpdError {
    /// The daemon attempted to perform a task the required contacting dpd without
    /// being connected to a dpd instance.
    #[error("Not connected to dpd daemon")]
    NoDpd,
    /// An error received during a dpd-client operation
    #[error("dpd error: {0:?}")]
    DpdClientError(String),
    #[error("I/O error: {0:?}")]
    Io(std::io::Error),
    #[error("Resource already exists: {0}")]
    Exists(String),
    #[error("No such resource: {0}")]
    Missing(String),
    #[error("Invalid argument: {0}")]
    Invalid(String),
    #[error("LLDP protocol error: {0}")]
    Protocol(String),
    #[error("SMF error: {0}")]
    Smf(String),
    #[error("Pcap error: {0}")]
    Pcap(String),
    #[error("DLPI error: {0}")]
    DLPI(String),
    #[error("error: {0}")]
    Other(String),
}

#[cfg(feature = "smf")]
impl From<crucible_smf::ScfError> for LldpdError {
    fn from(e: crucible_smf::ScfError) -> Self {
        Self::Smf(format!("{e}"))
    }
}

impl convert::From<std::io::Error> for LldpdError {
    fn from(err: std::io::Error) -> Self {
        LldpdError::Io(err)
    }
}

impl convert::From<LldpdError> for dropshot::HttpError {
    fn from(o: LldpdError) -> dropshot::HttpError {
        match o {
            LldpdError::NoDpd => dropshot::HttpError::for_internal_error(
                "not connected to dpd".to_string(),
            ),
            LldpdError::DpdClientError(e) => {
                dropshot::HttpError::for_internal_error(format!(
                    "dpd client error: {e}"
                ))
            }
            LldpdError::Io(e) => {
                dropshot::HttpError::for_internal_error(e.to_string())
            }
            LldpdError::Exists(e) => dropshot::HttpError::for_status(
                Some(e),
                http::StatusCode::CONFLICT,
            ),
            LldpdError::Missing(e) => dropshot::HttpError::for_status(
                Some(e),
                http::StatusCode::NOT_FOUND,
            ),
            LldpdError::Invalid(e) => {
                dropshot::HttpError::for_bad_request(None, e)
            }
            LldpdError::Protocol(e) => {
                dropshot::HttpError::for_bad_request(None, e)
            }
            LldpdError::Pcap(e) => dropshot::HttpError::for_internal_error(e),
            LldpdError::DLPI(e) => dropshot::HttpError::for_internal_error(e),
            LldpdError::Smf(e) => dropshot::HttpError::for_internal_error(e),
            LldpdError::Other(e) => dropshot::HttpError::for_internal_error(e),
        }
    }
}

impl convert::From<String> for LldpdError {
    fn from(err: String) -> Self {
        LldpdError::Other(err)
    }
}

impl convert::From<&str> for LldpdError {
    fn from(err: &str) -> Self {
        LldpdError::Other(err.to_string())
    }
}

impl convert::From<anyhow::Error> for LldpdError {
    fn from(err: anyhow::Error) -> Self {
        LldpdError::Other(err.to_string())
    }
}
