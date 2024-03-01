// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::convert;

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
    #[error("buffer too small for incoming packet. have: {0}  need: {1}")]
    TooSmall(usize, usize),
    #[error("SMF error: {0}")]
    Smf(String),
    #[error("Pcap error: {0}")]
    Pcap(String),
    #[error("DLPI error: {0}")]
    Dlpi(String),
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
            LldpdError::TooSmall(_, _) => {
                dropshot::HttpError::for_internal_error(
                    "internal buffer exceeded".to_string(),
                )
            }
            LldpdError::Pcap(e) => dropshot::HttpError::for_internal_error(e),
            LldpdError::Dlpi(e) => dropshot::HttpError::for_internal_error(e),
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
