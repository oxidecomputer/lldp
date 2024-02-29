// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::fmt;

use chrono::DateTime;
use chrono::Utc;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::errors;
use crate::protocol;

pub type LldpdResult<T> = Result<T, errors::LldpdError>;

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

/// This struct is used to record information about a neighbor whose
/// advertisements we have received.
#[derive(Clone, Debug)]
pub struct Neighbor {
    /// When the neighbor was first seen.  Note: this is reset if the
    /// neighbor's TTL expires and we subsequently rediscover it.
    pub first_seen: DateTime<Utc>,
    /// When we last received an advertisement from this system.
    pub last_seen: DateTime<Utc>,
    /// When the data advertised by this system last changed
    pub last_changed: DateTime<Utc>,

    /// The latest advertised data received from this neighbor
    pub lldpdu: protocol::Lldpdu,
}

impl Neighbor {
    pub fn from_lldpdu(lldpdu: &protocol::Lldpdu) -> Self {
        let now = Utc::now();

        Neighbor {
            first_seen: now,
            last_seen: now,
            last_changed: now,
            lldpdu: lldpdu.clone(),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct NeighborId {
    pub chassis_id: protocol::ChassisId,
    pub port_id: protocol::PortId,
}

impl NeighborId {
    pub fn new(lldpdu: &protocol::Lldpdu) -> Self {
        NeighborId {
            chassis_id: lldpdu.chassis_id.clone(),
            port_id: lldpdu.port_id.clone(),
        }
    }
}

/// This structure contains some of the global state described in section 9.2.5
/// of the standard.  This structure contains those values that can be
/// configured by an administrator, while the values that are updated
/// dynamically are all stored in per-interface structs.
#[derive(Clone, Debug)]
pub struct Agent {
    /// Whether the agent should be sending, receiving, or both.
    pub admin_status: AdminStatus,
    /// How quickly to resend LLDPDUs during fast tx periods.
    /// Measured in ticks from 1-3600.
    pub msg_fast_tx: u16,
    /// Multiplier of msg_tx_interval, used to calculate TTL.  Legal values
    /// are 1-100.
    pub msg_tx_hold: u16,
    /// Time between LLDPDU transmissions during normal tx periods.
    /// Measured in ticks from 1-3600.
    pub msg_tx_interval: u16,
    /// After becoming disabled, time in seconds to wait before attempting
    /// reinitialization.
    pub reinit_delay: u16,
    /// Maximum value of the per-interface tx_credit
    pub tx_credit_max: u16,
    /// Initial value of the per-interface tx_fast
    pub tx_fast_init: u16,
}

impl Default for Agent {
    /// Returns an Agent struct with all fields set as recommended by the
    /// standard
    fn default() -> Self {
        Agent {
            admin_status: AdminStatus::default(),
            msg_fast_tx: 1,
            msg_tx_hold: 4,
            msg_tx_interval: 30,
            reinit_delay: 2,
            tx_credit_max: 5,
            tx_fast_init: 4,
        }
    }
}

/// Whether the agent should be sending, receiving, or both.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminStatus {
    EnabledRxTx,
    EnabledRxOnly,
    EnabledTxOnly,
    Disabled,
}

impl Default for AdminStatus {
    fn default() -> Self {
        AdminStatus::EnabledRxTx
    }
}

impl AdminStatus {
    pub fn has_rx(self) -> bool {
        self == AdminStatus::EnabledRxTx || self == AdminStatus::EnabledRxOnly
    }

    pub fn has_tx(self) -> bool {
        self == AdminStatus::EnabledRxTx || self == AdminStatus::EnabledTxOnly
    }
}
