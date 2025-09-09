// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use chrono::DateTime;
use chrono::Utc;

use crate::errors;
use protocol::types as protocol;

pub type LldpdResult<T> = Result<T, errors::LldpdError>;

/// This struct is used to record information about a neighbor whose
/// advertisements we have received.
#[derive(Clone, Debug)]
pub struct Neighbor {
    /// Uuid assigned when the neighbor was first seen
    pub id: uuid::Uuid,
    /// When the neighbor was first seen.  Note: this is reset if the
    /// neighbor's TTL expires and we subsequently rediscover it.
    pub first_seen: DateTime<Utc>,
    /// When we last received an advertisement from this system.
    pub last_seen: DateTime<Utc>,
    /// When the data advertised by this system last changed
    pub last_changed: DateTime<Utc>,

    /// The latest advertised data received from this neighbor
    pub lldpdu: protocol::Lldpdu,
    /// When this record expires
    pub expires_at: DateTime<Utc>,
}

impl Neighbor {
    pub fn from_lldpdu(
        lldpdu: &protocol::Lldpdu,
        uuid: Option<uuid::Uuid>,
    ) -> Self {
        let now = Utc::now();

        let id = uuid.unwrap_or(uuid::Uuid::new_v4());
        let ttl = std::time::Duration::from_secs(lldpdu.ttl as u64);
        Neighbor {
            id,
            first_seen: now,
            last_seen: now,
            last_changed: now,
            lldpdu: lldpdu.clone(),
            expires_at: now + ttl,
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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AdminStatus {
    #[default]
    EnabledRxTx,
    EnabledRxOnly,
    EnabledTxOnly,
    Disabled,
}

impl AdminStatus {
    pub fn has_rx(self) -> bool {
        self == AdminStatus::EnabledRxTx || self == AdminStatus::EnabledRxOnly
    }

    pub fn has_tx(self) -> bool {
        self == AdminStatus::EnabledRxTx || self == AdminStatus::EnabledTxOnly
    }
}
