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
