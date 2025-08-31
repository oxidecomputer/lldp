// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

use chrono::{DateTime, Utc};
use protocol::types::{ChassisId, Lldpdu, PortId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::system_info::SystemInfo;

#[derive(
    Debug,
    Clone,
    Deserialize,
    JsonSchema,
    Serialize,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct NeighborId {
    pub chassis_id: ChassisId,
    pub port_id: PortId,
}

impl NeighborId {
    pub fn new(lldpdu: &Lldpdu) -> Self {
        NeighborId {
            chassis_id: lldpdu.chassis_id.clone(),
            port_id: lldpdu.port_id.clone(),
        }
    }
}

/// A remote system that has been discovered on one of our configured interfaces
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Neighbor {
    /// The port on which the neighbor was seen
    pub port: String,
    /// An ID that uniquely identifies the neighbor.  Note: this ID is assigned
    /// when we first see a neighbor we are currently tracking.  If a neighbor
    /// goes offline long enough to be forgotten, it will be assigned a new ID
    /// if and when it comes back online.
    pub id: uuid::Uuid,
    /// When was the first beacon received from this neighbor.
    pub first_seen: DateTime<Utc>,
    /// When was the latest beacon received from this neighbor.
    pub last_seen: DateTime<Utc>,
    /// When was the last time this neighbor's beaconed LLDPDU contents changed.
    pub last_changed: DateTime<Utc>,
    /// Contents of the neighbor's LLDPDU beacon.
    pub system_info: SystemInfo,
}
