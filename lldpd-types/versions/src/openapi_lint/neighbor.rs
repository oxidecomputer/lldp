// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Oxide Computer Company

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::system_info::SystemInfo;
use crate::v1;

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

impl From<Neighbor> for v1::neighbor::Neighbor {
    fn from(new: Neighbor) -> Self {
        v1::neighbor::Neighbor {
            port: new.port,
            id: new.id,
            first_seen: new.first_seen,
            last_seen: new.last_seen,
            last_changed: new.last_changed,
            system_info: new.system_info.into(),
        }
    }
}
