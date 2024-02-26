// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::btree_map::Entry;

use chrono::DateTime;
use chrono::Utc;
use slog::info;
use slog::trace;

use crate::interfaces;
use crate::protocol;
use crate::protocol::Lldpdu;
use crate::types;
use crate::Global;

#[derive(Clone, Debug)]
pub struct Neighbor {
    pub interface: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_changed: DateTime<Utc>,

    pub lldpdu: Lldpdu,
}

impl Neighbor {
    pub fn from_lldpdu(interface: impl ToString, lldpdu: &Lldpdu) -> Self {
        let now = Utc::now();

        Neighbor {
            interface: interface.to_string(),
            first_seen: now,
            last_seen: now,
            last_changed: now,
            lldpdu: lldpdu.clone(),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct NeighborId {
    pub interface: String,
    pub chassis_id: protocol::ChassisId,
    pub port_id: protocol::PortId,
}

impl NeighborId {
    fn new(interface: &str, lldpdu: &Lldpdu) -> Self {
        NeighborId {
            interface: interface.to_string(),
            chassis_id: lldpdu.chassis_id.clone(),
            port_id: lldpdu.port_id.clone(),
        }
    }
}

pub fn incoming_lldpdu(g: &Global, interface: &str, lldpdu: Lldpdu) {
    let id = NeighborId::new(interface, &lldpdu);
    if interfaces::neighbor_id_match(g, &id) {
        trace!(g.log, "ignoring our own lldpdu for {id:?}");
        return;
    }
    let mut neighbors = g.neighbors.lock().unwrap();
    match neighbors.entry(id.clone()) {
        Entry::Vacant(e) => {
            let sysinfo: types::SystemInfo = (&lldpdu).into();
            info!(g.log, "new neighbor {:?}: {}", id, &sysinfo;
		    "unit" => "neighbor");
            let neighbor = Neighbor::from_lldpdu(interface, &lldpdu);
            e.insert(neighbor);
        }
        Entry::Occupied(old) => {
            let now = Utc::now();
            let old = old.into_mut();
            old.last_seen = now;
            if old.lldpdu != lldpdu {
                let sysinfo: types::SystemInfo = (&lldpdu).into();
                info!(g.log, "updated neighbor {:?}: {}", id, &sysinfo;
		    "unit" => "neighbor");
                old.last_changed = now;
                old.lldpdu = lldpdu;
            }
        }
    };
}
