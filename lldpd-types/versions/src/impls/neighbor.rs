// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

use protocol::types::Lldpdu;

use crate::latest::neighbor::NeighborId;

impl NeighborId {
    pub fn new(lldpdu: &Lldpdu) -> Self {
        NeighborId {
            chassis_id: lldpdu.chassis_id.clone(),
            port_id: lldpdu.port_id.clone(),
        }
    }
}
