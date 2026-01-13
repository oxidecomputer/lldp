// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

use std::fmt;

use protocol::types::Lldpdu;

use crate::latest::system_info::SystemInfo;

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
        for ma in &self.management_addresses {
            writeln!(f, "Management address: {ma}")?;
        }
        for os in &self.organizationally_specific {
            writeln!(f, "Organizationally Specific: {os}")?;
        }
        Ok(())
    }
}

impl From<&Lldpdu> for SystemInfo {
    fn from(lldpdu: &Lldpdu) -> SystemInfo {
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
