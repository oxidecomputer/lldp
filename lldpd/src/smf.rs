// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use anyhow::Context;
use crucible_smf::PropertyGroup;
use slog::debug;
use slog::error;

use crate::protocol::ChassisId;
use crate::types::LldpdError;
use crate::types::LldpdResult;

// Given a property name within a group, return all the associated values as
// a vec of strings.
fn get_properties(
    config: &PropertyGroup,
    name: &str,
) -> LldpdResult<Vec<String>> {
    let prop = config.get_property(name).map_err(|e| {
        LldpdError::Smf(format!("failed to get '{name}' property: {e:?}"))
    })?;

    let mut rval = Vec::new();
    if let Some(values) = prop {
        for value in values.values().map_err(|e| {
            LldpdError::Smf(format!("failed to get values for '{name}': {e:?}"))
        })? {
            let value = value
                .map_err(|e| {
                    LldpdError::Smf(format!(
                        "failed to get value for '{name}': {e:?}"
                    ))
                })?
                .as_string()
                .map_err(|e| {
                    LldpdError::Smf(format!(
                        "failed to convert value '{name}' to string: {e:?}"
                    ))
                })?;
            if value != "unknown" {
                rval.push(value);
            }
        }
    }

    Ok(rval)
}

pub fn refresh_smf_config(g: &crate::Global) -> LldpdResult<()> {
    const SMF_SCRIMLET_ID_PROP: &str = "scrimlet_id";
    const SMF_SCRIMLET_MODEL_PROP: &str = "scrimlet_model";
    const SMF_BOARD_REV_PROP: &str = "board_rev";
    const SMF_ADDRESS_PROP: &str = "address";

    debug!(&g.log, "refreshing SMF configuration data");

    // Create an SMF context and take a snapshot of the current settings
    let scf = crucible_smf::Scf::new().context("creating scf handle")?;
    let instance = scf.get_self_instance().context("getting smf instance")?;
    let snapshot = instance
        .get_running_snapshot()
        .context("getting running snapshot")?;

    // All the properties relevant to us fall under the "config" property group
    let pg = match snapshot
        .get_pg("config")
        .context("getting 'config' propertygroup")?
    {
        Some(c) => c,
        None => return Ok(()),
    };

    if let Ok(addresses) = get_properties(&pg, SMF_ADDRESS_PROP) {
        debug!(g.log, "config/{SMF_ADDRESS_PROP}: {addresses:?}");
        let mut listen_addresses = Vec::new();
        for addr in addresses {
            match addr.parse() {
                Ok(a) => listen_addresses.push(a),
                Err(e) => error!(
                    g.log,
                    "bad socket address {} in smf config/{}: {:?}",
                    addr,
                    SMF_ADDRESS_PROP,
                    e
                ),
            }
        }
        *(g.listen_addresses.lock().unwrap()) = listen_addresses;
    }

    let mut s = g.switchinfo.lock().unwrap();
    if let Ok(id) = get_properties(&pg, SMF_SCRIMLET_ID_PROP) {
        debug!(g.log, "config/{SMF_SCRIMLET_ID_PROP}: {id:?}");
        let chassis_id = ChassisId::ChassisComponent(id[0].to_string());
        if !id.is_empty() {
            s.chassis_id = chassis_id;
            s.system_name = Some(id[0].clone());
        }
    }
    let mut desc = Vec::new();
    if let Ok(model) = get_properties(&pg, SMF_SCRIMLET_MODEL_PROP) {
        debug!(g.log, "config/{SMF_SCRIMLET_MODEL_PROP}: {model:?}");
        if !model.is_empty() {
            desc.push(format!("Oxide sled model: {}", model[0]));
        }
    }
    if let Ok(board) = get_properties(&pg, SMF_BOARD_REV_PROP) {
        debug!(g.log, "config/{SMF_BOARD_REV_PROP}: {board:?}");
        if !board.is_empty() {
            desc.push(format!("Sidecar revision: {}", board[0]));
        }
    }
    if !desc.is_empty() {
        s.system_description = Some(desc.join(", "));
    }

    Ok(())
}
