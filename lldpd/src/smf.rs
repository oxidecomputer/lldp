// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use crucible_smf::PropertyGroup;
use crucible_smf::Snapshot;
use slog::debug;
use slog::error;
use slog::info;

use super::interfaces;
use super::types;
use crate::protocol::ChassisId;
use crate::protocol::PortId;
use crate::types::LldpdResult;
use crate::LldpdError;

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

// Given a property name within a group, return the single value it holds
fn get_property(config: &PropertyGroup, name: &str) -> LldpdResult<String> {
    let all = get_properties(config, name)?;
    match all.len() {
        1 => Ok(all[0].clone()),
        0 => Err(LldpdError::Smf(format!("'{name}' has no value"))),
        _ => Err(LldpdError::Smf(format!("'{name}' has multiple values"))),
    }
}

fn update_system_properties(
    g: &crate::Global,
    snapshot: &Snapshot,
) -> LldpdResult<()> {
    const SMF_SCRIMLET_ID_PROP: &str = "scrimlet_id";
    const SMF_SCRIMLET_MODEL_PROP: &str = "scrimlet_model";
    const SMF_BOARD_REV_PROP: &str = "board_rev";
    const SMF_ADDRESS_PROP: &str = "address";

    // All the properties relevant to us fall under the "config" property group
    let Some(pg) = snapshot
        .get_pg("config")
        .context("getting 'config' propertygroup")?
    else {
        return Ok(());
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
    if let Ok(id) = get_property(&pg, SMF_SCRIMLET_ID_PROP) {
        debug!(g.log, "config/{SMF_SCRIMLET_ID_PROP}: {id:?}");
        s.chassis_id = ChassisId::ChassisComponent(id.to_string());
        s.system_name = Some(id.clone());
    }
    let mut desc = Vec::new();
    if let Ok(model) = get_property(&pg, SMF_SCRIMLET_MODEL_PROP) {
        debug!(g.log, "config/{SMF_SCRIMLET_MODEL_PROP}: {model:?}");
        desc.push(format!("Oxide sled model: {}", model));
    }
    if let Ok(board) = get_property(&pg, SMF_BOARD_REV_PROP) {
        debug!(g.log, "config/{SMF_BOARD_REV_PROP}: {board:?}");
        desc.push(format!("Sidecar revision: {}", board));
    }
    if !desc.is_empty() {
        s.system_description = Some(desc.join(", "));
    }

    Ok(())
}

fn construct_config(
    snapshot: &Snapshot,
    iface: &str,
) -> LldpdResult<interfaces::InterfaceCfg> {
    let pg = snapshot
        .get_pg(&format!("port_{iface}"))
        .expect("existence guaranteed by presence in this list")
        .unwrap();

    let admin_status =
        Some(match get_property(&pg, "status")?.to_lowercase().as_str() {
            "enabled" => types::AdminStatus::EnabledRxTx,
            "disabled" => types::AdminStatus::Disabled,
            "rx_only" | "rxonly" | "rx" => types::AdminStatus::EnabledRxOnly,
            "tx_only" | "txonly" | "tx" => types::AdminStatus::EnabledTxOnly,
            x => {
                return Err(LldpdError::Smf(format!(
                    "invalid status for {iface}: {x}"
                )));
            }
        });
    let chassis_id = get_property(&pg, "chassis_id")
        .ok()
        .map(|id| ChassisId::LocallyAssigned(id.to_string()));

    let port_id = get_property(&pg, "port_id")
        .map(|id| PortId::LocallyAssigned(id.to_string()))
        .ok();

    let system_name = get_property(&pg, "system_name").ok();
    let system_description = get_property(&pg, "system_description").ok();
    let port_description = get_property(&pg, "port_description").ok();
    let management_addrs = None; //get_property(&pg, "management_addrs").ok();

    Ok(interfaces::InterfaceCfg {
        admin_status,
        chassis_id,
        port_id,
        system_name,
        system_description,
        port_description,
        management_addrs,
    })
}

async fn update_interface_properties(
    g: &Arc<crate::Global>,
    snapshot: &Snapshot<'_>,
) -> LldpdResult<()> {
    // Iterate over all of the property groups, looking for port_qsfpX.
    let ifaces: Vec<String> = {
        let mut groups = snapshot.pgs().context("getting property groups")?;
        let mut all = Vec::new();
        while let Some(pg) = groups.next().transpose()? {
            all.push(pg.name().context("extracting property name")?);
        }
        all.iter()
            .filter_map(|name| name.strip_prefix("port_"))
            .map(|s| s.to_string())
            .collect()
    };

    let mut orphaned_interfaces = HashSet::new();
    for iface in g.interfaces.lock().unwrap().keys() {
        orphaned_interfaces.insert(iface.to_string());
    }

    for iface in &ifaces {
        match construct_config(snapshot, iface) {
            Ok(c) => {
                // The parameters are all vetted while constructing the
                // config struct, so the only way the update call can fail
                // is if the interface hasn't been configured yet.
                match interfaces::update_from_cfg(g, iface, &c).await {
                    Ok(_) => _ = orphaned_interfaces.remove(iface),
                    Err(_) => {
                        _ = interfaces::interface_add(g, iface.clone(), c).await
                    }
                }
            }
            Err(e) => {
                error!(g.log, "unable to parse config for {iface}: {e:?}")
            }
        }
    }
    info!(g.log, "orphaned interfaces: {orphaned_interfaces:?}");

    Ok(())
}

pub async fn refresh_smf_config(g: &Arc<crate::Global>) -> LldpdResult<()> {
    debug!(&g.log, "refreshing SMF configuration data");

    // Create an SMF context and take a snapshot of the current settings
    let scf = crucible_smf::Scf::new().context("creating scf handle")?;
    let instance = scf.get_self_instance().context("getting smf instance")?;
    let snapshot = instance
        .get_running_snapshot()
        .context("getting running snapshot")?;

    update_system_properties(g, &snapshot)?;
    update_interface_properties(g, &snapshot).await?;

    Ok(())
}
