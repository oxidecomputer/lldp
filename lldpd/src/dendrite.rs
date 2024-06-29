// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::HashSet;
use std::sync::Arc;

use slog::error;
use slog::info;

use crate::types::LldpdResult;
use crate::Global;
use crate::LldpdError;
use common::MacAddr;
use dpd_client::types::LinkId;
use dpd_client::types::PortId;
use dpd_client::Client;
use dpd_client::ClientState;

fn parse_link_name(name: &str) -> LldpdResult<(PortId, LinkId)> {
    let Some((port_id, link_id)) = name.split_once('/') else {
        return Err(LldpdError::Invalid(format!(
            "Invalid switch port or link ID: {name}"
        )));
    };
    let Ok(port_id) = PortId::try_from(port_id) else {
        return Err(LldpdError::Invalid(format!(
            "Invalid switch port: {port_id}"
        )));
    };
    let Ok(link_id) = link_id.parse() else {
        return Err(LldpdError::Invalid(format!("Invalid link ID: {link_id}")));
    };
    Ok((port_id, link_id))
}

#[cfg(feature = "dendrite")]
pub async fn dpd_tfport(
    g: &Global,
    name: &str,
) -> LldpdResult<(String, MacAddr)> {
    let (port_id, link_id) = parse_link_name(name)?;
    let client = g.dpd.as_ref().ok_or(LldpdError::NoDpd)?;
    let link_info = client
        .link_get(&port_id, &link_id)
        .await
        .map_err(|e| LldpdError::DpdClientError(e.to_string()))?;
    let iface =
        format!("tfport{}_{}", port_id.to_string(), link_id.to_string());
    let mac = link_info.into_inner().address;
    Ok((iface, mac))
}

async fn dpd_version(log: &slog::Logger, client: &Client) -> String {
    let mut warn_at = 0;
    let mut warn_delay = 1;
    let mut iter = 0;

    loop {
        if let Ok(version) = client.dpd_version().await {
            return version.into_inner();
        }
        if iter >= warn_at {
            error!(log, "Failed to connect to dpd.  Retrying...");
            warn_at += warn_delay;
            warn_delay = std::cmp::min(60, warn_delay * 2);
        }
        iter += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

async fn get_links(g: &crate::Global) -> LldpdResult<HashSet<String>> {
    let mut links = HashSet::new();
    for l in g
        .dpd
        .as_ref()
        .expect("monitor only runs if dpd is set up")
        .link_list_all()
        .await
        .map_err(|e| LldpdError::DpdClientError(e.to_string()))?
        .into_inner()
    {
        links.insert(format!(
            "{}/{}",
            l.port_id.to_string(),
            l.link_id.to_string()
        ));
    }
    Ok(links)
}

#[cfg(feature = "smf")]
pub async fn link_monitor(g: Arc<crate::Global>) {
    let log = g.log.new(slog::o!("unit" => "dpd-link-monitor"));
    let mut links = HashSet::new();
    loop {
        let _ =
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        match get_links(&g).await {
            Ok(current) => {
                let new = current.difference(&links);
                let dead = links.difference(&current);
                if links != current {
                    info!(g.log, "new links: {new:?}  missing links: {dead:?}");
                    _ = super::smf::refresh_smf_config(&g).await;
                    links = current;
                }
            }
            Err(e) => error!(log, "failed to fetch link info: {e:?}"),
        }
    }
}

pub async fn dpd_init(
    log: &slog::Logger,
    opts: crate::Opt,
) -> Option<dpd_client::Client> {
    if opts.no_dpd {
        None
    } else {
        let host = opts.host.unwrap_or_else(|| "localhost".to_string());
        let port = opts.port.unwrap_or(dpd_client::DEFAULT_PORT);
        info!(log, "connecting to dpd at {host}:{port}");
        let client_state = ClientState {
            tag: String::from("lldpd"),
            log: log.new(slog::o!("unit" => "lldpd-client")),
        };
        let client =
            Client::new(&format!("http://{host}:{port}"), client_state);

        info!(
            log,
            "connected to dpd running {}",
            dpd_version(log, &client).await
        );
        Some(client)
    }
}
