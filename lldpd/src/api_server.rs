// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! LLDP HTTP API types and endpoint functions.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;

use dropshot::ClientSpecifiesVersionInHeader;
use dropshot::EmptyScanParams;
use dropshot::HttpError;
use dropshot::HttpResponseCreated;
use dropshot::HttpResponseDeleted;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::PaginationParams;
use dropshot::Path;
use dropshot::Query;
use dropshot::RequestContext;
use dropshot::ResultsPage;
use dropshot::TypedBody;
use dropshot::VersionPolicy;
use dropshot::WhichPage;
use lldpd_api::LldpdApi;
use lldpd_types::build_info::BuildInfo;
use lldpd_types::interfaces::Interface;
use lldpd_types::interfaces::InterfaceAdd;
use lldpd_types::interfaces::InterfaceAddressPathParams;
use lldpd_types::interfaces::InterfaceCapabilityPathParams;
use lldpd_types::interfaces::InterfacePathParams;
use lldpd_types::neighbor::Neighbor;
use lldpd_types::neighbor::NeighborId;
use lldpd_types::neighbor::NeighborToken;
use lldpd_types::system_info::SystemAddressPathParams;
use lldpd_types::system_info::SystemCapabilityPathParams;
use slog::debug;
use slog::error;
use slog::info;
use slog::o;

use crate::interfaces;
use crate::Global;
use crate::LldpdError;
use protocol::types as protocol;

type ApiServer = dropshot::HttpServer<Arc<Global>>;

fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_sha: env!("VERGEN_GIT_SHA").to_string(),
        git_commit_timestamp: env!("VERGEN_GIT_COMMIT_TIMESTAMP").to_string(),
        git_branch: env!("VERGEN_GIT_BRANCH").to_string(),
        rustc_semver: env!("VERGEN_RUSTC_SEMVER").to_string(),
        rustc_channel: env!("VERGEN_RUSTC_CHANNEL").to_string(),
        rustc_host_triple: env!("VERGEN_RUSTC_HOST_TRIPLE").to_string(),
        rustc_commit_sha: env!("VERGEN_RUSTC_COMMIT_HASH").to_string(),
        cargo_triple: env!("VERGEN_CARGO_TARGET_TRIPLE").to_string(),
        debug: env!("VERGEN_CARGO_DEBUG").parse().unwrap(),
        opt_level: env!("VERGEN_CARGO_OPT_LEVEL").parse().unwrap(),
    }
}

pub enum LldpdApiImpl {}

impl LldpdApi for LldpdApiImpl {
    type Context = Arc<Global>;

    async fn sys_set_chassis_id(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<protocol::ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let val = body.into_inner();
        debug!(global.log, "set chassis_id = {:?}", val);
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn sys_set_system_name(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let val = body.into_inner();
        debug!(global.log, "set system_name = {:?}", val);
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn sys_del_system_name(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        debug!(global.log, "delete system_name");
        Ok(HttpResponseDeleted())
    }

    async fn sys_set_system_description(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let val = body.into_inner();
        debug!(global.log, "set system_description = {:?}", val);
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn sys_del_system_description(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        debug!(global.log, "delete system_description");
        Ok(HttpResponseDeleted())
    }

    async fn sys_add_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(global.log, "set system_capability {:?}", inner.capability);
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn sys_del_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(global.log, "clear system_capability {:?}", inner.capability);
        Ok(HttpResponseDeleted())
    }

    async fn sys_enable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(
            global.log,
            "enable system_capability {:?}", inner.capability
        );
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn sys_disable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(global.log, "clear system_capability {:?}", inner.capability);
        Ok(HttpResponseDeleted())
    }

    async fn sys_add_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<SystemAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(global.log, "add management address {}", inner.address);
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn sys_del_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<SystemAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(global.log, "remove management address {}", inner.address);
        Ok(HttpResponseDeleted())
    }

    async fn sys_clear_management_addr(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        debug!(global.log, "clear all management addresses");
        Ok(HttpResponseDeleted())
    }

    async fn interface_add(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        params: TypedBody<InterfaceAdd>,
    ) -> Result<HttpResponseCreated<()>, HttpError> {
        let global: &Arc<Global> = rqctx.context();
        let interface = path.into_inner().iface;
        let params = params.into_inner();
        let cfg = interfaces::InterfaceCfg {
            chassis_id: params.chassis_id,
            port_id: params.port_id,
            system_name: params.system_name,
            system_description: params.system_description,
            port_description: params.port_description,
            management_addrs: None,
            admin_status: None,
        };

        crate::interfaces::interface_add(global, interface, cfg)
            .await
            .map(HttpResponseCreated)
            .map_err(|e| e.into())
    }

    async fn interface_del(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Arc<Global> = rqctx.context();
        let interface = path.into_inner().iface;
        crate::interfaces::interface_remove(global, interface)
            .await
            .map(|_| HttpResponseDeleted())
            .map_err(|e| e.into())
    }

    async fn interface_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
    ) -> Result<HttpResponseOk<Interface>, HttpError> {
        let global: &Global = rqctx.context();
        let switchinfo = global.switchinfo.lock().unwrap().clone();
        let interface = path.into_inner().iface;

        Ok(HttpResponseOk(
            global
                .interfaces
                .lock()
                .unwrap()
                .get(&interface)
                .ok_or_else(|| {
                    LldpdError::Missing(format!(
                        "no such interface: {interface}"
                    ))
                })
                .map(|iface| {
                    let i = iface.lock().unwrap();
                    Interface {
                        port: interface.clone(),
                        iface: i.iface.clone(),
                        disabled: i.disabled,
                        system_info: (&interfaces::build_lldpdu(
                            &switchinfo,
                            &i,
                        ))
                            .into(),
                    }
                })?,
        ))
    }

    async fn interface_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<Interface>>, HttpError> {
        let global: &Global = rqctx.context();
        let switchinfo = global.switchinfo.lock().unwrap().clone();
        Ok(HttpResponseOk(
            global
                .interfaces
                .lock()
                .unwrap()
                .iter()
                .map(|(name, iface)| {
                    let i = iface.lock().unwrap();
                    Interface {
                        port: name.clone(),
                        iface: i.iface.clone(),
                        disabled: i.disabled,
                        system_info: (&interfaces::build_lldpdu(
                            &switchinfo,
                            &i,
                        ))
                            .into(),
                    }
                })
                .collect(),
        ))
    }

    async fn interface_set_disabled(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        let val = body.into_inner();
        interfaces::disabled_set(global, &inner.iface, val)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseUpdatedNoContent())
    }

    async fn interface_set_chassis_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        body: TypedBody<protocol::ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        let val = body.into_inner();
        interfaces::chassis_id_set(global, &inner.iface, val)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseUpdatedNoContent())
    }

    async fn interface_del_chassis_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        interfaces::chassis_id_del(global, &inner.iface)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseDeleted())
    }

    async fn interface_set_port_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        body: TypedBody<protocol::PortId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        let val = body.into_inner();
        interfaces::port_id_set(global, &inner.iface, val)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseUpdatedNoContent())
    }

    async fn interface_set_port_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        let val = body.into_inner();
        interfaces::port_desc_set(global, &inner.iface, &val)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseUpdatedNoContent())
    }

    async fn interface_del_port_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        interfaces::port_desc_del(global, &inner.iface)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseDeleted())
    }

    async fn interface_set_system_name(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        let val = body.into_inner();
        interfaces::system_name_set(global, &inner.iface, &val)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseUpdatedNoContent())
    }

    async fn interface_del_system_name(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        interfaces::system_name_del(global, &inner.iface)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseDeleted())
    }

    async fn interface_set_system_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        let val = body.into_inner();
        interfaces::system_desc_set(global, &inner.iface, &val)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseUpdatedNoContent())
    }

    async fn interface_del_system_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        interfaces::system_desc_del(global, &inner.iface)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseDeleted())
    }

    async fn interface_add_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(
            global.log,
            "set system_capability {:?} on {}", inner.capability, inner.iface
        );
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn interface_del_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(
            global.log,
            "clear system_capability {:?} on {}", inner.capability, inner.iface
        );
        Ok(HttpResponseDeleted())
    }

    async fn interface_enable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(
            global.log,
            "enable system_capability {:?} on {}",
            inner.capability,
            inner.iface
        );
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn interface_disable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        debug!(
            global.log,
            "clear system_capability {:?} on {}", inner.capability, inner.iface
        );
        Ok(HttpResponseDeleted())
    }

    async fn interface_add_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfaceAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        interfaces::addr_add(global, &inner.iface, &inner.address)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseUpdatedNoContent())
    }

    async fn interface_del_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfaceAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        interfaces::addr_delete(global, &inner.iface, &inner.address)
            .await
            .map(|_| HttpResponseDeleted())
            .map_err(HttpError::from)
    }

    async fn interface_clear_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let global: &Global = rqctx.context();
        let inner = path.into_inner();
        interfaces::addr_delete_all(global, &inner.iface)
            .await
            .map_err(|e| e.into())
            .map(|_| HttpResponseDeleted())
    }

    async fn get_neighbors(
        rqctx: RequestContext<Self::Context>,
        path: Path<InterfacePathParams>,
        query: Query<PaginationParams<EmptyScanParams, NeighborToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<Neighbor>>, HttpError> {
        let global: &Global = rqctx.context();
        let pag_params = query.into_inner();
        let iface = path.into_inner().iface;
        let max = rqctx.page_limit(&pag_params)?.get();

        let previous = match &pag_params.page {
            WhichPage::First(..) => None,
            WhichPage::Next(NeighborToken { id }) => Some(id.clone()),
        };

        let neighbors: Vec<Neighbor> =
            interfaces::get_neighbors(global, &iface, previous, max)
                .await
                .map_err(HttpError::from)
                .map(|neighbors| {
                    neighbors
                        .iter()
                        .map(|n| Neighbor {
                            port: iface.clone(),
                            id: n.id,
                            first_seen: n.first_seen,
                            last_seen: n.last_seen,
                            last_changed: n.last_changed,
                            system_info: (&n.lldpdu).into(),
                        })
                        .collect()
                })?;

        ResultsPage::new(neighbors, &EmptyScanParams {}, |n: &Neighbor, _| {
            NeighborToken {
                id: NeighborId {
                    chassis_id: n.system_info.chassis_id.clone(),
                    port_id: n.system_info.port_id.clone(),
                },
            }
        })
        .map(HttpResponseOk)
    }

    async fn build_info(
        _rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BuildInfo>, HttpError> {
        Ok(HttpResponseOk(build_info()))
    }
}

/// The API server manager is a task that is responsible for launching and
/// halting dropshot instances that serve the lldp API.  The set of instances
/// is governed by the "listen_addesses" vector in the Global structure.  The
/// initial set of addesses can come from the CLI or SMF, depending on how the
/// daemon is launched.  It can be updated as the daemon runs by refreshing the
/// daemon's SMF properties.  When that happens, this thread gets a message,
/// which causes it it compare the updated list of addresses with the list of
/// servers it is currently running.  The server population is adjusted as
/// needed to keep those lists in sync.
fn launch_server(
    global: Arc<Global>,
    addr: &SocketAddr,
    id: u32,
) -> anyhow::Result<ApiServer> {
    let config_dropshot = dropshot::ConfigDropshot {
        bind_address: *addr,
        default_request_body_max_bytes: 10240,
        default_handler_task_mode: dropshot::HandlerTaskMode::Detached,
        log_headers: Vec::new(),
    };

    dropshot::ServerBuilder::new(
        http_api(),
        global.clone(),
        global
            .log
            .new(o!("unit" => "api-server", "server_id" => id.to_string())),
    )
    .config(config_dropshot)
    .version_policy(VersionPolicy::Dynamic(Box::new(
        ClientSpecifiesVersionInHeader::new(
            omicron_common::api::VERSION_HEADER,
            lldpd_api::latest_version(),
        ),
    )))
    .build_starter()
    .map(|s| s.start())
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

// Manage the set of api servers currently listening for requests.  When a
// change is made to the service's smf settings, we will get a message on our
// smf_rx channel, which tells us to re-evaluate the set of api_server
// addresses.
pub async fn api_server_manager(
    global: Arc<Global>,
    mut smf_rx: tokio::sync::watch::Receiver<()>,
) {
    let mut active = HashMap::<SocketAddr, ApiServer>::new();
    let mut id = 0;
    let mut running = true;

    let log = global.log.new(o!("unit" => "api-server-manager"));
    while running {
        let active_addrs = active.keys().cloned().collect::<Vec<SocketAddr>>();
        let mut config_addrs = global.listen_addresses.lock().unwrap().to_vec();
        // We always listen on localhost
        config_addrs.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            lldpd_common::DEFAULT_LLDPD_PORT,
        ));
        // Get the list of all the addresses we should be listening on,
        // and compare it to the list we currently are listening on.
        let (add, remove) =
            lldpd_common::purge_common(&config_addrs, &active_addrs);

        for addr in remove {
            let hdl = active.remove(&addr).unwrap();
            info!(log, "closing api server on {addr}");
            if let Err(e) = hdl.close().await {
                error!(log, "error closing api server on {addr}: {e:?}");
            }
        }

        for addr in &add {
            // Increase the `id` to give each server a unique name
            id += 1;
            match launch_server(global.clone(), addr, id) {
                Ok(s) => {
                    active.insert(*addr, s);
                }
                Err(e) => {
                    error!(
                        log,
                        "failed to launch api server {id} on {addr}: {e:?}"
                    );
                }
            };
        }

        // When the tx side is dropped, the changed() below will return an
        // error, telling us that it is time to exit.
        running = smf_rx.changed().await.is_ok();
    }

    // Shut down all the active API servers
    for (addr, hdl) in active {
        info!(log, "closing api server on {addr}");
        if let Err(e) = hdl.close().await {
            error!(log, "error closing api server on {addr}: {e:?}");
        }
    }
}

pub fn http_api() -> dropshot::ApiDescription<Arc<Global>> {
    lldpd_api::lldpd_api_mod::api_description::<LldpdApiImpl>().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::api_server::build_info;

    use std::process::Command;

    #[test]
    fn test_build_info() {
        let info = build_info();
        println!("{info:#?}");
        let out = Command::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .unwrap();
        assert!(out.status.success());
        let ours = std::str::from_utf8(&out.stdout).unwrap().trim();
        assert_eq!(info.git_sha, ours);
    }
}
