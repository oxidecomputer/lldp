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

use chrono::DateTime;
use chrono::Utc;
use dropshot::endpoint;
use dropshot::HttpError;
use dropshot::HttpResponseCreated;
use dropshot::HttpResponseDeleted;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use slog::debug;
use slog::error;
use slog::info;
use slog::o;

use crate::interfaces;
use crate::protocol;
use crate::types;
use crate::types::LldpdError;
use crate::Global;

type ApiServer = dropshot::HttpServer<Arc<Global>>;

/// Detailed build information about `lldpd`.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct BuildInfo {
    pub version: String,
    pub git_sha: String,
    pub git_commit_timestamp: String,
    pub git_branch: String,
    pub rustc_semver: String,
    pub rustc_channel: String,
    pub rustc_host_triple: String,
    pub rustc_commit_sha: String,
    pub cargo_triple: String,
    pub debug: bool,
    pub opt_level: u8,
}

impl Default for BuildInfo {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: env!("VERGEN_GIT_SHA").to_string(),
            git_commit_timestamp: env!("VERGEN_GIT_COMMIT_TIMESTAMP")
                .to_string(),
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
}

/// Set the default chassis ID advertised on all ports
#[endpoint {
	method = POST,
	path = "/system/chassis_id",
}]
async fn sys_set_chassis_id(
    rqctx: RequestContext<Arc<Global>>,
    body: TypedBody<protocol::ChassisId>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let val = body.into_inner();
    debug!(global.log, "set chassis_id = {:?}", val);
    Ok(HttpResponseUpdatedNoContent())
}

/// Set the default TTL advertised on all ports
#[endpoint {
	method = POST,
	path = "/system/ttl",
}]
async fn sys_set_ttl(
    rqctx: RequestContext<Arc<Global>>,
    body: TypedBody<u16>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let val = body.into_inner();
    debug!(global.log, "set ttl = {:?}", val);
    Ok(HttpResponseUpdatedNoContent())
}

/// Set the default system name advertised on all ports
#[endpoint {
	method = POST,
	path = "/system/system_name",
}]
async fn sys_set_system_name(
    rqctx: RequestContext<Arc<Global>>,
    body: TypedBody<String>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let val = body.into_inner();
    debug!(global.log, "set system_name = {:?}", val);
    Ok(HttpResponseUpdatedNoContent())
}

/// Delete default system name advertised on all ports.  A system name will
/// only be advertised on those interfaces with a locally set system name.
#[endpoint {
    method = DELETE,
    path = "/system/system_name",
}]
async fn sys_del_system_name(
    rqctx: RequestContext<Arc<Global>>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    debug!(global.log, "delete system_name");
    Ok(HttpResponseDeleted())
}

/// Set the default system description advertised on all interfaces
#[endpoint {
	method = POST,
	path = "/system/system_description",
}]
async fn sys_set_system_description(
    rqctx: RequestContext<Arc<Global>>,
    body: TypedBody<String>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let val = body.into_inner();
    debug!(global.log, "set system_description = {:?}", val);
    Ok(HttpResponseUpdatedNoContent())
}

/// Delete default system description advertised on all interfaces.  A system name will
/// only be advertised on those interfaces with a locally set system description.
#[endpoint {
    method = DELETE,
    path = "/system/system_description",
}]
async fn sys_del_system_description(
    rqctx: RequestContext<Arc<Global>>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    debug!(global.log, "delete system_description");
    Ok(HttpResponseDeleted())
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct SystemCapabilityPathParams {
    capability: protocol::SystemCapabilities,
}

/// Add a capability to the set of those advertised on all interfaces
#[endpoint {
	method = POST,
	path = "/system/system_capability/{capability}",
}]
async fn sys_add_system_capability(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<SystemCapabilityPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    debug!(global.log, "set system_capability {:?}", inner.capability);
    Ok(HttpResponseUpdatedNoContent())
}

/// Remove a capability from the set of those advertised on all interfaces
#[endpoint {
	method = DELETE,
	path = "/system/system_capability/{capability}",
}]
async fn sys_del_system_capability(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<SystemCapabilityPathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    debug!(global.log, "clear system_capability {:?}", inner.capability);
    Ok(HttpResponseDeleted())
}

/// Add a capability to the set of those advertised as enabled on all interfaces
#[endpoint {
	method = POST,
	path = "/system/enabled_capability/{capability}",
}]
async fn sys_enable_system_capability(
    rqctx: RequestContext<Arc<Global>>,
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

/// Remove a capability from the set of those advertised as enabled on all interfaces
#[endpoint {
	method = DELETE,
	path = "/system/enabled_capability/{capability}",
}]
async fn sys_disable_system_capability(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<SystemCapabilityPathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    debug!(global.log, "clear system_capability {:?}", inner.capability);
    Ok(HttpResponseDeleted())
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct SystemAddressPathParams {
    address: IpAddr,
}

/// Add a management address to the set of those advertised on all interfaces
#[endpoint {
	method = POST,
	path = "/system/management_address/{address}",
}]
async fn sys_add_management_addr(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<SystemAddressPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    debug!(global.log, "add management address {}", inner.address);
    Ok(HttpResponseUpdatedNoContent())
}

/// Remove a management address from the set of those advertised on all interfaces
#[endpoint {
	method = DELETE,
	path = "/system/management_address/{address}",
}]
async fn sys_del_management_addr(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<SystemAddressPathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    debug!(global.log, "remove management address {}", inner.address);
    Ok(HttpResponseDeleted())
}

/// Remove all management addresses from the set of those advertised on all
/// interfaces
#[endpoint {
	method = DELETE,
	path = "/system/management_address",
}]
async fn sys_clear_management_addr(
    rqctx: RequestContext<Arc<Global>>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    debug!(global.log, "clear all management addresses");
    Ok(HttpResponseDeleted())
}

/// A local interface on which we are listening for, and dispatching, LLDPDUs
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Interface {
    pub port: String,
    pub iface: String,
    pub system_info: types::SystemInfo,
}

/// Optional arguments when adding an interface to LLDPD.  Any argument left
/// unspecified will be assigned the default values for this system.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct InterfaceAdd {
    pub chassis_id: Option<protocol::ChassisId>,
    pub port_id: Option<protocol::PortId>,
    pub ttl: Option<u16>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct InterfacePathParams {
    /// The switch port on which to operate.
    iface: String,
}

#[endpoint {
    method = PUT,
    path = "/interface/{iface}",
}]
async fn interface_add(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
    params: TypedBody<InterfaceAdd>,
) -> Result<HttpResponseCreated<()>, HttpError> {
    let global: &Arc<Global> = rqctx.context();
    let interface = path.into_inner().iface;
    let params = params.into_inner();
    crate::interfaces::interface_add(
        global,
        interface,
        params.chassis_id,
        params.port_id,
        params.ttl,
        params.system_name,
        params.system_description,
        params.port_description,
    )
    .await
    .map(HttpResponseCreated)
    .map_err(|e| e.into())
}

#[endpoint {
    method = DELETE,
    path = "/interface/{iface}",
}]
async fn interface_del(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let interface = path.into_inner().iface;
    debug!(global.log, "deleted  {interface}");
    Ok(HttpResponseDeleted())
}

#[endpoint {
    method = GET,
    path = "/interface/{iface}",
}]
async fn interface_get(
    rqctx: RequestContext<Arc<Global>>,
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
                LldpdError::Missing(format!("no such interface: {interface}"))
            })
            .map(|iface| {
                let i = iface.lock().unwrap();
                Interface {
                    port: interface.clone(),
                    iface: i.iface.clone(),
                    system_info: (&interfaces::build_lldpdu(&switchinfo, &i))
                        .into(),
                }
            })?,
    ))
}

#[endpoint {
    method = GET,
    path = "/interface",
}]
async fn interface_list(
    rqctx: RequestContext<Arc<Global>>,
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
                    system_info: (&interfaces::build_lldpdu(&switchinfo, &i))
                        .into(),
                }
            })
            .collect(),
    ))
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/chassis_id",
}]
async fn interface_set_chassis_id(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
    body: TypedBody<protocol::ChassisId>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    let val = body.into_inner();
    interfaces::chassis_id_set(global, &inner.iface, val)
        .map_err(|e| e.into())
        .map(|_| HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = DELETE,
    path = "/interface/{iface}/chassis_id",
}]
async fn interface_del_chassis_id(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::chassis_id_del(global, &inner.iface)
        .map_err(|e| e.into())
        .map(|_| HttpResponseDeleted())
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/port_id",
}]
async fn interface_set_port_id(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
    body: TypedBody<protocol::PortId>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    let val = body.into_inner();
    interfaces::port_id_set(global, &inner.iface, val)
        .map_err(|e| e.into())
        .map(|_| HttpResponseUpdatedNoContent())
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/ttl",
}]
async fn interface_set_ttl(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
    body: TypedBody<u16>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    let val = body.into_inner();
    interfaces::ttl_set(global, &inner.iface, val)
        .map_err(|e| e.into())
        .map(|_| HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = DELETE,
    path = "/interface/{iface}/ttl",
}]
async fn interface_del_ttl(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::ttl_del(global, &inner.iface)
        .map_err(|e| e.into())
        .map(|_| HttpResponseDeleted())
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/port_description",
}]
async fn interface_set_port_description(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
    body: TypedBody<String>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    let val = body.into_inner();
    interfaces::port_desc_set(global, &inner.iface, &val)
        .map_err(|e| e.into())
        .map(|_| HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = DELETE,
    path = "/interface/{iface}/port_description",
}]
async fn interface_del_port_description(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::port_desc_del(global, &inner.iface)
        .map_err(|e| e.into())
        .map(|_| HttpResponseDeleted())
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/system_name",
}]
async fn interface_set_system_name(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
    body: TypedBody<String>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    let val = body.into_inner();
    interfaces::system_name_set(global, &inner.iface, &val)
        .map_err(|e| e.into())
        .map(|_| HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = DELETE,
    path = "/interface/{iface}/system_name",
}]
async fn interface_del_system_name(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::system_name_del(global, &inner.iface)
        .map_err(|e| e.into())
        .map(|_| HttpResponseDeleted())
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/system_description",
}]
async fn interface_set_system_description(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
    body: TypedBody<String>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    let val = body.into_inner();
    interfaces::system_desc_set(global, &inner.iface, &val)
        .map_err(|e| e.into())
        .map(|_| HttpResponseUpdatedNoContent())
}

#[endpoint {
    method = DELETE,
    path = "/interface/{iface}/system_description",
}]
async fn interface_del_system_description(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::system_desc_del(global, &inner.iface)
        .map_err(|e| e.into())
        .map(|_| HttpResponseDeleted())
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct InterfaceCapabilityPathParams {
    /// The switch port on which to operate.
    iface: String,
    capability: protocol::SystemCapabilities,
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/system_capability/{capability}",
}]
async fn interface_add_system_capability(
    rqctx: RequestContext<Arc<Global>>,
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

#[endpoint {
	method = DELETE,
	path = "/interface/{iface}/system_capability/{capability}",
}]
async fn interface_del_system_capability(
    rqctx: RequestContext<Arc<Global>>,
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

#[endpoint {
	method = POST,
	path = "/interface/{iface}/enabled_capability/{capability}",
}]
async fn interface_enable_system_capability(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfaceCapabilityPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    debug!(
        global.log,
        "enable system_capability {:?} on {}", inner.capability, inner.iface
    );
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint {
	method = DELETE,
	path = "/interface/{iface}/enabled_capability/{capability}",
}]
async fn interface_disable_system_capability(
    rqctx: RequestContext<Arc<Global>>,
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

#[derive(Deserialize, Serialize, JsonSchema)]
struct InterfaceAddressPathParams {
    /// The switch port on which to operate.
    iface: String,
    /// Management Address to advertise on this port
    // TODO-completeness: this should allow non-IP addresses to be specified (as
    // per the standard) and should include an optional interface number.
    address: IpAddr,
}

#[endpoint {
	method = POST,
	path = "/interface/{iface}/management_address/{address}",
}]
async fn interface_add_management_addr(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfaceAddressPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::addr_add(global, &inner.iface, &inner.address)
        .map_err(|e| e.into())
        .map(|_| HttpResponseUpdatedNoContent())
}

#[endpoint {
	method = DELETE,
	path = "/interface/{iface}/management_address/{address}",
}]
async fn interface_del_management_addr(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfaceAddressPathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::addr_delete(global, &inner.iface, &inner.address)
        .map_err(|e| e.into())
        .map(|_| HttpResponseDeleted())
}

#[endpoint {
	method = DELETE,
	path = "/interface/{iface}/management_address",
}]
async fn interface_clear_management_addr(
    rqctx: RequestContext<Arc<Global>>,
    path: Path<InterfacePathParams>,
) -> Result<HttpResponseDeleted, HttpError> {
    let global: &Global = rqctx.context();
    let inner = path.into_inner();
    interfaces::addr_delete_all(global, &inner.iface)
        .map_err(|e| e.into())
        .map(|_| HttpResponseDeleted())
}

/// A remote system that has been discovered on one of our configured interfaces
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Neighbor {
    pub port: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_changed: DateTime<Utc>,
    pub system_info: types::SystemInfo,
}
/// Return a list of the active neighbors
#[endpoint {
    method = GET,
    path = "/neighbors",
}]
async fn get_neighbors(
    rqctx: RequestContext<Arc<Global>>,
) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError> {
    let global: &Global = rqctx.context();
    let n = global.neighbors.lock().unwrap();
    Ok(HttpResponseOk(
        n.values()
            .map(|n| Neighbor {
                port: n.interface.clone(),
                first_seen: n.first_seen,
                last_seen: n.last_seen,
                last_changed: n.last_changed,
                system_info: (&n.lldpdu).into(),
            })
            .collect(),
    ))
}

/// Return detailed build information about the `dpd` server itself.
#[endpoint {
    method = GET,
    path = "/build-info",
}]
async fn build_info(
    _rqctx: RequestContext<Arc<Global>>,
) -> Result<HttpResponseOk<BuildInfo>, HttpError> {
    Ok(HttpResponseOk(BuildInfo::default()))
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
        request_body_max_bytes: 10240,
        default_handler_task_mode: dropshot::HandlerTaskMode::Detached,
    };
    let log = global
        .log
        .new(o!("unit" => "api-server", "server_id" => id.to_string()));

    slog::info!(log, "starting api server {id} on {addr}");
    dropshot::HttpServerStarter::new(
        &config_dropshot,
        http_api(),
        global.clone(),
        &log,
    )
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
            common::DEFAULT_LLDPD_PORT,
        ));
        // Get the list of all the addresses we should be listening on,
        // and compare it to the list we currently are listening on.
        let (add, remove) = common::purge_common(&config_addrs, &active_addrs);

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

#[cfg(test)]
mod tests {
    use super::BuildInfo;
    use std::process::Command;

    #[test]
    fn test_build_info() {
        let info = BuildInfo::default();
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

pub fn http_api() -> dropshot::ApiDescription<Arc<Global>> {
    let mut api = dropshot::ApiDescription::new();

    api.register(build_info).unwrap();
    api.register(sys_set_chassis_id).unwrap();
    api.register(sys_set_ttl).unwrap();
    api.register(sys_set_system_name).unwrap();
    api.register(sys_del_system_name).unwrap();
    api.register(sys_set_system_description).unwrap();
    api.register(sys_del_system_description).unwrap();
    api.register(sys_add_system_capability).unwrap();
    api.register(sys_del_system_capability).unwrap();
    api.register(sys_enable_system_capability).unwrap();
    api.register(sys_disable_system_capability).unwrap();
    api.register(sys_add_management_addr).unwrap();
    api.register(sys_del_management_addr).unwrap();
    api.register(sys_clear_management_addr).unwrap();
    //api.register(sys_add_org_specific).unwrap();
    //api.register(sys_del_org_specific).unwrap();
    api.register(interface_add).unwrap();
    api.register(interface_del).unwrap();
    api.register(interface_list).unwrap();
    api.register(interface_get).unwrap();
    api.register(interface_set_chassis_id).unwrap();
    api.register(interface_del_chassis_id).unwrap();
    api.register(interface_set_port_id).unwrap();
    api.register(interface_del_ttl).unwrap();
    api.register(interface_set_ttl).unwrap();
    api.register(interface_set_port_description).unwrap();
    api.register(interface_del_port_description).unwrap();
    api.register(interface_set_system_name).unwrap();
    api.register(interface_del_system_name).unwrap();
    api.register(interface_set_system_description).unwrap();
    api.register(interface_del_system_description).unwrap();
    api.register(interface_add_system_capability).unwrap();
    api.register(interface_del_system_capability).unwrap();
    api.register(interface_enable_system_capability).unwrap();
    api.register(interface_disable_system_capability).unwrap();
    api.register(interface_add_management_addr).unwrap();
    api.register(interface_del_management_addr).unwrap();
    api.register(interface_clear_management_addr).unwrap();
    //api.register(interface_add_org_specific).unwrap();
    //api.register(interface_del_org_specific).unwrap();
    api.register(get_neighbors).unwrap();

    api
}
