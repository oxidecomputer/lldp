// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

use dropshot::{
    EmptyScanParams, HttpError, HttpResponseCreated, HttpResponseDeleted,
    HttpResponseOk, HttpResponseUpdatedNoContent, PaginationParams, Path,
    Query, RequestContext, ResultsPage, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use lldpd_types_versions::latest;
use protocol::types::{ChassisId, PortId};

api_versions!([
    // WHEN CHANGING THE API (part 1 of 2):
    //
    // +- Pick a new semver and define it in the list below.  The list MUST
    // |  remain sorted, which generally means that your version should go at
    // |  the very top.
    // |
    // |  Duplicate this line, uncomment the *second* copy, update that copy for
    // |  your new API version, and leave the first copy commented out as an
    // |  example for the next person.
    // v
    // (next_int, IDENT),
    (1, INITIAL),
]);

// WHEN CHANGING THE API (part 2 of 2):
//
// The call to `api_versions!` above defines constants of type
// `semver::Version` that you can use in your Dropshot API definition to specify
// the version when a particular endpoint was added or removed.  For example, if
// you used:
//
//     (2, ADD_FOOBAR)
//
// Then you could use `VERSION_ADD_FOOBAR` as the version in which endpoints
// were added or removed.

#[dropshot::api_description]
pub trait LldpdApi {
    type Context;

    /// Set the default chassis ID advertised on all ports
    #[endpoint {
    	method = POST,
    	path = "/system/chassis_id",
    }]
    async fn sys_set_chassis_id(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Set the default system name advertised on all ports
    #[endpoint {
    	method = POST,
    	path = "/system/system_name",
    }]
    async fn sys_set_system_name(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Delete default system name advertised on all ports.  A system name will
    /// only be advertised on those interfaces with a locally set system name.
    #[endpoint {
        method = DELETE,
        path = "/system/system_name",
    }]
    async fn sys_del_system_name(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Set the default system description advertised on all interfaces
    #[endpoint {
    	method = POST,
    	path = "/system/system_description",
    }]
    async fn sys_set_system_description(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Delete default system description advertised on all interfaces.  A system name will
    /// only be advertised on those interfaces with a locally set system description.
    #[endpoint {
        method = DELETE,
        path = "/system/system_description",
    }]
    async fn sys_del_system_description(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Add a capability to the set of those advertised on all interfaces
    #[endpoint {
    	method = POST,
    	path = "/system/system_capability/{capability}",
    }]
    async fn sys_add_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove a capability from the set of those advertised on all interfaces
    #[endpoint {
    	method = DELETE,
    	path = "/system/system_capability/{capability}",
    }]
    async fn sys_del_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Add a capability to the set of those advertised as enabled on all interfaces
    #[endpoint {
    	method = POST,
    	path = "/system/enabled_capability/{capability}",
    }]
    async fn sys_enable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove a capability from the set of those advertised as enabled on all interfaces
    #[endpoint {
    	method = DELETE,
    	path = "/system/enabled_capability/{capability}",
    }]
    async fn sys_disable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Add a management address to the set of those advertised on all interfaces
    #[endpoint {
    	method = POST,
    	path = "/system/management_address/{address}",
    }]
    async fn sys_add_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove a management address from the set of those advertised on all interfaces
    #[endpoint {
    	method = DELETE,
    	path = "/system/management_address/{address}",
    }]
    async fn sys_del_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Remove all management addresses from the set of those advertised on all
    /// interfaces
    #[endpoint {
    	method = DELETE,
    	path = "/system/management_address",
    }]
    async fn sys_clear_management_addr(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/interface/{iface}",
    }]
    async fn interface_add(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        params: TypedBody<latest::interfaces::InterfaceAdd>,
    ) -> Result<HttpResponseCreated<()>, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}",
    }]
    async fn interface_del(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = GET,
        path = "/interface/{iface}",
    }]
    async fn interface_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseOk<latest::interfaces::Interface>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/interface",
    }]
    async fn interface_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::interfaces::Interface>>, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/disabled",
    }]
    async fn interface_set_disabled(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/chassis_id",
    }]
    async fn interface_set_chassis_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/chassis_id",
    }]
    async fn interface_del_chassis_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/port_id",
    }]
    async fn interface_set_port_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<PortId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/port_description",
    }]
    async fn interface_set_port_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/port_description",
    }]
    async fn interface_del_port_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/system_name",
    }]
    async fn interface_set_system_name(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/system_name",
    }]
    async fn interface_del_system_name(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/system_description",
    }]
    async fn interface_set_system_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;
    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/system_description",
    }]
    async fn interface_del_system_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/system_capability/{capability}",
    }]
    async fn interface_add_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
    	method = DELETE,
    	path = "/interface/{iface}/system_capability/{capability}",
    }]
    async fn interface_del_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/enabled_capability/{capability}",
    }]
    async fn interface_enable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
    	method = DELETE,
    	path = "/interface/{iface}/enabled_capability/{capability}",
    }]
    async fn interface_disable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
    	method = POST,
    	path = "/interface/{iface}/management_address/{address}",
    }]
    async fn interface_add_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
    	method = DELETE,
    	path = "/interface/{iface}/management_address/{address}",
    }]
    async fn interface_del_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
    	method = DELETE,
    	path = "/interface/{iface}/management_address",
    }]
    async fn interface_clear_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Return a list of the active neighbors
    #[endpoint {
        method = GET,
        path = "/interface/{iface}/neighbors",
    }]
    async fn get_neighbors(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        query: Query<
            PaginationParams<EmptyScanParams, latest::neighbor::NeighborToken>,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<latest::neighbor::Neighbor>>,
        HttpError,
    >;

    /// Return detailed build information about the `dpd` server itself.
    #[endpoint {
        method = GET,
        path = "/build-info",
    }]
    async fn build_info(
        _rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::build_info::BuildInfo>, HttpError>;
}
