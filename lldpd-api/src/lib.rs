// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Oxide Computer Company

use dropshot::{
    EmptyScanParams, HttpError, HttpResponseCreated, HttpResponseDeleted,
    HttpResponseOk, HttpResponseUpdatedNoContent, PaginationParams, Path,
    Query, RequestContext, ResultsPage, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use lldpd_types_versions::{latest, v1};

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
    (3, OPENAPI_LINT),
    (2, SWITCH_IDENTIFIERS),
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
        path = "/system/chassis-id",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_set_chassis_id(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<latest::system_info::ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Set the default chassis ID advertised on all ports
    #[endpoint {
        operation_id = "sys_set_chassis_id",
        method = POST,
        path = "/system/chassis_id",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_set_chassis_id_v1(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<protocol::types::ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::sys_set_chassis_id(
            rqctx,
            body.map(latest::system_info::ChassisId::from),
        )
        .await
    }

    /// Set the default system name advertised on all ports
    #[endpoint {
        method = POST,
        path = "/system/system-name",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_set_system_name(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Set the default system name advertised on all ports
    #[endpoint {
        operation_id = "sys_set_system_name",
        method = POST,
        path = "/system/system_name",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_set_system_name_v1(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::sys_set_system_name(rqctx, body).await
    }

    /// Delete default system name advertised on all ports.  A system name will
    /// only be advertised on those interfaces with a locally set system name.
    #[endpoint {
        method = DELETE,
        path = "/system/system-name",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_del_system_name(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Delete default system name advertised on all ports.  A system name will
    /// only be advertised on those interfaces with a locally set system name.
    #[endpoint {
        operation_id = "sys_del_system_name",
        method = DELETE,
        path = "/system/system_name",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_del_system_name_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::sys_del_system_name(rqctx).await
    }

    /// Set the default system description advertised on all interfaces
    #[endpoint {
        method = POST,
        path = "/system/system-description",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_set_system_description(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Set the default system description advertised on all interfaces
    #[endpoint {
        operation_id = "sys_set_system_description",
        method = POST,
        path = "/system/system_description",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_set_system_description_v1(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::sys_set_system_description(rqctx, body).await
    }

    /// Delete default system description advertised on all interfaces.  A system name will
    /// only be advertised on those interfaces with a locally set system description.
    #[endpoint {
        method = DELETE,
        path = "/system/system-description",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_del_system_description(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Delete default system description advertised on all interfaces.  A system name will
    /// only be advertised on those interfaces with a locally set system description.
    #[endpoint {
        operation_id = "sys_del_system_description",
        method = DELETE,
        path = "/system/system_description",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_del_system_description_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::sys_del_system_description(rqctx).await
    }

    /// Add a capability to the set of those advertised on all interfaces
    #[endpoint {
        method = POST,
        path = "/system/system-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_add_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Add a capability to the set of those advertised on all interfaces
    #[endpoint {
        operation_id = "sys_add_system_capability",
        method = POST,
        path = "/system/system_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_add_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::sys_add_system_capability(
            rqctx,
            path.map(latest::system_info::SystemCapabilityPathParams::from),
        )
        .await
    }

    /// Remove a capability from the set of those advertised on all interfaces
    #[endpoint {
        method = DELETE,
        path = "/system/system-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_del_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Remove a capability from the set of those advertised on all interfaces
    #[endpoint {
        operation_id = "sys_del_system_capability",
        method = DELETE,
        path = "/system/system_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_del_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::sys_del_system_capability(
            rqctx,
            path.map(latest::system_info::SystemCapabilityPathParams::from),
        )
        .await
    }

    /// Add a capability to the set of those advertised as enabled on all interfaces
    #[endpoint {
        method = POST,
        path = "/system/enabled-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_enable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Add a capability to the set of those advertised as enabled on all interfaces
    #[endpoint {
        operation_id = "sys_enable_system_capability",
        method = POST,
        path = "/system/enabled_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_enable_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::sys_enable_system_capability(
            rqctx,
            path.map(latest::system_info::SystemCapabilityPathParams::from),
        )
        .await
    }

    /// Remove a capability from the set of those advertised as enabled on all interfaces
    #[endpoint {
        method = DELETE,
        path = "/system/enabled-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_disable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Remove a capability from the set of those advertised as enabled on all interfaces
    #[endpoint {
        operation_id = "sys_disable_system_capability",
        method = DELETE,
        path = "/system/enabled_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_disable_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::system_info::SystemCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::sys_disable_system_capability(
            rqctx,
            path.map(latest::system_info::SystemCapabilityPathParams::from),
        )
        .await
    }

    /// Add a management address to the set of those advertised on all interfaces
    #[endpoint {
        method = POST,
        path = "/system/management-address/{address}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_add_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Add a management address to the set of those advertised on all interfaces
    #[endpoint {
        operation_id = "sys_add_management_addr",
        method = POST,
        path = "/system/management_address/{address}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_add_management_addr_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::system_info::SystemAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::sys_add_management_addr(rqctx, path).await
    }

    /// Remove a management address from the set of those advertised on all interfaces
    #[endpoint {
        method = DELETE,
        path = "/system/management-address/{address}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_del_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::system_info::SystemAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Remove a management address from the set of those advertised on all interfaces
    #[endpoint {
        operation_id = "sys_del_management_addr",
        method = DELETE,
        path = "/system/management_address/{address}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_del_management_addr_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::system_info::SystemAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::sys_del_management_addr(rqctx, path).await
    }

    /// Remove all management addresses from the set of those advertised on all
    /// interfaces
    #[endpoint {
        method = DELETE,
        path = "/system/management-address",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn sys_clear_management_addr(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Remove all management addresses from the set of those advertised on all
    /// interfaces
    #[endpoint {
        operation_id = "sys_clear_management_addr",
        method = DELETE,
        path = "/system/management_address",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn sys_clear_management_addr_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::sys_clear_management_addr(rqctx).await
    }

    #[endpoint {
        method = PUT,
        path = "/interface/{iface}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_add(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        params: TypedBody<latest::interfaces::InterfaceAdd>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_add",
        method = PUT,
        path = "/interface/{iface}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_add_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
        params: TypedBody<v1::interfaces::InterfaceAdd>,
    ) -> Result<HttpResponseCreated<()>, HttpError> {
        let HttpResponseUpdatedNoContent() = Self::interface_add(
            rqctx,
            path,
            params.map(latest::interfaces::InterfaceAdd::from),
        )
        .await?;
        Ok(HttpResponseCreated(()))
    }

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
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseOk<latest::interfaces::Interface>, HttpError>;

    #[endpoint {
        operation_id = "interface_get",
        method = GET,
        path = "/interface/{iface}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_get_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseOk<v1::interfaces::Interface>, HttpError> {
        Ok(Self::interface_get(rqctx, path)
            .await?
            .map(v1::interfaces::Interface::from))
    }

    #[endpoint {
        method = GET,
        path = "/interface",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::interfaces::Interface>>, HttpError>;

    #[endpoint {
        operation_id = "interface_list",
        method = GET,
        path = "/interface",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_list_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<v1::interfaces::Interface>>, HttpError> {
        Ok(Self::interface_list(rqctx).await?.map(|interfaces| {
            interfaces
                .into_iter()
                .map(v1::interfaces::Interface::from)
                .collect()
        }))
    }

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
        path = "/interface/{iface}/chassis-id",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_set_chassis_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<latest::system_info::ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_set_chassis_id",
        method = POST,
        path = "/interface/{iface}/chassis_id",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_set_chassis_id_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
        body: TypedBody<protocol::types::ChassisId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_set_chassis_id(
            rqctx,
            path,
            body.map(latest::system_info::ChassisId::from),
        )
        .await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/chassis-id",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_del_chassis_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_del_chassis_id",
        method = DELETE,
        path = "/interface/{iface}/chassis_id",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_del_chassis_id_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_del_chassis_id(rqctx, path).await
    }

    #[endpoint {
        method = POST,
        path = "/interface/{iface}/port-id",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_set_port_id(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<latest::system_info::PortId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_set_port_id",
        method = POST,
        path = "/interface/{iface}/port_id",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_set_port_id_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
        body: TypedBody<protocol::types::PortId>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_set_port_id(
            rqctx,
            path,
            body.map(latest::system_info::PortId::from),
        )
        .await
    }

    #[endpoint {
        method = POST,
        path = "/interface/{iface}/port-description",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_set_port_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_set_port_description",
        method = POST,
        path = "/interface/{iface}/port_description",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_set_port_description_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_set_port_description(rqctx, path, body).await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/port-description",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_del_port_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_del_port_description",
        method = DELETE,
        path = "/interface/{iface}/port_description",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_del_port_description_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_del_port_description(rqctx, path).await
    }

    #[endpoint {
        method = POST,
        path = "/interface/{iface}/system-name",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_set_system_name(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_set_system_name",
        method = POST,
        path = "/interface/{iface}/system_name",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_set_system_name_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_set_system_name(rqctx, path, body).await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/system-name",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_del_system_name(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_del_system_name",
        method = DELETE,
        path = "/interface/{iface}/system_name",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_del_system_name_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_del_system_name(rqctx, path).await
    }

    #[endpoint {
        method = POST,
        path = "/interface/{iface}/system-description",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_set_system_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_set_system_description",
        method = POST,
        path = "/interface/{iface}/system_description",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_set_system_description_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
        body: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_set_system_description(rqctx, path, body).await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/system-description",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_del_system_description(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_del_system_description",
        method = DELETE,
        path = "/interface/{iface}/system_description",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_del_system_description_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_del_system_description(rqctx, path).await
    }

    #[endpoint {
        method = POST,
        path = "/interface/{iface}/system-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_add_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_add_system_capability",
        method = POST,
        path = "/interface/{iface}/system_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_add_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_add_system_capability(
            rqctx,
            path.map(latest::interfaces::InterfaceCapabilityPathParams::from),
        )
        .await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/system-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_del_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_del_system_capability",
        method = DELETE,
        path = "/interface/{iface}/system_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_del_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_del_system_capability(
            rqctx,
            path.map(latest::interfaces::InterfaceCapabilityPathParams::from),
        )
        .await
    }

    #[endpoint {
        method = POST,
        path = "/interface/{iface}/enabled-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_enable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_enable_system_capability",
        method = POST,
        path = "/interface/{iface}/enabled_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_enable_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_enable_system_capability(
            rqctx,
            path.map(latest::interfaces::InterfaceCapabilityPathParams::from),
        )
        .await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/enabled-capability/{capability}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_disable_system_capability(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_disable_system_capability",
        method = DELETE,
        path = "/interface/{iface}/enabled_capability/{capability}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_disable_system_capability_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfaceCapabilityPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_disable_system_capability(
            rqctx,
            path.map(latest::interfaces::InterfaceCapabilityPathParams::from),
        )
        .await
    }

    #[endpoint {
        method = POST,
        path = "/interface/{iface}/management-address/{address}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_add_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "interface_add_management_addr",
        method = POST,
        path = "/interface/{iface}/management_address/{address}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_add_management_addr_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfaceAddressPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::interface_add_management_addr(rqctx, path).await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/management-address/{address}",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_del_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfaceAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_del_management_addr",
        method = DELETE,
        path = "/interface/{iface}/management_address/{address}",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_del_management_addr_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfaceAddressPathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_del_management_addr(rqctx, path).await
    }

    #[endpoint {
        method = DELETE,
        path = "/interface/{iface}/management-address",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn interface_clear_management_addr(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        operation_id = "interface_clear_management_addr",
        method = DELETE,
        path = "/interface/{iface}/management_address",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn interface_clear_management_addr_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::interface_clear_management_addr(rqctx, path).await
    }

    /// Return a list of the active neighbors
    #[endpoint {
        method = GET,
        path = "/interface/{iface}/neighbors",
        versions = VERSION_OPENAPI_LINT..,
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

    /// Return a list of the active neighbors
    #[endpoint {
        operation_id = "get_neighbors",
        method = GET,
        path = "/interface/{iface}/neighbors",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn get_neighbors_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::interfaces::InterfacePathParams>,
        query: Query<
            PaginationParams<EmptyScanParams, v1::neighbor::NeighborToken>,
        >,
    ) -> Result<HttpResponseOk<ResultsPage<v1::neighbor::Neighbor>>, HttpError>
    {
        Ok(Self::get_neighbors(rqctx, path, query).await?.map(|page| {
            ResultsPage {
                next_page: page.next_page,
                items: page
                    .items
                    .into_iter()
                    .map(v1::neighbor::Neighbor::from)
                    .collect(),
            }
        }))
    }

    /// Return detailed build information about the `dpd` server itself.
    #[endpoint {
        method = GET,
        path = "/build-info",
    }]
    async fn build_info(
        _rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::build_info::BuildInfo>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/switch/identifiers",
        versions = VERSION_SWITCH_IDENTIFIERS..,
    }]
    async fn switch_identifiers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::switch::SwitchIdentifiers>, HttpError>;
}
