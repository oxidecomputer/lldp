// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Oxide Computer Company

//! Re-exports the latest versions of each type.

pub mod build_info {
    pub use crate::v1::build_info::BuildInfo;
}

pub mod interfaces {
    pub use crate::v1::interfaces::InterfaceAddressPathParams;
    pub use crate::v1::interfaces::InterfacePathParams;

    pub use crate::v3::interfaces::Interface;
    pub use crate::v3::interfaces::InterfaceAdd;
    pub use crate::v3::interfaces::InterfaceCapabilityPathParams;
}

pub mod neighbor {
    pub use crate::v1::neighbor::NeighborId;
    pub use crate::v1::neighbor::NeighborToken;

    pub use crate::v3::neighbor::Neighbor;
}

pub mod switch {
    pub use crate::v2::switch::SwitchIdentifiers;
}

pub mod system_info {
    pub use crate::v1::system_info::SystemAddressPathParams;

    pub use crate::v3::system_info::ChassisId;
    pub use crate::v3::system_info::ManagementAddress;
    pub use crate::v3::system_info::NetworkAddress;
    pub use crate::v3::system_info::PortId;
    pub use crate::v3::system_info::SystemCapabilities;
    pub use crate::v3::system_info::SystemCapabilityPathParams;
    pub use crate::v3::system_info::SystemInfo;
}
