// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2025 Oxide Computer Company

//! Re-exports the latest versions of each type.

pub mod build_info {
    pub use crate::v1::build_info::BuildInfo;
}

pub mod interfaces {
    pub use crate::v1::interfaces::Interface;
    pub use crate::v1::interfaces::InterfaceAdd;
    pub use crate::v1::interfaces::InterfaceAddressPathParams;
    pub use crate::v1::interfaces::InterfaceCapabilityPathParams;
    pub use crate::v1::interfaces::InterfacePathParams;
}

pub mod neighbor {
    pub use crate::v1::neighbor::Neighbor;
    pub use crate::v1::neighbor::NeighborId;
    pub use crate::v1::neighbor::NeighborToken;
}

pub mod system_info {
    pub use crate::v1::system_info::SystemAddressPathParams;
    pub use crate::v1::system_info::SystemCapabilityPathParams;
    pub use crate::v1::system_info::SystemInfo;
}
