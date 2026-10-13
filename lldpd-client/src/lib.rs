// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Client library for the LLDP daemon.

use std::fmt;

/// Return the default port on which the `lldpd` API server listens for clients.
pub const fn default_port() -> u16 {
    ::lldpd_common::DEFAULT_LLDPD_PORT
}

// Automatically generate the client bindings using Progenitor.
progenitor::generate_api!(
    spec = "../openapi/lldpd/lldpd-latest.json",
    interface = Positional,
    inner_type = slog::Logger,
    hooks = Expected,
    derives = [PartialEq],
 replace = {
        ManagementAddress = protocol::types::ManagementAddress,
        NetworkAddress = protocol::types::NetworkAddress,
    }
);

progenitor_extras::slog_hooks::impl_slog_client_hooks!(Client);

impl fmt::Display for types::MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5]
        )
    }
}
