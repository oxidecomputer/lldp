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
    pre_hook = (|log: &slog::Logger, request: &reqwest::Request| {
        slog::trace!(log, "client request";
            "method" => %request.method(),
            "uri" => %request.url(),
            "body" => ?&request.body(),
        );
    }),
    post_hook = (|log: &slog::Logger, result: &Result<_, _>| {
        slog::trace!(log, "client response"; "result" => ?result);
    }),
    derives = [PartialEq],
 replace = {
        ManagementAddress = protocol::types::ManagementAddress,
        NetworkAddress = protocol::types::NetworkAddress,
    }
);

impl fmt::Display for types::MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5]
        )
    }
}
