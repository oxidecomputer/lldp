// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Client library for the Dendrite data plane daemon.

use slog::Logger;

pub const DEFAULT_PORT: u16 = 12224;

/// State maintained by a [`Client`].
#[derive(Clone, Debug)]
pub struct ClientState {
    /// An arbitrary tag used to identify a client, for controlling things like
    /// per-client settings.
    pub tag: String,
    /// Used for logging requests and responses.
    pub log: Logger,
}

// Automatically generate the client bindings using Progenitor.
#[cfg(feature = "dendrite")]
progenitor::generate_api!(
    spec = "../openapi/dpd.json",
    interface = Positional,
    inner_type = crate::ClientState,
    pre_hook = (|state: &crate::ClientState, request: &reqwest::Request| {
        slog::trace!(state.log, "client request";
            "method" => %request.method(),
            "uri" => %request.url(),
            "body" => ?&request.body(),
        );
    }),
    post_hook = (|state: &crate::ClientState, result: &Result<_, _>| {
        slog::trace!(state.log, "client response"; "result" => ?result);
    }),
    derives = [PartialEq],
    replace = {
        PortId = common::ports::PortId ,
        MacAddr = common::MacAddr
    }
);
