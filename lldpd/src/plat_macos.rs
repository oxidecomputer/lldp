// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

// macOS platform stubs for lldpd.  Packet capture and injection are not
// implemented; the Transport is a no-op that never delivers or sends frames.
// MAC address discovery uses `ifconfig`.

use std::sync::Arc;

use tokio::process::Command;
use tokio::sync::Notify;

use crate::types::LldpdResult;
use crate::Global;
use crate::LldpdError;
use protocol::macaddr::MacAddr;

/// Stub transport for macOS.  It never produces incoming packets (readable()
/// returns a future that is always pending) and silently discards outgoing
/// packets.
pub struct Transport {
    _iface: String,
    /// Never notified; keeps readable() pending indefinitely so the rest of
    /// the event loop (timers, control messages) continues to work.
    _notify: Arc<Notify>,
}

impl Transport {
    pub fn new(iface: &str) -> LldpdResult<Transport> {
        Ok(Transport {
            _iface: iface.to_string(),
            _notify: Arc::new(Notify::new()),
        })
    }

    /// Returns a future that is always pending (stub – packet capture is not
    /// implemented on macOS).
    pub async fn readable(&self) -> LldpdResult<()> {
        self._notify.notified().await;
        Ok(())
    }

    /// No-op on macOS (packet injection is not implemented).
    pub fn packet_send(&self, _data: &[u8]) -> LldpdResult<()> {
        Ok(())
    }

    /// Always returns `Ok(None)` on macOS (packet capture is not implemented).
    pub fn packet_recv(&self, _buf: &mut [u8]) -> LldpdResult<Option<usize>> {
        Ok(None)
    }
}

/// Look up the MAC address of `name` by parsing `ifconfig <name>` output.
pub async fn get_iface_and_mac(
    _g: &Global,
    name: &str,
) -> LldpdResult<(String, MacAddr)> {
    let out = Command::new("ifconfig").arg(name).output().await?;
    if !out.status.success() {
        return Err(LldpdError::Other(format!(
            "ifconfig {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ether ") {
            let mac_str = rest.split_whitespace().next().unwrap_or("").trim();
            let mac = mac_str.parse().map_err(|e| {
                LldpdError::Other(format!(
                    "failed to parse MAC address '{mac_str}': {e:?}"
                ))
            })?;
            return Ok((name.to_string(), mac));
        }
    }

    Err(LldpdError::Other(format!(
        "could not find MAC address for interface {name}"
    )))
}
