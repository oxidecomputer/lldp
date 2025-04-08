// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::BTreeMap;
use tokio::io::unix::AsyncFd;
use tokio::process::Command;

use crate::types::LldpdResult;
use crate::Global;
use crate::LldpdError;
use protocol::macaddr::MacAddr;

const DLADM: &str = "/usr/sbin/dladm";

// Get a BTreeMap containing the names and types of all links on the system
async fn get_links() -> LldpdResult<BTreeMap<String, String>> {
    // When we run dladm with no arguments, we get a list of all links on
    // the system.  The first field is the link name and the second is the
    // link type
    let out = Command::new(DLADM).output().await?;
    if !out.status.success() {
        return Err(LldpdError::Other(format!(
            "dladm failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let mut rval = BTreeMap::new();
    let mut idx = 0;
    for line in std::str::from_utf8(&out.stdout)
        .map_err(|e| {
            LldpdError::Other(format!("while reading dladm outout: {e:?}"))
        })?
        .lines()
    {
        idx += 1;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            return Err(LldpdError::Other("invalid dladm output".to_string()));
        }
        if idx > 0 {
            rval.insert(fields[0].to_string(), fields[1].to_string());
        }
    }
    Ok(rval)
}

async fn get_mac(dladm_args: Vec<&str>) -> LldpdResult<MacAddr> {
    let out = Command::new(DLADM).args(dladm_args).output().await?;
    if !out.status.success() {
        return Err(LldpdError::Other(format!(
            "dladm failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
        .map_err(|e| {
            LldpdError::Other(format!("while reading dladm outout: {e:?}"))
        })?
        .lines()
        .collect();
    if lines.len() == 1 {
        let mac = lines[0];
        mac.parse::<MacAddr>().map_err(|e| {
            LldpdError::Other(format!(
                "failed to parse mac address {mac}: {e:?}"
            ))
        })
    } else {
        Err(LldpdError::Other("invalid dladm output".to_string()))
    }
}

#[allow(unused_variables)]
pub async fn get_iface_and_mac(
    g: &Global,
    name: &str,
) -> LldpdResult<(String, MacAddr)> {
    #[cfg(feature = "dendrite")]
    if name.contains('/') {
        return crate::dendrite::dpd_tfport(g, name).await;
    }

    let links = get_links().await?;
    let iface = name.to_string();
    let mac = match links.get(name).map(|t| t.as_str()) {
        Some("phys") => {
            get_mac(vec!["show-phys", "-p", "-o", "address", "-m", name]).await
        }
        Some("vnic") => {
            get_mac(vec!["show-vnic", "-p", "-o", "macaddress", name]).await
        }
        Some("tfport") => Err(LldpdError::Invalid(
            "cannot use LLDP with a tfport - use the sidecar link".into(),
        )),
        Some(x) => {
            Err(LldpdError::Invalid(format!("cannot use LLDP on {x} links")))
        }
        None => Err(LldpdError::Missing("no such link".into())),
    }?;
    Ok((iface, mac))
}

pub struct Transport {
    dlpi_in: dlpi::DropHandle,
    dlpi_out: dlpi::DropHandle,
    asyncfd: AsyncFd<i32>,
}

fn dlpi_open(iface: &str) -> LldpdResult<dlpi::DlpiHandle> {
    dlpi::open(iface, dlpi::sys::DLPI_RAW)
        .map_err(|e| {
            LldpdError::Dlpi(format!("failed to bind recv to LLDP: {e:?}"))
        })
        .and_then(|hdl| {
            dlpi::bind(hdl, protocol::packet::ETHER_LLDP as u32)
                .map(|_| hdl)
                .map_err(|e| {
                    LldpdError::Dlpi(format!("failed to open {iface}: {e:?}"))
                })
        })
}

impl Transport {
    pub fn new(iface: &str) -> LldpdResult<Transport> {
        let dlpi_in = dlpi_open(iface).and_then(|hdl| {
            dlpi::promisc_on(hdl, dlpi::sys::DL_PROMISC_PHYS)
                .map_err(|e| {
                    LldpdError::Dlpi(format!(
                        "failed to set promisc on {iface}: {e:?}"
                    ))
                })
                .map(|_| dlpi::DropHandle(hdl))
        })?;
        let dlpi_out = dlpi_open(iface).map(dlpi::DropHandle)?;

        let in_fd =
            dlpi_in.fd().map_err(|e| LldpdError::Dlpi(e.to_string()))?;
        let asyncfd = AsyncFd::new(in_fd)
            .map_err(|e| LldpdError::Other(e.to_string()))?;

        Ok(Transport {
            dlpi_in,
            dlpi_out,
            asyncfd,
        })
    }

    pub async fn readable(&self) -> LldpdResult<()> {
        self.asyncfd
            .readable()
            .await
            .map(|_| ())
            .map_err(|e| e.into())
    }

    pub fn packet_send(&self, data: &[u8]) -> LldpdResult<()> {
        let dummy = [0u8; 0];
        dlpi::send(self.dlpi_out.0, &dummy, data, None)
            .map_err(|e| LldpdError::Dlpi(e.to_string()))
    }

    pub fn packet_recv(&self, buf: &mut [u8]) -> LldpdResult<Option<usize>> {
        let mut src = [0u8; dlpi::sys::DLPI_PHYSADDR_MAX];
        // In the calling code, we only get here if the underlying fd is
        // readable(), but apparently that doesn't mean that there is actually
        // data available.  Thus, we set a 1 second timeout to ensure that we
        // don't block on this recv indefinitely.
        dlpi::recv(self.dlpi_in.0, &mut src, buf, 1000, None)
            .map(|(_, len)| Some(len))
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::Interrupted => LldpdError::EIntr,
                std::io::ErrorKind::Other => {
                    // One would expect dlpi-sys to return
                    // `ErrorKind::Timedout`, but it buries it in an Other
                    // for some reason.
                    if let Ok(r) = e.downcast::<dlpi::ResultCode>() {
                        if r == dlpi::ResultCode::ETimedout {
                            LldpdError::ETimedOut
                        } else {
                            LldpdError::Dlpi(r.to_string())
                        }
                    } else {
                        LldpdError::Dlpi("malformed DLPI error".into())
                    }
                }
                _ => LldpdError::Dlpi(e.to_string()),
            })
    }
}
