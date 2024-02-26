// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::BTreeMap;
use tokio::process::Command;

use crate::types::LldpdError;
use crate::types::LldpdResult;
use crate::Global;
use common::MacAddr;

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
    dlpi_in: dlpi::DlpiHandle,
    dlpi_out: dlpi::DlpiHandle,
}

fn dlpi_open(iface: &str) -> LldpdResult<dlpi::DlpiHandle> {
    dlpi::open(iface, dlpi::sys::DLPI_RAW)
        .map_err(|e| {
            LldpdError::Dlpi(format!("failed to bind recv to LLDP: {e:?}"))
        })
        .and_then(|hdl| {
            dlpi::bind(hdl, crate::packet::ETHER_LLDP as u32)
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
                .map(|_| hdl)
        })?;

        dlpi_open(iface).map(|dlpi_out| Transport { dlpi_in, dlpi_out })
    }

    pub fn get_poll_fd(&self) -> LldpdResult<i32> {
        match unsafe { dlpi::sys::dlpi_fd(self.dlpi_in.0) } {
            -1 => Err(LldpdError::Dlpi("invalid handle".to_string())),
            fd => Ok(fd),
        }
    }

    pub fn packet_send(&self, data: &[u8]) -> LldpdResult<()> {
        let dummy = [0u8; 0];
        dlpi::send(self.dlpi_out, &dummy, data, None)
            .map_err(|e| LldpdError::Dlpi(e.to_string()))
    }

    pub fn packet_recv(&self, buf: &mut [u8]) -> LldpdResult<Option<usize>> {
        let mut src = [0u8; dlpi::sys::DLPI_PHYSADDR_MAX];
        dlpi::recv(self.dlpi_in, &mut src, buf, -1, None)
            .map(|(_, len)| Some(len))
            .map_err(|e| LldpdError::Dlpi(e.to_string()))
    }
}
