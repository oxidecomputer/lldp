use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use slog::debug;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use tokio::process::Command;
use tokio::sync::oneshot;

use common::ports::PortId;
use dpd_client::types::LinkId;
use packet::Packet;

use crate::protocol;
use crate::types::LldpdError;
use crate::types::LldpdResult;
use crate::Global;
use common::network::MacAddr;
use protocol::Lldpdu;

const DLADM: &str = "/usr/sbin/dladm";
// By default, we set an LLDPDUs TTL to 120 seconds.
const DEFAULT_TTL: u16 = 120;

pub struct Interface {
    /// Name of the interface on which LLDPDUs are sent and received.
    /// For sidecar ports, this will be the tfport.
    pub iface: String,
    pub mac: MacAddr,

    pub chassis_id: Option<String>,
    pub port_id: Option<String>,
    pub ttl: Option<u16>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,

    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,

    exit_tx: oneshot::Sender<()>,
}

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

async fn get_mac_phys(link: &str) -> LldpdResult<MacAddr> {
    get_mac(vec!["show-phys", "-p", "-o", "address", "-m", link]).await
}

async fn get_mac_vnic(link: &str) -> LldpdResult<MacAddr> {
    get_mac(vec!["show-vnic", "-p", "-o", "macaddress", link]).await
}

fn pcap_open(iface: &str) -> anyhow::Result<pcap::Pcap> {
    let mut pcap = pcap::create(&Some(iface)).map_err(|e| anyhow!(e))?;
    pcap.set_timeout(1)
        .expect("setting the pcap timeout to this constant should never fail");
    if let Err(e) = pcap.activate() {
        pcap.close();
        Err(anyhow!(e))
    } else {
        Ok(pcap)
    }
}

fn pcap_open_duplex(iface: &str) -> LldpdResult<(pcap::Pcap, pcap::Pcap)> {
    let pcap_in = match pcap_open(iface) {
        Ok(i) => i,
        Err(e) => {
            return Err(LldpdError::Other(format!(
                "failed to open inbound pcap: {e:?}"
            )));
        }
    };
    let pcap_out = match pcap_open(iface) {
        Ok(o) => o,
        Err(e) => {
            pcap_in.close();
            return Err(LldpdError::Other(format!(
                "failed to open outbound pcap: {e:?}"
            )));
        }
    };
    Ok((pcap_in, pcap_out))
}

pub fn build_lldpdu(
    switchinfo: &crate::SwitchInfo,
    name: &str,
    iface: &Interface,
) -> Lldpdu {
    let chassis_id = match &iface.chassis_id {
        Some(c) => c.to_string(),
        None => switchinfo.chassis_id.to_string(),
    };
    let port_id = match &iface.port_id {
        Some(port_id) => protocol::PortId::InterfaceAlias(port_id.to_string()),
        None => protocol::PortId::InterfaceName(name.to_string()),
    };

    let mut avail = BTreeSet::new();
    avail.insert(protocol::SystemCapabilities::Router);
    let enabled = avail.clone();

    let mut management_addresses = Vec::new();
    for ipv4 in &iface.ipv4 {
        management_addresses.push(protocol::ManagementAddress {
            addr: (*ipv4).into(),
            interface_num: protocol::InterfaceNum::Unknown(0),
            oid: None,
        });
    }
    for ipv6 in &iface.ipv6 {
        management_addresses.push(protocol::ManagementAddress {
            addr: (*ipv6).into(),
            interface_num: protocol::InterfaceNum::Unknown(0),
            oid: None,
        });
    }

    Lldpdu {
        chassis_id: protocol::ChassisId::ChassisComponent(chassis_id),
        port_id,
        ttl: iface.ttl.unwrap_or(DEFAULT_TTL),
        system_description: Some(switchinfo.system_description.to_string()),
        system_capabilities: Some((avail, enabled)),
        port_description: None,
        system_name: None,
        management_addresses,
        organizationally_specific: Vec::new(),
    }
}

fn build_lldpdu_packet(g: &Global, name: &str) -> LldpdResult<Option<Packet>> {
    let switchinfo = g.switchinfo.lock().unwrap().clone();
    let iface_hash = g.interfaces.lock().unwrap();
    let Some(iface) = iface_hash.get(name) else {
        return Ok(None);
    };

    let lldpdu = build_lldpdu(&switchinfo, name, iface);

    let tgt_mac: MacAddr = protocol::Scope::Bridge.into();
    let tgt = packet::L2Endpoint::new(tgt_mac);
    let src = packet::L2Endpoint::new(iface.mac);
    let mut packet = Packet::gen(
        src.into(),
        tgt.into(),
        vec![packet::eth::ETHER_LLDP],
        None,
    )
    .map_err(|e| {
        LldpdError::Other(format!("while building LLDP packet: {e:?}"))
    })?;

    packet.hdrs.lldp_hdr = Some(
        (&lldpdu)
            .try_into()
            .map_err(|e| LldpdError::Invalid(format!("{e:?}")))?,
    );

    Ok(Some(packet))
}

async fn xmit_lldpdu(pcap: &pcap::Pcap, packet: Packet) -> LldpdResult<i32> {
    match packet.deparse() {
        Ok(data) => pcap
            .send(&data)
            .map_err(|e| anyhow!("failed to send lldpdu: {:?}", e).into()),
        Err(e) => {
            Err(anyhow!("unable to deparse {:?}: {:?}", packet, e).into())
        }
    }
}

fn try_add(
    g: &Global,
    name: &str,
    interface: Option<Interface>,
) -> LldpdResult<()> {
    let mut iface_hash = g.interfaces.lock().unwrap();
    if iface_hash.get(name).is_some() {
        return Err(LldpdError::Exists("interface already added".into()));
    }
    if let Some(i) = interface {
        iface_hash.insert(name.to_string(), i);
    }
    Ok(())
}

fn interface_remove(g: &Global, name: &str) {
    let mut iface_hash = g.interfaces.lock().unwrap();
    if let Some(i) = iface_hash.remove(name) {
        info!(&g.log, "removed {name} from interface hash");
        let _ = i.exit_tx.send(());
    } else {
        error!(&g.log, "unable to remove interface: not in interface hash";
	    "port" => name);
    }
}

fn handle_packet(g: &Global, name: &str, data: &[u8]) {
    // Before fully parsing the packet, check the ethertype at bytes 12
    // and 13 to see if it could be an LLDP packet.

    if data.len() < 14 || data[12] != 0x88 || data[13] != 0xcc {
        return;
    }

    let packet = match packet::Packet::parse(data) {
        Ok(packet) => packet,
        Err(e) => {
            debug!(g.log, "failed to parse packet: {:?}", e;
		    "port" => name);
            return;
        }
    };

    match packet.hdrs.lldp_hdr {
        Some(lldp) => match Lldpdu::try_from(&lldp) {
            Ok(lldpdu) => {
                trace!(g.log, "handling incoming LLDPDU"; "port" => name);
                crate::neighbors::incoming_lldpdu(g, name, lldpdu)
            }
            Err(e) => error!(g.log, "parsing LLDP packet failed: {e:?}";
		 "port" => name),
        },
        None => {
            debug!(g.log, "found packet with LLDP ethertype but no header";
		    "port" => name);
        }
    }
}

async fn interface_recv_loop(
    g: Arc<Global>,
    name: String,
    iface: String,
    pcap: pcap::Pcap,
    done: oneshot::Receiver<()>,
) {
    loop {
        match pcap.next() {
            pcap::Ternary::None => {
                break;
            }
            pcap::Ternary::Err(e) => {
                error!(g.log, "listener died: {e:?}"; "port" => iface.clone());
                break;
            }
            pcap::Ternary::Ok(data) => handle_packet(&g, &name, data),
        }
    }
    pcap.close();
    let _ = done.await;
}

async fn interface_loop(
    g: Arc<Global>,
    name: String,
    iface: String,
    mut done: oneshot::Receiver<()>,
) {
    let log = g.log.new(slog::o!(
	"port" => name.to_string(),
	"iface" => iface.to_string()));
    let (pcap_in, pcap_out) = match pcap_open_duplex(&iface) {
        Ok((i, o)) => (i, o),
        Err(e) => {
            error!(&log, "failed to open pcap"; "err" => e.to_string());
            // TODO: add a "failed" state to interfaces in the hash so the
            // client can retrieve an error message, rather than having them
            // silently disappear
            return;
        }
    };
    debug!(&log, "pcaps open");

    let (exit_tx, exit_rx) = oneshot::channel();
    let recv_hdl = tokio::task::spawn(interface_recv_loop(
        g.clone(),
        name.clone(),
        iface.clone(),
        pcap_in,
        exit_rx,
    ));

    let mut next_xmit = Instant::now();
    loop {
        if Instant::now() > next_xmit {
            match build_lldpdu_packet(&g, &name) {
                Err(e) => {
                    error!(&log, "Failed to build lldpdu";
			"err" => e.to_string());
                }
                Ok(None) => {
                    warn!(&log, "iface removed");
                    break;
                }
                Ok(Some(packet)) => {
                    trace!(&log, "transmit LLDPDU");
                    match xmit_lldpdu(&pcap_out, packet).await {
                        Ok(n) => trace!(&log, "sent {n} bytes"),
                        Err(e) => error!(&log, "failed to xmit lldpdu";
			    "err" => e.to_string()),
                    }
                }
            }
            next_xmit = Instant::now() + Duration::from_secs(30);
        }

        let now = Instant::now();
        let delay = if next_xmit > now {
            next_xmit - now
        } else {
            Duration::from_secs(0)
        };

        tokio::select! {
               _= &mut done => { break}
          _ = tokio::time::sleep(delay) => {}
        };
    }
    // Shut down the receive loop
    debug!(log, "shutting down receive loop");
    let _ = exit_tx.send(());
    debug!(log, "waiting for receive loop to exit");
    let _ = tokio::join!(recv_hdl);
    debug!(log, "interface loop shutting down");
    interface_remove(&g, &name);
}

fn parse_link_name(name: &str) -> LldpdResult<(PortId, LinkId)> {
    let Some((port_id, link_id)) = name.split_once('/') else {
        return Err(LldpdError::Invalid(format!(
            "Invalid switch port or link ID: {name}"
        )));
    };
    let Ok(port_id) = PortId::try_from(port_id) else {
        return Err(LldpdError::Invalid(format!(
            "Invalid switch port: {port_id}"
        )));
    };
    let Ok(link_id) = link_id.parse() else {
        return Err(LldpdError::Invalid(format!("Invalid link ID: {link_id}")));
    };
    Ok((port_id, link_id))
}

async fn dpd_tfport(g: &Global, name: &str) -> LldpdResult<(String, MacAddr)> {
    let (port_id, link_id) = parse_link_name(name)?;
    let client = g.dpd.as_ref().ok_or(LldpdError::NoDpd)?;
    let link_info = client
        .link_get(&port_id, &link_id)
        .await
        .map_err(|e| LldpdError::DpdClientError(e.to_string()))?;
    let iface = format!("tfport{}_{}", port_id, link_id.to_string());
    let mac = link_info.into_inner().address;
    Ok((iface, mac.into()))
}

async fn local_port(name: &str) -> LldpdResult<(String, MacAddr)> {
    let links = get_links().await?;
    let iface = name.to_string();
    let mac = match links.get(name).map(|t| t.as_str()) {
        Some("phys") => get_mac_phys(name).await,
        Some("vnic") => get_mac_vnic(name).await,
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

#[allow(clippy::too_many_arguments)]
pub async fn interface_add(
    global: &Arc<Global>,
    name: String,
    chassis_id: Option<String>,
    port_id: Option<String>,
    ttl: Option<u16>,
    system_name: Option<String>,
    system_description: Option<String>,
    port_description: Option<String>,
) -> LldpdResult<()> {
    info!(&global.log, "Adding interface"; "name" => name.to_string());
    try_add(global, &name, None)?;

    let (iface, mac) = if name.contains('/') {
        dpd_tfport(global, &name).await
    } else {
        local_port(&name).await
    }?;

    let (exit_tx, exit_rx) = oneshot::channel();
    let interface = Interface {
        iface: iface.clone(),
        mac,
        chassis_id,
        port_id,
        ttl,
        system_name,
        system_description,
        port_description,
        ipv4: Vec::new(),
        ipv6: Vec::new(),
        exit_tx,
    };

    try_add(global, &name, Some(interface))?;
    let global = global.clone();
    let _hdl = tokio::task::spawn(async move {
        interface_loop(global, name, iface, exit_rx).await
    });
    Ok(())
}
