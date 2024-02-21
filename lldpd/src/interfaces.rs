use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use slog::debug;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::packet::LldpTlv;
use crate::packet::Packet;
use crate::protocol;
use crate::types::LldpdError;
use crate::types::LldpdResult;
use crate::Global;
use common::MacAddr;
use protocol::Lldpdu;

const DLADM: &str = "/usr/sbin/dladm";
// By default, we set an LLDPDUs TTL to 120 seconds.
const DEFAULT_TTL: u16 = 120;

#[derive(Debug)]
pub struct Interface {
    /// Name of the interface on which LLDPDUs are sent and received.
    /// For sidecar ports, this will be the tfport.
    pub iface: String,
    pub mac: MacAddr,

    pub chassis_id: Option<protocol::ChassisId>,
    pub port_id: Option<protocol::PortId>,
    pub ttl: Option<u16>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,

    pub management_addrs: Option<BTreeSet<IpAddr>>,

    done_tx: mpsc::Sender<()>,
}

macro_rules! get_interface {
    ($hash:ident, $name:ident) => {
        $hash
            .get($name)
            .ok_or_else(|| {
                LldpdError::Missing(format!("no such interface: {}", $name))
            })
            .map(|i| i.lock().unwrap())
    };
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
        Some(c) => c.clone(),
        None => switchinfo.chassis_id.clone(),
    };
    let port_id = match &iface.port_id {
        Some(p) => p.clone(),
        None => protocol::PortId::InterfaceName(name.to_string()),
    };

    let mut avail = BTreeSet::new();
    avail.insert(protocol::SystemCapabilities::Router);
    let enabled = avail.clone();

    let mut management_addresses = Vec::new();
    let addrs = iface
        .management_addrs
        .as_ref()
        .unwrap_or(&switchinfo.management_addrs);
    for addr in addrs {
        management_addresses.push(protocol::ManagementAddress {
            addr: *addr,
            interface_num: protocol::InterfaceNum::Unknown(0),
            oid: None,
        });
    }

    let system_name = match &iface.system_name {
        Some(n) => Some(n.clone()),
        None => switchinfo.system_name.clone(),
    };
    let system_description = match &iface.system_description {
        Some(d) => Some(d.clone()),
        None => switchinfo.system_description.clone(),
    };
    Lldpdu {
        chassis_id,
        port_id,
        ttl: iface.ttl.unwrap_or(DEFAULT_TTL),
        system_capabilities: Some((avail, enabled)),
        port_description: iface.port_description.clone(),
        system_name,
        system_description,
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
    let iface = iface.lock().unwrap();

    let lldpdu = build_lldpdu(&switchinfo, name, &iface);
    let tlvs: Vec<LldpTlv> = (&lldpdu).try_into()?;

    let tgt_mac: MacAddr = protocol::Scope::Bridge.into();
    let mut packet = Packet::new(tgt_mac, iface.mac);
    tlvs.iter().for_each(|tlv| packet.add_tlv(tlv));

    Ok(Some(packet))
}

async fn xmit_lldpdu(pcap: &pcap::Pcap, packet: Packet) -> LldpdResult<i32> {
    pcap.send(&packet.deparse())
        .map_err(|e| anyhow!("failed to send lldpdu: {:?}", e).into())
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
        iface_hash.insert(name.to_string(), Mutex::new(i));
    }
    Ok(())
}

fn interface_remove(g: &Global, name: &str) {
    let mut iface_hash = g.interfaces.lock().unwrap();
    match iface_hash.remove(name) {
        Some(i) => {
            info!(&g.log, "removed {name} from interface hash");
            let i = i.lock().unwrap();
            let _ = &i.done_tx.send(());
        }
        None => {
            error!(&g.log, "unable to remove interface: not in interface hash";
	    "port" => name);
        }
    }
}

fn handle_packet(g: &Global, name: &str, data: &[u8]) {
    let packet = match Packet::parse(data) {
        Ok(Some(packet)) => packet,
        Ok(None) => return,
        Err(e) => {
            debug!(g.log, "failed to parse packet: {:?}", e;
		    "port" => name);
            return;
        }
    };

    if packet.lldp_hdr.lldp_data.is_empty() {
        debug!(g.log, "found packet with LLDP ethertype but no header";
		    "port" => name);
    } else {
        match Lldpdu::try_from(&packet.lldp_hdr.lldp_data) {
            Ok(lldpdu) => {
                trace!(g.log, "handling incoming LLDPDU"; "port" => name);
                crate::neighbors::incoming_lldpdu(g, name, lldpdu)
            }
            Err(e) => error!(g.log, "parsing LLDP packet failed: {e:?}";
		 "port" => name),
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
    mut done_rx: mpsc::Receiver<()>,
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
    let mut done = false;
    while !done {
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
               _= done_rx.recv() => { done = true}
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

#[allow(unused_variables)]
async fn get_iface_mac(
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
    chassis_id: Option<protocol::ChassisId>,
    port_id: Option<protocol::PortId>,
    ttl: Option<u16>,
    system_name: Option<String>,
    system_description: Option<String>,
    port_description: Option<String>,
) -> LldpdResult<()> {
    info!(&global.log, "Adding interface"; "name" => name.to_string());
    try_add(global, &name, None)?;

    let (iface, mac) = get_iface_mac(global, &name).await?;

    let (done_tx, done_rx) = mpsc::channel(1);
    let interface = Interface {
        iface: iface.clone(),
        mac,
        chassis_id,
        port_id,
        ttl,
        system_name,
        system_description,
        port_description,
        management_addrs: None,
        done_tx,
    };

    try_add(global, &name, Some(interface))?;
    let global = global.clone();
    let _hdl = tokio::task::spawn(async move {
        interface_loop(global, name, iface, done_rx).await
    });
    Ok(())
}

/// Add a single management addresses to an interface.
pub fn addr_add(g: &Global, name: &String, addr: &IpAddr) -> LldpdResult<()> {
    info!(g.log, "adding management address";
	    "iface" => name, "addr" => addr.to_string());
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;

    if iface.management_addrs.is_none() {
        iface.management_addrs = Some(BTreeSet::new());
    }
    iface
        .management_addrs
        .as_mut()
        .expect("existence guaranteed above")
        .insert(*addr);
    Ok(())
}

/// Set the interface-local chassis id
pub fn chassis_id_set(
    g: &Global,
    name: &String,
    chassis_id: protocol::ChassisId,
) -> LldpdResult<()> {
    info!(g.log, "setting interface-level chassis ID";
	    "iface" => name, "chassis_id" => chassis_id.to_string());
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.chassis_id = Some(chassis_id);
    Ok(())
}

/// Clearing the interface-local chassis id
pub fn chassis_id_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level chassis ID"; "iface" => name);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.chassis_id = None;
    Ok(())
}

/// Set the port id
pub fn port_id_set(
    g: &Global,
    name: &String,
    port_id: protocol::PortId,
) -> LldpdResult<()> {
    info!(g.log, "setting port ID";
	    "iface" => name, "port_id" => port_id.to_string());
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.port_id = Some(port_id);
    Ok(())
}

/// Clearing the port id
pub fn port_id_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing port ID"; "iface" => name);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.port_id = None;
    Ok(())
}

/// Set the interface-local ttl
pub fn ttl_set(g: &Global, name: &String, ttl: u16) -> LldpdResult<()> {
    info!(g.log, "setting interface-level port ID";
	    "iface" => name, "ttl" => ttl);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.ttl = Some(ttl);
    Ok(())
}

/// Clearing the interface-local ttl
pub fn ttl_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level port ID"; "iface" => name);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.ttl = None;
    Ok(())
}

/// Set the port description
pub fn port_desc_set(
    g: &Global,
    name: &String,
    desc: &String,
) -> LldpdResult<()> {
    info!(g.log, "setting port description";
	    "iface" => name, "port_desc" => desc.to_string());
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.port_description = Some(desc.to_string());
    Ok(())
}

/// Clearing the port description
pub fn port_desc_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level port ID"; "iface" => name);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.port_description = None;
    Ok(())
}

/// Set the interface-local system name
pub fn system_name_set(
    g: &Global,
    name: &String,
    sysname: &String,
) -> LldpdResult<()> {
    info!(g.log, "setting interface-level system name";
	    "iface" => name, "sysname" =>sysname.to_string());
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.system_name = Some(sysname.to_string());
    Ok(())
}

/// Clearing the interface-local system name
pub fn system_name_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level port ID"; "iface" => name);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.system_name = None;
    Ok(())
}

/// Set the interface-local system name
pub fn system_desc_set(
    g: &Global,
    name: &String,
    sysdesc: &String,
) -> LldpdResult<()> {
    info!(g.log, "setting interface-level system description";
	    "iface" => name, "sysdesc" =>sysdesc.to_string());
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.system_description = Some(sysdesc.to_string());
    Ok(())
}

/// Clearing the interface-local system description
pub fn system_desc_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level system description"; "iface" => name);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.system_description = None;
    Ok(())
}

/// Remove a single management addresses from an interface.
pub fn addr_delete(
    g: &Global,
    name: &String,
    addr: &IpAddr,
) -> LldpdResult<()> {
    info!(g.log, "removing management address";
	    "iface" => name, "addr" => addr.to_string());
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;

    if let Some(addrs) = &mut iface.management_addrs {
        if addrs.remove(addr) {
            Ok(())
        } else {
            Err(LldpdError::Missing(format!("no such address: {addr}")))
        }
    } else {
        Err(LldpdError::Missing(
            "no interface-local addresses".to_string(),
        ))
    }
}

/// Remove all management addresses on an interface.
pub fn addr_delete_all(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "removing all management addresses"; "iface" => name);
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)?;
    iface.management_addrs = None;
    Ok(())
}
