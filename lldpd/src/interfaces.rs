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
use tokio::sync::mpsc;

use crate::neighbors;
use crate::packet::LldpTlv;
use crate::packet::Packet;
use crate::protocol;
use crate::types::LldpdError;
use crate::types::LldpdResult;
use crate::Global;
use common::MacAddr;
use protocol::Lldpdu;

// By default, we set an LLDPDUs TTL to 120 seconds.
const DEFAULT_TTL: u16 = 120;

#[cfg(target_os = "illumos")]
use crate::plat_illumos as plat;
#[cfg(target_os = "linux")]
use crate::plat_linux as plat;

#[derive(Debug)]
pub struct Interface {
    /// Name of the interface on which LLDPDUs are sent and received.
    /// For sidecar ports, this will be the tfport.
    pub iface: String,
    pub mac: MacAddr,

    pub chassis_id: Option<protocol::ChassisId>,
    pub port_id: protocol::PortId,
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

pub fn build_lldpdu(
    switchinfo: &crate::SwitchInfo,
    iface: &Interface,
) -> Lldpdu {
    let chassis_id = match &iface.chassis_id {
        Some(c) => c.clone(),
        None => switchinfo.chassis_id.clone(),
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
        port_id: iface.port_id.clone(),
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

    let lldpdu = build_lldpdu(&switchinfo, &iface);
    let tlvs: Vec<LldpTlv> = (&lldpdu).try_into()?;

    let tgt_mac: MacAddr = protocol::Scope::Bridge.into();
    let mut packet = Packet::new(tgt_mac, iface.mac);
    tlvs.iter().for_each(|tlv| packet.add_tlv(tlv));

    Ok(Some(packet))
}

async fn xmit_lldpdu(
    transport: &plat::Transport,
    packet: Packet,
) -> LldpdResult<()> {
    transport
        .packet_send(&packet.deparse())
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

// Clippy mistakenly believes that the returns in the map_err code below are
// unnecessary.  Without those returns, the subsequent unwrap()s would panic.
#[allow(clippy::needless_return)]
async fn interface_loop(
    g: Arc<Global>,
    name: String,
    iface: String,
    mut done_rx: mpsc::Receiver<()>,
) {
    let log = g.log.new(slog::o!(
	"port" => name.to_string(),
	"iface" => iface.to_string()));
    let transport = plat::Transport::new(&iface)
        .map_err(|e| {
            // TODO: add a "failed" state to interfaces in the hash so the
            // client can retrieve an error message, rather than having them
            // silently disappear
            error!(&log, "failed to open transport"; "err" => e.to_string());
            return;
        })
        .unwrap();

    let asyncfd = transport
        .get_poll_fd()
        .map_err(|e| {
            error!(g.log, "failed to get transport fd: {e:?}");
            return;
        })
        .map(|fd| {
            tokio::io::unix::AsyncFd::new(fd)
                .map_err(|e| {
                    error!(
                        g.log,
                        "failed to wrap transport fd for tokio: {e:?}"
                    );
                    return;
                })
                .unwrap()
        })
        .unwrap();

    let mut next_xmit = Instant::now();
    let mut done = false;
    let mut buf = [0u8; 4096];
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
                    if let Err(e) = xmit_lldpdu(&transport, packet).await {
                        error!(&log, "failed to xmit lldpdu";
			    "err" => e.to_string());
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

        let mut do_read = false;
        tokio::task::yield_now().await;
        tokio::select! {
            _= done_rx.recv() => { done = true}
        _= asyncfd.readable() => { do_read = true}
        _ = tokio::time::sleep(delay) => {}
        };

        if do_read {
            match transport.packet_recv(&mut buf) {
                Ok(None) => {
                    debug!(g.log, "no data");
                    break;
                }
                Ok(Some(n)) => handle_packet(&g, &name, &buf[0..n]),
                Err(LldpdError::TooSmall(_, b)) => {
                    warn!(g.log, "dropped excessively large packet: {b} bytes"; "port" => iface.clone())
                }
                Err(e) => {
                    error!(g.log, "listener died: {e:?}"; "port" => iface.clone());
                    break;
                }
            }
        }
    }

    debug!(log, "interface loop shutting down");
    interface_remove(&g, &name);
}

pub fn neighbor_id_match(g: &Global, id: &neighbors::NeighborId) -> bool {
    let chassis_id = g.switchinfo.lock().unwrap().chassis_id.clone();
    g.interfaces
        .lock()
        .unwrap()
        .iter()
        .filter(|(name, _iface)| name == &&id.interface)
        .any(|(_name, iface)| {
            let iface = iface.lock().unwrap();
            let chassis_id = iface.chassis_id.as_ref().unwrap_or(&chassis_id);
            id.port_id == iface.port_id && &id.chassis_id == chassis_id
        })
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

    let (iface, mac) = plat::get_iface_and_mac(global, &name).await?;

    let port_id =
        port_id.unwrap_or(protocol::PortId::InterfaceName(name.to_string()));
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
    iface.port_id = port_id;
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
