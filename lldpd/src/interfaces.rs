// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use chrono::Utc;
use slog::debug;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::errors::LldpdError;
use crate::packet::LldpTlv;
use crate::packet::Packet;
use crate::protocol;
use crate::types;
use crate::types::LldpdResult;
use crate::Global;
use common::MacAddr;
use plat::Transport;
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

    /// Configurable properties
    pub chassis_id: Option<protocol::ChassisId>,
    pub port_id: protocol::PortId,
    pub ttl: Option<u16>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,
    pub management_addrs: Option<BTreeSet<IpAddr>>,

    /// Counters of packets in, packets out, etc.
    pub stats: Stats,

    /// Neighbors we are currently aware of
    pub neighbors: BTreeMap<types::NeighborId, types::Neighbor>,

    msg_tx: mpsc::Sender<InterfaceMsg>,

    /// The values below are settings defined in section 9.2.5 of the standard.
    /// We support changing these settings are either the interface level or
    /// system levl.  Any value of None in the Interface struct will default to
    /// the system-level setting defined in the Agent structure.

    /// Whether the agent should be sending, receiving, or both.
    admin_status: Option<types::AdminStatus>,
    /// How quickly to resend LLDPDUs during fast tx periods.
    /// Measured in ticks from 1-3600.
    msg_fast_tx: Option<u16>,
    /// Multiplier of msg_tx_interval, used to calculate TTL.  Legal values
    /// are 1-100.
    msg_tx_hold: Option<u16>,
    /// Time between LLDPDU transmissions during normal tx periods.
    /// Measured in ticks from 1-3600.
    msg_tx_interval: Option<u16>,
    /// After becoming disabled, time in seconds to wait before attempting
    /// reinitialization.
    reinit_delay: Option<u16>,
    /// Maximum value of tx_credit.  If None, default to the agent-level setting
    tx_credit_max: Option<u16>,
    /// Initial value of tx_fast.  If None, default to the agent-level setting
    tx_fast_init: Option<u16>,

    /// The values below are variables defined in section 9.2.5 of the standard.
    /// These are set dynamically by the various state machines as the daemon
    /// runs.  The standard defines a number of variables that are not reflected
    /// here, as we implement them as per-task timers or inter-task messages
    /// rather than as flag variables.

    /// Number of LLDPDUs that can be transmitted at any one time
    tx_credit: u16,
    /// If this value is non-0, this interface is in fast tx mode, with tx_fast
    /// packets remaining to send
    tx_fast: u16,
}

/// Statistics described in section 9.2.6 of the standard
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// How many times a neighbor's record has been deleted because its TTL
    /// expired
    ageouts_total: u64,
    /// How many LLDP frames have been discarded because of an invalid TLV or
    /// lack of local space
    frames_discarded_total: u64,
    /// LLDPDU frames discarded because of a detected error
    frames_in_errors_total: u64,
    /// Count of all LLDPDU frames received
    frames_in_total: u64,
    /// Count of all LLDPDU frames transmitted
    frames_out_total: u64,
    /// TLVs that were received and discarded for any reason
    tlvs_discarded_total: u64,
    /// Well-formed TLVs that were discarded because they were not recognized.
    tlvs_unrecognized_total: u64,
    /// LLDPDUs that were discarded because they violated a length restriction
    lldpdu_length_errors: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceMsg {
    UpdatedInfo,
    TimeToGo,
}

impl Interface {
    /// Ask the interface loop to shut itself down and clean up after itself.
    pub async fn shutdown(&mut self) {
        let _ = self.msg_tx.send(InterfaceMsg::TimeToGo).await;
    }
}

// Convenience macro to look for an interface in the hash and return a
// consistent error if it's not found.
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

// Construct an LLDPDU structure with all of the information we have about this
// interface
pub fn build_lldpdu(
    switchinfo: &crate::SwitchInfo,
    iface: &Interface,
) -> Lldpdu {
    let chassis_id = match &iface.chassis_id {
        Some(c) => c.clone(),
        None => switchinfo.chassis_id.clone(),
    };

    // TODO-completeness: the available and enabled capabilities should be
    // configurable - not just hardcoded as "Router".
    let mut avail = BTreeSet::new();
    avail.insert(protocol::SystemCapabilities::Router);
    let enabled = avail.clone();

    // XXX: this can be done more neatly with iter().map().collect()
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

// Construct an LLDPDU packet with all of the data we want to communicate about
// this interface
fn build_lldpdu_packet(
    switchinfo: &crate::SwitchInfo,
    iface: &Interface,
) -> Packet {
    let lldpdu = build_lldpdu(&switchinfo, &iface);
    let tlvs: Vec<LldpTlv> = (&lldpdu)
        .try_into()
        .expect(&format!("we constructed an invalid LLDPDU: {lldpdu:#?}"));

    let tgt_mac: MacAddr = protocol::Scope::Bridge.into();
    let mut packet = Packet::new(tgt_mac, iface.mac);
    tlvs.iter().for_each(|tlv| packet.add_tlv(tlv));

    packet
}

// Construct an LLDPDU packet with a TTL of 0 to notify neighbors that this interface
// is going away immediately.
fn build_shutdown_packet(
    switchinfo: &crate::SwitchInfo,
    iface: &Interface,
) -> Packet {
    let lldpdu = build_lldpdu(&switchinfo, &iface);
    let tlvs: Vec<LldpTlv> = (&lldpdu)
        .try_into()
        .expect(&format!("we constructed an invalid LLDPDU: {lldpdu:#?}"));

    let tgt_mac: MacAddr = protocol::Scope::Bridge.into();
    let mut packet = Packet::new(tgt_mac, iface.mac);
    // The first two TLVs in a a load-bearing lldpdu contain the chassis_id and
    // port_id.  The shutdown lldpdu we want to send will consist of those two
    // TLVs and a TLV with a TTL of 0.
    packet.add_tlv(&tlvs[0]);
    packet.add_tlv(&tlvs[1]);
    packet.add_tlv(&protocol::ttl_to_tlv(0));

    packet
}

// Transmit a single packet on the provided transport
async fn xmit_lldpdu(transport: &Transport, packet: Packet) -> LldpdResult<()> {
    transport
        .packet_send(&packet.deparse())
        .map_err(|e| anyhow!("failed to send lldpdu: {:?}", e).into())
}

// Bump error statistics when receiving a bad packet
fn error_accounting(g: &Global, name: &str, _error: LldpdError) {
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)
        .expect("interface still exists, so it must be in the hash");
    iface.stats.frames_in_errors_total += 1;
    iface.stats.frames_discarded_total += 1;
}

// Process a single packet that arrived on our transport.
fn handle_packet(g: &Global, log: &slog::Logger, name: &str, data: &[u8]) {
    // Given a raw packet, extract the ethernet and LLDP headers and drop
    // anything else.
    let packet = match Packet::parse(data) {
        Ok(Some(packet)) => packet,
        Ok(None) => return, // non-LLDP packet
        Err(e) => {
            debug!(log, "failed to parse packet: {:?}", e);
            return error_accounting(g, name, e);
        }
    };

    // Parse each of the TLVs in the LLDP header trying to build a valid LLDPDU
    // structure.
    let lldpdu = match Lldpdu::try_from(&packet.lldp_hdr.lldp_data) {
        Ok(lldpdu) => lldpdu,
        Err(e) => {
            error!(log, "parsing LLDP packet failed: {e:?}");
            // TODO-completeness: examine the error details to detect the
            // specific failure modes for which the spec has counters.
            return error_accounting(g, name, e);
        }
    };

    let id = types::NeighborId::new(&lldpdu);
    let switchinfo = g.switchinfo.lock().unwrap().clone();
    let iface_hash = g.interfaces.lock().unwrap();
    let mut iface = get_interface!(iface_hash, name)
        .expect("interface hash entry should persist until task exits");

    // If one of our own LLDPDUs was reflected back to us, drop it
    if match &iface.chassis_id {
        Some(chassis_id) => chassis_id == &lldpdu.chassis_id,
        None => switchinfo.chassis_id == lldpdu.chassis_id,
    } {
        trace!(log, "ignoring our own lldpdu for {id:?}");
        return;
    }

    // Is this is new neighbor, an update from an old neighbor, or just a
    // periodic re-advertisement of the same old stuff?
    match iface.neighbors.entry(id.clone()) {
        Entry::Vacant(e) => {
            let sysinfo: types::SystemInfo = (&lldpdu).into();
            let neighbor = types::Neighbor::from_lldpdu(&lldpdu);
            info!(log, "new neighbor {:?}: {}", id, &sysinfo);
            e.insert(neighbor);
        }
        Entry::Occupied(old) => {
            let now = Utc::now();
            let old = old.into_mut();
            old.last_seen = now;
            if old.lldpdu != lldpdu {
                let sysinfo: types::SystemInfo = (&lldpdu).into();
                info!(log, "updated neighbor {:?}: {}", id, &sysinfo);
                old.last_changed = now;
                old.lldpdu = lldpdu;
            }
        }
    };
}

// Construct and transmit an LLDPDU on this interface.  Return the number of
// ticks to delay before issuing the next one.
async fn tx_lldpdu(
    g: &Global,
    log: &slog::Logger,
    transport: &Transport,
    name: &String,
) -> u16 {
    let ticks;
    let packet = {
        let switchinfo = g.switchinfo.lock().unwrap().clone();
        let iface_hash = g.interfaces.lock().unwrap();
        let mut iface = get_interface!(iface_hash, name)
            .expect("interface hash entry should persist until task exits");
        let status = iface
            .admin_status
            .unwrap_or_else(|| switchinfo.agent.admin_status);

        if !status.has_tx() {
            return u16::MAX;
        }

        if iface.tx_fast > 0 {
            iface.tx_fast -= 1;
            ticks = iface
                .msg_fast_tx
                .unwrap_or_else(|| switchinfo.agent.msg_fast_tx);
        } else {
            ticks = iface
                .msg_tx_interval
                .unwrap_or_else(|| switchinfo.agent.msg_tx_interval);
        }
        build_lldpdu_packet(&switchinfo, &iface)
    };
    trace!(&log, "transmit LLDPDU");
    if let Err(e) = xmit_lldpdu(&transport, packet).await {
        error!(&log, "failed to xmit lldpdu"; "err" => e.to_string());
    }
    ticks
}

// Construct and transmit a "shutting down" LLDPDU on this interface.
async fn tx_shutdown(
    g: &Global,
    log: &slog::Logger,
    transport: &Transport,
    name: &String,
) {
    let packet = {
        let switchinfo = g.switchinfo.lock().unwrap().clone();
        let iface_hash = g.interfaces.lock().unwrap();
        let iface = get_interface!(iface_hash, name)
            .expect("interface hash entry should persist until task exits");
        let status = iface
            .admin_status
            .unwrap_or_else(|| switchinfo.agent.admin_status);

        if !status.has_tx() {
            return;
        }

        build_shutdown_packet(&switchinfo, &iface)
    };
    trace!(&log, "transmit shutdown LLDPDU");
    if let Err(e) = xmit_lldpdu(&transport, packet).await {
        error!(&log, "failed to xmit lldpdu"; "err" => e.to_string());
    }
}

enum WakeupEvent {
    Message(InterfaceMsg),
    FdReady,
    Timeout,
}

async fn wait_for_event(
    msg_rx: &mut mpsc::Receiver<InterfaceMsg>,
    asyncfd: &AsyncFd<i32>,
    timeout: Instant,
) -> WakeupEvent {
    tokio::task::yield_now().await;
    let now = Instant::now();
    let delay = if timeout <= now {
        return WakeupEvent::Timeout;
    } else {
        timeout - now
    };

    #[rustfmt::skip]
    tokio::select! {
	msg = msg_rx.recv() => WakeupEvent::Message(msg
	      .expect("channel shouldn't be dropped while the interface thread is alive")),
	_ = asyncfd.readable() => WakeupEvent::FdReady,
	_ = tokio::time::sleep(delay) => WakeupEvent::Timeout,
    }
}

// Open a transport (DLPI or pcap) on an interface and return a file descriptor
// that tokio can poll() on.
fn transport_init(iface: &String) -> LldpdResult<(Transport, AsyncFd<i32>)> {
    let transport = plat::Transport::new(&iface)?;
    transport.get_poll_fd().and_then(|fd| {
        tokio::io::unix::AsyncFd::new(fd)
            .map_err(|e| {
                LldpdError::Other(format!(
                    "failed to wrap transport fd for tokio: {e:?}"
                ))
            })
            .map(|asyncfd| (transport, asyncfd))
    })
}

// Clippy mistakenly believes that the returns in the map_err code below are
// unnecessary.  Without those returns, the subsequent unwrap()s would panic.
#[allow(clippy::needless_return)]
async fn interface_loop(
    g: Arc<Global>,
    name: String,
    iface: String,
    mut msg_rx: mpsc::Receiver<InterfaceMsg>,
) {
    let log = g.log.new(slog::o!(
	"port" => name.to_string(),
	"iface" => iface.to_string()));

    let (transport, asyncfd) = match transport_init(&iface) {
        Ok((t, a)) => (t, a),
        Err(e) => {
            // TODO: add a "failed" state to interfaces in the hash so the
            // client can retrieve an error message, rather than having them
            // silently disappear
            error!(log, "failed to init transport: {e:?}");
            return;
        }
    };

    let mut buf = [0u8; 4096];
    let mut next_tx = Instant::now();
    loop {
        // Is it time for another advertisement?
        if Instant::now() > next_tx {
            let ticks = tx_lldpdu(&g, &log, &transport, &name).await;
            next_tx = Instant::now() + Duration::from_secs(ticks as u64);
        }

        match wait_for_event(&mut msg_rx, &asyncfd, next_tx).await {
            WakeupEvent::Message(msg) => match msg {
                InterfaceMsg::TimeToGo => break,
                InterfaceMsg::UpdatedInfo => next_tx = Instant::now(),
            },
            WakeupEvent::FdReady => match transport.packet_recv(&mut buf) {
                Ok(None) => { /* spurious wakeup? */ }
                Ok(Some(n)) => handle_packet(&g, &log, &name, &buf[0..n]),
                Err(LldpdError::TooSmall(_, b)) => {
                    warn!(log, "dropped excessively large packet: {b} bytes");
                }
                Err(e) => {
                    error!(log, "listener died: {e:?}");
                    break;
                }
            },
            WakeupEvent::Timeout => {
                // packet transmit happens at the top of the loop
            }
        }
    }

    tx_shutdown(&g, &log, &transport, &name).await;
    debug!(log, "interface loop shutting down");
    let mut iface_hash = g.interfaces.lock().unwrap();
    iface_hash
        .remove(&name)
        .expect("interface hash entry should persist until task exits");
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

    let port_id =
        port_id.unwrap_or(protocol::PortId::InterfaceName(name.to_string()));
    let (iface, mac) = plat::get_iface_and_mac(global, &name).await?;

    let mut iface_hash = global.interfaces.lock().unwrap();
    if iface_hash.get(&name).is_some() {
        return Err(LldpdError::Exists("interface already added".into()));
    }

    let (msg_tx, msg_rx) = mpsc::channel(1);
    let global = global.clone();
    let task_iface = iface.clone();
    let task_name = name.clone();
    let _hdl = tokio::task::spawn(async move {
        interface_loop(global, task_name, task_iface, msg_rx).await
    });

    let interface = Interface {
        iface,
        mac,
        chassis_id,
        port_id,
        ttl,
        system_name,
        system_description,
        port_description,
        management_addrs: None,
        msg_tx,

        stats: Stats::default(),
        neighbors: BTreeMap::new(),

        admin_status: None,
        msg_fast_tx: None,
        msg_tx_hold: None,
        msg_tx_interval: None,
        reinit_delay: None,
        tx_credit_max: None,
        tx_fast_init: None,
        tx_credit: 0,
        tx_fast: 0,
    };

    iface_hash.insert(name, Mutex::new(interface));

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
