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

#[cfg(target_os = "illumos")]
use crate::plat_illumos as plat;
#[cfg(target_os = "linux")]
use crate::plat_linux as plat;

#[derive(Debug)]
pub struct Interface {
    log: slog::Logger,

    /// Name of the interface on which LLDPDUs are sent and received.
    /// For sidecar ports, this will be the tfport.
    pub iface: String,
    pub mac: MacAddr,

    /// Configurable properties
    pub chassis_id: Option<protocol::ChassisId>,
    pub port_id: protocol::PortId,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,
    pub management_addrs: Option<BTreeSet<IpAddr>>,

    /// Counters of packets in, packets out, etc.
    pub stats: Stats,

    /// Neighbors we are currently aware of
    pub neighbors: BTreeMap<types::NeighborId, types::Neighbor>,

    pub msg_tx: mpsc::Sender<InterfaceMsg>,

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
    _reinit_delay: Option<u16>,
    /// Maximum value of tx_credit.  If None, default to the agent-level setting
    _tx_credit_max: Option<u16>,
    /// Initial value of tx_fast.  If None, default to the agent-level setting
    tx_fast_init: Option<u16>,

    /// The values below are variables defined in section 9.2.5 of the standard.
    /// These are set dynamically by the various state machines as the daemon
    /// runs.  The standard defines a number of variables that are not reflected
    /// here, as we implement them as per-task timers or inter-task messages
    /// rather than as flag variables.

    /// Number of LLDPDUs that can be transmitted at any one time
    _tx_credit: u16,
    /// If this value is non-0, this interface is in fast tx mode, with tx_fast
    /// packets remaining to send
    tx_fast: u16,
}

/// Settings that can be updated via SMF
#[derive(Debug)]
pub struct InterfaceCfg {
    pub chassis_id: Option<protocol::ChassisId>,
    pub port_id: Option<protocol::PortId>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub port_description: Option<String>,
    pub management_addrs: Option<BTreeSet<IpAddr>>,
    pub admin_status: Option<types::AdminStatus>,
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
    _tlvs_discarded_total: u64,
    /// Well-formed TLVs that were discarded because they were not recognized.
    _tlvs_unrecognized_total: u64,
    /// LLDPDUs that were discarded because they violated a length restriction
    _lldpdu_length_errors: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceMsg {
    UpdatedInfo,
    TimeToGo,
}

macro_rules! maybe_update {
    ($a:ident, $b:ident, $field:ident) => {
        if $a.$field != $b.$field {
            $a.$field = $b.$field.clone();
            true
        } else {
            false
        }
    };
}

impl Interface {
    // Given an InterfaceCfg structure, update any fields in the Interface
    // that don't match.  If any fields were modified, return "true".  If
    // the Interface is unchanged, return "false".
    pub fn update_from_cfg(&mut self, cfg: &InterfaceCfg) -> bool {
        let mut updated = false;

        if let Some(port_id) = &cfg.port_id {
            if self.port_id != *port_id {
                self.port_id = port_id.clone();
                updated = true;
            }
        }

        updated |= maybe_update!(self, cfg, chassis_id);
        updated |= maybe_update!(self, cfg, system_name);
        updated |= maybe_update!(self, cfg, system_description);
        updated |= maybe_update!(self, cfg, port_description);
        updated |= maybe_update!(self, cfg, management_addrs);
        updated |= maybe_update!(self, cfg, admin_status);

        updated
    }

    /// Ask the interface loop to shut itself down and clean up after itself.
    pub async fn shutdown(&mut self) {
        let _ = self.msg_tx.send(InterfaceMsg::TimeToGo).await;
    }
}

// Convenience macro to look for an interface in the hash and return a
// consistent error if it's not found.
fn get_interface(
    g: &Global,
    iface: &str,
) -> LldpdResult<Arc<Mutex<Interface>>> {
    g.interfaces
        .lock()
        .unwrap()
        .get(iface)
        .ok_or(LldpdError::Missing(format!("no such interface: {iface}")))
        .cloned()
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

    // The advertised TTL is derived by multiplying the tx_interval by the
    // tx_hold.
    let tx_interval = iface
        .msg_tx_interval
        .unwrap_or(switchinfo.agent.msg_tx_interval);
    let tx_hold = iface.msg_tx_hold.unwrap_or(switchinfo.agent.msg_tx_hold);
    let ttl: u16 = tx_interval.saturating_mul(tx_hold);

    let management_addresses = iface
        .management_addrs
        .as_ref()
        .unwrap_or(&switchinfo.management_addrs)
        .iter()
        .map(|addr| protocol::ManagementAddress {
            addr: *addr,
            // TODO-completeness: include an interface number with each
            // management address.
            interface_num: protocol::InterfaceNum::Unknown(0),
            oid: None,
        })
        .collect();

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
        ttl,
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
#[allow(clippy::expect_fun_call)]
fn build_lldpdu_packet(
    switchinfo: &crate::SwitchInfo,
    iface: &Interface,
) -> Packet {
    let lldpdu = build_lldpdu(switchinfo, iface);
    let tlvs: Vec<LldpTlv> = (&lldpdu)
        .try_into()
        .expect(&format!("we constructed an invalid LLDPDU: {lldpdu:#?}"));

    let tgt_mac: MacAddr = protocol::Scope::Bridge.into();
    let mut packet = Packet::new(tgt_mac, iface.mac);
    tlvs.iter().for_each(|tlv| packet.add_tlv(tlv));

    packet
}

// Construct an LLDPDU packet with a TTL of 0 to notify neighbors that this
// interface is going away immediately.
#[allow(clippy::expect_fun_call)]
fn build_shutdown_packet(
    switchinfo: &crate::SwitchInfo,
    iface: &Interface,
) -> Packet {
    let lldpdu = build_lldpdu(switchinfo, iface);
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
fn error_accounting(iface: &mut Interface, _error: LldpdError) {
    iface.stats.frames_in_errors_total += 1;
    iface.stats.frames_discarded_total += 1;
}

// Process a single packet that arrived on our transport.
fn handle_packet(
    switchinfo: &crate::SwitchInfo,
    iface: &mut Interface,
    data: &[u8],
) {
    iface.stats.frames_in_total += 1;
    // Given a raw packet, extract the ethernet and LLDP headers and drop
    // anything else.
    let packet = match Packet::parse(data) {
        Ok(Some(packet)) => packet,
        Ok(None) => return, // non-LLDP packet
        Err(e) => {
            debug!(iface.log, "failed to parse packet: {:?}", e);
            return error_accounting(iface, e);
        }
    };

    // Parse each of the TLVs in the LLDP header trying to build a valid LLDPDU
    // structure.
    let lldpdu = match Lldpdu::try_from(&packet.lldp_hdr.lldp_data) {
        Ok(lldpdu) => lldpdu,
        Err(e) => {
            error!(iface.log, "parsing LLDP packet failed: {e:?}");
            // TODO-completeness: examine the error details to detect the
            // specific failure modes for which the spec has counters.
            return error_accounting(iface, e);
        }
    };
    let id = types::NeighborId::new(&lldpdu);

    // If one of our own LLDPDUs was reflected back to us, drop it
    if match &iface.chassis_id {
        Some(chassis_id) => chassis_id == &lldpdu.chassis_id,
        None => switchinfo.chassis_id == lldpdu.chassis_id,
    } {
        return;
    }

    // Is this is new neighbor, an update from an old neighbor, or just a
    // periodic re-advertisement of the same old stuff?
    match iface.neighbors.entry(id.clone()) {
        Entry::Vacant(e) => {
            let sysinfo: types::SystemInfo = (&lldpdu).into();
            let neighbor = types::Neighbor::from_lldpdu(&lldpdu);
            info!(iface.log, "new neighbor {:?}: {}", id, &sysinfo);
            e.insert(neighbor);
        }
        Entry::Occupied(old) => {
            // A TTL of 0 is a signal that the neighbor is going away.  This
            // doesn't require any special handling here, as the updated
            // "expires_at" field will cause it to be cleaned up
            // automatically.
            let ttl = std::time::Duration::from_secs(lldpdu.ttl as u64);
            let now = Utc::now();
            let old = old.into_mut();
            old.last_seen = now;
            old.expires_at = now + ttl;
            if old.lldpdu != lldpdu {
                let sysinfo: types::SystemInfo = (&lldpdu).into();
                old.last_changed = now;
                old.lldpdu = lldpdu;
                info!(iface.log, "updated neighbor {:?}: {}", id, &sysinfo);
            } else {
                trace!(iface.log, "refresh neighbor {:?}", id);
            }
        }
    };
}

// Construct and transmit an LLDPDU on this interface.  Return the number of
// ticks to delay before issuing the next one.
async fn tx_lldpdu(
    switchinfo: &crate::SwitchInfo,
    iface_lock: &Mutex<Interface>,
    transport: &Transport,
) -> u16 {
    let ticks;
    let log;

    let packet = {
        let mut iface = iface_lock.lock().unwrap();
        log = iface.log.clone();

        let status =
            iface.admin_status.unwrap_or(switchinfo.agent.admin_status);

        if !status.has_tx() {
            return u16::MAX;
        }

        if iface.tx_fast > 0 {
            iface.tx_fast -= 1;
            ticks = iface.msg_fast_tx.unwrap_or(switchinfo.agent.msg_fast_tx);
        } else {
            ticks = iface
                .msg_tx_interval
                .unwrap_or(switchinfo.agent.msg_tx_interval);
        }
        build_lldpdu_packet(switchinfo, &iface)
    };

    trace!(log, "transmit LLDPDU");
    match xmit_lldpdu(transport, packet).await {
        Err(e) => error!(log, "failed to xmit lldpdu"; "err" => e.to_string()),
        Ok(_) => iface_lock.lock().unwrap().stats.frames_out_total += 1,
    }
    ticks
}

// Construct and transmit a "shutting down" LLDPDU on this interface.
async fn tx_shutdown(
    switchinfo: &crate::SwitchInfo,
    iface_lock: &Mutex<Interface>,
    transport: &Transport,
) {
    let log;

    let packet = {
        let iface = iface_lock.lock().unwrap();
        log = iface.log.clone();

        let status =
            iface.admin_status.unwrap_or(switchinfo.agent.admin_status);

        if !status.has_tx() {
            return;
        }

        build_shutdown_packet(switchinfo, &iface)
    };

    trace!(&log, "transmit shutdown LLDPDU");
    match xmit_lldpdu(transport, packet).await {
        Err(e) => error!(&log, "failed to xmit lldpdu"; "err" => e.to_string()),
        Ok(_) => iface_lock.lock().unwrap().stats.frames_out_total += 1,
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
fn transport_init(iface: &str) -> LldpdResult<(Transport, AsyncFd<i32>)> {
    let transport = plat::Transport::new(iface)?;
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
    iface_lock: Arc<Mutex<Interface>>,
    mut msg_rx: mpsc::Receiver<InterfaceMsg>,
) {
    let iface_name = iface_lock.lock().unwrap().iface.clone();
    let log = iface_lock.lock().unwrap().log.clone();

    debug!(log, "Interface loop started");
    let (transport, asyncfd) =
        match transport_init(&iface_name) {
            Ok((t, a)) => (t, a),
            Err(e) => {
                // TODO: add a "failed" state to interfaces in the hash so the
                // client can retrieve an error message, rather than having them
                // silently disappear
                error!(log, "failed to init transport: {e:?}");
                g.interfaces.lock().unwrap().remove(&name).expect(
                    "interface hash entry should persist until task exits",
                );
                return;
            }
        };

    let mut buf = [0u8; 4096];
    let mut next_tx = Instant::now();
    loop {
        // Scan the neighbor list for any whose TTL has expired
        {
            let now = Utc::now();
            let mut iface = iface_lock.lock().unwrap();
            let expired: Vec<types::NeighborId> = iface
                .neighbors
                .iter()
                .filter(|(_id, n)| {
                    let ttl = Duration::from_secs(n.lldpdu.ttl as u64);
                    n.last_seen + ttl < now
                })
                .map(|(id, _n)| id.clone())
                .collect();

            for id in &expired {
                info!(iface.log, "neighbor {id:?} TTL expired");
                iface.neighbors.remove(id);
                iface.stats.ageouts_total += 1;
            }
        }

        // Is it time for another advertisement?
        if Instant::now() > next_tx {
            let switchinfo = g.switchinfo.lock().unwrap().clone();
            let ticks = tx_lldpdu(&switchinfo, &iface_lock, &transport).await;
            next_tx = Instant::now() + Duration::from_secs(ticks as u64);
        }

        match wait_for_event(&mut msg_rx, &asyncfd, next_tx).await {
            WakeupEvent::Message(msg) => match msg {
                InterfaceMsg::TimeToGo => break,
                // TODO-completeness: use the tx_credit mechanism to avoid
                // spamming if we have a lot of updates in quick succession.
                InterfaceMsg::UpdatedInfo => next_tx = Instant::now(),
            },
            WakeupEvent::FdReady => match transport.packet_recv(&mut buf) {
                Ok(None) => { /* spurious wakeup? */ }
                Ok(Some(n)) => {
                    let switchinfo = g.switchinfo.lock().unwrap().clone();
                    let mut iface = iface_lock.lock().unwrap();
                    let old_neighbors = iface.neighbors.len();

                    handle_packet(&switchinfo, &mut iface, &buf[0..n]);

                    // If we discovered a new neighbor, we switch into fast_tx
                    // mode and immediately send an LLDPDU.
                    if old_neighbors < iface.neighbors.len() {
                        iface.tx_fast = iface
                            .tx_fast_init
                            .unwrap_or(switchinfo.agent.tx_fast_init);
                        next_tx = Instant::now();
                    }
                }
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

    let switchinfo = g.switchinfo.lock().unwrap().clone();
    tx_shutdown(&switchinfo, &iface_lock, &transport).await;

    debug!(log, "interface loop shutting down");
    g.interfaces
        .lock()
        .unwrap()
        .remove(&name)
        .expect("interface hash entry should persist until task exits");
}

pub async fn interface_add(
    global: &Arc<Global>,
    name: String,
    cfg: InterfaceCfg,
) -> LldpdResult<()> {
    info!(&global.log, "Adding interface"; "name" => name.to_string());

    let port_id = cfg
        .port_id
        .unwrap_or(protocol::PortId::InterfaceName(name.to_string()));
    let (iface, mac) = plat::get_iface_and_mac(global, &name).await?;

    let mut iface_hash = global.interfaces.lock().unwrap();
    if iface_hash.get(&name).is_some() {
        return Err(LldpdError::Exists("interface already added".into()));
    }

    let log = global.log.new(slog::o!(
	"port" => name.to_string(),
	"iface" => iface.to_string()));
    let (msg_tx, msg_rx) = mpsc::channel(1);
    let global = global.clone();
    let task_name = name.clone();

    let interface = Interface {
        log,
        iface,
        mac,
        chassis_id: cfg.chassis_id,
        port_id,
        system_name: cfg.system_name,
        system_description: cfg.system_description,
        port_description: cfg.port_description,
        management_addrs: cfg.management_addrs,
        msg_tx,

        stats: Stats::default(),
        neighbors: BTreeMap::new(),

        admin_status: cfg.admin_status,
        msg_fast_tx: None,
        msg_tx_hold: None,
        msg_tx_interval: None,
        _reinit_delay: None,
        _tx_credit_max: None,
        _tx_credit: 0,
        tx_fast_init: None,
        tx_fast: 0,
    };

    let iface_lock = Arc::new(Mutex::new(interface));
    iface_hash.insert(name, iface_lock.clone());

    let _hdl = tokio::task::spawn(async move {
        interface_loop(global, task_name, iface_lock, msg_rx).await
    });

    Ok(())
}

pub async fn interface_remove(
    global: &Arc<Global>,
    name: String,
) -> LldpdResult<()> {
    for tries in 1..11 {
        {
            // Look in the hash for this interface.  If we find it, make a
            // copy of the tx channel needed to ask it to shut down.
            let msg_tx = {
                let iface_hash = global.interfaces.lock().unwrap();
                iface_hash
                    .get(&name)
                    .map(|iface| iface.lock().unwrap().msg_tx.clone())
            };

            // If this is our first attempt to shut down the interface, but we
            // don't have a tx channel, it means the interface wasn't
            // configured.  If it's not the first attempt, it means that the
            // interface has shut down in response to our message.
            match (tries, msg_tx) {
                (_, Some(tx)) => {
                    info!(global.log, "Shutting down {name}. Attempt: {tries}");
                    let _ = tx.send(InterfaceMsg::TimeToGo).await;
                }
                (1, None) => {
                    return Err(LldpdError::Missing(
                        "no such interface configured".into(),
                    ))
                }
                (_, None) => {
                    info!(global.log, "Monitor loop for {name} shut down");
                    return Ok(());
                }
            };
        }
        let _ = tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(LldpdError::Other(
        "interface monitor loop failed to shut down".into(),
    ))
}

pub async fn shutdown_all(g: &Global) {
    debug!(&g.log, "shutting down interface tasks");
    let msgs: Vec<mpsc::Sender<InterfaceMsg>> = g
        .interfaces
        .lock()
        .unwrap()
        .values()
        .map(|i| i.lock().unwrap().msg_tx.clone())
        .collect();

    for msg_tx in &msgs {
        let _ = msg_tx.send(InterfaceMsg::TimeToGo).await;
    }
    debug!(&g.log, "waiting for tasks to exit");
    while !g.interfaces.lock().unwrap().is_empty() {
        let _ = tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(feature = "smf")]
pub async fn update_from_cfg(
    g: &Global,
    name: &String,
    cfg: &InterfaceCfg,
) -> LldpdResult<()> {
    let msg_tx = {
        let iface = get_interface(g, name)?;
        let mut iface = iface.lock().unwrap();

        if !iface.update_from_cfg(cfg) {
            return Ok(());
        }
        info!(g.log, "updated {name} to {iface:#?}");
        iface.msg_tx.clone()
    };

    let _ = msg_tx.send(InterfaceMsg::UpdatedInfo).await;
    Ok(())
}

/// Update a property belonging to an interface, and send the interface loop
/// a message indicating the change.
pub async fn update_interface(
    g: &Global,
    name: &str,
    f: impl FnOnce(&mut Interface) -> LldpdResult<()>,
) -> LldpdResult<()> {
    let msg_tx = {
        let iface = get_interface(g, name)?;
        let mut iface = iface.lock().unwrap();
        f(&mut iface)?;
        iface.msg_tx.clone()
    };

    let _ = msg_tx.send(InterfaceMsg::UpdatedInfo).await;
    Ok(())
}

/// Add a single management addresses to an interface.
pub async fn addr_add(
    g: &Global,
    name: &String,
    addr: &IpAddr,
) -> LldpdResult<()> {
    info!(g.log, "adding management address";
	    "iface" => name, "addr" => addr.to_string());
    update_interface(g, name, |iface| {
        if iface.management_addrs.is_none() {
            iface.management_addrs = Some(BTreeSet::new());
        }
        iface
            .management_addrs
            .as_mut()
            .expect("existence guaranteed above")
            .insert(*addr);
        Ok(())
    })
    .await
}

/// Set the interface-local chassis id
pub async fn chassis_id_set(
    g: &Global,
    name: &String,
    chassis_id: protocol::ChassisId,
) -> LldpdResult<()> {
    info!(g.log, "setting interface-level chassis ID";
	    "iface" => name, "chassis_id" => chassis_id.to_string());
    update_interface(g, name, |iface| {
        iface.chassis_id = Some(chassis_id);
        Ok(())
    })
    .await
}

/// Clearing the interface-local chassis id
pub async fn chassis_id_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level chassis ID"; "iface" => name);
    update_interface(g, name, |iface| {
        iface.chassis_id = None;
        Ok(())
    })
    .await
}

/// Set the port id
pub async fn port_id_set(
    g: &Global,
    name: &String,
    port_id: protocol::PortId,
) -> LldpdResult<()> {
    info!(g.log, "setting port ID";
	    "iface" => name, "port_id" => port_id.to_string());
    update_interface(g, name, |iface| {
        iface.port_id = port_id;
        Ok(())
    })
    .await
}

/// Set the port description
pub async fn port_desc_set(
    g: &Global,
    name: &String,
    desc: &String,
) -> LldpdResult<()> {
    info!(g.log, "setting port description";
	    "iface" => name, "port_desc" => desc.to_string());
    update_interface(g, name, |iface| {
        iface.port_description = Some(desc.to_string());
        Ok(())
    })
    .await
}

/// Clearing the port description
pub async fn port_desc_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level port ID"; "iface" => name);
    update_interface(g, name, |iface| {
        iface.port_description = None;
        Ok(())
    })
    .await
}

/// Set the interface-local system name
pub async fn system_name_set(
    g: &Global,
    name: &String,
    sysname: &String,
) -> LldpdResult<()> {
    info!(g.log, "setting interface-level system name";
	    "iface" => name, "sysname" =>sysname.to_string());
    update_interface(g, name, |iface| {
        iface.system_name = Some(sysname.to_string());
        Ok(())
    })
    .await
}

/// Clearing the interface-local system name
pub async fn system_name_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level port ID"; "iface" => name);
    update_interface(g, name, |iface| {
        iface.system_name = None;
        Ok(())
    })
    .await
}

/// Set the interface-local system name
pub async fn system_desc_set(
    g: &Global,
    name: &String,
    sysdesc: &String,
) -> LldpdResult<()> {
    info!(g.log, "setting interface-level system description";
	    "iface" => name, "sysdesc" =>sysdesc.to_string());
    update_interface(g, name, |iface| {
        iface.system_description = Some(sysdesc.to_string());
        Ok(())
    })
    .await
}

/// Clearing the interface-local system description
pub async fn system_desc_del(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "clearing interface-level system description"; "iface" => name);
    update_interface(g, name, |iface| {
        iface.system_description = None;
        Ok(())
    })
    .await
}

/// Remove a single management addresses from an interface.
pub async fn addr_delete(
    g: &Global,
    name: &String,
    addr: &IpAddr,
) -> LldpdResult<()> {
    info!(g.log, "removing management address";
	    "iface" => name, "addr" => addr.to_string());
    update_interface(g, name, |iface| {
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
    })
    .await
}

/// Remove all management addresses on an interface.
pub async fn addr_delete_all(g: &Global, name: &String) -> LldpdResult<()> {
    info!(g.log, "removing all management addresses"; "iface" => name);
    update_interface(g, name, |iface| {
        iface.management_addrs = None;
        Ok(())
    })
    .await
}
