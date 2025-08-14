// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::net::IpAddr;

use anyhow::Context;
use chrono::DateTime;
use chrono::Utc;
use futures::stream::TryStreamExt;
use structopt::*;

use lldpd_client::default_port;
use lldpd_client::types;
use lldpd_client::Client;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "lldpadm",
    about = "provides a command-line interface to the Oxide LLDP daemon",
    version = "0.0.1"
)]
struct GlobalOpts {
    #[structopt(short, long, help = "LLDP daemon's hostname or IP address")]
    host: Option<String>,

    #[structopt(help = "daemon's TCP port", short, long)]
    port: Option<u16>,

    #[structopt(subcommand)]
    cmd: Commands,
}

#[derive(Debug, StructOpt)]
enum IfaceSetProp {
    #[structopt(visible_alias = "cid")]
    ChassisId { iface: String, chassis_id: String },
    #[structopt(visible_alias = "pid")]
    PortId { iface: String, id: String },
    #[structopt(visible_alias = "portdesc")]
    PortDescription { iface: String, desc: String },
    #[structopt(visible_alias = "sysname")]
    SystemName { iface: String, name: String },
    #[structopt(visible_alias = "sysdesc")]
    SystemDescription { iface: String, desc: String },
}

#[derive(Debug, StructOpt)]
enum IfaceDelProp {
    #[structopt(visible_alias = "cid")]
    ChassisId { iface: String },
    #[structopt(visible_alias = "portdesc")]
    PortDescription { iface: String },
    #[structopt(visible_alias = "sysname")]
    SystemName { iface: String },
    #[structopt(visible_alias = "sysdesc")]
    SystemDescription { iface: String },
}

#[derive(Debug, StructOpt)]
enum IfaceProp {
    /// Set an interface-level property
    Set(IfaceSetProp),
    /// Delete an interface-level property
    Del(IfaceDelProp),
}

#[derive(Debug, StructOpt)]
enum Capability {
    /// Add to the list of available capabilities
    Add { _cap: String },
    /// Remove the list of available capabilities
    Remove { _cap: String },
    /// Advertise an available capability as enabled
    Enable { _cap: String },
    /// Stop advertising an available capability as enabled
    Disable { _cap: String },
    /// Clear all available and enabled capabilities
    Clear,
}

#[derive(Debug, StructOpt)]
enum IfaceAddress {
    /// Add a single address to the list of advertised management addresses
    Add { iface: String, addr: IpAddr },
    /// Remove a single address from the list of advertised management addresses
    Del { iface: String, addr: IpAddr },
    /// Remove all management addresses
    Clear { iface: String },
}

#[derive(Debug, StructOpt)]
enum Interface {
    /// Add a new interface
    Add {
        #[structopt(long, short = "c")]
        chassis_id: Option<String>,
        #[structopt(long, short = "p")]
        port_id: Option<String>,
        #[structopt(long)]
        system_name: Option<String>,
        #[structopt(long)]
        system_description: Option<String>,
        #[structopt(long)]
        port_description: Option<String>,
        iface: String,
    },
    /// Remove interface
    Del { iface: String },
    /// Manage a property on the interface
    Prop(IfaceProp),
    /// Manage the advertised capabilities for the interface
    #[structopt(visible_alias = "cap")]
    Capability(Capability),
    /// Manage the management addresses for the interface
    #[structopt(visible_alias = "addr")]
    Address(IfaceAddress),
    /// Get a single configured interface
    Get { iface: String },
    /// List all configured interfaces
    #[structopt(visible_alias = "ls")]
    List,
    /// Locally disable lldp on the interface.  This refers strictly to
    /// local interface plumbing, and is independent of the LLDP protocol's
    /// administrative tx/rx disablement.
    Disable { iface: String },
    /// Clear the locally set disable flag.
    Enable { iface: String },
}

#[derive(Debug, StructOpt)]
/// Set a property for the whole system, which may be overridden by
/// per-interface settings.
enum SystemSetProp {
    /// Change the ChassisId advertised on all interfaces
    #[structopt(visible_alias = "cid")]
    ChassisId { chassis_id: String },
    /// Change the system name advertised on all interfaces
    #[structopt(visible_alias = "sysname")]
    SystemName { name: String },
    /// Change the system description advertised on all interfaces
    #[structopt(visible_alias = "sysdesc")]
    SystemDescription { desc: String },
}

#[derive(Debug, StructOpt)]
/// Clear system level properties.  Some properties are required, and can only
/// by changed - not removed.
enum SystemDelProp {
    #[structopt(visible_alias = "name")]
    SystemName,
    #[structopt(visible_alias = "desc")]
    SystemDescription,
}

#[derive(Debug, StructOpt)]
enum SystemProp {
    /// Set a system level property
    Set(SystemSetProp),
    /// Delete a system level property
    Del(SystemDelProp),
}

#[derive(Debug, StructOpt)]
enum SystemAddress {
    /// Add a single address to the list of advertised management addresses
    Add { addr: IpAddr },
    /// Remove a single address from the list of advertised management addresses
    Del { addr: IpAddr },
    /// Remove all management addresses
    Clear,
}

#[derive(Debug, StructOpt)]
enum System {
    /// Manage a property on the system
    Prop(SystemProp),
    /// Manage the advertised capabilities for the system
    #[structopt(visible_alias = "cap")]
    Capability(Capability),
    /// Manage the management addresses for the system
    #[structopt(visible_alias = "addr")]
    Address(SystemAddress),
}

#[derive(Debug, StructOpt)]
enum Commands {
    /// Print detailed build information about the `lldpd` server.
    #[structopt(visible_alias = "build")]
    BuildInfo,
    /// Manage system-level settings, most of which can be overridden at the
    /// interface level with per-interface settings.
    #[structopt(visible_alias = "sys")]
    System(System),
    /// Manage interface population and properties.
    #[structopt(visible_alias = "iface")]
    Interface(Interface),
    /// Get the neighbors the daemon has seen
    #[structopt(visible_alias = "ne")]
    Neighbors,
}

async fn build_info(client: &Client) -> anyhow::Result<()> {
    let info = client
        .build_info()
        .await
        .context("failed to get build information")?
        .into_inner();
    println!("Version: {}", info.version);
    println!("Commit SHA: {}", info.git_sha);
    println!("Commit timestamp: {}", info.git_commit_timestamp);
    println!("Git branch: {}", info.git_branch);
    println!("Rustc version: {}", info.rustc_semver);
    println!("Rustc channel: {}", info.rustc_channel);
    println!("Rustc triple: {}", info.rustc_host_triple);
    println!("Rustc commit SHA: {}", info.rustc_commit_sha);
    println!("Cargo triple: {}", info.cargo_triple);
    println!("Debug: {}", info.debug);
    println!("Opt level: {}", info.opt_level);
    Ok(())
}

fn display_sysinfo(s: &types::SystemInfo) {
    println!("\tChassisID: {:?}", s.chassis_id);
    println!("\tPortId: {:?}", s.port_id);
    println!("\tTTL:  {} seconds", s.ttl);
    if let Some(s) = &s.port_description {
        println!("\tPortDescription: {s}");
    }
    if let Some(s) = &s.system_name {
        println!("\tSystem Name: {s}");
    }
    if let Some(s) = &s.system_description {
        println!("\tSystem Description: {s}");
    }
    println!("\tCapabilities Available: {:?}", s.capabilities_available);
    println!("\tCapabilities Enabled: {:?}", s.capabilities_enabled);
    if !s.management_addresses.is_empty() {
        println!("\tManagement addresses:");
        for ma in &s.management_addresses {
            println!("\t\t{ma:?}");
        }
    }
    if !s.organizationally_specific.is_empty() {
        println!("\tOrganizationally Specific:");
        for os in &s.organizationally_specific {
            println!("\t\t{os}");
        }
    }
}

async fn system_prop(client: &Client, prop: SystemProp) -> anyhow::Result<()> {
    match prop {
        SystemProp::Set(set) => match set {
            SystemSetProp::ChassisId { chassis_id } => {
                // TODO-completeness: allow for different kinds of chassis IDs
                let id = types::ChassisId::ChassisComponent(chassis_id);
                client.sys_set_chassis_id(&id).await
            }
            SystemSetProp::SystemName { name } => {
                client.sys_set_system_name(&name).await
            }
            SystemSetProp::SystemDescription { desc } => {
                client.sys_set_system_description(&desc).await
            }
        },
        SystemProp::Del(del) => match del {
            SystemDelProp::SystemName => client.sys_del_system_name().await,
            SystemDelProp::SystemDescription => {
                client.sys_del_system_description().await
            }
        },
    }
    .map(|r| r.into_inner())
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

async fn system_addr(
    client: &Client,
    addr: SystemAddress,
) -> anyhow::Result<()> {
    match addr {
        SystemAddress::Add { addr } => {
            client.sys_add_management_addr(&addr).await
        }
        SystemAddress::Del { addr } => {
            client.sys_del_management_addr(&addr).await
        }
        SystemAddress::Clear => client.sys_clear_management_addr().await,
    }
    .map(|r| r.into_inner())
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

fn system_capability(cap: Capability) -> anyhow::Result<()> {
    println!("{cap:?}");
    Ok(())
}

fn age(now: DateTime<Utc>, then: DateTime<Utc>) -> String {
    let mut secs = (now - then).to_std().unwrap().as_secs();
    let mut mins = secs / 60;
    secs -= mins * 60;
    let mut hours = mins / 60;
    mins -= hours * 60;
    let days = hours / 24;
    hours -= days * 24;
    if days > 0 {
        format!("{days}d{hours}h{mins}m{secs}s")
    } else if hours > 0 {
        format!("{hours}h{mins}m{secs}s")
    } else if mins > 0 {
        format!("{mins}m{secs}s")
    } else {
        format!("{secs}s")
    }
}

fn display_neighbor(n: &types::Neighbor) {
    let now = Utc::now();
    if now > n.first_seen && now > n.last_seen && now > n.last_changed {
        println!("\tfirst seen:   {:>7} ago", age(now, n.first_seen));
        println!("\tlast seen:    {:>7} ago", age(now, n.last_seen));
        println!("\tlast changed: {:>7} ago", age(now, n.last_changed));
    } else {
        println!("\ttime skew detected.  local 'now': {now:?}");
        println!("\tfirst seen:    {}", n.first_seen);
        println!("\tlast seen:     {}", n.last_seen);
        println!("\tlast changed:  {}", n.last_changed);
    }
    display_sysinfo(&n.system_info);
}

fn display_interface(i: &types::Interface) {
    println!(
        "port: {} interface: {}{}",
        i.port,
        i.iface,
        match i.disabled {
            true => " [Disabled]",
            false => "",
        }
    );
    display_sysinfo(&i.system_info);
}

async fn interface_prop(
    client: &Client,
    prop: IfaceProp,
) -> anyhow::Result<()> {
    match prop {
        IfaceProp::Set(set) => match set {
            IfaceSetProp::ChassisId { iface, chassis_id } => {
                // TODO-completeness: allow for different kinds of chassis IDs
                let id = types::ChassisId::ChassisComponent(chassis_id);
                client.interface_set_chassis_id(&iface, &id).await
            }
            IfaceSetProp::PortId { iface, id } => {
                // TODO-completeness: allow for different kinds of port IDs
                let port_id = types::PortId::PortComponent(id);
                client.interface_set_port_id(&iface, &port_id).await
            }
            IfaceSetProp::PortDescription { iface, desc } => {
                client.interface_set_port_description(&iface, &desc).await
            }
            IfaceSetProp::SystemName { iface, name } => {
                client.interface_set_system_name(&iface, &name).await
            }
            IfaceSetProp::SystemDescription { iface, desc } => {
                client.interface_set_system_description(&iface, &desc).await
            }
        },
        IfaceProp::Del(del) => match del {
            IfaceDelProp::ChassisId { iface } => {
                client.interface_del_chassis_id(&iface).await
            }
            IfaceDelProp::PortDescription { iface } => {
                client.interface_del_port_description(&iface).await
            }
            IfaceDelProp::SystemName { iface } => {
                client.interface_del_system_name(&iface).await
            }
            IfaceDelProp::SystemDescription { iface } => {
                client.interface_del_system_description(&iface).await
            }
        },
    }
    .map(|r| r.into_inner())
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

fn interface_capability(cap: Capability) -> anyhow::Result<()> {
    println!("{cap:?}");
    Ok(())
}

async fn interface_addr(
    client: &Client,
    addr: IfaceAddress,
) -> anyhow::Result<()> {
    match addr {
        IfaceAddress::Add { iface, addr } => {
            client.interface_add_management_addr(&iface, &addr).await
        }
        IfaceAddress::Del { iface, addr } => {
            client.interface_del_management_addr(&iface, &addr).await
        }
        IfaceAddress::Clear { iface } => {
            client.interface_clear_management_addr(&iface).await
        }
    }
    .map(|r| r.into_inner())
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = GlobalOpts::from_args();
    let port = opts.port.unwrap_or_else(default_port);
    let host = opts.host.unwrap_or_else(|| "localhost".to_string());
    let log = slog::Logger::root(slog::Discard, slog::o!());

    let api_log = log.new(slog::o!("unit" => "api"));
    let client = Client::new(&format!("http://{host}:{port}"), api_log);

    match opts.cmd {
        Commands::BuildInfo => build_info(&client).await,
        Commands::System(sub) => match sub {
            System::Prop(prop) => system_prop(&client, prop).await,
            System::Capability(cap) => system_capability(cap),
            System::Address(address) => system_addr(&client, address).await,
        },
        Commands::Interface(sub) => match sub {
            Interface::Add {
                chassis_id,
                port_id,
                system_name,
                system_description,
                port_description,
                iface,
            } => {
                // TODO-completeness: allow for other types of chassis ID
                let chassis_id =
                    chassis_id.map(types::ChassisId::ChassisComponent);
                // TODO-completeness: allow for other types of port ID
                let port_id = port_id.map(types::PortId::PortComponent);
                let add_args = types::InterfaceAdd {
                    chassis_id,
                    port_id,
                    system_name,
                    system_description,
                    port_description,
                };
                client
                    .interface_add(&iface, &add_args)
                    .await
                    .map(|r| r.into_inner())
                    .context("failed to add interface")
            }
            Interface::Del { iface } => client
                .interface_del(&iface)
                .await
                .map(|r| r.into_inner())
                .context("failed to remove interface"),
            Interface::Prop(prop) => interface_prop(&client, prop).await,
            Interface::Capability(cap) => interface_capability(cap),
            Interface::Address(address) => {
                interface_addr(&client, address).await
            }
            Interface::Get { iface } => client
                .interface_get(&iface)
                .await
                .map(|r| display_interface(&r.into_inner()))
                .context("failed to get interface"),
            Interface::List => client
                .interface_list()
                .await
                .map(|r| r.into_inner().iter().for_each(display_interface))
                .context("failed to get interface list"),
            Interface::Disable { iface } => client
                .interface_set_disabled(&iface, true)
                .await
                .map(|_| ())
                .context("failed to set the disabled flag"),
            Interface::Enable { iface } => client
                .interface_set_disabled(&iface, false)
                .await
                .map(|_| ())
                .context("failed to clear the disabled flag"),
        },
        Commands::Neighbors => {
            for iface in client
                .interface_list()
                .await
                .context("failed to get interface list")?
                .iter()
            {
                let neighbors: Vec<types::Neighbor> = client
                    .get_neighbors_stream(&iface.port, None)
                    .try_collect()
                    .await?;
                for n in neighbors {
                    println!("On interface {}", n.port);
                    display_neighbor(&n);
                }
            }
            Ok(())
        }
    }
}
