use std::net::IpAddr;

use anyhow::Context;
use chrono::DateTime;
use chrono::Utc;
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
enum SetProp {
    #[structopt(visible_alias = "c")]
    ChassisId {
        _iface: String,
        _chassis_id: String,
    },
    PortId {
        _iface: String,
        _id: String,
    },
    Ttl {
        _iface: String,
        _ttl: u16,
    },
    PortDescrption {
        _iface: String,
        _desc: String,
    },
    SystemName {
        _iface: String,
        _name: String,
    },
    SystemDescrption {
        _iface: String,
        _desc: String,
    },
}

#[derive(Debug, StructOpt)]
enum DelProp {
    #[structopt(visible_alias = "c")]
    ChassisId {
        _iface: String,
    },
    PortId {
        _iface: String,
    },
    Ttl {
        _iface: String,
    },
    PortDescrption {
        _iface: String,
    },
    SystemName {
        _iface: String,
    },
    SystemDescrption {
        _iface: String,
    },
}

#[derive(Debug, StructOpt)]
enum Prop {
    Set(SetProp),
    Del(DelProp),
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
enum Address {
    /// Add a single address to the list of advertised management addresses
    Add { _addr: IpAddr },
    /// Remove a single address from the list of advertised management addresses
    Del { _addr: IpAddr },
    /// Remove all management addresses
    Clear,
}

#[derive(Debug, StructOpt)]
enum Interface {
    /// Add a new interface
    Add {
        #[structopt(long, short = "c")]
        chassis_id: Option<String>,
        #[structopt(long, short = "p")]
        port_id: Option<String>,
        #[structopt(long, short = "t")]
        ttl: Option<u16>,
        #[structopt(long)]
        system_name: Option<String>,
        #[structopt(long)]
        system_description: Option<String>,
        #[structopt(long)]
        port_description: Option<String>,
        iface: String,
    },
    /// Remove interface
    #[structopt(visible_alias = "rm", visible_alias = "del")]
    Remove { iface: String },
    /// Manage a property on the interface
    Prop(Prop),
    /// Manage the advertised capabilities for the interface
    #[structopt(visible_alias = "cap", visible_alias = "capab")]
    Capability(Capability),
    /// Manage the management addresses for the interface
    #[structopt(visible_alias = "addr")]
    Address(Address),
    /// Get a single configured interface
    #[structopt(visible_alias = "ls")]
    Get { iface: String },
    /// List all configured interfaces
    #[structopt(visible_alias = "ls")]
    List,
}

#[derive(Debug, StructOpt)]
enum Commands {
    /// Print detailed build information about the `lldpd` server.
    #[structopt(visible_alias = "buildinfo")]
    BuildInfo,
    /// Manage the interfaces on which we are listenting and transmitting
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
    println!("\tChassisID: {}", s.chassis_id);
    println!("\tPortId: {}", s.port_id);
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
            println!("\t\t{ma}");
        }
    }
    if !s.organizationally_specific.is_empty() {
        println!("\tOrganizationally Specific:");
        for os in &s.organizationally_specific {
            println!("\t\t{os}");
        }
    }
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
    println!("port: {} interface: {}", i.port, i.iface);
    display_sysinfo(&i.system_info);
}

fn interface_prop(prop: Prop) -> anyhow::Result<()> {
    match prop {
        Prop::Set(set) => println!("{set:?}"),
        Prop::Del(del) => println!("{del:?}"),
    };
    Ok(())
}

fn interface_capability(cap: Capability) -> anyhow::Result<()> {
    println!("{cap:?}");
    Ok(())
}

fn interface_addr(addr: Address) -> anyhow::Result<()> {
    println!("{addr:?}");
    Ok(())
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
        Commands::Interface(sub) => match sub {
            Interface::Add {
                chassis_id,
                port_id,
                ttl,
                system_name,
                system_description,
                port_description,
                iface,
            } => {
                let add_args = types::InterfaceAdd {
                    chassis_id,
                    port_id,
                    ttl,
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
            Interface::Remove { iface } => client
                .interface_del(&iface)
                .await
                .map(|r| r.into_inner())
                .context("failed to remove interface"),
            Interface::Prop(prop) => interface_prop(prop),
            Interface::Capability(cap) => interface_capability(cap),
            Interface::Address(address) => interface_addr(address),
            Interface::Get { iface } => {
                println!("get {iface}");
                Ok(())
            }
            Interface::List => client
                .interface_list()
                .await
                .map(|r| r.into_inner().iter().for_each(display_interface))
                .context("failed to remove interface"),
        },
        Commands::Neighbors => {
            let neighbors = client.get_neighbors().await?;
            for n in neighbors.into_inner() {
                println!("On interface {}", n.port);
                display_neighbor(&n);
            }
            Ok(())
        }
    }
}
