// Todo:
//   Connect to dpd
//   Get switchinfo from dpd
//   Accept sidecar ports as interfaces
//   Fetch MAC address from dpd
//   Check RFD for chassis_id, port_id, management address values
//   Expire neighbors according to TTL
//   Xmit packets according to TLL/RFC
//   Read state machine part of RFC and implement
//   Get onto centrum and verify that we're seeing expected info
//   Revisit MAC address scope
//   Put sidecar/dpd stuff behind a feature flag
//   Store neighbors in per-interface vecs.
//   Add optional interface arg to get_neighbors()

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Context;
use crucible_smf::PropertyGroup;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use slog::debug;
use slog::error;
use slog::info;
use structopt::StructOpt;

use dpd_client::Client;
use dpd_client::ClientState;

use interfaces::Interface;
use neighbors::Neighbor;
use neighbors::NeighborId;
use types::LldpdError;
use types::LldpdResult;

mod api_server;
mod interfaces;
mod neighbors;
mod protocol;
mod types;

/// All global state for the lldpd daemon
pub struct Global {
    /// Root of the tree of loggers
    pub log: slog::Logger,
    /// Client connection to dpd
    pub dpd: Option<Client>,
    /// Information about this system
    pub switchinfo: Mutex<SwitchInfo>,
    /// List of addresses on which the api_server should listen.
    pub listen_addresses: Mutex<Vec<SocketAddr>>,
    /// List of interfaces we ar managing
    pub interfaces: Mutex<BTreeMap<String, Interface>>,
    /// All of the neighbors we are tracking
    pub neighbors: Mutex<BTreeMap<NeighborId, Neighbor>>,
}
unsafe impl Send for Global {}
unsafe impl Sync for Global {}

impl Global {
    fn new(log: &slog::Logger, dpd_client: Option<Client>, switchinfo: SwitchInfo) -> Self {
        Global {
            log: log.clone(),
            dpd: dpd_client,
            switchinfo: Mutex::new(switchinfo),
            listen_addresses: Mutex::new(Vec::new()),
            interfaces: Mutex::new(BTreeMap::new()),
            neighbors: Mutex::new(BTreeMap::new()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SwitchInfo {
    pub chassis_id: String,
    pub system_name: String,
    pub system_description: String,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "lldpd", about = "Oxide LLDP daemon")]
enum Args {
    /// Run the LLDPD API server.
    Run(Opt),
    /// Generate an OpenAPI specification for the LLDPD server.
    Openapi,
}

#[derive(Debug, StructOpt)]
pub(crate) struct Opt {
    #[structopt(long, about = "log file")]
    log_file: Option<String>,

    #[structopt(
        long,
        short = "l",
        default_value = "json",
        about = "log format",
        help = "format logs for 'human' or 'json' consumption"
    )]
    log_format: common::logging::LogFormat,

    #[structopt(long, help = "run without dpd")]
    no_dpd: bool,
    #[structopt(long, about = "dpd host name/addr")]
    host: Option<String>,
    #[structopt(long, about = "dpd port number")]
    port: Option<u16>,

    #[structopt(
        long = "chassis",
        short = "c",
        about = "String to use as the ChassisID"
    )]
    chassis_id: Option<String>,

    #[structopt(long = "name", short = "n", about = "String to use as the SystemName")]
    system_name: Option<String>,

    #[structopt(
        long = "desc",
        short = "d",
        about = "String to use as the SystemDescription"
    )]
    system_description: Option<String>,
}

// Given a property name within a group, return all the associated values as
// a vec of strings.
fn get_properties(config: &PropertyGroup, name: &str) -> LldpdResult<Vec<String>> {
    let prop = config
        .get_property(name)
        .map_err(|e| LldpdError::Smf(format!("failed to get '{name}' property: {e:?}")))?;

    let mut rval = Vec::new();
    if let Some(values) = prop {
        for value in values
            .values()
            .map_err(|e| LldpdError::Smf(format!("failed to get values for '{name}': {e:?}")))?
        {
            let value = value
                .map_err(|e| LldpdError::Smf(format!("failed to get value for '{name}': {e:?}")))?
                .as_string()
                .map_err(|e| {
                    LldpdError::Smf(format!("failed to convert value '{name}' to string: {e:?}"))
                })?;
            if value != "unknown" {
                rval.push(value);
            }
        }
    }

    Ok(rval)
}

fn refresh_smf_config(g: &Global) -> LldpdResult<()> {
    const SMF_SCRIMLET_ID_PROP: &str = "scrimlet_id";
    const SMF_SCRIMLET_MODEL_PROP: &str = "scrimlet_model";
    const SMF_BOARD_REV_PROP: &str = "board_rev";
    const SMF_ADDRESS_PROP: &str = "address";

    debug!(&g.log, "refreshing SMF configuration data");

    // Create an SMF context and take a snapshot of the current settings
    let scf = crucible_smf::Scf::new().context("creating scf handle")?;
    let instance = scf.get_self_instance().context("getting smf instance")?;
    let snapshot = instance
        .get_running_snapshot()
        .context("getting running snapshot")?;

    // All the properties relevant to us fall under the "config" property group
    let pg = match snapshot
        .get_pg("config")
        .context("getting 'config' propertygroup")?
    {
        Some(c) => c,
        None => return Ok(()),
    };

    if let Ok(addresses) = get_properties(&pg, SMF_ADDRESS_PROP) {
        debug!(g.log, "config/{SMF_ADDRESS_PROP}: {addresses:?}");
        let mut listen_addresses = Vec::new();
        for addr in addresses {
            match addr.parse() {
                Ok(a) => listen_addresses.push(a),
                Err(e) => error!(
                    g.log,
                    "bad socket address {} in smf config/{}: {:?}", addr, SMF_ADDRESS_PROP, e
                ),
            }
        }
        *(g.listen_addresses.lock().unwrap()) = listen_addresses;
    }

    let mut s = g.switchinfo.lock().unwrap();
    if let Ok(id) = get_properties(&pg, SMF_SCRIMLET_ID_PROP) {
        debug!(g.log, "config/{SMF_SCRIMLET_ID_PROP}: {id:?}");
        if !id.is_empty() {
            s.chassis_id = id[0].clone();
            s.system_name = id[0].clone();
        }
    }
    let mut desc = Vec::new();
    if let Ok(model) = get_properties(&pg, SMF_SCRIMLET_MODEL_PROP) {
        debug!(g.log, "config/{SMF_SCRIMLET_MODEL_PROP}: {model:?}");
        if !model.is_empty() {
            desc.push(format!("Oxide sled model: {}", model[0]));
        }
    }
    if let Ok(board) = get_properties(&pg, SMF_BOARD_REV_PROP) {
        debug!(g.log, "config/{SMF_BOARD_REV_PROP}: {board:?}");
        if !board.is_empty() {
            desc.push(format!("Sidecar revision: {}", board[0]));
        }
    }
    if !desc.is_empty() {
        s.system_description = desc.join(", ");
    }

    Ok(())
}

fn signal_handler(g: Arc<Global>, smf_tx: tokio::sync::watch::Sender<()>) {
    const SIGNALS: &[std::ffi::c_int] = &[SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGUSR2];
    let mut sigs = Signals::new(SIGNALS).unwrap();

    let log = g.log.new(slog::o!("unit" => "signal-handler"));
    for signal in &mut sigs {
        info!(&log, "caught signal {}", signal);
        if signal == SIGINT || signal == SIGQUIT || signal == SIGTERM {
            break;
        }
        if signal == SIGUSR2 && std::env::var("SMF_FMRI").is_ok() {
            match refresh_smf_config(&g) {
                Ok(()) => _ = smf_tx.send(()),
                Err(e) => {
                    error!(&log, "While updating the SMF config: {e:?}")
                }
            }
        }
    }
}

async fn dpd_version(log: &slog::Logger, client: &Client) -> String {
    let mut warn_at = 0;
    let mut warn_delay = 1;
    let mut iter = 0;

    loop {
        if let Ok(version) = client.dpd_version().await {
            return version.into_inner();
        }
        if iter >= warn_at {
            error!(log, "Failed to connect to dpd.  Retrying...");
            warn_at += warn_delay;
            warn_delay = std::cmp::min(60, warn_delay * 2);
        }
        iter += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn get_uname(opt: &str) -> String {
    const UNAME: &str = "/usr/bin/uname";

    if let Ok(out) = std::process::Command::new(UNAME).args(vec![opt]).output() {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    "unknown".to_string()
}

fn get_switchinfo(opts: &Opt) -> SwitchInfo {
    SwitchInfo {
        chassis_id: match &opts.chassis_id {
            Some(c) => c.to_string(),
            None => get_uname("-n"),
        },
        system_name: match &opts.system_name {
            Some(s) => s.to_string(),
            None => get_uname("-m"),
        },
        system_description: match &opts.system_description {
            Some(d) => d.to_string(),
            None => format!("{} {}", get_uname("-o"), get_uname("-m")),
        },
    }
}

async fn run_lldpd(opts: Opt) -> LldpdResult<()> {
    const CLIENT_NAME: &str = "lldpd";
    let log = common::logging::init(CLIENT_NAME, &opts.log_file, opts.log_format)?;

    let switchinfo = get_switchinfo(&opts);
    println!("switchinfo: {switchinfo:#?}");

    let client = if opts.no_dpd {
        None
    } else {
        let host = opts.host.unwrap_or_else(|| "localhost".to_string());
        let port = opts.port.unwrap_or_else(|| dpd_client::DEFAULT_PORT);
        info!(log, "connecting to dpd at {host}:{port}");
        let client_state = ClientState {
            tag: String::from(CLIENT_NAME),
            log: log.new(slog::o!("unit" => "lldpd-client")),
        };
        let client = Client::new(&format!("http://{host}:{port}"), client_state);

        info!(
            log,
            "connected to dpd running {}",
            dpd_version(&log, &client).await
        );
        Some(client)
    };

    let global = Arc::new(Global::new(&log, client, switchinfo));
    if let Err(e) = refresh_smf_config(&global) {
        error!(&log, "while loading SMF config: {e:?}");
    }

    let (smf_tx, smf_rx) = tokio::sync::watch::channel(());
    let api_server_manager = tokio::task::spawn(api_server::api_server_manager(
        global.clone(),
        smf_rx.clone(),
    ));

    signal_handler(global.clone(), smf_tx);

    api_server_manager
        .await
        .expect("while shutting down the api_server_manager");

    info!(&log, "exiting");
    Ok(())
}

fn print_openapi() -> LldpdResult<()> {
    crate::api_server::http_api()
        .openapi("Oxide LLDP Daemon", "0.0.1")
        .description("API for managing the LLDP daemon")
        .contact_url("https://oxide.computer")
        .contact_email("api@oxide.computer")
        .write(&mut std::io::stdout())
        .map_err(|e| LldpdError::Io(e.into()))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> LldpdResult<()> {
    let args = Args::from_args();

    match args {
        Args::Openapi => print_openapi(),
        Args::Run(opt) => run_lldpd(opt).await,
    }
}
