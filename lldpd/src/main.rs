// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use slog::debug;
use slog::info;
use structopt::StructOpt;

pub use errors::LldpdError;
use interfaces::Interface;
pub use types::LldpdResult;

mod api_server;
mod errors;
mod interfaces;
mod types;

#[cfg(feature = "dendrite")]
mod dendrite;
#[cfg(feature = "smf")]
mod smf;

#[cfg(target_os = "linux")]
mod ffi;
#[cfg(target_os = "illumos")]
mod plat_illumos;
#[cfg(target_os = "linux")]
mod plat_linux;

/// All global state for the lldpd daemon
pub struct Global {
    /// Root of the tree of loggers
    pub log: slog::Logger,
    /// Client connection to dpd
    #[cfg(feature = "dendrite")]
    pub dpd: Option<dpd_client::Client>,
    /// Information about this system
    pub switchinfo: Mutex<SwitchInfo>,
    /// List of addresses on which the api_server should listen.
    pub listen_addresses: Mutex<Vec<SocketAddr>>,
    /// List of interfaces we are managing
    pub interfaces: Mutex<BTreeMap<String, Arc<Mutex<Interface>>>>,
}

unsafe impl Send for Global {}
unsafe impl Sync for Global {}

impl Global {
    fn new(
        log: &slog::Logger,
        switchinfo: SwitchInfo,
        #[cfg(feature = "dendrite")] dpd_client: Option<dpd_client::Client>,
    ) -> Self {
        Global {
            log: log.clone(),
            #[cfg(feature = "dendrite")]
            dpd: dpd_client,
            switchinfo: Mutex::new(switchinfo),
            listen_addresses: Mutex::new(Vec::new()),
            interfaces: Mutex::new(BTreeMap::new()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SwitchInfo {
    pub chassis_id: protocol::types::ChassisId,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub management_addrs: BTreeSet<IpAddr>,
    pub agent: types::Agent,
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
    log_format: lldpd_common::LogFormat,

    #[structopt(long, help = "run without dpd")]
    #[cfg(feature = "dendrite")]
    no_dpd: bool,
    #[structopt(long, about = "dpd host name/addr")]
    #[cfg(feature = "dendrite")]
    host: Option<String>,
    #[structopt(long, about = "dpd port number")]
    #[cfg(feature = "dendrite")]
    port: Option<u16>,

    #[structopt(
        long = "chassis",
        short = "c",
        about = "String to use as the ChassisID"
    )]
    chassis_id: Option<String>,

    #[structopt(
        long = "name",
        short = "n",
        about = "String to use as the SystemName"
    )]
    system_name: Option<String>,

    #[structopt(
        long = "desc",
        short = "d",
        about = "String to use as the SystemDescription"
    )]
    system_description: Option<String>,
}

#[allow(unused_variables)]
async fn signal_handler(
    g: Arc<Global>,
    smf_tx: tokio::sync::watch::Sender<()>,
) {
    const SIGNALS: &[std::ffi::c_int] =
        &[SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGUSR1];
    let mut sigs = Signals::new(SIGNALS).unwrap();

    let log = g.log.new(slog::o!("unit" => "signal-handler"));
    for signal in &mut sigs {
        if signal == SIGINT || signal == SIGQUIT || signal == SIGTERM {
            info!(&log, "caught signal {signal} - exiting");
            break;
        }
        #[cfg(feature = "smf")]
        if signal == SIGUSR1 && std::env::var("SMF_FMRI").is_ok() {
            match smf::refresh_smf_config(&g).await {
                Ok(()) => _ = smf_tx.send(()),
                Err(e) => {
                    slog::error!(&log, "While updating the SMF config: {e:?}")
                }
            }
        }
    }
}

fn get_uname(opt: &str) -> String {
    const UNAME: &str = "/usr/bin/uname";

    if let Ok(out) = std::process::Command::new(UNAME).args(vec![opt]).output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    "unknown".to_string()
}

fn get_switchinfo(opts: &Opt) -> SwitchInfo {
    let chassis_id = match &opts.chassis_id {
        Some(c) => c.to_string(),
        None => get_uname("-n"),
    };
    let system_name = match &opts.system_name {
        Some(s) => s.to_string(),
        None => get_uname("-m"),
    };
    let system_description = match &opts.system_description {
        Some(d) => d.to_string(),
        None => get_uname("-a"),
    };
    SwitchInfo {
        chassis_id: protocol::types::ChassisId::ChassisComponent(chassis_id),
        system_name: Some(system_name),
        system_description: Some(system_description),
        management_addrs: BTreeSet::new(),
        agent: types::Agent::default(),
    }
}

async fn run_lldpd(opts: Opt) -> LldpdResult<()> {
    let log = lldpd_common::log_init("lldpd", &opts.log_file, opts.log_format)?;

    let switchinfo = get_switchinfo(&opts);
    println!("switchinfo: {switchinfo:#?}");

    let global = Arc::new(Global::new(
        &log,
        switchinfo.clone(),
        #[cfg(feature = "dendrite")]
        dendrite::dpd_init(&log, opts).await,
    ));

    #[cfg(feature = "smf")]
    if let Err(e) = smf::refresh_smf_config(&global).await {
        slog::error!(&log, "while loading SMF config: {e:?}");
    }

    #[cfg(all(feature = "smf", feature = "dendrite"))]
    if global.dpd.is_some() {
        let g = global.clone();
        _ = tokio::task::spawn(async move { dendrite::link_monitor(g).await })
    }

    let (api_tx, api_rx) = tokio::sync::watch::channel(());
    let api_global = global.clone();
    let api_server_manager = tokio::task::spawn(async move {
        api_server::api_server_manager(api_global, api_rx).await
    });

    signal_handler(global.clone(), api_tx).await;

    debug!(&log, "shutting down API server");
    api_server_manager
        .await
        .expect("while shutting down the api_server_manager");

    interfaces::shutdown_all(&global).await;

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
