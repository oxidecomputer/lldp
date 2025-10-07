// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::fs;
#[cfg(target_os = "illumos")]
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};

mod external;

#[cfg(target_os = "illumos")]
mod illumos;
#[cfg(target_os = "illumos")]
use illumos as plat;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as plat;

// Possible formats for a bundled dendrite distro.  Currently the two "zone"
// package formats are helios-only.
#[derive(PartialEq, Clone, Debug, ValueEnum)]
pub enum DistFormat {
    /// .deb or .p5p, depending on the platform
    #[value(alias = "n")]
    Native,
    /// package to be included in an omicron zone
    #[value(alias = "o")]
    Omicron,
    /// package to run standalone in the global zone
    #[value(alias = "g")]
    Global,
}

#[derive(Debug, Parser)]
/// lldp xtask support
#[clap(name = "xtask")]
enum Xtasks {
    /// manage OpenAPI documents
    Openapi(Box<external::External>),
    /// build an installable dataplane controller package
    Dist {
        /// package release bits
        #[clap(short, long)]
        release: bool,

        /// package format: omicron, global zone, os-native
        #[clap(short, long, default_value = "native")]
        format: DistFormat,
    },
}

fn collect<T: ToString>(src: &str, dst: &str, files: Vec<T>) -> Result<()> {
    let src_dir = Path::new(src);
    if !src_dir.is_dir() {
        return Err(anyhow!("source isn't a directory: {src}",));
    }

    let dst_dir = Path::new(&dst);
    if !dst_dir.is_dir() {
        fs::create_dir_all(dst_dir)?;
    }

    for f in files {
        let f = f.to_string();
        let src_file = src_dir.join(&f);
        let dst_file = dst_dir.join(&f);
        println!("-- Installing: {dst_file:?}");
        std::fs::copy(src_file, dst_file).with_context(|| {
            format!(
                "copying {f:?} from {src} to {dst}, \
                    was it built with the same --release / \
                    --debug flag passed to `cargo xtask`?"
            )
        })?;
    }
    Ok(())
}

fn collect_binaries(release: bool, dst: &str) -> Result<()> {
    let src = match release {
        true => "./target/release",
        false => "./target/debug",
    };

    let binaries = vec!["lldpd".to_string(), "lldpadm".to_string()];

    collect(src, dst, binaries)
}

#[tokio::main]
async fn main() {
    let task = Xtasks::parse();
    if let Err(e) = match task {
        Xtasks::Openapi(external) => {
            external.exec_bin("lldp-dropshot-apis", "lldp-dropshot-apis")
        }
        Xtasks::Dist { release, format } => plat::dist(release, format).await,
    } {
        eprintln!("failed: {e}");
        std::process::exit(-1);
    }
}
