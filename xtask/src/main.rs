// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::fs;
#[cfg(target_os = "illumos")]
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use structopt::*;

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
#[derive(PartialEq, Debug)]
pub enum DistFormat {
    Native,  // .deb or .p5p, depending on the platform
    Omicron, // package to be included in an omicron zone
    Global,  // package to run standalone in the global zone
}

type ParseError = &'static str;
impl FromStr for DistFormat {
    type Err = ParseError;
    fn from_str(format: &str) -> Result<Self, Self::Err> {
        match format {
            "native" | "n" => Ok(DistFormat::Native),
            "omicron" | "o" => Ok(DistFormat::Omicron),
            "global" | "g" => Ok(DistFormat::Global),
            _ => Err("Could not parse distribution format"),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "xtask", about = "lldp xtask support")]
enum Xtasks {
    #[structopt(about = "build an installable dataplane controller package")]
    Dist {
        #[structopt(short, long, help = "package release bits ")]
        release: bool,

        #[structopt(
            short,
            long,
            help = "package format: omicron, global zone, os-native",
            default_value = "native"
        )]
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
    let task = Xtasks::from_args();
    if let Err(e) = match task {
        Xtasks::Dist { release, format } => plat::dist(release, format).await,
    } {
        eprintln!("failed: {e}");
        std::process::exit(-1);
    }
}
