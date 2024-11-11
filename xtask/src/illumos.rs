// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::env;
use std::fs;
use std::io::BufRead;
use std::io::Write;
use std::process::Command;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use camino::Utf8Path;

use omicron_zone_package::package::BuildConfig;

use crate::*;

fn collect_misc(dst: &str) -> Result<()> {
    let bin_dir = format!("{dst}/opt/oxide/bin");
    let svc_xml = format!("{dst}/lib/svc/manifest/system");

    collect("./lldpd/misc", &bin_dir, vec!["svc-lldpd"])?;
    collect("./lldpd/misc", &svc_xml, vec!["lldpd.xml"])
}

fn illumos_package() -> Result<()> {
    let dist_root = "target/dist";
    fs::create_dir_all(dist_root).with_context(|| "Creating {dist_root}")?;
    let manifest = format!("{}/manifest", &dist_root);
    let proto_root = "target/proto";
    let fmri = format!("pkg://oxide/system/lldp@{}", env!("CARGO_PKG_VERSION"));

    let dist_dir = Path::new(&dist_root);
    if !dist_dir.is_dir() {
        fs::create_dir_all(dist_dir)?;
    }

    // construct a manifest for the package
    let output = Command::new("/usr/bin/pkgsend")
        .args(vec!["generate", proto_root])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!("manifest generation failed"));
    }
    let mut f = fs::File::create(&manifest)?;
    f.write_all(format!("set name=pkg.fmri value={fmri}\n").as_bytes())?;
    f.write_all(
        b"set name=pkg.description value=\"Oxide LLDP daemon and CLI\"\n",
    )?;

    // Manually tweak the auto-generated manifest as we write it to the file
    let b = std::io::BufReader::new(output.stdout.as_slice());
    for line in b.lines().map_while(Result::ok) {
        let mut s = line.as_str().to_string();
        if s.ends_with("path=opt") || s.contains("path=lib/svc/manifest") {
            // pkgsend generate' causes each directory to be owned by
            // root/bin, but some packages deliver directories as root/sys.
            // Play along.
            s = s.replace("group=bin", "group=sys");
        }
        if s.ends_with("llpd.xml") {
            // tag the service manifest so it gets automatically imported
            // and deleted from the SMF database.
            s = format!("{s} restart_fmri=svc:/system/manifest-import:default",);
        }

        f.write_all(s.as_bytes())?;
        f.write_all(b"\n")?;
    }

    // build a temporary repo
    let repo_dir = format!("{}/repo", &dist_root);
    fs::create_dir_all(&repo_dir)?;
    let _ = fs::remove_dir_all(&repo_dir);
    let status = Command::new("/usr/bin/pkgrepo")
        .args(vec!["create", &repo_dir])
        .status()?;
    if !status.success() {
        return Err(anyhow!("repo creation failed"));
    }

    // populate the repo
    let status = Command::new("/usr/bin/pkgsend")
        .args(vec![
            "publish", "-d", proto_root, "-s", &repo_dir, &manifest,
        ])
        .status()?;
    if !status.success() {
        return Err(anyhow!("repo population failed"));
    }

    let output_dir = Path::new("out");
    if !output_dir.is_dir() {
        fs::create_dir_all(output_dir)?;
    } else {
        let _ = std::fs::remove_file("out/lldp.p5p");
    }

    // build the archive file
    let status = Command::new("/usr/bin/pkgrecv")
        .args(vec!["-a", "-d", "out/lldp.p5p", "-s", &repo_dir, &fmri])
        .status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("package creation failed")),
    }
}

fn project_root() -> Result<String> {
    match Path::new(&std::env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
        .to_str()
    {
        Some(p) => Ok(p.to_string()),
        _ => Err(anyhow!("bad path")),
    }
}

// Build a package suitable for omicron-package to bundle into a switch zone
async fn omicron_package() -> Result<()> {
    let manifest_file = "lldp-manifest.toml";
    let manifest_path = format!("{}/tools/{}", project_root()?, manifest_file);
    let mut file = fs::File::open(manifest_path)
        .with_context(|| "attempting to open omicron manifest")?;
    let mut manifest = String::new();
    file.read_to_string(&mut manifest)
        .with_context(|| "reading manifest")?;
    let cfg = omicron_zone_package::config::parse_manifest(&manifest)?;

    let output_dir = Utf8Path::new("out");
    fs::create_dir_all(output_dir)?;

    let build_config = BuildConfig::default();
    for package in cfg.packages.values() {
        if let Err(e) = package.create("lldp", output_dir, &build_config).await
        {
            eprintln!("omicron packaging failed: {e:?}");
            return Err(e);
        }
    }

    Ok(())
}

// Build a tarball that, after unpacking in /, can be used to run lldp as a
// standalone project in the global zone.
pub fn global_package() -> Result<()> {
    let root = project_root()?;
    let tgt_path = format!("{root}/lldp-global.tar.gz");
    let mut tar_args = vec!["cfz".to_string(), tgt_path.clone()];

    // cd into the proto area before collecting everything under opt/
    tar_args.push("-C".into());
    tar_args.push("target/proto".into());
    tar_args.push("opt".into());

    println!("building global zone dist in {tgt_path}");
    let status = Command::new("tar").args(&tar_args).status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("tarball construction failed")),
    }
}

pub async fn dist(release: bool, format: DistFormat) -> Result<()> {
    let proto_root = "target/proto";
    let opt_root = format!("{}/opt/oxide", &proto_root);
    let bin_root = format!("{opt_root}/bin");

    println!("cleaning up proto area");
    let _ = std::fs::remove_dir_all(proto_root);

    // populate the proto area
    collect_binaries(release, &bin_root)?;
    collect_misc(proto_root)?;

    match format {
        DistFormat::Omicron => omicron_package().await,
        DistFormat::Native => illumos_package(),
        DistFormat::Global => global_package(),
    }
}
