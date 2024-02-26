// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::*;

fn write_file(name: &str, content: Vec<&str>) -> Result<()> {
    let mut f = fs::File::create(name)?;
    for l in content {
        f.write_all(l.as_bytes())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

pub async fn dist(release: bool, format: DistFormat) -> Result<()> {
    if format != DistFormat::Native {
        return Err(anyhow!("dist format unsupported on Linux: {format:?}"));
    }

    let proto_root = "target/proto";
    let opt_root = format!("{}/opt/oxide", &proto_root);
    let bin_root = format!("{}/bin", opt_root);

    // populate the proto area
    collect_binaries(release, &bin_root)?;

    let debian_dir = format!("{}/DEBIAN", &proto_root);
    let compat_file = format!("{}/compat", &debian_dir);
    let copyright_file = format!("{}/copyright", &debian_dir);
    let control_file = format!("{}/control", &debian_dir);

    if !Path::new(&debian_dir).is_dir() {
        fs::create_dir_all(&debian_dir)?;
    }

    write_file(&compat_file, vec!["10"])?;
    write_file(&copyright_file, vec!["Copyright Oxide Computer"])?;

    let version = format!("Version: {}", env!("CARGO_PKG_VERSION"));
    let control = vec![
        "Maintainer: Nils Nieuwejaar <nils@oxidecomputer.com>",
        "Section: misc",
        "Priority: optional",
        "Package: lldp",
        &version,
        "Architecture: amd64",
        "Depends:",
        "Description: Oxide lldp daemon and CLI",
    ];

    write_file(&control_file, control)?;

    let package = format!("lldp-{}.deb", env!("CARGO_PKG_VERSION"));
    let status = Command::new("/usr/bin/dpkg")
        .args(vec!["--build", proto_root, &package])
        .status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("package creation failed")),
    }
}
