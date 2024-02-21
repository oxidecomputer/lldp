use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::*;

// Collect the artifacts of a p4 build in a tar file.  The most common use case
// for this operation is so we can copy them from a Linux build system to an
// Illumos system
pub fn tar_p4(names: Vec<String>) -> Result<()> {
    let root = project_root()?;
    let tgt_path = format!("{root}/p4_artifacts.tgz");
    let mut tar_args = vec!["cfz".to_string(), tgt_path.clone()];

    // cd into the proto area before collecting the artifacts
    tar_args.push("-C".into());
    tar_args.push("target/proto".into());

    let opt_root = "opt/oxide/dendrite";
    for name in &names {
        tar_args.push(format!("{}/{}", &opt_root, name));
    }

    println!("collecting p4 artifacts in {}", &tgt_path);
    let status = Command::new("tar").args(&tar_args).status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("tarball construction failed")),
    }
}

fn copylinks(dst: &str, links: HashMap<String, String>) -> Result<()> {
    let dst_dir = Path::new(dst);

    if !dst_dir.is_dir() {
        fs::create_dir_all(&dst)?;
    }

    for (tgt, orig) in links {
        println!("-- Linking: {} to {}", tgt, orig);
        let link_file = dst_dir.join(&tgt);
        std::os::unix::fs::symlink(&orig, &link_file).with_context(|| {
            format!("linking {:?} to {:?}", link_file, orig)
        })?;
    }
    Ok(())
}

// Copy file "file" rom "src" to "dst".  If the destination directory doesn't
// exist create it, and any necessary parent directories.
fn copyfiles<T: ToString>(src: &str, dst: &str, file: &[T]) -> Result<()> {
    let src_dir = Path::new(src);
    let dst_dir = Path::new(dst);

    if !src_dir.is_dir() {
        return Err(anyhow!("source '{}' isn't a directory", src));
    }

    if !dst_dir.is_dir() {
        fs::create_dir_all(&dst)?;
    }

    for f in file {
        let f = f.to_string();
        let src_file = src_dir.join(&f);
        let dst_file = dst_dir.join(&f);
        println!("-- Installing: {:?}", dst_file);
        fs::copy(src_file, dst_file).with_context(|| {
            format!("copying {:?} from {} to {}", f, src, dst)
        })?;
    }

    Ok(())
}

// Copy all of the files from "src" to "dst".
fn copydir(src: &str, dst: &str) -> Result<()> {
    let src_dir = Path::new(src);

    if !src_dir.is_dir() {
        return Err(anyhow!("source '{}' isn't a directory", src));
    }

    let mut files = Vec::new();
    let mut links = HashMap::new();
    for entry in fs::read_dir(src_dir)? {
        let e = entry?;
        let name = e.file_name().into_string().unwrap();
        let metadata = fs::symlink_metadata(e.path())?;
        if metadata.file_type().is_symlink() {
            let tgt = fs::read_link(e.path())?
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            links.insert(name, tgt);
        } else {
            files.push(name);
        }
    }
    copylinks(dst, links)?;
    copyfiles(src, dst, &files)
}

// Use the Intel p4 compiler suite to generate the p4 binary artifacts
// from our dpd/p4 source tree.
pub fn codegen(opts: CodegenOptions) -> Result<()> {
    let root = project_root()?;
    let src_dir = match opts.name.as_str() {
        "sidecar" => format!("{}/dpd/p4", root),
        name => format!("{}/{}/p4", root, name),
    };
    let tgt_path = format!("{}/target", root);
    let bin_path =
        format!("{}/proto/opt/oxide/dendrite/{}", tgt_path, opts.name);

    println!("using Tofino SDE at {}", opts.sde);
    // Construct a new writeable build directory, using the CMake files from
    // the SDE.
    let p4studio_path = format!("{}/p4studio", opts.sde);
    let build_path = format!("{}/target/p4/build", root);
    copyfiles(&p4studio_path, &build_path, &["CMakeLists.txt"])?;

    let installed = match opts.sde.starts_with("/opt") {
        true => opts.sde.to_string(),
        false => format!("{}/install", opts.sde),
    };

    println!("building p4 payload in: {}", &tgt_path);
    fs::create_dir_all(&Path::new(&tgt_path))?;

    let mut cmake_args = vec![
        build_path.clone(),
        format!("-DP4_NAME={}", opts.name),
        format!("-DCMAKE_INSTALL_PREFIX={}", installed),
        format!("-DCMAKE_MODULE_PATH={}/cmake", opts.sde),
        format!("-DP4_PATH={}/{}.p4", src_dir, opts.name),
        format!("-DP4PPFLAGS='-I{}'", src_dir),
    ];
    if let Some(s) = opts.stages {
        cmake_args.push(format!(
            "-DP4FLAGS='--num-stages-override {} --create-graphs'",
            s
        ));
    }

    match opts.tofino {
        1 => {
            cmake_args.push("-DTOFINO=on".to_string());
            cmake_args.push("-DTOFINO2=off".to_string());
        }
        2 => {
            cmake_args.push("-DTOFINO=off".to_string());
            cmake_args.push("-DTOFINO2=on".to_string());
        }
        x => return Err(anyhow!("unsupported tofino model: {}", x)),
    }

    println!("preparing cmake for build");
    let status = Command::new("cmake")
        .current_dir(&build_path)
        .args(&cmake_args)
        .status()?;

    if !status.success() {
        return Err(anyhow!("cmake setup failed"));
    }

    println!("building in {}", &build_path);
    let status = Command::new("make").current_dir(&build_path).status()?;

    if !status.success() {
        return Err(anyhow!("p4 build failed"));
    }

    // p4studio wants to install our code into the same 'install' area in
    // which the SDE tools live.  To override that, we need to rebuild the cmake
    // files with our intended target location before running the install.
    let cmake_args = vec![
        build_path.clone(),
        format!("-DCMAKE_INSTALL_PREFIX={}", &bin_path),
        format!("-DP4_NAME={}", opts.name),
    ];

    println!("preparing cmake for installation");
    let status = Command::new("cmake")
        .current_dir(&build_path)
        .args(&cmake_args)
        .status()?;

    if !status.success() {
        return Err(anyhow!("cmake setup failed"));
    }

    let _ = fs::remove_dir_all(&bin_path);
    println!("collecting p4 artifacts");
    let status = Command::new("make")
        .current_dir(&build_path)
        .args(vec!["install"])
        .status()?;

    if !status.success() {
        return Err(anyhow!("p4 installation failed"));
    }

    // None of this gets used in a simulation environment, but the library barfs
    // if it can't be loaded.  When we have real hardware and real non-avago
    // firmware, the library will need to be modified to deal with that.  For
    // now we'll bundle the unnecessary firmware to allow people to use the
    // stock SDE.
    println!("collecting firmware artifacts");

    // When copying the firmware from an SDE repo, we have to pull it from the
    // 'install' directory.  When copying from an installed SDE package, that's
    // already been done for us.
    let fw_dir = match opts.sde.starts_with("/opt") {
        true => opts.sde.clone(),
        false => format!("{}/install", opts.sde),
    };
    for d in ["avago", "credo"] {
        let fw_stub = format!("share/tofino_sds_fw/{}/firmware", d);
        let fw_src = format!("{}/{}", fw_dir, fw_stub);
        let fw_tgt = format!(
            "{}/proto/opt/oxide/dendrite/{}/{}",
            tgt_path, opts.name, fw_stub
        );

        copydir(&fw_src, &fw_tgt)?;
    }

    Ok(())
}

fn collect(src: &str, dst: &str, files: Vec<&str>) -> Result<()> {
    let src_dir = Path::new(src);
    if !src_dir.is_dir() {
        return Err(anyhow!("source isn't a directory"));
    }

    let dst_dir = Path::new(&dst);
    if !dst_dir.is_dir() {
        fs::create_dir_all(&dst_dir)?;
    }

    for f in files {
        let src_file = src_dir.join(f);
        let dst_file = dst_dir.join(f);
        println!("-- Installing: {:?}", dst_file);
        std::fs::copy(src_file, dst_file).with_context(|| {
            format!("copying {:?} from {} to {}", f, src, dst)
        })?;
    }
    Ok(())
}

fn write_file(name: &str, content: Vec<&str>) -> Result<()> {
    let mut f = fs::File::create(name)?;
    for l in content {
        f.write_all(l.as_bytes())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

pub async fn dist(
    _features: Option<String>,
    names: Vec<String>,
    release: bool,
    format: DistFormat,
    p4: Option<String>,
) -> Result<()> {
    if format != DistFormat::Native {
        return Err(anyhow!("dist format unsupported on Linux: {format:?}"));
    }

    let proto_root = "target/proto";
    let opt_root = format!("{}/opt/oxide/dendrite", &proto_root);
    let bin_root = format!("{}/bin", opt_root);
    let etc_root = format!("{}/etc", opt_root);
    let lib_root = format!("{}/lib", opt_root);
    let misc_root = format!("{}/misc", opt_root);

    if let Some(p4) = p4 {
        unpack_p4_artifacts(p4, proto_root)?;
    }

    // populate the proto area
    collect_binaries(&names, release, &bin_root)?;
    let tools = vec![
        "run_dpd.sh",
        "run_tofino_model.sh",
        "veth_setup.sh",
        "veth_teardown.sh",
    ];
    collect("./tools", &bin_root, tools)?;
    collect("./tools", &etc_root, vec!["ports_tof2.json"])?;
    {
        let lib = Path::new("tools/remote_model/remote_model.so");
        if lib.is_file() {
            collect(
                "./tools/remote_model",
                &lib_root,
                vec!["remote_model.so"],
            )?;
        } else {
            println!("{:?} not built - skipping", lib);
        }
    }
    collect(
        "./dpd/misc",
        &misc_root,
        vec!["zlog-cfg", "model_config.toml", "sidecar_config.toml"],
    )?;

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
        "Package: dendrite",
        &version,
        "Architecture: amd64",
        "Depends:",
        "Description: dendrite dataplane daemon",
    ];

    write_file(&control_file, control)?;

    let package = format!("dendrite-{}.deb", env!("CARGO_PKG_VERSION"));
    let status = Command::new("/usr/bin/dpkg")
        .args(vec!["--build", proto_root, &package])
        .status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("package creation failed")),
    }
}
