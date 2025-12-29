#!/bin/bash
#:
#: name = "linux"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = true
#: output_rules = [
#:   "=/out/lldp-0.1.0.deb",
#:   "=/out/lldp-0.1.0.deb.sha256.txt",
#:   "=/out/lldpd",
#:   "=/out/lldpd.sha256.txt",
#:   "=/out/lldpadm",
#:   "=/out/lldpadm.sha256.txt",
#: ]
#:
#: [[publish]]
#: series = "linux"
#: name = "lldp-0.1.0.deb"
#: from_output = "/out/lldp-0.1.0.deb"
#:
#: [[publish]]
#: series = "linux"
#: name = "lldp-0.1.0.deb.sha256.txt"
#: from_output = "/out/lldp-0.1.0.deb.sha256.txt"
#:
#: [[publish]]
#: series = "linux"
#: name = "lldpd"
#: from_output = "/out/lldpd"
#:
#: [[publish]]
#: series = "linux"
#: name = "lldpd.sha256.txt"
#: from_output = "/out/lldpd.sha256.txt"
#:
#: [[publish]]
#: series = "linux"
#: name = "lldpadm"
#: from_output = "/out/lldpadm"
#:
#: [[publish]]
#: series = "linux"
#: name = "lldpadm.sha256.txt"
#: from_output = "/out/lldpadm.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install

banner "Packages"
sudo apt update -y
sudo apt install -y libpcap-dev libclang-dev libssl-dev pkg-config

banner "Build"
cargo build --release

banner "Artifacts"
pfexec mkdir -p /out
pfexec chown "$UID" /out

cp target/release/lldpadm /out/
digest -a sha256 /out/lldpadm > /out/lldpadm.sha256.txt
cp target/release/lldpd /out/
digest -a sha256 /out/lldpd > /out/lldpd.sha256.txt

cargo xtask dist --release
cp lldp-0.1.0.deb /out/
digest -a sha256 lldp-0.1.0.deb > /out/lldp-0.1.0.deb.sha256.txt
