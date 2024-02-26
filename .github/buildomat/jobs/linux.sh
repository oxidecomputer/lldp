#!/bin/bash
#:
#: name = "linux"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/out/*",
#: ]
#:
#: [[publish]]
#: series = "linux"
#: name = "lldp-0.1.0.deb"
#: from_output = "lldp-0.1.0.deb"
#:
#: [[publish]]
#: series = "linux"
#: name = "lldp-0.1.0.deb.sha256.txt"
#: from_output = "lldp-0.1.0.deb.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

function digest {
    shasum -a 256 "$1" | awk -F ' ' '{print $1}'
}

banner "Packages"
sudo apt update -y

banner "Build"
cargo build --release

banner "Artifacts"
pfexec mkdir -p /out
pfexec chown "$UID" /out
cargo xtask dist --release
cp lldp-0.1.0.deb /out/
sha256sum lldp-0.1.0.deb | sed "s/ .*//" > /out/lldp-0.1.0.deb.sha256.txt
