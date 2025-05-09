#!/bin/bash
#:
#: name = "illumos"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = [
#:   "/out/*",
#: ]
#:
#: [[publish]]
#: series = "image"
#: name = "lldp.p5p"
#: from_output = "/out/lldp.p5p"
#:
#: [[publish]]
#: series = "image"
#: name = "lldp.p5p.sha256.txt"
#: from_output = "/out/lldp.p5p.sha256.txt"
#:
#: [[publish]]
#: series = "image"
#: name = "lldp.tar.gz"
#: from_output = "/out/lldp.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "lldp.sha256.txt"
#: from_output = "/out/lldp.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

# Copy file from our local working directory into the /out directory, where
# buildomat can retrieve for archiving.
# usage: archive <source stem> <dest stem> <suffix>
function archive {
    mv out/$1$2 /out/$1$2
    digest -a sha256 /out/$1$2 > /out/$1.sha256.txt
}

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install

pfexec mkdir -p /out
pfexec chown "$UID" /out

PKG="lldp.tar.gz"
banner build $PKG
ptime -m cargo build --release --verbose --features "smf,dendrite"
banner package $PKG
ptime -m cargo xtask dist --format omicron --release
banner archive
archive lldp .tar.gz

PKG="lldp.p5p"
banner build $PKG
ptime -m cargo build --release --verbose
banner package $PKG
ptime -m cargo xtask dist --release
banner archive $PKG
archive $PKG
