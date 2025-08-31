#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"

set -o errexit
set -o pipefail
set -o xtrace

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install

banner "clippy"
for feat in smf dendrite
do
	cargo clippy --features $feat -- --deny warnings
done

banner "fmt"
cargo fmt -- --check
