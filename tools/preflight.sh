#!/bin/bash

set -o errexit
set -o pipefail
set -o xtrace

banner "fmt"
# This file is generated dynamically during the build, and its absence here
# makes rustfmt sad.
echo '#![rustfmt::skip]' > lldpd/src/ffi.rs
cargo fmt -- --check

banner "openapi"
./tools/ci_download_dendrite_openapi

banner "clippy"
for feat in smf dendrite
do
	cargo clippy --features $feat -- --deny warnings
done

banner Build Simple
ptime -m cargo build --release

banner Build Omicron
ptime -m cargo build --release --features "smf,dendrite"
