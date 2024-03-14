#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"

set -o errexit
set -o pipefail
set -o xtrace

banner "openapi"
./tools/ci_download_dendrite_openapi

banner "clippy"
for feat in smf dendrite
do
	cargo clippy --features $feat -- --deny warnings
done

# This file is generated dynamically during the build, and its absence here
# makes rustfmt sad.
echo '#![rustfmt::skip]' > lldpd/src/ffi.rs

banner "fmt"
cargo fmt -- --check
