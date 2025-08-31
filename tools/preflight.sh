#!/bin/bash

set -o errexit
set -o pipefail
set -o xtrace

banner "clippy"
for feat in smf dendrite
do
	cargo clippy --features $feat -- --deny warnings
done

banner Build Simple
ptime -m cargo build --release

banner Build Omicron
ptime -m cargo build --release --features "smf,dendrite"

banner "fmt"
cargo fmt -- --check
