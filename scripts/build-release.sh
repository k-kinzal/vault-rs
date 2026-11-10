#!/usr/bin/env bash
# Keep the feature/target graph identical for tested, packaged, and rebuilt bins.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked --workspace --all-features --release --bins --example deployment_fixture "$@"
