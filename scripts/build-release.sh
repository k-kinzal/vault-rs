#!/usr/bin/env bash
# Keep the feature/target graph identical for tested, packaged, and rebuilt bins.
set -euo pipefail
cd "$(dirname "$0")/.."
export ZERO_AR_DATE=1
if [[ "$(uname -s)" == Darwin ]]; then
  # Mach-O UUIDs are not authorization identities; use the full binary digest.
  export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-no_uuid"
fi
cargo build --locked --workspace --all-features --release --bins --example deployment_fixture "$@"
