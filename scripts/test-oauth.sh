#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .tools/oauth-as
cp tools/oauth-as/package.json tools/oauth-as/package-lock.json tools/oauth-as/server.mjs .tools/oauth-as/
npm ci --prefix .tools/oauth-as --ignore-scripts --no-fund --no-audit
npm audit --prefix .tools/oauth-as --omit=dev --audit-level=low
cargo test --locked -p vault-rs --test security real_authorization_server_code_pkce_dpop_flow -- --ignored --nocapture
