#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .tools
if ! cargo kani --version 2>/dev/null | grep -q '0.66.0'; then
  cargo install kani-verifier --version 0.66.0 --locked
fi
cargo kani setup
if ! cargo audit --version 2>/dev/null | grep -q '0.22.2'; then
  cargo install cargo-audit --version 0.22.2 --locked
fi
curl --fail --location --proto '=https' https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar -o .tools/tla2tools.jar
curl --fail --location --proto '=https' https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.39.1.crate -o .tools/libsqlite3-sys-0.39.1.crate
python3 - <<'PY'
import hashlib,pathlib
for name,digest in [('tla2tools.jar','936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88'),('libsqlite3-sys-0.39.1.crate','14a5f01b87b92705d07b433c06f96cbc764637d81a0bffb5734ce17cf0f9a2b3')]:
    assert hashlib.sha256((pathlib.Path('.tools')/name).read_bytes()).hexdigest()==digest, name+' digest mismatch'
print('Pinned tool and vendor archive digests verified.')
PY
