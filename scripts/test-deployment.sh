#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .tools
cargo build --locked -p vault-rs --all-features --bins --example deployment_fixture
cargo test --locked -p vault-rs --test deployment --no-run --message-format=json > .tools/deployment-artifacts.jsonl
task_test_binary=$(python3 - <<'PY'
import json
for line in open('.tools/deployment-artifacts.jsonl'):
    v=json.loads(line)
    if v.get('reason')=='compiler-artifact' and v.get('target',{}).get('name')=='deployment' and v.get('executable'):
        print(v['executable'])
PY
)
test -n "$task_test_binary"
docker run --rm --network none \
  -e VAULT_TEST_RUNNER_BIN=/opt/vault-rs \
  -v "$PWD/target/debug/vault-rs:/test-input/vault-rs:ro" \
  -v "$task_test_binary:/test-input/deployment-tests:ro" \
  -v "$PWD/target/debug/examples/deployment_fixture:/test-input/helper:ro" \
  vault-rs-tpm-simulation \
  bash -c 'install -m 755 /test-input/vault-rs /opt/vault-rs && install -m 755 /test-input/helper /opt/deployment-test-helper && exec /test-input/deployment-tests --ignored --nocapture --test-threads=1'
