#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .tools
cc -O2 -Wall -Wextra -Werror tools/isolation-fixture.c -o .tools/isolation-fixture
cargo build --locked -p vault-rs
cargo test --locked -p vault-rs --lib --no-run --message-format=json > .tools/isolation-artifacts.jsonl
task_test_binary=$(python3 - <<'PY'
import json
for line in open('.tools/isolation-artifacts.jsonl'):
    v=json.loads(line)
    if v.get('reason')=='compiler-artifact' and v.get('profile',{}).get('test') and v.get('target',{}).get('name')=='vault_rs' and v.get('executable'):
        print(v['executable'])
PY
)
test -n "$task_test_binary"
# Root is confined to a disposable user-namespaced container; no host privilege
# escalation, hardware emulation, or root directories are modified on the host.
docker run --rm --network none \
  -e VAULT_TEST_RUNNER_BIN=/opt/vault-rs \
  -v "$PWD/target/debug/vault-rs:/test-input/vault-rs:ro" \
  -v "$PWD/.tools/isolation-fixture:/test-input/isolation-fixture:ro" \
  -v "$task_test_binary:/test-input/vault-tests:ro" \
  vault-rs-tpm-simulation \
  bash -c 'install -m 755 /test-input/isolation-fixture /opt/isolation-fixture && install -m 755 /test-input/vault-rs /opt/vault-rs && exec /test-input/vault-tests runner::tests::os_isolation_with_real_uids_and_inherited_pipe --ignored --nocapture --test-threads=1'
