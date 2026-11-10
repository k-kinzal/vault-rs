#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -t vault-rs-tpm-simulation tools/tpm-simulator
docker run --rm --network none vault-rs-tpm-simulation
docker run --rm --network none vault-rs-tpm-simulation dpkg-query -W swtpm tpm2-tools python3-cryptography
docker image inspect vault-rs-tpm-simulation --format '{{.Id}}'
