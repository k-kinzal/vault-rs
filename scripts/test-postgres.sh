#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .tools
task_tmp=$(mktemp -d "$PWD/.tools/postgres.XXXXXX")
chmod 755 "$task_tmp"
task_container="vault-proof-postgres-$RANDOM-$$"
cleanup() { task_result=$?; if test "$task_result" -ne 0; then docker logs --tail 60 "$task_container" 2>&1 || true; fi; docker rm -f "$task_container" >/dev/null 2>&1 || true; rm -rf "$task_tmp"; }
trap cleanup EXIT
openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$task_tmp/server.key" -out "$task_tmp/server.crt" >/dev/null 2>&1
cat > "$task_tmp/init.sql" <<'SQL'
CREATE ROLE report_reader NOLOGIN;
CREATE ROLE vault_issuer_test LOGIN CREATEROLE PASSWORD 'test-only-issuer';
GRANT CREATE ON DATABASE vault_test TO vault_issuer_test;
GRANT report_reader TO vault_issuer_test WITH ADMIN OPTION;
GRANT pg_signal_backend TO vault_issuer_test;
CREATE TABLE public.vault_test_data(value INTEGER);
INSERT INTO public.vault_test_data VALUES (42);
GRANT SELECT ON public.vault_test_data TO report_reader;
SQL
chmod 644 "$task_tmp/init.sql"
# Synthetic credentials; bind to loopback and delete this container afterward.
docker run -d --name "$task_container" -p 127.0.0.1::5432 \
  -e POSTGRES_DB=vault_test -e POSTGRES_PASSWORD=test-only-bootstrap \
  -v "$task_tmp:/test-input:ro" \
  -v "$task_tmp/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" \
  postgres:17-bookworm@sha256:665dc7b37ac52a17e298511414c21d23ffa4e6a6ef6225b3e5d59c7afb35e994 bash -c 'cp /test-input/server.key /tmp/server.key; cp /test-input/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.key /tmp/server.crt; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key' >/dev/null
for task_attempt in $(seq 1 60); do
  if test "$(docker inspect --format '{{.State.Running}}' "$task_container")" != true; then exit 1; fi
  if docker exec "$task_container" pg_isready -h 127.0.0.1 -U postgres -d vault_test >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$task_container" psql -U postgres -d vault_test -c 'SELECT * FROM public.vault_test_data' >/dev/null
task_port=$(docker port "$task_container" 5432/tcp | sed 's/.*://')
VAULT_TEST_POSTGRES="host=localhost port=$task_port user=vault_issuer_test password=test-only-issuer dbname=vault_test" \
VAULT_TEST_POSTGRES_CA="$task_tmp/server.crt" \
  cargo test --locked -p vault-rs --test security postgres_dynamic_credentials -- --ignored
docker exec "$task_container" postgres --version
docker image inspect postgres:17-bookworm@sha256:665dc7b37ac52a17e298511414c21d23ffa4e6a6ef6225b3e5d59c7afb35e994 --format '{{json .RepoDigests}}'
