# OAuth, service keys, updates, and recovery

This document describes the contract of the implemented operations. Physical-device experiments are excluded at the requester's direction. Consult each manifest for macOS/Linux execution results and PROOF_CONTRACT.md for the formal assurance contract.

## Connecting an OAuth AS

Set the broker's `oauth` fields: `client_id`, `authorization_endpoint`, `token_endpoint`, `redirect_uri`, and optional `ca`. The AS issuer and both endpoints must use the same HTTPS origin. A callback such as `http://127.0.0.1:49152/callback` requires a registered fixed loopback IP and explicit port. Register a native/public client with code flow, S256 PKCE, DPoP-bound tokens, and callback `iss` support. The HTTP callback only receives the code; communication with Vault uses HTTPS in both local and hosted deployments.

When given only an owner-signed Grant, the broker binds its callback before printing `authorization_url`. The administrator logs in and grants consent using a trusted browser. The broker verifies state and issuer, then exchanges the code using its retained PKCE verifier and DPoP private key. A DPoP nonce challenge at the token endpoint is retried once with a fresh proof. Tests against the real AS engine cover rejection of a different verifier or key for an unused code, code replay, and modified state or issuer.

AS tokens must use ES256 with `typ=at+jwt` and contain `iss`, string `aud`, `sub`, `nbf`, `exp`, `scope`, UUID `grant_id`, and `cnf.jkt`. Vault pins the issuer public key and rejects substitution through an embedded token jwk. The AS must validate the approved owner Grant and issue matching subject, grant ID, scope, and DPoP thumbprint values. The owner-signed Grant is passed in the `vault_grant` request parameter. Vault independently rechecks each field.

`tools/oauth-as` is a **test-only** fixture whose login/consent handler uses fixed data. Its OIDC/OAuth engine is oidc-provider 9.13.3, exercising actual HTTPS, PKCE, DPoP, and authorization-code processing. Never use this login handler or in-memory adapter as a production AS. Production identity, MFA, and consent are the connected AS's responsibility.

Issuer-key rotation requires accepting new Trust configuration and deployment evidence, then restarting; keys are not fetched automatically. There is no overlap period for continued use of old tokens. Obtain a token signed by the new issuer key.

## Unlocking service keys once at startup

Owner/device/guardian operation-approval keys are distinct from service keys for the witness, operator, and database. Interactive approval keys use native Secure Enclave or TPM protection. Service keys are generated as P-256 keys; only an envelope encrypted to the hardware protector's public key is stored.

```sh
vault-rs generate-service-key --protector-public /etc/vault-rs/protector.pub --purpose signing
vault-rs generate-service-key --protector-public /etc/vault-rs/protector.pub --purpose agreement
```

Save the output JSON's `envelope` in a root-managed file with mode 0600, and pin the accompanying `public_key` in configuration. RuntimeKeyConfig accepts the existing NativeConfig or `{protector:<NativeConfig>,envelope:<absolute path>,purpose:"signing"|"agreement",public_key:<pinned key>}`. At service startup, the protector unlocks the envelope and loads the key into memory only if purpose and public key match. Subsequent requests do not require a PIN. Restarting after shutdown requires unlocking again.

Resident keys are software keys present in process memory. They are not claimed to be non-exportable. The protection boundary consists of separate root and AI UIDs, disabled core dumps, Linux dump restrictions, immutable configuration/executables, and an independent guardian. Control of a running root process's memory is a TCB compromise. Power-off/locking policy, disk encryption, and swap management belong to the deployment. Unit tests of resident keys do not substitute for physical-attack resistance.

Native configuration on macOS requires `macos_uid`. Specify a dedicated login user separate from the AI, using that user's Keychain and GUI session. The design does not open Data Protection Keychain UI directly from a root launch daemon. Linux rejects `macos_uid`.

## Key rotation

SQLCipher database rotation creates a new database generation rather than overwriting the old file.

```sh
vault-rs rotate-storage --source /var/lib/vault-rs/old.db \
  --destination /var/lib/vault-rs/new.db \
  --old-key /etc/vault-rs/old-key.json --new-key /etc/vault-rs/new-key.json
```

1. Stop the affected service. An open database holds a shared flock; rotation is rejected if it cannot obtain an exclusive flock.
2. Open the old database with its old key and checkpoint the WAL. Generate a new random DEK and wrap it with the new protector.
3. Export into the new database with `sqlcipher_export`, reopen with the new key, verify integrity, and fsync the file and directory. Retain the old generation as a backup.
4. Confirm the output is `prepared`, accept deployment evidence for configuration using the new database path and key, and restart. Preserve any destination left by an intermediate failure as unpublished; retry at a different new path. Never automatically revert to the old configuration.

This operation does more than rewrap the existing database's DEK. Tests verify that the new database cannot be opened with the old key or envelope. The old backup remains readable with its old key, so manage key retirement and backup retention. This program does not guarantee physical erasure of discarded media.

Re-encrypt a provider DSN or resident-key envelope for a new protector with `rewrap-config --source ... --destination ... --old-key ... --new-key ...`. The new envelope is checked with the new key before being written; the new configuration requires separate acceptance.

Update E2E records through `RecipientSession::rotate_record`. Complete an authorized release of the old record, then re-encrypt with a new version and DEK, splitting shares for the device's and guardian's new public keys. Retire the old grant through owner-signed revoke or quarantine, and approve a new Grant ID for the new record hash. Rotation never restores the old grant's remaining uses. Tests use independently generated new keys and reject decryption with old keys.

## Failures and key loss

- When restoring only the Vault database, continue only grants that match the current independent witness. Permanently retire mismatches through owner-signed quarantine and authorize new IDs.
- The witness requires independent administration, backup, and preservation of its latest state. Never restore Vault and the witness to the same old snapshot. If the latest witness state is lost, do not resume old grants: stop the old Vault and migrate to a new vault ID, trust configuration, and grants. Do not reconstruct use counts from past approvals.
- If a hardware protector is lost, recovery requires an independent recovery endpoint or encrypted backup legitimately prepared beforehand. Without one, there is no way to decrypt the secrets. Availability does not justify an authorization-bypassing recovery path.
- The provider outbox may retry using idempotent lease IDs. Revocation commits NOLOGIN before terminating existing sessions and dropping roles. TTL enforcement against existing PostgreSQL sessions during a provider outage is not guaranteed; this remains an operational limitation of dynamic credentials.

## Reproducing the tests

`test-deployment.sh` starts real CLI processes inside rootless Docker. It checks HTTPS witness/Vault services, two subjects, the broker's private control pipe and separate-UID workload, startup-only resident-key unlocking, process restart, and revocation. Native helpers and issuer keys are synthetic fixtures and are not classified as physical-device evidence. Separately, `test-oauth.sh` checks a real AS protocol engine. These tests do not claim to have exercised both paths in a single production deployment.

## Initial database creation and configuration measurement

Before production startup, prepare canonical absolute directories managed by root. On macOS, use canonical paths such as `/private/var`, not the `/var` alias. Separate the service and AI accounts and give the AI no sudo access. Place configuration, helpers, CAs, extensions, and provider envelopes under root-managed paths; remove group/other write permissions and macOS extended ACLs.

```sh
vault-rs initialize-storage --database /opt/vault-data/vault.db --key-config /opt/vault-config/decryption.json
vault-rs observe --config /opt/vault-config/server.json
```

`initialize-storage` creates a new encrypted generation and digest without overwriting an existing database or key envelope. Specify the same key as the service's decryption RuntimeKeyConfig. Initialize the witness database in the same way. The configuration hash from `observe` binds the main configuration plus the contents of helpers, CAs, key envelopes, providers, extensions, and other inputs, tagged by role and canonical path, including the database key envelope. Mutable database pages are excluded. An envelope that differs from the accepted generation is rejected before unwrap.

Then register signed release/review/deployment evidence and the authority policy. Pass only a configuration accepted by `readiness` to `serve`, `witness`, or `broker` through `--acceptance`. Successful validation of a release's distribution artifacts does not imply approval of your deployment. The actual enrolled authorities must create the required signatures through `approve`.

Never overwrite accepted helpers, CAs, provider configuration, or other dependencies while the service is running. Update by stopping the service, installing at new generation paths, running observe, obtaining new approval, and restarting. Malicious root changes are outside the guarantee, but accidental concurrent updates must also be avoided. If a token expires in less than 30 seconds, the operation deadline follows the token; if it expires during device interaction, no value is passed to the workload.

## Obtaining verified distribution artifacts

The `production-software-release` artifact from a single GitHub Actions run contains native Linux/macOS binaries, the macOS helper, all verification logs, source, `release.json`, and `SHA256SUMS`. The `release-evidence` job runs only after both OS jobs succeed and checks every source file and all binary/log hashes. Intermediate artifacts from a failed run are not valid product-acceptance evidence. Also verify the workflow's commit and origin: hashes alone do not authenticate the distributor.

The Linux binary targets Ubuntu 24.04 x86_64 with glibc 2.39 and OpenSSL 3. The macOS binary targets macOS 15 arm64 and uses Homebrew OpenSSL 3 (`brew install openssl@3`). Rebuild and reverify the same source for other OS versions or architectures. After extraction, check contents with `sha256sum -c SHA256SUMS`, or `shasum -a 256 -c SHA256SUMS` on macOS, then install the relevant binary under a root-managed path using `install -m 755`. The macOS helper also requires the dedicated user's Keychain, signing, and entitlement configuration; see HARDWARE.md.

`source.tar.gz` contains the complete verified source. The Rust toolchain is pinned in rust-toolchain.toml, crates in Cargo.lock, and CI actions by commit SHA. Extract the source, initialize a Git repository, and run `scripts/prepare-tools.sh` and `scripts/verify.py --with-docker` to regenerate Linux evidence. On macOS, follow the workflow's native steps. Regeneration creates new evidence and does not inherit the original acceptance signatures.

`scripts/build-release.sh` centralizes release feature and target selection. Diagnostics found that ThinLTO internal symbols and layout varied with cache state, so the release profile disables LTO and sets codegen-units=1. This favors full-byte reproducibility under identical conditions over optimization. Verification still requires SHA-256 equality of the entire binary.

On macOS, build.rs applies `-no_uuid` only to the distributed vault-rs executable, not to proc-macro dylibs or other compiler plugins. `ZERO_AR_DATE=1` fixes archive creation timestamps. Authorization and evidence use the SHA-256 of the complete executed/distributed binary, not Mach-O UUIDs. Comparison never excludes identification data or code signatures.
