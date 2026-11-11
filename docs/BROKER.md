# Broker, approval, and production acceptance

This guide describes the macOS/Linux implementation contract. Physical-key experiments are excluded at the requester's direction; implementation, software tests, and key-enrollment assumptions are distinguished. PRODUCTION_GOAL.md and ASSURANCE.md define production acceptance status.

## Identity and executable bundles

Run the AI under an unprivileged UID different from the broker's. This boundary does not hold if the AI has sudo access or can write root-managed files. The broker is a one-shot process started by an administrator. It exposes no public socket, arbitrary-message signing API, or sudo wrapper usable by the AI.

Bundle JSON contains `entrypoint`, `arguments`, and `files[{path,contents,executable}]`. Contents use unpadded base64url. Limits are 32 MiB and 512 files. All files and arguments contribute to the hash. Files are extracted with create_new into a root-managed directory, then fixed to modes 444/555 with directories at 555. Symlinks and relative-path escapes are rejected. Adding or changing code requires new owner approval.

```sh
vault-rs measure-bundle --bundle /etc/vault-rs/tool.bundle.json
```

OS libraries and interpreters used by the executable are part of the TCB. A hash alone does not make a tool safe if it independently downloads and executes dependencies outside its bundle. User installations such as Python packages and the parent process's environment are not inherited. Include dependency files in the bundle and manage the system runtime in the accepted deployment.

UIDs are allocated once from the witness revision in a dedicated namespace. Require `uid_base >= 10000`, `uid_limit <= 2000000000`, and a range that excludes existing OS accounts/groups and the AI UID. Never reset the witness, namespace, or range, or share a UID range between brokers. Do not recycle an exhausted range; an administrator must register a new unused range and namespace. The broker allocator uses an independent WitnessAuthority deployment that authorizes only its operator.

## One operation

The broker's stdin/stdout are private pipes held by the administrator. Do not share a terminal, FIFO, or control socket with the AI. The workload receives a separate dedicated stdin pipe.

1. Start `broker --config ... --acceptance ...` as the administrator.
2. The broker prints a public Intent as one line of JSON: recipient, public DPoP JWK, instance, artifact hash, secret ID/version/hash, subject, and device public key. No private keys are emitted.
3. The owner inspects the Intent and signs a Grant. The AS issues an access token bound to the same subject, grant ID, DPoP thumbprint, and scope. The administrator supplies `{"grant":<Signed<Grant>>,"access_token":"..."}` as one stdin line. With `oauth` configured, the token may be omitted; the broker prints an authorization URL and waits for the loopback callback. It retains the PKCE verifier and DPoP key internally and exchanges the authorization code with the AS. See `test-oauth.sh` for real-AS tests.
4. The broker performs install and challenge, then publicly outputs the complete Operation. An independent guardian reviews and signs it.
5. The administrator supplies `{"guardian_signature":"..."}`. After checking every other authorization condition, the broker requests device-key confirmation or a PIN.
6. Reserve a UID through the witness, perform release/issue, verify and decrypt through the SDK, and execute under the separate UID. Only the authorized secret value reaches the tool.

`approve --key-config /etc/vault-rs/owner.json --kind grant` reads a typed Grant from stdin and returns Signed<Grant> under the owner-grant domain. The same interface supports `guardian-operation`, `revoke`, `quarantine`, `release`, `review`, and `deployment`. Guardian output is Signed<Operation>; pass its signature field to the broker. Do not sign based on the key ordering of a generic JSON Value.

Native approval helpers are interactive. Allocator service signing uses a separate native service handle; service/witness/TLS operations use attested handles in the common Linux confidential guest. Every signature reaches a protected handle; no resident scalar is unlocked at startup. `test-deployment.sh` verifies CLI startup, retrieval by two users, TLS handle signing, restart and use counts with explicit software fixtures. Never store plaintext PINs in environment variables or configuration. If approval exceeds the authorization lifetime, reject it and approve a new operation.

Linux tests reject memory, FD, and key-file reads, executable modification, and direct broker invocation from another UID, while checking delivery solely through authorized stdin. Linux applies no_new_privs, disables core dumps, and enforces resource limits. The virtual-address-space limit is 512 MiB on Linux and the OS-observed startup virtual size plus 512 MiB on macOS; the same absolute limit is unsuitable because macOS includes dyld shared mappings. This is neither a resident-memory limit nor a DoS-resistance guarantee. Rust and Swift have been cross-built for Mac ARM64. The implementation switches from the root broker to a dedicated GUI user through `launchctl asuser` and a UID change to access Data Protection Keychain. Native CI logs establish macOS OS isolation. Physical Secure Enclave/Keychain device tests are excluded.

A timeout terminates the process group, but termination of all descendants that have called setsid is not guaranteed. Descendants retain only their never-reused UID and already-authorized secret. Complete job lifecycle control remains a separate limitation.

## Recovery

Do not automatically adopt an old snapshot when the witness and database disagree.

1. Send an owner-signed Grant to `POST /v1/checkpoint` to obtain the current independent witness value.
2. Sign `{vault,grant,expected:{revision,hash}}` with `approve --kind quarantine` and send it to `POST /v1/quarantine`.
3. Witness CAS followed by database commit permanently retires that ID. Obtain new owner approval for another unused ID. Unspent uses are not restored.

After an intermediate failure, obtain a fresh checkpoint and new approval. If only provider cleanup fails after quarantine, retry by sending owner-signed `/v1/revoke` for the same grant. [OPERATIONS.md](OPERATIONS.md) describes database, E2E, and configuration-key rotation, shutdown after key loss, and recovery that preserves the independent witness. There is no backdoor that unconditionally regenerates a lost decryption key. If the latest witness state is also lost, old grants cannot resume.

## Production acceptance

Place `AcceptanceFiles{policy,bundle,logs}` under root-managed paths. To exclude physical-key tests, record `allow_physical_test_exclusion:true` in the policy and `physical_tests_excluded:true` in the signed Release. Other acceptance criteria remain mandatory. The policy contains separately enrolled release/review/deployment public keys, minimum_epoch, and a maximum validity period of at most 30 days. The bundle contains Signed<Release>, Signed<Review>, and Signed<Deployment>.

Release specifies the source hash, each macOS/Linux binary hash, and results, methods, log paths, and SHA-256 digests for G01 through G13 on both OSes. Review approves the same release hash with zero unresolved findings. Deployment binds that release to the actual host, binary, configuration hash, OS, and expiry. `observe --config ...` emits measurements but does not create acceptance signatures.

Readiness checks signatures, completeness, methods, hashes, and expiry. Startup performs these checks; the process stops at the earliest evidence expiry, with a one-second monitoring interval and a trusted-clock assumption. New acceptance requires an explicit restart. Whether tests were actually performed, whether the three keys belong to different administrators, and whether log contents establish the claimed properties require accountable approvers and independent review. Signature verification does not automatically prove that log contents are true.

Synthetic successful acceptance fixtures in unit tests only exercise the validator. They are not exported as evidence or reported as successful production acceptance.
