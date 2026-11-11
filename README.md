# vault-rs

End-to-end encrypted secret management in Rust with two-party authorization. macOS and Linux use the same HTTPS, authorization, and cryptographic implementation. Independent device and guardian approval is required in addition to OAuth and DPoP.

Production requirements are defined by [13 acceptance criteria](docs/PRODUCTION_GOAL.md). The software release decision is recorded in `evidence/release.json`, combining Linux and macOS evidence for the same source. Deployment acceptance is checked by `vault-rs readiness` against signed evidence. Only physical-key experiments are excluded at the requester's direction. The [assurance scope](docs/ASSURANCE.md) and [proof contract](docs/PROOF_CONTRACT.md) distinguish directly verified properties from assumptions about cryptography, the OS, databases, and other dependencies.

## Implemented mechanisms

- Require device and independent guardian signatures over the complete operation, in addition to OAuth and DPoP. Stealing both the token and DPoP private key still leaves independent approval required.
- Bind the subject, secret ID/version, action, executable and arguments, execution instance, recipient key, validity period, and use count in an owner-signed grant. A root-managed broker fixes the executable and passes only the authorized secret through a dedicated stdin pipe to a tool running under a UID allocated once by the witness.
- Split each secret's data encryption key into two shares, both required for recovery, and wrap each share with a separate P-256 HPKE key. Responses are also HPKE-encrypted to the recipient. Vault never obtains the device share of a static secret.
- Encrypt the database and WAL with SQLCipher. Wrap database keys and issuer configuration with hardware keys. An open database key and released plaintext exist in the executing process's memory.
- Enforce independent witness CAS, then database commit, then disclosure. Rollback and crashes fail closed. Owner-authorized recovery can only retire an old grant ID permanently.
- Issue PostgreSQL credentials with restricted roles and TTLs, idempotent issuance, revocation, and expiry cleanup. Wasm extensions have no host imports, run under memory and fuel limits, and never receive administrative credentials.
- Target Macs with Secure Enclave and Linux systems with TPM 2.0. External PKCS#11 devices are optional. There is no automatic fallback to software keys.
- Bind signed release, review, and deployment evidence to the source, binary, configuration, host, and validity period. Check all 13 criteria on both OSes before accepting production startup.

Local and hosted deployments use the same HTTPS, cryptography, and authorization. Even single-user operation requires an independent guardian and a witness that cannot be rolled back with Vault. Native approval keys are interactive. Service and TLS signing keys remain native handles at an independent key custodian. Mac/Linux clients use a common Linux SNP guest; each protected operation requires fresh attestation, and DB runtime memory remains inside that guest. See [conditional guarantees](docs/GUARANTEES.md) and [confidential deployment](docs/CONFIDENTIAL_DEPLOYMENT.md).

## Verification

Linux prerequisites: Rustup, a C compiler, pkg-config, OpenSSL development headers, Python 3, Java 21, Node.js 24, and Docker. macOS builds require Xcode Command Line Tools and OpenSSL.

```sh
python3 scripts/restore-vendor.py
bash scripts/prepare-tools.sh
python3 scripts/verify.py --with-docker --macos-cross
```

Kani checks the policy code used by the product; TLC checks a finite concurrent model; execution tests cover HTTPS, cryptography, databases, separate-UID isolation, and sandboxing. Verification also includes locked builds, dependency auditing, and a clean rebuild in a separate target directory. [Saved evidence](evidence/latest/report.md) records commands, results, and source/log/binary SHA-256 digests. Checks skipped without Docker are marked NOT_RUN. This is not a proof of the entire system's safety or third-party certification.

```sh
cargo run --locked -p vault-rs -- readiness
cargo run --locked -p vault-rs -- observe --config /absolute/path/config.json
```

Without evidence, `readiness` exits nonzero. Normal `serve`, `witness`, and `broker` commands require `--acceptance`. The test-only `--verification-run` option never sets production readiness to true and restricts server binding to loopback. Do not use it to bypass production acceptance.

## Interfaces

Commands include `initialize-storage`, `seal`, `protect-config`, `rotate-storage`, `rewrap-config`, `measure-bundle`, `broker`, `approve`, `custodian`, `serve`, `witness`, `observe`, and `readiness`. Owner and guardian approval use typed JSON and native-key confirmation prompts or PINs. A general-purpose OAuth consent UI and organization-management UI are not included.

See [key, OAuth, and recovery operations](docs/OPERATIONS.md), [broker and acceptance](docs/BROKER.md), [the protocol](docs/PROTOCOL.md), [the threat model](docs/THREAT_MODEL.md), [key enrollment and physical testing](docs/HARDWARE.md), and [configuration examples](examples/). Example configurations contain placeholders and cannot be started unchanged. Test PEM files contain public synthetic data.

## Project language

Use English for repository documentation, code comments, user-facing messages, generated reports, commit messages, and pull request descriptions.
