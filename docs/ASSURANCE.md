# Assurance scope and evidence

The product's production decision is `decision_scope=software_release` in `evidence/release.json`. Acceptance of a specific deployment is `decision_scope=deployment` from the actual `readiness` CLI. Product acceptance requires all Linux checks and software tests on real macOS for the same source. Deployment signatures are not generated automatically. Only physical-key experiments are excluded at the requester's direction.

## Goals and supporting evidence

| ID | Implementation and required evidence | Assurance boundary |
|---|---|---|
| G01 | Independent device/guardian signatures, Kani checks of shared wire predicates, stolen-token/DPoP and field-tampering tests | Trust signature unforgeability and enrolled keys |
| G02 | Separate-UID rejection of memory/FD/file/IPC access and direct broker invocation on macOS/Linux | Kernel/root are in the TCB |
| G03 | Bundle/argument/instance/recipient binding, immutable paths, macOS ACL rejection | Trust system runtime and administrator updates |
| G04 | Secure Enclave/TPM helper builds, swtpm, rejection of incorrect keys in native profiles | Physical-key experiments excluded; fixtures are not hardware evidence |
| G05 | SQLCipher/WAL, 2-of-2 E2E encryption, accepted database-generation pinning, rejection of substitution before unwrap | Hardware protector, cryptographic primitives, swap/physical-memory protection |
| G06 | Kani controller, TLC concurrency/crash/rollback model, real database commit failures | Independent witness CAS and non-rollback behavior |
| G07 | Real-AS code/S256 PKCE/DPoP/nonce/subject/expiry tests, shared scope/parser predicates | Production AS identity and consent operations |
| G08 | Actual CLI HTTPS on both OSes, two users, private stdin, restart, and revocation | Deployment TLS and identity enrollment |
| G09 | Wasm import/filesystem/network/fuel/memory restrictions, real PostgreSQL role/TTL/idempotence/revocation tests | Trusted issuer/SQL. Expiry alone does not terminate existing database sessions while cleanup is stopped |
| G10 | Database DEK/configuration/E2E rotation, permanent retirement, source/binary/config/host/epoch/expiry binding | Stop, install at new generation paths, and reaccept updates |
| G11 | Machine verification of actual authorization/shared types/32-byte splitting/commit controller, mutation tests with counterexamples | Primitive contracts in PROOF_CONTRACT.md; not a whole-service simulation theorem |
| G12 | Designated-key signatures and completeness, accepted snapshots, transitive-input pinning, negative tests | Trust signers and log provenance. Different keys do not prove different people |
| G13 | Locked builds, dependency auditing, pinned tools/images, clean rebuilds on both OSes, independent-agent review | Compiler and other dependencies remain in the TCB; not third-party certification |

## Formal verification

Kani checks the same no_std policy code used by the product across full Rust scalar bit widths. Coverage includes wire-field comparisons, OAuth/DPoP, challenges, execution, actual Request conversion, State transitions, persistence ordering, UID/revocation/interval handling, evidence methods and physical-test exclusions, and 32-byte share operations. Machine-checked initialization, transition, and finalization lemmas for the actual scope step/finish functions combine with structural induction to cover finite inputs, including the full 256-byte domain. Fold correspondence rests on Rust iterator/control-flow semantics and is distinct from a successful Kani run over two separately unrolled entire loops; see SCOPE_PROOF.md. `commands/kani.log` is authoritative for harness counts and results. Signature functions, serde, OpenSSL, and the OS are not themselves proven in Kani.

The TLC baseline explores one grant, four request identities, and a bound of two each for budget, challenges, administrator operations, and provider attempts. During review, the expanded model explored 1,587,137 distinct states and 9,465,906 generated states at depth 33. Rerun logs are authoritative and retain fingerprint-collision estimates. Removing each of six defenses must produce a counterexample to a specified invariant. Three reachability checks demonstrate an authorized release, an identical-issue retry, and quarantine after an administrator crash.

Mutations that remove authorization checks from actual Rust source must also produce `VERIFICATION:- FAILED` in the corresponding harness. Compilation failures do not count as successful detection. These checks do not prove cryptographic security, unbounded state for arbitrary user counts, whole-service liveness, or the absence of unknown vulnerabilities.

## Execution and aggregation

```sh
python3 scripts/restore-vendor.py
bash scripts/prepare-tools.sh
python3 scripts/verify.py --with-docker --macos-cross
python3 scripts/release-evidence.py evaluate \
  --linux evidence/latest --macos evidence/macos --output evidence/release.json
```

Linux runs record unchanged source between start and finish, formatting/Clippy/tests, a real OAuth AS, Kani/TLC/mutations, real PostgreSQL, swtpm, separate-UID isolation, actual CLI deployment, auditing, release build, and clean rebuild. The GitHub `macos-15` runner performs native unit/integration tests, OAuth, OS isolation and ACL checks, actual CLI use by two users with restart/revocation, Swift helper compilation, and a clean rebuild. A macOS cross-build alone does not satisfy macOS runtime evidence requirements.

Each manifest includes the source inventory, source fingerprint, and binary/log SHA-256 digests. The aggregate validator checks source equality across both OSes, every required check, log digests, and review results. This is a conditional decision based on reviewed execution logs; hashes and signatures do not prove the truth of those logs. Successful `readiness` fixtures test the validator and are not exported as acceptance of a real deployment.

## Reviews and dependencies

[REVIEW.md](REVIEW.md) records findings, fixes, and remaining assumptions from a separate agent. This is automated review in an independent context, not certification by an independent organization or person. Execution also exposed and resolved macOS differences in TLS certificate generation and database parent aliases/NOFOLLOW behavior.

The initial audit's crypto-bigint/SQLite/RSA findings led to P-256/HPKE updates and removal of the RSA private-operation crate from the product. Verification checks the upstream libsqlite3-sys archive digest and the single-line SQLCipher/SQLite dependency patch. There are no custom C-code changes. Execution logs are authoritative for the current RustSec database commit and audit results. Updates to the compiler, kernel, OpenSSL, helpers, and similar dependencies require a new distribution and deployment acceptance.
