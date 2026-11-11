# Production goal v3: software release and deployment decisions

The goal is a product suitable for production use. Every `production_ready` decision must specify its scope. `software_release` identifies a distribution with the G01-G13 implementation, macOS/Linux software evidence, and conditional assurance below. `deployment` accepts that distribution on a specific host with specific configuration and key generations. The former is evaluated by `scripts/release-evidence.py evaluate`; the latter by the actual CLI command `readiness --acceptance ... --config ...`.

Version 2 combined product-development completion with acceptance signatures for an unspecified user host. These decisions are now separate so the product can be verified before a destination is specified. An unspecified deployment is never accepted through fabricated signatures, nor is the result recast as an unconditional proof of the entire system. G01-G13 defenses and the exclusion of physical experiments alone remain unchanged.

The acceptance criteria preserve the requester's requirements. The requester explicitly excluded physical-key verification while requiring completion of everything else, so only physical-device experiments for G04/G05 are out of scope. This does not mean non-exportability has been experimentally proven. OS software tests, formal verification, and independent review remain required. Treating mocks as physical devices or simply changing an expected result to true does not meet the goal.

## Scope

Target Macs with Secure Enclave and Linux systems with TPM 2.0. External PKCS#11 devices are optional. Do not claim equivalent non-exportability on systems without a protector. Local and hosted deployments share the protocol, implementation, and authorization, differing only in network reachability and user count. Even single-user operation requires an independent approver and a witness that cannot be rolled back with Vault.

Assume the AI can execute arbitrary code and debuggers under its OS account and obtain both an OAuth token and DPoP private key. Include malicious dependencies in developed tools/extensions, database/WAL/backup disclosure, and offline attacks against a lost PC. Forwarding a secret legitimately returned to the tool is explicitly excluded by the requester.

The design does not claim to distinguish an attacker from a legitimate user if the attacker controls the OS kernel, the protector's cryptographic implementation, the owner's approval endpoint, and the independent guardian. Formal assurance is conditional on this explicit TCB and standard cryptographic assumptions.

## Required acceptance criteria

| ID | Requirement | Required evidence |
|---|---|---|
| G01 | Token and DPoP key theft cannot authorize additional access | Signature verification, complete field binding, authorization-transition correspondence, and negative tests with counterexamples |
| G02 | The AI cannot read broker, decryption, or recipient keys | macOS/Linux attacks from separate UIDs against memory, FDs, IPC, configuration, and executable substitution |
| G03 | Execute only owner-approved artifacts and arguments | Hash binding, modification races, symlinks, environment injection, and request impersonation from another process |
| G04 | Keys are non-exportable and a stolen device cannot be used without approval | Hardware contract, helper builds, and software tests rejecting incorrect authentication or a different key. Physical-device experiments explicitly excluded |
| G05 | Secrets/database keys cannot be recovered from the database and WAL | Encrypted database, key envelopes, rejection of decryption with only one share, and protector integration tests. Physical-device experiments explicitly excluded |
| G06 | Preserve use limits, revocation, rollback resistance, and concurrency safety | Kani, state-machine models, real database fault injection, and independent-witness operation tests |
| G07 | OAuth permissions cannot be expanded | Real-AS authorization, expiry, subject, audience, DPoP, and cross-tenant rejection tests |
| G08 | Use the same mechanisms locally/hosted and for one/multiple users | Multi-tenant E2E tests over real HTTPS on macOS and Linux |
| G09 | Extensions cannot obtain issuer administrative privileges | Import/filesystem/network/fuel/memory restrictions, fixed role/TTL, and actual SQL privilege tests |
| G10 | Updates, restarts, and recovery cannot resurrect permissions | Signed release, artifact/configuration binding, rejection of stale evidence, and recovery/key-rotation demonstrations |
| G11 | Formal specifications correspond to security-critical implementation | Direct machine verification of actual authorization, binding, and broker/release gates; abstraction boundaries and a list of unproven dependencies |
| G12 | Forgery, stale logs, or self-report alone cannot pass production acceptance | Designated-authority signatures, source/binary/configuration/environment binding, evidence expiry, complete criteria, and negative tests |
| G13 | Releases can be reproduced and maintained | Locked builds, dependency auditing, pinned tools/images, complete logs and digests, and independent review records |

Set `software_release.production_ready=true` only when both OSes meet the product criteria and execution logs, distributed binaries, review, and formal verification cover the same source. G11 uses the direct machine verification and abstraction boundaries in PROOF_CONTRACT.md; it does not require or claim unconditional proof of OS/cryptographic/database internals. OS-independent verification such as Kani checks the same code shared by both platforms. OS-specific isolation, HTTPS/CLI, OAuth, and rebuild checks execute on each OS.

Deployment additionally requires G04/G05 key enrollment, an independent guardian/witness, trusted time, protected administrative paths, a real AS, and measurement and approval of the target host. Only after those checks may `deployment.production_ready=true`. Synthetic successful validator fixtures, Linux-only passes, or macOS logs from different source do not establish product completion.

## Authoritative evidence

Linux evidence is in `evidence/latest/`; macOS evidence is the GitHub Actions `macos-software-evidence` artifact downloaded to `evidence/macos/`; the combined decision is `evidence/release.json`. Preserve the executed commit, source fingerprint, and binary/log SHA-256 digests. Missing files, failed tests, or mismatched sources must fail acceptance. Public source publication, macOS CI, and separate-agent review were authorized by the requester.

## Preventing unauthorized exclusions

Include `Release.physical_tests_excluded=true` in the release signature. Physical methods for G04/G05 may be replaced with software methods only when it agrees with root-managed `AuthorityPolicy.allow_physical_test_exclusion=true`. The default is false. G02 OS isolation and G11/G13 evidence cannot be omitted. Kani full-value-range checks and negative signature tests verify this condition.

Defining a goal and providing evidence that it has been met are separate deliverables. Acceptance criteria alone never authorize production use.
