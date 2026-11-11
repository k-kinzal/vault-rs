# Threat model and prerequisites

## Goals and boundaries

Forwarding, echoing, or maliciously using a secret already returned to an authorized tool is explicitly excluded by the requester. Vault keys, grants with expanded privileges, unauthorized decryption, reuse of consumed permissions, and decryption from leaked databases remain in scope.

An attacker holding both an OAuth token and its DPoP private key is indistinguishable from the legitimate client at the OAuth layer. The additional distinguishing evidence is a signature from the device and guardian in separate protection domains, covering the nonce, recipient, target, executable, and expiry. An attacker who can freely operate those signing oracles exceeds this assumption. Blockchain or zero-knowledge proofs of possession cannot distinguish the legitimate party from an attacker using the same stolen witness either.

## Attacker capabilities

| Attack | Implementation response | Remaining assumptions |
|---|---|---|
| OAuth token and DPoP key theft | Require independent device and guardian signatures | The attacker cannot operate the approval UI or signing service on the user's behalf |
| Network observation or substitution | TLS, signatures, AEAD, and recipient/request-hash binding | Trust certificate, issuer, and owner public-key enrollment |
| Database, WAL, backup, and key-envelope disclosure | SQLCipher, wrapped keys, and E2E encryption | Non-exportable keys and unlock authentication remain intact |
| Vault database tampering or rollback | Stop on a mismatch with the independent witness revision and hash | The witness cannot be rolled back at the same time |
| Out-of-scope operations or another user's grant | Enforce owner signature and matching OAuth sub, grant ID, action, and resource | Trust owner and AS keys |
| Duplicate or concurrent requests and crashes | Witness, then database commit, then disclosure; consume a use | Trust SQLite locking/fsync and witness CAS |
| Malicious extension input | Pin role, TTL, and provider; prohibit arbitrary SQL | Trust actual PostgreSQL privileges and the trusted issuer |
| Compromised AI/tool dependencies | Bind the grant to executable hash and recipient; expose no keys over HTTP | Root-managed broker and disposable UIDs are implemented and Linux isolation is tested. macOS software runs in native CI; physical-key tests are excluded |
| PC theft | Design uses Secure Enclave with user presence and TPM with a PIN | Physical devices have not been tested. Seizure of an entire running, unlocked PC remains unresolved |
| Compromised service, OS, or compiler | Outside the guarantee as a TCB compromise | Requires an independent guardian, least privilege, update approval, and reproducible-build verification |

## Trusted components

The trusted computing base includes owner grant approval, OAuth AS signatures, independent device and guardian key protection and approval, the Runner, verification code, cryptographic libraries, C code such as SQLCipher and OpenSSL, the kernel, hardware, clock, randomness, and compiler/verifiers. `unsafe_code=forbid` in the project's Rust code does not prove the safety of C dependencies or the OS.

The implementation only checks that `device_public_key` and `guardian_public_key` are different keys. It does not attest that they belong to different physical devices, people, UIDs, or cloud accounts. Non-exportability also depends on API responses and enrollment procedures.

Local and hosted deployments use identical mechanisms. An independent witness is required even locally. Keeping Vault and its witness on the same disk, with snapshots that can roll both back, does not provide rollback resistance. Equivalent resistance in a fully offline single-machine deployment would require non-rollback state such as TPM NV; that is not implemented.

## Revocation and availability

The linearization point is the durable commit that consumes a use. Revocation committed before that point rejects the request. Later revocation cannot undo a committed operation or recall a returned secret.

If the witness succeeds but the database commit fails, processing stops. An old backup is never automatically adopted as the latest state. Quarantine against a current owner-approved checkpoint permanently retires the old ID, after which a new ID may be authorized. Key rotation and witness-preserving quarantine/reauthorization are implemented. Losing a decryption key requires a previously prepared recovery protection domain; without a recovery key, the data cannot be restored. Simultaneous witness rollback or loss of its latest state cannot restore permissions. Deadline handling resilient to clock rollback is not implemented; trusted time is assumed.

The guarantee excludes DoS, metadata leakage such as traffic volume, database size, and public-key fingerprints in envelopes, OS memory forensics, and physical attacks while unlocked. Zeroization is best effort and does not cover every library copy or swap.
