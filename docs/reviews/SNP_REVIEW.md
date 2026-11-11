# In-progress SNP verifier review

Read-only primary scope: the two new attestation modules; supporting inspection of key-role selection, runtime key variants, readiness path pinning, and pinned sev8.0.0 parser/certificate/report verification. These are uncommitted changes on baseline5f7400c. No product edits, builds, proof runs, new attack tools or physical execution were performed. The per-operation RPC and guest-image/startup integration were explicitly pending at task assignment; their new concurrent implementation is not certified by this report.

## Findings

**S1: implication-only proofs admit blanket denial.** `policy/attestation.rs:50-75` only checks the case where accepted/challenge_live returns true. Both proofs pass if their target becomes constant false. Current implementation does not always deny; this is a concrete coverage gap. Prove accepted iff the independent declarative conjunction, and challenge_live iff `issued<=now && (now as u128)<issued as u128+30`. Include satisfiable positive acceptance and negative mutations for required boundaries. Preserve full scalar domains.

**S2: endorsement revocation is unchecked.** `vault/attestation.rs:75-79,108-117` verifies the certificate chain and dates. sev8 Chain::verify checks ARK self-signature, ARK->ASK and ASK->VCEK signatures; its certificate verifier is X509::verify(public_key), not a revocation-aware PKI validator. A date-valid signed endorsement remains accepted after a relevant revocation until local policy is withdrawn/expired. expires_at alone has no enforced maximum approval lifetime.

Verify authenticated fresh issuer revocation data for the certificates it covers, reject known-revoked/compromised endorsement and TCB material, and bind that policy to acceptance. If operating offline, explicitly specify/enforce the bounded staleness/renewal interval and independent custodian administrator's revocation duty; do not call date/signature validation a complete revocation check. A fresh quote nonce establishes quote freshness, not revocation freshness.

**S3: direct proof still has a manual field-projection boundary.** The actual assignments at `vault/attestation.rs:115-132` currently compare the intended fields correctly: exact chip ID, VCEK-endorsed reported TCB, exact measurement and request data, VMPL, debug/migration/SMT policy, signing-key selector, and componentwise TCB floors. Kani checks only the resulting booleans/scalars. Version/algorithm/canonicality, certificate dates, policy expiry and array-equality projections remain outside the proved predicate. Do not claim whole-verifier refinement from this proof.

For stronger correspondence, use shared expected/observed structures holding actual measurement/report-data/chip arrays and normalized scalar fields, then call one pure decision from production. Kani can prove their exact comparison/floor/time rules. Parser, DER/X509, SHA/signature implementations, AMD TCB semantics and hardware meanings stay primitive contracts. Never let wire input construct verified crypto booleans.

**Transitive VCEK pinning follow-up:** initially, ConfigurationSnapshot did not recognize vcek. During review the parent added the `vcek` path field (`readiness.rs:54`); source inspection confirms it now enters the existing role/path/content digest. This specific omission is closed at source level. Future CRL/policy/image-manifest inputs need equivalent transitive pinning. The same edit adds shared preflight to check_configuration, but the new preflight implementation is outside this attestation-only pass and is not certified here.

## Sound behavior in inspected source

- Roots and signing CAs are the pinned sev crate's Milan/Genoa built-ins, not request/config-supplied replacement roots. VCEK must chain to them before opening the verifier.
- Endorsement extension extraction rejects duplicate/missing OIDs. Reported TCB and exact chip ID bind the report to that leaf; masked chip IDs and non-VCEK selectors reject. TCB floors are componentwise, not lexicographic.
- sev ByteParser enforces exact report length before decoding. Version/algorithm checks and exact re-encoding precede verification. This matters because sev verifies SHA384/ECDSA over the re-encoded first0x2a0 bytes: equality avoids accepting different parsed and signed representations.
- The predicate rejects debug/migration/SMT-allowed policy and nonzero VMPL. Local quote generation requests VMPL0 and rejects non-Linux execution. The `/dev/sev-guest` character-device check is only a local precondition; remote signed-report verification supplies trust.
- KeyRole's existing Kani harness uses iff and NativeKey::open_for calls its actual matrix. RuntimeKeyConfig now contains Native/Attested variants with no Resident scalar variant. AttestedKey's implementation is being added concurrently and is not reviewed by this disposition.

Only report versions2/3, Milan/Genoa and VCEK are supported. Newer versions, other products and VLEK fail closed. Deployments must choose an actually supported, sufficiently patched image/firmware combination. An arbitrary minimum_tcb value is not evidence that every known platform vulnerability is mitigated. Required platform mitigation bits must follow the chosen vendor security policy; the three checked policy flags are not exhaustive physical/side-channel protection.

## Required architecture obligations for the pending RPC/image

1. The measured agent must generate the HPKE recipient internally, keep its private key in guest-private memory, and build report_data itself. `quote(data)` proves only that guest code requested those64 bytes; an API that attests caller-selected report_data/recipient would let an outside caller obtain an attested response encrypted to an outside key.
2. Domain-separate a canonical transcript containing protocol version, custodian identity, protected key/generation, role, operation, input/context, approved config/image generation, unpredictable custodian nonce and guest recipient. Bind returned HPKE ciphertext to this same transcript. Reject swapped keys/roles/sign-vs-ECDH/labels/recipients and stale replies. Authenticate/pin the custodian too.
3. Attestation is not blanket operation authorization. A measured key agent must not expose unrestricted signing/ECDH to arbitrary network callers. Restrict custodian key/role/operation tuples and preserve actual protocol authorization before requests. Interactive owner/device/guardian approval keys must not become unattended service oracles.
4. Atomically consume a fresh bounded-lifetime custodian challenge before the private operation; concurrent duplicates and crash/restart must not resurrect it. Bound frames and reject unknown/malformed fields. Test actual adapter ordering, not just a pure live-time helper.
5. Launch measurement must pin kernel/initrd and immutable rootfs or a verified-boot chain that authenticates the agent and configuration. OVMF alone does not measure a later mutable application. Exclude host-controlled cloud-init, root login/debug agents, mutable code/modules and unverified configuration. Host_data is host-supplied; a runtime executable hash does not repair an insufficient boot measurement.
6. Keep SQLCipher pages/DEKs, provider credentials and guest private/traffic keys in private guest memory or encrypted external buffers. Cover swap/hibernation/crash output/shared virtio pages/logs/snapshots. The independent native custodian remains explicitly trusted and can perform private operations; do not claim secrecy against its compromised root.
7. Production serve/witness must require the attested backend before unlock, with no native/software fallback. Mac/Linux brokers use that same independent Linux service. Witness persistence must remain outside the adversary's joint rollback/snapshot capability. A measured witness colocated in the same rollback domain is not independent merely because its code is measured.
8. Fresh per-operation attestation cannot erase a DEK already delivered to a running guest. Acceptance expiry/stop policy, durable release budgets/revocation, generation rotation and witness continuity remain distinct. A report authenticates approved launch and request binding under the hardware/guest contract, not every future instruction or absence of all runtime bugs.

## Bounded conclusion

No signature-chain, chip-ID, request-equality or TCB-component wiring error was found in the inspected verifier. S1/S2 and the proof boundary in S3 remain actionable. RPC/startup/image integration must be reviewed and exercised before declaring the new production profile ready.

A defensible eventual claim is conditional: the actual Rust gate accepts only the supported, cryptographically verified, currently approved report and exact fresh operation/guest-recipient binding; under AMD confidential-memory/attestation, trusted immutable guest, trusted independent custodian, crypto and persistence contracts, an external malicious guest host cannot obtain the private-operation output or DB plaintext through ordinary host memory access. This is not an unconditional whole-system theorem, proof of all physical/side-channel resistance, or hardware-execution evidence.

## Exact reviewed worktree digests

- `crates/policy/src/attestation.rs`: `e49debc0498bb989cf43ed07ddc0857fb96264df3dfb094ef62878f6edd42052`
- `crates/vault/src/attestation.rs`: `a4cf7f085456f215e86e7b424369e0c13d82d3cd28eca8c4f95dcaed170be0ac`
- `crates/policy/src/key_policy.rs`: `f1f99b3a8b49657f62b539f349e421a299ed1fee007e3698d6d4f5852ad90b64`
- `crates/vault/src/keys.rs`: `d3b266992ac6c7881464c55aca3d1ca048d6a1655336c12ef0b41f224564f480`
- `crates/vault/src/readiness.rs`: `e491297468c428dd1a74f775cb53dd979ea994dfc908c7febf5cc2b80da28150`
