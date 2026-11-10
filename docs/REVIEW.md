# レビュー記録

別コンテキストのagentによるレビュー。第三者機関の認証ではありません。

security_reviewから報告されたMac ACL、device unwrap後の期限、DB generation差替えの3指摘を修正し、回帰試験を追加しました。同agentの最終パスはツールエラーで中断したため、完了したsecurity auditとは数えません。以下はformal_reviewによる実装接続の最終確認です。親agentによる追加のMac ATTACH修正とCI検証は実行ログへ記録します。

# Final integrated-fix review

Independent automated read-only review by /root/formal_review, 2026-11-10. Scope: the parent-requested integration changes and directly adjacent production paths. No attack tools were generated and no product source was edited. This pass is source review; it does not rerun or certify the parent's test/proof outputs.

## Result

The one configuration-acceptance correspondence issue reported in this pass is now closed by source verification of the parent fix. No unresolved concrete finding remains within this bounded review scope under the primitive contracts below. This is not a claim that the entire service has no vulnerabilities.

### F-1: Broker discards the accepted configuration snapshot — CLOSED

Original finding: the Broker command called `require_acceptance(...)` but discarded its returned `VerifiedDeployment`, then `broker::run` read the configuration pathname again. Serve and Witness already parsed accepted snapshot bytes.

A concurrent administrator configuration update can therefore cause Broker to execute different configuration bytes than the bytes authorized by the deployment acceptance. Protected-path checks prevent the AI UID from doing this; this is not an asserted unprivileged file-write bypass. It is an avoidable mismatch in the exact-config acceptance contract, especially during administrator update/restart operations.

Verified closure: `main.rs:255-257` now retains `VerifiedDeployment` and passes `accepted.map(|a| a.configuration)` to Broker. `broker.rs:270-286` accepts that snapshot and deserializes `snapshot.bytes()`; only the explicit no-acceptance verification path reads configuration from disk. This addresses F-1 without replacing the protected-path checks. Follow-up verification was source inspection, not a new test execution.

Parent also notified this reviewer of a forthcoming parent-only canonicalization of the rotation ATTACH path. That additional change is outside this final follow-up verification; it is not silently included in this disposition.

## Integrated changes reviewed as correct

- `store.rs:20-36,449-453`: Ledger embeds the exact policy State; authorization passes that State and assigns the entire returned State. No hand-maintained field projection/writeback remains on this path. Serde flatten preserves the existing top-level state field shape.
- `wire.rs:75-84`, `protocol.rs:177`: the production operation-to-request conversion is inside the directly checked policy crate and is called by the service.
- `lib.rs:169-177`, `crypto.rs:171,220`: both production 32-byte split/join operations call the actual indexed loops covered by the policy harness. Fresh independent masks still depend on OsRng.
- `store.rs:120-129`: installation uses the same record/hash/context binding predicate as release and broker verification.
- `readiness.rs:30-106`: the acceptance digest binds raw configuration bytes plus canonical input paths, escaped JSON-pointer roles and file SHA256 values, including nested key/helper/CA/provider/extension inputs and the database key envelope. Mutable SQLCipher pages are intentionally omitted.
- `readiness.rs:115-124`, `main.rs:521-568`, `storage.rs:201-247`: production Gate and Witness receive an authenticated generation pin. The exact envelope bytes are hashed and compared before parsing/unwrapping; missing or replacement generations fail closed. Pinning is sourced from the accepted snapshot, not recomputed from the replacement envelope.
- `storage.rs:256-270`: only the parent is canonicalized for macOS `/var` compatibility; the final component remains subject to SQLITE_OPEN_NOFOLLOW. Private singly-linked-file validation remains in place. Production also requires a protected canonical parent.
- `client.rs:18-28`, `broker.rs:403-423`: static plaintext retrieval rechecks time after a potentially interactive unwrap, and Broker checks again before launch. Plaintext failing that check stays in a Zeroizing value and is not handed to the workload.
- `broker.rs:124-145`: operation expiry is bounded by the verified access token's expiry in addition to grant, challenge and maximum request lifetime.

## Remaining contracts and limits

1. Signature verification authenticates the expected registered keys; HPKE/AEAD provide confidentiality/integrity; hashes are collision-resistant; random masks/keys/nonces are independent and unpredictable.
2. Serde and other parsers implement their documented formats and field meanings. The policy predicates and shared shapes reduce mapping assumptions but do not prove parser libraries.
3. SQLCipher/SQLite transactions are atomic and durable; witness CAS is linearizable and independently persistent. An attacker cannot roll back the witness together with the Vault DB. PostgreSQL issue transactions/advisory locks implement the reviewed idempotence contract.
4. OS ownership, ACL, no-follow opening, process/UID/FD isolation, protected administrative paths and native helpers behave as documented. The kernel, administrator identity and required approval domains are outside the adversary's control. Hardware non-exportability has not been physically tested by this review.
5. Non-DB dependency files are measured at acceptance and subsequently reopened from administrator-controlled paths. Correct composition assumes trusted administration does not mutate those dependencies during startup/use. The DB envelope is stronger: its original accepted hash is checked on the exact bytes consumed. A malicious root process is outside this guarantee.
6. Clock observations are fresh and trusted. The expiry check is a logical authorization point, not a real-time guarantee against arbitrary scheduler suspension between instructions.
7. Actual signature/parse/SQL/OS adapter calls, release-path coverage, compiler/runtime and verifier correctness remain composition/TCB assumptions supported by review and integration tests. This report is not a whole-service refinement theorem or a cryptographic proof.

The earlier expanded TLA proposal and results remain in PROPOSAL.md. Those finite bounds and explicit interface assumptions remain applicable. Distinct signing keys do not prove distinct human operators or independent administrative domains.

## Reviewed source digests

These digests identify the initial read snapshot, except main.rs and broker.rs which are refreshed for the verified F-1 closure. Other subsequent parent edits require their own validation. These are review metadata, not a deployment attestation.

- `crates/policy/src/lib.rs`: `04cbcb5ed51c9904f3b59e01517b18adfef504d5f9713244fce0bea5826a1c4b`
- `crates/policy/src/wire.rs`: `9abff6040b164d4e9aa9ea599b0a322ac4125f05691e3a4c173a98d652e3c23e`
- `crates/vault/src/store.rs`: `723fb846d9ce93a9311ee76f5d9c0431fd7a1e227330329cbe5b196d29a9f89b`
- `crates/vault/src/protocol.rs`: `e110e4182235d7030a2524cef48a7ced86cc73e3b3e0060a9bc52b402192310a`
- `crates/vault/src/crypto.rs`: `285a694df2f49de7a7c4e1f740297be6fb4689445cc131476692045e4612549d`
- `crates/vault/src/readiness.rs`: `443d0cf4c2f18e221bb615aa8f371acbb8202832d666bc4df071836fec1886bf`
- `crates/vault/src/storage.rs`: `b57d07bf4f9ba9307ed621efdc33504a8d9a1610d8a4558fe1636fbbaa94985e`
- `crates/vault/src/main.rs`: `ce638a704fdd49b00f3d509a2d94de2fdd5860955ab38bb143f7d2518b8f695c`
- `crates/vault/src/client.rs`: `b3c7071f89bc0c800501a7c9ad0d02212a179d420cbab2d8ae69f08a351f2906`
- `crates/vault/src/broker.rs`: `a69c2dbf0e339a2ad86bd0ea9e88b4b75e6b868ae62368d6ad46571cbd6bbe44`
- `crates/vault/src/runner.rs`: `001c64bc3d3b21b8a222b3a458d3e858c248ef5e327935a4c4ebe3fa7b7cf2f1`
- `crates/vault/src/native.rs`: `59ba5d2a0d2fa16bbb1431dfbd4fbecb4f665d7a1caf9b499530fc8e162e1151`
- `crates/vault/src/hardware.rs`: `2e8d3b19ec00ac918f3abec3fe8f4c96b42e601420688c8e15202c8f09f336fb`
- `crates/vault/src/resident.rs`: `f8b95ace384e19d2e769c86230a4012fc55e0a5ad8720130705e023c8a206b6d`


---

# Independent formal-review proposal (scratch, 2026-11-10)

This is a review artifact. Product files were not modified by this reviewer. The parent must review the model/claims before adopting them.

## Expanded model and exact results

`VaultExpanded.tla` / `.cfg` extend the original model with persisted challenge revision + nonce, challenge replacement, independent reserve/commit/crash actions for normal requests and revoke/quarantine, and a pending dynamic-issue operation with identical-operation retries. The witness holds the complete abstract ledger rather than an unrelated counter. A DB rollback chooses an actually committed historical ledger while the independent witness is preserved.

Baseline: TLC 2.19, four request identities, budget 2, at most two newly issued challenges, two administrator attempts and two provider attempts. 9,465,906 states generated, 1,587,137 distinct states, complete graph depth 33, no invariant failure, 37 seconds. `baseline.log` is the raw result. TLC uses fingerprints; its printed collision estimate is approximately 7e-7, not an unbounded mathematical induction proof.

Checked invariants:
- `NoUnauthorizedRelease`: every disclosure corresponds to an operation whose device AND guardian evidence and exact current nonce/sequence were accepted.
- `NoReplay`: distinct operations cannot disclose under the same sequence; static operations cannot disclose twice. Two replies of the identical committed dynamic issue are expressly permitted.
- `BoundedRelease`: at most Budget distinct authorized operations disclose. It does not incorrectly bound the number of retransmitted ciphertext replies.
- `CommitBeforeDisclosure`: each response comes after its authorization commit and below the independent witness sequence.
- `OneCredentialPerOperation`: retries return a single provider credential per exact operation identity, under the modeled provider transaction/idempotence contract.
- `TypeOK`: finite-state bounds and phases.

Negative controls each produced an actual counterexample (raw `<flag>.log`):

| Weakened flag | Failed invariant | Distinct states before stop |
| --- | --- | ---: |
| RequireGuardian | NoUnauthorizedRelease | 1,711 |
| RequireDevice | NoUnauthorizedRelease | 1,918 |
| RequireWitness | CommitBeforeDisclosure | 12,691 |
| RequireNonce | NoUnauthorizedRelease | 11,025 |
| CommitBeforeRelease | CommitBeforeDisclosure | 141 |
| RequireIdempotence | OneCredentialPerOperation | 3,015 |

Three expected-failing coverage invariants demonstrate non-vacuity:
- `NoHonestStaticRelease`: reached a real honest static response (846 distinct states).
- `NoIdenticalIssueRetry`: reached two identical issue replies (66,573 states).
- `NoRecoveredAdminCrash`: reached admin reserve -> admin crash -> quarantine reserve -> quarantine commit (836 states). The trace has two revisions and only the initial and final committed history entries, demonstrating the first revision was reserved but not committed.

One parallel TLC invocation initially raced on extracted `/tmp/Naturals.tla` and failed during parsing; its sequential rerun succeeded and produced the expected coverage trace. Run sequentially, or pass a different `-Djava.io.tmpdir` to each JVM. Do not treat any nonzero exit as a successful negative control: check the named invariant failure explicitly.

Example from the repository root:

```
java -XX:+UseParallelGC -Xmx1g -cp .tools/tla2tools.jar tlc2.TLC \
  -workers 2 -metadir .tools/review-formal/states \
  -config .tools/review-formal/VaultExpanded.cfg \
  .tools/review-formal/VaultExpanded.tla
```

## Abstraction and code correspondence

| Model action | Production behavior |
| --- | --- |
| ChallengeReuse/ChallengeBegin/Reserve/Commit | `Gate::challenge`: reuse valid stored nonce, or persist replacement through witness then DB |
| Begin | `Gate::authorize`: exact installed grant, record, protocol, challenge, policy consumption |
| Reserve/Commit | `ordered_commit`: witness CAS, then atomic SQLite commit |
| ReadReply | linear `Committed` consumption before guardian-share decryption |
| IssueAttempt | PostgreSQL operation-ID advisory lock + existing lease lookup + transactional role/lease insertion |
| FinishBegin/Reserve/Commit | `Gate::complete_issue`: pending -> last_issue, durable completion |
| Resume | `Gate::resume_issue`: only identical still-valid signed pending operation |
| AdminBegin/Reserve/Commit/AdminCrash | owner-authorized revoke or exact-current-checkpoint quarantine |
| Rollback | restore a previously committed Vault DB, without rolling back the independent witness |

The model initializes one installed grant. Installation, grant signatures, owner recovery signature/current-checkpoint checks, cryptographic authenticity/confidentiality, provider SQL transaction semantics, clock arithmetic, UID/process isolation and parsing are not proved by this TLA model. Challenge replacement abstracts old-challenge expiry, and 0 means no nonce. Cryptographic hash collisions are excluded. DeviceOnly and GuardianOnly are stronger cases than theft of token+DPoP alone; actual token/OAuth/field checks are proved separately in shared Rust predicates. Different tenant IDs require the Rust binding proof and actual adapter tests; this model is one grant.

The provider idempotence transition is an explicit contract from actual SQL adapter review/tests. `RequireIdempotence=FALSE` demonstrates the global invariant depends on that contract; it is not a proof of PostgreSQL itself. SQL durability and witness CAS are likewise interface contracts, not conclusions from this TLA model. No liveness or infinite-user theorem is claimed. The model allows already-committed static replies after revocation, matching the documented linearization point. It permits fail-closed service unavailability after an interrupted reservation.

## Direct Rust correspondence review

The parent's new `crates/policy/src/wire.rs` now contains actual shared Grant, Operation, Challenge, Trust, AccessClaims, DpopClaims and RecordContext shapes. `protocol.rs`, `broker.rs`, `store.rs` call the same exact binding/time/scope/DPoP predicates used by Kani. This closes the old hand-built Grant/Operation `Binding` projections rather than merely claiming an unchecked mapping is correct.

Additional recommended direct closures:
1. Put `Operation::request(now)` in policy, call it from `verify_release`, and verify exact epoch/sequence/not_before/expires/now fields. Current protocol still manually projects these fields into Request.
2. Embed the shared policy `State` in Ledger with serde flatten (or move generic Ledger to policy) so `Ledger::state()` does not manually map revoked/locked/epoch/next/remaining; write back the complete returned State.
3. Use `record_matches_grant` in `Gate::install` as well as release and broker validation.
4. Keep the actual 32-byte split/join loops inside policy, with all 32 bytes symbolically tested; a byte XOR lemma alone does not prove implementation indexing.
5. Mutate each shared field family, nonce check, OAuth scope/expiry and DPoP binding in actual code to confirm the exact proof harness fails. Never count a compilation error as a detected authorization mutation.

Concrete reviewed issues reported to parent and now being fixed: fresh expiry must be checked after potentially blocking device unwrap and immediately before broker launch; operation expiry must be bounded by actual access-token expiry as well as grant/challenge/max lifetime. The security reviewer separately found the known-key replacement DB-envelope vulnerability and is checking the parent's pinning fix.

## Conditional production claim that is supportable

Product release eligibility and a concrete deployment's acceptance must be separate predicates. Do not invent a private live deployment, attestation logs or human approvals to force `production_ready=true`. A usable release can be eligible after real Mac/Linux software E2E, direct Kani checks, bounded concurrent/crash/rollback exploration, real DB failure tests and reviewed security fixes. Its per-host production entrypoint must still reject an unaccepted binary/config/key-envelope generation or missing required evidence.

A precise security statement is: under signature authenticity, HPKE/AEAD confidentiality and integrity, collision-resistant hashing, atomic durable serialized database transactions, linearizable independent witness CAS that the attacker cannot roll back, the documented OS account/process protections, fresh trusted time, correct key registration and independently controlled device/guardian approval, an attacker with arbitrary AI/tool-account code, token and DPoP key cannot obtain additional Vault plaintext, broaden the signed grant, consume a fresh sequence twice, or recover a static secret from a DB/WAL/envelope leak. A legitimate disclosed secret is outside the requested guarantee. Dynamic issuer plaintext exists inside the explicitly trusted issuing adapter. An attacker who controls all required signing/approval domains cannot be distinguished by another possession proof.

The directly verified Rust predicates and durable-order controller support the authorization part of that statement. Integration/OS tests and source review support the adapters and isolation. They do not constitute a whole-service TLA-to-Rust simulation theorem or proofs of third-party cryptography, OS kernels or physical hardware. Physical-key experiments are explicitly excluded by the user; this does not prove non-exportability. Three distinct signer public keys prove different keys, not different humans, independence of administrative domains, hardware attestation, or the truth of signed evidence.
