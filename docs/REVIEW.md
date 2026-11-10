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


---

# Bounded release and native-evidence source review

Reviewed commit: `a61228f50987898b4247b7f57b0be23970d764ed`.
Reviewer: independent automated source-review agent `/root/formal_review`, 2026-11-10.

Scope: runner/native working-directory changes; native C isolation fixture and Linux/macOS wiring; release evaluator, packager and GitHub workflow; adjacent collector, source fingerprint and rebuild code needed to assess evidence binding. Product source was read only. No native attack tooling, new builds, CI invocations, or interrupted security-review calls were run or retried. This report is not execution evidence. The parent reports macOS CI still running; its outcome has not been verified by this reviewer.

## Findings

### R-1 — Medium: Linux native suites do not exercise the packaged release binary

`scripts/test-isolation.sh:6,23` builds/mounts `target/debug/vault-rs`; `scripts/test-deployment.sh:6,23` likewise mounts the debug binary. The package instead contains `target/release/vault-rs` (`scripts/package-release.py:10-24`). macOS correctly installs the release binary for native suites (`.github/workflows/verify.yml:63,65,73`).

Thus Linux native isolation/deployment checks can pass while the distributed release binary has not undergone those checks. Same-source unit tests and a reproducible release build are useful but do not establish native behavior of a different optimized executable. No concrete behavior difference in the current product was demonstrated; this is an artifact-to-execution correspondence gap.

Close by building and using the exact release binary in both Linux suites, recording the SHA256 of the installed executable actually tested, and checking that digest against the producer's packaged binary digest. Preserve the same all-features build configuration used for the distributed binary.

### R-2 — Medium: native fixture claims FD denial without checking inherited descriptors

`tools/isolation-fixture.c:25-38` checks opening the parent's `/proc/PID/fd/N` only on Linux. On macOS it explicitly ignores the supplied FD (`:27`) and checks only `task_for_pid`. Neither branch checks whether the workload already inherited the parent's open private descriptor. Yet `:75` prints a success statement including FDs denied, and the workflow advertises descriptor isolation.

`runner.rs:492-499,529-536` creates and passes a real open private FD, so a direct native inheritance check is feasible. Add a check on both platforms that this descriptor is unavailable to the workload (e.g. `fcntl(fd,F_GETFD)` must fail with EBADF, or compare fstat device/inode identity while scanning the bounded descriptor range). An inherited readable descriptor bypasses file-path permissions, so Mach memory denial does not cover this case. This finding concerns missing execution evidence, not a proven descriptor leak in the product.

### R-3 — Medium: native evidence accepts a zero-test successful run

`release-evidence.py:42-49` accepts only the generic substring `test result: ok.` for isolation, deployment and OAuth logs. Rust's test harness reports that same text and exits zero when a filter matches no tests. Linux's collector likewise treats a zero exit as a passed native command (`verify.py:16-25`), and the evaluator checks method names/booleans rather than positive native-test evidence (`release-evidence.py:83-87`).

The exact filters in the reviewed source currently name existing tests; this is not a claim that the current run skipped them. It is a fail-closed validation gap: an accidental filter/target mismatch can be recorded as completed native coverage and reach software `production_ready=true`.

Require positive counts and the exact expected test name, plus explicit native probe completion markers for AI denial, authorized worker delivery, ACL denial on macOS, UID monotonicity/timeout, and CLI deployment completion. Validate that required logs occur in the digest map. A negative collector test with an authentic `0 passed` test-harness summary should be rejected. The final evaluator should enforce these conditions, not only rely on a producer's `checks_passed=true` declaration.

### R-4 — Medium: direct Broker denial test accepts unrelated config failures

`tools/isolation-fixture.c:53` invokes Broker using `/opt/vault-isolation/private/key` as its config. That file is intentionally unreadable to the AI UID and contains non-JSON bytes. `:56-57` accepts any normal nonzero exit except127. If the explicit Broker privilege check regressed, this command could still fail on configuration permissions/parsing and the test would report Broker invocation denied.

The product's explicit root/UID check is present; no bypass was demonstrated. Close the regression-test gap by capturing and asserting the specific privilege-refusal error or by exercising a valid accessible setup with a verifiable intended denial stage. Excluding exec failure127 alone does not distinguish these failure causes.

## Reviewed behavior that is sound within the stated trust boundary

- `native.rs:121` sets an accessible `/` working directory for helper execution. `runner.rs:344` selects the staged, administrator-controlled directory before entering the worker. These changes address inherited inaccessible working directories without adding ambient environment variables or weakening the UID checks.
- The C fixture invokes native OS APIs and checks errors explicitly. Linux path probes require EACCES, so nonexistent `/proc` paths do not silently pass. Mac probes target the passed live test-process PID rather than an unrelated parent PID. The test timeout/alarm turns stalls into failure rather than success.
- GitHub `defaults.run.shell: bash` selects the platform's explicit Bash execution mode with pipefail. Combined with the script `set -euo pipefail`, failed native commands cannot be masked by a successful `tee` in the reviewed workflow. The final packaging job depends on successful Linux and macOS jobs. `if: always()` uploads failure artifacts but does not authorize the release job after failed prerequisites.
- Actions are pinned to commit hashes. Download steps select same-workflow-run named artifacts. Source manifests are compared against the packaging checkout, and producer log hashes are checked. The packaged Linux binary is copied into the evaluator's expected path and compared to the producer's binary digest; the Mac binary is compared directly to its digest.
- The producer uses real macOS execution checks (`platform.system() == 'Darwin'`) and does not label a cross-build as native execution. The compiled Secure Enclave helper is shipped, but physical-key experimentation remains explicitly excluded; synthetic helper tests are not hardware attestation.
- The release decision explicitly has `decision_scope=software_release` and `deployment_accepted=false`. Packaging documentation requires actual key registration and deployment acceptance rather than pretending to create operator approval.

## Remaining trust and provenance limits

The validator trusts reviewed producer executions and GitHub workflow/artifact origin. Hashes detect substitution after measurement; they do not authenticate an arbitrary locally supplied manifest or establish the honesty of its producer. `package-release.py:31-37` writes a fixed 'GitHub Actions same-run artifacts' authentication description even when run locally without GitHub context; outside this exact workflow that description should be conditional or explicitly marked unverified. This observation is a provenance-label limitation, not evidence that the reviewed same-run Actions download path is wrong.

The evaluator compares embedded source fingerprints recorded by the two producer binaries; it does not independently derive that fingerprint from the current tree. Its binary-to-source conclusion therefore depends on the reviewed build/collector path and trusted compiler/toolchain. Producer source-before/after checks and byte-identical rebuilds support that path but are not an independent compiler proof.

OS kernel/UID/ACL/FD semantics, compiler/runtime, cryptographic primitives, independent witness persistence, correct key registration and trusted CI administration remain explicit primitive/operational contracts. This review does not certify third-party dependencies, physical hardware, live deployments, or a whole-service refinement theorem.

## Source snapshot

The findings above refer to the requested commit, before concurrent parent fixes. Untracked evidence output and restored vendor files were present. Digests below are computed from that exact Git commit, not the concurrently changing worktree. They are review metadata, not deployment attestations. The parent began applying fixes during this pass; those follow-up edits are not included in these dispositions.

Observed HEAD: `a61228f50987898b4247b7f57b0be23970d764ed`.

- `crates/vault/src/runner.rs`: `9826db4885391ddcf16973b268a6c088a82852555e58f022c353a87a6f7460e8`
- `crates/vault/src/native.rs`: `e60b9cdb48f3c65302a2972bc757d128d13d3281ee9ac19d81b764d6a922db0d`
- `tools/isolation-fixture.c`: `d67a139542f0f9c139601a31982ac131849a4f3c9dcacc28114a017097e5d59d`
- `scripts/test-isolation.sh`: `ae8495d64bcaef7e69e11105a0869dd7bde70d17d21c0263db1a13dda100bea3`
- `scripts/test-deployment.sh`: `a7bf74bf1a2a682000954cd62108a2b0b62b0a4d0c0a126c199fb22b08bb59a7`
- `crates/vault/tests/deployment.rs`: `fdd964d0456f3b52902e8fff892934244444785a216ae7eff6114aafda51d54f`
- `scripts/release-evidence.py`: `71e99c9cbff107b63ce1b1fe2847374ab279cf9beafaf89bdb0176057604a42e`
- `scripts/package-release.py`: `0915b668cd789c430f0469418d7e06bcdeb3bf42c4d655b4c4eb7b2ff66db949`
- `.github/workflows/verify.yml`: `fe940f5c6eae7d10776d2efd9b09161e7cfd66971ee616b11bed68de45a0bd39`
- `scripts/verify.py`: `9de7e56092254c9ada23c29315ca05d49bdb20efd6e859d88faedca083ea5736`
- `scripts/check-reproducible.py`: `46c79f2e2281908c570e372a58881ec6fb6b6548385326ff0435f84f1baeedeb`
- `scripts/restore-vendor.py`: `43bed4bf7730649bebeb76192044560f7f5358cdd89310dd6a6cf49b295e32d5`
- `crates/vault/build.rs`: `e5c40a9c0bc94cf2f9b2a79b6450836e06d9f61dbd067aad06f67d98cf322662`
- `docs/review-status.json`: `bd5454be083caa428db22a0184e54a0fed1fefce2e6693f3e3a72f784add0b38`
- `docs/REVIEW.md`: `46d954118c2d02db4ad4e887188a926072adac039b969591e4533ba82256208a`
- `docs/ASSURANCE.md`: `bb3d21e652ee5f4aae55c99d30d4d5851a2b8489162d1ebf739f1fe5249f5f67`
- `docs/PRODUCTION_GOAL.md`: `b6008b0528f6864779c00c9319b51f73665315d9138bb4ec1745aaa98ed2c609`
- `.gitignore`: `020d44e9bfccc8fd06b4cf4d14b37e9c9fa9393f5ca4c9b59a2e732958cbc94b`

## Source-inspected follow-up closure

The parent supplied follow-up edits on top of a61228f. The reviewer inspected their actual source before recording these dispositions. **R-1 through R-4 are closed at source-review level.** No unresolved concrete defect was found within this follow-up scope under the previously stated CI/OS/toolchain trust contracts. This is not an execution certificate or a whole-service no-vulnerabilities claim.

| Finding | Verified closure |
| --- | --- |
| R-1 | Both Linux native scripts now build `--release --all-features`, mount the release executable, and emit exactly one `TESTED_BINARY_SHA256` receipt. Mac emits the digest of its installed tested executable. `evidence_checks.native` requires a unique matching digest; both producers and the final evaluator invoke it against the packaged binary digest. |
| R-2 | The C fixture now requires `fcntl(parent_private_fd,F_GETFD)` to fail with EBADF before either platform's memory probe. The real open descriptor number is supplied to both AI and worker probes. Mac no longer discards the descriptor argument. |
| R-3 | Shared receipt validation now requires a positive suite count, the exact focused test name, one passed/zero failed/zero ignored, and expected native completion markers, including Mac ACL denial. Producer and aggregate paths call the same validator. The added regression-test source contains positive control and negative cases for zero tests, wrong name, missing probes, missing/wrong/repeated binary receipt and generic success. |
| R-4 | The native AI probe captures child stderr and requires the exact Broker privilege-refusal message in addition to a normal nonzero/non127 exit. EACCES or JSON failure alone can no longer satisfy that check. |

Final evaluator follow-up inspected: `release-evidence.py:89-94` now requires all 24 common Linux commands, including tool versions, vendor/format/syntax validation and advisory-DB commit, and requires every corresponding log name in the Linux digest map. All seven required macOS logs must likewise appear in its digest map. Together with the existing `verify_logs` pass, required receipts cannot be silently omitted from hash coverage.

The new receipt checks are still evidence from trusted executions, not cryptographic proof that arbitrary supplied log text is truthful. Existing hash verification, unchanged-source checks and same-run workflow dependencies remain necessary.

### Bounded Darwin identity primitive review

Reviewed `crates/platform/src/lib.rs`, its private package manifest, workspace/dependency wiring and both call sites in `runner.rs`.

- The package is macOS-only, `publish=false`, and denies unsafe code except the explicitly annotated adapter. Policy and main product retain workspace `unsafe_code=forbid`; unsafe code was not spread into the authorization kernel.
- `configure_identity` validates the numeric UID range before registering a callback. It captures only that scalar. In the child it first verifies real/effective root identity, then short-circuit checks `setgroups(1,&gid)` -> `setgid(gid)` -> `setuid(uid)` in that order. Any failure returns the current OS error to abort spawn; no untrusted executable is intentionally reached after a failed credential transition.
- The group pointer references one live, aligned stack `gid_t`, with count1; no foreign pointer is retained. Callback source contains no allocation, formatting, logging, locks or deliberate Rust unwind. The safety comment now correctly treats Darwin/libSystem's allocation/locking behavior as an explicit OS contract, not a POSIX guarantee for setgroups.
- Mac worker and AI-probe commands use this adapter and do not also configure Command::uid/gid, avoiding an earlier std credential drop before the callback. Linux retains its prior std Command path.
- The worker checks real/effective UID and GID after exec, plus its independently resolved OpenDirectory group set. The native fixture checks real/effective identities, supplemental groups, private descriptor closure, and failed root UID recovery. The production worker still separately enforces its >=10000 UID policy.
- The temporary sudo numeric-UID worker launch is absent from the inspected final call sites. The existing native-key helper GUI-session path is a separate unchanged mechanism.

This adapter is an explicit narrowly reviewed OS primitive boundary. Kani does not prove the Darwin kernel, libSystem, fork/exec machinery or absence of OS credential bugs. Native macOS execution remains necessary to establish the supported deployment behavior.

### Execution evidence status

This follow-up performed source inspection only. The parent reports matching-digest Linux release-binary isolation/deployment tests passed and the new adapter cross-built for Mac ARM64. This reviewer did not rerun or independently validate those logs. A cross-build is not Mac runtime evidence. The earlier a61228f Mac run cannot validate these changed source bytes; fresh same-source native CI must finish before software release acceptance.

### Follow-up source digests

These hashes bind the exact uncommitted follow-up worktree files inspected, on top of a61228f, before the parent appends this report and freezes the next CI commit. They supersede the earlier commit-blob hashes only for these files. Report insertion and other later edits require the normal fresh-source evidence checks.

- `Cargo.toml`: `aa7c778c44a6eb222f2fd93a287add4e992558dc281dec51502e71e386aa8b68`
- `Cargo.lock`: `4c780384a62376d58d808ab0ee70a868ba92442403a8fde1b709258826f9cca6`
- `crates/platform/Cargo.toml`: `289a41d66326484d7e447f15c13653271fed620c52c28c36ea93b656a4fb2d07`
- `crates/platform/src/lib.rs`: `fa7f2ece139a999de06ff90f3faac6f9cff9e4d333ef4b03a9f4f587e87bcf1d`
- `crates/vault/Cargo.toml`: `abb5a3d078a46bcfbe81363b713ac685ebd4186c0baa8e0f2d9e179fcf04529a`
- `crates/vault/src/runner.rs`: `3b5fa8ffe6bf2ef248f529bd0974c0fa562d6b7b74bf1f8f726eee5ca980f5ab`
- `tools/isolation-fixture.c`: `cc4741dc610d369bd2cec9d85b6674992a261536f5e346515afe7c34770cb10f`
- `scripts/evidence_checks.py`: `202767166da63f410940b2fd37997db409004f54f8e9113d1992bb0e1ce4c2a2`
- `scripts/test-evidence-checks.py`: `08f06a10bdae9ee029a1849f699dc9efc99b2d1470d45eb3b0aa3fa3f3b9f5df`
- `scripts/test-isolation.sh`: `2a5294528d95ec03705b316e1192f6caf159d6a22f3660da991e6089dd0db2ad`
- `scripts/test-deployment.sh`: `d6b9501e74f7f8ceb02c066ccec4baaae8bbad921859273731ff90077d11b545`
- `scripts/verify.py`: `cb7e6cf48bba5c726d65e8f2a85bd0e98afa5782a49966b7c92324792b337dcf`
- `scripts/release-evidence.py`: `0a6c06697c406cb5bc88b45075a91ff90d1ff38a8b4174bc5a070258f6c075d2`
- `.github/workflows/verify.yml`: `b3a48559605445f702c074e8eac0b2573107785638f86181282261b00a1441d8`
- `docs/PROOF_CONTRACT.md`: `d5f92dc095c7918d743eb1919cef0d1b873e6acc6eff29880b6f5c20ce73267f`


## Source-only follow-up: macOS VM limits and reproducible release profile

Reviewed the bounded changes on top of commit `127b3541bbc31e959f4a753bd4c52d18c70041f4`, including the final release-profile edit. No new concrete defect was found within this source-inspection scope. Earlier R-1 through R-4 remain closed at source-review level. This disposition is conditional on the previously listed trusted OS, compiler, build producer and CI-origin contracts; it is not native execution evidence or a proof that the new build is reproducible.

- `runner.rs:408-422,443-470` retains Linux's 512 MiB virtual-address ceiling and obtains macOS's current worker VSZ from protected `/bin/ps`, using its own numeric PID, a cleared environment and null stdin. The observation must succeed, be at most4096 bytes, parse as a positive u64 KiB count, and survive checked multiplication/addition of512 MiB. Both hard and soft AS limits are set before executing the workload; observation or limit failure aborts. Existing identity, supplemental-group, path and descriptor checks are unchanged. This trusts Darwin's protected inspector and virtual-memory/resource-limit semantics. It guarantees neither a512 MiB RSS cap nor DoS resistance; the code and BROKER text explicitly state that distinction.
- `tools/isolation-fixture.c:84-88` adds actual kernel `getrlimit` assertions for hard core=0, descriptor=64, CPU=60 and finite address-space limits. The existing assertions for effective identity, groups, memory/FD isolation and authorized stdin remain. Source inspection establishes the probes' presence, not their native execution or their success.
- `scripts/build-release.sh:5` centralizes the exact workspace/all-features/release/bins/deployment-fixture build graph. Both Linux native scripts, the Linux evidence collector, the native macOS workflow and the clean rebuild now use it. This removes the reviewed graph discrepancy without weakening the tested-binary receipts or source/hash comparisons. The separate macOS cross-build diagnostic is not substituted for shipped native evidence.
- `Cargo.toml:14-18` changes ThinLTO to `lto=false` and sets `codegen-units=1`, retaining `overflow-checks=true` and debuginfo stripping. This is a compiler optimization/reproducibility choice, not a relaxation of authorization or evidence checks. OPERATIONS documents the performance tradeoff. Its actual effect on byte equality still requires successful clean-rebuild evidence.
- `scripts/check-reproducible.py:9-23` still hashes the complete original and clean-target executable and raises failure on any unequal byte result. New mismatch diagnostics preserve both binaries under ignored scratch space and print their embedded source fingerprints. They do not normalize sections, exclude bytes, accept matching fingerprints instead of matching binaries, or turn a mismatch into a pass. If diagnostic parsing itself fails, execution also fails. This remains same-host/toolchain reproducibility evidence, not independent compilation attestation.

The parent reports that the earlier127b354 native Mac run reached the real AI isolation checks but failed during worker resource-limit setup; that run is not a pass for these modified bytes. The parent also reports that the prior equal-source ThinLTO diagnostic produced unequal executable bytes. Those failures are not superseded by this source review. At this report's completion, the new reference/clean build is still running and fresh same-source Mac native execution remains required. The reviewer ran no builds or native probes in this follow-up. Report insertion itself changes the embedded source identity and must precede the final evidence-producing builds.

### Exact reviewed follow-up worktree digests

These SHA-256 values bind the source bytes inspected above, on top of127b354, before parent report insertion and final CI freeze. They are review metadata, not signed attestations or binary measurements.

- `Cargo.toml`: `2baa404cbc094708c553d63417425f3e347568c51671cb7125d4a739dcf0c190`
- `crates/vault/src/runner.rs`: `e83d69059012737fb2f3aee8fa208ba54c6f5f83a8875cb149fe949a6dc523e7`
- `tools/isolation-fixture.c`: `56739c5259d85bba7515c3670332704103f2f8cc361bd2899def8aa217a737d8`
- `scripts/build-release.sh`: `8f57e8ee613841b0222a328e7261ebd04187dc14dc76a08192eb1051e391463c`
- `scripts/check-reproducible.py`: `cfbeb39c9ea95f6a4b143e58bf6a6ecff314678d472a7b31c9897d9bbd1ccee9`
- `scripts/test-isolation.sh`: `a0733449350b8b698ba6f06efac2ad79cb064b50fe2aaa6376660edc1ef2d653`
- `scripts/test-deployment.sh`: `f4dadc7969793f010ba25a22e2da4f1743d2ed10c556c6c570b5b2d153a9fc3f`
- `scripts/verify.py`: `e3013696539b84b6af855687ed904d246a3de0c843520ca63e1fec9243671bd9`
- `.github/workflows/verify.yml`: `60c77b59585079b54805f908396fda0a3c705e1920b209a7c761a756d9658885`
- `docs/BROKER.md`: `9cd82b4b65de89bb80bfe21aa54c8666755134221a1758bccf785284c5e15d82`
- `docs/OPERATIONS.md`: `7d65f39f46a1d9ff51c2962d079ac27a4164c6aa062920602f789d2b95777da1`


---

# Bounded Mach-O release-source review

Reviewed uncommitted changes on top of `dca3ba6e6b5fdba7eb38f100f16bc7019670cbe4`. The scope is the four files hashed below and their existing release-build, evidence and packaging call sites. No product source was modified by the reviewer.

**Disposition: no concrete release-acceptance or security regression found within this bounded source scope.** This is source-review evidence; the effect on native macOS reproducibility remains unverified until the new CI run succeeds. The previous review's OS/compiler/producer/CI trust contracts still apply.

## Inspected changes

- `scripts/build-release.sh:5-10` sets `ZERO_AR_DATE=1` for archive production and appends `-C link-arg=-Wl,-no_uuid` only on native Darwin. The same helper continues to build the reference native executable and its clean-target comparison, with the same locked workspace/features/targets. The change requests deterministic linker/archive behavior at build time; it does not rewrite completed binaries. Native toolchain behavior and the trusted build environment remain assumptions. These options alone are not proof of deterministic output.
- Mach-O UUIDs are not used as the application's authorization identity. The inspected readiness path binds the entire running executable's SHA-256 (`readiness.rs:320-326,423-427`). The source changes do not disable signing, remove code signatures after linking, or substitute an unsigned/normalized hash for the delivered executable. UUID removal can affect debugger/crash-symbol association; no such association is a stated authorization primitive here. The OPERATIONS addition accurately retains full-binary measurement and comparison.
- `scripts/check-reproducible.py:35-54` continues to compare SHA-256 of the complete reference and clean-rebuilt executables. Every unequal result enters a branch that raises failure. Source fingerprint equality, section equality, absent UUIDs and code-signature hashes cannot turn a mismatch into a pass.
- The new `macho_layout` helper is invoked only inside that already-failing branch. The inspected 64-bit little-endian field offsets match segment/section, UUID, symbol-string-table and code-signature layout; zero-fill section types are omitted only from diagnostic payload hashing. This diagnostic is deliberately incomplete: it does not validate all Mach-O structure or enumerate every load command. Its results are not acceptance predicates. An unsupported file returns no layout, while malformed data may raise an exception; neither path bypasses the previously established byte mismatch.
- `.github/workflows/verify.yml:87-93` uploads the narrow `.tools/repro-failure/` directory only after failure, with explicit `include-hidden-files: true`. The reviewed script places the two local compiler-output executables there; it does not collect private key stores. The failure artifact has its own name and is not downloaded by the packaging job. Upload success cannot clear the job failure: the release job still requires successful Linux and macOS jobs and the normal evidence evaluator. Missing diagnostic files are ignored only for this failure-debugging upload.

## Checks and execution boundary

The reviewer checked shell syntax with `bash -n`, parsed the Python script's AST, and checked the diff for whitespace errors. These checks passed. The reviewer did not rebuild, execute native macOS probes or validate new CI logs in this pass.

The parent reports dca3ba6 Linux checks passed and native Mac OAuth, UID/ACL/memory/FD isolation and CLI deployment passed, but complete binary reproducibility failed despite equal embedded source fingerprints. Those earlier observations do not establish reproducibility for the changed source. The parent also reports parsing an existing cross-built helper's Mach-O layout; this is diagnostic parser exercise, not native execution evidence. Fresh same-source native CI must still succeed before release acceptance. Any subsequent report insertion changes the source identity and must precede the final evidence-producing builds.

## Exact reviewed worktree digests

These values identify source bytes, not binaries or signed attestations.

- `scripts/build-release.sh`: `da6189e7bb6342c4790c71dc9122c9f3b57a5e01c34df87dd8dfa611dd98f16f`
- `scripts/check-reproducible.py`: `2d1c09089b64404d791469ace5b742495f657457706390c7973afc714824933f`
- `.github/workflows/verify.yml`: `104288841ff70ac5c7753c2731c53107bc15ea0a074b13eebe64db9f65b0f57c`
- `docs/OPERATIONS.md`: `1dfc8d80bab792e3c1c8e6c610320d3b28e859377280a884313041d2ba8f0881`
