# Confidential RPC and immutable-guest integration review

Read-only review on top of5f7400c, limited to the inspected worktree snapshots below. Parent edits continued during review; this report records findings against those snapshots and does not preempt later fixes. No product edits, agent spawning, hardware execution, attack-image generation or proof/build runs. A small in-memory Python check confirmed the NUL-path predicate issue below. Parent-reported Kani/mutation results are not reclassified as this reviewer's execution evidence.

## Concrete findings

### C1 — High: unauthenticated bootstrap output can authorize an attacker-known DB key

`main.rs:154-161` now correctly requires attested initialization, but emits only unsigned JSON with the resulting envelope digest. Observe likewise emits unsigned config/host digests (`main.rs:219-224`). The new fixed initialization/rotation/observe images send these values through the guest console while `/state` is an externally controlled disk (`build-confidential-guest.py:102-123,142`). The selected threat model gives the adversary both hypervisor/console and external-disk control.

The hypervisor can replace a freshly initialized empty DB and envelope with a valid SQLCipher database under a DEK it chose. Wrapping that DEK to the native public key does not require a private key. It can replace the serial digest/observation too. If the deployment authority uses this supported output/disk digest to approve the generation, production open_pinned faithfully accepts the attacker's approved envelope; future DB pages use a known DEK. This is an unauthenticated provisioning-origin gap, not a break in SQLCipher, native key protection, SNP or the existing post-approval pin check. No actual SNP attack was run. The same receipt-origin issue affects new rotation generations.

Provide an authenticated bootstrap receipt, bound to an operator-selected nonce/run ID, intended vault/deployment/config/key generation, measured initialization image and exact produced envelope digest. Sign it through a dedicated attested custodian-backed key, or deliver/verify it over an authenticated attested guest channel. Deployment approval must verify this receipt and match its generation, rather than treat host serial output or a hash of host-supplied disk content as origin evidence. Verification must also reject old/unrelated receipts. An arbitrary unauthenticated observe transcript is not an attestation.

### C2 — Medium: embedded-NUL archive path aliases bypass duplicate/config checks

`build-confidential-guest.py:73-83,91-96` treats PurePosixPath normalization and raw Python-string equality as guest path identity. A target `/etc/vault/service.json\u0000alias` passes the current prefix, absolute, normalization and no-.. checks. It is a different entries dictionary key, so it bypasses duplicate rejection and is emitted as a distinct newc record. Linux filesystem path handling uses NUL-terminated names, so that record aliases `/etc/vault/service.json`; the archive/receipt namespace can disagree with the booted filesystem and allow an apparent second file to replace required configuration.

Reject embedded NUL/control bytes before archiving, and reject file-vs-directory ancestor conflicts (for example a regular `/lib/x` followed by `/lib/x/y`). Validate name byte lengths and the archive namespace using Linux path semantics. Add a regression using a separately implemented reader/extraction validator, not only the same Python dictionary. This reviewer confirmed the predicates accept the NUL string; no attack archive was executed.

### C3 — Medium integration gap: a passing builder need not produce an executable image

The required kernel list at61 omits BINFMT_SCRIPT and BINFMT_ELF, while `/init` is a shell script and both entry binaries are ELF. At68-69 the script says it requires a static BusyBox but checks only the four-byte ELF magic. It does not establish x86_64 class/machine, absence of PT_INTERP for BusyBox, or a complete interpreter/DT_NEEDED closure for the Vault executable and shipped libraries. A wrong-architecture, dynamic-but-missing-loader, or even truncated ELF file can pass packaging and fail before any attestation.

Require the relevant built-in binary formats, validate ELF architecture/interpreter and shipped dependency closure, and obtain build evidence tying the supplied kernel .config to the actual kernel. A separately hashed .config cannot by itself prove that the kernel binary has those options. Keep 'packaging verified' distinct from 'boot/runtime verified'. At boot, explicitly open stdin/stdout/stderr after mounting devtmpfs: this archive contains no initial `/dev/console` node, so PID1 may start without usable console descriptors and maintenance receipts can be lost. A non-SNP boot harness can test entrypoint packaging/failure behavior without pretending to be SNP evidence; actual supported SNP launch remains a deployment obligation.

### C4 — Medium reporting gap: preflight and startup still disagree on some invalid configurations

`CustodianConfig::preflight` at252-268 checks nonempty keys but omits the64-key limit and duplicate IDs enforced by `Custodian::open:288-315`. `ServiceConfig::attest_live:76-95` proves key operations but does not check TLS certificate/key correspondence; startup later enforces it in `native_tls::configuration:81-98`. Custodian preflight similarly opens its TLS handle without validating the certificate pairing. Thus an otherwise correctly signed readiness input can report accepted although startup deterministically rejects it.

Reuse static configuration validation (including origin/key inventory/certificate consistency and role-specific required fields) between preflight and actual constructors, before running live probes. This is a fail-closed readiness/integration problem, not a demonstrated plaintext-release bypass.

## Follow-up closure and sound inspected behavior

- The original absence of a supported initialization route was reported during review. The parent added fixed initialize-storage, rotate-storage, rewrap-config and observe image entrypoints. The inspected branches select fixed paths/arguments and power off afterwards; no general command-line or network shell was added. This removes that entrypoint blocker at source level. C1 remains necessary to authenticate the resulting provisioning outputs.
- Actual SNP byte bindings now call the shared array predicate; accepted/challenge_live harnesses use iff, so the previous blanket-denial proof gap is closed at source level. The parent reports17 actual policy mutants produced counterexamples. This reviewer inspected code but did not rerun those proofs.
- Offline VCEK policy now rejects startup leases over24 hours and expired policy, checks both allowed and actual SMT state, and expressly documents trusted independent operator revocation review with no CRL claim. This is a conditional offline policy, not automatic/immediate revocation detection. A max interval measured from process startup does not itself timestamp the operator's last review; the documented review obligation remains trusted.
- `AttestedKey::invoke:139-189` generates its own ephemeral recipient before constructing/hashing Request, obtains the local report for that exact digest, and decrypts the result with that same private key and digest context. No caller-selected report_data or recipient endpoint is exposed here.
- Request serialization is typed and domain-separated. It binds custodian, challenge, key ID/public generation, sign/ECDH operation, input, context and recipient. The exact immutable guest measurement indirectly binds its configuration; this relies on actual approved launch inputs covering the entire image/configuration.
- Custodian checks origin/key generation/purpose and bounds inputs; it removes a challenge while holding the mutex before quote verification/private operation. Failed post-removal attempts burn the nonce; restart forgets pending nonces. Quote verification precedes native use, and output is HPKE-sealed to the bound recipient. No ordinary RPC replay or recipient-substitution bypass was found in this pass under the stated crypto/guest/custodian contracts.
- Production main requires attested service keys, readiness verifies signed acceptance before live key probes, and acceptance time is checked again after the probes. Native TLS checks certificate/public-key correspondence and returns DER signatures through Rustls without loading a TLS private scalar. Native/fixture verification mode is not mislabeled as production acceptance.

## Remaining explicit contracts and integration limits

The guest's ordinary SystemTime is not authenticated by SNP; a hostile hypervisor can influence RTC/virtual-time inputs. Custodian time protects nonce and endorsement checks, but does not automatically make all guest OAuth/grant/lease/acceptance deadlines trustworthy. Existing authorization theorems assume trusted time. The supported deployment must supply/enforce that assumption or move relevant deadline enforcement to a fresh trusted authority; do not infer it from confidential memory. No time-based plaintext bypass was demonstrated in this review.

Guest and witness may not share an adversary-controlled rollback domain. Immutable code measurements do not make mutable witness persistence non-rollback. Custodian root/provider, measured guest kernel/service/libraries, crypto/randomness, SQLCipher/SQL semantics and the declared hardware policy remain trusted. Mounted external ext4 and other host I/O are untrusted inputs to that trusted kernel. No claim of exhaustive implementation/physical/side-channel safety follows from this review.

The new G-C text properly excludes a compromised independent custodian and names its transient ECDH output exposure. No native SNP launch or physical-key operation was performed here. Software predicates, synthetic reports and packaging checks do not establish actual launch support.

## Snapshot hashes

These identify the source bytes inspected during this pass; later fixes require a follow-up disposition. They are neither signed deployment attestations nor executable measurements.

- `crates/vault/src/confidential.rs`: `28fa0d92132ee20a0b323da58455a71e93c68ed950023aaf5a362c20c439928a`
- `crates/vault/src/service_config.rs`: `057b1cf3de0a77ec5ffeb7f77778b1637a7307a9fc613fd815b1ab621801ec57`
- `crates/vault/src/main.rs`: `01e587c0ce622ab9eceb9dec4a739438fa7308543e21f4e17972e4eb13e2a628`
- `crates/vault/src/readiness.rs`: `7ae745f28a1b6e411297d6cb2ed5e152b17f1a4b7c85add5dc5dfa34d6dffc14`
- `scripts/build-confidential-guest.py`: `1abc67542b4bdde0ed3014b84997a0f07bf48619bc63fa6ef3aec36f3b1777e8`
- `crates/policy/src/attestation.rs`: `943e123d2a2f3ce0c878ee84ca55cb4e1db525e9d48c261e485d82883a5ce15b`
- `crates/vault/src/attestation.rs`: `db8a3423ba26dbeb69cc3070e07e4ce5f92e950e5c09a5d435ad3bdef2e8e06f`
- `crates/vault/src/native_tls.rs`: `0989e70003ad5b1e1cc466702a21f4f2a5c4755f6305b9c5fbd5d0cce9fc91d5`
- `scripts/test-confidential-guest.py`: `1d725ad525256d8ced6c32a850155c693779fbe99f46586349aa91b859ad3032`
- `docs/GUARANTEES.md`: `94472ad159151a0a4328024910ee98b43a3f1b0e3b769b35de0d89386752a54d`


## Source-inspected closure follow-up

The parent implemented a bounded follow-up, which was inspected against the hashes below. **C1, C2 and the concrete C4 mismatches are closed at source-review level. C3 is materially improved, with the two small packaging issues below still open in this snapshot.** This does not certify execution or establish a boot/SNP pass.

### C1 closure

`provisioning.rs` adds a signed domain-separated Receipt and a verifier requiring the operator's out-of-band public key, operation, nonce and output. The payload signs the output pin, source/binary identity and optional observation. Runtime signing requires an Attested service key. Initialize and rotate print this signed receipt; rewrap validates its authenticated source digest and signs the bytes generated in memory. Observe-attested validates the expected database-generation pin against the same captured ConfigurationSnapshot before signing the observation. The guest builder fixes the nonce, signing-key configuration, maintenance command and expected source pin in the measured image; it does not accept host-provided shell arguments.

`storage.rs::open_unleased_with_pin` hashes a newly generated envelope before writing, retains that expected hash, compares the exact read bytes before unwrap, and returns the matched pin. Initialize no longer computes its returned pin by an unauthenticated later disk reread. Rotation validates its source pin, retains the newly generated destination pin and compares it on subsequent envelope reads and reopening. Changing the disk after a successful unwrap cannot make the final signed receipt authenticate the attacker's replacement. The inspected fault-test source explicitly substitutes the envelope after unwrap and checks the returned pin remains the original while later pinned open rejects.

These mechanisms address the reported known-key-substitution path provided the operator retains a fresh out-of-band nonce, expected intent and trusted receipt public key, verifies the receipt before accepting its pin, and the independent custodian permits that receipt signer only for the intended approved fixed image. These are explicit enrollment/approval contracts. A signed receipt does not certify an unknown image merely by containing a source hash; the custodian's genuine measurement check supplies its origin. Receipt public keys/nonces copied from the hostile console are not out-of-band trust anchors.

### C2 and C4 closure

The builder rejects ASCII control/NUL/DEL characters before archiving, rejects duplicate targets, and rejects regular-file ancestors. The new negative cases cover NUL aliases, control characters and file/directory prefixes. This closes the reported archive-namespace mismatch at source level.

Custodian preflight now enforces the key count limit, uniqueness/shape of key IDs and HTTPS origin, and calls native_tls::configuration to validate its TLS certificate/key pairing. Service live preflight also calls the same TLS configuration validator before the separate TLS/service/storage live probes. These close the specific preflight/startup disagreements reported in C4; this is not a claim that every possible startup failure can be predicted.

### C3 remaining narrow items

The builder now requires BINFMT_SCRIPT/BINFMT_ELF, parses ELF64 little-endian x86-64 headers, rejects interpreter/dependency use for BusyBox, and checks named interpreter/DT_NEEDED presence while rejecting custom RPATH/RUNPATH. These address the original missing-format/staticness checks. Kernel binary/config build correspondence and real boot/ABI compatibility remain external build/runtime evidence requirements; the code continues to label output as packaging, not native execution.

At this snapshot, dependency presence at builder154-158 accepts any entries key, including a directory or non-ELF regular file with the expected loader/library name. Require resolved dependencies to be regular, valid ELF files before declaring the closure complete. Also reopen stdin/stdout/stderr after devtmpfs is mounted: the initial archive has no `/dev/console` node and the current init script does not restore console FDs. This is especially relevant because authenticated maintenance receipts must actually reach the operator. Neither item is a demonstrated cryptographic or SNP-memory bypass.

### Scope wording and evidence

GUARANTEES.md explicitly states that trusted application time, independent witness persistence and provider enforcement remain requirements; SNP provides neither trusted wall time nor rollback-resistant witness state. It also disclaims erasure of already-unwrapped DEKs. No overclaim on those points was found in the inspected text. Guest-host memory protection remains conditional on the named primitive contracts and does not silently imply expiry correctness against a manipulated guest clock.

The reviewer inspected the added receipt/fault/packaging-test source, but ran no tests or hardware operations in this follow-up. Any parent-reported test passes retain their own logs/provenance; this source closure is not a substitute.

### Closure snapshot digests

- `crates/vault/src/provisioning.rs`: `0466e6bad5210c89c8849304ce21816f4faa0926465fa5ed93cbdc4c01c32424`
- `crates/vault/src/storage.rs`: `73a24a00ccdc119c3bc77efd0129d861700523cf60bf8eb79fa6400cdb586c95`
- `crates/vault/src/main.rs`: `f7abefb42a8ed97570dddbcf658000888b6e344f1c8f7d58b4f906af5a775aad`
- `crates/vault/src/readiness.rs`: `c4685015d0cefd5b43ae26e310220a6c91beb65faea5b9bfb75934d80f20f58a`
- `crates/vault/src/confidential.rs`: `bc4c22f93ca52b9bcab75a9b0c39387f07d8b8c2f386baecaf0f44b776990023`
- `crates/vault/src/service_config.rs`: `2975df8072395242fb1afe1f94b2d1f4328dffd5d0cc555a0f28f2de760117e7`
- `scripts/build-confidential-guest.py`: `1b1b9cbc44cfa5fa5acce6cecd758f565d5432ad1705c2bafa599aa74e71d610`
- `scripts/test-confidential-guest.py`: `31eb39e650c7c83271fa6e6d6e6a213e3c8ef5258c609ecf19aef54541bdda3f`
- `crates/vault/tests/security.rs`: `802c2e2afc4c1e92e67dddf5a6ac0f016207c0f5f742e419a04b22ec31d3a8fc`
- `docs/GUARANTEES.md`: `94472ad159151a0a4328024910ee98b43a3f1b0e3b769b35de0d89386752a54d`


## Final C3 source disposition

Inspected the two remaining bounded changes. `build-confidential-guest.py:151-163` now requires each resolved interpreter/library target to be a regular file and pass the ELF parser. Directory or plaintext-file placeholders no longer satisfy the dependency check. At208-210, the init script mounts devtmpfs and explicitly reopens all three standard descriptors on `/dev/console` before maintenance output or service startup.

**C1 through C4 are now closed at the stated source-review scope.** No further concrete finding remains from this bounded review. This conclusion preserves the earlier primitive/build contracts and does not mean that the packaging parser proves complete ABI/runtime compatibility, that kernel .config correspondence is mechanically established, or that an actual SNP guest booted. The parent reports packaging regression passed; the reviewer only inspected these final lines and ran a clean diff-whitespace check, not the packaging suite or native hardware.

The final guest-builder SHA-256 is `add170dc18a3871aa344055e93865fa3cd4a2ecba2008f98866b9e061b3b9194`. Its inspected regression-source digest remains `31eb39e650c7c83271fa6e6d6e6a213e3c8ef5258c609ecf19aef54541bdda3f`. These supersede the builder hash in the previous closure snapshot only; subsequent source/report changes still require the normal full verification and fresh CI evidence.
