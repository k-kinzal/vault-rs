# Conditional security guarantees

These are affirmative, scoped claims about specified bad events. They are not a
claim that all real-world failures are impossible, that an earlier list of 15
failure cases was exhaustive, or that the whole product has been formally
verified. Claims apply to the exact source and binaries in a successful current
verification manifest. An earlier manifest does not cover a changed source tree.

## G-A: Authorization and disclosure ordering (machine-checked)

For every input representable by the actual Rust policy types, the proved
functions cannot authorize a release outside the specified conjunction of owner,
OAuth, DPoP, device and independent guardian bindings, current grant state,
sequence, freshness and use limit. Persistence failure cannot reach the
policy-controlled disclosure callback. A token and its DPoP private key alone
cannot satisfy the independent device and guardian predicates.

The corresponding Kani proofs execute the implementation functions in
`crates/policy`, including wire-field correspondence and the transaction-order
adapter. This statement assumes that the calling adapters supply authentic
verification results, use the proved transition and commit order, and implement
the witness, persistence and disclosure contracts in PROOF_CONTRACT.md. It does
not assume that a failed check succeeds or define “authorized” as whatever the
implementation happens to allow. The expected relation is checked for both
acceptance and rejection. Deliberately removed checks and an implementation
that denies every request must produce counterexamples.

The state-machine model adds bounded temporal exploration; its state count is
not an unbounded whole-system proof. Parser, cryptographic-library, database,
OS and compiler correctness remain explicit contracts, not Kani conclusions.

## G-B: Native role separation and attestation decisions (machine-checked)

For every `KeyRole`, `KeyUsage` and key-purpose input, the actual `key_allowed`
function accepts exactly the specified role matrix. An unattended service key
cannot serve as an interactive owner/device approval key through these entry
points. Legacy resident-scalar configurations have no production variant.

For all values of the actual SNP acceptance inputs, `accepted` is equivalent to
valid signature and certificate predicates, endorsed TCB correspondence, exact
measurement/request bindings, VMPL zero, VCEK signing, no debug/migration/SMT,
and component-wise minimum TCB for reported/current/committed/launch versions.
`bindings_match` checks the actual 48/64-byte measurement, request and chip
identifiers. A challenge is live exactly when issued no later than the current
time and less than 30 seconds old, without arithmetic wraparound. These are
machine-checked functional guarantees. Signature verification, vendor report
parsing and the projection from the vendor struct are reviewed/tested adapters;
their correctness is not an end-to-end compiler-refinement theorem.

## G-C: Guest-host memory confidentiality (conditional composition argument)

Against an adversary controlling the **SNP guest's hypervisor, host OS, external
disks and network**, the adversary cannot recover the guest's DB DEK, decrypted
SQLCipher pages, provider configuration, TLS traffic keys or key-operation
responses by reading host memory, copying disks, replaying quotes, or replacing
a response recipient, except with negligible cryptographic probability, under
all of the following conditions:

1. Approved AMD SEV-SNP hardware/firmware correctly enforces private memory,
   integrity and report authenticity. The approved TCB has no exploitable
   vulnerability for this adversary. CPU side channels, fault injection and
   physical silicon attacks are outside this claim.
2. The independently computed launch digest covers the exact reviewed OVMF,
   kernel, full initramfs, command line and vCPU layout. OVMF direct-kernel hashes
   are enabled. The measured guest includes its immutable application, libraries,
   CA trust, service configuration and acceptance authorities. No unmeasured
   rootfs, cloud-init, SSH, arbitrary quote endpoint, host-injected executable,
   debug shell, swap, kexec or hibernation path is permitted.
3. The guest kernel and measured application are trusted and not compromised.
   The guest itself generates the ephemeral HPKE recipient and constructs the
   complete request; an external caller cannot supply either private key or
   arbitrary report data. “Measured” alone does not mean “safe”.
4. The **independently administered key custodian**, its OS/root, native helper,
   physical key provider and administrative policy are trusted. It is outside
   the adversarial guest host's administration/snapshot domain. Native private
   scalars stay in its protected handles. ECDH results pass through custodian
   memory: custodian compromise is explicitly outside G-C and can defeat this
   confidentiality claim. A host-controlled vTPM does not satisfy this contract.
5. Cryptographic primitives and randomness satisfy their standard security
   assumptions. TLS authenticates the pinned custodian CA; responses use HPKE
   to the recipient whose key is in the fresh signed report. The independent
   custodian's clock and challenge state are trustworthy.
6. Operator-approved VCEK enrollment and component-wise minimum TCB are current
   and unrevoked. The implementation verifies AMD's pinned ARK/ASK chain,
   certificate dates, VCEK TCB extensions and chip ID. It does **not** fetch CRLs.
   Offline approval expires within 24 hours and must be renewed only after a
   trusted revocation/advisory review. A revocation occurring within that window
   is a residual risk; immediate revocation detection is not claimed.
7. Guest plaintext leaves only through the intended authorized response or
   approved provider protocol. Legitimately returned secrets and compromise of
   their receiving workload/SQL server are outside this memory claim.

Why these conditions suffice: without an approved report and fresh challenge,
no native operation is reached. A report binds the custodian origin, exact key
and generation, operation, input, context, challenge and recipient. Replaying a
report cannot create a second operation. A relay cannot change the recipient;
the operation response is encrypted to the private recipient key inside the
measured guest. The DB DEK is unwrapped there, and SNP protects its runtime
memory from the specified host adversary. This is a cryptographic/architectural
argument using named primitive contracts, **not a mechanized proof of SNP or of
all Rust/OpenSSL/SQLCipher instructions**.

## G-D: Operational boundaries

Local and hosted deployments use the same broker and HTTPS service mechanisms.
Mac and Linux clients use an independent Linux SNP service; a conventional local
Mac process or ordinary VM does not receive G-C. Native client approval keys
remain in Secure Enclave/physical TPM handles. A trusted client kernel/root is
still required; this change does not protect plaintext after authorized delivery
from a compromised client OS.

Service `readiness` verifies signed deployment acceptance and then performs live
attested probes for TLS, signing and storage keys. A configuration string alone
cannot establish the boundary. `serve`/`witness` reject native-only and direct
PKCS#11 service profiles in production; `--verification-run` is loopback-only and
never asserts production readiness. Offline initialization/rotation likewise
require the attested provider. Native enrollment and custody are intentionally
separate trusted operations.

Witness independence, trusted application time, durable storage behavior and
correct provider enforcement remain requirements for use counts, expiry and
revocation. A confidential VM does not by itself give trusted wall time or an
independent rollback-resistant witness. Renewed quotes do not erase DEKs already
unwrapped in a live guest. Stop/retire the guest and rotate generations when
revoking a running deployment; do not promise retroactive erasure of delivered
plaintext. Availability, denial of service, traffic size/timing, and metadata
confidentiality are not established by these claims.

## Evidence and status

The reproducible verifier runs Kani, actual-source mutations, the temporal
model, signature/HPKE/report tests, typed configuration rejection, real database
and OS-isolation tests, native TLS/CLI tests, TPM command simulation, image
packaging checks, dependency auditing and reproducible builds. The public AMD
report fixture tests vendor cryptographic verification; synthetic signed reports
test current-request success and rejection. Neither is this deployment's fresh
hardware attestation. The image check verifies packaging and rejection rules,
not booting an SNP processor.

A real production deployment must supply an independently reviewed measured
image, physical enrolled key handles, current VCEK approval and successful live
attestation. No physical-key or physical-SNP experiment has been represented as
completed in this workspace. Software evidence and actual deployment acceptance
are separate artifacts; neither may be fabricated to make a readiness flag true.
