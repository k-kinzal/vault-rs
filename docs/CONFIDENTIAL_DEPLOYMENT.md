# Independent Linux confidential service

Mac and Linux brokers use the same HTTPS API. Both local and hosted services run
inside an independently measured AMD SEV-SNP Linux guest. An ordinary VM,
container, Secure Enclave key alone, or a host-controlled vTPM does not provide
this memory boundary. Milan and Genoa VCEK reports, versions 2/3, are supported;
VLEK, migration and other processors/report versions fail closed.

The threat boundary and exact conditional guarantees are in GUARANTEES.md.
The key custodian is independently trusted, including its OS/root. It must not
share the guest host's administrator or snapshot domain. It holds native service
handles and performs one signing/ECDH operation after verifying each fresh SNP
quote. Its ECDH result is secret and briefly exists in its own process memory.
This design protects against the guest host, not a compromised custodian.

## Enrollment and key custody

Use distinct native keys for service signing, storage unwrap and TLS signing,
plus separate custodian TLS keys. `examples/custodian.native.json` shows the
schema. Replace every placeholder, including a reviewed nonzero minimum TCB and
an expiry no more than 24 hours away. Do not reuse that example's zero values.
The policy pins an exact independently calculated launch digest and locally
enrolled VCEK. VCEKs must chain to the built-in AMD ARK/ASK; a caller-provided
root cannot be substituted. Updating the VCEK/minimum TCB/launch image requires
new signed custodian deployment acceptance. VCEK inputs are transitively hashed.

On a physical Linux custodian, enroll a service handle with a PCR selection
appropriate to its verified boot chain:

```sh
python3 platform/linux/enroll-tpm.py --key-id guardian-ecdh \
  --parent 0x81000001 --kind ecdh --usage service --pcrs sha256:0,2,4,7
```

The service key has no password-authentication bypass. Its policy requires the
selected PCR values and exact TPM command. `fixedtpm`, `fixedparent` and
`sensitivedataorigin` keep its wrapped private blob chip-bound. Determine PCRs
from the actual boot design; the example selection is not universal. After an
approved firmware/boot update, rotate/re-enroll rather than weakening the policy.
Interactive owner/device keys retain the separate PIN/user-presence path.

macOS service handles use a separate Keychain tag namespace and the Secure
Enclave's private-key API without per-operation user presence; creation still
requires confirmation. Interactive handles keep user presence. The dedicated
login/keychain identity and OS remain trusted. Never give that identity to the
AI account. Native helpers now require explicit `usage` in their request;
legacy deployments must explicitly re-enroll/migrate, not silently downgrade.

A TLS certificate must contain the enrolled P-256 signing public key. The CA may
issue from that public SPKI (for example OpenSSL `x509 -new -force_pubkey` under
the administrator's CA procedure). Do not generate/import a PEM TLS private key.
`native_tls` checks the certificate SPKI and delegates every TLS signature to
the enrolled handle. Trust only the intended CA on each connection.

Start a separately accepted custodian with:

```sh
vault-rs custodian --config /etc/vault-rs/custodian.json \
  --acceptance /etc/vault-rs/acceptance-files.json
```

The production custodian has no verification-mode switch or synthetic signer.
Its HTTPS challenge endpoint is intentionally public but bounded; a challenge
alone confers no key authority. Challenges expire after 30 seconds, are consumed
once even on failed attempts, and disappear on restart. Network admission/rate
control belongs outside the cryptographic confidentiality guarantee.

## Building a measured guest

`scripts/build-confidential-guest.py` takes a JSON manifest of SHA-256-pinned
inputs and creates `kernel`, `OVMF.fd`, deterministic `initramfs.cpio`, `cmdline`
and `launch-inputs.json`. Supply an independently built/reviewed x86 Linux kernel
with SNP guest, virtio, network and ext4 support built in, its matching config,
a static x86 busybox, the verified Linux vault-rs binary, and its complete
ELF loader/library closure. The kernel config rejects swap, kexec, hibernation,
raw memory devices, debugfs and loadable modules. Verifying that the supplied
kernel config corresponds to the kernel binary is a release/build obligation.

Manifest shape (all paths/digests and network values are deployment inputs):

```json
{
  "kernel": {"path": "/build/bzImage", "sha256": "REPLACE"},
  "kernel_config": {"path": "/build/kernel.config", "sha256": "REPLACE"},
  "firmware": {"path": "/build/OVMF.fd", "sha256": "REPLACE"},
  "vault": {"path": "/build/vault-rs", "sha256": "REPLACE"},
  "busybox": {"path": "/build/busybox-static", "sha256": "REPLACE"},
  "files": [
    {"path": "/build/service.json", "sha256": "REPLACE", "target": "/etc/vault/service.json", "executable": false},
    {"path": "/build/acceptance-files.json", "sha256": "REPLACE", "target": "/etc/vault/acceptance-files.json", "executable": false}
  ],
  "network": {"interface": "eth0", "address": "192.0.2.2/24", "gateway": "192.0.2.1", "dns": "192.0.2.53"},
  "role": "serve",
  "machine_id": "11111111111111111111111111111111",
  "vcpus": 2,
  "memory_mib": 2048
}
```

Add the actual loader, libraries, CA/certificate files, signed evidence bundle,
authority policy and evidence logs under their exact guest paths. Example paths
are illustrative, not a complete launchable OS distribution. All runtime input
files must be present. The only external writable volume is `/dev/vdb`, mounted
at `/state` with `nosuid,nodev,noexec`; it holds encrypted DB state. The root
image contains no login/SSH/cloud-init/host control endpoint. Network failures
or a missing SNP guest device stop the fixed entrypoint.

```sh
python3 scripts/build-confidential-guest.py --manifest guest-inputs.json --output guest-image
```

Compute the SNP launch digest independently from these exact outputs with a
reviewed SNP measurement implementation, such as virtee's `sev-snp-measure`.
Use the actual CPU model/vCPU layout and OVMF, enable direct-kernel
`kernel-hashes=on`, and include the kernel, entire initramfs and exact command
line. Do not approve a digest solely because an untrusted host returned it.
Launch with SNP policy `0x20000` (debug, migration and SMT forbidden), an
SNP-capable kernel/QEMU/OVMF stack, private guest memory and no migration agent.
A conventional `qemu -enable-kvm` invocation is not equivalent. Firmware must
actually measure direct-kernel inputs; this is an audited platform contract.

The packager intentionally reports `physical_snp_launch=NOT_RUN` and
`measurement_status=REQUIRES_INDEPENDENT_SNP_LAUNCH_DIGEST`; packaging is not
attestation. The actual runtime verifies the signed launch measurement before
any protected key result can return. Unsupported measurements fail closed.

## Bootstrap, operation and maintenance

There is no host-controlled shell or CLI argument channel into a service image.
Each maintenance operation has a separate measured image and explicit custodian
approval, so initialization does not require a pre-existing accepted database:

1. Prepare the encrypted-state volume and an image with role
   `initialize-storage`, `/etc/vault/service.json` naming one fixed
   `/state/NAME.db`, and `/etc/vault/storage-key.json` containing its SNP key
   descriptor. This image needs no service acceptance bundle: the custodian
   authorizes its exact fixed bootstrap code by launch measurement.
2. Boot that image under its temporarily approved measurement. It initializes
   storage using a real attested operation, prints only the public generation
   receipt, and powers off. Repeated initialization refuses to overwrite state.
3. An `observe` image prints the actual source/binary/configuration/generation
   measurements. Prepare signed acceptance for the fixed machine ID and exact
   immutable inputs. `serve` or `witness` images include those signed files.
4. Approve the final service image measurement on the custodian and retire the
   bootstrap measurement. Start the service image. Readiness verifies acceptance
   first, then makes live attested probes of TLS/signing/storage handles. Startup
   cannot substitute a native-only, resident or direct PKCS#11 service config.
5. For rotation, stop the service and approve a fixed `rotate-storage` image:
   `/state/source.db` to `/state/destination.db`, with `/etc/vault/old-key.json`
   and `/etc/vault/new-key.json`. `rewrap-config` similarly uses fixed
   `/state/source.envelope.json` and `/state/destination.envelope.json`.
   Neither accepts host-supplied arguments. Each powers off after completion.
   Re-measure and accept the new service generation, and retire maintenance
   approvals. Keep the independent witness outside rollback of this volume.

The minimum TCB and VCEK endorsement policy use bounded offline revocation
review, not an online CRL fetch. Renew only after checking authenticated AMD
revocations/advisories and actual platform patch status. Policy expiry stops new
key operations but cannot erase a DEK already loaded into a running guest.
Trusted application time and witness durability/independence are separate
requirements; SNP alone does not establish them. See GUARANTEES.md for exact
limits and failure cases.

## Authenticating provisioning across an untrusted host

Never approve a generation from unsigned serial output or a disk hash. The host
can create an envelope for an attacker-known DEK using a public wrapping key.
Bootstrap, rotation and rewrap commands therefore require `--receipt-key` (an
attested service signing descriptor) and `--receipt-nonce` (32 fresh random bytes
chosen by the operator before approving the fixed image). They sign a
`snp-provisioning-receipt` containing the exact operation, nonce, output path,
source/binary hashes and output-envelope digest. That digest is retained from
newly generated bytes in guest memory; it is not obtained by rereading a
host-controlled file after generation. Substitution during initial envelope
creation or rotation is checked against the retained digest before unwrap.

Maintenance image manifests include `receipt_nonce`; include the pinned
`/etc/vault/receipt-key.json` as well. `rotate-storage`, `rewrap-config` and
`observe` also require `expected_source_sha256`, taken from the authenticated
previous receipt. Source generation substitution fails before decryption.
The `observe` image runs `observe-attested`, verifies this expected generation
against its snapshot, and signs the observation. Its source/binary/configuration
fields can then be used in deployment acceptance. The launch policy must bind
these exact nonce/key/expected-generation inputs through the full initramfs.

On the trusted operator machine, verify each receipt before using any field:

```sh
vault-rs verify-receipt --public-key enrolled-provisioning-signing.pub \
  --operation initialize-storage --nonce OPERATOR_GENERATED_64_HEX_NONCE \
  --output /state/vault.db < received-receipt.json
```

The public key, operation, nonce and intended output path are out-of-band trusted
inputs; never take them from the unverified receipt itself. Compare returned
source/binary fields with the reviewed release, preserve the resulting generation
pin, and retire the nonce after accepting one result. Console suppression or
replacement can cause denial of service, but cannot forge a receipt. Fixed
maintenance images power off after the command; they provide no arbitrary
signing/quote/command endpoint.
