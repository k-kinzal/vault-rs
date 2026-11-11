# Built-in key protection by default

The design does not require an external HSM as its only option. Secure Enclave on macOS and TPM 2.0 on Linux are the primary targets; PKCS#11 is optional. If protection is unavailable at runtime, startup or the operation fails. There is no automatic fallback to software PEM keys.

| Environment | Backend | Protection and current evidence |
|---|---|---|
| Mac with Secure Enclave | Security.framework, P-256 signing/ECDH | ARM64 Mach-O Rust/Swift binaries generated with the Apple SDK; userPresence and WhenUnlockedThisDeviceOnly. macOS software is checked in native CI. Physical Secure Enclave tests are excluded |
| Linux with physical TPM 2.0 | tpm2-tools, fixedTPM/fixedParent keys, PIN | Helper source provided. swtpm tests command formats, matching ECDH results, signatures, and rejection of incorrect PINs. This is not evidence of physical resistance |
| External PKCS#11 | RSA-OAEP decryption/ECDSA signing | Compiles with feature=pkcs11; no physical device has been connected |
| No built-in protection | Unsupported | Software keys alone do not provide equivalent theft resistance. A separate protected guardian endpoint is required |

## Separate key roles

Owner signing, OAuth issuer, DPoP, device-operation signing, guardian-operation signing, device ECDH, guardian ECDH, and witness/operator signing have different roles. Do not reuse the same key across roles. When enrolling the owner, verify both approval parties' public keys and purposes.

Putting the guardian in the same compromisable OS account as the device exposes both to the same compromise. Even single-user operation requires independent OS protection domains and user approval. This condition is identical for local and hosted deployments. A vTPM is a protection domain only under trust in the cloud administrator; it does not automatically provide non-exportability against that administrator.

## Native helper contract

Rust's `NativeKey` validates a canonical absolute path, root ownership, no group/other write permission on the helper and parent directories, and SHA-256. It launches the helper with a cleared environment and calls `sign` or `ecdh` through a small stdin/stdout JSON contract. No operation returns the private key itself. Signing displays the complete message; ECDH displays the record/storage label. Rust also verifies signatures against the enrolled public key.

This contract is not exposed to the AI as a generic signing oracle. The Linux helper rejects callers whose real or effective UID is not root. The macOS helper runs in the GUI session of the dedicated login user specified by `macos_uid`. From root, Rust invokes `launchctl asuser UID sudo -n -H -u #UID -- helper` and rejects configurations where the AI UID equals the key owner's UID. Keychain items belong to the key owner's user domain. A same-named key created under the AI's own UID does not match the enrolled public key and cannot be used. Broker control input is restricted to an inherited pipe held by the administrator. Native CI `deployment.log` covers software execution of this path, separately from physical testing of real Secure Enclave operations.

### macOS

```sh
swiftc platform/macos/SecureEnclaveHelper.swift -o SecureEnclaveHelper
```

An administrator defines signing, entitlements, and the keychain access group, then installs the helper at a protected path. Do not treat casual ad-hoc codesigning as a production trust anchor. JSON `{usage:"interactive",operation:"create",key_id:"device-sign",data:"",context:"..."}` creates a SecKey; actual input requires valid JSON quoting. The public key is 65-byte SEC1. For encryption configuration, encode it as `p256:` plus base64url; for signing, convert it to compressed 33-byte SEC1.

The helper supports `public`, `sign`, and `ecdh`, and requests user confirmation during creation as well. Prompt reuse, locking, and access-control behavior are not guaranteed until tested on a physical device. Trusted transaction display on an external screen and an XPC service remain future work.

### Linux

An administrator enrolls P-256 keys on the real TPM at `/dev/tpmrm0`. Signing attributes are `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign`; use `decrypt` as the final attribute for ECDH. Leave `noda` unset to enable dictionary-attack protection. Enter a nonempty PIN through the terminal, never through argv or environment variables.

Under root-managed `/var/lib/vault-rs/tpm/<key_id>/`, store `key.pub`, the TPM-wrapped `key.priv`, and `parent-handle` (`0x81......`). The parent is an administrator-created persistent storage parent; never overwrite an existing handle. `key.priv` is not a plaintext private-key export. Preserve enrollment evidence for the public-key fingerprint and attributes.

The current helper can only be invoked by the root-managed broker. Do not place the AI UID in groups with access to the TPM/key directory or give it a path to root elevation. Set the root-owned helper to mode 755 with `chmod 755` and make directories writable only by administrators. The Python interpreter and tpm2-tools are also part of the TCB.

`platform/linux/enroll-tpm.py` enrolls keys under an existing persistent parent prepared by the administrator. It displays a strong random authorization value once on `/dev/tty` and asks for confirmation that it was saved. Only public information is returned on stdout; existing keys and parents are not overwritten. It targets a real TPM and has not yet been run on physical hardware.

The helper currently displays the operation on `/dev/tty` and interactively requests a PIN. Temporary authentication files are created in tmpfs with mode 0600 and deleted at exit. Complete memory zeroization inside Python or TPM utilities is not guaranteed. Unattended service handles use PCR plus exact-command policy on Linux, or a separate Secure Enclave service namespace on macOS; see [CONFIDENTIAL_DEPLOYMENT.md](CONFIDENTIAL_DEPLOYMENT.md). No resident-scalar fallback is available. Owner/device/guardian interactive approval remains separate. Do not automate it through PIN environment injection.

### PKCS#11

Direct PKCS#11 service configurations are rejected by the confidential production profile. The optional library backend remains available for isolated verification. Pin its module by a root-managed path and digest. Require a hardware slot, token serial, and protected authentication path. Private-key attributes must be Sensitive/AlwaysSensitive/Local/NeverExtractable=true and Extractable=false. Authenticate each fresh session. Context-specific login for `AlwaysAuthenticate=true` keys is not implemented, so those keys are rejected. These attributes are assertions by a trusted module, not remote attestation.

## Physical-key experiments

The requester excluded these experiments from this acceptance run; none has been performed.

1. Plaintext key export is impossible, and copying a wrapped blob to another machine does not permit operations.
2. Locking, restarting, or absence of the user causes rejection; incorrect-PIN limits and biometric failures are effective.
3. Calls from the AI UID, differently signed applications, debuggers, and other sessions are rejected.
4. Signing is limited to the resource, recipient, and artifact the user confirmed; substitution is rejected.
5. Another environment cannot open data using only the database, WAL, and key envelope.
6. Unapproved build, helper, and dependency-library updates are rejected; authorized updates and recovery retain evidence.

Never copy a TPM simulator PASS into the results of these physical acceptance tests.
