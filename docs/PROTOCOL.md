# Protocol v1

## Static secrets

1. The client generates a random 256-bit DEK `K` and an independent 256-bit value `A`, then computes `B = K XOR A`.
2. Encrypt the secret with XChaCha20-Poly1305 using `vault/resource/version` as AAD. Wrap `A` with the device public key and `B` with the guardian public key.
3. The owner signs a grant containing the record hash, subject, action, resource/version, epoch, validity period, uses, DPoP JWK thumbprint, both signing public keys, recipient, instance, and artifact_hash.
4. `/v1/install` verifies the owner signature and registers only a new ID. `/v1/challenge` returns the next sequence and a 256-bit nonce for a valid grant. Issuing a challenge does not disclose a secret. Fetching an unexpired challenge again returns the same challenge.
5. The client creates an Operation containing the token hash, grant hash, and nonce. The device and guardian sign the same Operation under distinct domains. OAuth and DPoP evidence accompany it.
6. `/v1/release` verifies every signature and binding, completes witness CAS followed by the SQLCipher transaction, and consumes a use before decrypting only the guardian share.
7. Encrypt the guardian share to the recipient's X25519 HPKE key. The client SDK revalidates the request and record, combines it with the device share, and decrypts locally.

There is no API that sends static-secret plaintext or the device share to Vault. The server's database encryption key is separate from this DEK; it is unwrapped through hardware at startup and passed to SQLCipher. The two-share protection remains even if the database key leaks.

## Cryptography and encoding

- Signatures use ES256. Public keys are base64url-encoded compressed SEC1 values of 33 bytes; signatures have a fixed length of 64 bytes. Rust struct definitions fix JSON types and field order, and unknown fields are rejected. Only AccessClaims permits additional AS claims. Serde rejects duplicate known fields.
- The signed bytes are `vault-rs/v1/<domain>\0 || serde_json(struct)`. This is not general JSON canonicalization through JCS. Interoperable implementations must match typed field order, nulls, integers, UUIDs, and base64url representations.
- P-256 key wrapping uses RFC 9180 DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305 base mode, with sequence=0 only. The label is included in both info and AAD. The HPKE sender uses the library; receiver glue for non-exportable ECDH is in `external_kem.rs`. Tests cover official vectors and upstream interoperability.
- Optional RSA wrapping uses RSA-3072 through RSA-4096, e=65537, and OAEP-SHA256/MGF1-SHA256. The label binds the record context and share role. Production private RSA operations use PKCS#11 only.
- Response HPKE uses X25519/HKDF-SHA256/ChaCha20Poly1305, info=`vault-rs/v1/response`, and the Operation hash as AAD.
- Every public-key use validates its type, size, and curve. Secrets and shares are not logged. `ReleaseRequest` deliberately does not implement Debug to avoid accidental token logging.

## OAuth / DPoP profile

This is a strict OAuth Resource Server profile, not a new Authorization Server. The broker implements authorization code flow, S256 PKCE, and DPoP. The connected AS supplies the consent UI. The issuer key is pinned; key changes require a deployment update rather than automatic JWKS rotation.

The AS issues ES256 tokens with `typ=at+jwt`, a pinned issuer signing key, and `iss,aud,sub,nbf,exp,scope,grant_id,cnf.jkt`. Scope is `secret:read` or `secret:issue`; effective permissions are the intersection with the owner grant. Scope alone cannot select a secret.

DPoP validation covers RFC 9449 `typ=dpop+jwt`, a public P-256 JWK, and `htm,htu,iat,jti,ath,nonce`. The expected `htu` is computed from the configured HTTPS origin and fixed endpoint; Host/X-Forwarded-* headers are not trusted. Requests live for at most 30 seconds, future iat values are rejected, and the nonce and sequence are consumed once. This custom profile carries evidence in JSON fields of a signed request envelope rather than HTTP Authorization/DPoP headers. It is not a drop-in integration with general middleware.

## Dynamic issuance

An owner grant and Operation with `action=issue` include `IssueSpec{provider,role,ttl_seconds}`. They undergo the same authentication, signature verification, and use consumption. `CommittedIssue` can only be constructed from the persistent outbox; external code cannot construct or Deserialize it. The trusted PostgresIssuer pins the destination and role policy in local configuration.

A database transaction creates the user, grants privileges, and stores an encrypted receipt atomically. The request hash provides idempotence; only the same pending request may be retried before expiry. Replays after completion are rejected. There is no API to retrieve a completed receipt after a response is lost. An incomplete or expired outbox does not automatically restore a use; the owner must revoke it and authorize a new grant.

The issuer and target PostgreSQL server temporarily know the issued password. For dynamic secrets, the issuer is itself an E2E endpoint; the design does not claim to hide the secret from its generator. Provider connection settings are encrypted with `protect-config` and opened through hardware only at startup.

Issued users have `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS` and only the registered role's privileges. A role with excessive privileges produces an overly privileged user, so actual privilege tests are necessary. Revocation applies NOLOGIN, terminates existing sessions, drops the role, and records a tombstone. TTL enforcement uses database VALID UNTIL and an expiry worker. New logins expire even while the worker is stopped, but termination of existing sessions depends on the worker remaining alive.

Wasm proposal extensions run in `wasmi`: no host imports or WASI, at most 64 KiB of memory, 100000 fuel, a 128 KiB module, and 4096 bytes of JSON. A module exports `memory` and `propose(i32 pointer,i32 length)->i64`; the upper 32 bits of the return value encode the output pointer and the lower 32 bits encode its length. The output IssueSpec must match the signed input. Extensions receive no administrative credentials, filesystem access, or network access. Administrative operations for a new provider require a separately reviewed trusted adapter.

## Execution and recovery

The broker verifies other authorization evidence and the guardian signature before requesting a device signature. Expiry is rechecked before the HTTP response; a response that expired while waiting for hardware, the database, or the witness is not returned. If dynamic issuance exceeds the deadline, the issuer attempts to revoke the issued lease. Existing sessions during a provider outage remain subject to the limitation above.

`/v1/checkpoint` returns the independent witness value for an owner-signed Grant. Sending owner-quarantine-signed `{vault,grant,expected}` to `/v1/quarantine` permanently retires the ID only if CAS against that checkpoint succeeds. It neither restores remaining uses nor rolls back the witness.
