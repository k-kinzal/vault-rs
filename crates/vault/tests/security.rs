//! Software keys here are PUBLIC TEST FIXTURES. No test signer/unwrapper is linked
//! into vault-rs binaries. These tests do not establish hardware non-extractability.
use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::Generate;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;
use vault_rs::{
    client::RecipientSession,
    crypto::*,
    protocol::*,
    store::Gate,
    witness::{Checkpoint, ProofSigner, Witness, WitnessAuthority, WitnessCommand},
};
use zeroize::Zeroizing;

struct TestRsa {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    public: String,
    calls: AtomicUsize,
}
impl TestRsa {
    fn new(pem: &str) -> Self {
        let key = openssl::pkey::PKey::private_key_from_pem(pem.as_bytes()).unwrap();
        let public = encode(&key.public_key_to_der().unwrap());
        Self {
            key,
            public,
            calls: AtomicUsize::new(0),
        }
    }
}
impl ShareUnwrapper for TestRsa {
    fn public_key(&self) -> &str {
        &self.public
    }
    fn unwrap(&self, ciphertext: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
        if !label.starts_with("vault-rs/v1/storage/") {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        let mut d = openssl::encrypt::Decrypter::new(&self.key)?;
        d.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
        d.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
        d.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;
        d.set_rsa_oaep_label(label.as_bytes())?;
        let mut bytes = Zeroizing::new(vec![0; d.decrypt_len(ciphertext)?]);
        let len = d.decrypt(ciphertext, &mut bytes)?;
        bytes.truncate(len);
        Ok(Zeroizing::new(bytes.as_slice().try_into()?))
    }
}
fn device() -> Arc<TestRsa> {
    static KEY: OnceLock<Arc<TestRsa>> = OnceLock::new();
    KEY.get_or_init(|| Arc::new(TestRsa::new(include_str!("fixtures/device.TEST-ONLY.pem"))))
        .clone()
}
fn guardian() -> Arc<TestRsa> {
    Arc::new(TestRsa::new(include_str!(
        "fixtures/guardian.TEST-ONLY.pem"
    )))
}

#[derive(Default)]
struct TestWitness {
    values: Mutex<HashMap<Uuid, Checkpoint>>,
    fail: AtomicBool,
    crash_after_commit: AtomicBool,
}
impl Witness for TestWitness {
    fn read(&self, k: Uuid) -> Result<Option<Checkpoint>> {
        ensure!(!self.fail.load(Ordering::SeqCst), "offline");
        Ok(self.values.lock().unwrap().get(&k).cloned())
    }
    fn advance(&self, k: Uuid, old: Option<Checkpoint>, next: Checkpoint) -> Result<()> {
        ensure!(!self.fail.load(Ordering::SeqCst), "offline");
        let mut values = self.values.lock().unwrap();
        ensure!(values.get(&k).cloned() == old, "conflict");
        values.insert(k, next);
        ensure!(
            !self.crash_after_commit.swap(false, Ordering::SeqCst),
            "simulated lost commit response"
        );
        Ok(())
    }
}

fn jwt<T: Serialize>(header: serde_json::Value, claims: &T, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        encode(&serde_json::to_vec(&header).unwrap()),
        encode(&serde_json::to_vec(claims).unwrap())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", encode(&signature.to_bytes()))
}
fn jwk(key: &SigningKey) -> Jwk {
    let p = key.verifying_key().to_sec1_point(false);
    Jwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: encode(p.x().unwrap()),
        y: encode(p.y().unwrap()),
    }
}
struct Fixture {
    dir: TempDir,
    gate: Arc<Gate>,
    trust: Trust,
    witness: Arc<TestWitness>,
    unwrapper: Arc<TestRsa>,
    owner: SigningKey,
    as_key: SigningKey,
    dpop: SigningKey,
    device: SigningKey,
    approval: SigningKey,
    grant: Signed<Grant>,
    record: CiphertextRecord,
    recipient: RecipientSession,
    now: u64,
}
impl Fixture {
    fn new() -> Self {
        Self::with_audience("https://vault.test")
    }
    fn with_audience(audience: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = SigningKey::generate();
        let as_key = SigningKey::generate();
        let dpop = SigningKey::generate();
        let device_key = SigningKey::generate();
        let approval = SigningKey::generate();
        let recipient = RecipientSession::new();
        let unwrapper = guardian();
        let trust = Trust {
            vault: Uuid::new_v4(),
            audience: audience.into(),
            issuer: "https://issuer.test".into(),
            issuer_public_key: public(&as_key),
            owner_public_key: public(&owner),
        };
        let record = seal_record(
            RecordContext {
                vault: trust.vault,
                resource: Uuid::new_v4(),
                version: 1,
            },
            b"test-only: database credential",
            device().public_key(),
            unwrapper.public_key(),
        )
        .unwrap();
        let payload = Grant {
            vault: trust.vault,
            id: Uuid::new_v4(),
            subject: "alice".into(),
            resource: record.context.resource,
            version: 1,
            record_hash: object_hash(&record).unwrap(),
            action: Action::Read,
            issue: None,
            epoch: 7,
            not_before: now - 1,
            expires: now + 300,
            uses: 2,
            dpop_thumbprint: jwk(&dpop).thumbprint().unwrap(),
            device_public_key: public(&device_key),
            guardian_public_key: public(&approval),
            recipient: recipient.public_key().into(),
            instance: Uuid::new_v4(),
            artifact_hash: digest(b"frozen artifact"),
        };
        let grant = sign("owner-grant", &payload, &owner).unwrap();
        let witness = Arc::new(TestWitness::default());
        let gate = Arc::new(
            Gate::open(
                &dir.path().join("vault.db"),
                trust.clone(),
                witness.clone(),
                unwrapper.clone(),
            )
            .unwrap(),
        );
        gate.install(&grant, &record).unwrap();
        Self {
            dir,
            gate,
            trust,
            witness,
            unwrapper,
            owner,
            as_key,
            dpop,
            device: device_key,
            approval,
            grant,
            record,
            recipient,
            now,
        }
    }
    fn request(&self) -> ReleaseRequest {
        let c = self.gate.challenge(&self.grant, self.now).unwrap();
        let g = &self.grant.payload;
        let (scope, endpoint) = match g.action {
            Action::Read => ("secret:read", "release"),
            Action::Issue => ("secret:issue", "issue"),
        };
        let claims = AccessClaims {
            iss: self.trust.issuer.clone(),
            aud: self.trust.audience.clone(),
            sub: g.subject.clone(),
            exp: self.now + 60,
            nbf: self.now - 1,
            scope: scope.into(),
            grant_id: g.id,
            cnf: Confirmation {
                jkt: g.dpop_thumbprint.clone(),
            },
        };
        let access_token = jwt(
            serde_json::json!({"typ":"at+jwt","alg":"ES256"}),
            &claims,
            &self.as_key,
        );
        let dpop = jwt(
            serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk(&self.dpop)}),
            &DpopClaims {
                jti: Uuid::new_v4().to_string(),
                htm: "POST".into(),
                htu: format!("{}/v1/{endpoint}", self.trust.audience),
                iat: self.now,
                ath: digest(access_token.as_bytes()),
                nonce: c.nonce.clone(),
            },
            &self.dpop,
        );
        let operation = Operation {
            vault: g.vault,
            grant: g.id,
            grant_hash: object_hash(&self.grant).unwrap(),
            resource: g.resource,
            version: g.version,
            record_hash: g.record_hash.clone(),
            action: g.action,
            issue: g.issue.clone(),
            epoch: g.epoch,
            sequence: c.sequence,
            nonce: c.nonce,
            not_before: self.now,
            expires: c.expires,
            recipient: g.recipient.clone(),
            instance: g.instance,
            artifact_hash: g.artifact_hash.clone(),
            access_token_hash: digest(access_token.as_bytes()),
        };
        let device_signature = sign("device-operation", &operation, &self.device)
            .unwrap()
            .signature;
        let guardian_signature = sign("guardian-operation", &operation, &self.approval)
            .unwrap()
            .signature;
        ReleaseRequest {
            grant: self.grant.clone(),
            operation,
            device_signature,
            guardian_signature,
            access_token,
            dpop,
        }
    }
    fn resign(&self, r: &mut ReleaseRequest) {
        r.device_signature = sign("device-operation", &r.operation, &self.device)
            .unwrap()
            .signature;
        r.guardian_signature = sign("guardian-operation", &r.operation, &self.approval)
            .unwrap()
            .signature;
    }
}

#[test]
fn legitimate_roundtrip_and_restart_replay_rejection() {
    let f = Fixture::new();
    let r = f.request();
    let result = f.gate.release(&r, f.now).unwrap();
    let plaintext = f
        .recipient
        .open(&f.trust, &r, &result, device().as_ref(), f.now)
        .unwrap();
    assert_eq!(&*plaintext, b"test-only: database credential");
    let restarted = Gate::open(
        &f.dir.path().join("vault.db"),
        f.trust.clone(),
        f.witness.clone(),
        f.unwrapper.clone(),
    )
    .unwrap();
    assert!(restarted.release(&r, f.now).is_err());
    assert_eq!(f.unwrapper.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn stolen_oauth_and_dpop_private_key_cannot_supply_either_independent_proof() {
    let f = Fixture::new();
    let r = f.request();
    for role in ["device", "guardian", "both"] {
        let mut forged = r.clone();
        if role != "guardian" {
            forged.device_signature = sign("device-operation", &forged.operation, &f.dpop)
                .unwrap()
                .signature;
        }
        if role != "device" {
            forged.guardian_signature = sign("guardian-operation", &forged.operation, &f.dpop)
                .unwrap()
                .signature;
        }
        assert!(f.gate.release(&forged, f.now).is_err(), "{role}");
    }
    assert_eq!(f.unwrapper.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn all_security_relevant_operation_fields_are_bound() {
    let f = Fixture::new();
    let original = f.request();
    for field in 0..17 {
        let mut r = original.clone();
        match field {
            0 => r.operation.vault = Uuid::new_v4(),
            1 => r.operation.grant = Uuid::new_v4(),
            2 => r.operation.resource = Uuid::new_v4(),
            3 => r.operation.version += 1,
            4 => r.operation.action = Action::Issue,
            5 => r.operation.epoch += 1,
            6 => r.operation.sequence += 1,
            7 => r.operation.recipient = RecipientSession::new().public_key().into(),
            8 => r.operation.instance = Uuid::new_v4(),
            9 => r.operation.artifact_hash = digest(b"substituted dependency"),
            10 => r.operation.record_hash = digest(b"other record"),
            11 => r.operation.expires += 1,
            12 => r.operation.access_token_hash = digest(b"other token"),
            13 => r.operation.nonce = encode(&[42; 32]),
            14 => r.operation.grant_hash = digest(b"different owner grant"),
            15 => {
                r.operation.issue = Some(vault_rs::extension::IssueSpec {
                    provider: "postgres".into(),
                    role: "administrator".into(),
                    ttl_seconds: 3600,
                })
            }
            16 => r.operation.not_before = f.grant.payload.not_before - 1,
            _ => unreachable!(),
        }
        f.resign(&mut r); // Even two signers cannot expand an owner's grant.
        assert!(f.gate.release(&r, f.now).is_err(), "field {field}");
    }
    assert_eq!(f.unwrapper.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn issuer_signed_tokens_and_client_signed_dpop_cannot_expand_owner_scope() {
    let f = Fixture::new();
    let original = f.request();
    fn payload<T: serde::de::DeserializeOwned>(token: &str) -> T {
        serde_json::from_slice(&decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
    }
    for case in 0..10 {
        let mut request = original.clone();
        let mut claims: AccessClaims = payload(&request.access_token);
        match case {
            0 => claims.iss = "https://other-issuer.test".into(),
            1 => claims.aud = "https://other-vault.test".into(),
            2 => claims.sub = "another-user".into(),
            3 => claims.grant_id = Uuid::new_v4(),
            4 => claims.scope = "secret:issue".into(),
            5 => claims.scope = "secret:read-all".into(),
            6 => claims.nbf = f.now + 1,
            7 => claims.exp = f.now,
            8 => claims.exp = f.now + 1, // token must cover the entire operation
            _ => claims.cnf.jkt = digest(b"different DPoP key"),
        }
        request.access_token = jwt(
            serde_json::json!({"typ":"at+jwt","alg":"ES256"}),
            &claims,
            &f.as_key,
        );
        request.operation.access_token_hash = digest(request.access_token.as_bytes());
        let mut proof: DpopClaims = payload(&request.dpop);
        proof.ath = digest(request.access_token.as_bytes());
        request.dpop = jwt(
            serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk(&f.dpop)}),
            &proof,
            &f.dpop,
        );
        f.resign(&mut request);
        assert!(
            f.gate.release(&request, f.now).is_err(),
            "token claim case {case}"
        );
    }
    for case in 0..9 {
        let mut request = original.clone();
        let mut proof: DpopClaims = payload(&request.dpop);
        let other = SigningKey::generate();
        match case {
            0 => proof.htm = "GET".into(),
            1 => proof.htu = "https://other-vault.test/v1/release".into(),
            2 => proof.htu = "https://vault.test/v1/issue".into(),
            3 => proof.iat = f.now + 1,
            4 => proof.ath = digest(b"different token"),
            5 => proof.nonce = encode(&[7; 32]),
            6 => proof.jti = String::new(),
            7 => proof.jti = "x".repeat(129),
            _ => {}
        }
        let key = if case == 8 { &other } else { &f.dpop };
        request.dpop = jwt(
            serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk(key)}),
            &proof,
            key,
        );
        f.resign(&mut request);
        assert!(f.gate.release(&request, f.now).is_err(), "DPoP case {case}");
    }
    assert_eq!(f.unwrapper.calls.load(Ordering::SeqCst), 0);
    assert!(f.gate.release(&original, f.now).is_ok());
}

#[test]
fn revocation_is_terminal_and_grant_id_cannot_be_reinstalled() {
    let f = Fixture::new();
    let r = f.request();
    let rev = sign(
        "owner-revoke",
        &Revocation {
            vault: f.trust.vault,
            grant: f.grant.payload.id,
        },
        &f.owner,
    )
    .unwrap();
    f.gate.revoke(&rev).unwrap();
    assert!(f.gate.release(&r, f.now).is_err());
    assert!(f.gate.install(&f.grant, &f.record).is_err());
    assert!(f.gate.challenge(&f.grant, f.now).is_err());
}

#[test]
fn rollback_and_lost_witness_response_fail_closed() {
    for crash in [false, true] {
        let f = Fixture::new();
        let r = f.request();
        // Stronger attacker for this test: even a DB writer with the at-rest key
        // cannot restore an old ledger without the independent witness noticing.
        let db =
            vault_rs::storage::open(&f.dir.path().join("vault.db"), f.unwrapper.as_ref()).unwrap();
        let snapshot: String = db
            .query_row("SELECT body FROM grants", [], |r| r.get(0))
            .unwrap();
        if crash {
            f.witness.crash_after_commit.store(true, Ordering::SeqCst);
            assert!(f.gate.release(&r, f.now).is_err());
        } else {
            f.gate.release(&r, f.now).unwrap();
            db.execute("UPDATE grants SET body=?1", [snapshot]).unwrap();
        }
        assert!(f.gate.release(&r, f.now).is_err());
        assert!(f.gate.challenge(&f.grant, f.now).is_err());
        assert_eq!(
            f.unwrapper.calls.load(Ordering::SeqCst),
            if crash { 0 } else { 1 }
        );
    }
}

#[test]
fn interrupted_commit_can_only_recover_by_retirement_and_fresh_owner_grant() {
    let mut f = Fixture::new();
    let old = f.grant.clone();
    let request = f.request();
    f.witness.crash_after_commit.store(true, Ordering::SeqCst);
    assert!(f.gate.release(&request, f.now).is_err());
    assert!(f.gate.challenge(&old, f.now).is_err());
    let checkpoint = f.gate.checkpoint(&old).unwrap();
    let payload = Quarantine {
        vault: f.trust.vault,
        grant: old.payload.id,
        expected: checkpoint,
    };
    assert!(f
        .gate
        .quarantine(&sign("owner-quarantine", &payload, &f.dpop).unwrap())
        .is_err());
    let approved = sign("owner-quarantine", &payload, &f.owner).unwrap();
    f.gate.quarantine(&approved).unwrap();
    assert!(f.gate.release(&request, f.now).is_err());
    assert!(f.gate.install(&old, &f.record).is_err());
    assert!(f.gate.quarantine(&approved).is_err());
    f.grant.payload.id = Uuid::new_v4();
    f.grant = sign("owner-grant", &f.grant.payload, &f.owner).unwrap();
    f.gate.install(&f.grant, &f.record).unwrap();
    assert!(f.gate.release(&f.request(), f.now).is_ok());
    assert!(f.gate.challenge(&old, f.now).is_err());
}

#[test]
fn witness_outage_never_falls_back_to_local_database() {
    let f = Fixture::new();
    let r = f.request();
    f.witness.fail.store(true, Ordering::SeqCst);
    assert!(f.gate.release(&r, f.now).is_err());
    assert_eq!(f.unwrapper.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn simultaneous_replay_has_exactly_one_winner_across_database_connections() {
    let f = Fixture::new();
    let r = f.request();
    let other = Arc::new(
        Gate::open(
            &f.dir.path().join("vault.db"),
            f.trust.clone(),
            f.witness.clone(),
            f.unwrapper.clone(),
        )
        .unwrap(),
    );
    let mut threads = Vec::new();
    for i in 0..12 {
        let g = if i % 2 == 0 {
            f.gate.clone()
        } else {
            other.clone()
        };
        let req = r.clone();
        let now = f.now;
        threads.push(std::thread::spawn(move || g.release(&req, now).is_ok()));
    }
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|b| *b)
            .count(),
        1
    );
    assert_eq!(f.unwrapper.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn quota_and_expiry_are_enforced() {
    let f = Fixture::new();
    let r = f.request();
    assert!(f.gate.release(&r, r.operation.expires).is_err());
    for _ in 0..2 {
        f.gate.release(&f.request(), f.now).unwrap();
    }
    assert!(f.gate.challenge(&f.grant, f.now).is_err());
}

#[test]
fn database_contains_neither_plaintext_nor_plain_decryption_shares() {
    assert!(
        rusqlite::version_number() >= 3_054_001,
        "requires patched SQLite within SQLCipher"
    );
    let f = Fixture::new();
    let mut bytes = std::fs::read(f.dir.path().join("vault.db")).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"));
    let locked = rusqlite::Connection::open(f.dir.path().join("vault.db")).unwrap();
    assert!(locked
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| r
            .get::<_, i64>(0))
        .is_err());
    assert!(vault_rs::storage::open(&f.dir.path().join("vault.db"), device().as_ref()).is_err());
    bytes.extend(std::fs::read(f.dir.path().join("vault.db-wal")).unwrap());
    assert!(!bytes.windows(6).any(|w| w == b"grants"));
    let plaintext = b"test-only: database credential";
    assert!(!bytes.windows(plaintext.len()).any(|w| w == plaintext));
    let serialized = serde_json::to_vec(&f.record).unwrap();
    assert!(!String::from_utf8(serialized)
        .unwrap()
        .contains("database credential"));
    let a = unwrap_share(&f.record, "device", device().as_ref()).unwrap();
    let b = unwrap_share(&f.record, "guardian", f.unwrapper.as_ref()).unwrap();
    assert!(!bytes
        .windows(32)
        .any(|w| w == a.as_ref() || w == b.as_ref()));
    assert!(open_record(&f.record, &a, &[0; 32]).is_err());
    assert!(open_record(&f.record, &[0; 32], &b).is_err());
    let mut swapped = f.record.clone();
    swapped.context.resource = Uuid::new_v4();
    assert!(open_record(&swapped, &a, &b).is_err());
}

#[test]
fn provider_configuration_is_encrypted_and_bound_to_its_hardware_key() {
    use vault_rs::storage::ProtectedConfig;
    let secret = b"test-only-provider-credential";
    let config = ProtectedConfig::seal(device().public_key(), secret).unwrap();
    assert_eq!(config.open(device().as_ref()).unwrap().as_slice(), secret);
    assert!(config.open(guardian().as_ref()).is_err());
    let mut json = serde_json::to_value(&config).unwrap();
    assert!(!json.to_string().contains("test-only-provider"));
    json["id"] = Uuid::new_v4().to_string().into();
    assert!(serde_json::from_value::<ProtectedConfig>(json)
        .unwrap()
        .open(device().as_ref())
        .is_err());
}

#[test]
fn resident_service_keys_unlock_once_and_enforce_purpose_and_public_key() {
    use vault_rs::resident::{Purpose, ResidentKey};
    for purpose in [Purpose::Signing, Purpose::Agreement] {
        let protector = guardian();
        let (envelope, public) = ResidentKey::generate(protector.public_key(), purpose).unwrap();
        let key = ResidentKey::unlock(&envelope, protector.as_ref(), purpose, &public).unwrap();
        assert_eq!(protector.calls.load(Ordering::SeqCst), 1);
        for _ in 0..8 {
            if purpose == Purpose::Signing {
                let payload = Revocation {
                    vault: Uuid::new_v4(),
                    grant: Uuid::new_v4(),
                };
                let signature = key
                    .sign_bytes(&transcript("owner-revoke", &payload).unwrap())
                    .unwrap();
                verify("owner-revoke", &Signed { payload, signature }, &public).unwrap();
                assert!(key.unwrap(&[], "anything").is_err());
            } else {
                let wrapped = vault_rs::external_kem::wrap(
                    &fixed::<65>(public.strip_prefix("p256:").unwrap()).unwrap(),
                    b"test-context",
                    &[7; 32],
                )
                .unwrap();
                assert_eq!(*key.unwrap(&wrapped, "test-context").unwrap(), [7; 32]);
                assert!(key.sign_bytes(b"forbidden signing").is_err());
            }
        }
        assert_eq!(
            protector.calls.load(Ordering::SeqCst),
            1,
            "service operation must not prompt/unseal again"
        );
        assert!(ResidentKey::unlock(&envelope, device().as_ref(), purpose, &public).is_err());
        assert!(ResidentKey::unlock(
            &envelope,
            protector.as_ref(),
            purpose,
            "substituted public key"
        )
        .is_err());
    }
}

#[test]
fn offline_storage_rotation_uses_new_dek_and_excludes_running_services() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.db");
    let new = dir.path().join("new.db");
    let previous = guardian();
    let next = device();
    let db = vault_rs::storage::open(&old, previous.as_ref()).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE secrets(value TEXT); INSERT INTO secrets VALUES('old generation test data');").unwrap();
    assert!(
        vault_rs::storage::rotate_generation(&old, &new, previous.as_ref(), next.as_ref()).is_err()
    );
    drop(db);
    vault_rs::storage::rotate_generation(&old, &new, previous.as_ref(), next.as_ref()).unwrap();
    assert!(vault_rs::storage::open(&new, previous.as_ref()).is_err());
    let db = vault_rs::storage::open(&new, next.as_ref()).unwrap();
    let value: String = db
        .query_row("SELECT value FROM secrets", [], |r| r.get(0))
        .unwrap();
    assert_eq!(value, "old generation test data");
    db.execute("INSERT INTO secrets VALUES(?1)", ["new generation only"])
        .unwrap();
    drop(db);
    let envelope_path = |p: &std::path::Path| {
        let mut n = p.as_os_str().to_os_string();
        n.push(".key-envelope.json");
        std::path::PathBuf::from(n)
    };
    let new_envelope = std::fs::read(envelope_path(&new)).unwrap();
    std::fs::copy(envelope_path(&old), envelope_path(&new)).unwrap();
    assert!(
        vault_rs::storage::open(&new, previous.as_ref()).is_err(),
        "old DEK must not decrypt new generation even with the old envelope"
    );
    std::fs::write(envelope_path(&new), new_envelope).unwrap();
    let db = vault_rs::storage::open(&new, next.as_ref()).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM secrets", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn e2e_rotation_requires_current_authority_and_retires_old_grant() {
    let f = Fixture::new();
    let request = f.request();
    let response = f.gate.release(&request, f.now).unwrap();
    use vault_rs::resident::{Purpose, ResidentKey};
    let protector = device();
    let (device_envelope, device_public) =
        ResidentKey::generate(protector.public_key(), Purpose::Agreement).unwrap();
    let (guardian_envelope, guardian_public) =
        ResidentKey::generate(protector.public_key(), Purpose::Agreement).unwrap();
    let new_device = ResidentKey::unlock(
        &device_envelope,
        protector.as_ref(),
        Purpose::Agreement,
        &device_public,
    )
    .unwrap();
    let new_guardian = ResidentKey::unlock(
        &guardian_envelope,
        protector.as_ref(),
        Purpose::Agreement,
        &guardian_public,
    )
    .unwrap();
    let rotated = f
        .recipient
        .rotate_record(
            &f.trust,
            &request,
            &response,
            device().as_ref(),
            (&device_public, &guardian_public),
            f.now,
        )
        .unwrap();
    assert_eq!(rotated.context.version, f.record.context.version + 1);
    assert!(unwrap_share(&rotated, "device", device().as_ref()).is_err());
    assert!(unwrap_share(&rotated, "guardian", f.unwrapper.as_ref()).is_err());
    let a = unwrap_share(&rotated, "device", &new_device).unwrap();
    let b = unwrap_share(&rotated, "guardian", &new_guardian).unwrap();
    assert_eq!(
        open_record(&rotated, &a, &b).unwrap().as_slice(),
        b"test-only: database credential"
    );
    let revoked = sign(
        "owner-revoke",
        &Revocation {
            vault: f.trust.vault,
            grant: f.grant.payload.id,
        },
        &f.owner,
    )
    .unwrap();
    f.gate.revoke(&revoked).unwrap();
    assert!(f.gate.challenge(&f.grant, f.now).is_err());
    assert!(f.gate.install(&f.grant, &rotated).is_err());
}

#[test]
fn database_commit_failure_after_witness_does_not_disclose() {
    let f = Fixture::new();
    let request = f.request();
    let db = vault_rs::storage::open(&f.dir.path().join("vault.db"), f.unwrapper.as_ref()).unwrap();
    db.execute_batch("CREATE TRIGGER reject_update BEFORE UPDATE ON grants BEGIN SELECT RAISE(ABORT,'injected durable storage failure'); END;").unwrap();
    assert!(f.gate.release(&request, f.now).is_err());
    assert_eq!(f.unwrapper.calls.load(Ordering::SeqCst), 0);
    db.execute_batch("DROP TRIGGER reject_update").unwrap();
    assert!(f.gate.release(&request, f.now).is_err());
    assert!(f.gate.challenge(&f.grant, f.now).is_err());
}

#[test]
fn native_p256_wrapping_profile_roundtrips_both_shares_and_database() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use vault_rs::external_kem::{self, P256Agreement};
    struct SyntheticNative {
        key: p256::SecretKey,
        public: String,
    }
    impl SyntheticNative {
        fn new() -> Self {
            let key = p256::SecretKey::generate();
            let public = format!(
                "p256:{}",
                encode(key.public_key().to_sec1_point(false).as_bytes())
            );
            Self { key, public }
        }
    }
    impl P256Agreement for SyntheticNative {
        fn public_sec1(&self) -> Result<[u8; 65]> {
            fixed(self.public.strip_prefix("p256:").unwrap())
        }
        fn agree(&self, peer: &[u8; 65], _: &str) -> Result<Zeroizing<[u8; 32]>> {
            let peer = p256::PublicKey::from_sec1_bytes(peer)?;
            Ok(Zeroizing::new(
                p256::ecdh::diffie_hellman(self.key.to_nonzero_scalar(), peer.as_affine())
                    .raw_secret_bytes()
                    .as_slice()
                    .try_into()?,
            ))
        }
    }
    impl ShareUnwrapper for SyntheticNative {
        fn public_key(&self) -> &str {
            &self.public
        }
        fn unwrap(&self, ct: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
            Ok(Zeroizing::new(
                external_kem::open(self, ct, label.as_bytes(), label)?
                    .as_slice()
                    .try_into()?,
            ))
        }
    }
    let a = SyntheticNative::new();
    let b = SyntheticNative::new();
    let record = seal_record(
        RecordContext {
            vault: Uuid::new_v4(),
            resource: Uuid::new_v4(),
            version: 1,
        },
        b"test-only-native-profile",
        &a.public,
        &b.public,
    )
    .unwrap();
    let sa = unwrap_share(&record, "device", &a).unwrap();
    let sb = unwrap_share(&record, "guardian", &b).unwrap();
    assert_eq!(
        open_record(&record, &sa, &sb).unwrap().as_slice(),
        b"test-only-native-profile"
    );
    assert!(unwrap_share(&record, "device", &b).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("native.db");
    vault_rs::storage::open(&path, &a)
        .unwrap()
        .execute_batch("CREATE TABLE proof(value INTEGER); INSERT INTO proof VALUES(42)")
        .unwrap();
    assert_eq!(
        vault_rs::storage::open(&path, &a)
            .unwrap()
            .query_row("SELECT value FROM proof", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        42
    );
    assert!(vault_rs::storage::open(&path, &b).is_err());
}

#[test]
#[ignore = "requires the isolated TLS PostgreSQL fixture; scripts/test-postgres.sh runs it"]
fn postgres_dynamic_credentials_are_scoped_idempotent_and_revocable() {
    use std::str::FromStr;
    use vault_rs::extension::*;
    let connection = std::env::var("VAULT_TEST_POSTGRES").expect("isolated test database required");
    let ca = std::path::PathBuf::from(std::env::var("VAULT_TEST_POSTGRES_CA").unwrap());
    let issuer = PostgresIssuer::connect(
        &connection,
        Some(&ca),
        ProviderPolicy {
            provider: "postgres".into(),
            role: "report_reader".into(),
            max_ttl_seconds: 300,
        },
    )
    .unwrap();
    let wasm=wat::parse_str(r#"(module (memory (export "memory") 1 1) (func (export "propose") (param i32 i32) (result i64) local.get 1 i64.extend_i32_u))"#).unwrap();
    let issuer = vault_rs::extension_host::SandboxedIssuer::new(
        Arc::new(issuer),
        vault_rs::extension_host::ProposalModule::from_bytes(&wasm, &digest(&wasm)).unwrap(),
    );
    let mut f = Fixture::new();
    f.grant.payload.id = Uuid::new_v4();
    f.grant.payload.action = Action::Issue;
    f.grant.payload.issue = Some(IssueSpec {
        provider: "postgres".into(),
        role: "report_reader".into(),
        ttl_seconds: 60,
    });
    f.grant = sign("owner-grant", &f.grant.payload, &f.owner).unwrap();
    f.gate.install(&f.grant, &f.record).unwrap();
    let request = f.request();
    let permit = f.gate.prepare_issue(&request, f.now).unwrap();
    let recovered = f.gate.pending_issue(permit.grant()).unwrap().unwrap();
    assert_eq!(recovered.id(), permit.id());
    assert_eq!(
        f.gate.resume_issue(&request, f.now).unwrap().id(),
        permit.id()
    );
    let mut forged = request.clone();
    forged.operation.recipient = RecipientSession::new().public_key().into();
    f.resign(&mut forged);
    assert!(f.gate.resume_issue(&forged, f.now).is_err());
    let lease = issuer.issue(&permit, f.now).unwrap();
    let retried = issuer.issue(&recovered, f.now).unwrap();
    assert_eq!(
        serde_json::to_string(&lease).unwrap(),
        serde_json::to_string(&retried).unwrap()
    );
    let plaintext = f
        .recipient
        .open_lease(&f.trust, &request, &f.record, &lease, f.now)
        .unwrap();
    let credentials: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    let username = credentials["username"].as_str().unwrap();
    let password = credentials["password"].as_str().unwrap();
    let mut ssl = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
    ssl.set_ca_file(&ca).unwrap();
    let mut cfg = postgres::Config::from_str(&connection).unwrap();
    cfg.user(username)
        .password(password)
        .ssl_mode(postgres::config::SslMode::Require);
    let mut client = cfg
        .connect(postgres_openssl::MakeTlsConnector::new(ssl.build()))
        .unwrap();
    assert_eq!(
        client
            .query_one("SELECT value FROM public.vault_test_data", &[])
            .unwrap()
            .get::<_, i32>(0),
        42
    );
    assert!(client
        .execute("INSERT INTO public.vault_test_data VALUES(99)", &[])
        .is_err());
    let valid_until:i64=client.query_one("SELECT EXTRACT(EPOCH FROM rolvaliduntil)::BIGINT FROM pg_roles WHERE rolname=current_user",&[]).unwrap().get(0);
    assert_eq!(valid_until as u64, lease.expires);
    f.gate.complete_issue(&permit).unwrap();
    f.gate.complete_issue(&permit).unwrap(); // concurrent identical completion
    assert!(f.gate.pending_issue(permit.grant()).unwrap().is_none());
    issuer.revoke(permit.id()).unwrap();
    issuer.revoke(permit.id()).unwrap();
    assert!(client.query("SELECT 1", &[]).is_err());
    assert!(issuer.issue(&permit, f.now).is_err());
    assert!(f.gate.prepare_issue(&request, f.now).is_err());
    let next = f.request();
    let second = f.gate.prepare_issue(&next, f.now).unwrap();
    let second_lease = issuer.issue(&second, f.now).unwrap();
    f.gate.complete_issue(&second).unwrap();
    assert_eq!(issuer.expire(second_lease.expires).unwrap(), 1);
    assert!(issuer.issue(&second, f.now).is_err());
}

#[test]
fn response_is_bound_to_recipient_and_exact_request() {
    let f = Fixture::new();
    let r = f.request();
    let response = f.gate.release(&r, f.now).unwrap();
    assert!(RecipientSession::new()
        .open(&f.trust, &r, &response, device().as_ref(), f.now)
        .is_err());
    let mut modified = response.clone();
    modified.request_hash = digest(b"different request");
    assert!(f
        .recipient
        .open(&f.trust, &r, &modified, device().as_ref(), f.now)
        .is_err());
    let mut modified = response;
    modified.guardian_share.ciphertext = encode(&[0; 48]);
    assert!(f
        .recipient
        .open(&f.trust, &r, &modified, device().as_ref(), f.now)
        .is_err());
}

#[tokio::test]
async fn http_surface_uses_the_same_gate_and_does_not_cache_or_disclose_errors() {
    let f = Fixture::new();
    let r = f.request();
    let app = vault_rs::server::router(f.gate.clone());
    let request = Request::post("/v1/release")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&r).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let request = Request::post("/v1/release")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&r).unwrap()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(body.as_ref(), b"request denied");
}

struct TestSigner {
    key: SigningKey,
    public: String,
}

#[test]
#[ignore = "requires installed real AS fixture; scripts/test-oauth.sh"]
fn real_authorization_server_code_pkce_dpop_flow() {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::Duration,
    };
    use vault_rs::oauth::{OAuthConfig, OAuthFlow};
    struct Process(std::process::Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut f = Fixture::new();
    let cert = f.dir.path().join("as.crt");
    let key = f.dir.path().join("as.key");
    assert!(Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout"
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap()
        .status
        .success());
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let callback_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let redirect = format!("http://127.0.0.1:{callback_port}/callback");
    let ready = f.dir.path().join("ready.json");
    let config = f.dir.path().join("as.json");
    let setup = serde_json::json!({"test_fixture":true,"port":port,"redirect_uri":redirect,"resource":f.trust.audience,"grant_id":f.grant.payload.id,"subject":f.grant.payload.subject,"cert":cert,"key":key,"ready":ready});
    std::fs::File::create(&config)
        .unwrap()
        .write_all(serde_json::to_string(&setup).unwrap().as_bytes())
        .unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let _as = Process(
        Command::new("node")
            .arg(root.join(".tools/oauth-as/server.mjs"))
            .arg(&config)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ready).expect("AS failed to start")).unwrap();
    f.trust.issuer = metadata["issuer"].as_str().unwrap().into();
    f.trust.issuer_public_key = metadata["public_key"].as_str().unwrap().into();
    let oauth = OAuthConfig {
        client_id: "vault-broker".into(),
        authorization_endpoint: format!("{}/auth", f.trust.issuer),
        token_endpoint: format!("{}/token", f.trust.issuer),
        redirect_uri: redirect.clone(),
        ca: Some(cert.clone()),
    };
    let flow = OAuthFlow::new(oauth.clone(), &f.trust, &f.grant, &f.dpop).unwrap();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap(),
        )
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let navigate = |flow: &OAuthFlow| {
        let mut url = flow.authorization_url().to_owned();
        let mut cookies = std::collections::BTreeMap::new();
        for _ in 0..16 {
            if url.starts_with(&redirect) {
                break;
            }
            assert!(url.starts_with(&f.trust.issuer));
            let response = client
                .get(&url)
                .header(
                    "cookie",
                    cookies
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
                .send()
                .unwrap();
            for cookie in response.headers().get_all("set-cookie") {
                if let Some((name, value)) = cookie
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .split_once('=')
                {
                    cookies.insert(name.to_string(), value.to_string());
                }
            }
            assert!(
                response.status().is_redirection(),
                "AS response {}: {}",
                response.status(),
                response.text().unwrap()
            );
            url = reqwest::Url::parse(&url)
                .unwrap()
                .join(response.headers()["location"].to_str().unwrap())
                .unwrap()
                .into();
        }
        url
    };
    let url = navigate(&flow);
    let code = flow.callback_code(&url).unwrap();
    let mut duplicate = reqwest::Url::parse(&url).unwrap();
    duplicate.query_pairs_mut().append_pair("state", "attacker");
    assert!(flow.callback_code(duplicate.as_str()).is_err());
    assert!(flow
        .callback_code(&url.replace("iss=", "wrong_iss="))
        .is_err());
    // Independent, unused codes isolate verifier and key-binding failures from replay.
    let pkce_target = OAuthFlow::new(oauth.clone(), &f.trust, &f.grant, &f.dpop).unwrap();
    let pkce_code = pkce_target.callback_code(&navigate(&pkce_target)).unwrap();
    let wrong_verifier = OAuthFlow::new(oauth.clone(), &f.trust, &f.grant, &f.dpop).unwrap();
    assert!(wrong_verifier.exchange(&pkce_code, &f.dpop).is_err());
    let key_target = OAuthFlow::new(oauth.clone(), &f.trust, &f.grant, &f.dpop).unwrap();
    let key_code = key_target.callback_code(&navigate(&key_target)).unwrap();
    assert!(key_target
        .exchange(&key_code, &SigningKey::generate())
        .is_err());
    let token = flow.exchange(&code, &f.dpop).unwrap();
    let replay = OAuthFlow::new(oauth.clone(), &f.trust, &f.grant, &f.dpop).unwrap();
    assert!(replay.exchange(&code, &f.dpop).is_err());
    let mut request = f.request();
    request.access_token = token.to_string();
    request.operation.access_token_hash = digest(token.as_bytes());
    let challenge = f.gate.challenge(&f.grant, f.now).unwrap();
    request.dpop = jwt(
        serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk(&f.dpop)}),
        &DpopClaims {
            jti: Uuid::new_v4().to_string(),
            htm: "POST".into(),
            htu: format!("{}/v1/release", f.trust.audience),
            iat: f.now,
            ath: digest(token.as_bytes()),
            nonce: challenge.nonce,
        },
        &f.dpop,
    );
    f.resign(&mut request);
    let gate = Gate::open(
        &f.dir.path().join("vault.db"),
        f.trust.clone(),
        f.witness.clone(),
        f.unwrapper.clone(),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let response = gate.release(&request, now).unwrap();
    assert_eq!(
        f.recipient
            .open(&f.trust, &request, &response, device().as_ref(), now)
            .unwrap()
            .as_slice(),
        b"test-only: database credential"
    );
    assert!(gate.release(&request, now).is_err());
    println!("PASS: real oidc-provider HTTPS authorization code, S256 PKCE, consent, DPoP nonce, issuer/state, unused-code PKCE/key rejection, code replay, and Vault E2E release");
}

#[tokio::test]
async fn request_expiring_during_hardware_operation_never_discloses() {
    struct Slow(Arc<TestRsa>);
    impl ShareUnwrapper for Slow {
        fn public_key(&self) -> &str {
            self.0.public_key()
        }
        fn unwrap(&self, ciphertext: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
            if !label.starts_with("vault-rs/v1/storage/") {
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            self.0.unwrap(ciphertext, label)
        }
    }
    let f = Fixture::new();
    let mut request = f.request();
    request.operation.expires = f.now + 2;
    request.device_signature = sign("device-operation", &request.operation, &f.device)
        .unwrap()
        .signature;
    request.guardian_signature = sign("guardian-operation", &request.operation, &f.approval)
        .unwrap()
        .signature;
    let gate = Arc::new(
        Gate::open(
            &f.dir.path().join("vault.db"),
            f.trust.clone(),
            f.witness.clone(),
            Arc::new(Slow(f.unwrapper.clone())),
        )
        .unwrap(),
    );
    let response = vault_rs::server::router(gate)
        .oneshot(
            Request::post("/v1/release")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
        b"request denied"
    );
    // Timeouts burn an already committed use, rather than restoring its authority.
    assert!(f.gate.release(&request, f.now).is_err());
    assert_eq!(f.gate.challenge(&f.grant, f.now + 4).unwrap().sequence, 1);
}

#[tokio::test]
async fn real_https_roundtrip_rejects_wrong_ca_plain_http_and_replay() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let f = Fixture::with_audience(&origin);
    let certificate = f.dir.path().join("tls.pem");
    let private_key = f.dir.path().join("tls.key");
    let output = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(&private_key)
        .arg("-out")
        .arg(&certificate)
        .output()
        .unwrap();
    assert!(output.status.success());
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&certificate, &private_key)
        .await
        .unwrap();
    let handle = axum_server::Handle::new();
    let server = tokio::spawn(
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .handle(handle.clone())
            .serve(vault_rs::server::router(f.gate.clone()).into_make_service()),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&certificate).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let r = f.request();
    let url = format!("{origin}/v1/release");
    assert!(reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&url)
        .json(&r)
        .send()
        .await
        .is_err());
    assert!(client
        .post(url.replacen("https:", "http:", 1))
        .json(&r)
        .send()
        .await
        .is_err());
    let response = client.post(&url).json(&r).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let response = response
        .json::<vault_rs::store::ReleaseResponse>()
        .await
        .unwrap();
    assert_eq!(
        f.recipient
            .open(&f.trust, &r, &response, device().as_ref(), f.now)
            .unwrap()
            .as_slice(),
        b"test-only: database credential"
    );
    assert_eq!(
        client.post(&url).json(&r).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    handle.shutdown();
    server.await.unwrap().unwrap();
}
impl TestSigner {
    fn new() -> Self {
        let key = SigningKey::generate();
        let public = public(&key);
        Self { key, public }
    }
}
impl ProofSigner for TestSigner {
    fn public_key(&self) -> &str {
        &self.public
    }
    fn sign_bytes(&self, b: &[u8]) -> Result<String> {
        let s: Signature = self.key.sign(b);
        Ok(encode(&s.to_bytes()))
    }
}

#[test]
fn broker_binds_measured_launch_and_never_signs_unapproved_operations() {
    use vault_rs::broker::{Authorization, BrokerSession};
    struct CountSigner {
        inner: TestSigner,
        calls: AtomicUsize,
    }
    impl ProofSigner for CountSigner {
        fn public_key(&self) -> &str {
            self.inner.public_key()
        }
        fn sign_bytes(&self, bytes: &[u8]) -> Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.sign_bytes(bytes)
        }
    }
    let mut f = Fixture::new();
    let signer = CountSigner {
        inner: TestSigner::new(),
        calls: AtomicUsize::new(0),
    };
    let broker = BrokerSession::new(
        digest(b"measured immutable bundle and arguments"),
        "alice".into(),
    )
    .unwrap();
    let intent = broker.intent(&f.record, &signer).unwrap();
    let g = &mut f.grant.payload;
    g.id = Uuid::new_v4();
    g.instance = intent.instance;
    g.artifact_hash = intent.artifact_hash;
    g.recipient = intent.recipient;
    g.dpop_thumbprint = intent.dpop.thumbprint().unwrap();
    g.device_public_key = intent.device_public_key;
    f.grant = sign("owner-grant", &f.grant.payload, &f.owner).unwrap();
    f.gate.install(&f.grant, &f.record).unwrap();
    let token = jwt(
        serde_json::json!({"typ":"at+jwt","alg":"ES256"}),
        &AccessClaims {
            iss: f.trust.issuer.clone(),
            aud: f.trust.audience.clone(),
            sub: "alice".into(),
            exp: f.now + 60,
            nbf: f.now - 1,
            scope: "secret:read".into(),
            grant_id: f.grant.payload.id,
            cnf: Confirmation {
                jkt: f.grant.payload.dpop_thumbprint.clone(),
            },
        },
        &f.as_key,
    );
    let challenge = f.gate.challenge(&f.grant, f.now).unwrap();
    let mut request = broker
        .prepare(
            &f.trust,
            Authorization {
                grant: f.grant.clone(),
                access_token: token,
            },
            &f.record,
            &signer,
            challenge,
            f.now,
        )
        .unwrap();
    assert!(broker
        .approve_device(&f.trust, &mut request, &f.record, &signer, f.now)
        .is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    request.guardian_signature = sign("guardian-operation", &request.operation, &f.approval)
        .unwrap()
        .signature;
    let mut substituted = request.clone();
    substituted.operation.artifact_hash = digest(b"replaced executable");
    substituted.guardian_signature =
        sign("guardian-operation", &substituted.operation, &f.approval)
            .unwrap()
            .signature;
    assert!(broker
        .approve_device(&f.trust, &mut substituted, &f.record, &signer, f.now)
        .is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    broker
        .approve_device(&f.trust, &mut request, &f.record, &signer, f.now)
        .unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    let response = f.gate.release(&request, f.now).unwrap();
    assert_eq!(
        broker
            .recipient()
            .open(&f.trust, &request, &response, device().as_ref(), f.now)
            .unwrap()
            .as_slice(),
        b"test-only: database credential"
    );
    let other = BrokerSession::new(f.grant.payload.artifact_hash.clone(), "alice".into()).unwrap();
    assert!(other
        .validate_grant(&f.trust, &f.grant, &f.record, &signer)
        .is_err());
}
#[test]
fn witness_requires_authorized_operator_and_monotonic_cas() {
    let d = tempfile::tempdir().unwrap();
    let operator = SigningKey::generate();
    let signer = TestSigner::new();
    let witness_key = signer.public.clone();
    let authority = WitnessAuthority::open(
        &d.path().join("witness.db"),
        public(&operator),
        Box::new(signer),
        guardian().as_ref(),
    )
    .unwrap();
    let mut c = WitnessCommand {
        key: Uuid::new_v4(),
        expected: None,
        next: Some(Checkpoint {
            revision: 0,
            hash: digest(b"initial"),
        }),
        nonce: encode(&[1; 32]),
    };
    let response = authority
        .execute(sign("witness-command", &c, &operator).unwrap())
        .unwrap();
    verify("witness-receipt", &response, &witness_key).unwrap();
    assert_eq!(response.payload.command_hash, object_hash(&c).unwrap());
    assert!(authority
        .execute(sign("witness-command", &c, &operator).unwrap())
        .is_err());
    c.expected = c.next.clone();
    c.next = Some(Checkpoint {
        revision: 0,
        hash: digest(b"rollback"),
    });
    assert!(authority
        .execute(sign("witness-command", &c, &operator).unwrap())
        .is_err());
    c.next = Some(Checkpoint {
        revision: 1,
        hash: digest(b"next"),
    });
    assert!(authority
        .execute(sign("witness-command", &c, &SigningKey::generate()).unwrap())
        .is_err());
    authority
        .execute(sign("witness-command", &c, &operator).unwrap())
        .unwrap();
}

#[test]
fn untrusted_extension_cannot_expand_role_or_ttl_or_submit_sql() {
    use vault_rs::extension::*;
    let policy = ProviderPolicy {
        provider: "postgres".into(),
        role: "report_reader".into(),
        max_ttl_seconds: 300,
    };
    let good = IssueSpec {
        provider: "postgres".into(),
        role: "report_reader".into(),
        ttl_seconds: 60,
    };
    validate_proposal(&policy, &good).unwrap();
    let mut bad = good.clone();
    bad.role = "admin".into();
    assert!(validate_proposal(&policy, &bad).is_err());
    bad = good;
    bad.ttl_seconds = 301;
    assert!(validate_proposal(&policy, &bad).is_err());
    assert!(serde_json::from_str::<IssueSpec>(
        r#"{"provider":"postgres","role":"report_reader","ttl_seconds":60,"sql":"GRANT ALL"}"#
    )
    .is_err());
}
