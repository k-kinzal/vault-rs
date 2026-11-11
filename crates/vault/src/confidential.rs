//! A fresh SNP quote authorizes one native-key operation at an independent
//! custodian. The response is HPKE sealed to an ephemeral key generated inside
//! the measured guest. There is no report-file, software-quote or plaintext
//! response fallback in this module.
use crate::{
    attestation::{SnpPolicy, SnpVerifier},
    crypto::{self, ShareUnwrapper},
    external_kem::{self, P256Agreement},
    keys::KeyRole,
    native::{NativeConfig, NativeKey},
    witness::ProofSigner,
};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use p256::ecdsa::signature::Verifier;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{
    collections::HashMap,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedConfig {
    pub kind: SnpKind,
    pub endpoint: String,
    pub ca: PathBuf,
    pub key_id: String,
    pub public_key: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SnpKind {
    #[serde(rename = "snp")]
    Snp,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Sign,
    Ecdh,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    custodian: String,
    challenge: String,
    key_id: String,
    public_key: String,
    operation: Operation,
    data: String,
    context: String,
    recipient: String,
}
impl Request {
    fn digest(&self) -> Result<[u8; 64]> {
        let mut hash = Sha512::new();
        hash.update(b"vault-rs/snp-key-operation/v1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hash.finalize().into())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QuotedRequest {
    request: Request,
    report: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    key_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    challenge: String,
}

pub struct AttestedKey {
    config: AttestedConfig,
}
impl AttestedKey {
    pub fn open(config: AttestedConfig, role: KeyRole) -> Result<Self> {
        ensure!(
            vault_policy::key_policy::key_allowed(
                role,
                vault_policy::key_policy::KeyUsage::Service,
                config.public_key.starts_with("p256:")
            ),
            "attested key cannot fulfill this role"
        );
        let url = reqwest::Url::parse(&config.endpoint)?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "custodian requires an HTTPS origin"
        );
        crate::runner::protected_path(&config.ca)?;
        if let Some(point) = config.public_key.strip_prefix("p256:") {
            external_kem::validate_public(&crypto::fixed::<65>(point)?)?;
        } else {
            crypto::parse_public(&config.public_key)?;
        }
        ensure!(
            !config.key_id.is_empty() && config.key_id.len() <= 128,
            "invalid custodian key ID"
        );
        Ok(Self { config })
    }
    fn invoke(
        &self,
        operation: Operation,
        data: &[u8],
        context: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let config = self.config.clone();
        let data = crypto::encode(data);
        let context = context.to_owned();
        // TLS signing is synchronous and can be called on a Tokio thread. Own
        // the blocking HTTPS client on a dedicated thread, including its drop.
        std::thread::spawn(move || -> Result<Zeroizing<Vec<u8>>> {
            let ca = crate::runner::read_bounded(&config.ca, 65536)?;
            let client = reqwest::blocking::Client::builder()
                .https_only(true)
                .tls_built_in_root_certs(false)
                .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(20))
                .build()?;
            let read = |response: reqwest::blocking::Response| -> Result<Vec<u8>> {
                let mut bytes = Vec::new();
                response
                    .error_for_status()?
                    .take(65537)
                    .read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 65536, "custodian response too large");
                Ok(bytes)
            };
            let challenge: Challenge = serde_json::from_slice(&read(
                client
                    .post(format!("{}v1/challenge", config.endpoint))
                    .json(&ChallengeRequest {
                        key_id: config.key_id.clone(),
                    })
                    .send()?,
            )?)?;
            crypto::fixed::<32>(&challenge.challenge)?;
            let (private, recipient) = crypto::recipient_keypair();
            let request = Request {
                custodian: config.endpoint.clone(),
                challenge: challenge.challenge,
                key_id: config.key_id,
                public_key: config.public_key,
                operation,
                data,
                context,
                recipient,
            };
            let digest = request.digest()?;
            let report = crate::attestation::quote(digest)?;
            let sealed = serde_json::from_slice(&read(
                client
                    .post(format!("{}v1/operate", config.endpoint))
                    .json(&QuotedRequest {
                        request,
                        report: crypto::encode(&report),
                    })
                    .send()?,
            )?)?;
            crypto::open_response(&private, &hex::encode(digest), &sealed)
        })
        .join()
        .map_err(|_| anyhow::anyhow!("attested operation worker failed"))?
    }
}
impl P256Agreement for AttestedKey {
    fn public_sec1(&self) -> Result<[u8; 65]> {
        crypto::fixed(
            self.config
                .public_key
                .strip_prefix("p256:")
                .context("agreement key required")?,
        )
    }
    fn agree(&self, peer: &[u8; 65], context: &str) -> Result<Zeroizing<[u8; 32]>> {
        external_kem::validate_public(peer)?;
        let bytes = self.invoke(Operation::Ecdh, peer, context)?;
        Ok(Zeroizing::new(bytes.as_slice().try_into()?))
    }
}
impl ShareUnwrapper for AttestedKey {
    fn public_key(&self) -> &str {
        &self.config.public_key
    }
    fn unwrap(&self, ciphertext: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
        let bytes = external_kem::open(self, ciphertext, label.as_bytes(), label)?;
        Ok(Zeroizing::new(bytes.as_slice().try_into()?))
    }
}
impl ProofSigner for AttestedKey {
    fn public_key(&self) -> &str {
        &self.config.public_key
    }
    fn sign_bytes(&self, message: &[u8]) -> Result<String> {
        let bytes = self.invoke(
            Operation::Sign,
            message,
            "vault-rs attested signing operation",
        )?;
        let signature = p256::ecdsa::Signature::from_slice(&bytes)?;
        crypto::parse_public(&self.config.public_key)?.verify(message, &signature)?;
        Ok(crypto::encode(&bytes))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodianKeyConfig {
    pub key_id: String,
    pub native: NativeConfig,
    pub guest: SnpPolicy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodianConfig {
    pub origin: String,
    pub listen: std::net::SocketAddr,
    pub certificate: PathBuf,
    pub tls_signing: NativeConfig,
    pub custodian_keys: Vec<CustodianKeyConfig>,
}
impl CustodianConfig {
    pub fn preflight(&self) -> Result<()> {
        ensure!(
            nix::unistd::getuid().is_root() && nix::unistd::geteuid().is_root(),
            "independent custodian administrator required"
        );
        NativeKey::open_for(self.tls_signing.clone(), KeyRole::TlsSigning)?;
        ensure!(
            !self.custodian_keys.is_empty() && self.custodian_keys.len() <= 64,
            "invalid custodian key count"
        );
        let mut ids = std::collections::HashSet::new();
        let origin = reqwest::Url::parse(&self.origin)?;
        ensure!(
            origin.scheme() == "https"
                && origin.path() == "/"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none(),
            "custodian HTTPS origin required"
        );
        crate::native_tls::configuration(
            &self.certificate,
            crate::keys::RuntimeKeyConfig::Native(self.tls_signing.clone()),
        )?;
        for key in &self.custodian_keys {
            ensure!(
                !key.key_id.is_empty() && key.key_id.len() <= 128 && ids.insert(&key.key_id),
                "duplicate or invalid custodian key ID"
            );
            let role = if key.native.public_key.starts_with("p256:") {
                KeyRole::ServiceUnwrap
            } else {
                KeyRole::ServiceSigning
            };
            NativeKey::open_for(key.native.clone(), role)?;
            SnpVerifier::open(key.guest.clone())?;
        }
        Ok(())
    }
}
trait CustodianOperation: ProofSigner + P256Agreement {}
impl CustodianOperation for NativeKey {}
struct CustodianKey {
    native: Box<dyn CustodianOperation>,
    verifier: SnpVerifier,
    agreement: bool,
}
struct Pending {
    key_id: String,
    issued: u64,
}
pub struct Custodian {
    origin: String,
    keys: HashMap<String, CustodianKey>,
    challenges: Mutex<HashMap<String, Pending>>,
}
impl Custodian {
    pub fn open(origin: String, configs: Vec<CustodianKeyConfig>) -> Result<Self> {
        ensure!(
            !configs.is_empty() && configs.len() <= 64,
            "invalid custodian key count"
        );
        let mut keys = HashMap::new();
        for config in configs {
            let agreement = config.native.public_key.starts_with("p256:");
            let native = NativeKey::open_for(
                config.native,
                if agreement {
                    KeyRole::ServiceUnwrap
                } else {
                    KeyRole::ServiceSigning
                },
            )?;
            let verifier = SnpVerifier::open(config.guest)?;
            ensure!(
                keys.insert(
                    config.key_id,
                    CustodianKey {
                        native: Box::new(native),
                        verifier,
                        agreement
                    }
                )
                .is_none(),
                "duplicate key ID"
            );
        }
        Ok(Self {
            origin,
            keys,
            challenges: Mutex::new(HashMap::new()),
        })
    }
    fn challenge(&self, key_id: String) -> Result<Challenge> {
        ensure!(self.keys.contains_key(&key_id), "unknown key");
        let now = now()?;
        let mut pending = self
            .challenges
            .lock()
            .map_err(|_| anyhow::anyhow!("challenge state unavailable"))?;
        pending.retain(|_, p| vault_policy::attestation::challenge_live(p.issued, now));
        ensure!(pending.len() < 4096, "challenge capacity exceeded");
        let mut nonce = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let challenge = crypto::encode(&nonce);
        ensure!(!pending.contains_key(&challenge), "challenge collision");
        pending.insert(
            challenge.clone(),
            Pending {
                key_id,
                issued: now,
            },
        );
        Ok(Challenge { challenge })
    }
    fn operate(&self, quoted: QuotedRequest) -> Result<crate::crypto::SealedResponse> {
        let request = quoted.request;
        ensure!(request.custodian == self.origin, "wrong custodian origin");
        let key = self.keys.get(&request.key_id).context("unknown key")?;
        ensure!(
            request.public_key == ProofSigner::public_key(key.native.as_ref()),
            "key generation mismatch"
        );
        ensure!(
            key.agreement == matches!(request.operation, Operation::Ecdh),
            "key purpose mismatch"
        );
        ensure!(
            request.data.len() <= 24000 && request.context.len() <= 1024,
            "oversized operation"
        );
        crypto::fixed::<32>(&request.recipient)?;
        let digest = request.digest()?;
        let mut pending = self
            .challenges
            .lock()
            .map_err(|_| anyhow::anyhow!("challenge state unavailable"))?;
        // A failed attempt consumes the challenge too. A restart forgets all
        // challenges. The lock and removal prevent concurrent replay.
        let challenge = pending
            .remove(&request.challenge)
            .context("unknown or consumed challenge")?;
        drop(pending);
        ensure!(
            challenge.key_id == request.key_id
                && vault_policy::attestation::challenge_live(challenge.issued, now()?),
            "challenge expired or wrong key"
        );
        key.verifier
            .verify(&crypto::decode(&quoted.report)?, &digest, now()?)?;
        let data = crypto::decode(&request.data)?;
        let response = match request.operation {
            Operation::Sign => Zeroizing::new(crypto::decode(&key.native.sign_bytes(&data)?)?),
            Operation::Ecdh => Zeroizing::new(
                key.native
                    .agree(&data.as_slice().try_into()?, &request.context)?
                    .to_vec(),
            ),
        };
        crypto::seal_response(&request.recipient, &hex::encode(digest), &response)
    }
}
async fn challenge_handler(
    State(c): State<Arc<Custodian>>,
    Json(r): Json<ChallengeRequest>,
) -> Result<Json<Challenge>, StatusCode> {
    c.challenge(r.key_id)
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}
async fn operate_handler(
    State(c): State<Arc<Custodian>>,
    Json(r): Json<QuotedRequest>,
) -> Result<Json<crate::crypto::SealedResponse>, StatusCode> {
    tokio::task::spawn_blocking(move || c.operate(r))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}
pub fn router(custodian: Custodian) -> Router {
    Router::new()
        .route("/v1/challenge", post(challenge_handler))
        .route("/v1/operate", post(operate_handler))
        .layer(DefaultBodyLimit::max(40000))
        .with_state(Arc::new(custodian))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::signature::Signer,
        elliptic_curve::{sec1::ToSec1Point, Generate},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct FixtureKey {
        key: p256::SecretKey,
        public: String,
        calls: Arc<AtomicUsize>,
    }
    impl ProofSigner for FixtureKey {
        fn public_key(&self) -> &str {
            &self.public
        }
        fn sign_bytes(&self, data: &[u8]) -> Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let signature: p256::ecdsa::Signature =
                p256::ecdsa::SigningKey::from(&self.key).sign(data);
            Ok(crypto::encode(&signature.to_bytes()))
        }
    }
    impl P256Agreement for FixtureKey {
        fn public_sec1(&self) -> Result<[u8; 65]> {
            Ok(self
                .key
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()?)
        }
        fn agree(&self, peer: &[u8; 65], _: &str) -> Result<Zeroizing<[u8; 32]>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let peer = p256::PublicKey::from_sec1_bytes(peer)?;
            Ok(Zeroizing::new(
                p256::ecdh::diffie_hellman(self.key.to_nonzero_scalar(), peer.as_affine())
                    .raw_secret_bytes()
                    .as_slice()
                    .try_into()?,
            ))
        }
    }
    impl CustodianOperation for FixtureKey {}
    #[test]
    fn quoted_operations_bind_recipient_input_key_and_single_use_challenge() {
        for agreement in [false, true] {
            let (verifier, report, quote_key) =
                crate::attestation::tests::synthetic_at(now().unwrap());
            let calls = Arc::new(AtomicUsize::new(0));
            let key = p256::SecretKey::generate();
            let public = if agreement {
                format!(
                    "p256:{}",
                    crypto::encode(key.public_key().to_sec1_point(false).as_bytes())
                )
            } else {
                crypto::encode(key.public_key().to_sec1_point(true).as_bytes())
            };
            let fixture = FixtureKey {
                key,
                public: public.clone(),
                calls: calls.clone(),
            };
            let peer = p256::SecretKey::generate();
            let data = if agreement {
                peer.public_key().to_sec1_point(false).as_bytes().to_vec()
            } else {
                b"typed signed operation".to_vec()
            };
            let custodian = Custodian {
                origin: "https://custodian.test/".into(),
                keys: HashMap::from([(
                    "key".into(),
                    CustodianKey {
                        native: Box::new(fixture),
                        verifier,
                        agreement,
                    },
                )]),
                challenges: Mutex::new(HashMap::new()),
            };
            let (private, recipient) = crypto::recipient_keypair();
            let mut request = Request {
                custodian: custodian.origin.clone(),
                challenge: String::new(),
                key_id: "key".into(),
                public_key: public,
                operation: if agreement {
                    Operation::Ecdh
                } else {
                    Operation::Sign
                },
                data: crypto::encode(&data),
                context: "purpose".into(),
                recipient,
            };
            let quoted = |request: &Request| {
                let mut report = report;
                report.report_data = request.digest().unwrap();
                QuotedRequest {
                    request: request.clone(),
                    report: crypto::encode(&crate::attestation::tests::sign(report, &quote_key)),
                }
            };
            for mutation in 0..7 {
                request.challenge = custodian.challenge("key".into()).unwrap().challenge;
                let mut changed = quoted(&request);
                match mutation {
                    0 => changed.request.recipient = crypto::recipient_keypair().1,
                    1 => changed.request.data = crypto::encode(b"different input"),
                    2 => changed.request.context.push('!'),
                    3 => changed.request.public_key.push('!'),
                    4 => changed.request.custodian.push('!'),
                    5 => changed.request.challenge = crypto::encode(&[0; 32]),
                    _ => {
                        custodian
                            .challenges
                            .lock()
                            .unwrap()
                            .get_mut(&request.challenge)
                            .unwrap()
                            .issued = 0;
                    }
                }
                assert!(custodian.operate(changed).is_err());
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    0,
                    "rejected requests must never reach a native key"
                );
            }
            request.challenge = custodian.challenge("key".into()).unwrap().challenge;
            let result = custodian.operate(quoted(&request)).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let digest = hex::encode(request.digest().unwrap());
            let result_bytes = crypto::open_response(&private, &digest, &result).unwrap();
            assert!(!result_bytes.is_empty());
            assert!(
                crypto::open_response(&crypto::recipient_keypair().0, &digest, &result).is_err()
            );
            assert!(custodian.operate(quoted(&request)).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}
