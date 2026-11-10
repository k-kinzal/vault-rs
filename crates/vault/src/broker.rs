//! One-shot native broker. Its only control input is the administrator-owned
//! inherited stdin. Public intent/operation records may be sent to an OAuth AS
//! and independent approval service; no private key is exported to either.
use crate::{
    client::RecipientSession,
    crypto::*,
    protocol::*,
    resident::RuntimeKeyConfig,
    runner::{self, Bundle},
    witness::{ProofSigner, RemoteWitness},
};
use anyhow::{ensure, Context, Result};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::Generate,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    io::{BufRead, Read, Write},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Serialize)]
pub struct Intent {
    pub instance: Uuid,
    pub recipient: String,
    pub artifact_hash: String,
    pub dpop: Jwk,
    pub device_public_key: String,
    pub resource: Uuid,
    pub version: u64,
    pub record_hash: String,
    pub subject: String,
}
pub struct BrokerSession {
    recipient: RecipientSession,
    dpop: SigningKey,
    instance: Uuid,
    artifact: String,
    subject: String,
}
impl BrokerSession {
    pub fn new(artifact: String, subject: String) -> Result<Self> {
        fixed::<32>(&artifact)?;
        ensure!(!subject.is_empty(), "subject required");
        Ok(Self {
            recipient: RecipientSession::new(),
            dpop: SigningKey::generate(),
            instance: Uuid::new_v4(),
            artifact,
            subject,
        })
    }
    fn jwk(&self) -> Jwk {
        let p = self.dpop.verifying_key().to_sec1_point(false);
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: encode(p.x().unwrap()),
            y: encode(p.y().unwrap()),
        }
    }
    pub fn intent(&self, record: &CiphertextRecord, device: &dyn ProofSigner) -> Result<Intent> {
        Ok(Intent {
            instance: self.instance,
            recipient: self.recipient.public_key().into(),
            artifact_hash: self.artifact.clone(),
            dpop: self.jwk(),
            device_public_key: device.public_key().into(),
            resource: record.context.resource,
            version: record.context.version,
            record_hash: object_hash(record)?,
            subject: self.subject.clone(),
        })
    }
    pub fn validate_grant(
        &self,
        trust: &Trust,
        grant: &Signed<Grant>,
        record: &CiphertextRecord,
        device: &dyn ProofSigner,
    ) -> Result<()> {
        validate_grant(trust, grant)?;
        let g = &grant.payload;
        ensure!(
            g.artifact_hash == self.artifact
                && g.instance == self.instance
                && g.recipient == self.recipient.public_key()
                && g.subject == self.subject
                && g.dpop_thumbprint == self.jwk().thumbprint()?
                && g.device_public_key == device.public_key(),
            "grant does not authorize this measured execution"
        );
        ensure!(
            g.record_hash == object_hash(record)?
                && g.resource == record.context.resource
                && g.version == record.context.version
                && g.vault == record.context.vault,
            "record outside execution grant"
        );
        Ok(())
    }
    pub fn prepare(
        &self,
        trust: &Trust,
        authorization: Authorization,
        record: &CiphertextRecord,
        device: &dyn ProofSigner,
        challenge: Challenge,
        now: u64,
    ) -> Result<ReleaseRequest> {
        let Authorization {
            grant,
            access_token: token,
        } = authorization;
        self.validate_grant(trust, &grant, record, device)?;
        let g = &grant.payload;
        ensure!(challenge.grant == g.id, "wrong challenge");
        let operation = Operation {
            vault: g.vault,
            grant: g.id,
            grant_hash: object_hash(&grant)?,
            resource: g.resource,
            version: g.version,
            record_hash: g.record_hash.clone(),
            action: g.action,
            issue: g.issue.clone(),
            epoch: g.epoch,
            sequence: challenge.sequence,
            nonce: challenge.nonce.clone(),
            not_before: now,
            expires: now
                .checked_add(MAX_REQUEST_LIFETIME)
                .context("clock overflow")?
                .min(challenge.expires)
                .min(g.expires),
            recipient: self.recipient.public_key().into(),
            instance: self.instance,
            artifact_hash: self.artifact.clone(),
            access_token_hash: digest(token.as_bytes()),
        };
        let endpoint = match g.action {
            Action::Read => "release",
            Action::Issue => "issue",
        };
        let claims = DpopClaims {
            jti: Uuid::new_v4().to_string(),
            htm: "POST".into(),
            htu: format!("{}/v1/{endpoint}", trust.audience),
            iat: now,
            ath: digest(token.as_bytes()),
            nonce: challenge.nonce,
        };
        let header = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":self.jwk()});
        let input = format!(
            "{}.{}",
            encode(&serde_json::to_vec(&header)?),
            encode(&serde_json::to_vec(&claims)?)
        );
        let signature: Signature = self.dpop.sign(input.as_bytes());
        Ok(ReleaseRequest {
            grant,
            operation,
            device_signature: String::new(),
            guardian_signature: String::new(),
            access_token: token,
            dpop: format!("{input}.{}", encode(&signature.to_bytes())),
        })
    }
    pub fn approve_device(
        &self,
        trust: &Trust,
        request: &mut ReleaseRequest,
        record: &CiphertextRecord,
        device: &dyn ProofSigner,
        now: u64,
    ) -> Result<()> {
        self.validate_grant(trust, &request.grant, record, device)?;
        // Validate the complete request and guardian before invoking private key UI.
        verify_before_device(trust, request, record, now)?;
        request.device_signature =
            device.sign_bytes(&transcript("device-operation", &request.operation)?)?;
        verify_release(trust, request, record, now)?;
        Ok(())
    }
    pub fn recipient(&self) -> &RecipientSession {
        &self.recipient
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    #[serde(default)]
    pub oauth: Option<crate::oauth::OAuthConfig>,
    pub trust: Trust,
    pub subject: String,
    pub record: PathBuf,
    pub bundle: PathBuf,
    pub staging_directory: PathBuf,
    pub ai_uid: u32,
    pub uid_base: u32,
    pub uid_limit: u32,
    pub timeout_seconds: u64,
    pub device_signing: RuntimeKeyConfig,
    pub device_decryption: RuntimeKeyConfig,
    pub allocator_signing: RuntimeKeyConfig,
    pub allocator_namespace: Uuid,
    pub allocator_url: String,
    pub allocator_public_key: String,
    pub ca: Option<PathBuf>,
    pub allocator_ca: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub grant: Signed<Grant>,
    pub access_token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    guardian_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationInput {
    grant: Signed<Grant>,
    #[serde(default)]
    access_token: Option<String>,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn line<T: DeserializeOwned>(input: &mut impl BufRead) -> Result<T> {
    let mut bytes = Vec::new();
    input.take(262145).read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.len() <= 262144 && bytes.last() == Some(&b'\n'),
        "invalid control frame"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn emit(value: &impl Serialize) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn response<T: DeserializeOwned>(response: reqwest::blocking::Response) -> Result<T> {
    let mut bytes = Vec::new();
    response
        .error_for_status()?
        .take(262145)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 262144, "response too large");
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn run(config_path: PathBuf) -> Result<i32> {
    ensure!(
        nix::unistd::getuid().is_root() && nix::unistd::geteuid().is_root(),
        "broker must be started by its administrator service, not the AI UID"
    );
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false)?;
    runner::protected_path(&config_path)?;
    let config: BrokerConfig = serde_json::from_slice(&runner::read_bounded(&config_path, 65536)?)?;
    ensure!(config.ai_uid != 0, "AI must not have broker privileges");
    ensure!(
        !(config.uid_base..config.uid_limit).contains(&config.ai_uid),
        "worker UID range must exclude the AI identity"
    );
    runner::protected_path(&config.bundle)?;
    runner::protected_path(&config.record)?;
    let bundle: Bundle = serde_json::from_slice(&runner::read_bounded(
        &config.bundle,
        runner::MAX_BUNDLE_BYTES * 2,
    )?)?;
    let staged = bundle.stage(&config.staging_directory)?;
    let record: CiphertextRecord =
        serde_json::from_slice(&runner::read_bounded(&config.record, 262144)?)?;
    config.device_signing.isolate_from(config.ai_uid)?;
    config.device_decryption.isolate_from(config.ai_uid)?;
    config.allocator_signing.isolate_from(config.ai_uid)?;
    let device = config.device_signing.open()?;
    let decryption = config.device_decryption.open()?;
    ensure!(
        record.device_key == wrapping_key_hash(ShareUnwrapper::public_key(decryption.as_ref()))?,
        "wrong device decryption key"
    );
    let session = BrokerSession::new(staged.hash().into(), config.subject)?;
    emit(&session.intent(&record, device.as_ref())?)?;
    let mut input = std::io::stdin().lock();
    let incoming: AuthorizationInput = line(&mut input)?;
    session.validate_grant(&config.trust, &incoming.grant, &record, device.as_ref())?;
    let access_token = match incoming.access_token {
        Some(token) => token,
        None => {
            let oauth = config
                .oauth
                .context("OAuth configuration required when no token is supplied")?;
            if let Some(ca) = &oauth.ca {
                runner::protected_path(ca)?;
            }
            let flow =
                crate::oauth::OAuthFlow::new(oauth, &config.trust, &incoming.grant, &session.dpop)?;
            let callback = flow.bind_callback()?;
            emit(&serde_json::json!({"authorization_url":flow.authorization_url()}))?;
            let code = flow.wait_callback(callback)?;
            flow.exchange(&code, &session.dpop)?.to_string()
        }
    };
    let auth = Authorization {
        grant: incoming.grant,
        access_token,
    };
    session.validate_grant(&config.trust, &auth.grant, &record, device.as_ref())?;
    let mut client = reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10));
    if let Some(ca) = config.ca {
        runner::protected_path(&ca)?;
        client = client.add_root_certificate(reqwest::Certificate::from_pem(
            &runner::read_bounded(&ca, 65536)?,
        )?);
    }
    let client = client.build()?;
    let origin = &config.trust.audience;
    let installed = client
        .post(format!("{origin}/v1/install"))
        .json(&serde_json::json!({"grant":&auth.grant,"record":&record}))
        .send()?;
    ensure!(
        installed.status() == reqwest::StatusCode::CREATED,
        "grant installation denied"
    );
    let challenge = response(
        client
            .post(format!("{origin}/v1/challenge"))
            .json(&auth.grant)
            .send()?,
    )?;
    let mut request = session.prepare(
        &config.trust,
        auth,
        &record,
        device.as_ref(),
        challenge,
        now()?,
    )?;
    emit(&request.operation)?;
    let approval: Approval = line(&mut input)?;
    request.guardian_signature = approval.guardian_signature;
    session.approve_device(
        &config.trust,
        &mut request,
        &record,
        device.as_ref(),
        now()?,
    )?;
    let allocator_ca = config
        .allocator_ca
        .map(|p| {
            runner::protected_path(&p)?;
            runner::read_bounded(&p, 65536)
        })
        .transpose()?;
    let witness = RemoteWitness::new(
        config.allocator_url,
        config.allocator_public_key,
        config.allocator_signing.open()? as Box<dyn ProofSigner>,
        allocator_ca.as_deref(),
    )?;
    let worker = runner::allocate_worker(
        &witness,
        config.allocator_namespace,
        config.uid_base,
        config.uid_limit,
        config.ai_uid,
    )?;
    let plaintext = match request.operation.action {
        Action::Read => {
            let result = response(
                client
                    .post(format!("{origin}/v1/release"))
                    .json(&request)
                    .send()?,
            )?;
            session.recipient.open_current(
                &config.trust,
                &request,
                &result,
                decryption.as_ref(),
                now,
            )?
        }
        Action::Issue => {
            let result = response(
                client
                    .post(format!("{origin}/v1/issue"))
                    .json(&request)
                    .send()?,
            )?;
            session
                .recipient
                .open_lease(&config.trust, &request, &record, &result, now()?)?
        }
    };
    crate::client::ensure_current(&request, now()?)?;
    runner::launch(
        &std::env::current_exe()?,
        &staged,
        worker,
        config.ai_uid,
        &plaintext,
        Duration::from_secs(config.timeout_seconds),
    )
}
