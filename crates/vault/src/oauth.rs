//! OAuth authorization code + S256 PKCE + DPoP. The broker retains both secrets.
use crate::{
    crypto::*,
    protocol::{Action, Grant, Jwk, Trust},
};
use anyhow::{ensure, Context, Result};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpListener},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub redirect_uri: String,
    pub ca: Option<PathBuf>,
}
pub struct OAuthFlow {
    config: OAuthConfig,
    verifier: Zeroizing<String>,
    state: String,
    issuer: String,
    resource: String,
    authorization_url: String,
}
fn random() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    encode(&b)
}
fn endpoint(value: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(value)?;
    ensure!(
        u.scheme() == "https"
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
            && u.query().is_none(),
        "OAuth endpoint must be an explicit HTTPS URL"
    );
    Ok(u)
}
pub fn public_jwk(key: &SigningKey) -> Jwk {
    let p = key.verifying_key().to_sec1_point(false);
    Jwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: encode(p.x().unwrap()),
        y: encode(p.y().unwrap()),
    }
}
impl OAuthFlow {
    pub fn new(
        config: OAuthConfig,
        trust: &Trust,
        grant: &Signed<Grant>,
        key: &SigningKey,
    ) -> Result<Self> {
        crate::protocol::validate_grant(trust, grant)?;
        ensure!(
            grant.payload.dpop_thumbprint == public_jwk(key).thumbprint()?,
            "OAuth key differs from owner grant"
        );
        ensure!(
            !config.client_id.is_empty() && config.client_id.len() <= 256,
            "invalid OAuth client ID"
        );
        let mut url = endpoint(&config.authorization_endpoint)?;
        let token = endpoint(&config.token_endpoint)?;
        let issuer = endpoint(&trust.issuer)?;
        ensure!(
            url.origin() == issuer.origin() && token.origin() == issuer.origin(),
            "OAuth endpoints must use pinned issuer origin"
        );
        let redirect = reqwest::Url::parse(&config.redirect_uri)?;
        ensure!(
            redirect.scheme() == "http"
                && redirect
                    .host_str()
                    .and_then(|s| s.parse::<IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
                && redirect.port().is_some()
                && redirect.username().is_empty()
                && redirect.password().is_none()
                && redirect.query().is_none()
                && redirect.fragment().is_none()
                && redirect.path() == "/callback",
            "native OAuth redirect must be an explicit loopback IP port /callback"
        );
        let verifier = Zeroizing::new(random());
        let state = random();
        let scope = match grant.payload.action {
            Action::Read => "secret:read",
            Action::Issue => "secret:issue",
        };
        url.query_pairs_mut().extend_pairs([
            ("client_id", config.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("scope", scope),
            ("state", state.as_str()),
            ("code_challenge_method", "S256"),
            ("code_challenge", digest(verifier.as_bytes()).as_str()),
            ("dpop_jkt", public_jwk(key).thumbprint()?.as_str()),
            ("resource", trust.audience.as_str()),
            ("vault_grant", encode(&serde_json::to_vec(grant)?).as_str()),
        ]);
        Ok(Self {
            config,
            verifier,
            state,
            issuer: trust.issuer.clone(),
            resource: trust.audience.clone(),
            authorization_url: url.into(),
        })
    }
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }
    pub fn bind_callback(&self) -> Result<TcpListener> {
        let url = reqwest::Url::parse(&self.config.redirect_uri)?;
        let listener = TcpListener::bind((
            url.host_str().context("missing callback host")?,
            url.port().context("missing callback port")?,
        ))?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    }
    pub fn callback_code(&self, url: &str) -> Result<Zeroizing<String>> {
        let callback = reqwest::Url::parse(url)?;
        let expected = reqwest::Url::parse(&self.config.redirect_uri)?;
        ensure!(
            callback.origin() == expected.origin()
                && callback.path() == expected.path()
                && callback.fragment().is_none(),
            "wrong OAuth callback"
        );
        let mut values = std::collections::BTreeMap::new();
        for (k, v) in callback.query_pairs() {
            ensure!(
                values.insert(k.to_string(), v.to_string()).is_none(),
                "duplicate OAuth callback field"
            );
        }
        ensure!(
            values.get("state") == Some(&self.state) && values.get("iss") == Some(&self.issuer),
            "OAuth state/issuer mismatch"
        );
        ensure!(!values.contains_key("error"), "OAuth authorization denied");
        let code = values
            .remove("code")
            .context("missing authorization code")?;
        ensure!(
            !code.is_empty() && code.len() <= 4096,
            "invalid authorization code"
        );
        Ok(Zeroizing::new(code))
    }
    pub fn wait_callback(&self, listener: TcpListener) -> Result<Zeroizing<String>> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(300) {
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    ensure!(peer.ip().is_loopback(), "non-local callback");
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    let mut bytes = Zeroizing::new(Vec::new());
                    let mut byte = [0u8; 1];
                    while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
                        ensure!(
                            start.elapsed() < Duration::from_secs(300),
                            "OAuth authorization timed out"
                        );
                        if stream.read(&mut byte)? == 0 {
                            break;
                        }
                        bytes.push(byte[0]);
                    }
                    let text = std::str::from_utf8(&bytes)?;
                    let first = text.lines().next().unwrap_or("");
                    let mut fields = first.split(' ');
                    let method = fields.next().unwrap_or("");
                    let path = fields.next().unwrap_or("");
                    let base = reqwest::Url::parse(&self.config.redirect_uri)?;
                    let result = if method == "GET" && path.starts_with("/callback?") {
                        self.callback_code(&format!(
                            "{}{}",
                            base.origin().ascii_serialization(),
                            path
                        ))
                    } else {
                        Err(anyhow::anyhow!("invalid callback"))
                    };
                    let (status, body) = if result.is_ok() {
                        (
                            "200 OK",
                            "Authorization received. You may close this window.",
                        )
                    } else {
                        ("400 Bad Request", "Authorization rejected.")
                    };
                    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())?;
                    if let Ok(code) = result {
                        return Ok(code);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("OAuth authorization timed out")
    }
    pub fn exchange(self, code: &str, key: &SigningKey) -> Result<Zeroizing<String>> {
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15));
        if let Some(ca) = &self.config.ca {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(
                &crate::runner::read_bounded(ca, 65536)?,
            )?);
        }
        let client = builder.build()?;
        let mut nonce: Option<String> = None;
        for _ in 0..2 {
            let header = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":public_jwk(key)});
            let mut claims = serde_json::json!({"jti":uuid::Uuid::new_v4().to_string(),"htm":"POST","htu":self.config.token_endpoint,"iat":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
            if let Some(value) = &nonce {
                claims["nonce"] = serde_json::Value::String(value.clone());
            }
            let input = format!(
                "{}.{}",
                encode(&serde_json::to_vec(&header)?),
                encode(&serde_json::to_vec(&claims)?)
            );
            let signature: Signature = key.sign(input.as_bytes());
            let proof = format!("{input}.{}", encode(&signature.to_bytes()));
            let response = client
                .post(&self.config.token_endpoint)
                .header("DPoP", proof)
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("client_id", &self.config.client_id),
                    ("redirect_uri", &self.config.redirect_uri),
                    ("code", code),
                    ("code_verifier", self.verifier.as_str()),
                    ("resource", &self.resource),
                ])
                .send()?;
            let status = response.status();
            let next_nonce = response
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let mut bytes = Zeroizing::new(Vec::new());
            response.take(32769).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 32768, "OAuth response too large");
            if !status.is_success() {
                let error: serde_json::Value = serde_json::from_slice(&bytes)?;
                if error.get("error").and_then(|v| v.as_str()) == Some("use_dpop_nonce")
                    && nonce.is_none()
                {
                    nonce = Some(
                        next_nonce
                            .filter(|n| n.len() <= 512)
                            .context("invalid OAuth DPoP nonce")?,
                    );
                    continue;
                }
                anyhow::bail!("OAuth token exchange rejected");
            }
            #[derive(Deserialize)]
            struct Token {
                access_token: String,
                token_type: String,
            }
            impl Drop for Token {
                fn drop(&mut self) {
                    self.access_token.zeroize();
                }
            }
            let mut token: Token = serde_json::from_slice(&bytes)?;
            ensure!(
                token.token_type.eq_ignore_ascii_case("DPoP")
                    && !token.access_token.is_empty()
                    && token.access_token.len() <= 16384,
                "AS did not issue a bounded DPoP token"
            );
            return Ok(Zeroizing::new(std::mem::take(&mut token.access_token)));
        }
        anyhow::bail!("OAuth nonce retry exhausted")
    }
}
