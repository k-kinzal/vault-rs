//! Strict, versioned authorization profile. Not a new OAuth authorization server.
use crate::crypto::*;
use anyhow::{ensure, Context, Result};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    Sec1Point,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;
use vault_policy::{Evidence, Request};

pub const MAX_REQUEST_LIFETIME: u64 = 30;

pub type Trust = vault_policy::wire::Trust<Uuid, String>;

pub use vault_policy::wire::Action;

pub type Grant = vault_policy::wire::Grant<Uuid, String, Option<crate::extension::IssueSpec>>;

pub type Operation =
    vault_policy::wire::Operation<Uuid, String, Option<crate::extension::IssueSpec>>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    pub grant: Signed<Grant>,
    pub operation: Operation,
    pub device_signature: String,
    pub guardian_signature: String,
    pub access_token: String,
    pub dpop: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub vault: Uuid,
    pub grant: Uuid,
}

/// Owner-authorized recovery can only retire an ID against an exact independent
/// checkpoint. It cannot restore a use, replace a witness, or reopen an old grant.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    pub vault: Uuid,
    pub grant: Uuid,
    pub expected: crate::witness::Checkpoint,
}

pub type Challenge = vault_policy::wire::Challenge<Uuid, String>;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}
impl Jwk {
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        ensure!(self.kty == "EC" && self.crv == "P-256", "unsupported JWK");
        let x = fixed::<32>(&self.x)?;
        let y = fixed::<32>(&self.y)?;
        let point = Sec1Point::from_affine_coordinates((&x).into(), (&y).into(), false);
        Ok(VerifyingKey::from_sec1_point(&point)?)
    }
    pub fn thumbprint(&self) -> Result<String> {
        self.verifying_key()?;
        // RFC 7638 lexicographic required-member representation.
        Ok(digest(
            format!(
                "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                self.x, self.y
            )
            .as_bytes(),
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtHeader {
    typ: String,
    alg: String,
    #[serde(default)]
    jwk: Option<Jwk>,
    #[serde(default)]
    kid: Option<String>,
}
pub type Confirmation = vault_policy::wire::Confirmation<String>;
pub type AccessClaims = vault_policy::wire::AccessClaims<Uuid, String, String>;
pub type DpopClaims = vault_policy::wire::DpopClaims<String, String>;

fn jwt_parts<T: DeserializeOwned>(
    jwt: &str,
    typ: &str,
    expected: Option<&str>,
) -> Result<(T, Option<Jwk>)> {
    ensure!(jwt.len() <= 16384, "JWT too large");
    let p: Vec<_> = jwt.split('.').collect();
    ensure!(p.len() == 3, "invalid JWT");
    let header: JwtHeader = serde_json::from_slice(&decode(p[0])?)?;
    ensure!(
        header.typ == typ && header.alg == "ES256",
        "invalid JWT algorithm/type"
    );
    if let Some(kid) = &header.kid {
        ensure!(kid.len() <= 128, "invalid kid");
    }
    let key = if let Some(key) = expected {
        ensure!(header.jwk.is_none(), "token may not select issuer key");
        parse_public(key)?
    } else {
        header
            .jwk
            .as_ref()
            .context("DPoP JWK required")?
            .verifying_key()?
    };
    let sig = Signature::from_slice(&fixed::<64>(p[2])?)?;
    key.verify(format!("{}.{}", p[0], p[1]).as_bytes(), &sig)?;
    Ok((serde_json::from_slice(&decode(p[1])?)?, header.jwk))
}

pub fn validate_grant(trust: &Trust, grant: &Signed<Grant>) -> Result<()> {
    verify("owner-grant", grant, &trust.owner_public_key)?;
    let g = &grant.payload;
    ensure!(
        g.vault == trust.vault && g.uses > 0 && g.not_before < g.expires,
        "invalid grant"
    );
    ensure!(
        matches!(
            (g.action, &g.issue),
            (Action::Read, None) | (Action::Issue, Some(_))
        ),
        "invalid action specification"
    );
    ensure!(
        !g.subject.is_empty() && g.subject.len() <= 256,
        "invalid subject"
    );
    fixed::<32>(&g.record_hash)?;
    fixed::<32>(&g.recipient)?;
    fixed::<32>(&g.artifact_hash)?;
    fixed::<32>(&g.dpop_thumbprint)?;
    let device = parse_public(&g.device_public_key)?;
    let guardian = parse_public(&g.guardian_public_key)?;
    ensure!(device != guardian, "device and guardian keys must differ");
    Ok(())
}

/// The constructor is private: HTTP callers cannot supply evidence flags.
pub(crate) struct Verified {
    pub request: Request,
    pub evidence: Evidence,
}
pub(crate) fn verify_release(
    trust: &Trust,
    req: &ReleaseRequest,
    record: &CiphertextRecord,
    now: u64,
) -> Result<Verified> {
    verify_before_device(trust, req, record, now)?;
    verify(
        "device-operation",
        &Signed {
            payload: &req.operation,
            signature: req.device_signature.clone(),
        },
        &req.grant.payload.device_public_key,
    )?;
    let o = &req.operation;
    Ok(Verified {
        request: o.request(now),
        evidence: Evidence {
            owner: true,
            oauth: true,
            dpop: true,
            device: true,
            guardian: true,
            bindings: true,
            record: true,
            witness: false,
        },
    })
}

/// Only the trusted broker may call this before asking its device to sign.
/// This result cannot be reached from the HTTP gate without verify_release.
pub(crate) fn verify_before_device(
    trust: &Trust,
    req: &ReleaseRequest,
    record: &CiphertextRecord,
    now: u64,
) -> Result<()> {
    validate_grant(trust, &req.grant)?;
    let g = &req.grant.payload;
    let o = &req.operation;
    let grant_hash = object_hash(&req.grant)?;
    ensure!(
        vault_policy::wire::operation_matches_grant(g, o, &trust.vault, &grant_hash),
        "grant/resource/action/execution binding"
    );
    ensure!(
        vault_policy::wire::operation_current(g, o, now, MAX_REQUEST_LIFETIME),
        "grant time binding and request lifetime"
    );
    fixed::<32>(&o.nonce)?;
    ensure!(
        vault_policy::wire::record_matches_grant(g, &record.context, &object_hash(record)?),
        "record binding"
    );
    let at = verified_access_claims(trust, &req.access_token)?;
    ensure!(
        vault_policy::wire::oauth_matches_grant(trust, g, o, &at, now),
        "OAuth binding, scope or expiry"
    );
    let (dpop, jwk): (DpopClaims, _) = jwt_parts(&req.dpop, "dpop+jwt", None)?;
    let jwk = jwk.context("missing JWK")?;
    let endpoint = match o.action {
        Action::Read => "release",
        Action::Issue => "issue",
    };
    let proof = vault_policy::wire::ProofContext {
        actual_key: &jwk.verifying_key()?,
        device_key: &parse_public(&g.device_public_key)?,
        guardian_key: &parse_public(&g.guardian_public_key)?,
        thumbprint: &jwk.thumbprint()?,
        method: &"POST".to_owned(),
        target: &format!("{}/v1/{endpoint}", trust.audience),
        token_hash: &digest(req.access_token.as_bytes()),
    };
    ensure!(
        vault_policy::wire::dpop_matches_request(
            g,
            o,
            &at,
            &dpop,
            &proof,
            now,
            MAX_REQUEST_LIFETIME
        ),
        "DPoP binding or freshness"
    );
    verify(
        "guardian-operation",
        &Signed {
            payload: o,
            signature: req.guardian_signature.clone(),
        },
        &g.guardian_public_key,
    )?;
    Ok(())
}

/// The broker uses the same pinned issuer verification before calculating expiry.
pub(crate) fn verified_access_claims(trust: &Trust, token: &str) -> Result<AccessClaims> {
    Ok(jwt_parts(token, "at+jwt", Some(&trust.issuer_public_key))?.0)
}
