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

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub vault: Uuid,
    pub audience: String,
    pub issuer: String,
    pub issuer_public_key: String,
    pub owner_public_key: String,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Issue,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub vault: Uuid,
    pub id: Uuid,
    pub subject: String,
    pub resource: Uuid,
    pub version: u64,
    pub record_hash: String,
    pub action: Action,
    pub issue: Option<crate::extension::IssueSpec>,
    pub epoch: u64,
    pub not_before: u64,
    pub expires: u64,
    pub uses: u64,
    pub dpop_thumbprint: String,
    pub device_public_key: String,
    pub guardian_public_key: String,
    pub recipient: String,
    pub instance: Uuid,
    pub artifact_hash: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub vault: Uuid,
    pub grant: Uuid,
    pub grant_hash: String,
    pub resource: Uuid,
    pub version: u64,
    pub record_hash: String,
    pub action: Action,
    pub issue: Option<crate::extension::IssueSpec>,
    pub epoch: u64,
    pub sequence: u64,
    pub nonce: String,
    pub not_before: u64,
    pub expires: u64,
    pub recipient: String,
    pub instance: Uuid,
    pub artifact_hash: String,
    pub access_token_hash: String,
}

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

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub grant: Uuid,
    pub sequence: u64,
    pub nonce: String,
    pub expires: u64,
}

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
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub jkt: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: u64,
    pub nbf: u64,
    pub scope: String,
    pub grant_id: Uuid,
    pub cnf: Confirmation,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct DpopClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: u64,
    pub ath: String,
    pub nonce: String,
}

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
        request: Request {
            epoch: o.epoch,
            sequence: o.sequence,
            not_before: o.not_before,
            expires: o.expires,
            now,
        },
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
    let expected = vault_policy::Binding {
        vault: trust.vault,
        grant: g.id,
        grant_hash: grant_hash.as_str(),
        resource: g.resource,
        version: g.version,
        record_hash: g.record_hash.as_str(),
        action: g.action,
        issue: &g.issue,
        epoch: g.epoch,
        instance: g.instance,
        artifact_hash: g.artifact_hash.as_str(),
        recipient: g.recipient.as_str(),
    };
    let actual = vault_policy::Binding {
        vault: o.vault,
        grant: o.grant,
        grant_hash: o.grant_hash.as_str(),
        resource: o.resource,
        version: o.version,
        record_hash: o.record_hash.as_str(),
        action: o.action,
        issue: &o.issue,
        epoch: o.epoch,
        instance: o.instance,
        artifact_hash: o.artifact_hash.as_str(),
        recipient: o.recipient.as_str(),
    };
    ensure!(
        vault_policy::bindings_match(&expected, &actual),
        "grant/resource/action/execution binding"
    );
    ensure!(
        vault_policy::request_period(
            g.not_before,
            g.expires,
            o.not_before,
            o.expires,
            now,
            MAX_REQUEST_LIFETIME
        ),
        "grant time binding and request lifetime"
    );
    ensure!(o.not_before <= now && now < o.expires, "request expired");
    fixed::<32>(&o.nonce)?;
    ensure!(
        object_hash(record)? == g.record_hash
            && record.context.vault == g.vault
            && record.context.resource == g.resource
            && record.context.version == g.version,
        "record binding"
    );
    ensure!(
        o.access_token_hash == digest(req.access_token.as_bytes()),
        "token binding"
    );
    let (at, _): (AccessClaims, _) =
        jwt_parts(&req.access_token, "at+jwt", Some(&trust.issuer_public_key))?;
    ensure!(
        at.iss == trust.issuer
            && at.aud == trust.audience
            && at.sub == g.subject
            && at.grant_id == g.id,
        "OAuth binding"
    );
    ensure!(
        at.nbf <= now && now < at.exp && o.expires <= at.exp,
        "OAuth expired"
    );
    let scope = match g.action {
        Action::Read => "secret:read",
        Action::Issue => "secret:issue",
    };
    ensure!(at.scope.split(' ').any(|s| s == scope), "OAuth scope");
    let (dpop, jwk): (DpopClaims, _) = jwt_parts(&req.dpop, "dpop+jwt", None)?;
    let jwk = jwk.context("missing JWK")?;
    ensure!(
        at.cnf.jkt == jwk.thumbprint()? && at.cnf.jkt == g.dpop_thumbprint,
        "DPoP key binding"
    );
    ensure!(
        jwk.verifying_key()? != parse_public(&g.device_public_key)?
            && jwk.verifying_key()? != parse_public(&g.guardian_public_key)?,
        "independent keys required"
    );
    let endpoint = match o.action {
        Action::Read => "release",
        Action::Issue => "issue",
    };
    ensure!(
        dpop.htm == "POST" && dpop.htu == format!("{}/v1/{endpoint}", trust.audience),
        "DPoP target"
    );
    ensure!(
        dpop.ath == digest(req.access_token.as_bytes()) && dpop.nonce == o.nonce,
        "DPoP token/nonce"
    );
    ensure!(
        dpop.iat <= now
            && now - dpop.iat <= MAX_REQUEST_LIFETIME
            && !dpop.jti.is_empty()
            && dpop.jti.len() <= 128,
        "DPoP freshness"
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
