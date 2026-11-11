//! Extensions propose a typed role request. They never receive issuer credentials.
use crate::crypto::*;
use anyhow::{ensure, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr, sync::Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssueSpec {
    pub provider: String,
    pub role: String,
    pub ttl_seconds: u32,
}

/// Trusted host policy. An extension cannot add SQL, network targets, or grants.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPolicy {
    pub provider: String,
    pub role: String,
    pub max_ttl_seconds: u32,
}
pub fn validate_proposal(policy: &ProviderPolicy, proposal: &IssueSpec) -> Result<()> {
    ensure!(
        proposal.provider == policy.provider && proposal.role == policy.role,
        "extension exceeded role scope"
    );
    ensure!(
        proposal.ttl_seconds > 0 && proposal.ttl_seconds <= policy.max_ttl_seconds,
        "extension exceeded TTL"
    );
    ensure!(valid_identifier(&policy.role), "invalid role identifier");
    Ok(())
}
fn valid_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

// Persisted only inside the witness-authenticated ledger. Not a public capability.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredIssue {
    pub id: String,
    pub grant: Uuid,
    pub spec: IssueSpec,
    pub recipient: String,
    pub authorized_at: u64,
    pub valid_until: u64,
}
/// Opaque capability; deliberately does NOT implement Deserialize or expose a
/// constructor. Only Gate can mint this after durable authorization.
#[derive(Clone)]
pub struct CommittedIssue {
    pub(crate) inner: StoredIssue,
}
impl CommittedIssue {
    pub fn id(&self) -> &str {
        &self.inner.id
    }
    pub fn grant(&self) -> Uuid {
        self.inner.grant
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct IssuedLease {
    pub id: String,
    pub expires: u64,
    pub credentials: SealedResponse,
}

pub trait Issuer: Send + Sync {
    fn issue(&self, permit: &CommittedIssue, now: u64) -> Result<IssuedLease>;
    fn revoke(&self, id: &str) -> Result<()>;
    fn revoke_grant(&self, grant: Uuid) -> Result<()>;
    fn expire(&self, now: u64) -> Result<usize>;
}

/// Trusted adapter; untrusted extensions only submit IssueSpec proposals.
/// The target DB principal must have the minimal role-issuance permissions.
pub struct PostgresIssuer {
    client: Mutex<postgres::Client>,
    policy: ProviderPolicy,
}
impl PostgresIssuer {
    pub fn connect(connection: &str, ca: Option<&Path>, policy: ProviderPolicy) -> Result<Self> {
        ensure!(
            valid_identifier(&policy.role) && policy.max_ttl_seconds > 0,
            "invalid provider policy"
        );
        let mut ssl = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;
        if let Some(ca) = ca {
            ssl.set_ca_file(ca)?;
        }
        ssl.set_verify(openssl::ssl::SslVerifyMode::PEER);
        let tls = postgres_openssl::MakeTlsConnector::new(ssl.build());
        let mut cfg = postgres::Config::from_str(connection)?;
        cfg.ssl_mode(postgres::config::SslMode::Require);
        let mut client = cfg.connect(tls)?;
        // Explicit initialization; adapter never accepts SQL or database targets
        // from an extension or an OAuth client.
        client.batch_execute("CREATE SCHEMA IF NOT EXISTS vault_issuer; CREATE TABLE IF NOT EXISTS vault_issuer.leases (id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, username TEXT UNIQUE NOT NULL, expires BIGINT NOT NULL, response TEXT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, cleanup_pending BOOLEAN NOT NULL DEFAULT TRUE)")?;
        Ok(Self {
            client: Mutex::new(client),
            policy,
        })
    }
}
impl Issuer for PostgresIssuer {
    fn issue(&self, permit: &CommittedIssue, now: u64) -> Result<IssuedLease> {
        let p = &permit.inner;
        validate_proposal(&self.policy, &p.spec)?;
        ensure!(
            now >= p.authorized_at && now < p.valid_until,
            "issuance authorization expired"
        );
        let expires = p
            .authorized_at
            .checked_add(p.spec.ttl_seconds as u64)
            .ok_or_else(|| anyhow::anyhow!("expiry overflow"))?;
        ensure!(
            now < expires && expires <= i64::MAX as u64,
            "invalid lease expiry"
        );
        let id_bytes = fixed::<32>(&p.id)?;
        let lock_id = i64::from_be_bytes(id_bytes[..8].try_into()?);
        let username = format!("vr_{}", hex::encode(&id_bytes[..12]));
        let mut client = self
            .client
            .lock()
            .map_err(|_| anyhow::anyhow!("issuer poisoned"))?;
        let mut tx = client.transaction()?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_id])?;
        if let Some(row) = tx.query_opt(
            "SELECT response,revoked,expires FROM vault_issuer.leases WHERE id=$1",
            &[&p.id],
        )? {
            ensure!(
                !row.get::<_, bool>(1) && row.get::<_, i64>(2) > now as i64,
                "lease is terminal"
            );
            return Ok(serde_json::from_str(&row.get::<_, String>(0))?);
        }
        let mut entropy = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(entropy.as_mut());
        let password = Zeroizing::new(encode(entropy.as_ref()));
        let expiry: String = tx
            .query_one(
                "SELECT to_char(to_timestamp($1),'YYYY-MM-DD HH24:MI:SSOF')",
                &[&(expires as f64)],
            )?
            .get(0);
        // username/role are validated identifiers; password is generated base64url;
        // timestamp comes from the server. No extension-controlled SQL is accepted.
        let sql=Zeroizing::new(format!("CREATE ROLE \"{}\" LOGIN PASSWORD '{}' VALID UNTIL '{}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT \"{}\" TO \"{}\"",username,password.as_str(),expiry,self.policy.role,username));
        tx.batch_execute(&sql)?;
        #[derive(Serialize)]
        struct Credential<'a> {
            username: &'a str,
            password: &'a str,
            expires: u64,
        }
        let plaintext = Zeroizing::new(serde_json::to_vec(&Credential {
            username: &username,
            password: &password,
            expires,
        })?);
        let lease = IssuedLease {
            id: p.id.clone(),
            expires,
            credentials: seal_response(&p.recipient, &p.id, &plaintext)?,
        };
        tx.execute("INSERT INTO vault_issuer.leases(id,grant_id,username,expires,response) VALUES($1,$2,$3,$4,$5)",&[&p.id,&p.grant.to_string(),&username,&(expires as i64),&serde_json::to_string(&lease)?])?;
        tx.commit()?;
        Ok(lease)
    }
    fn revoke(&self, id: &str) -> Result<()> {
        fixed::<32>(id)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| anyhow::anyhow!("issuer poisoned"))?;
        let mut tx = client.transaction()?;
        let username = if let Some(row) = tx.query_opt(
            "SELECT username,revoked,cleanup_pending FROM vault_issuer.leases WHERE id=$1 FOR UPDATE",
            &[&id],
        )? {
            if row.get::<_, bool>(1) && !row.get::<_, bool>(2) {
                return Ok(());
            }
            let username: String = row.get(0);
            ensure!(
                username.starts_with("vr_") && valid_identifier(&username),
                "invalid stored username"
            );
            if !row.get::<_, bool>(1) {
                tx.batch_execute(&format!("ALTER ROLE \"{username}\" NOLOGIN"))?;
            }
            tx.execute(
                "UPDATE vault_issuer.leases SET revoked=TRUE WHERE id=$1",
                &[&id],
            )?;
            Some(username)
        } else { None };
        // Publish NOLOGIN before terminating sessions. Holding it uncommitted
        // until DROP would allow fresh logins between termination and commit.
        tx.commit()?;
        if let Some(username) = username {
            client.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()",&[&username])?;
            client.batch_execute(&format!("DROP ROLE IF EXISTS \"{username}\""))?;
            client.execute(
                "UPDATE vault_issuer.leases SET cleanup_pending=FALSE WHERE id=$1",
                &[&id],
            )?;
        }
        Ok(())
    }
    fn revoke_grant(&self, grant: Uuid) -> Result<()> {
        let ids: Vec<String> = {
            let mut client = self
                .client
                .lock()
                .map_err(|_| anyhow::anyhow!("issuer poisoned"))?;
            client
                .query(
                    "SELECT id FROM vault_issuer.leases WHERE grant_id=$1 AND (NOT revoked OR cleanup_pending)",
                    &[&grant.to_string()],
                )?
                .iter()
                .map(|r| r.get(0))
                .collect()
        };
        for id in ids {
            self.revoke(&id)?;
        }
        Ok(())
    }
    fn expire(&self, now: u64) -> Result<usize> {
        ensure!(now <= i64::MAX as u64, "clock out of range");
        let ids: Vec<String> = {
            let mut client = self
                .client
                .lock()
                .map_err(|_| anyhow::anyhow!("issuer poisoned"))?;
            client
                .query(
                    "SELECT id FROM vault_issuer.leases WHERE (expires<=$1 AND NOT revoked) OR (revoked AND cleanup_pending)",
                    &[&(now as i64)],
                )?
                .iter()
                .map(|r| r.get(0))
                .collect()
        };
        for id in &ids {
            self.revoke(id)?;
        }
        Ok(ids.len())
    }
}
