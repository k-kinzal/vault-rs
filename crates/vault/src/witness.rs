//! A separately administered monotonic witness. Its state is a trust assumption:
//! never restore this database together with the Vault database. See ASSURANCE.
use crate::crypto::*;
use anyhow::{ensure, Result};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path, sync::Mutex, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub revision: u64,
    pub hash: String,
}

pub trait Witness: Send + Sync {
    fn read(&self, key: Uuid) -> Result<Option<Checkpoint>>;
    fn advance(&self, key: Uuid, expected: Option<Checkpoint>, next: Checkpoint) -> Result<()>;
}

/// This object is deliberately NOT exposed by the Vault HTTP API.
pub trait ProofSigner: Send + Sync {
    fn public_key(&self) -> &str;
    fn sign_bytes(&self, message: &[u8]) -> Result<String>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessCommand {
    pub key: Uuid,
    pub expected: Option<Checkpoint>,
    pub next: Option<Checkpoint>,
    pub nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceipt {
    pub command_hash: String,
    pub current: Option<Checkpoint>,
}

pub struct RemoteWitness {
    url: String,
    public_key: String,
    signer: Box<dyn ProofSigner>,
    client: reqwest::blocking::Client,
}
impl RemoteWitness {
    pub fn new(
        url: String,
        public_key: String,
        signer: Box<dyn ProofSigner>,
        ca: Option<&[u8]>,
    ) -> Result<Self> {
        let parsed = reqwest::Url::parse(&url)?;
        ensure!(
            parsed.scheme() == "https"
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "witness requires HTTPS"
        );
        parse_public(&public_key)?;
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true);
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(ca)?);
        }
        Ok(Self {
            url,
            public_key,
            signer,
            client: builder.build()?,
        })
    }
    fn command(
        &self,
        key: Uuid,
        expected: Option<Checkpoint>,
        next: Option<Checkpoint>,
    ) -> Result<Option<Checkpoint>> {
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let payload = WitnessCommand {
            key,
            expected,
            next,
            nonce: encode(&nonce),
        };
        let signed = Signed {
            signature: self
                .signer
                .sign_bytes(&transcript("witness-command", &payload)?)?,
            payload,
        };
        let response = self
            .client
            .post(&self.url)
            .json(&signed)
            .send()?
            .error_for_status()?;
        let mut bytes = Vec::new();
        response.take(16385).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16384, "witness response too large");
        let receipt: Signed<WitnessReceipt> = serde_json::from_slice(&bytes)?;
        verify("witness-receipt", &receipt, &self.public_key)?;
        ensure!(
            receipt.payload.command_hash == object_hash(&signed.payload)?,
            "witness replay/binding"
        );
        Ok(receipt.payload.current)
    }
}
impl Witness for RemoteWitness {
    fn read(&self, key: Uuid) -> Result<Option<Checkpoint>> {
        self.command(key, None, None)
    }
    fn advance(&self, key: Uuid, expected: Option<Checkpoint>, next: Checkpoint) -> Result<()> {
        ensure!(
            self.command(key, expected, Some(next.clone()))? == Some(next),
            "witness CAS failed"
        );
        Ok(())
    }
}

pub struct WitnessAuthority {
    connection: Mutex<crate::storage::Database>,
    operator: String,
    signer: Box<dyn ProofSigner>,
}
impl WitnessAuthority {
    pub fn open(
        path: &Path,
        operator: String,
        signer: Box<dyn ProofSigner>,
        protector: &dyn ShareUnwrapper,
    ) -> Result<Self> {
        parse_public(&operator)?;
        let connection = crate::storage::open(path, protector)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS checkpoints (id TEXT PRIMARY KEY, body TEXT NOT NULL);")?;
        Ok(Self {
            connection: Mutex::new(connection),
            operator,
            signer,
        })
    }
    pub fn execute(&self, command: Signed<WitnessCommand>) -> Result<Signed<WitnessReceipt>> {
        verify("witness-command", &command, &self.operator)?;
        fixed::<32>(&command.payload.nonce)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("witness poisoned"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT body FROM checkpoints WHERE id=?1",
                [command.payload.key.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        let current: Option<Checkpoint> = old.map(|b| serde_json::from_str(&b)).transpose()?;
        let current = if let Some(next) = &command.payload.next {
            ensure!(current == command.payload.expected, "witness conflict");
            fixed::<32>(&next.hash)?;
            let revision = match &current {
                Some(c) => c
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("revision exhausted"))?,
                None => 0,
            };
            ensure!(next.revision == revision, "non-monotonic checkpoint");
            tx.execute("INSERT INTO checkpoints(id,body) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET body=excluded.body",params![command.payload.key.to_string(),serde_json::to_string(next)?])?;
            Some(next.clone())
        } else {
            ensure!(command.payload.expected.is_none(), "invalid read");
            current
        };
        tx.commit()?;
        let payload = WitnessReceipt {
            command_hash: object_hash(&command.payload)?,
            current,
        };
        Ok(Signed {
            signature: self
                .signer
                .sign_bytes(&transcript("witness-receipt", &payload)?)?,
            payload,
        })
    }
}
