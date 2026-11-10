use crate::extension::{CommittedIssue, StoredIssue};
use crate::{
    crypto::*,
    protocol::*,
    witness::{Checkpoint, Witness},
};
use anyhow::{ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
use vault_policy::{Committed, State};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    grant_hash: String,
    #[serde(flatten)]
    state: State,
    challenge: Option<Challenge>,
    pending: Option<StoredIssue>,
    last_issue: Option<String>,
}
impl std::ops::Deref for Ledger {
    type Target = State;
    fn deref(&self) -> &State {
        &self.state
    }
}
impl std::ops::DerefMut for Ledger {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.state
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    revision: u64,
    ledger: Ledger,
}
impl Stored {
    fn checkpoint(&self) -> Result<Checkpoint> {
        Ok(Checkpoint {
            revision: self.revision,
            hash: object_hash(&self.ledger)?,
        })
    }
}

pub struct Gate {
    db: Mutex<crate::storage::Database>,
    trust: Trust,
    witness: Arc<dyn Witness>,
    unwrapper: Arc<dyn ShareUnwrapper>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ReleaseResponse {
    pub request_hash: String,
    pub record: CiphertextRecord,
    pub guardian_share: SealedResponse,
}

impl Gate {
    pub fn open(
        path: &Path,
        trust: Trust,
        witness: Arc<dyn Witness>,
        unwrapper: Arc<dyn ShareUnwrapper>,
    ) -> Result<Self> {
        Self::open_generation(path, trust, witness, unwrapper, None)
    }
    pub fn open_pinned(
        path: &Path,
        trust: Trust,
        witness: Arc<dyn Witness>,
        unwrapper: Arc<dyn ShareUnwrapper>,
        generation: &str,
    ) -> Result<Self> {
        Self::open_generation(path, trust, witness, unwrapper, Some(generation))
    }
    fn open_generation(
        path: &Path,
        trust: Trust,
        witness: Arc<dyn Witness>,
        unwrapper: Arc<dyn ShareUnwrapper>,
        generation: Option<&str>,
    ) -> Result<Self> {
        parse_public(&trust.owner_public_key)?;
        parse_public(&trust.issuer_public_key)?;
        let audience = reqwest::Url::parse(&trust.audience)?;
        ensure!(
            audience.scheme() == "https"
                && audience.username().is_empty()
                && audience.password().is_none()
                && audience.query().is_none()
                && audience.fragment().is_none()
                && audience.path() == "/"
                && !trust.audience.ends_with('/'),
            "audience must be an HTTPS origin without trailing slash"
        );
        let db = match generation {
            Some(pin) => crate::storage::open_pinned(path, unwrapper.as_ref(), pin)?,
            None => crate::storage::open(path, unwrapper.as_ref())?,
        };
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS records (hash TEXT PRIMARY KEY, body TEXT NOT NULL);")?;
        Ok(Self {
            db: Mutex::new(db),
            trust,
            witness,
            unwrapper,
        })
    }
    pub fn install(&self, grant: &Signed<Grant>, record: &CiphertextRecord) -> Result<()> {
        validate_grant(&self.trust, grant)?;
        ensure!(
            vault_policy::wire::record_matches_grant(
                &grant.payload,
                &record.context,
                &object_hash(record)?
            ),
            "record context or hash mismatch"
        );
        ensure!(
            record.guardian_key == wrapping_key_hash(self.unwrapper.public_key())?,
            "wrong guardian encryption key"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM grants WHERE id=?1)",
            [grant.payload.id.to_string()],
            |r| r.get(0),
        )?;
        ensure!(
            !exists && self.witness.read(grant.payload.id)?.is_none(),
            "grant ID cannot be reused"
        );
        let stored = Stored {
            revision: 0,
            ledger: Ledger {
                grant_hash: object_hash(grant)?,
                state: State {
                    epoch: grant.payload.epoch,
                    next: 0,
                    remaining: grant.payload.uses,
                    revoked: false,
                    locked: false,
                },
                challenge: None,
                pending: None,
                last_issue: None,
            },
        };
        self.witness
            .advance(grant.payload.id, None, stored.checkpoint()?)?;
        tx.execute(
            "INSERT INTO grants(id,body) VALUES(?1,?2)",
            params![
                grant.payload.id.to_string(),
                serde_json::to_string(&stored)?
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO records(hash,body) VALUES(?1,?2)",
            params![grant.payload.record_hash, serde_json::to_string(record)?],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn load(&self, tx: &Transaction<'_>, id: Uuid) -> Result<Stored> {
        let body: String = tx
            .query_row(
                "SELECT body FROM grants WHERE id=?1",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .context("unknown grant")?;
        let stored: Stored = serde_json::from_str(&body)?;
        ensure!(
            self.witness.read(id)? == Some(stored.checkpoint()?),
            "checkpoint mismatch: possible rollback or incomplete commit; fail closed"
        );
        Ok(stored)
    }
    fn commit(&self, tx: Transaction<'_>, id: Uuid, old: Checkpoint, ledger: Ledger) -> Result<()> {
        let stored = Stored {
            revision: old.revision.checked_add(1).context("revision exhausted")?,
            ledger,
        };
        // Witness first. If SQLite commit subsequently fails, no result is released.
        // The mismatch on restart is deliberately unrecoverable without owner action.
        vault_policy::ordered_commit(
            || self.witness.advance(id, Some(old), stored.checkpoint()?),
            || {
                tx.execute(
                    "UPDATE grants SET body=?2 WHERE id=?1",
                    params![id.to_string(), serde_json::to_string(&stored)?],
                )?;
                tx.commit()?;
                Ok(())
            },
        )
    }
    pub fn challenge(&self, grant: &Signed<Grant>, now: u64) -> Result<Challenge> {
        validate_grant(&self.trust, grant)?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = self.load(&tx, grant.payload.id)?;
        let old = stored.checkpoint()?;
        let mut l = stored.ledger;
        ensure!(
            l.grant_hash == object_hash(grant)?
                && !l.revoked
                && !l.locked
                && l.remaining > 0
                && l.pending.is_none(),
            "inactive grant"
        );
        ensure!(
            grant.payload.not_before <= now && now < grant.payload.expires,
            "grant expired"
        );
        if let Some(c) = &l.challenge {
            if now < c.expires {
                return Ok(c.clone());
            }
        }
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let expires = now
            .checked_add(MAX_REQUEST_LIFETIME)
            .context("clock overflow")?
            .min(grant.payload.expires);
        let challenge = Challenge {
            grant: grant.payload.id,
            sequence: l.next,
            nonce: encode(&nonce),
            expires,
        };
        l.challenge = Some(challenge.clone());
        self.commit(tx, grant.payload.id, old, l)?;
        Ok(challenge)
    }
    pub fn revoke(&self, revocation: &Signed<Revocation>) -> Result<()> {
        verify("owner-revoke", revocation, &self.trust.owner_public_key)?;
        ensure!(revocation.payload.vault == self.trust.vault, "wrong vault");
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = self.load(&tx, revocation.payload.grant)?;
        let old = stored.checkpoint()?;
        let mut l = stored.ledger;
        l.revoked = true;
        l.challenge = None;
        l.pending = None;
        self.commit(tx, revocation.payload.grant, old, l)
    }
    pub fn release(&self, req: &ReleaseRequest, now: u64) -> Result<ReleaseResponse> {
        ensure!(
            req.operation.action == Action::Read,
            "wrong operation endpoint"
        );
        self.authorize(req, now, None)?.release(|record| {
            let share = unwrap_share(&record, "guardian", self.unwrapper.as_ref())?;
            let request_hash = object_hash(&req.operation)?;
            let guardian_share =
                seal_response(&req.operation.recipient, &request_hash, share.as_ref())?;
            Ok(ReleaseResponse {
                request_hash,
                record,
                guardian_share,
            })
        })
    }
    pub fn checkpoint(&self, grant: &Signed<Grant>) -> Result<Checkpoint> {
        validate_grant(&self.trust, grant)?;
        self.witness
            .read(grant.payload.id)?
            .context("unknown independent checkpoint")
    }
    /// Recovery from an interrupted witness->database commit burns all remaining
    /// authority. A new grant must be approved separately under a never-used ID.
    pub fn quarantine(&self, request: &Signed<Quarantine>) -> Result<()> {
        verify("owner-quarantine", request, &self.trust.owner_public_key)?;
        ensure!(request.payload.vault == self.trust.vault, "wrong vault");
        let q = &request.payload;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            self.witness.read(q.grant)? == Some(q.expected.clone()),
            "checkpoint changed; new owner approval required"
        );
        let terminal = vault_policy::retired();
        let ledger = Ledger {
            grant_hash: object_hash(&("permanently-quarantined", q.grant))?,
            state: terminal,
            challenge: None,
            pending: None,
            last_issue: None,
        };
        let stored = Stored {
            revision: q
                .expected
                .revision
                .checked_add(1)
                .context("revision exhausted")?,
            ledger,
        };
        self.witness
            .advance(q.grant, Some(q.expected.clone()), stored.checkpoint()?)?;
        tx.execute("INSERT INTO grants(id,body) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET body=excluded.body",params![q.grant.to_string(),serde_json::to_string(&stored)?])?;
        tx.commit()?;
        Ok(())
    }
    pub fn prepare_issue(&self, req: &ReleaseRequest, now: u64) -> Result<CommittedIssue> {
        ensure!(
            req.operation.action == Action::Issue,
            "wrong operation endpoint"
        );
        let permit = StoredIssue {
            id: object_hash(&req.operation)?,
            grant: req.operation.grant,
            spec: req
                .operation
                .issue
                .clone()
                .context("missing issue specification")?,
            recipient: req.operation.recipient.clone(),
            authorized_at: now,
            valid_until: req.operation.expires,
        };
        let _committed = self.authorize(req, now, Some(permit.clone()))?;
        Ok(CommittedIssue { inner: permit })
    }
    /// Resume only the identical, still-valid signed request after an interrupted
    /// issuance. No new policy use is consumed, and the issuer remains idempotent.
    pub fn resume_issue(&self, req: &ReleaseRequest, now: u64) -> Result<CommittedIssue> {
        ensure!(
            req.operation.action == Action::Issue,
            "wrong operation endpoint"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let s = self.load(&tx, req.operation.grant)?;
        ensure!(
            !s.ledger.revoked
                && !s.ledger.locked
                && s.ledger.grant_hash == object_hash(&req.grant)?,
            "inactive grant"
        );
        let pending = s.ledger.pending.context("no pending operation")?;
        ensure!(
            pending.id == object_hash(&req.operation)?,
            "different pending operation"
        );
        let body: String = tx.query_row(
            "SELECT body FROM records WHERE hash=?1",
            [&req.grant.payload.record_hash],
            |r| r.get(0),
        )?;
        verify_release(&self.trust, req, &serde_json::from_str(&body)?, now)?;
        Ok(CommittedIssue { inner: pending })
    }
    /// Called only by the trusted worker. Pending work is covered by the witness.
    pub fn pending_issue(&self, id: Uuid) -> Result<Option<CommittedIssue>> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let s = self.load(&tx, id)?;
        ensure!(!s.ledger.revoked && !s.ledger.locked, "inactive grant");
        Ok(s.ledger.pending.map(|inner| CommittedIssue { inner }))
    }
    pub fn complete_issue(&self, permit: &CommittedIssue) -> Result<()> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let s = self.load(&tx, permit.grant())?;
        let checkpoint = s.checkpoint()?;
        let mut l = s.ledger;
        ensure!(!l.revoked && !l.locked, "inactive grant");
        if l.pending.is_none() && l.last_issue.as_deref() == Some(permit.id()) {
            return Ok(());
        }
        ensure!(
            l.pending.as_ref().is_some_and(|p| p.id == permit.id()),
            "pending operation changed"
        );
        l.pending = None;
        l.last_issue = Some(permit.id().to_owned());
        self.commit(tx, permit.grant(), checkpoint, l)
    }
    fn authorize(
        &self,
        req: &ReleaseRequest,
        now: u64,
        pending: Option<StoredIssue>,
    ) -> Result<Committed<CiphertextRecord>> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database poisoned"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = self.load(&tx, req.operation.grant)?;
        let old = stored.checkpoint()?;
        let mut l = stored.ledger;
        ensure!(
            l.grant_hash == object_hash(&req.grant)? && l.pending.is_none(),
            "installed grant mismatch or pending work"
        );
        let body: String = tx.query_row(
            "SELECT body FROM records WHERE hash=?1",
            [&req.grant.payload.record_hash],
            |r| r.get(0),
        )?;
        let record: CiphertextRecord = serde_json::from_str(&body)?;
        let mut verified = verify_release(&self.trust, req, &record, now)?;
        let challenge = l.challenge.as_ref().context("missing challenge")?;
        ensure!(
            vault_policy::wire::challenge_allows(challenge, &req.operation, now),
            "invalid challenge"
        );
        verified.evidence.witness = true;
        vault_policy::authorize_and_commit(l.state, verified.request, verified.evidence, |next| {
            l.state = next;
            l.challenge = None;
            l.pending = pending;
            self.commit(tx, req.operation.grant, old, l)?;
            Ok(record)
        })
        .map_err(|error| match error {
            vault_policy::CommitError::Policy(_) => anyhow::anyhow!("policy denied"),
            vault_policy::CommitError::Storage(e) => e,
        })
    }
}
