//! Per-run response key stays in this process. This is NOT an OS-isolated Runner.
use crate::{crypto::*, protocol::*, store::ReleaseResponse};
use anyhow::{ensure, Result};
use zeroize::Zeroizing;

pub struct RecipientSession {
    private: RecipientSecret,
    public: String,
}
impl Default for RecipientSession {
    fn default() -> Self {
        Self::new()
    }
}
impl RecipientSession {
    /// Live broker path: recheck the clock after a possibly interactive unwrap.
    /// The explicit-time `open` remains useful to deterministic offline callers.
    pub fn open_current(
        &self,
        trust: &Trust,
        request: &ReleaseRequest,
        response: &ReleaseResponse,
        device: &dyn ShareUnwrapper,
        clock: impl Fn() -> Result<u64>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext = self.open(trust, request, response, device, clock()?)?;
        ensure_current(request, clock()?)?;
        Ok(plaintext)
    }
    /// Obtain the authorized plaintext through the regular E2E gate, then create
    /// a new version under fresh independent keys. Old grants must be revoked;
    /// their signatures cannot authorize this new ciphertext/version.
    pub fn rotate_record(
        &self,
        trust: &Trust,
        request: &ReleaseRequest,
        response: &ReleaseResponse,
        device: &dyn ShareUnwrapper,
        new_keys: (&str, &str),
        now: u64,
    ) -> Result<CiphertextRecord> {
        ensure!(
            request.operation.action == Action::Read,
            "rotation requires an authorized read"
        );
        let plaintext = self.open(trust, request, response, device, now)?;
        let mut context = response.record.context.clone();
        context.version = context
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record version exhausted"))?;
        seal_record(context, &plaintext, new_keys.0, new_keys.1)
    }
    pub fn new() -> Self {
        let (private, public) = recipient_keypair();
        Self { private, public }
    }
    pub fn public_key(&self) -> &str {
        &self.public
    }
    pub fn open_lease(
        &self,
        trust: &Trust,
        request: &ReleaseRequest,
        record: &CiphertextRecord,
        lease: &crate::extension::IssuedLease,
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            request.operation.action == Action::Issue && request.operation.recipient == self.public,
            "wrong issuance recipient"
        );
        verify_release(trust, request, record, now)?;
        let hash = object_hash(&request.operation)?;
        ensure!(lease.id == hash, "lease request binding");
        let plaintext = open_response(&self.private, &hash, &lease.credentials)?;
        #[derive(serde::Deserialize)]
        struct Metadata {
            expires: u64,
        }
        let metadata: Metadata = serde_json::from_slice(&plaintext)?;
        ensure!(
            metadata.expires == lease.expires && now < lease.expires,
            "lease expiry binding"
        );
        Ok(plaintext)
    }
    pub fn open(
        &self,
        trust: &Trust,
        request: &ReleaseRequest,
        response: &ReleaseResponse,
        device: &dyn ShareUnwrapper,
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            request.operation.recipient == self.public,
            "wrong execution recipient"
        );
        // Verify the full authorization again before using the device's hardware.
        verify_release(trust, request, &response.record, now)?;
        let expected = object_hash(&request.operation)?;
        ensure!(
            response.request_hash == expected,
            "response request binding"
        );
        let guardian = open_response(&self.private, &expected, &response.guardian_share)?;
        ensure!(guardian.len() == 32, "invalid guardian share");
        let guardian_array: Zeroizing<[u8; 32]> = Zeroizing::new(guardian.as_slice().try_into()?);
        let device_share = unwrap_share(&response.record, "device", device)?;
        open_record(&response.record, &device_share, &guardian_array)
    }
}

/// Call again immediately before handing plaintext to a workload. Native key UI,
/// network calls, and scheduler pauses must not reuse an earlier time snapshot.
pub fn ensure_current(request: &ReleaseRequest, now: u64) -> Result<()> {
    let g = &request.grant.payload;
    let o = &request.operation;
    ensure!(
        vault_policy::request_period(
            g.not_before,
            g.expires,
            o.not_before,
            o.expires,
            now,
            MAX_REQUEST_LIFETIME
        ),
        "operation expired before plaintext delivery"
    );
    Ok(())
}
