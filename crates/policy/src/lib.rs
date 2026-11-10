//! The executable reference monitor. No IO, allocations, crypto, clocks, or unsafe.
//! Evidence booleans MUST be supplied by trusted verification, never by a caller.
#![no_std]

/// An abstract refinement boundary: each flag is produced by protocol verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Evidence {
    pub owner: bool,
    pub oauth: bool,
    pub dpop: bool,
    pub device: bool,
    pub guardian: bool,
    pub bindings: bool,
    pub record: bool,
    pub witness: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct State {
    pub epoch: u64,
    pub next: u64,
    pub remaining: u64,
    pub revoked: bool,
    pub locked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Request {
    pub epoch: u64,
    pub sequence: u64,
    pub not_before: u64,
    pub expires: u64,
    pub now: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    Evidence,
    Revoked,
    Locked,
    Epoch,
    Replay,
    Expired,
    Exhausted,
}

/// A non-duplicable result of successful policy and the trusted persist adapter.
/// No Deserialize, Clone, default, public field, or external constructor exists.
///
/// ```compile_fail
/// let forged = vault_policy::Committed { value: "secret" };
/// ```
/// ```compile_fail
/// use vault_policy::*;
/// fn duplicate(capability: Committed<u8>) {
///     capability.release(|_| ());
///     capability.release(|_| ());
/// }
/// ```
#[must_use]
pub struct Committed<T> {
    value: T,
}
impl<T> Committed<T> {
    pub fn release<R>(self, operation: impl FnOnce(T) -> R) -> R {
        operation(self.value)
    }
}
#[derive(Debug)]
pub enum CommitError<E> {
    Policy(Denied),
    Storage(E),
}
pub fn authorize_and_commit<T, E>(
    s: State,
    r: Request,
    e: Evidence,
    persist: impl FnOnce(State) -> Result<T, E>,
) -> Result<Committed<T>, CommitError<E>> {
    let next = consume(s, r, e).map_err(CommitError::Policy)?;
    let value = persist(next).map_err(CommitError::Storage)?;
    Ok(Committed { value })
}
/// The actual adapter invokes both closures synchronously. Hardware disclosure
/// receives Committed<T> only after this ordering succeeds.
pub fn ordered_commit<E>(
    reserve: impl FnOnce() -> Result<(), E>,
    database: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    reserve()?;
    database()
}

/// Returns the next state iff this exact request is authorized. Commit this state
/// durably before releasing any result. A crash may burn a use, never restore it.
pub fn consume(s: State, r: Request, e: Evidence) -> Result<State, Denied> {
    if !(e.owner
        && e.oauth
        && e.dpop
        && e.device
        && e.guardian
        && e.bindings
        && e.record
        && e.witness)
    {
        return Err(Denied::Evidence);
    }
    if s.revoked {
        return Err(Denied::Revoked);
    }
    if s.locked {
        return Err(Denied::Locked);
    }
    if s.epoch != r.epoch {
        return Err(Denied::Epoch);
    }
    if s.next != r.sequence {
        return Err(Denied::Replay);
    }
    if r.now < r.not_before || r.now >= r.expires {
        return Err(Denied::Expired);
    }
    if s.remaining == 0 || s.next == u64::MAX {
        return Err(Denied::Exhausted);
    }
    Ok(State {
        next: s.next + 1,
        remaining: s.remaining - 1,
        ..s
    })
}

/// Revocation is terminal for a grant ID. Reauthorization needs a new ID.
pub fn revoke(s: State) -> State {
    State { revoked: true, ..s }
}

/// Lock/unlock is a trusted administrative operation, never a wire field.
pub fn lock(s: State) -> State {
    State { locked: true, ..s }
}

/// Recovery is permanent retirement, including after an interrupted commit.
pub fn retired() -> State {
    State {
        epoch: 0,
        next: u64::MAX,
        remaining: 0,
        revoked: true,
        locked: true,
    }
}

/// Fields that must match the owner grant before a device or gate may approve.
/// Production instantiates this with UUIDs, strings, Action, and IssueSpec;
/// their equality and conversion from parsed JSON remain explicit assumptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Binding<I, D, A, Q> {
    pub vault: I,
    pub grant: I,
    pub grant_hash: D,
    pub resource: I,
    pub version: u64,
    pub record_hash: D,
    pub action: A,
    pub issue: Q,
    pub epoch: u64,
    pub instance: I,
    pub artifact_hash: D,
    pub recipient: D,
}
pub fn bindings_match<I: Eq, D: Eq, A: Eq, Q: Eq>(
    a: &Binding<I, D, A, Q>,
    b: &Binding<I, D, A, Q>,
) -> bool {
    a.vault == b.vault
        && a.grant == b.grant
        && a.grant_hash == b.grant_hash
        && a.resource == b.resource
        && a.version == b.version
        && a.record_hash == b.record_hash
        && a.action == b.action
        && a.issue == b.issue
        && a.epoch == b.epoch
        && a.instance == b.instance
        && a.artifact_hash == b.artifact_hash
        && a.recipient == b.recipient
}

/// One byte of a 2-of-2 secret split. The caller must supply an independent,
/// uniformly random mask. This exact implementation is also used by crypto.rs.
pub fn mask_byte(secret: u8, mask: u8) -> u8 {
    secret ^ mask
}
pub fn join_byte(first: u8, second: u8) -> u8 {
    first ^ second
}

/// UID allocation is a monotonic witness revision, not a reusable process slot.
/// UID 0 and the AI account are excluded before any child receives a secret.
pub fn worker_uid(base: u32, limit: u32, revision: u64, ai_uid: u32) -> Option<u32> {
    if base < 10_000 || limit > 2_000_000_000 || base >= limit {
        return None;
    }
    let uid = (base as u64).checked_add(revision)?;
    if uid >= limit as u64 || uid == ai_uid as u64 {
        return None;
    }
    Some(uid as u32)
}

/// Exact request lifetime used by the wire verifier, with overflow-safe ordering.
pub fn request_period(
    grant_start: u64,
    grant_end: u64,
    start: u64,
    end: u64,
    now: u64,
    max: u64,
) -> bool {
    start >= grant_start
        && end <= grant_end
        && start < end
        && end - start <= max
        && start <= now
        && now < end
}

/// Release acceptance is a conjunction, never a count/percentage of passing checks.
/// Method bits refer to distinct measured evidence classes, not user preferences.
pub const CRITERIA: usize = 13;
pub const REQUIRED_METHODS: [u32; CRITERIA] = [
    0b11,   // proof + software test
    1 << 2, // OS isolation
    (1 << 1) | (1 << 2),
    1 << 3, // physical hardware (never simulator)
    (1 << 1) | (1 << 3),
    (1 << 0) | (1 << 4),   // proof + fault injection
    1 << 5,                // OAuth AS integration
    1 << 6,                // live deployment parity
    (1 << 7) | (1 << 8),   // sandbox + database
    (1 << 9) | (1 << 10),  // recovery + update
    (1 << 11) | (1 << 12), // implementation refinement + review
    (1 << 0) | (1 << 1),
    (1 << 13) | (1 << 14) | (1 << 12), // audit + reproducible build + review
];
pub fn acceptance_check(index: usize, passed: bool, methods: u32) -> bool {
    acceptance_check_scoped(index, passed, methods, false)
}
/// Only the explicitly excluded physical-device experiment may be replaced by
/// software evidence. OS execution, refinement and review remain mandatory.
pub fn acceptance_check_scoped(
    index: usize,
    passed: bool,
    methods: u32,
    physical_tests_excluded: bool,
) -> bool {
    if index >= CRITERIA {
        return false;
    }
    let required = if physical_tests_excluded && (index == 3 || index == 4) {
        (REQUIRED_METHODS[index] & !(1 << 3)) | (1 << 1)
    } else {
        REQUIRED_METHODS[index]
    };
    index < CRITERIA && passed && methods & !0x7fff == 0 && methods & required == required
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn physical_exclusion_cannot_waive_other_requirements() {
        let index: usize = kani::any();
        let methods: u32 = kani::any();
        let passed: bool = kani::any();
        let excluded: bool = kani::any();
        let result = acceptance_check_scoped(index, passed, methods, excluded);
        if !excluded || (index != 3 && index != 4) {
            assert_eq!(result, acceptance_check(index, passed, methods));
        }
        if result && excluded && (index == 3 || index == 4) {
            assert!(passed && methods & (1 << 1) != 0);
            assert_eq!(methods & !0x7fff, 0);
        }
    }

    #[kani::proof]
    fn implementation_transaction_refines_atomic_disclosure_spec() {
        use core::cell::Cell;
        let state: State = kani::any();
        let request: Request = kani::any();
        let evidence: Evidence = kani::any();
        let witness_success: bool = kani::any();
        let database_success: bool = kani::any();
        let stage = Cell::new(0u8);
        let disclosed = Cell::new(false);
        let result = authorize_and_commit(state, request, evidence, |next| -> Result<State, ()> {
            ordered_commit(
                || {
                    assert_eq!(stage.get(), 0);
                    if !witness_success {
                        return Err(());
                    }
                    stage.set(1);
                    Ok(())
                },
                || {
                    assert_eq!(stage.get(), 1);
                    if !database_success {
                        return Err(());
                    }
                    stage.set(2);
                    Ok(())
                },
            )?;
            Ok(next)
        });
        let expected = allowed(state, request, evidence) && witness_success && database_success;
        assert_eq!(result.is_ok(), expected);
        if let Ok(permit) = result {
            permit.release(|next| {
                assert_eq!(stage.get(), 2);
                assert!(next.remaining < state.remaining && next.next > state.next);
                disclosed.set(true);
            });
        }
        assert_eq!(disclosed.get(), expected);
    }

    #[kani::proof]
    fn all_binding_fields_refine_record_equality() {
        let a: Binding<u128, u128, u8, u128> = kani::any();
        let b = kani::any();
        assert_eq!(bindings_match(&a, &b), a == b);
    }

    #[kani::proof]
    fn recovery_never_restores_authority() {
        assert!(consume(retired(), kani::any(), kani::any()).is_err());
        assert_eq!(retired().remaining, 0);
        assert_eq!(retired().next, u64::MAX);
    }

    #[kani::proof]
    fn production_check_never_accepts_missing_required_evidence() {
        let index: usize = kani::any();
        let passed: bool = kani::any();
        let methods: u32 = kani::any();
        if acceptance_check(index, passed, methods) {
            assert!(index < CRITERIA && passed);
            assert_eq!(methods & REQUIRED_METHODS[index], REQUIRED_METHODS[index]);
        }
        assert!(!acceptance_check(index, false, methods));
        assert!(!acceptance_check(3, true, 1 << 1)); // software/simulator cannot satisfy hardware
    }

    #[kani::proof]
    fn allocated_worker_never_has_broker_or_ai_identity() {
        let base = kani::any();
        let limit = kani::any();
        let rev = kani::any();
        let ai = kani::any();
        if let Some(uid) = worker_uid(base, limit, rev, ai) {
            assert!(uid >= 10_000 && uid < limit && uid != ai && uid != 0);
            assert_eq!(uid as u128, base as u128 + rev as u128);
            if let Some(next) = rev
                .checked_add(1)
                .and_then(|r| worker_uid(base, limit, r, ai))
            {
                assert!(next > uid);
            }
        }
    }
    #[kani::proof]
    fn request_lifetime_refines_mathematical_interval() {
        let gs: u64 = kani::any();
        let ge: u64 = kani::any();
        let s: u64 = kani::any();
        let e: u64 = kani::any();
        let n: u64 = kani::any();
        let max: u64 = kani::any();
        let spec = (gs as u128 <= s as u128)
            && (s as u128 <= n as u128)
            && ((n as u128) < e as u128)
            && (e as u128 <= ge as u128)
            && (e as u128 <= s as u128 + max as u128);
        assert_eq!(request_period(gs, ge, s, e, n, max), spec);
    }

    /// Independent declarative specification; exercised over all bit patterns.
    fn allowed(s: State, r: Request, e: Evidence) -> bool {
        let signatures = [e.owner, e.oauth, e.dpop, e.device, e.guardian];
        let mut valid = true;
        for b in signatures {
            valid &= b;
        }
        valid
            && e.bindings
            && e.record
            && e.witness
            && !s.revoked
            && !s.locked
            && r.epoch == s.epoch
            && r.sequence == s.next
            && r.not_before <= r.now
            && r.now < r.expires
            && s.remaining > 0
            && s.next < u64::MAX
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn implementation_refines_specification() {
        let s: State = kani::any();
        let r: Request = kani::any();
        let e: Evidence = kani::any();
        let result = consume(s, r, e);
        assert_eq!(result.is_ok(), allowed(s, r, e));
        if let Ok(n) = result {
            assert_eq!(n.next as u128, s.next as u128 + 1);
            assert_eq!(n.remaining as u128 + 1, s.remaining as u128);
            assert_eq!(n.epoch, s.epoch);
            assert_eq!(n.revoked, s.revoked);
            assert_eq!(n.locked, s.locked);
        }
    }

    #[kani::proof]
    fn stolen_token_and_dpop_key_are_insufficient() {
        let s = kani::any();
        let r = kani::any();
        let mut e: Evidence = kani::any();
        e.oauth = true;
        e.dpop = true;
        // Attacker may control every other flag; either independent gate suffices.
        kani::assume(!e.device || !e.guardian);
        assert!(consume(s, r, e).is_err());
    }

    #[kani::proof]
    fn replay_after_commit_is_rejected() {
        let s = kani::any();
        let r = kani::any();
        let e = kani::any();
        if let Ok(n) = consume(s, r, e) {
            assert!(consume(n, r, e).is_err());
        }
    }

    #[kani::proof]
    fn revoked_and_locked_states_never_release() {
        let s = kani::any();
        let r = kani::any();
        let e = kani::any();
        assert!(consume(revoke(s), r, e).is_err());
        assert!(consume(lock(s), r, e).is_err());
    }

    #[kani::proof]
    fn stale_epoch_or_missing_witness_never_releases() {
        let s: State = kani::any();
        let r: Request = kani::any();
        let mut e: Evidence = kani::any();
        if s.epoch != r.epoch {
            assert!(consume(s, r, e).is_err());
        }
        e.witness = false;
        assert!(consume(s, r, e).is_err());
    }

    #[kani::proof]
    fn accepted_use_has_strictly_decreasing_budget() {
        let s: State = kani::any();
        if let Ok(n) = consume(s, kani::any(), kani::any()) {
            assert!(n.remaining < s.remaining);
            assert!(n.next > s.next);
        }
    }

    // Perfect 2-of-2 splitting algebra, not a proof of RNG/AEAD/RSA security.
    #[kani::proof]
    fn one_share_is_compatible_with_every_possible_secret_byte() {
        let known: u8 = kani::any();
        let candidate: u8 = kani::any();
        let other = mask_byte(candidate, known);
        assert_eq!(join_byte(known, other), candidate);
        let original: u8 = kani::any();
        let random: u8 = kani::any();
        assert_eq!(join_byte(random, mask_byte(original, random)), original);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legitimate_request_is_not_vacuously_denied() {
        let s = State {
            epoch: 3,
            next: 0,
            remaining: 2,
            revoked: false,
            locked: false,
        };
        let r = Request {
            epoch: 3,
            sequence: 0,
            not_before: 4,
            now: 5,
            expires: 6,
        };
        let e = Evidence {
            owner: true,
            oauth: true,
            dpop: true,
            device: true,
            guardian: true,
            bindings: true,
            record: true,
            witness: true,
        };
        let n = consume(s, r, e).unwrap();
        assert_eq!(n.next, 1);
        assert_eq!(n.remaining, 1);
        assert_eq!(consume(n, r, e), Err(Denied::Replay));
    }
}
