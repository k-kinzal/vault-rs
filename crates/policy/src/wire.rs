//! Wire field shapes and authorization predicates shared by the service and proofs.

use crate::request_period;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(deny_unknown_fields))]
pub struct Trust<I, D> {
    pub vault: I,
    pub audience: D,
    pub issuer: D,
    pub issuer_public_key: D,
    pub owner_public_key: D,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(rename_all = "snake_case"))]
pub enum Action {
    Read,
    Issue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(deny_unknown_fields))]
pub struct Grant<I, D, Q> {
    pub vault: I,
    pub id: I,
    pub subject: D,
    pub resource: I,
    pub version: u64,
    pub record_hash: D,
    pub action: Action,
    pub issue: Q,
    pub epoch: u64,
    pub not_before: u64,
    pub expires: u64,
    pub uses: u64,
    pub dpop_thumbprint: D,
    pub device_public_key: D,
    pub guardian_public_key: D,
    pub recipient: D,
    pub instance: I,
    pub artifact_hash: D,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(deny_unknown_fields))]
pub struct Operation<I, D, Q> {
    pub vault: I,
    pub grant: I,
    pub grant_hash: D,
    pub resource: I,
    pub version: u64,
    pub record_hash: D,
    pub action: Action,
    pub issue: Q,
    pub epoch: u64,
    pub sequence: u64,
    pub nonce: D,
    pub not_before: u64,
    pub expires: u64,
    pub recipient: D,
    pub instance: I,
    pub artifact_hash: D,
    pub access_token_hash: D,
}

impl<I, D, Q> Operation<I, D, Q> {
    pub fn request(&self, now: u64) -> crate::Request {
        crate::Request {
            epoch: self.epoch,
            sequence: self.sequence,
            not_before: self.not_before,
            expires: self.expires,
            now,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(deny_unknown_fields))]
pub struct Challenge<I, D> {
    pub grant: I,
    pub sequence: u64,
    pub nonce: D,
    pub expires: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(deny_unknown_fields))]
pub struct RecordContext<I> {
    pub vault: I,
    pub resource: I,
    pub version: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(deny_unknown_fields))]
pub struct Confirmation<D> {
    pub jkt: D,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
pub struct AccessClaims<I, D, S> {
    pub iss: D,
    pub aud: D,
    pub sub: D,
    pub exp: u64,
    pub nbf: u64,
    pub scope: S,
    pub grant_id: I,
    pub cnf: Confirmation<D>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(deny_unknown_fields))]
pub struct DpopClaims<D, J> {
    pub jti: J,
    pub htm: D,
    pub htu: D,
    pub iat: u64,
    pub ath: D,
    pub nonce: D,
}

pub fn operation_matches_grant<I: Eq, D: Eq, Q: Eq>(
    g: &Grant<I, D, Q>,
    o: &Operation<I, D, Q>,
    vault: &I,
    grant_hash: &D,
) -> bool {
    &g.vault == vault
        && &o.vault == vault
        && o.grant == g.id
        && &o.grant_hash == grant_hash
        && o.resource == g.resource
        && o.version == g.version
        && o.record_hash == g.record_hash
        && o.action == g.action
        && o.issue == g.issue
        && o.epoch == g.epoch
        && o.instance == g.instance
        && o.artifact_hash == g.artifact_hash
        && o.recipient == g.recipient
}

pub fn record_matches_grant<I: Eq, D: Eq, Q>(
    g: &Grant<I, D, Q>,
    record: &RecordContext<I>,
    hash: &D,
) -> bool {
    &g.record_hash == hash
        && record.vault == g.vault
        && record.resource == g.resource
        && record.version == g.version
}

pub fn challenge_allows<I: Eq, D: Eq, Q>(
    challenge: &Challenge<I, D>,
    operation: &Operation<I, D, Q>,
    now: u64,
) -> bool {
    challenge.grant == operation.grant
        && challenge.nonce == operation.nonce
        && challenge.sequence == operation.sequence
        && now < challenge.expires
        && operation.expires <= challenge.expires
}

/// Values retained by the broker for one measured launch. The proof compares
/// Grant fields directly; there is no second manually mapped Grant projection.
pub struct Execution<'a, I, D> {
    pub instance: &'a I,
    pub recipient: &'a D,
    pub artifact: &'a D,
    pub subject: &'a D,
    pub dpop_thumbprint: &'a D,
    pub device: &'a D,
}
pub fn execution_matches<I: Eq, D: Eq, Q>(g: &Grant<I, D, Q>, e: &Execution<'_, I, D>) -> bool {
    &g.instance == e.instance
        && &g.recipient == e.recipient
        && &g.artifact_hash == e.artifact
        && &g.subject == e.subject
        && &g.dpop_thumbprint == e.dpop_thumbprint
        && &g.device_public_key == e.device
}

/// RFC 6749's ASCII scope-token grammar, bounded to 256 bytes. Private bits can
/// only be produced by this actual parser; unknown scopes grant no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeSet(u8);
impl ScopeSet {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > 256 {
            return None;
        }
        let mut mask = 0;
        let mut length = 0u8;
        let mut read = true;
        let mut issue = true;
        for &b in bytes {
            if b == b' ' {
                if length == 0 {
                    return None;
                }
                if read && length == 11 {
                    mask |= 1;
                }
                if issue && length == 12 {
                    mask |= 2;
                }
                length = 0;
                read = true;
                issue = true;
            } else {
                if !(b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)) {
                    return None;
                }
                read = read && b"secret:read".get(usize::from(length)) == Some(&b);
                issue = issue && b"secret:issue".get(usize::from(length)) == Some(&b);
                // Beyond 12 bytes neither recognized scope can match.
                length = length.saturating_add(1).min(13);
            }
        }
        if length == 0 {
            return None;
        }
        if read && length == 11 {
            mask |= 1;
        }
        if issue && length == 12 {
            mask |= 2;
        }
        Some(Self(mask))
    }
    pub fn allows(self, action: Action) -> bool {
        self.0
            & match action {
                Action::Read => 1,
                Action::Issue => 2,
            }
            != 0
    }
}

pub fn oauth_matches_grant<I: Eq, D: Eq, Q, S: AsRef<[u8]>>(
    trust: &Trust<I, D>,
    grant: &Grant<I, D, Q>,
    operation: &Operation<I, D, Q>,
    token: &AccessClaims<I, D, S>,
    now: u64,
) -> bool {
    token.iss == trust.issuer
        && token.aud == trust.audience
        && token.sub == grant.subject
        && token.grant_id == grant.id
        && token.nbf <= now
        && now < token.exp
        && operation.expires <= token.exp
        && ScopeSet::parse(token.scope.as_ref()).is_some_and(|s| s.allows(grant.action))
}

pub struct ProofContext<'a, D, K> {
    pub actual_key: &'a K,
    pub device_key: &'a K,
    pub guardian_key: &'a K,
    pub thumbprint: &'a D,
    pub method: &'a D,
    pub target: &'a D,
    pub token_hash: &'a D,
}
pub fn dpop_matches_request<I, D: Eq, Q, S, J: AsRef<[u8]>, K: Eq>(
    grant: &Grant<I, D, Q>,
    operation: &Operation<I, D, Q>,
    token: &AccessClaims<I, D, S>,
    proof: &DpopClaims<D, J>,
    c: &ProofContext<'_, D, K>,
    now: u64,
    max: u64,
) -> bool {
    token.cnf.jkt == grant.dpop_thumbprint
        && &token.cnf.jkt == c.thumbprint
        && c.actual_key != c.device_key
        && c.actual_key != c.guardian_key
        && &proof.htm == c.method
        && &proof.htu == c.target
        && &proof.ath == c.token_hash
        && &operation.access_token_hash == c.token_hash
        && proof.nonce == operation.nonce
        && proof.iat <= now
        && now - proof.iat <= max
        && !proof.jti.as_ref().is_empty()
        && proof.jti.as_ref().len() <= 128
}

pub fn operation_current<I, D, Q>(
    g: &Grant<I, D, Q>,
    o: &Operation<I, D, Q>,
    now: u64,
    max: u64,
) -> bool {
    request_period(g.not_before, g.expires, o.not_before, o.expires, now, max)
}
pub fn bounded_expiry(now: u64, grant: u64, challenge: u64, token: u64, max: u64) -> Option<u64> {
    let end = now.checked_add(max)?.min(grant).min(challenge).min(token);
    if now < end {
        Some(end)
    } else {
        None
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    type G = Grant<u128, u128, u128>;
    type O = Operation<u128, u128, u128>;
    #[kani::proof]
    fn actual_request_projection_preserves_every_field() {
        let o: O = kani::any();
        let now = kani::any();
        let r = o.request(now);
        assert_eq!(
            (r.epoch, r.sequence, r.not_before, r.expires, r.now),
            (o.epoch, o.sequence, o.not_before, o.expires, now)
        );
    }
    #[kani::proof]
    fn actual_wire_mapping_refines_owner_binding() {
        let g: G = kani::any();
        let o: O = kani::any();
        let vault = kani::any();
        let hash = kani::any();
        let spec = g.vault == vault
            && (
                o.vault,
                o.grant,
                o.grant_hash,
                o.resource,
                o.version,
                o.record_hash,
                o.action,
                o.issue,
                o.epoch,
                (o.instance, o.artifact_hash, o.recipient),
            ) == (
                vault,
                g.id,
                hash,
                g.resource,
                g.version,
                g.record_hash,
                g.action,
                g.issue,
                g.epoch,
                (g.instance, g.artifact_hash, g.recipient),
            );
        assert_eq!(operation_matches_grant(&g, &o, &vault, &hash), spec);
    }
    #[kani::proof]
    fn actual_record_and_challenge_binding_are_complete() {
        let g: G = kani::any();
        let o: O = kani::any();
        let record = kani::any();
        let hash = kani::any();
        let c: Challenge<u128, u128> = kani::any();
        let now = kani::any();
        assert_eq!(
            record_matches_grant(&g, &record, &hash),
            (record, hash)
                == (
                    RecordContext {
                        vault: g.vault,
                        resource: g.resource,
                        version: g.version
                    },
                    g.record_hash
                )
        );
        assert_eq!(
            challenge_allows(&c, &o, now),
            (c.grant, c.nonce, c.sequence) == (o.grant, o.nonce, o.sequence)
                && now < c.expires
                && o.expires <= c.expires
        );
    }
    #[kani::proof]
    fn actual_execution_binding_is_complete() {
        let g: G = kani::any();
        let values: [u128; 6] = kani::any();
        let e = Execution {
            instance: &values[0],
            recipient: &values[1],
            artifact: &values[2],
            subject: &values[3],
            dpop_thumbprint: &values[4],
            device: &values[5],
        };
        assert_eq!(
            execution_matches(&g, &e),
            [
                g.instance,
                g.recipient,
                g.artifact_hash,
                g.subject,
                g.dpop_thumbprint,
                g.device_public_key
            ] == values
        );
    }
    // Independent trie recognizer: scalar prefix states, not the production
    // parser's two arrays/length/prefix booleans. All 256 bytes remain symbolic.
    fn scope_reference(bytes: &[u8]) -> Option<u8> {
        let mut state = 0u8;
        let mut mask = 0;
        for &b in bytes {
            if b == 32 {
                if state == 0 {
                    return None;
                }
                if state == 11 {
                    mask |= 1;
                }
                if state == 16 {
                    mask |= 2;
                }
                state = 0;
            } else {
                if !(b == 33 || (35..=91).contains(&b) || (93..=126).contains(&b)) {
                    return None;
                }
                state = match (state, b) {
                    (0, b's') => 1,
                    (1, b'e') => 2,
                    (2, b'c') => 3,
                    (3, b'r') => 4,
                    (4, b'e') => 5,
                    (5, b't') => 6,
                    (6, b':') => 7,
                    (7, b'r') => 8,
                    (8, b'e') => 9,
                    (9, b'a') => 10,
                    (10, b'd') => 11,
                    (7, b'i') => 12,
                    (12, b's') => 13,
                    (13, b's') => 14,
                    (14, b'u') => 15,
                    (15, b'e') => 16,
                    _ => 17,
                };
            }
        }
        if state == 0 {
            return None;
        }
        if state == 11 {
            mask |= 1;
        }
        if state == 16 {
            mask |= 2;
        }
        Some(mask)
    }
    fn scope_equivalence(part: u8) {
        let input: [u8; 256] = kani::any();
        let length: u16 = kani::any();
        kani::assume(length <= 256);
        let bytes = &input[..length as usize];
        let expected = scope_reference(bytes);
        let actual = ScopeSet::parse(bytes);
        if part == 0 {
            assert_eq!(actual.is_some(), expected.is_some());
        }
        if let (Some(actual), Some(expected)) = (actual, expected) {
            if part == 1 {
                assert_eq!(actual.allows(Action::Read), expected & 1 != 0);
            }
            if part == 2 {
                assert_eq!(actual.allows(Action::Issue), expected & 2 != 0);
            }
        }
    }
    #[kani::proof]
    #[kani::unwind(258)]
    fn scope_grammar_matches_whole_token_specification() {
        scope_equivalence(0);
    }
    #[kani::proof]
    #[kani::unwind(258)]
    fn scope_read_matches_whole_token_specification() {
        scope_equivalence(1);
    }
    #[kani::proof]
    #[kani::unwind(258)]
    fn scope_issue_matches_whole_token_specification() {
        scope_equivalence(2);
    }
    #[kani::proof]
    #[kani::unwind(26)]
    fn oauth_claims_refine_scope_subject_audience_and_lifetime() {
        let g: G = kani::any();
        let o: O = kani::any();
        let t: Trust<u128, u128> = kani::any();
        let now = kani::any();
        let at: AccessClaims<u128, u128, u8> = kani::any();
        let scope = match at.scope % 4 {
            0 => b"secret:read".as_slice(),
            1 => b"secret:issue".as_slice(),
            2 => b"secret:read secret:issue".as_slice(),
            _ => b"unrelated".as_slice(),
        };
        let scope_ok = match g.action {
            Action::Read => at.scope % 4 == 0 || at.scope % 4 == 2,
            Action::Issue => at.scope % 4 == 1 || at.scope % 4 == 2,
        };
        let token = AccessClaims {
            iss: at.iss,
            aud: at.aud,
            sub: at.sub,
            exp: at.exp,
            nbf: at.nbf,
            scope,
            grant_id: at.grant_id,
            cnf: at.cnf,
        };
        let spec = (at.iss, at.aud, at.sub, at.grant_id) == (t.issuer, t.audience, g.subject, g.id)
            && at.nbf <= now
            && now < at.exp
            && o.expires <= at.exp
            && scope_ok;
        assert_eq!(oauth_matches_grant(&t, &g, &o, &token, now), spec);
    }
    #[kani::proof]
    fn dpop_refines_all_bindings_and_freshness() {
        let g: G = kani::any();
        let o: O = kani::any();
        let token: AccessClaims<u128, u128, u8> = kani::any();
        let d: DpopClaims<u128, u8> = kani::any();
        let values: [u128; 7] = kani::any();
        let now: u64 = kani::any();
        let max: u64 = kani::any();
        let len: u8 = kani::any();
        let bytes = [0u8; 255];
        let proof = DpopClaims {
            jti: &bytes[..len as usize],
            htm: d.htm,
            htu: d.htu,
            iat: d.iat,
            ath: d.ath,
            nonce: d.nonce,
        };
        let c = ProofContext {
            actual_key: &values[0],
            device_key: &values[1],
            guardian_key: &values[2],
            thumbprint: &values[3],
            method: &values[4],
            target: &values[5],
            token_hash: &values[6],
        };
        let spec = token.cnf.jkt == g.dpop_thumbprint
            && token.cnf.jkt == values[3]
            && values[0] != values[1]
            && values[0] != values[2]
            && (d.htm, d.htu, d.ath, d.nonce, o.access_token_hash)
                == (values[4], values[5], values[6], o.nonce, values[6])
            && d.iat as u128 <= now as u128
            && now as u128 <= d.iat as u128 + max as u128
            && (1..=128).contains(&len);
        assert_eq!(
            dpop_matches_request(&g, &o, &token, &proof, &c, now, max),
            spec
        );
    }
    #[kani::proof]
    fn expiry_never_exceeds_any_authority() {
        let now: u64 = kani::any();
        let g: u64 = kani::any();
        let c: u64 = kani::any();
        let t: u64 = kani::any();
        let max: u64 = kani::any();
        let result = bounded_expiry(now, g, c, t, max);
        let sum = now as u128 + max as u128;
        let spec = sum.min(g as u128).min(c as u128).min(t as u128);
        assert_eq!(
            result.is_some(),
            sum <= u64::MAX as u128 && spec > now as u128
        );
        if let Some(end) = result {
            assert_eq!(end as u128, spec);
        }
    }
}
