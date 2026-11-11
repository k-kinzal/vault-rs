//! Pure decisions used by the SNP key custodian, not a model-only copy.
//! Signature verification, SHA-512, hardware measurements and clock integrity
//! are primitive contracts; these proofs establish the acceptance predicate.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Evidence {
    pub signature_valid: bool,
    pub certificate_valid: bool,
    pub endorsed_tcb_matches: bool,
    pub measurement_matches: bool,
    pub request_matches: bool,
    pub vmpl: u32,
    pub debug: bool,
    pub migration: bool,
    pub smt: bool,
    pub signing_key_is_vcek: bool,
    pub reported_tcb: [u8; 4],
    pub current_tcb: [u8; 4],
    pub committed_tcb: [u8; 4],
    pub launch_tcb: [u8; 4],
}
pub fn tcb_at_least(value: [u8; 4], minimum: [u8; 4]) -> bool {
    value[0] >= minimum[0]
        && value[1] >= minimum[1]
        && value[2] >= minimum[2]
        && value[3] >= minimum[3]
}
pub fn accepted(e: Evidence, minimum: [u8; 4]) -> bool {
    e.signature_valid
        && e.certificate_valid
        && e.endorsed_tcb_matches
        && e.measurement_matches
        && e.request_matches
        && e.vmpl == 0
        && !e.debug
        && !e.migration
        && !e.smt
        && e.signing_key_is_vcek
        && tcb_at_least(e.reported_tcb, minimum)
        && tcb_at_least(e.current_tcb, minimum)
        && tcb_at_least(e.committed_tcb, minimum)
        && tcb_at_least(e.launch_tcb, minimum)
}
pub fn challenge_live(issued: u64, now: u64) -> bool {
    now >= issued && now - issued < 30
}
/// Called on the actual vendor report fields, not an abstract string ID.
pub fn bindings_match(
    measurement: &[u8; 48],
    expected_measurement: &[u8; 48],
    request: &[u8; 64],
    expected_request: &[u8; 64],
    chip: &[u8; 64],
    expected_chip: &[u8; 64],
) -> bool {
    measurement == expected_measurement && request == expected_request && chip == expected_chip
}
#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    #[kani::unwind(5)]
    fn accepted_quote_requires_every_boundary() {
        let e: Evidence = kani::any();
        let minimum: [u8; 4] = kani::any();
        let required = e.signature_valid
            && e.certificate_valid
            && e.endorsed_tcb_matches
            && e.measurement_matches
            && e.request_matches
            && e.vmpl == 0
            && !e.debug
            && !e.migration
            && !e.smt
            && e.signing_key_is_vcek
            && (0..4).all(|i| {
                [e.reported_tcb, e.current_tcb, e.committed_tcb, e.launch_tcb]
                    .iter()
                    .all(|tcb| tcb[i] >= minimum[i])
            });
        assert_eq!(accepted(e, minimum), required);
        if accepted(e, minimum) {
            assert!(e.signature_valid && e.certificate_valid && e.endorsed_tcb_matches);
            assert!(e.measurement_matches && e.request_matches);
            assert!(e.vmpl == 0 && !e.debug && !e.migration && !e.smt);
            assert!(e.signing_key_is_vcek);
            for i in 0..4 {
                assert!(e.reported_tcb[i] >= minimum[i]);
                assert!(e.current_tcb[i] >= minimum[i]);
                assert!(e.committed_tcb[i] >= minimum[i]);
                assert!(e.launch_tcb[i] >= minimum[i]);
            }
        }
    }
    #[kani::proof]
    fn challenge_time_has_no_wraparound_or_future_acceptance() {
        let issued: u64 = kani::any();
        let now: u64 = kani::any();
        assert_eq!(
            challenge_live(issued, now),
            now >= issued && (now as u128) < (issued as u128) + 30
        );
        if challenge_live(issued, now) {
            assert!(now >= issued);
            assert!((now as u128) < (issued as u128) + 30);
        }
    }
    #[kani::proof]
    #[kani::unwind(65)]
    fn actual_snp_bindings_refine_exact_byte_equality() {
        let measurement = kani::any();
        let expected_measurement = kani::any();
        let request = kani::any();
        let expected_request = kani::any();
        let chip = kani::any();
        let expected_chip = kani::any();
        let result = bindings_match(
            &measurement,
            &expected_measurement,
            &request,
            &expected_request,
            &chip,
            &expected_chip,
        );
        assert_eq!(
            result,
            measurement == expected_measurement
                && request == expected_request
                && chip == expected_chip
        );
    }
}
