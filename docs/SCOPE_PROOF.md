# Scope parser induction proof

The production parser is `crates/policy/src/scope.rs`. `wire::ScopeSet::parse` calls it and wraps its private mask. The public length limit remains 256 bytes; no byte value or accepted length is removed for proof performance.

The production state P=(mask,length,read,issue) and independent trie state Q=(state,reference_mask) obey relation R: masks are equal and in 0..3, with these prefix cases:

| Trie state | Production fields |
| --- | --- |
| 0..7 | length=state, read=true, issue=true |
| 8..11 | length=state, read=true, issue=false |
| 12..16 | length=state−4, read=false, issue=true |
| 17, unknown token | 1≤length≤13, read=false, issue=false |

Three Kani harnesses check the exact production functions:

1. `base`: `Scan::new()` is related to the initial trie state.
2. `step_preserves_relation_and_error_equivalence`: for every related state pair and every u8 byte, both steps reject or both accept; accepting successors remain related.
3. `finalization_equivalent`: for every related pair, `Scan::finish()` equals trie finalization, including rejection of empty tokens and trailing spaces.

`kani::assume(R)` in the step/exit proofs is the induction hypothesis, established by base and preserved by step. It assumes neither the desired output equality nor a restriction on byte values. The production parser directly folds these checked steps over each byte, propagates rejection with `?`, and invokes the checked finalizer once.

Lift both transitions to propagate rejection unchanged. Structural induction on the input list gives initial correspondence for the empty prefix, preserved correspondence or equal rejection after appending any byte, and equal outputs at finalization. Thus the theorem covers every finite byte list, including every 0..256-byte input. The identical public guard excludes empty/oversized input; boundary and complete-token tests cover that driver as well.

The three induction obligations are mechanically checked. The composition uses Rust's sequential iterator/control-flow semantics and the literal fold above; it is not reported as a successful Kani comparison of two separately unrolled whole parsers. Those longer diagnostic attempts and experimental loop-contract attempts were stopped and are not counted as passing evidence. The compiler/standard-library semantic contract is explicit, as for UUID/String equality elsewhere in policy.

Removing the actual issue-bit accumulation must produce a semantic counterexample to the step relation. `scripts/check-kernel-mutations.py` reruns that negative control and rejects compilation failures as evidence. The final integrated Kani/mutation logs, tied to source hashes, are authoritative; scratch reviewer runs are not substituted for product runs.
