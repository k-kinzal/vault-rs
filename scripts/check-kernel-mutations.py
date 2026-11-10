#!/usr/bin/env python3
"""Kani must reject the ACTUAL policy source when a critical check is removed."""
import argparse, pathlib, subprocess, tempfile, json
root=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--output",type=pathlib.Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
sources={name:(root/"crates/policy/src"/name).read_text() for name in ("lib.rs","wire.rs")}
mutations=[("missing-guardian","&& e.guardian","&& true","stolen_token_and_dpop_key_are_insufficient"),("missing-sequence","if s.next != r.sequence","if false","replay_after_commit_is_rejected"),("missing-recipient","&& o.recipient == g.recipient","&& true","actual_wire_mapping_refines_owner_binding")]
mutations.append(("missing-witness-order", "    reserve()?;\n    database()", "    let _ = reserve;\n    database()", "implementation_transaction_refines_atomic_disclosure_spec"))
mutations.append(("deny-every-operation", "let value = persist(next).map_err(CommitError::Storage)?;", "if true { return Err(CommitError::Policy(Denied::Locked)); } let value = persist(next).map_err(CommitError::Storage)?;", "implementation_transaction_refines_atomic_disclosure_spec"))
# The second mutant drops all success paths; the refinement theorem must also
# catch a vacuous implementation that denies every legitimate operation.
mutations += [
 ("missing-challenge-nonce","&& challenge.nonce == operation.nonce","&& true","actual_record_and_challenge_binding_are_complete"),
 ("missing-execution-artifact","&& &g.artifact_hash == e.artifact","&& true","actual_execution_binding_is_complete"),
 ("missing-oauth-subject","&& token.sub == grant.subject","&& true","oauth_claims_refine_scope_subject_audience_and_lifetime"),
 ("missing-oauth-expiry","&& now < token.exp","&& true","oauth_claims_refine_scope_subject_audience_and_lifetime"),
 ("missing-dpop-nonce","&& proof.nonce == operation.nonce","&& true","dpop_refines_all_bindings_and_freshness")]
results=[]
for name,needle,replacement,harness in mutations:
    matches=[name for name,text in sources.items() if needle in text]
    assert len(matches)==1,(needle,matches)
    changed=matches[0]
    with tempfile.TemporaryDirectory(prefix="vault-kernel-mutation-") as temp:
        d=pathlib.Path(temp);(d/"src").mkdir();
        for filename,source in sources.items(): (d/"src"/filename).write_text(source.replace(needle,replacement,1) if filename==changed else source)
        (d/"Cargo.toml").write_text('[package]\nname="vault-policy-mutant"\nversion="0.0.0"\nedition="2021"\n[features]\nwire=[]\n[lints.rust]\nunexpected_cfgs={level="warn",check-cfg=["cfg(kani)"]}\n')
        run=subprocess.run(["cargo","kani","--manifest-path",str(d/"Cargo.toml"),"--harness",harness,"--output-format","terse"],cwd=root,text=True,capture_output=True,timeout=120)
        text=run.stdout+run.stderr;(a.output/(name+".log")).write_text(text)
        ok=run.returncode!=0 and "VERIFICATION:- FAILED" in text
        print(name,"PASS (counterexample found)" if ok else "FAIL")
        if not ok:print(text[-3000:])
        results.append({"case":name,"exit_code":run.returncode,"expected_failure_observed":ok})
(a.output/"kernel-mutation-results.json").write_text(json.dumps(results,indent=2)+"\n")
raise SystemExit(0 if all(r["expected_failure_observed"] for r in results) else 1)
