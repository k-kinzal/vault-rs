#!/usr/bin/env python3
"""Check the finite model and require counterexamples for weakened controls."""
import argparse, hashlib, json, pathlib, subprocess, tempfile

root=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument("--output",type=pathlib.Path,required=True);args=parser.parse_args()
args.output.mkdir(parents=True,exist_ok=True)
jar=root/".tools/tla2tools.jar"
assert hashlib.sha256(jar.read_bytes()).hexdigest()=="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88", "unexpected TLC binary"
cfg=(root/"formal/Vault.cfg").read_text()
cases=[("baseline",None,None),("without-guardian","RequireGuardian","NoUnauthorizedRelease"),("without-device","RequireDevice","NoUnauthorizedRelease"),("without-witness","RequireWitness","NoReplay"),("release-before-commit","CommitBeforeRelease","CommitBeforeDisclosure")]
results=[]
for name,flag,expected in cases:
    with tempfile.TemporaryDirectory(prefix="vault-model-") as temp:
        config=pathlib.Path(temp)/"Model.cfg"
        config.write_text(cfg if flag is None else cfg.replace(f"{flag} = TRUE",f"{flag} = FALSE"))
        (pathlib.Path(temp)/"Vault.tla").write_bytes((root/"formal/Vault.tla").read_bytes())
        command=["java","-XX:+UseParallelGC","-Xmx1g","-cp",str(jar),"tlc2.TLC","-workers","2","-metadir",temp+"/states","-config","Model.cfg","Vault.tla"]
        result=subprocess.run(command,cwd=temp,capture_output=True,text=True,timeout=120)
        output=result.stdout+result.stderr
        (args.output/(name+".log")).write_text(output)
        if expected:
            ok=result.returncode!=0 and f"Invariant {expected} is violated" in output
        else:
            ok=result.returncode==0 and "Model checking completed. No error has been found." in output
        results.append({"case":name,"exit_code":result.returncode,"expected_counterexample":expected,"passed":ok})
        print(name, "PASS" if ok else "FAIL")
        if not ok: print(output[-3000:])
(args.output/"model-results.json").write_text(json.dumps(results,indent=2)+"\n")
raise SystemExit(0 if all(r["passed"] for r in results) else 1)
