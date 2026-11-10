#!/usr/bin/env python3
"""Compare a second clean build, in a fresh target directory, on this host.

This does not claim independent builder review or cross-platform equivalence.
"""
import hashlib, pathlib, subprocess, tempfile, shutil, json
root=pathlib.Path(__file__).resolve().parents[1]
reference=root/'target/release/vault-rs'
before=hashlib.sha256(reference.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='vault-rebuild-') as target:
    subprocess.run(['bash','scripts/build-release.sh','--offline','--target-dir',target],cwd=root,check=True)
    second=hashlib.sha256((pathlib.Path(target)/'release/vault-rs').read_bytes()).hexdigest()
    print('Original SHA-256:',before,flush=True)
    print('Clean rebuild SHA-256:',second,flush=True)
    if before!=second:
        diagnostic=root/'.tools/repro-failure'
        diagnostic.mkdir(parents=True,exist_ok=True)
        for name,path in [('original',reference),('rebuilt',pathlib.Path(target)/'release/vault-rs')]:
            shutil.copy2(path,diagnostic/name)
            result=subprocess.run([str(path),'readiness'],capture_output=True,text=True)
            print(name,'source fingerprint:',json.loads(result.stdout.splitlines()[0])['source_sha256'],flush=True)
        raise SystemExit('FAIL: build outputs differ; diagnostic binaries in .tools/repro-failure')
print('PASS: clean target rebuild is byte-identical on the same host/toolchain; not independent attestation')
