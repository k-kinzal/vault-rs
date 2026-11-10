#!/usr/bin/env python3
"""Compare a second clean build, in a fresh target directory, on this host.

This does not claim independent builder review or cross-platform equivalence.
"""
import hashlib, pathlib, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[1]
reference=root/'target/release/vault-rs'
before=hashlib.sha256(reference.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='vault-rebuild-') as target:
    subprocess.run(['cargo','build','--locked','--offline','--workspace','--all-features','--release','--target-dir',target],cwd=root,check=True)
    second=hashlib.sha256((pathlib.Path(target)/'release/vault-rs').read_bytes()).hexdigest()
    print('Original SHA-256:',before,flush=True)
    print('Clean rebuild SHA-256:',second,flush=True)
    if before!=second:raise SystemExit('FAIL: build outputs differ')
print('PASS: clean target rebuild is byte-identical on the same host/toolchain; not independent attestation')
