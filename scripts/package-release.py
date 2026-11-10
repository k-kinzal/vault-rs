#!/usr/bin/env python3
"""Package same-run native artifacts only after the release validator accepts them."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tarfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
for name in ('linux', 'macos', 'output'):
    p.add_argument('--'+name, type=pathlib.Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
binary = ROOT/'target/release/vault-rs'
binary.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(a.linux/'vault-rs', binary)
subprocess.run(['python3', str(ROOT/'scripts/release-evidence.py'), 'evaluate',
                '--linux', str(a.linux), '--macos', str(a.macos),
                '--output', str(a.output/'release.json')], check=True, cwd=ROOT)
# All inputs were hash-checked above. Keep the full evidence, not just a summary.
shutil.copytree(a.linux, a.output/'evidence/linux')
shutil.copytree(a.macos, a.output/'evidence/macos')
for platform, directory, names in [('linux', a.linux, ['vault-rs']),
                                   ('macos', a.macos, ['vault-rs', 'vault-se-helper'])]:
    for name in names:
        dest = a.output/'bin'/platform/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(directory/name, dest)
        dest.chmod(0o755)
# Include exactly the source bytes identified by both producer manifests.
sources = json.loads((a.linux/'sources.json').read_text())
with tarfile.open(a.output/'source.tar.gz', 'w:gz') as archive:
    for name in sorted(sources):
        archive.add(ROOT/name, arcname='vault-rs/'+name, recursive=False)
provenance = {'repository': os.environ.get('GITHUB_REPOSITORY'),
              'commit': os.environ.get('GITHUB_SHA'),
              'head_ref': os.environ.get('GITHUB_HEAD_REF'),
              'run_id': os.environ.get('GITHUB_RUN_ID'),
              'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'source_commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'authentication': 'GitHub Actions same-run artifacts; no fabricated operator acceptance signature'}
(a.output/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
(a.output/'README.txt').write_text('''Verified software release for Linux and macOS. Physical-key experiments excluded by request.
release.json is a software-release decision, not acceptance of an unspecified deployment.
Extract source.tar.gz and read docs/OPERATIONS.md, docs/PROOF_CONTRACT.md and docs/PRODUCTION_GOAL.md.
Register real keys, configure independent guardian/witness and OAuth, then obtain deployment acceptance.
The proof applies to the documented security kernel under the documented OS/crypto/storage contracts.
CI fixture keys are synthetic and MUST NOT be installed for production.
GitHub artifact downloads do not preserve executable modes: chmod 755 bin/linux/vault-rs or bin/macos/*.
Binaries use system OpenSSL; install the platform dependencies described in the operations guide.
SHA256SUMS binds this package's files; trust its GitHub workflow origin as well as its digest.
''')
lines = []
for path in sorted(a.output.rglob('*')):
    if path.is_file():
        lines.append(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path.relative_to(a.output)))
(a.output/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
print('PASS: native Linux/macOS software release and complete evidence packaged')
