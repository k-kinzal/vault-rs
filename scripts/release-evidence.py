#!/usr/bin/env python3
"""Cross-platform software release decision; never fabricates host acceptance.

The input directories must come from reviewed executions. Digests detect later
substitution; they do not prove that a log's producer was honest.
"""
import argparse, datetime, hashlib, json, pathlib, platform, subprocess
from evidence_checks import native, oauth, suite
if not __debug__:
    raise SystemExit("Evidence validation requires Python assertions; -O is refused")
ROOT = pathlib.Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def sources():
    names = subprocess.check_output(['git', 'ls-files', '-co', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    return {n: sha(ROOT/n) for n in sorted(set(names)) if n and not n.startswith('evidence/') and (ROOT/n).is_file()}

def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)+'\n')

def verify_logs(directory, hashes):
    for name, digest in hashes.items():
        path = directory/name
        assert not pathlib.Path(name).is_absolute() and '..' not in pathlib.Path(name).parts
        assert path.is_file() and not path.is_symlink() and sha(path) == digest, f'changed log: {path}'

p = argparse.ArgumentParser()
s = p.add_subparsers(dest='command', required=True)
a = s.add_parser('begin-macos'); a.add_argument('--directory', type=pathlib.Path, required=True)
a = s.add_parser('finish-macos'); a.add_argument('--directory', type=pathlib.Path, required=True)
a = s.add_parser('evaluate'); a.add_argument('--linux', type=pathlib.Path, required=True); a.add_argument('--macos', type=pathlib.Path, required=True); a.add_argument('--output', type=pathlib.Path, required=True)
a = p.parse_args()
if a.command == 'begin-macos':
    assert platform.system() == 'Darwin', 'must execute on macOS, not a cross compiler'
    a.directory.mkdir(parents=True, exist_ok=True)
    write(a.directory/'sources.json', sources())
elif a.command == 'finish-macos':
    assert platform.system() == 'Darwin'
    before = json.loads((a.directory/'sources.json').read_text())
    assert before == sources(), 'sources changed during verification'
    required = {'tests.log':'test result: ok.', 'oauth.log':'test result: ok.',
                'os-isolation.log':'test result: ok.', 'deployment.log':'test result: ok.',
                'clean-rebuild.log':'PASS: clean target rebuild is byte-identical',
                'build.log':'Finished', 'swift.log':None}
    for name, marker in required.items():
        text = (a.directory/name).read_text()
        assert 'test result: FAILED' not in text, name
        assert marker is None or marker in text, name
    binary = ROOT/'target/release/vault-rs'
    suite((a.directory/'tests.log').read_text())
    oauth((a.directory/'oauth.log').read_text())
    for kind in ('os-isolation', 'deployment'):
        native((a.directory/(kind+'.log')).read_text(), kind, sha(binary), macos=True)
    result = subprocess.run([str(binary), 'readiness'], capture_output=True, text=True)
    assert result.returncode == 1
    ready = json.loads(result.stdout.splitlines()[0])
    assert ready['production_ready'] is False
    (a.directory/'readiness.log').write_text(result.stdout+result.stderr)
    # Include installable artifacts, not just hashes of absent files.
    import shutil
    shutil.copy2(binary, a.directory/'vault-rs')
    shutil.copy2('/tmp/vault-se-helper', a.directory/'vault-se-helper')
    write(a.directory/'manifest.json', {
        'schema':1, 'platform':platform.platform(), 'machine':platform.machine(),
        'checks_passed':True, 'source_unchanged':True, 'physical_tests_excluded_by_user':True,
        'source_sha256':ready['source_sha256'], 'source_manifest_sha256':sha(a.directory/'sources.json'),
        'binary_sha256':sha(binary), 'methods':list(required),
        'logs_sha256':{str(f.relative_to(a.directory)):sha(f) for f in a.directory.rglob('*') if f.is_file() and f.name!='manifest.json'},
        'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
else:
    failures = []
    decision = {'schema':1, 'decision_scope':'software_release', 'production_ready':False,
                'deployment_accepted':False, 'physical_tests_excluded_by_user':True,
                'assumptions':'docs/PROOF_CONTRACT.md', 'blockers':failures}
    try:
        linux = json.loads((a.linux/'manifest.json').read_text())
        mac = json.loads((a.macos/'manifest.json').read_text())
        assert linux['checks_passed'] and linux['all_scheduled_checks_executed'] and linux['source_unchanged']
        assert mac['checks_passed'] and mac['source_unchanged'] and mac['platform'].startswith('macOS-')
        assert linux['platform'].startswith('Linux-')
        for directory, manifest in [(a.linux,linux), (a.macos,mac)]:
            assert manifest['physical_tests_excluded_by_user']
            assert sha(directory/'sources.json') == manifest['source_manifest_sha256']
            assert json.loads((directory/'sources.json').read_text()) == sources(), 'evidence belongs to a different source tree'
            verify_logs(directory,manifest['logs_sha256'])
        names = {r['name'] for r in linux['commands'] if r.get('passed') is True}
        required = {'rustc','kani-version','java','openssl','audit-version','vendor','format','python-syntax','evidence-checks','clippy','tests','oauth','kani','model','kernel-mutations','postgres','tpm-simulation','os-isolation','deployment','audit','audit-db-commit','release-build','clean-rebuild','readiness'}
        assert required <= names, 'missing Linux verification'
        assert {'commands/'+name+'.log' for name in required} <= set(linux['logs_sha256']), 'unhashed Linux evidence'
        required_mac = {'tests.log','oauth.log','os-isolation.log','deployment.log','clean-rebuild.log','build.log','swift.log'}
        assert required_mac <= set(mac['methods']), 'missing macOS verification'
        assert required_mac <= set(mac['logs_sha256']), 'unhashed macOS evidence'
        ready = json.loads((a.linux/'commands/readiness.log').read_text().splitlines()[0])
        assert ready['source_sha256'] == mac['source_sha256'], 'embedded source fingerprints differ'
        assert sha(a.macos/'vault-rs') == mac['binary_sha256']
        assert sha(ROOT/'target/release/vault-rs') == linux['binary']['sha256']
        for directory, digest, is_mac in [(a.linux/'commands', linux['binary']['sha256'], False),
                                          (a.macos, mac['binary_sha256'], True)]:
            suite((directory/'tests.log').read_text())
            oauth((directory/'oauth.log').read_text())
            for kind in ('os-isolation', 'deployment'):
                native((directory/(kind+'.log')).read_text(), kind, digest, macos=is_mac)
        # Review conclusions are source-controlled claims, explicitly bounded;
        # this cannot prove independent human identity or the truth of a review.
        review = json.loads((ROOT/'docs/review-status.json').read_text())
        assert review['unresolved_findings'] == [] and review['review_kind'] == 'independent_agent_source_review'
        assert (ROOT/review['report']).is_file()
        decision.update(production_ready=True, source_sha256=mac['source_sha256'],
                        linux_binary_sha256=linux['binary']['sha256'], macos_binary_sha256=mac['binary_sha256'],
                        linux_manifest_sha256=sha(a.linux/'manifest.json'), macos_manifest_sha256=sha(a.macos/'manifest.json'),
                        review_sha256=sha(ROOT/review['report']))
    except (AssertionError, KeyError, OSError, ValueError) as e:
        failures.append(str(e) or type(e).__name__)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    write(a.output,decision)
    print(json.dumps(decision,ensure_ascii=False))
    raise SystemExit(0 if decision['production_ready'] else 1)
