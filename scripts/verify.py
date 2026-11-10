#!/usr/bin/env python3
"""Reproducible evidence collection; never promotes test success to system proof."""
import argparse, datetime, hashlib, json, os, pathlib, platform, subprocess, time

root=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--with-docker',action='store_true');p.add_argument('--macos-cross',action='store_true');p.add_argument('--output',type=pathlib.Path);a=p.parse_args()
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out=(a.output or root/'evidence/runs'/stamp).resolve();out.mkdir(parents=True,exist_ok=False)
(out/'commands').mkdir()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def sources():
    paths=subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z'],cwd=root).decode().split('\0')
    return {name:sha(root/name) for name in sorted(set(paths)) if name and not name.startswith('evidence/') and (root/name).is_file()}
before=sources();(out/'sources.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
results=[]
def run(name,command,expected=0,timeout=1800):
    print('RUN',name,flush=True);start=time.monotonic();log=out/'commands'/(name+'.log')
    try:
        with log.open('w') as f:
            result=subprocess.run(command,cwd=root,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        code=result.returncode;ok=(code==expected)
    except (OSError,subprocess.TimeoutExpired) as e:
        with log.open('a') as f:f.write('\n'+str(e)+'\n')
        code=None;ok=False
    results.append({'name':name,'command':command,'expected_exit':expected,'exit_code':code,'passed':ok,'seconds':round(time.monotonic()-start,3),'log':str(log.relative_to(out))})
    print('PASS' if ok else 'FAIL',name,flush=True)
    if not ok:print(log.read_text()[-3000:],flush=True)
run('rustc',['rustc','-Vv']);run('kani-version',['cargo','kani','--version']);run('java',['java','-version']);run('openssl',['openssl','version','-a'])
run('audit-version',['cargo','audit','--version'])
run('vendor',['python3','scripts/check-vendor.py'])
run('format',['cargo','fmt','--all','--check'])
run('python-syntax',['python3','-c','import ast,pathlib; files=[*pathlib.Path("platform").rglob("*.py"),*pathlib.Path("scripts").rglob("*.py")]; [ast.parse(p.read_text(),filename=str(p)) for p in files]; print("Parsed",len(files),"Python source files; not hardware execution")'])
run('clippy',['cargo','clippy','--locked','--workspace','--all-features','--all-targets','--','-D','warnings'])
run('tests',['cargo','test','--locked','--workspace','--all-features'])
run('oauth',['bash','scripts/test-oauth.sh'])
run('kani',['cargo','kani','-p','vault-policy','--output-format','terse'])
run('model',['python3','scripts/check-model.py','--output',str(out/'model')])
run('kernel-mutations',['python3','scripts/check-kernel-mutations.py','--output',str(out/'mutations')])
if a.with_docker:
    run('postgres',['bash','scripts/test-postgres.sh'])
    run('tpm-simulation',['bash','scripts/test-tpm-simulator.sh'])
    run('os-isolation',['bash','scripts/test-isolation.sh'])
    run('deployment',['bash','scripts/test-deployment.sh'])
else:
    results.extend([{'name':name,'passed':None,'status':'NOT_RUN'} for name in ('postgres','tpm-simulation','os-isolation','deployment')])
if a.macos_cross:run('macos-cross',['python3','scripts/check-macos-cross.py'])
run('audit',['cargo','audit','--deny','warnings','--json'])
audit_db=pathlib.Path.home()/'.cargo/advisory-db'
if audit_db.exists():run('audit-db-commit',['git','-C',str(audit_db),'rev-parse','HEAD'])
run('release-build',['cargo','build','--locked','--workspace','--all-features','--release'])
run('clean-rebuild',['python3','scripts/check-reproducible.py'])
run('readiness',['target/release/vault-rs','readiness'],expected=1)
try:ready=json.loads((out/'commands/readiness.log').read_text().splitlines()[0]) if results[-1]['passed'] else {}
except (ValueError,IndexError):ready={}
ready_ok=ready.get('production_ready') is False and len(ready.get('blockers',[]))>=5
same=sources()==before
passed=all(r['passed'] is not False for r in results) and same and ready_ok
complete=passed and all(r['passed'] is True for r in results)
manifest={'schema':1,'started_utc':stamp,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':platform.platform(),'machine':platform.machine(),'checks_passed':passed,'all_scheduled_checks_executed':complete,'source_unchanged':same,'deployment_ready':ready.get('production_ready',False),'product_eligibility':'evaluate_with_macos_evidence','hardware_test_kind':'SIMULATED_TPM_AND_SYNTHETIC_NATIVE_CLI; physical tests EXCLUDED_BY_USER; macOS evidence collected by separate native CI','source_manifest_sha256':sha(out/'sources.json'),'commands':results,'assurance_blockers':ready.get('blockers',[])}
manifest['physical_tests_excluded_by_user']=True
if a.macos_cross:
    manifest['macos_cross_binaries']={str(p.relative_to(root)):sha(p) for p in [root/'target/aarch64-apple-darwin/release/vault-rs',root/'.tools/macos/vault-se-helper'] if p.exists()}
binary=root/'target/release/vault-rs'
if binary.exists():manifest['binary']={'path':str(binary),'sha256':sha(binary)}
manifest['tool_digests']={name:sha(root/'.tools'/name) for name in ('tla2tools.jar','libsqlite3-sys-0.39.1.crate')}
manifest['logs_sha256']={str(f.relative_to(out)):sha(f) for f in out.rglob('*') if f.is_file() and f.name!='sources.json'}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
lines=['# 検証実行結果','',f'UTC: {stamp}',f'チェック成功: {passed} / 全予定試験実行: {complete} / ソース不変: {same}','', '**この記録はLinux検証です。製品の本番利用判定はMac実行証跡と統合してrelease-evidence.pyで評価します。導入先の受入署名を代行しません。**','', '| 検査 | 結果 | ログ |','|---|---|---|']
for r in results:lines.append(f"| {r['name']} | {'PASS' if r['passed'] is True else 'FAIL' if r['passed'] is False else 'NOT_RUN'} | [{r.get('log','未実行')}]({r.get('log','')}) |")
assurance=os.path.relpath(root/'docs/ASSURANCE.md',out)
lines+=['',f'[保証範囲]({assurance}) を参照。TPMはシミュレータのみ。Linuxの別UID隔離はos-isolationログが正本。物理鍵実験は利用者指定で除外。Macクロスビルドは対応ログが正本で、Mac OS上の実行を意味しない。全体refinementは未証明。','',f"対象ソース一覧 SHA-256: `{manifest['source_manifest_sha256']}`",'','同一環境による自己記録であり、独立した認証機関の証明ではありません。']
(out/'report.md').write_text('\n'.join(lines)+'\n')
print('Evidence:',out,flush=True)
raise SystemExit(0 if passed else 1)
