#!/usr/bin/env python3
"""Compare a second clean build, in a fresh target directory, on this host.

This does not claim independent builder review or cross-platform equivalence.
"""
import hashlib, pathlib, subprocess, tempfile, shutil, json, struct
def macho_layout(path):
    data=path.read_bytes()
    if data[:4] != b'\xcf\xfa\xed\xfe': return {}
    offset=32; result={}
    for i in range(struct.unpack_from('<I',data,16)[0]):
        command,size=struct.unpack_from('<II',data,offset)
        if command==0x19:
            sections=struct.unpack_from('<I',data,offset+64)[0]
            for j in range(sections):
                section=offset+72+j*80
                name=data[section:section+16].split(b'\0')[0].decode()
                segment=data[section+16:section+32].split(b'\0')[0].decode()
                length,start=struct.unpack_from('<QI',data,section+40)
                flags=struct.unpack_from('<I',data,section+64)[0]
                if flags & 0xff not in (1,12,18):
                    result[segment+'/'+name]=[length,hashlib.sha256(data[start:start+length]).hexdigest()]
        elif command==0x1b: result['LC_UUID']=data[offset+8:offset+24].hex()
        elif command==2:
            _,_,start,length=struct.unpack_from('<IIII',data,offset+8)
            result['string_table']=[length,hashlib.sha256(data[start:start+length]).hexdigest()]
        elif command==0x1d:
            start,length=struct.unpack_from('<II',data,offset+8)
            result['code_signature']=[length,hashlib.sha256(data[start:start+length]).hexdigest()]
        offset+=size
    return result

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
        original_layout=macho_layout(diagnostic/'original')
        rebuilt_layout=macho_layout(diagnostic/'rebuilt')
        for name in sorted(set(original_layout)|set(rebuilt_layout)):
            if original_layout.get(name)!=rebuilt_layout.get(name):
                print('DIFFERENT Mach-O component',name,original_layout.get(name),rebuilt_layout.get(name),flush=True)
        raise SystemExit('FAIL: build outputs differ; diagnostic binaries in .tools/repro-failure')
print('PASS: clean target rebuild is byte-identical on the same host/toolchain; not independent attestation')
