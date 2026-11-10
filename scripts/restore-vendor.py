#!/usr/bin/env python3
"""Restore the checksum-pinned crate for small CI source checkouts.

All local vendor bytes are subsequently compared against upstream + one declared
manifest patch. Existing files are never overwritten with different content.
"""
import hashlib, json, pathlib, subprocess, tarfile
root=pathlib.Path(__file__).resolve().parents[1]
archive=root/'.tools/libsqlite3-sys-0.39.1.crate'
archive.parent.mkdir(exist_ok=True)
if not archive.exists():
    subprocess.run(['curl','-fL','--retry','2','--max-time','120','https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.39.1.crate','-o',str(archive)],check=True)
expected=json.loads((root/'vendor/PROVENANCE.json').read_text())['upstream_archive_sha256']
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
with tarfile.open(archive) as tar:
    for member in tar:
        if not member.isfile(): continue
        relative=pathlib.PurePosixPath(member.name)
        assert relative.parts[0]=='libsqlite3-sys-0.39.1' and '..' not in relative.parts
        name=pathlib.Path(*relative.parts[1:])
        if str(name) in ('.cargo-ok','.cargo_vcs_info.json'): continue
        data=tar.extractfile(member).read()
        if str(name)=='Cargo.toml':
            assert data.count(b'version = "=419.0.6"')==1
            data=data.replace(b'version = "=419.0.6"',b'version = "=420.0.0"')
        dest=root/'vendor/libsqlite3-sys'/name
        if dest.exists(): assert dest.read_bytes()==data, 'existing vendor file differs: '+str(name)
        else:
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(data)
subprocess.run(['python3',str(root/'scripts/check-vendor.py')],check=True)
