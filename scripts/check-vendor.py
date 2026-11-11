#!/usr/bin/env python3
"""Verify the only vendor change against the checksum-pinned published crate."""
import hashlib,json,pathlib,tarfile
root=pathlib.Path(__file__).resolve().parents[1]
archive=root/'.tools/libsqlite3-sys-0.39.1.crate'
provenance=json.loads((root/'vendor/PROVENANCE.json').read_text())
assert hashlib.sha256(archive.read_bytes()).hexdigest()==provenance['upstream_archive_sha256']
files={}
with tarfile.open(archive) as tar:
    for entry in tar:
        if entry.isfile():
            name=entry.name.split('/',1)[1]
            if name not in ('.cargo-ok','.cargo_vcs_info.json'):
                files[name]=tar.extractfile(entry).read()
needle=b'version = "=419.0.6"'
assert files['Cargo.toml'].count(needle)==1
files['Cargo.toml']=files['Cargo.toml'].replace(needle,b'version = "=420.0.0"')
vendor=root/'vendor/libsqlite3-sys'
actual={str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
assert files==actual, 'unexpected change in vendored source'
print(f'PASS: {len(files)} files equal published crate; only allowed sqlcipher-src dependency change.')
