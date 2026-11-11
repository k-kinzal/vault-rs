#!/usr/bin/env python3
"""Test image packaging and rejection rules; not CPU execution or attestation."""
import copy, importlib.util, json, pathlib, tempfile, struct
source = pathlib.Path(__file__).with_name('build-confidential-guest.py')
spec = importlib.util.spec_from_file_location('guest_builder', source)
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
with tempfile.TemporaryDirectory() as name:
    root = pathlib.Path(name)
    def file(label, data):
        path = root/label; path.write_bytes(data)
        return {'path': str(path), 'sha256': builder.digest(data)}
    kernel = bytearray(4096); kernel[0x202:0x206] = b'HdrS'
    enabled = ('AMD_MEM_ENCRYPT', 'SEV_GUEST', 'DEVTMPFS', 'VIRTIO_PCI', 'VIRTIO_BLK', 'VIRTIO_NET', 'EXT4_FS', 'TMPFS', 'PROC_FS', 'SYSFS', 'INET', 'BLK_DEV_INITRD', 'BINFMT_SCRIPT', 'BINFMT_ELF')
    config = ''.join(f'CONFIG_{k}=y\n' for k in enabled).encode()
    elf = bytearray(120); elf[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<HH', elf, 16, 2, 62); struct.pack_into('<Q', elf, 32, 64); struct.pack_into('<HH', elf, 54, 56, 1)
    manifest = {'kernel': file('kernel', kernel), 'kernel_config': file('config', config),
        'firmware': file('firmware', b'SYNTHETIC PACKAGING TEST'),
        'vault': file('vault', elf), 'busybox': file('busybox', elf),
        'files': [dict(file('service.json', b'{}'), target='/etc/vault/service.json', executable=False),
                  dict(file('acceptance.json', b'{}'), target='/etc/vault/acceptance-files.json', executable=False)],
        'network': {'interface': 'eth0', 'address': '192.0.2.2/24', 'gateway': '192.0.2.1', 'dns': '192.0.2.53'},
        'role': 'serve', 'machine_id': '1'*32, 'vcpus': 2, 'memory_mib': 1024}
    builder.build(manifest, root/'first'); builder.build(manifest, root/'second')
    data = (root/'first/initramfs.cpio').read_bytes()
    assert data == (root/'second/initramfs.cpio').read_bytes()
    # Independent newc reader validates the actual output, including padding.
    entries = {}; offset = 0
    while True:
        assert data[offset:offset+6] == b'070701'
        fields = [int(data[offset+6+8*i:offset+14+8*i], 16) for i in range(13)]
        mode, uid, gid, mtime, size, namesize = fields[1], fields[2], fields[3], fields[5], fields[6], fields[11]
        assert (uid, gid, mtime) == (0, 0, 0)
        name_start = offset + 110
        filename = data[name_start:name_start+namesize-1].decode()
        offset = (name_start + namesize + 3) & ~3
        content = data[offset:offset+size]; offset = (offset+size+3) & ~3
        if filename == 'TRAILER!!!': break
        assert filename not in entries; entries[filename] = content
    init = entries['init'].decode()
    assert '--verification-run' not in init and '--acceptance /etc/vault/acceptance-files.json' in init
    assert 'test -c /dev/sev-guest' in init and 'env -i' in init
    assert entries['bin/sh'] == b'busybox' and entries['etc/vault/service.json'] == b'{}'
    for case in range(11):
        bad = copy.deepcopy(manifest)
        if case == 0: bad['vault']['sha256'] = '0'*64
        elif case == 1: bad['files'][0]['target'] = '/etc/vault/../init'
        elif case == 2: bad['files'].append(bad['files'][0])
        elif case == 3: bad['network']['interface'] = 'eth0;sh'
        elif case == 4: bad['role'] = 'isolated-worker'
        elif case == 5: bad['files'].pop()
        elif case == 6: bad['kernel_config'] = file('bad-config', config+b'CONFIG_DEVMEM=y\n')
        elif case == 7: bad['kernel_config'] = file('bad-config2', b'CONFIG_SEV_GUEST=m\n')
        elif case == 8: bad['files'][0]['target'] += '\0alias'
        elif case == 9: bad['files'].append(dict(file('prefix', b'bad'), target='/etc/vault/service.json/child', executable=False))
        else: bad['files'][0]['target'] += '\nalias'
        try: builder.build(bad, root/f'bad-{case}')
        except ValueError: pass
        else: raise AssertionError('unsafe manifest accepted: '+str(case))
    for role in ('initialize-storage', 'rotate-storage', 'rewrap-config', 'observe'):
        maintenance = copy.deepcopy(manifest); maintenance['role'] = role; maintenance['receipt_nonce'] = '2'*64
        if role != 'initialize-storage': maintenance['expected_source_sha256'] = '3'*64
        maintenance['files'][0] = dict(file('maintenance.json', b'{"database":"/state/vault.db"}'), target='/etc/vault/service.json', executable=False)
        for label in ('storage-key', 'old-key', 'new-key', 'receipt-key'):
            maintenance['files'].append(dict(file(label, b'{"kind":"snp"}'), target='/etc/vault/'+label+'.json', executable=False))
        builder.build(maintenance, root/role)
        packed = (root/role/'initramfs.cpio').read_bytes()
        assert ('/bin/vault-rs '+('observe-attested' if role == 'observe' else role)+' --').encode() in packed
        assert b'/bin/busybox poweroff -f' in packed
print('PASS: deterministic measured-image packaging, newc structure, immutable entrypoint, pinned inputs and unsafe-manifest rejection. NO PHYSICAL SNP LAUNCH.')
