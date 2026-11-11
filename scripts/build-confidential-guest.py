#!/usr/bin/env python3
"""Build a deterministic, self-contained SNP guest initramfs from pinned inputs.

This packages a reviewed kernel/OVMF/busybox/runtime; it does not download an OS,
trust a host-reported measurement, or claim a physical SNP launch. Include the
entire initramfs in the OVMF direct-kernel launch measurement (kernel-hashes=on).
"""
import argparse, hashlib, ipaddress, json, pathlib, re, stat, struct


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_input(item):
    if set(item) != {'path', 'sha256'}:
        raise ValueError('each input requires exactly path and sha256')
    data = pathlib.Path(item['path']).read_bytes()
    if len(data) > 256 * 1024 * 1024 or digest(data) != item['sha256']:
        raise ValueError('pinned input digest/size mismatch: ' + item['path'])
    return data


def archive(entries):
    """Linux newc, with fixed inode order, root ownership and timestamp zero."""
    result = bytearray()
    def add(name, mode, data, inode):
        encoded = name.encode() + b'\0'
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        result.extend(b'070701' + ''.join(f'{v:08x}' for v in fields).encode())
        result.extend(encoded)
        result.extend(b'\0' * (-len(result) % 4))
        result.extend(data)
        result.extend(b'\0' * (-len(result) % 4))
    for inode, (name, (mode, data)) in enumerate(sorted(entries.items()), 1):
        add(name, mode, data, inode)
    add('TRAILER!!!', 0, b'', len(entries) + 1)
    result.extend(b'\0' * (-len(result) % 512))
    return bytes(result)


def elf_dependencies(data):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ELF64 little-endian image required')
    kind, machine = struct.unpack_from('<HH', data, 16)
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    if machine != 62 or kind not in (2, 3) or phsize != 56 or not 1 <= phnum <= 128 or phoff + phsize * phnum > len(data):
        raise ValueError('invalid x86-64 ELF program header')
    segments = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(phnum)]
    interpreter = None; dynamic = []
    for kind, flags, offset, virtual, physical, size, memory, align in segments:
        if offset + size > len(data):
            raise ValueError('truncated ELF segment')
        if kind == 3:
            raw = data[offset:offset+size]
            if not raw.endswith(b'\0') or b'\0' in raw[:-1] or interpreter is not None:
                raise ValueError('invalid ELF interpreter')
            interpreter = raw[:-1].decode()
        if kind == 2:
            if size % 16:
                raise ValueError('invalid ELF dynamic table')
            dynamic = [struct.unpack_from('<QQ', data, offset + i) for i in range(0, size, 16)]
    needed = [value for tag, value in dynamic if tag == 1]
    if any(tag in (15, 29) for tag, value in dynamic):
        raise ValueError('custom RPATH/RUNPATH is unsupported in the minimal guest')
    names = []
    if needed:
        tables = [value for tag, value in dynamic if tag == 5]
        if len(tables) != 1:
            raise ValueError('ELF string table missing')
        mapped = [offset + tables[0] - virtual for kind, flags, offset, virtual, physical, size, memory, align in segments if kind == 1 and virtual <= tables[0] < virtual + size]
        if len(mapped) != 1:
            raise ValueError('ELF string table is not file-backed')
        for offset in needed:
            start = mapped[0] + offset
            end = data.find(b'\0', start, start + 256)
            if end < start:
                raise ValueError('invalid ELF dependency name')
            name = data[start:end].decode()
            if not re.fullmatch(r'[A-Za-z0-9_.+-]+', name):
                raise ValueError('invalid ELF dependency path')
            names.append(name)
    return interpreter, names


def build(manifest, output):
    required = {'kernel', 'kernel_config', 'firmware', 'vault', 'busybox', 'files', 'network', 'role', 'machine_id', 'vcpus', 'memory_mib'}
    if manifest.get('role') not in ('serve', 'witness'):
        required.add('receipt_nonce')
    if manifest.get('role') in ('rotate-storage', 'rewrap-config', 'observe'):
        required.add('expected_source_sha256')
    if set(manifest) != required:
        raise ValueError('unknown or missing image fields')
    if manifest['role'] not in ('serve', 'witness', 'initialize-storage', 'rotate-storage', 'rewrap-config', 'observe'):
        raise ValueError('immutable guest requires one fixed service role')
    if not re.fullmatch('[0-9a-f]{32}', manifest['machine_id']):
        raise ValueError('fixed machine identity required')
    if type(manifest['vcpus']) is not int or not 1 <= manifest['vcpus'] <= 64:
        raise ValueError('invalid vCPU count')
    if type(manifest['memory_mib']) is not int or not 512 <= manifest['memory_mib'] <= 65536:
        raise ValueError('invalid guest memory size')
    network = manifest['network']
    if set(network) != {'interface', 'address', 'gateway', 'dns'} or not re.fullmatch('[a-z][a-z0-9]{0,14}', network['interface']):
        raise ValueError('invalid immutable network configuration')
    address = str(ipaddress.IPv4Interface(network['address']))
    gateway = str(ipaddress.IPv4Address(network['gateway']))
    dns = str(ipaddress.IPv4Address(network['dns']))
    kernel_config = checked_input(manifest['kernel_config']).decode()
    for option in ('AMD_MEM_ENCRYPT', 'SEV_GUEST', 'DEVTMPFS', 'VIRTIO_PCI', 'VIRTIO_BLK', 'VIRTIO_NET', 'EXT4_FS', 'TMPFS', 'PROC_FS', 'SYSFS', 'INET', 'BLK_DEV_INITRD', 'BINFMT_SCRIPT', 'BINFMT_ELF'):
        if f'CONFIG_{option}=y\n' not in kernel_config:
            raise ValueError('required built-in kernel support missing: ' + option)
    for option in ('KEXEC', 'KEXEC_FILE', 'HIBERNATION', 'SWAP', 'DEVMEM', 'DEVKMEM', 'PROC_KCORE', 'DEBUG_FS', 'MODULES'):
        if f'CONFIG_{option}=' in kernel_config:
            raise ValueError('forbidden kernel capability: ' + option)
    inputs = {name: checked_input(manifest[name]) for name in ('kernel', 'firmware', 'vault', 'busybox')}
    elf_dependencies(inputs['vault'])
    if elf_dependencies(inputs['busybox']) != (None, []):
        raise ValueError('static busybox required')
    if inputs['kernel'][0x202:0x206] != b'HdrS':
        raise ValueError('x86 Linux boot-protocol kernel required')
    entries = {}
    def add(name, data, mode):
        path = pathlib.PurePosixPath(name)
        if any(ord(c) < 32 or ord(c) == 127 for c in name) or not name.startswith('/') or str(path) != name or '..' in path.parts or name == '/':
            raise ValueError('canonical absolute guest path required')
        name = name[1:]
        if name in entries:
            raise ValueError('duplicate guest path: ' + name)
        for parent in path.parents:
            if str(parent) != '/':
                parent_name = str(parent)[1:]
                if parent_name in entries and not stat.S_ISDIR(entries[parent_name][0]):
                    raise ValueError('file cannot be used as a parent directory')
                entries.setdefault(parent_name, (stat.S_IFDIR | 0o555, b''))
        entries[name] = (mode, data)
    for name in ('/proc', '/sys', '/dev', '/run', '/tmp', '/state'):
        add(name, b'', stat.S_IFDIR | 0o700)
    add('/bin/busybox', inputs['busybox'], stat.S_IFREG | 0o555)
    add('/bin/sh', b'busybox', stat.S_IFLNK | 0o777)
    add('/bin/vault-rs', inputs['vault'], stat.S_IFREG | 0o555)
    add('/etc/machine-id', (manifest['machine_id'] + '\n').encode(), stat.S_IFREG | 0o444)
    add('/etc/resolv.conf', ('nameserver ' + dns + '\n').encode(), stat.S_IFREG | 0o444)
    for item in manifest['files']:
        if set(item) != {'path', 'sha256', 'target', 'executable'} or type(item['executable']) is not bool:
            raise ValueError('invalid pinned guest file')
        if not item['target'].startswith(('/etc/vault/', '/lib/', '/lib64/', '/usr/lib/')):
            raise ValueError('only immutable configuration and runtime libraries may be added')
        add(item['target'], checked_input({k: item[k] for k in ('path', 'sha256')}), stat.S_IFREG | (0o555 if item['executable'] else 0o400))
    loader_paths = ('lib', 'lib64', 'usr/lib', 'lib/x86_64-linux-gnu', 'usr/lib/x86_64-linux-gnu')
    def is_elf(name):
        if name not in entries or not stat.S_ISREG(entries[name][0]):
            return False
        elf_dependencies(entries[name][1])
        return True
    for name, (mode, content) in entries.items():
        if stat.S_ISREG(mode) and content[:4] == b'\x7fELF':
            interpreter, needed = elf_dependencies(content)
            if interpreter is not None and not is_elf(interpreter.removeprefix('/')):
                raise ValueError('ELF interpreter missing from immutable image: ' + interpreter)
            for library in needed:
                if not any(is_elf(directory + '/' + library) for directory in loader_paths):
                    raise ValueError('ELF dependency missing from immutable image: ' + library)
    role = manifest['role']
    needed = ['etc/vault/service.json']
    if role in ('serve', 'witness'):
        needed.append('etc/vault/acceptance-files.json')
        command = f'/bin/vault-rs {role} --config /etc/vault/service.json --acceptance /etc/vault/acceptance-files.json'
    elif role == 'initialize-storage':
        needed.append('etc/vault/storage-key.json')
        service = json.loads(entries['etc/vault/service.json'][1])
        database = service.get('database', '')
        if not re.fullmatch(r'/state/[a-zA-Z0-9_-]+\.db', database):
            raise ValueError('bootstrap database must be one fixed /state/*.db file')
        command = f'/bin/vault-rs initialize-storage --database {database} --key-config /etc/vault/storage-key.json'
    elif role == 'rotate-storage':
        needed.extend(['etc/vault/old-key.json', 'etc/vault/new-key.json'])
        command = '/bin/vault-rs rotate-storage --source /state/source.db --destination /state/destination.db --old-key /etc/vault/old-key.json --new-key /etc/vault/new-key.json'
    elif role == 'rewrap-config':
        needed.extend(['etc/vault/old-key.json', 'etc/vault/new-key.json'])
        command = '/bin/vault-rs rewrap-config --source /state/source.envelope.json --destination /state/destination.envelope.json --old-key /etc/vault/old-key.json --new-key /etc/vault/new-key.json'
    else:
        command = '/bin/vault-rs observe-attested --config /etc/vault/service.json --expected-envelope-sha256 ' + manifest['expected_source_sha256']
    if role not in ('serve', 'witness'):
        needed.append('etc/vault/receipt-key.json')
        if not re.fullmatch('[0-9a-f]{64}', manifest['receipt_nonce']):
            raise ValueError('operator-generated 32-byte nonce required')
        command += ' --receipt-key /etc/vault/receipt-key.json --receipt-nonce ' + manifest['receipt_nonce']
    if role in ('rotate-storage', 'rewrap-config', 'observe'):
        if not re.fullmatch('[0-9a-f]{64}', manifest['expected_source_sha256']):
            raise ValueError('authenticated source generation hash required')
        if role != 'observe':
            command += ' --source-sha256 ' + manifest['expected_source_sha256']
    if any(path not in entries for path in needed):
        raise ValueError('immutable entrypoint configuration is missing')
    command = '/bin/busybox env -i PATH=/bin HOME=/ ' + command
    if role in ('serve', 'witness'):
        command = 'exec ' + command
    else:
        command += '\n/bin/busybox poweroff -f'
    init = f'''#!/bin/sh
set -eu
export PATH=/bin
export HOME=/
umask 077
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
# PID 1 starts before devtmpfs supplies /dev/console; reopen all stdio FDs.
exec </dev/console >/dev/console 2>&1
/bin/busybox mount -t tmpfs -o nosuid,nodev,noexec,mode=0700 tmpfs /run
/bin/busybox mount -t tmpfs -o nosuid,nodev,noexec,mode=0700 tmpfs /tmp
# No swap, cloud-init, SSH, getty, debug shell or host-supplied executable.
/bin/busybox test -c /dev/sev-guest
/bin/busybox ip link set lo up
/bin/busybox ip link set {network['interface']} up
/bin/busybox ip address add {address} dev {network['interface']}
/bin/busybox ip route add default via {gateway}
# The only writable external filesystem contains SQLCipher state; paths and
# the envelope generation are verified by signed deployment acceptance.
/bin/busybox mount -t ext4 -o nosuid,nodev,noexec /dev/vdb /state
{command}
'''
    add('/init', init.encode(), stat.S_IFREG | 0o500)
    output.mkdir(parents=True, exist_ok=False)
    payload = archive(entries)
    (output/'initramfs.cpio').write_bytes(payload)
    (output/'kernel').write_bytes(inputs['kernel'])
    (output/'OVMF.fd').write_bytes(inputs['firmware'])
    commandline = 'rdinit=/init console=ttyS0 panic=-1 oops=panic module.sig_enforce=1'
    (output/'cmdline').write_text(commandline + '\n')
    receipt = {'schema': 1, 'physical_snp_launch': 'NOT_RUN', 'measurement_status': 'REQUIRES_INDEPENDENT_SNP_LAUNCH_DIGEST',
               'policy': '0x20000', 'kernel_hashes': True, 'vcpus': manifest['vcpus'], 'memory_mib': manifest['memory_mib'],
               'commandline': commandline, 'files': {name: digest((output/name).read_bytes()) for name in ('kernel', 'OVMF.fd', 'initramfs.cpio')},
               'guest_files': {name: digest(data) for name, (mode, data) in sorted(entries.items()) if stat.S_ISREG(mode)},
               'inputs': manifest}
    # SNP policy bit 16 (SMT) must be clear; bit 17 is the mandatory reserved bit.
    (output/'launch-inputs.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = build(json.loads(args.manifest.read_text()), args.output)
    print(json.dumps({'initramfs_sha256': result['files']['initramfs.cpio'], 'physical_snp_launch': 'NOT_RUN'}))
