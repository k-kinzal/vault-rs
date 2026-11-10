#!/usr/bin/env python3
"""Build actual arm64 Mach-O binaries on Linux. This is NOT macOS execution.

Pinned Apple SDK archive from macosx-sdks; official Swift 6.2.1 Linux compiler;
Rust 1.91.1's Mach-O LLD; upstream OpenSSL 3.5.7, static, no applications/modules.
The SDK archive duplicates a libxml directory; byte-identical copies are replaced
with the normal symlink to avoid duplicate Clang modules. No headers are edited.
"""
import hashlib, os, pathlib, shutil, subprocess, tarfile
root = pathlib.Path(__file__).resolve().parents[1]
work = root/'.tools/macos'; work.mkdir(parents=True, exist_ok=True)
artifacts = [
 ('MacOSX15.5.sdk.tar.xz','https://github.com/joseluisq/macosx-sdks/releases/download/15.5/MacOSX15.5.sdk.tar.xz','c15cf0f3f17d714d1aa5a642da8e118db53d79429eb015771ba816aa7c6c1cbd','MacOSX15.5.sdk'),
 ('swift-linux.tar.gz','https://download.swift.org/swift-6.2.1-release/ubuntu2404/swift-6.2.1-RELEASE/swift-6.2.1-RELEASE-ubuntu24.04.tar.gz','4022cb64faf7e2681c19f9b62a22fb7d9055db6194d9e4a4bef9107b6ce10946','swift-6.2.1-RELEASE-ubuntu24.04'),
 ('openssl-3.5.7.tar.gz','https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz','a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8','openssl-3.5.7')]
def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
def run(args, cwd=root, env=None):
    print('COMMAND', ' '.join(map(str,args)), flush=True)
    subprocess.run(list(map(str,args)), cwd=cwd, env=env, check=True)
for name,url,digest,directory in artifacts:
    archive = work/name
    if not archive.exists(): run(['curl','-fL','--retry','2','--max-time','300',url,'-o',archive])
    assert sha(archive)==digest, f'download digest mismatch: {name}'
    print('VERIFIED',name,digest,flush=True)
    if not (work/directory).exists():
        with tarfile.open(archive) as tar: tar.extractall(work, filter='data')
sdk=work/'MacOSX15.5.sdk'; tool=work/artifacts[1][3]/'usr/bin'
xml=sdk/'usr/include/libxml'; duplicate=sdk/'usr/include/libxml2/libxml'
if not xml.is_symlink():
    files=lambda directory:{str(p.relative_to(directory)):sha(p) for p in directory.rglob('*') if p.is_file()}
    assert files(xml)==files(duplicate), 'SDK duplicate differs; do not patch'
    shutil.rmtree(xml);xml.symlink_to('libxml2/libxml',target_is_directory=True)
resource=work/'swift-resource';resource.mkdir(exist_ok=True)
for p in [tool.parent/'lib/swift/shims',tool.parent/'lib/swift/clang',*sorted((sdk/'usr/lib/swift').iterdir())]:
    dest=resource/p.name
    if not dest.exists(): dest.symlink_to(p,target_is_directory=p.is_dir())
(resource/'macosx').mkdir(exist_ok=True)
sysroot=pathlib.Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip())
def wrapper(name,command):
    p=work/name;p.write_text('#!/bin/sh\nexec '+command+' "$@"\n');p.chmod(0o700);return p
# The workspace path is controlled by the operator; quote it as shell text.
import shlex
q=lambda p:shlex.quote(str(p))
cc=wrapper('cc',f'{q(tool/"clang")} -target arm64-apple-macosx14.0 -isysroot {q(sdk)}')
ld=wrapper('ld64-rust',f'{q(sysroot/"lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld")} -flavor darwin')
linker=wrapper('linker',f'{q(cc)} -fuse-ld={q(ld)} -Wl,-platform_version,macos,14.0,15.5')
ssl=work/'openssl-arm64'
if not (ssl/'lib/libssl.a').exists():
    env=dict(os.environ,CC=str(cc),AR=str(tool/'llvm-ar'),RANLIB=str(tool/'llvm-ranlib'))
    run(['./Configure','darwin64-arm64-cc','no-shared','no-tests','no-apps','no-module',f'--prefix={ssl}'],work/'openssl-3.5.7',env)
    run(['make','-j4','build_sw'],work/'openssl-3.5.7',env)
    run(['make','install_sw'],work/'openssl-3.5.7',env)
run(['rustup','target','add','aarch64-apple-darwin'])
env=dict(os.environ,OPENSSL_DIR=str(ssl),OPENSSL_STATIC='1',CC_aarch64_apple_darwin=str(cc),AR_aarch64_apple_darwin=str(tool/'llvm-ar'),CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=str(linker),SDKROOT=str(sdk),MACOSX_DEPLOYMENT_TARGET='14.0')
run(['cargo','build','--locked','--workspace','--all-features','--release','--target','aarch64-apple-darwin'],env=env)
run([tool/'swiftc','-target','arm64-apple-macosx14.0','-resource-dir',resource,'-sdk',sdk,f'-use-ld={ld}','-Xlinker','-platform_version','-Xlinker','macos','-Xlinker','14.0','-Xlinker','15.5',root/'platform/macos/SecureEnclaveHelper.swift','-o',work/'vault-se-helper'])
for p in [root/'target/aarch64-apple-darwin/release/vault-rs',work/'vault-se-helper']:
    run(['file',p]);print('OUTPUT_SHA256',p.name,sha(p),flush=True)
print('PASS: macOS ARM64 Rust and Swift cross-compilation/link. OS isolation, Keychain and physical Secure Enclave execution are NOT tested.',flush=True)
