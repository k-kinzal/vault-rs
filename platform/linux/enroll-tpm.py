#!/usr/bin/python3 -I
"""Root-only enrollment into an existing administrator-provisioned TPM parent.

No persistent parent is replaced; no private key or PIN is printed to stdout.
This requires a real /dev/tpmrm0 and does not accept a simulator TCTI override.
"""
import argparse,base64,getpass,json,os,pathlib,re,secrets,shutil,stat,subprocess,tempfile
from cryptography.hazmat.primitives import serialization

def b64(value):return base64.urlsafe_b64encode(value).decode().rstrip('=')
def checked(path):
    if path.resolve()!=path:raise ValueError('canonical path required')
    for item in (path,*path.parents):
        info=item.stat()
        if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('administrator-controlled path required')
def tpm(tool,*args):
    binary=pathlib.Path('/usr/bin')/tool;checked(binary)
    return subprocess.run([str(binary),'-T','device:/dev/tpmrm0',*map(str,args)],check=True,capture_output=True).stdout
def main():
    p=argparse.ArgumentParser();p.add_argument('--key-id',required=True);p.add_argument('--parent',required=True);p.add_argument('--kind',choices=['sign','ecdh'],required=True);p.add_argument("--usage",choices=["interactive","service"],default="interactive");p.add_argument("--pcrs");a=p.parse_args()
    if os.getuid()!=0 or os.geteuid()!=0:raise ValueError('administrator required')
    if not re.fullmatch('[A-Za-z0-9_-]{1,128}',a.key_id) or not re.fullmatch('0x81[0-9A-Fa-f]{6}',a.parent):raise ValueError('invalid identity or parent handle')
    if not stat.S_ISCHR(pathlib.Path('/dev/tpmrm0').stat().st_mode):raise ValueError('physical TPM resource manager required')
    base=pathlib.Path('/var/lib/vault-rs/tpm');base.mkdir(mode=0o700,parents=True,exist_ok=True);checked(base)
    final=base/a.key_id
    if final.exists():raise ValueError('existing keys are never overwritten')
    parent=tpm('tpm2_readpublic','-c',a.parent)
    if not all(attr in parent for attr in [b'fixedtpm',b'fixedparent',b'restricted',b'decrypt']):raise ValueError('parent is not a TPM storage parent')
    if a.usage=="service" and (not a.pcrs or not re.fullmatch(r"sha256:[0-9]+(?:,[0-9]+)*",a.pcrs)):raise ValueError("service keys require an explicit SHA-256 PCR selection")
    # Strong random authorization avoids relying on a guessed human password.
    pin=None;repeated=None
    if a.usage=='interactive':
        pin=secrets.token_urlsafe(24)
        with open('/dev/tty','r+') as tty:
            tty.write('Record this new TPM key authorization in your password manager. It will not be shown again.\n'+pin+'\n');tty.flush()
            repeated=getpass.getpass('Enter the displayed authorization to confirm storage: ',stream=tty)
        if not secrets.compare_digest(pin,repeated):raise ValueError('confirmation mismatch')
    stage=pathlib.Path(tempfile.mkdtemp(prefix='.enroll-',dir=base))
    try:
        with tempfile.TemporaryDirectory(prefix='vault-auth-',dir='/dev/shm') as auth_dir:
            attrs='fixedtpm|fixedparent|sensitivedataorigin|'+('sign' if a.kind=='sign' else 'decrypt')
            if a.usage=='interactive':
                attrs+='|userwithauth'
                auth=pathlib.Path(auth_dir)/'auth';fd=os.open(auth,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                with os.fdopen(fd,'w') as stream:stream.write(pin)
                pin=None;repeated=None
                authorization=['-p','file:'+str(auth)]
            else:
                attrs+='|adminwithpolicy'
                session=pathlib.Path(auth_dir)/'policy.ctx'
                tpm('tpm2_startauthsession','-S',session)
                try:
                    tpm('tpm2_policypcr','-S',session,'-l',a.pcrs)
                    tpm('tpm2_policycommandcode','-S',session,'-L',stage/'policy.digest','TPM2_CC_Sign' if a.kind=='sign' else 'TPM2_CC_ECDH_ZGen')
                finally:tpm('tpm2_flushcontext',session)
                authorization=['-L',stage/'policy.digest']
            tpm('tpm2_create','-C',a.parent,'-G','ecc256','-a',attrs,*authorization,'-u',stage/'key.pub','-r',stage/'key.priv')
            ctx=pathlib.Path(auth_dir)/'key.ctx'
            tpm('tpm2_load','-C',a.parent,'-u',stage/'key.pub','-r',stage/'key.priv','-c',ctx)
            try:
                attributes=tpm('tpm2_readpublic','-c',ctx,'-f','pem','-o',stage/'public.pem')
                if not all(v.encode() in attributes for v in attrs.split('|')):raise ValueError('TPM attributes differ from enrollment request')
            finally:tpm('tpm2_flushcontext',ctx)
        key=serialization.load_pem_public_key((stage/'public.pem').read_bytes())
        point=key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint if a.kind=='sign' else serialization.PublicFormat.UncompressedPoint)
        public=b64(point) if a.kind=='sign' else 'p256:'+b64(point)
        (stage/'parent-handle').write_text(a.parent+'\n');(stage/'enrollment.json').write_text(json.dumps({'key_id':a.key_id,'usage':a.usage,'pcrs':a.pcrs,'kind':a.kind,'public_key':public,'attributes':attrs,'tcti':'device:/dev/tpmrm0','physical_theft_tests':'NOT_RUN'},indent=2)+'\n')
        for file in stage.iterdir():
            file.chmod(0o400)
            with file.open('rb') as stream:os.fsync(stream.fileno())
        stage.rename(final)
        descriptor=os.open(base,os.O_RDONLY);os.fsync(descriptor);os.close(descriptor)
        print(json.dumps({'key_id':a.key_id,'public_key':public,'record':str(final/'enrollment.json')}))
    finally:
        if stage.exists():shutil.rmtree(stage)
if __name__=='__main__':main()
