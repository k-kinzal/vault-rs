#!/usr/bin/python3
"""PUBLIC SOFTWARE FIXTURE ONLY. Never install as a production native helper.

Used inside a disposable network-isolated container to exercise the real CLI,
resident-key startup, HTTPS, broker and restarts. This is not hardware evidence.
"""
import base64, json, os, pathlib, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

root = pathlib.Path('/opt/vault-deployment-test')
assert os.geteuid() == 0 and root.is_dir()
def encode(data): return base64.urlsafe_b64encode(data).decode().rstrip('=')
def decode(data): return base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))
if sys.argv[1:] == ['--fixture-init']:
    public = {}
    for name in ('device', 'gate', 'witness'):
        key = ec.generate_private_key(ec.SECP256R1())
        with (root / (name + '.pem')).open('xb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public[name] = {
            'agreement': 'p256:' + encode(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
            'signing': encode(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))}
    print(json.dumps(public))
else:
    request = json.loads(sys.stdin.buffer.read(65537))
    assert request['key_id'] in ('device', 'gate', 'witness')
    key = serialization.load_pem_private_key((root / (request['key_id'] + '.pem')).read_bytes(), password=None)
    data = decode(request['data'])
    if request['operation'] == 'sign':
        value = key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        assert request['operation'] == 'ecdh'
        value = key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data))
    with (root / 'calls.log').open('a') as out:
        out.write(request['key_id'] + ':' + request['operation'] + '\n')
    print(json.dumps({'value': encode(value)}))
