#!/usr/bin/python3 -I
"""Native TPM helper contract. Root-install only; never grant AI its service UID.

Uses the real /dev/tpmrm0 device only. Software TPMs are tested separately and do
not satisfy production enrollment. Key blobs live in /var/lib/vault-rs/tpm/ID/.
Every invocation asks for the key authorization using /dev/tty. No PIN argv/env.
Native session isolation and physical theft tests remain deployment obligations.
"""
import base64
import getpass
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile

def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def command(tool, *args):
    path = Path("/usr/bin") / tool
    meta = path.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError("untrusted TPM utility")
    return subprocess.run([str(path), "-T", "device:/dev/tpmrm0", *map(str, args)],
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

def main():
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError("only the administrator-started key broker may invoke this helper")
    req = json.loads(sys.stdin.buffer.read(65537))
    if set(req) != {"operation", "key_id", "data", "context"}:
        raise ValueError("invalid request")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", req["key_id"]):
        raise ValueError("invalid key ID")
    if req["operation"] not in ("ecdh", "sign"):
        raise ValueError("unsupported operation")
    if not stat.S_ISCHR(Path("/dev/tpmrm0").stat().st_mode):
        raise ValueError("real TPM resource manager required")
    key_dir = Path("/var/lib/vault-rs/tpm") / req["key_id"]
    for path in (key_dir, *key_dir.parents):
        meta = path.stat()
        if path.resolve() != path or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError("untrusted key directory")
    for name in ("key.pub", "key.priv", "parent-handle"):
        path = key_dir / name
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError("untrusted key file")
    raw = base64.b64decode(req["data"] + "=" * (-len(req["data"]) % 4), altchars=b"-_", validate=True)
    if len(raw) > 16384:
        raise ValueError("oversized input")
    with open("/dev/tty", "r+", encoding="utf-8") as tty:
        tty.write("Vault native TPM operation: " + req["operation"] + "\n")
        tty.write((raw.decode("utf-8", errors="replace") if req["operation"] == "sign" else req["context"]) + "\n")
        tty.flush()
        pin = getpass.getpass("TPM key PIN (empty PINs are forbidden): ", stream=tty)
    if not pin:
        raise ValueError("empty PIN")
    # Short-lived, mode-0600 authentication file on tmpfs; service UID isolation
    # and encrypted swap are required. This is not a kernel/OS compromise defense.
    with tempfile.TemporaryDirectory(prefix="vault-tpm-", dir="/dev/shm") as tmp:
        root = Path(tmp)
        auth = root / "auth"
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(pin.encode())
        pin = None
        # Enrollment stores a TPM-wrapped private blob and parent handle. Neither
        # is an exportable private key. Parent handle is fixed by the administrator.
        parent = (key_dir / "parent-handle").read_text().strip()
        if not re.fullmatch(r"0x81[0-9a-fA-F]{6}", parent):
            raise ValueError("invalid persistent parent")
        context = root / "key.ctx"
        command("tpm2_load", "-C", parent, "-u", key_dir / "key.pub", "-r", key_dir / "key.priv", "-c", context)
        output = root / "output"
        try:
            attributes = command("tpm2_readpublic", "-c", context)
            for required in (b"fixedtpm", b"fixedparent", b"sensitivedataorigin", b"userwithauth"):
                if required not in attributes:
                    raise ValueError("key does not have required non-migratable attributes")
            if b"noda" in attributes:
                raise ValueError("dictionary-attack protection required")
            if req["operation"] == "sign":
                data = root / "message"
                data.write_bytes(raw)
                command("tpm2_sign", "-c", context, "-g", "sha256", "-s", "ecdsa", "-f", "plain", "-p", "file:" + str(auth), "-o", output, data)
                result = output.read_bytes()
            else:
                if len(raw) != 65 or raw[0] != 4:
                    raise ValueError("invalid P-256 point")
                point = struct.pack(">H", 68) + struct.pack(">H", 32) + raw[1:33] + struct.pack(">H", 32) + raw[33:]
                peer = root / "peer"
                peer.write_bytes(point)
                command("tpm2_ecdhzgen", "-c", context, "-u", peer, "-p", "file:" + str(auth), "-o", output)
                point = output.read_bytes()
                if len(point) != 70 or point[:4] != b"\x00\x44\x00\x20" or point[36:38] != b"\x00\x20":
                    raise ValueError("invalid TPM ECDH output")
                result = point[4:36]
        finally:
            command("tpm2_flushcontext", context)
        print(json.dumps({"value": b64(result)}))

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Native Vault key operation denied.", file=sys.stderr)
        sys.exit(1)
