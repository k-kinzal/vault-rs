"""Tests actual TPM command encoding against swtpm, not physical key security."""
import os, pathlib, struct, subprocess, tempfile, time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

with tempfile.TemporaryDirectory() as work:
    os.chdir(work)
    pathlib.Path("state").mkdir()
    sim = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=state", "--server", "type=tcp,port=2321", "--ctrl", "type=tcp,port=2322", "--flags", "not-need-init,startup-clear"])
    def tpm(tool, *args, success=True):
        p = subprocess.run([tool,"-T","swtpm:host=127.0.0.1,port=2321",*args], capture_output=True)
        if success and p.returncode:
            raise RuntimeError(tool + ": " + p.stderr.decode())
        if not success:
            assert p.returncode != 0, tool + " unexpectedly accepted wrong authorization"
        return p.stdout
    try:
        for attempt in range(30):
            p = subprocess.run(["tpm2_getcap","-T","swtpm:host=127.0.0.1,port=2321","properties-fixed"],capture_output=True)
            if p.returncode == 0: break
            time.sleep(0.1)
        tpm("tpm2_createprimary","-C","o","-G","ecc","-c","primary.ctx")
        tpm("tpm2_evictcontrol","-C","o","-c","primary.ctx","0x81000001")
        tpm("tpm2_flushcontext","-t")
        for role, attrs in [("ecdh","decrypt"),("sign","sign")]:
            tpm("tpm2_create","-C","0x81000001","-G","ecc256","-a",f"fixedtpm|fixedparent|sensitivedataorigin|userwithauth|{attrs}","-p","test-only-pin","-u",f"{role}.pub","-r",f"{role}.priv")
            tpm("tpm2_load","-C","0x81000001","-u",f"{role}.pub","-r",f"{role}.priv","-c",f"{role}.ctx")
            pub=tpm("tpm2_readpublic","-c",f"{role}.ctx","-f","pem","-o",f"{role}.pem")
            assert b"fixedtpm" in pub and b"fixedparent" in pub and b"sensitivedataorigin" in pub
            key=serialization.load_pem_public_key(pathlib.Path(f"{role}.pem").read_bytes())
            if role == "ecdh":
                peer=ec.generate_private_key(ec.SECP256R1())
                point=peer.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
                encoded=struct.pack(">HH",68,32)+point[1:33]+struct.pack(">H",32)+point[33:]
                pathlib.Path("point.bin").write_bytes(encoded)
                tpm("tpm2_ecdhzgen","-c","ecdh.ctx","-u","point.bin","-p","test-only-pin","-o","result.bin")
                result=pathlib.Path("result.bin").read_bytes()
                assert len(result)==70 and result[:4]==b"\x00\x44\x00\x20" and result[36:38]==b"\x00\x20"
                assert result[4:36]==peer.exchange(ec.ECDH(),key)
                tpm("tpm2_ecdhzgen","-c","ecdh.ctx","-u","point.bin","-p","wrong-pin","-o","wrong.bin",success=False)
                print("PASS: TPM P-256 ECDH wire format, shared secret, wrong-PIN rejection")
            else:
                message=b"vault-rs/v1/device-operation\x00test transcript"
                pathlib.Path("message").write_bytes(message)
                tpm("tpm2_sign","-c","sign.ctx","-g","sha256","-s","ecdsa","-f","plain","-p","test-only-pin","-o","signature","message")
                key.verify(pathlib.Path("signature").read_bytes(),message,ec.ECDSA(hashes.SHA256()))
                tpm("tpm2_sign","-c","sign.ctx","-g","sha256","-s","ecdsa","-f","plain","-p","wrong-pin","-o","wrong","message",success=False)
                print("PASS: TPM ECDSA DER signature and wrong-PIN rejection")
            tpm("tpm2_flushcontext","-t")
        print("SIMULATION ONLY: no physical non-extractability or theft claim")
    finally:
        sim.terminate()
        sim.wait(timeout=5)
