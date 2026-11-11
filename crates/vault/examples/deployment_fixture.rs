//! PUBLIC SOFTWARE TEST FIXTURE. Never install as a production key provider.
//! Built only as an example executable; absent from the vault-rs binary.
use anyhow::{ensure, Result};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::{sec1::ToSec1Point, Generate},
    SecretKey,
};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use vault_rs::crypto::{decode, encode};

const ROOT: &str = "/opt/vault-deployment-test";
#[derive(Deserialize)]
struct Request {
    usage: vault_rs::keys::KeyUsage,
    operation: String,
    key_id: String,
    data: String,
}
fn main() -> Result<()> {
    let root = Path::new(ROOT);
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--fixture-init") {
        ensure!(
            nix::unistd::geteuid().is_root(),
            "test initialization requires root"
        );
        let uid: u32 = args.get(2).map(String::as_str).unwrap_or("0").parse()?;
        let mut values = serde_json::Map::new();
        for name in ["device", "gate", "witness", "tls"] {
            let key = SecretKey::generate();
            let path = root.join(format!("{name}.fixture-key"));
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(&key.to_bytes())?;
            nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(uid)), None)?;
            values.insert(name.into(), serde_json::json!({
                "agreement": format!("p256:{}", encode(key.public_key().to_sec1_point(false).as_bytes())),
                "signing": encode(key.public_key().to_sec1_point(true).as_bytes())
            }));
        }
        let path = root.join("calls.log");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(uid)), None)?;
        println!("{}", serde_json::Value::Object(values));
    } else {
        let mut input = Vec::new();
        std::io::stdin().take(65537).read_to_end(&mut input)?;
        ensure!(input.len() <= 65536, "test request too large");
        let request: Request = serde_json::from_slice(&input)?;
        ensure!(
            ["device", "gate", "witness", "tls"].contains(&request.key_id.as_str()),
            "unknown fixture"
        );
        ensure!(
            request.usage
                == if request.key_id == "device" {
                    vault_rs::keys::KeyUsage::Interactive
                } else {
                    vault_rs::keys::KeyUsage::Service
                },
            "fixture usage mismatch"
        );
        let key = SecretKey::from_slice(&std::fs::read(
            root.join(format!("{}.fixture-key", request.key_id)),
        )?)?;
        let data = decode(&request.data)?;
        let value = match request.operation.as_str() {
            "sign" => {
                let signature: Signature = SigningKey::from(&key).sign(&data);
                signature.to_der().as_bytes().to_vec()
            }
            "ecdh" => {
                let peer = p256::PublicKey::from_sec1_bytes(&data)?;
                p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
                    .raw_secret_bytes()
                    .to_vec()
            }
            _ => anyhow::bail!("unknown test operation"),
        };
        writeln!(
            OpenOptions::new()
                .append(true)
                .open(root.join("calls.log"))?,
            "{}:{}",
            request.key_id,
            request.operation
        )?;
        println!("{}", serde_json::json!({"value": encode(&value)}));
    }
    Ok(())
}
