//! RFC 9180 base-mode HPKE receiver for a non-exportable P-256 ECDH key.
//! Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
//! Only seq=0 single-shot messages. Sender uses the upstream hpke implementation.
//! This adapter is test-vector checked, NOT covered by the policy proof.
use crate::crypto::*;
use anyhow::{ensure, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use hpke::{Deserializable, Kem, Serializable};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

pub trait P256Agreement: Send + Sync {
    /// Uncompressed SEC1 public key, exactly 65 bytes.
    fn public_sec1(&self) -> Result<[u8; 65]>;
    /// TPM ZGen / Secure Enclave standard ECDH: returns x-coordinate, 32 bytes.
    fn agree(&self, peer: &[u8; 65], context: &str) -> Result<Zeroizing<[u8; 32]>>;
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrapped {
    pub enc: String,
    pub ct: String,
}
pub fn validate_public(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == 65 && bytes[0] == 4,
        "noncanonical P-256 public key"
    );
    p256::PublicKey::from_sec1_bytes(bytes)?;
    Ok(())
}
pub fn wrap(public: &[u8; 65], info: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    type K = hpke::kem::DhP256HkdfSha256;
    validate_public(public)?;
    let pk = <K as Kem>::PublicKey::from_bytes(public)?;
    let (enc, mut ctx) = hpke::setup_sender::<
        hpke::aead::ChaCha20Poly1305,
        hpke::kdf::HkdfSha256,
        K,
    >(&hpke::OpModeS::Base, &pk, info)?;
    Ok(serde_json::to_vec(&Wrapped {
        enc: encode(&enc.to_bytes()),
        ct: encode(&ctx.seal(plaintext, info)?),
    })?)
}
fn extract(salt: &[u8], suite: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(Vec::new());
    input.extend_from_slice(b"HPKE-v1");
    input.extend_from_slice(suite);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    let mut out = Zeroizing::new([0; 32]);
    out.copy_from_slice(&prk);
    out
}
fn expand<const N: usize>(
    prk: &[u8],
    suite: &[u8],
    label: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; N]>> {
    let mut labeled = Vec::new();
    labeled.extend_from_slice(&(N as u16).to_be_bytes());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let mut out = Zeroizing::new([0; N]);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| anyhow::anyhow!("invalid HPKE PRK"))?
        .expand(&labeled, out.as_mut())
        .map_err(|_| anyhow::anyhow!("invalid HPKE expansion"))?;
    Ok(out)
}
pub fn open(
    agreement: &dyn P256Agreement,
    encoded: &[u8],
    info: &[u8],
    context: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    open_with_aad(agreement, encoded, info, info, context)
}
fn open_with_aad(
    agreement: &dyn P256Agreement,
    encoded: &[u8],
    info: &[u8],
    aad: &[u8],
    context: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let wrapped: Wrapped = serde_json::from_slice(encoded)?;
    let enc = fixed::<65>(&wrapped.enc)?;
    let pk = agreement.public_sec1()?;
    validate_public(&enc)?;
    validate_public(&pk)?;
    let dh = agreement.agree(&enc, context)?;
    let kem_suite = b"KEM\x00\x10";
    let eae = extract(&[], kem_suite, b"eae_prk", dh.as_ref());
    let mut kem_context = Vec::from(enc);
    kem_context.extend_from_slice(&pk);
    let shared = expand::<32>(eae.as_ref(), kem_suite, b"shared_secret", &kem_context)?;
    let suite = b"HPKE\x00\x10\x00\x01\x00\x03";
    let psk_id_hash = extract(&[], suite, b"psk_id_hash", &[]);
    let info_hash = extract(&[], suite, b"info_hash", info);
    let mut key_context = vec![0];
    key_context.extend_from_slice(psk_id_hash.as_ref());
    key_context.extend_from_slice(info_hash.as_ref());
    let secret = extract(shared.as_ref(), suite, b"secret", &[]);
    let key = expand::<32>(secret.as_ref(), suite, b"key", &key_context)?;
    let nonce = expand::<12>(secret.as_ref(), suite, b"base_nonce", &key_context)?;
    let plaintext = ChaCha20Poly1305::new_from_slice(key.as_ref())?
        .decrypt(
            Nonce::from_slice(nonce.as_ref()),
            Payload {
                msg: &decode(&wrapped.ct)?,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("HPKE authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::{sec1::ToSec1Point, Generate};
    struct Software(p256::SecretKey);
    #[test]
    fn rfc9180_published_known_answer_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/rfc9180-p256.json")).unwrap();
        let bytes = |s: &serde_json::Value| hex::decode(s.as_str().unwrap()).unwrap();
        let sk = Software(p256::SecretKey::from_slice(&bytes(&v["skRm"])).unwrap());
        assert_eq!(sk.public_sec1().unwrap().as_slice(), bytes(&v["pkRm"]));
        let e = &v["encryptions"][0];
        let wrapped = serde_json::to_vec(&Wrapped {
            enc: encode(&bytes(&v["enc"])),
            ct: encode(&bytes(&e["ct"])),
        })
        .unwrap();
        assert_eq!(
            &*open_with_aad(
                &sk,
                &wrapped,
                &bytes(&v["info"]),
                &bytes(&e["aad"]),
                "RFC vector"
            )
            .unwrap(),
            &bytes(&e["pt"])
        );
    }
    impl P256Agreement for Software {
        fn public_sec1(&self) -> Result<[u8; 65]> {
            Ok(self
                .0
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()?)
        }
        fn agree(&self, peer: &[u8; 65], _: &str) -> Result<Zeroizing<[u8; 32]>> {
            let pk = p256::PublicKey::from_sec1_bytes(peer)?;
            Ok(Zeroizing::new(
                p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), pk.as_affine())
                    .raw_secret_bytes()
                    .as_slice()
                    .try_into()?,
            ))
        }
    }
    #[test]
    fn external_receiver_interoperates_with_upstream_sender_and_binds_info() {
        for _ in 0..32 {
            let sk = Software(p256::SecretKey::generate());
            let pk = sk.public_sec1().unwrap();
            let enc = wrap(&pk, b"record binding", b"test-only-share").unwrap();
            assert_eq!(
                &*open(&sk, &enc, b"record binding", "test").unwrap(),
                b"test-only-share"
            );
            assert!(open(&sk, &enc, b"wrong record", "test").is_err());
            assert!(open(
                &Software(p256::SecretKey::generate()),
                &enc,
                b"record binding",
                "test"
            )
            .is_err());
        }
    }
}
