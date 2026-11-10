//! Service keys: hardware-wrapped at rest, unlocked once into the isolated
//! service. This does not claim that the resident key itself is non-exportable.
use crate::{
    crypto::*,
    external_kem::{self, P256Agreement},
    native::{NativeConfig, NativeKey},
    storage::ProtectedConfig,
    witness::ProofSigner,
};
use anyhow::{ensure, Result};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::{sec1::ToSec1Point, Generate},
    SecretKey,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Signing,
    Agreement,
}
pub struct ResidentKey {
    key: SecretKey,
    public: String,
    purpose: Purpose,
}
fn public(key: &SecretKey, purpose: Purpose) -> String {
    let point = key.public_key().to_sec1_point(purpose == Purpose::Signing);
    format!(
        "{}{}",
        if purpose == Purpose::Agreement {
            "p256:"
        } else {
            ""
        },
        encode(point.as_bytes())
    )
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlainKey {
    purpose: Purpose,
    scalar: String,
}
impl Drop for PlainKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scalar.zeroize();
    }
}
impl ResidentKey {
    pub fn generate(protector_public: &str, purpose: Purpose) -> Result<(ProtectedConfig, String)> {
        let key = SecretKey::generate();
        let plain = PlainKey {
            purpose,
            scalar: encode(key.to_bytes().as_ref()),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&plain)?);
        Ok((
            ProtectedConfig::seal(protector_public, &bytes)?,
            public(&key, purpose),
        ))
    }
    pub fn unlock(
        envelope: &ProtectedConfig,
        protector: &dyn ShareUnwrapper,
        purpose: Purpose,
        expected: &str,
    ) -> Result<Self> {
        let bytes = envelope.open(protector)?;
        let plain: PlainKey = serde_json::from_slice(&bytes)?;
        ensure!(plain.purpose == purpose, "resident key purpose mismatch");
        let scalar = Zeroizing::new(fixed::<32>(&plain.scalar)?);
        let key = SecretKey::from_slice(scalar.as_ref())?;
        let public = public(&key, purpose);
        ensure!(
            public == expected,
            "resident public key differs from pinned configuration"
        );
        Ok(Self {
            key,
            public,
            purpose,
        })
    }
}
impl ProofSigner for ResidentKey {
    fn public_key(&self) -> &str {
        &self.public
    }
    fn sign_bytes(&self, message: &[u8]) -> Result<String> {
        ensure!(
            self.purpose == Purpose::Signing,
            "agreement key cannot sign"
        );
        let key = SigningKey::from(&self.key);
        let signature: Signature = key.sign(message);
        Ok(encode(&signature.to_bytes()))
    }
}
impl P256Agreement for ResidentKey {
    fn public_sec1(&self) -> Result<[u8; 65]> {
        ensure!(
            self.purpose == Purpose::Agreement,
            "signing key cannot decrypt"
        );
        Ok(self
            .key
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()?)
    }
    fn agree(&self, peer: &[u8; 65], _: &str) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(
            self.purpose == Purpose::Agreement,
            "signing key cannot decrypt"
        );
        let peer = p256::PublicKey::from_sec1_bytes(peer)?;
        Ok(Zeroizing::new(
            p256::ecdh::diffie_hellman(self.key.to_nonzero_scalar(), peer.as_affine())
                .raw_secret_bytes()
                .as_slice()
                .try_into()?,
        ))
    }
}
impl ShareUnwrapper for ResidentKey {
    fn public_key(&self) -> &str {
        &self.public
    }
    fn unwrap(&self, ciphertext: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
        let bytes = external_kem::open(self, ciphertext, label.as_bytes(), label)?;
        Ok(Zeroizing::new(bytes.as_slice().try_into()?))
    }
}
pub trait RuntimeKey: ProofSigner + ShareUnwrapper {}
impl RuntimeKey for NativeKey {}
impl RuntimeKey for ResidentKey {}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentConfig {
    pub protector: NativeConfig,
    pub envelope: PathBuf,
    pub purpose: Purpose,
    pub public_key: String,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum RuntimeKeyConfig {
    Native(NativeConfig),
    Resident(ResidentConfig),
}
impl RuntimeKeyConfig {
    pub fn isolate_from(&self, ai_uid: u32) -> Result<()> {
        let config = match self {
            Self::Native(c) => c,
            Self::Resident(c) => &c.protector,
        };
        ensure!(
            config.macos_uid != Some(ai_uid),
            "AI and native key owner must have different UIDs"
        );
        Ok(())
    }
    pub fn open(self) -> Result<Box<dyn RuntimeKey>> {
        match self {
            Self::Native(c) => Ok(Box::new(NativeKey::open(c)?)),
            Self::Resident(c) => {
                crate::runner::protected_path(&c.envelope)?;
                let envelope: ProtectedConfig =
                    serde_json::from_slice(&crate::runner::read_bounded(&c.envelope, 65536)?)?;
                Ok(Box::new(ResidentKey::unlock(
                    &envelope,
                    &NativeKey::open(c.protector)?,
                    c.purpose,
                    &c.public_key,
                )?))
            }
        }
    }
}
