//! Runtime long-term keys are opaque native handles only. There is deliberately
//! no resident scalar, encrypted software-key import, or software fallback.
use crate::{
    crypto::ShareUnwrapper,
    native::{NativeConfig, NativeKey},
    witness::ProofSigner,
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
pub use vault_policy::key_policy::{KeyRole, KeyUsage};

pub trait RuntimeKey: ProofSigner + ShareUnwrapper {}
impl RuntimeKey for NativeKey {}
impl RuntimeKey for crate::confidential::AttestedKey {}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RuntimeKeyConfig {
    Native(NativeConfig),
    Attested(crate::confidential::AttestedConfig),
}
impl RuntimeKeyConfig {
    pub fn public_key(&self) -> &str {
        match self {
            Self::Native(c) => &c.public_key,
            Self::Attested(c) => &c.public_key,
        }
    }
    pub fn require_confidential(&self) -> Result<()> {
        ensure!(
            matches!(self, Self::Attested(_)),
            "production service keys require the independent SNP guest"
        );
        Ok(())
    }
    pub fn isolate_from(&self, ai_uid: u32) -> Result<()> {
        ensure!(
            !matches!(self, Self::Native(c) if c.macos_uid == Some(ai_uid)),
            "AI and native key owner must have different UIDs"
        );
        Ok(())
    }
    pub fn open(self, role: KeyRole) -> Result<Box<dyn RuntimeKey>> {
        match self {
            Self::Native(c) => Ok(Box::new(NativeKey::open_for(c, role)?)),
            Self::Attested(c) => Ok(Box::new(crate::confidential::AttestedKey::open(c, role)?)),
        }
    }
}
