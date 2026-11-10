//! Explicit administrator approvals, through the same native key UI/PIN path.
//! This is not a network signer. The typed transcript is displayed by the helper.
use crate::{
    crypto::*,
    native::{NativeConfig, NativeKey},
    witness::ProofSigner,
};
use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::{io::Read, path::Path};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Kind {
    Grant,
    GuardianOperation,
    Revoke,
    Quarantine,
    Release,
    Review,
    Deployment,
}

fn typed<T: DeserializeOwned + Serialize>(
    domain: &str,
    input: &[u8],
    key: &dyn ProofSigner,
) -> Result<String> {
    let payload: T = serde_json::from_slice(input)?;
    let signature = key.sign_bytes(&transcript(domain, &payload)?)?;
    Ok(serde_json::to_string(&Signed { payload, signature })?)
}
pub fn approve(config: &Path, kind: Kind) -> Result<String> {
    ensure!(
        nix::unistd::getuid().is_root() && nix::unistd::geteuid().is_root(),
        "administrator approval identity required"
    );
    crate::runner::protected_path(config)?;
    let native: NativeConfig =
        serde_json::from_slice(&crate::runner::read_bounded(config, 65536)?)?;
    let key = NativeKey::open(native)?;
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input)?;
    ensure!(input.len() <= 16384, "approval transcript too large");
    match kind {
        Kind::Grant => typed::<crate::protocol::Grant>("owner-grant", &input, &key),
        Kind::GuardianOperation => {
            typed::<crate::protocol::Operation>("guardian-operation", &input, &key)
        }
        Kind::Revoke => typed::<crate::protocol::Revocation>("owner-revoke", &input, &key),
        Kind::Quarantine => typed::<crate::protocol::Quarantine>("owner-quarantine", &input, &key),
        Kind::Release => typed::<crate::readiness::Release>("release-acceptance", &input, &key),
        Kind::Review => typed::<crate::readiness::Review>("independent-review", &input, &key),
        Kind::Deployment => {
            typed::<crate::readiness::Deployment>("deployment-acceptance", &input, &key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
    struct K(SigningKey, String);
    impl ProofSigner for K {
        fn public_key(&self) -> &str {
            &self.1
        }
        fn sign_bytes(&self, bytes: &[u8]) -> Result<String> {
            use p256::ecdsa::{signature::Signer, Signature};
            let sig: Signature = self.0.sign(bytes);
            Ok(encode(&sig.to_bytes()))
        }
    }
    #[test]
    fn typed_approval_normalizes_json_and_separates_domains() {
        let key = SigningKey::generate();
        let key = K(key.clone(), public(&key));
        let v = uuid::Uuid::new_v4();
        let g = uuid::Uuid::new_v4();
        let raw = format!("{{\"grant\":\"{g}\", \"vault\":\"{v}\"}}");
        let signed =
            typed::<crate::protocol::Revocation>("owner-revoke", raw.as_bytes(), &key).unwrap();
        let signed: Signed<crate::protocol::Revocation> = serde_json::from_str(&signed).unwrap();
        verify("owner-revoke", &signed, key.public_key()).unwrap();
        assert!(verify("owner-quarantine", &signed, key.public_key()).is_err());
        let bad = format!("{{\"grant\":\"{g}\",\"vault\":\"{v}\",\"extra\":true}}");
        assert!(
            typed::<crate::protocol::Revocation>("owner-revoke", bad.as_bytes(), &key).is_err()
        );
    }
}
