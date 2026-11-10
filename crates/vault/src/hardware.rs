//! Strict PKCS#11 adapter for externally enrolled hardware tokens.
//! Token claims are assertions by a pinned, trusted module, NOT remote attestation.
//! This adapter requires a protected authentication path on EVERY fresh session.
use crate::{crypto::*, witness::ProofSigner};
use anyhow::{ensure, Context, Result};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource},
        Mechanism, MechanismType,
    },
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
};
use p256::ecdsa::{signature::Verifier, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ModuleConfig {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub token_serial: String,
    pub key_id_hex: String,
    pub public_key: String,
}

pub struct HardwareModule {
    context: Pkcs11,
    operation_lock: Mutex<()>,
}
impl HardwareModule {
    pub fn open(config: &ModuleConfig) -> Result<Arc<Self>> {
        let canonical = config.path.canonicalize()?;
        ensure!(
            canonical == config.path && canonical.is_absolute(),
            "module path must be absolute and canonical"
        );
        // Loading a module executes native code. Only an OS-admin-controlled path
        // is allowed; signatures do not make an attacker-writable path safe.
        for p in canonical.ancestors() {
            let m = std::fs::metadata(p)?;
            ensure!(
                m.uid() == 0 && m.mode() & 0o022 == 0,
                "PKCS#11 module and ancestors must be root-owned and not group/world writable"
            );
        }
        let hash = hex::encode(Sha256::digest(std::fs::read(&canonical)?));
        ensure!(hash == config.sha256, "PKCS#11 module digest mismatch");
        let context = Pkcs11::new(&canonical)?;
        context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        Ok(Arc::new(Self {
            context,
            operation_lock: Mutex::new(()),
        }))
    }
    pub fn key(self: &Arc<Self>, config: KeyConfig) -> Result<HardwareKey> {
        ensure!(!config.token_serial.is_empty(), "token serial required");
        let id = hex::decode(&config.key_id_hex)?;
        ensure!(!id.is_empty() && id.len() <= 64, "invalid key ID");
        Ok(HardwareKey {
            module: self.clone(),
            config,
            id,
        })
    }
}
pub struct HardwareKey {
    module: Arc<HardwareModule>,
    config: KeyConfig,
    id: Vec<u8>,
}
impl HardwareKey {
    fn session(&self) -> Result<(Session, ObjectHandle)> {
        let mut selected = None;
        for slot in self.module.context.get_slots_with_token()? {
            let token = self.module.context.get_token_info(slot)?;
            if token.serial_number().trim() == self.config.token_serial {
                ensure!(selected.is_none(), "ambiguous hardware token");
                ensure!(
                    self.module.context.get_slot_info(slot)?.hardware_slot(),
                    "software token rejected"
                );
                ensure!(
                    token.protected_authentication_path(),
                    "protected authentication path required; no PIN files or environment fallback"
                );
                selected = Some(slot);
            }
        }
        let session = self
            .module
            .context
            .open_ro_session(selected.context("hardware token unavailable")?)?;
        session.login(UserType::User, None)?;
        let found = session.find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(self.id.clone()),
        ])?;
        ensure!(found.len() == 1, "private key missing or ambiguous");
        let key = found[0];
        let attrs = session.get_attributes(
            key,
            &[
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::NeverExtractable,
                AttributeType::AlwaysSensitive,
                AttributeType::Local,
                AttributeType::AlwaysAuthenticate,
            ],
        )?;
        for expected in [
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::NeverExtractable(true),
            Attribute::AlwaysSensitive(true),
            Attribute::Local(true),
        ] {
            ensure!(
                attrs.contains(&expected),
                "hardware key provenance/extraction policy rejected"
            );
        }
        ensure!(
            attrs.contains(&Attribute::AlwaysAuthenticate(false)),
            "context-specific authentication is unsupported by this adapter; refusing to downgrade"
        );
        Ok((session, key))
    }
    pub fn check(&self) -> Result<()> {
        let _lock = self
            .module
            .operation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("hardware lock poisoned"))?;
        let (_session, _key) = self.session()?;
        Ok(())
    }
}
impl ProofSigner for HardwareKey {
    fn public_key(&self) -> &str {
        &self.config.public_key
    }
    fn sign_bytes(&self, message: &[u8]) -> Result<String> {
        let _lock = self
            .module
            .operation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("hardware lock poisoned"))?;
        let (session, key) = self.session()?;
        let bytes = session.sign(&Mechanism::Ecdsa, key, &Sha256::digest(message))?;
        let signature = Signature::from_slice(&bytes)?;
        parse_public(&self.config.public_key)?.verify(message, &signature)?;
        Ok(encode(&bytes))
    }
}
impl ShareUnwrapper for HardwareKey {
    fn public_key(&self) -> &str {
        &self.config.public_key
    }
    fn unwrap(&self, ciphertext: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
        rsa_public(&self.config.public_key)?;
        let _lock = self
            .module
            .operation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("hardware lock poisoned"))?;
        let (session, key) = self.session()?;
        let params = PkcsOaepParams::new(
            MechanismType::SHA256,
            PkcsMgfType::MGF1_SHA256,
            PkcsOaepSource::data_specified(label.as_bytes()),
        );
        let bytes =
            Zeroizing::new(session.decrypt(&Mechanism::RsaPkcsOaep(params), key, ciphertext)?);
        ensure!(bytes.len() == 32, "invalid share length");
        let mut out = Zeroizing::new([0; 32]);
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() <= 1_000_000, "configuration too large");
    Ok(serde_json::from_slice(&bytes)?)
}
