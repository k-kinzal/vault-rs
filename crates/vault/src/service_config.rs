//! One typed configuration shared by readiness and the service entry points.
use crate::{keys::RuntimeKeyConfig, protocol::Trust};
use anyhow::{ensure, Result};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Backend {
    Native {
        signing: RuntimeKeyConfig,
        decryption: Option<RuntimeKeyConfig>,
    },
    #[cfg(feature = "pkcs11")]
    Pkcs11 {
        module: crate::hardware::ModuleConfig,
        signing: crate::hardware::KeyConfig,
        decryption: Option<crate::hardware::KeyConfig>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    pub connection_envelope: PathBuf,
    pub ca: Option<PathBuf>,
    pub policy: crate::extension::ProviderPolicy,
    pub extension: Option<crate::extension_host::ExtensionConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub tls_signing: RuntimeKeyConfig,
    pub database: PathBuf,
    pub backend: Backend,
    #[serde(default)]
    pub trust: Option<Trust>,
    #[serde(default)]
    pub witness_url: Option<String>,
    #[serde(default)]
    pub witness_public_key: Option<String>,
    #[serde(default)]
    pub witness_ca: Option<PathBuf>,
    #[serde(default)]
    pub operator_public_key: Option<String>,
    #[serde(default)]
    pub postgres: Option<PostgresConfig>,
}
impl ServiceConfig {
    pub fn require_confidential(&self) -> Result<()> {
        ensure!(
            cfg!(target_os = "linux"),
            "the common service runs inside a Linux SNP guest"
        );
        self.tls_signing.require_confidential()?;
        match &self.backend {
            Backend::Native {
                signing,
                decryption,
            } => {
                signing.require_confidential()?;
                decryption
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("storage protector required"))?
                    .require_confidential()?;
            }
            #[cfg(feature = "pkcs11")]
            Backend::Pkcs11 { .. } => {
                anyhow::bail!("direct PKCS#11 service keys do not establish an SNP memory boundary")
            }
        }
        Ok(())
    }
    /// Readiness must demonstrate a live custodian-approved SNP request, not
    /// merely deserialize an `snp` label. The probe signs a separate domain.
    pub fn attest_live(&self) -> Result<()> {
        self.require_confidential()?;
        crate::native_tls::configuration(&self.certificate, self.tls_signing.clone())?;
        use crate::keys::KeyRole;
        let key = self.tls_signing.clone().open(KeyRole::TlsSigning)?;
        let mut challenge = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);
        let mut message = b"vault-rs/snp-readiness/v1\0".to_vec();
        message.extend_from_slice(&challenge);
        key.sign_bytes(&message)?;
        if let Backend::Native {
            signing,
            decryption: Some(decryption),
        } = &self.backend
        {
            signing
                .clone()
                .open(KeyRole::ServiceSigning)?
                .sign_bytes(&message)?;
            let point = crate::crypto::fixed::<65>(
                decryption
                    .public_key()
                    .strip_prefix("p256:")
                    .ok_or_else(|| anyhow::anyhow!("attested P-256 storage key required"))?,
            )?;
            let label = "vault-rs/snp-readiness-unwrap/v1";
            let ciphertext = crate::external_kem::wrap(&point, label.as_bytes(), &challenge)?;
            let opened = decryption
                .clone()
                .open(KeyRole::ServiceUnwrap)?
                .unwrap(&ciphertext, label)?;
            ensure!(*opened == challenge, "attested storage probe mismatch");
        }
        Ok(())
    }
}

pub fn preflight(bytes: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value.get("backend").is_some() {
        serde_json::from_slice::<ServiceConfig>(bytes)?.attest_live()
    } else if value.get("custodian_keys").is_some() {
        serde_json::from_slice::<crate::confidential::CustodianConfig>(bytes)?.preflight()
    } else {
        crate::broker::preflight(bytes)
    }
}
