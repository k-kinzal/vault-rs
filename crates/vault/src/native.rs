//! Native Secure Enclave / TPM adapters communicate with a pinned OS helper.
//! The helper, OS identity checks, and hardware policy are explicit TCB elements.
use crate::{
    crypto::*,
    external_kem::{self, P256Agreement},
    witness::ProofSigner,
};
use anyhow::{ensure, Context, Result};
use p256::ecdsa::{signature::Verifier, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Command, Stdio},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct NativeConfig {
    /// macOS GUI/keychain identity, distinct from the AI account. Linux ignores
    /// no identities: this field must be absent on Linux.
    #[serde(default)]
    pub macos_uid: Option<u32>,
    pub helper: PathBuf,
    pub helper_sha256: String,
    pub key_id: String,
    pub public_key: String,
}
pub struct NativeKey {
    config: NativeConfig,
}
#[derive(Serialize)]
struct HelperRequest<'a> {
    operation: &'a str,
    key_id: &'a str,
    data: String,
    context: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperResponse {
    value: String,
}
impl Drop for HelperResponse {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
impl NativeKey {
    pub fn open(config: NativeConfig) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let uid = config
                .macos_uid
                .context("macOS native keys require a dedicated logged-in key owner UID")?;
            ensure!(
                uid >= 501
                    && nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?.is_some(),
                "invalid macOS key owner"
            );
            crate::runner::protected_path(std::path::Path::new("/bin/launchctl"))?;
            crate::runner::protected_path(std::path::Path::new("/usr/bin/sudo"))?;
        }
        #[cfg(target_os = "linux")]
        ensure!(
            config.macos_uid.is_none(),
            "macOS identity not supported on Linux"
        );
        ensure!(
            config.key_id.len() <= 128
                && !config.key_id.is_empty()
                && config
                    .key_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid native key ID"
        );
        let canonical = config.helper.canonicalize()?;
        ensure!(
            canonical == config.helper && canonical.is_absolute(),
            "native helper requires canonical absolute path"
        );
        for p in canonical.ancestors() {
            let m = std::fs::metadata(p)?;
            ensure!(m.uid()==0&&m.mode()&0o022==0,"native helper and ancestors must be administrator-owned and not writable by other users");
        }
        ensure!(
            hex::encode(Sha256::digest(std::fs::read(canonical)?)) == config.helper_sha256,
            "native helper digest mismatch"
        );
        Ok(Self { config })
    }
    fn invoke(&self, operation: &str, data: &[u8], context: &str) -> Result<Zeroizing<Vec<u8>>> {
        #[cfg(target_os = "linux")]
        let mut command = Command::new(&self.config.helper);
        #[cfg(target_os = "macos")]
        let mut command = {
            let uid = self
                .config
                .macos_uid
                .context("missing macOS key owner")?
                .to_string();
            let mut command = Command::new("/bin/launchctl");
            command
                .args([
                    "asuser",
                    &uid,
                    "/usr/bin/sudo",
                    "-n",
                    "-H",
                    "-u",
                    &format!("#{uid}"),
                    "--",
                ])
                .arg(&self.config.helper);
            command
        };
        let mut child = command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let request = HelperRequest {
            operation,
            key_id: &self.config.key_id,
            data: encode(data),
            context,
        };
        let bytes = serde_json::to_vec(&request)?;
        child
            .stdin
            .take()
            .context("helper stdin unavailable")?
            .write_all(&bytes)?;
        let output = child.wait_with_output()?;
        ensure!(output.status.success(), "native key operation denied");
        ensure!(output.stdout.len() <= 4096, "invalid helper response");
        let raw = Zeroizing::new(output.stdout);
        let response: HelperResponse = serde_json::from_slice(&raw)?;
        Ok(Zeroizing::new(decode(&response.value)?))
    }
}
impl P256Agreement for NativeKey {
    fn public_sec1(&self) -> Result<[u8; 65]> {
        fixed(
            self.config
                .public_key
                .strip_prefix("p256:")
                .context("agreement key requires p256 public format")?,
        )
    }
    fn agree(&self, peer: &[u8; 65], context: &str) -> Result<Zeroizing<[u8; 32]>> {
        external_kem::validate_public(peer)?;
        let value = self.invoke("ecdh", peer, context)?;
        Ok(Zeroizing::new(value.as_slice().try_into()?))
    }
}
impl ShareUnwrapper for NativeKey {
    fn public_key(&self) -> &str {
        &self.config.public_key
    }
    fn unwrap(&self, ciphertext: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
        let share = external_kem::open(self, ciphertext, label.as_bytes(), label)?;
        Ok(Zeroizing::new(share.as_slice().try_into()?))
    }
}
impl ProofSigner for NativeKey {
    fn public_key(&self) -> &str {
        &self.config.public_key
    }
    fn sign_bytes(&self, message: &[u8]) -> Result<String> {
        let bytes = self.invoke(
            "sign",
            message,
            "vault-rs signed operation; inspect complete transcript",
        )?;
        let signature = Signature::from_der(&bytes)?;
        parse_public(&self.config.public_key)?.verify(message, &signature)?;
        Ok(encode(&signature.to_bytes()))
    }
}
