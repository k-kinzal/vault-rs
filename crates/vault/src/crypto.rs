//! Standard primitives with domain separation. No Vault-wide data encryption key.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    OpModeS, Serializable,
};
use openssl::{
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Padding,
};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

pub fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
pub fn decode(value: &str) -> Result<Vec<u8>> {
    ensure!(value.len() <= 1_000_000, "encoded value too large");
    B64.decode(value).context("invalid base64url")
}
pub fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid field size"))
}
pub fn digest(bytes: &[u8]) -> String {
    encode(&Sha256::digest(bytes))
}
pub fn object_hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(digest(&serde_json::to_vec(value)?))
}
pub fn transcript<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>> {
    ensure!(!domain.contains('\0'), "invalid domain");
    let mut bytes = format!("vault-rs/v1/{domain}\0").into_bytes();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(bytes)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub payload: T,
    pub signature: String,
}
pub fn public(key: &SigningKey) -> String {
    encode(key.verifying_key().to_sec1_point(true).as_bytes())
}
pub fn parse_public(key: &str) -> Result<VerifyingKey> {
    let raw = fixed::<33>(key)?;
    VerifyingKey::from_sec1_bytes(&raw).context("invalid signing key")
}
pub fn sign<T: Serialize + Clone>(
    domain: &str,
    payload: &T,
    key: &SigningKey,
) -> Result<Signed<T>> {
    let signature: Signature = key.sign(&transcript(domain, payload)?);
    Ok(Signed {
        payload: payload.clone(),
        signature: encode(&signature.to_bytes()),
    })
}
pub fn verify<T: Serialize>(domain: &str, signed: &Signed<T>, key: &str) -> Result<()> {
    let signature = Signature::from_slice(&fixed::<64>(&signed.signature)?)?;
    parse_public(key)?
        .verify(&transcript(domain, &signed.payload)?, &signature)
        .context("invalid signature")
}

pub type RecordContext = vault_policy::wire::RecordContext<Uuid>;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CiphertextRecord {
    pub context: RecordContext,
    pub device_key: String,
    pub guardian_key: String,
    pub device_share: String,
    pub guardian_share: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn share_label(context: &RecordContext, role: &str) -> Result<String> {
    ensure!(role == "device" || role == "guardian", "invalid share role");
    Ok(format!("vault-rs/v1/{role}/{}", object_hash(context)?))
}
pub fn rsa_public(encoded: &str) -> Result<PKey<Public>> {
    let key = PKey::public_key_from_der(&decode(encoded)?)?;
    let rsa = key.rsa()?;
    ensure!(
        (3072..=4096).contains(&rsa.n().num_bits()),
        "RSA key must be 3072..4096 bits"
    );
    ensure!(rsa.e().to_vec() == [1, 0, 1], "RSA exponent must be 65537");
    Ok(key)
}
pub fn rsa_public_encoded(key: &PKey<Public>) -> Result<String> {
    Ok(encode(&key.public_key_to_der()?))
}

/// Public-key format: p256:<base64url SEC1 uncompressed>, or RSA SPKI base64url.
pub fn wrapping_key_hash(encoded: &str) -> Result<String> {
    if let Some(p) = encoded.strip_prefix("p256:") {
        let bytes = fixed::<65>(p)?;
        crate::external_kem::validate_public(&bytes)?;
        let mut domain = b"p256:".to_vec();
        domain.extend(bytes);
        Ok(digest(&domain))
    } else {
        rsa_public(encoded)?;
        Ok(digest(&decode(encoded)?))
    }
}
pub(crate) fn wrap_share(key: &str, label: &str, share: &[u8]) -> Result<Vec<u8>> {
    if let Some(p) = key.strip_prefix("p256:") {
        crate::external_kem::wrap(&fixed::<65>(p)?, label.as_bytes(), share)
    } else {
        let key = rsa_public(key)?;
        let mut e = Encrypter::new(&key)?;
        e.set_rsa_padding(Padding::PKCS1_OAEP)?;
        e.set_rsa_oaep_md(MessageDigest::sha256())?;
        e.set_rsa_mgf1_md(MessageDigest::sha256())?;
        e.set_rsa_oaep_label(label.as_bytes())?;
        let mut out = vec![0; e.encrypt_len(share)?];
        let len = e.encrypt(share, &mut out)?;
        out.truncate(len);
        Ok(out)
    }
}

/// The private RSA operation is intentionally absent from production software.
/// Production adapters must enforce their own physical key and use policy.
pub trait ShareUnwrapper: Send + Sync {
    fn public_key(&self) -> &str;
    fn unwrap(&self, ciphertext: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>>;
}

pub fn seal_record(
    context: RecordContext,
    plaintext: &[u8],
    device: &str,
    guardian: &str,
) -> Result<CiphertextRecord> {
    ensure!(plaintext.len() <= 65536, "secret exceeds 64 KiB");
    let device_key = wrapping_key_hash(device)?;
    let guardian_key = wrapping_key_hash(guardian)?;
    ensure!(
        device_key != guardian_key,
        "share holders must be independent keys"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    let mut a = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    OsRng.fill_bytes(a.as_mut());
    let mut b = Zeroizing::new([0u8; 32]);
    vault_policy::split32(&key, &a, &mut b);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = transcript("record", &context)?;
    let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_ref())?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let device_share = wrap_share(device, &share_label(&context, "device")?, a.as_ref())?;
    let guardian_share = wrap_share(guardian, &share_label(&context, "guardian")?, b.as_ref())?;
    Ok(CiphertextRecord {
        context,
        device_key,
        guardian_key,
        device_share: encode(&device_share),
        guardian_share: encode(&guardian_share),
        nonce: encode(&nonce),
        ciphertext: encode(&ciphertext),
    })
}

pub fn unwrap_share(
    record: &CiphertextRecord,
    role: &str,
    provider: &dyn ShareUnwrapper,
) -> Result<Zeroizing<[u8; 32]>> {
    let (expected, data) = match role {
        "device" => (&record.device_key, &record.device_share),
        "guardian" => (&record.guardian_key, &record.guardian_share),
        _ => bail!("invalid role"),
    };
    ensure!(
        *expected == wrapping_key_hash(provider.public_key())?,
        "wrong share holder"
    );
    provider.unwrap(&decode(data)?, &share_label(&record.context, role)?)
}

pub fn open_record(
    record: &CiphertextRecord,
    device_share: &[u8; 32],
    guardian_share: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = Zeroizing::new([0u8; 32]);
    vault_policy::join32(device_share, guardian_share, &mut key);
    let nonce = fixed::<24>(&record.nonce)?;
    let aad = transcript("record", &record.context)?;
    let plaintext = XChaCha20Poly1305::new_from_slice(key.as_ref())?
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &decode(&record.ciphertext)?,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("record authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

type ResponseKem = X25519HkdfSha256;
pub type RecipientSecret = <ResponseKem as Kem>::PrivateKey;
pub fn recipient_keypair() -> (RecipientSecret, String) {
    let (sk, pk) = ResponseKem::gen_keypair();
    (sk, encode(&pk.to_bytes()))
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SealedResponse {
    pub encapsulation: String,
    pub ciphertext: String,
}
pub fn seal_response(recipient: &str, request_hash: &str, bytes: &[u8]) -> Result<SealedResponse> {
    let pk = <ResponseKem as Kem>::PublicKey::from_bytes(&fixed::<32>(recipient)?)?;
    let (enc, mut ctx) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, ResponseKem>(
        &OpModeS::Base,
        &pk,
        b"vault-rs/v1/response",
    )?;
    Ok(SealedResponse {
        encapsulation: encode(&enc.to_bytes()),
        ciphertext: encode(&ctx.seal(bytes, request_hash.as_bytes())?),
    })
}
pub fn open_response(
    secret: &RecipientSecret,
    request_hash: &str,
    response: &SealedResponse,
) -> Result<Zeroizing<Vec<u8>>> {
    let enc =
        <ResponseKem as Kem>::EncappedKey::from_bytes(&fixed::<32>(&response.encapsulation)?)?;
    let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, ResponseKem>(
        &OpModeR::Base,
        secret,
        &enc,
        b"vault-rs/v1/response",
    )?;
    Ok(Zeroizing::new(ctx.open(
        &decode(&response.ciphertext)?,
        request_hash.as_bytes(),
    )?))
}
