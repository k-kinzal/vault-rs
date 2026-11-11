//! Rustls signing with an enrolled native handle. Only the certificate/public
//! key enters Rustls; the long-term TLS private scalar is never loaded here.
//! TLS traffic/session keys still exist in the process and are a separate asset.
use crate::{
    crypto::{decode, parse_public},
    keys::{KeyRole, RuntimeKey, RuntimeKeyConfig},
};
use anyhow::{ensure, Result};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    x509::X509,
};
use rustls::{
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
    SignatureAlgorithm, SignatureScheme,
};
use std::{fmt, path::Path, sync::Arc};

#[derive(Clone)]
struct NativeSigner {
    key: Arc<dyn RuntimeKey>,
    spki: Vec<u8>,
}
impl fmt::Debug for NativeSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeTlsSigningHandle")
    }
}
impl SigningKey for NativeSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.as_slice().into())
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}
impl Signer for NativeSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let sign = || -> Result<Vec<u8>> {
            let raw = decode(&self.key.sign_bytes(message)?)?;
            Ok(p256::ecdsa::Signature::from_slice(&raw)?
                .to_der()
                .as_bytes()
                .to_vec())
        };
        sign().map_err(|_| rustls::Error::General("native TLS signing failed".into()))
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

pub fn public_spki(public: &str) -> Result<Vec<u8>> {
    let key = parse_public(public)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut context = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, key.to_sec1_point(false).as_bytes(), &mut context)?;
    Ok(PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?.public_key_to_der()?)
}

pub fn configuration(
    certificate: &Path,
    config: RuntimeKeyConfig,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    crate::runner::protected_path(certificate)?;
    let pem = crate::runner::read_bounded(certificate, 65536)?;
    let certs = X509::stack_from_pem(&pem)?;
    ensure!(
        !certs.is_empty() && certs.len() <= 8,
        "invalid TLS certificate chain"
    );
    let spki = public_spki(config.public_key())?;
    ensure!(
        certs[0].public_key()?.public_key_to_der()? == spki,
        "TLS certificate does not match enrolled native key"
    );
    let key = config.open(KeyRole::TlsSigning)?;
    let chain = certs
        .into_iter()
        .map(|c| Ok(CertificateDer::from(c.to_der()?)))
        .collect::<Result<Vec<_>>>()?;
    let certified = CertifiedKey::new(
        chain,
        Arc::new(NativeSigner {
            key: Arc::from(key),
            spki,
        }),
    );
    certified.keys_match()?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}
