use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

/// Synthetic localhost leaf certificate, independent of the OS `openssl` CLI
/// (macOS may ship LibreSSL with different extension encoding defaults).
pub fn localhost_certificate(certificate: &Path, private: &Path) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(private)
        .unwrap();
    output
        .write_all(&key.private_key_to_pem_pkcs8().unwrap())
        .unwrap();
    std::fs::write(certificate, builder.build().to_pem().unwrap()).unwrap();
}
