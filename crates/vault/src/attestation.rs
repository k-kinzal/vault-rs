//! AMD SEV-SNP verification. Production roots come from the pinned sev crate;
//! neither requests nor policy files may replace the AMD root or signing CA.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sev::{
    certs::snp::{builtin, ca, Certificate, Chain, Verifiable},
    firmware::{guest::AttestationReport, host::TcbVersion},
    parser::ByteParser,
};
use std::path::PathBuf;
use vault_policy::attestation::{accepted, Evidence};
use x509_cert::der::Decode;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    Milan,
    Genoa,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnpPolicy {
    pub product: Product,
    /// Exact launch digest of an independently reviewed immutable guest image.
    pub measurement: String,
    /// Component order: bootloader, TEE, SNP, microcode. Not lexicographic.
    pub minimum_tcb: [u8; 4],
    /// Locally enrolled VCEK, never fetched from a request-controlled URL.
    pub vcek: PathBuf,
    /// Limits stale approval / revocation exposure. Requires a trusted clock.
    pub expires_at: u64,
}

pub struct SnpVerifier {
    policy: SnpPolicy,
    measurement: [u8; 48],
    chain: Chain,
    endorsed_tcb: [u8; 4],
    chip_id: [u8; 64],
}
fn component(t: TcbVersion) -> [u8; 4] {
    [t.bootloader, t.tee, t.snp, t.microcode]
}
fn certificate_fields(der: &[u8]) -> Result<([u8; 4], [u8; 64])> {
    let certificate = x509_cert::Certificate::from_der(der)?;
    let extensions = certificate
        .tbs_certificate
        .extensions
        .context("VCEK extensions missing")?;
    let value = |oid: &str| -> Result<&[u8]> {
        let oid: x509_cert::der::asn1::ObjectIdentifier = oid.parse()?;
        let mut matches = extensions.iter().filter(|e| e.extn_id == oid);
        let item = matches.next().context("VCEK endorsement field missing")?;
        ensure!(matches.next().is_none(), "duplicate VCEK endorsement field");
        Ok(item.extn_value.as_bytes())
    };
    let mut tcb = [0; 4];
    for (index, suffix) in [1, 2, 3, 8].iter().enumerate() {
        tcb[index] = u8::from_der(value(&format!("1.3.6.1.4.1.3704.1.3.{suffix}"))?)?;
    }
    // AMD's HWID extension contains the raw 64 bytes, not a nested OCTET STRING.
    let chip: [u8; 64] = value("1.3.6.1.4.1.3704.1.4")?.try_into()?;
    Ok((tcb, chip))
}
impl SnpVerifier {
    pub fn open(policy: SnpPolicy) -> Result<Self> {
        ensure!(
            policy.minimum_tcb != [0; 4],
            "an independently approved minimum TCB is required"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        ensure!(policy.expires_at > now && policy.expires_at - now <= 86400,
            "offline endorsement approval must expire within 24 hours; refresh revocation review before renewal");
        crate::runner::protected_path(&policy.vcek)?;
        let certificate =
            Certificate::from_pem(&crate::runner::read_bounded(&policy.vcek, 16384)?)?;
        let (ark, ask) = match policy.product {
            Product::Milan => (builtin::milan::ark()?, builtin::milan::ask()?),
            Product::Genoa => (builtin::genoa::ark()?, builtin::genoa::ask()?),
        };
        let chain = Chain {
            ca: ca::Chain { ark, ask },
            vek: certificate,
        };
        chain.verify()?;
        let measurement: [u8; 48] = hex::decode(&policy.measurement)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("SNP measurement must contain 48 bytes"))?;
        ensure!(measurement != [0; 48], "zero launch measurement forbidden");
        let (endorsed_tcb, chip_id) = certificate_fields(&chain.vek.to_der()?)?;
        ensure!(
            vault_policy::attestation::tcb_at_least(endorsed_tcb, policy.minimum_tcb),
            "enrolled VCEK below minimum TCB"
        );
        Ok(Self {
            policy,
            measurement,
            chain,
            endorsed_tcb,
            chip_id,
        })
    }
    pub fn verify(&self, bytes: &[u8], expected_data: &[u8; 64], now: u64) -> Result<()> {
        ensure!(now < self.policy.expires_at, "SNP approval expired");
        let report = AttestationReport::from_bytes(bytes)?;
        ensure!(
            matches!(report.version, 2 | 3),
            "unsupported SNP report version"
        );
        ensure!(
            report.sig_algo == 1 && report.to_bytes()?.as_slice() == bytes,
            "noncanonical SNP report"
        );
        let now_asn1 = openssl::asn1::Asn1Time::from_unix(now.try_into()?)?;
        let certificate_valid = [&self.chain.ca.ark, &self.chain.ca.ask, &self.chain.vek]
            .into_iter()
            .all(|c| {
                let c: &openssl::x509::X509 = c.into();
                c.not_before() <= now_asn1.as_ref() && c.not_after() >= now_asn1.as_ref()
            });
        let evidence = Evidence {
            signature_valid: (&self.chain, &report).verify().is_ok(),
            certificate_valid,
            endorsed_tcb_matches: component(report.reported_tcb) == self.endorsed_tcb
                && report.chip_id == self.chip_id
                && !report.key_info.mask_chip_key(),
            measurement_matches: report.measurement == self.measurement,
            request_matches: vault_policy::attestation::bindings_match(
                &report.measurement,
                &self.measurement,
                &report.report_data,
                expected_data,
                &report.chip_id,
                &self.chip_id,
            ),
            vmpl: report.vmpl,
            debug: report.policy.debug_allowed(),
            migration: report.policy.migrate_ma_allowed(),
            smt: report.policy.smt_allowed() || report.plat_info.smt_enabled(),
            signing_key_is_vcek: report.key_info.signing_key() == 0,
            reported_tcb: component(report.reported_tcb),
            current_tcb: component(report.current_tcb),
            committed_tcb: component(report.committed_tcb),
            launch_tcb: component(report.launch_tcb),
        };
        ensure!(
            accepted(evidence, self.policy.minimum_tcb),
            "SNP boundary rejected"
        );
        Ok(())
    }
}

pub fn quote(data: [u8; 64]) -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileTypeExt;
        ensure!(
            std::fs::metadata("/dev/sev-guest")?
                .file_type()
                .is_char_device(),
            "SNP guest device required"
        );
        Ok(sev::firmware::guest::Firmware::open()?.get_report(None, Some(data), Some(0))?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = data;
        anyhow::bail!("attested service keys require the independent Linux SNP guest")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{X509NameBuilder, X509},
    };
    const TIME: u64 = 1_700_000_000;
    pub(crate) fn synthetic_at(
        time: u64,
    ) -> (
        SnpVerifier,
        AttestationReport,
        EcKey<openssl::pkey::Private>,
    ) {
        let ec = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap();
        let key = PKey::from_ec_key(ec.clone()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "SYNTHETIC TEST ONLY")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::from_unix(time as i64 - 1).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::from_unix(time as i64 + 100).unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::sha384()).unwrap();
        let cert = Certificate::from(certificate.build());
        let tcb = TcbVersion::new(None, 2, 3, 4, 5);
        let report = AttestationReport {
            version: 2,
            sig_algo: 1,
            policy: (1u64 << 17).into(),
            measurement: [7; 48],
            chip_id: [9; 64],
            report_data: [42; 64],
            current_tcb: tcb,
            committed_tcb: tcb,
            reported_tcb: tcb,
            launch_tcb: tcb,
            ..Default::default()
        };
        let verifier = SnpVerifier {
            policy: SnpPolicy {
                product: Product::Milan,
                measurement: hex::encode(report.measurement),
                minimum_tcb: [2, 3, 4, 5],
                vcek: PathBuf::new(),
                expires_at: time + 100,
            },
            measurement: report.measurement,
            chain: Chain {
                ca: ca::Chain {
                    ark: cert.clone(),
                    ask: cert.clone(),
                },
                vek: cert,
            },
            endorsed_tcb: [2, 3, 4, 5],
            chip_id: report.chip_id,
        };
        (verifier, report, ec)
    }
    pub(crate) fn sign(
        mut report: AttestationReport,
        key: &EcKey<openssl::pkey::Private>,
    ) -> Vec<u8> {
        report.signature = openssl::ecdsa::EcdsaSig::sign(
            &openssl::sha::sha384(&report.to_bytes().unwrap()[..0x2a0]),
            key,
        )
        .unwrap()
        .into();
        report.to_bytes().unwrap().to_vec()
    }
    #[test]
    fn synthetic_quote_accepts_exact_policy_and_rejects_each_boundary_change() {
        let (verifier, report, key) = synthetic_at(TIME);
        let good = sign(report, &key);
        verifier.verify(&good, &[42; 64], TIME).unwrap();
        assert!(verifier.verify(&good, &[43; 64], TIME).is_err());
        assert!(verifier.verify(&good, &[42; 64], TIME + 100).is_err());
        assert!(verifier.verify(&good, &[42; 64], TIME - 2).is_err());
        assert!(verifier
            .verify(&good[..good.len() - 1], &[42; 64], TIME)
            .is_err());
        let mut corrupt = good.clone();
        corrupt[80] ^= 1;
        assert!(verifier.verify(&corrupt, &[42; 64], TIME).is_err());
        for change in 0..11 {
            let mut changed = report;
            match change {
                0 => changed.vmpl = 1,
                1 => changed.policy.set_debug_allowed(true),
                2 => changed.policy.set_migrate_ma_allowed(true),
                3 => changed.policy.set_smt_allowed(true),
                4 => changed.measurement[0] ^= 1,
                5 => changed.chip_id[0] ^= 1,
                6 => changed.reported_tcb.snp += 1, // Cannot claim a newer TCB than the VCEK endorses.
                7 => changed.current_tcb.tee -= 1,
                8 => changed.launch_tcb.microcode -= 1,
                9 => changed.committed_tcb.bootloader -= 1,
                _ => changed.report_data[0] ^= 1,
            }
            assert!(
                verifier
                    .verify(&sign(changed, &key), &[42; 64], TIME)
                    .is_err(),
                "boundary {change}"
            );
        }
    }
    #[test]
    fn public_amd_vector_checks_root_signature_and_endorsement_fields() {
        let vcek =
            Certificate::from_der(include_bytes!("../tests/fixtures/snp/vcek_milan.der")).unwrap();
        let chain = Chain {
            ca: ca::Chain {
                ark: builtin::milan::ark().unwrap(),
                ask: builtin::milan::ask().unwrap(),
            },
            vek: vcek,
        };
        let bytes = hex::decode(include_bytes!("../tests/fixtures/snp/report_milan.hex")).unwrap();
        let report = AttestationReport::from_bytes(&bytes).unwrap();
        (&chain, &report).verify().unwrap();
        let (tcb, chip) = certificate_fields(&chain.vek.to_der().unwrap()).unwrap();
        assert_eq!(tcb, component(report.reported_tcb));
        assert_eq!(chip, report.chip_id);
        let mut changed = report;
        changed.report_data[0] ^= 1;
        assert!((&chain, &changed).verify().is_err());
        let (fake, _, _) = synthetic_at(TIME);
        assert!(
            (&chain.ca.ask, &fake.chain.vek).verify().is_err(),
            "synthetic signer cannot chain to AMD"
        );
    }
}
