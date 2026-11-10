//! Production acceptance is a verified release/deployment decision. Neither a
//! successful unit test nor a mutable boolean can authorize a production start.
use crate::crypto::*;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize)]
struct InputPin {
    role: String,
    path: PathBuf,
    sha256: String,
}
/// Immutable measurements of the bytes checked against deployment acceptance.
/// Includes the DB key envelope, never the mutable SQLCipher database pages.
pub struct ConfigurationSnapshot {
    bytes: Vec<u8>,
    digest: String,
    pins: Vec<InputPin>,
}
impl ConfigurationSnapshot {
    pub fn read(path: &Path) -> Result<Self> {
        Self::capture(path, true)
    }
    fn capture(path: &Path, protected: bool) -> Result<Self> {
        if protected {
            crate::runner::protected_path(path)?;
        }
        let bytes = crate::runner::read_bounded(path, 1024 * 1024)?;
        let config: serde_json::Value = serde_json::from_slice(&bytes)?;
        let mut pins = Vec::new();
        fn walk(
            v: &serde_json::Value,
            role: &str,
            protected: bool,
            pins: &mut Vec<InputPin>,
        ) -> Result<()> {
            match v {
                serde_json::Value::Object(fields) => {
                    for (key, value) in fields {
                        let label = format!("{role}/{}", key.replace('~', "~0").replace('/', "~1"));
                        if let Some(name) = value.as_str() {
                            if matches!(
                                key.as_str(),
                                "certificate"
                                    | "tls_key"
                                    | "ca"
                                    | "witness_ca"
                                    | "allocator_ca"
                                    | "helper"
                                    | "envelope"
                                    | "connection_envelope"
                                    | "record"
                                    | "bundle"
                                    | "module"
                                    | "path"
                                    | "database"
                            ) {
                                let path = if key == "database" {
                                    PathBuf::from(format!("{name}.key-envelope.json"))
                                } else {
                                    PathBuf::from(name)
                                };
                                ensure!(
                                    path.is_absolute() && path.canonicalize()? == path,
                                    "deployment input must be a canonical absolute path"
                                );
                                if protected {
                                    crate::runner::protected_path(&path)?;
                                }
                                let data = crate::runner::read_bounded(&path, 64 * 1024 * 1024)?;
                                pins.push(InputPin {
                                    role: label.clone(),
                                    path,
                                    sha256: sha(&data),
                                });
                            }
                        }
                        walk(value, &label, protected, pins)?;
                    }
                }
                serde_json::Value::Array(values) => {
                    for (i, value) in values.iter().enumerate() {
                        walk(value, &format!("{role}/{i}"), protected, pins)?;
                    }
                }
                _ => (),
            }
            Ok(())
        }
        walk(&config, "", protected, &mut pins)?;
        pins.sort_by(|a, b| a.role.cmp(&b.role));
        let digest = sha(&serde_json::to_vec(&(
            "vault-rs/deployment-inputs/v2",
            sha(&bytes),
            &pins,
        ))?);
        Ok(Self {
            bytes,
            digest,
            pins,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn database_generation(&self, database: &Path) -> Result<&str> {
        let mut path = database.as_os_str().to_os_string();
        path.push(".key-envelope.json");
        self.pins
            .iter()
            .find(|p| p.path == Path::new(&path) && p.role.ends_with("/database"))
            .map(|p| p.sha256.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("database generation was not covered by deployment acceptance")
            })
    }
}

pub struct VerifiedDeployment {
    pub deadline: u64,
    pub configuration: ConfigurationSnapshot,
}

pub const SOURCE_SHA256: &str = env!("VAULT_SOURCE_SHA256");
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Macos,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Proof,
    SoftwareTest,
    OsIsolation,
    PhysicalDevice,
    FaultInjection,
    OauthIntegration,
    LiveDeployment,
    SandboxTest,
    DatabaseIntegration,
    RecoveryTest,
    UpdateTest,
    RefinementProof,
    IndependentReview,
    DependencyAudit,
    ReproducibleBuild,
}
impl Method {
    fn bit(self) -> u32 {
        1 << (self as u32)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    pub method: Method,
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub goal: u8,
    pub platform: Platform,
    pub passed: bool,
    pub measurements: Vec<Measurement>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    #[serde(default)]
    pub physical_tests_excluded: bool,
    pub schema: u32,
    pub epoch: u64,
    pub source_sha256: String,
    pub linux_binary_sha256: String,
    pub macos_binary_sha256: String,
    pub not_before: u64,
    pub expires: u64,
    pub checks: Vec<Check>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub release_hash: String,
    pub unresolved_findings: u32,
    pub not_before: u64,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub release_hash: String,
    pub host_sha256: String,
    pub platform: Platform,
    pub config_sha256: String,
    pub binary_sha256: String,
    pub not_before: u64,
    pub expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub release: Signed<Release>,
    pub review: Signed<Review>,
    pub deployment: Signed<Deployment>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPolicy {
    #[serde(default)]
    pub allow_physical_test_exclusion: bool,
    pub release_key: String,
    pub review_key: String,
    pub deployment_key: String,
    pub minimum_epoch: u64,
    pub maximum_age_seconds: u64,
}
#[derive(Serialize)]
pub struct Observed {
    pub source_sha256: String,
    pub binary_sha256: String,
    pub config_sha256: String,
    pub host_sha256: String,
    pub platform: Platform,
    pub now: u64,
}
#[derive(Serialize)]
pub struct Report {
    pub production_ready: bool,
    pub source_sha256: String,
    pub blockers: Vec<String>,
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn period(start: u64, end: u64, now: u64, max: u64) -> bool {
    start <= now && now < end && end.checked_sub(start).is_some_and(|v| v <= max)
}

pub fn verify_acceptance(
    policy: &AuthorityPolicy,
    bundle: &Acceptance,
    observed: &Observed,
    logs: &Path,
) -> Result<()> {
    let release_key = parse_public(&policy.release_key)?;
    let review_key = parse_public(&policy.review_key)?;
    let deployment_key = parse_public(&policy.deployment_key)?;
    ensure!(
        release_key != review_key && release_key != deployment_key && review_key != deployment_key,
        "acceptance authorities must be independent pinned keys"
    );
    ensure!(
        policy.minimum_epoch > 0
            && policy.maximum_age_seconds > 0
            && policy.maximum_age_seconds <= 30 * 86400,
        "invalid acceptance policy"
    );
    verify("release-acceptance", &bundle.release, &policy.release_key)?;
    verify("independent-review", &bundle.review, &policy.review_key)?;
    verify(
        "deployment-acceptance",
        &bundle.deployment,
        &policy.deployment_key,
    )?;
    let release = &bundle.release.payload;
    let review = &bundle.review.payload;
    let deploy = &bundle.deployment.payload;
    ensure!(
        !release.physical_tests_excluded || policy.allow_physical_test_exclusion,
        "physical testing exclusion was not authorized by the pinned operator policy"
    );
    ensure!(
        release.schema == 1 && release.epoch >= policy.minimum_epoch,
        "old or unsupported release"
    );
    for (start, end) in [
        (release.not_before, release.expires),
        (review.not_before, review.expires),
        (deploy.not_before, deploy.expires),
    ] {
        ensure!(
            period(start, end, observed.now, policy.maximum_age_seconds),
            "expired or future acceptance evidence"
        );
    }
    ensure!(
        review.unresolved_findings == 0,
        "review has unresolved findings"
    );
    let reference = object_hash(&bundle.release)?;
    ensure!(
        review.release_hash == reference && deploy.release_hash == reference,
        "review/deployment refer to a different release"
    );
    ensure!(
        release.source_sha256 == observed.source_sha256,
        "source does not match acceptance"
    );
    let binary = match observed.platform {
        Platform::Linux => &release.linux_binary_sha256,
        Platform::Macos => &release.macos_binary_sha256,
    };
    ensure!(
        binary == &observed.binary_sha256 && deploy.binary_sha256 == observed.binary_sha256,
        "running binary differs from accepted binary"
    );
    ensure!(
        deploy.host_sha256 == observed.host_sha256
            && deploy.config_sha256 == observed.config_sha256
            && deploy.platform == observed.platform,
        "deployment host/config/platform mismatch"
    );
    for hash in [
        &release.source_sha256,
        &release.linux_binary_sha256,
        &release.macos_binary_sha256,
        &deploy.config_sha256,
        &deploy.host_sha256,
    ] {
        ensure!(hash_valid(hash), "invalid acceptance digest");
    }
    ensure!(
        release.checks.len() == 2 * vault_policy::CRITERIA,
        "incomplete platform/goal coverage"
    );
    let logs = logs.canonicalize()?;
    let mut covered = BTreeSet::new();
    for check in &release.checks {
        ensure!(
            (1..=13).contains(&check.goal) && covered.insert((check.goal, check.platform)),
            "unknown or duplicate acceptance goal"
        );
        ensure!(
            !check.measurements.is_empty() && check.measurements.len() <= 16,
            "missing or excessive measurements"
        );
        let mut methods = 0;
        for m in &check.measurements {
            methods |= m.method.bit();
            let relative = Path::new(&m.path);
            ensure!(
                !m.path.is_empty()
                    && relative
                        .components()
                        .all(|c| matches!(c, Component::Normal(_))),
                "invalid evidence log path"
            );
            let path = logs.join(relative);
            ensure!(path.canonicalize()? == path, "evidence symlink refused");
            ensure!(
                hash_valid(&m.sha256)
                    && sha(&crate::runner::read_bounded(&path, 16 * 1024 * 1024)?) == m.sha256,
                "evidence log modified"
            );
        }
        ensure!(
            vault_policy::acceptance_check_scoped(
                check.goal as usize - 1,
                check.passed,
                methods,
                release.physical_tests_excluded
            ),
            "goal G{:02} on {:?} lacks required passing evidence",
            check.goal,
            check.platform
        );
    }
    Ok(())
}

pub fn observe(config: &Path) -> Result<Observed> {
    observe_snapshot(&ConfigurationSnapshot::read(config)?)
}
fn observe_snapshot(config: &ConfigurationSnapshot) -> Result<Observed> {
    #[cfg(target_os = "linux")]
    let (platform, host) = (
        Platform::Linux,
        crate::runner::read_bounded(Path::new("/etc/machine-id"), 4096)?,
    );
    #[cfg(target_os = "macos")]
    let (platform, host) = {
        let output = std::process::Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .env_clear()
            .output()?;
        ensure!(output.status.success(), "host identity unavailable");
        let text = std::str::from_utf8(&output.stdout)?;
        let line = text
            .lines()
            .find(|l| l.contains("\"IOPlatformUUID\" = "))
            .ok_or_else(|| anyhow::anyhow!("host identity unavailable"))?;
        let uuid = line
            .split('=')
            .nth(1)
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        let uuid = uuid::Uuid::parse_str(uuid)?;
        (Platform::Macos, uuid.as_bytes().to_vec())
    };
    Ok(Observed {
        source_sha256: SOURCE_SHA256.into(),
        binary_sha256: sha(&crate::runner::read_bounded(
            &std::env::current_exe()?,
            128 * 1024 * 1024,
        )?),
        config_sha256: config.digest.clone(),
        host_sha256: sha(&host),
        platform,
        now: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    })
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceFiles {
    pub policy: PathBuf,
    pub bundle: PathBuf,
    pub logs: PathBuf,
}
pub fn check_files(files: &AcceptanceFiles, config: &Path) -> Result<u64> {
    Ok(check_configuration(files, config)?.deadline)
}
pub fn check_configuration(files: &AcceptanceFiles, config: &Path) -> Result<VerifiedDeployment> {
    crate::runner::protected_path(&files.policy)?;
    crate::runner::protected_path(config)?;
    let policy: AuthorityPolicy =
        serde_json::from_slice(&crate::runner::read_bounded(&files.policy, 65536)?)?;
    let bundle: Acceptance = serde_json::from_slice(&crate::runner::read_bounded(
        &files.bundle,
        2 * 1024 * 1024,
    )?)?;
    let configuration = ConfigurationSnapshot::read(config)?;
    verify_acceptance(
        &policy,
        &bundle,
        &observe_snapshot(&configuration)?,
        &files.logs,
    )?;
    let deadline = bundle
        .release
        .payload
        .expires
        .min(bundle.review.payload.expires)
        .min(bundle.deployment.payload.expires);
    Ok(VerifiedDeployment {
        deadline,
        configuration,
    })
}
pub fn report(files: Option<&AcceptanceFiles>, config: Option<&Path>) -> Report {
    let result = match (files, config) {
        (Some(files), Some(config)) => check_files(files, config),
        _ => Err(anyhow::anyhow!(
            "acceptance policy, signed evidence, and deployment config are required"
        )),
    };
    let blockers = match result {
        Ok(_) => Vec::new(),
        Err(e) if files.is_some() => vec![e.to_string()],
        Err(_) => (1..=13)
            .map(|i| format!("G{i:02}: verified release/deployment evidence missing"))
            .collect(),
    };
    Report {
        production_ready: blockers.is_empty(),
        source_sha256: SOURCE_SHA256.into(),
        blockers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
    // Synthetic acceptance fixtures test the validator, NEVER actual deployment
    // readiness. No signed fixture is exported as production evidence.
    struct Fixture {
        dir: tempfile::TempDir,
        keys: [SigningKey; 3],
        policy: AuthorityPolicy,
        bundle: Acceptance,
        observed: Observed,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("measurement.log"),
                b"SYNTHETIC UNIT FIXTURE",
            )
            .unwrap();
            let keys = [
                SigningKey::generate(),
                SigningKey::generate(),
                SigningKey::generate(),
            ];
            let policy = AuthorityPolicy {
                allow_physical_test_exclusion: false,
                release_key: public(&keys[0]),
                review_key: public(&keys[1]),
                deployment_key: public(&keys[2]),
                minimum_epoch: 2,
                maximum_age_seconds: 3600,
            };
            let methods = [
                Method::Proof,
                Method::SoftwareTest,
                Method::OsIsolation,
                Method::PhysicalDevice,
                Method::FaultInjection,
                Method::OauthIntegration,
                Method::LiveDeployment,
                Method::SandboxTest,
                Method::DatabaseIntegration,
                Method::RecoveryTest,
                Method::UpdateTest,
                Method::RefinementProof,
                Method::IndependentReview,
                Method::DependencyAudit,
                Method::ReproducibleBuild,
            ];
            let mut checks = Vec::new();
            for platform in [Platform::Linux, Platform::Macos] {
                for goal in 1..=13 {
                    checks.push(Check {
                        goal,
                        platform,
                        passed: true,
                        measurements: methods
                            .iter()
                            .filter(|m| {
                                m.bit() & vault_policy::REQUIRED_METHODS[goal as usize - 1] != 0
                            })
                            .map(|m| Measurement {
                                method: *m,
                                path: "measurement.log".into(),
                                sha256: sha(b"SYNTHETIC UNIT FIXTURE"),
                            })
                            .collect(),
                    });
                }
            }
            let observed = Observed {
                source_sha256: sha(b"source"),
                binary_sha256: sha(b"linux-binary"),
                config_sha256: sha(b"config"),
                host_sha256: sha(b"host"),
                platform: Platform::Linux,
                now: 100,
            };
            let release = sign(
                "release-acceptance",
                &Release {
                    physical_tests_excluded: false,
                    schema: 1,
                    epoch: 2,
                    source_sha256: observed.source_sha256.clone(),
                    linux_binary_sha256: observed.binary_sha256.clone(),
                    macos_binary_sha256: sha(b"mac-binary"),
                    not_before: 90,
                    expires: 200,
                    checks,
                },
                &keys[0],
            )
            .unwrap();
            let reference = object_hash(&release).unwrap();
            let review = sign(
                "independent-review",
                &Review {
                    release_hash: reference.clone(),
                    unresolved_findings: 0,
                    not_before: 90,
                    expires: 200,
                },
                &keys[1],
            )
            .unwrap();
            let deployment = sign(
                "deployment-acceptance",
                &Deployment {
                    release_hash: reference,
                    host_sha256: observed.host_sha256.clone(),
                    platform: observed.platform,
                    config_sha256: observed.config_sha256.clone(),
                    binary_sha256: observed.binary_sha256.clone(),
                    not_before: 90,
                    expires: 200,
                },
                &keys[2],
            )
            .unwrap();
            Self {
                dir,
                keys,
                policy,
                bundle: Acceptance {
                    release,
                    review,
                    deployment,
                },
                observed,
            }
        }
        fn check(&self) -> Result<()> {
            verify_acceptance(&self.policy, &self.bundle, &self.observed, self.dir.path())
        }
        fn resign(&mut self) {
            self.bundle.release = sign(
                "release-acceptance",
                &self.bundle.release.payload,
                &self.keys[0],
            )
            .unwrap();
            self.bundle.review.payload.release_hash = object_hash(&self.bundle.release).unwrap();
            self.bundle.deployment.payload.release_hash =
                object_hash(&self.bundle.release).unwrap();
            self.bundle.review = sign(
                "independent-review",
                &self.bundle.review.payload,
                &self.keys[1],
            )
            .unwrap();
            self.bundle.deployment = sign(
                "deployment-acceptance",
                &self.bundle.deployment.payload,
                &self.keys[2],
            )
            .unwrap();
        }
    }
    #[test]
    fn transitive_inputs_and_database_generation_are_bound_to_acceptance() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let database = root.join("vault.db");
        let envelope = root.join("vault.db.key-envelope.json");
        let helper = root.join("helper");
        let ca = root.join("ca");
        let module = root.join("extension.wasm");
        let config = root.join("config.json");
        for path in [&database, &envelope, &helper, &ca, &module] {
            std::fs::write(path, b"initial").unwrap();
        }
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "database": database, "backend": {"helper": helper}, "ca": ca,
                "extension": {"module": module}
            }))
            .unwrap(),
        )
        .unwrap();
        let original = ConfigurationSnapshot::capture(&config, false).unwrap();
        assert_eq!(
            original.database_generation(&database).unwrap(),
            sha(b"initial")
        );
        assert_eq!(original.bytes(), std::fs::read(&config).unwrap());
        for path in [&envelope, &helper, &ca, &module] {
            std::fs::write(path, b"replacement").unwrap();
            assert_ne!(
                original.digest(),
                ConfigurationSnapshot::capture(&config, false)
                    .unwrap()
                    .digest()
            );
            std::fs::write(path, b"initial").unwrap();
        }
        std::fs::write(&database, b"normal mutable SQLCipher page").unwrap();
        assert_eq!(
            original.digest(),
            ConfigurationSnapshot::capture(&config, false)
                .unwrap()
                .digest()
        );
        std::fs::remove_file(&envelope).unwrap();
        assert!(ConfigurationSnapshot::capture(&config, false).is_err());
    }
    #[test]
    fn acceptance_positive_validator_fixture() {
        assert!(Fixture::new().check().is_ok());
        assert!(!report(None, None).production_ready);
    }
    #[test]
    fn physical_exclusion_requires_operator_policy_and_signed_release() {
        let mut f = Fixture::new();
        f.bundle.release.payload.physical_tests_excluded = true;
        for c in &mut f.bundle.release.payload.checks {
            if c.goal == 4 || c.goal == 5 {
                for m in &mut c.measurements {
                    if m.method == Method::PhysicalDevice {
                        m.method = Method::SoftwareTest;
                    }
                }
            }
        }
        f.resign();
        assert!(f.check().is_err());
        f.policy.allow_physical_test_exclusion = true;
        assert!(f.check().is_ok());
        f.bundle.release.payload.physical_tests_excluded = false;
        assert!(f.check().is_err());
        f.resign();
        assert!(f.check().is_err());
    }
    #[test]
    fn signed_but_missing_failed_duplicate_or_simulated_evidence_is_rejected() {
        for change in 0..6 {
            let mut f = Fixture::new();
            match change {
                0 => {
                    f.bundle.release.payload.checks.pop();
                }
                1 => f.bundle.release.payload.checks[0].passed = false,
                2 => {
                    f.bundle.release.payload.checks[1] = f.bundle.release.payload.checks[0].clone()
                }
                3 => {
                    f.bundle.release.payload.checks[3].measurements[0].method = Method::SoftwareTest
                }
                4 => f.bundle.release.payload.epoch = 1,
                _ => f.bundle.review.payload.unresolved_findings = 1,
            }
            f.resign();
            assert!(f.check().is_err(), "case {change}");
        }
    }
    #[test]
    fn source_binary_configuration_host_time_and_signature_are_bound() {
        for change in 0..8 {
            let mut f = Fixture::new();
            match change {
                0 => f.observed.source_sha256 = sha(b"new source"),
                1 => f.observed.binary_sha256 = sha(b"new binary"),
                2 => f.observed.config_sha256 = sha(b"new config"),
                3 => f.observed.host_sha256 = sha(b"new host"),
                4 => f.observed.now = 200,
                5 => f.observed.now = 89,
                6 => f.bundle.release.signature = encode(&[0; 64]),
                _ => f.policy.review_key = f.policy.release_key.clone(),
            }
            assert!(f.check().is_err(), "case {change}");
        }
    }
    #[test]
    fn logs_cannot_be_replaced_or_escape_the_evidence_directory() {
        let f = Fixture::new();
        std::fs::write(f.dir.path().join("measurement.log"), b"changed").unwrap();
        assert!(f.check().is_err());
        for path in ["../measurement.log", "/etc/passwd"] {
            let mut f = Fixture::new();
            f.bundle.release.payload.checks[0].measurements[0].path = path.into();
            f.resign();
            assert!(f.check().is_err());
        }
        let f = Fixture::new();
        std::fs::rename(
            f.dir.path().join("measurement.log"),
            f.dir.path().join("original"),
        )
        .unwrap();
        std::os::unix::fs::symlink("original", f.dir.path().join("measurement.log")).unwrap();
        assert!(f.check().is_err());
    }
}
