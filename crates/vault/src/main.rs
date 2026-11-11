use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{io::Read, path::PathBuf};
use vault_rs::crypto::*;
use vault_rs::keys::KeyRole;

#[derive(Parser)]
#[command(
    version,
    about = "Dual-authorized E2E Vault; authenticated deployment acceptance required"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Args)]
struct ReceiptArgs {
    #[arg(long)]
    receipt_key: PathBuf,
    #[arg(long)]
    receipt_nonce: String,
}
#[derive(Subcommand)]
enum Command {
    /// Initialize an encrypted DB generation before measuring deployment acceptance.
    InitializeStorage {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        key_config: PathBuf,
        #[command(flatten)]
        receipt: ReceiptArgs,
    },
    /// Offline SQLCipher generation rotation; refuses while a service holds the DB.
    RotateStorage {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        old_key: PathBuf,
        #[arg(long)]
        new_key: PathBuf,
        #[command(flatten)]
        receipt: ReceiptArgs,
        #[arg(long)]
        source_sha256: String,
    },
    /// Re-encrypt provider/service-key configuration under a new protector.
    RewrapConfig {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        old_key: PathBuf,
        #[arg(long)]
        new_key: PathBuf,
        #[command(flatten)]
        receipt: ReceiptArgs,
        #[arg(long)]
        source_sha256: String,
    },
    /// Sign a typed approval using a separately administered native key and its UI.
    Approve {
        #[arg(long)]
        key_config: PathBuf,
        #[arg(long, value_enum)]
        kind: vault_rs::approval::Kind,
    },
    /// Report actual deployment measurements; this does not assert acceptance.
    Observe {
        #[arg(long)]
        config: PathBuf,
    },
    /// Authenticated observation from a fixed measured SNP maintenance image.
    ObserveAttested {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        expected_envelope_sha256: String,
        #[command(flatten)]
        receipt: ReceiptArgs,
    },
    /// Verify a provisioning receipt using the operator's out-of-band intent.
    VerifyReceipt {
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Hash the full workload bundle and arguments for an owner's grant.
    MeasureBundle {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Administrator-started broker; tools receive plaintext only via private stdin.
    Broker {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        acceptance: Option<PathBuf>,
        #[arg(long)]
        verification_run: bool,
    },
    #[command(hide = true)]
    IsolatedWorker {
        #[arg(long)]
        spec: String,
    },
    /// Encrypt stdin locally using two public keys. Output contains no plaintext.
    Seal {
        #[arg(long)]
        vault: uuid::Uuid,
        #[arg(long)]
        resource: uuid::Uuid,
        #[arg(long)]
        version: u64,
        #[arg(long)]
        device_public: PathBuf,
        #[arg(long)]
        guardian_public: PathBuf,
    },
    /// Encrypt a trusted provider configuration from stdin to its hardware key.
    ProtectConfig {
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Start the identical HTTPS service on a local or network address. Hardware only.
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        acceptance: Option<PathBuf>,
        #[arg(long)]
        verification_run: bool,
    },
    /// Start an independently administered monotonic witness. Hardware only.
    Witness {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        acceptance: Option<PathBuf>,
        #[arg(long)]
        verification_run: bool,
    },
    /// Start the independent native-key custodian for measured SNP guests.
    Custodian {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        acceptance: PathBuf,
    },
    /// Report assurance blockers; exits nonzero until deployment evidence exists.
    Readiness {
        #[arg(long)]
        acceptance: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    // Apply before any key/configuration is read, including offline rotation.
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false)?;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    match Cli::parse().command {
        Command::InitializeStorage {
            database,
            key_config,
            receipt,
        } => {
            anyhow::ensure!(
                nix::unistd::getuid().is_root() && nix::unistd::geteuid().is_root(),
                "administrator initialization required"
            );
            vault_rs::runner::protected_path(&key_config)?;
            let parent = database
                .parent()
                .ok_or_else(|| anyhow::anyhow!("database parent missing"))?;
            vault_rs::runner::protected_path(parent)?;
            anyhow::ensure!(
                database.is_absolute() && parent.canonicalize()? == parent,
                "canonical absolute database path required"
            );
            let key: vault_rs::keys::RuntimeKeyConfig =
                serde_json::from_slice(&vault_rs::runner::read_bounded(&key_config, 65536)?)?;
            key.require_confidential()?;
            let protector = key.open(KeyRole::ServiceUnwrap)?;
            let digest = vault_rs::storage::initialize_generation(&database, protector.as_ref())?;
            println!(
                "{}",
                serde_json::to_string(&vault_rs::provisioning::sign(
                    "initialize-storage",
                    &receipt.receipt_nonce,
                    &database,
                    digest,
                    None,
                    &receipt.receipt_key
                )?)?
            );
            Ok(())
        }
        Command::RotateStorage {
            source,
            destination,
            old_key,
            new_key,
            receipt,
            source_sha256,
        } => {
            let (old, new) = rotation_keys(&source, &destination, &old_key, &new_key)?;
            let digest = vault_rs::storage::rotate_generation_checked(
                &source,
                &destination,
                old.as_ref(),
                new.as_ref(),
                &source_sha256,
            )?;
            println!(
                "{}",
                serde_json::to_string(&vault_rs::provisioning::sign(
                    "rotate-storage",
                    &receipt.receipt_nonce,
                    &destination,
                    digest,
                    None,
                    &receipt.receipt_key
                )?)?
            );
            Ok(())
        }
        Command::RewrapConfig {
            source,
            destination,
            old_key,
            new_key,
            receipt,
            source_sha256,
        } => {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let (old, new) = rotation_keys(&source, &destination, &old_key, &new_key)?;
            use sha2::{Digest, Sha256};
            let source_bytes = vault_rs::runner::read_bounded(&source, 100000)?;
            anyhow::ensure!(
                hex::encode(Sha256::digest(&source_bytes)) == source_sha256,
                "source envelope differs from authenticated intent"
            );
            let envelope: vault_rs::storage::ProtectedConfig =
                serde_json::from_slice(&source_bytes)?;
            let next = envelope.rewrap(old.as_ref(), ShareUnwrapper::public_key(new.as_ref()))?;
            let _validation = next.open(new.as_ref())?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&destination)?;
            let bytes = serde_json::to_vec(&next)?;
            let digest = hex::encode(Sha256::digest(&bytes));
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::File::open(
                destination
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("destination parent missing"))?,
            )?
            .sync_all()?;
            println!(
                "{}",
                serde_json::to_string(&vault_rs::provisioning::sign(
                    "rewrap-config",
                    &receipt.receipt_nonce,
                    &destination,
                    digest,
                    None,
                    &receipt.receipt_key
                )?)?
            );
            Ok(())
        }
        Command::Approve { key_config, kind } => {
            println!("{}", vault_rs::approval::approve(&key_config, kind)?);
            Ok(())
        }
        Command::Observe { config } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&vault_rs::readiness::observe(&config)?)?
            );
            Ok(())
        }
        Command::ObserveAttested {
            config,
            expected_envelope_sha256,
            receipt,
        } => {
            let (observed, database) =
                vault_rs::readiness::observe_pinned(&config, &expected_envelope_sha256)?;
            println!(
                "{}",
                serde_json::to_string(&vault_rs::provisioning::sign(
                    "observe",
                    &receipt.receipt_nonce,
                    &database,
                    expected_envelope_sha256,
                    Some(observed),
                    &receipt.receipt_key
                )?)?
            );
            Ok(())
        }
        Command::VerifyReceipt {
            public_key,
            operation,
            nonce,
            output,
        } => {
            let mut bytes = Vec::new();
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 65536, "receipt too large");
            let receipt: Signed<vault_rs::provisioning::Receipt> = serde_json::from_slice(&bytes)?;
            vault_rs::provisioning::verify(
                &receipt,
                std::fs::read_to_string(public_key)?.trim(),
                &operation,
                &nonce,
                &output,
            )?;
            println!("{}", serde_json::to_string(&receipt.payload)?);
            Ok(())
        }
        Command::MeasureBundle { bundle } => {
            let bundle: vault_rs::runner::Bundle = serde_json::from_slice(
                &vault_rs::runner::read_bounded(&bundle, 64 * 1024 * 1024)?,
            )?;
            println!("{}", bundle.hash()?);
            Ok(())
        }
        Command::Broker {
            config,
            acceptance,
            verification_run,
        } => {
            let accepted = require_acceptance(acceptance, &config, verification_run)?;
            let code = tokio::task::spawn_blocking(move || {
                vault_rs::broker::run(config, accepted.map(|a| a.configuration))
            })
            .await??;
            anyhow::ensure!(code == 0, "workload exited with status {code}");
            Ok(())
        }
        Command::IsolatedWorker { spec } => {
            vault_rs::runner::isolated_worker(serde_json::from_str(&spec)?)
        }
        Command::ProtectConfig { public_key } => {
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            let public = std::fs::read_to_string(public_key)?;
            let envelope = vault_rs::storage::ProtectedConfig::seal(public.trim(), &bytes)?;
            println!("{}", serde_json::to_string_pretty(&envelope)?);
            Ok(())
        }
        Command::Seal {
            vault,
            resource,
            version,
            device_public,
            guardian_public,
        } => {
            let mut plaintext = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(65537).read_to_end(&mut plaintext)?;
            let device = std::fs::read_to_string(device_public)?;
            let guardian = std::fs::read_to_string(guardian_public)?;
            let record = seal_record(
                RecordContext {
                    vault,
                    resource,
                    version,
                },
                &plaintext,
                device.trim(),
                guardian.trim(),
            )?;
            println!("{}", serde_json::to_string_pretty(&record)?);
            Ok(())
        }
        Command::Readiness { acceptance, config } => {
            let files = acceptance
                .map(|p| -> Result<vault_rs::readiness::AcceptanceFiles> {
                    Ok(serde_json::from_slice(&vault_rs::runner::read_bounded(
                        &p, 65536,
                    )?)?)
                })
                .transpose()?;
            let report = vault_rs::readiness::report(files.as_ref(), config.as_deref());
            println!("{}", serde_json::to_string(&report)?);
            anyhow::ensure!(
                report.production_ready,
                "deployment assurance is incomplete"
            );
            Ok(())
        }
        Command::Custodian { config, acceptance } => {
            let accepted = require_acceptance(Some(acceptance), &config, false)?.unwrap();
            let config: vault_rs::confidential::CustodianConfig =
                serde_json::from_slice(accepted.configuration.bytes())?;
            config.preflight()?;
            let listen = config.listen;
            let tls = vault_rs::native_tls::configuration(
                &config.certificate,
                vault_rs::keys::RuntimeKeyConfig::Native(config.tls_signing),
            )?;
            let custodian = tokio::task::spawn_blocking(move || {
                vault_rs::confidential::Custodian::open(config.origin, config.custodian_keys)
            })
            .await??;
            axum_server::bind_rustls(listen, tls)
                .serve(vault_rs::confidential::router(custodian).into_make_service())
                .await?;
            Ok(())
        }
        Command::Serve {
            config,
            acceptance,
            verification_run,
        } => {
            let accepted = require_acceptance(acceptance, &config, verification_run)?;
            run(config, false, verification_run, accepted).await
        }
        Command::Witness {
            config,
            acceptance,
            verification_run,
        } => {
            let accepted = require_acceptance(acceptance, &config, verification_run)?;
            run(config, true, verification_run, accepted).await
        }
    }
}
type RuntimeKeys = (
    Box<dyn vault_rs::keys::RuntimeKey>,
    Box<dyn vault_rs::keys::RuntimeKey>,
);
fn rotation_keys(
    source: &std::path::Path,
    destination: &std::path::Path,
    old: &std::path::Path,
    new: &std::path::Path,
) -> Result<RuntimeKeys> {
    anyhow::ensure!(
        nix::unistd::getuid().is_root() && nix::unistd::geteuid().is_root(),
        "administrator rotation required"
    );
    for path in [source, old, new] {
        vault_rs::runner::protected_path(path)?;
    }
    anyhow::ensure!(
        !destination.exists(),
        "rotation destination must be a new generation"
    );
    vault_rs::runner::protected_path(
        destination
            .parent()
            .ok_or_else(|| anyhow::anyhow!("destination parent missing"))?,
    )?;
    let old: vault_rs::keys::RuntimeKeyConfig =
        serde_json::from_slice(&vault_rs::runner::read_bounded(old, 65536)?)?;
    let new: vault_rs::keys::RuntimeKeyConfig =
        serde_json::from_slice(&vault_rs::runner::read_bounded(new, 65536)?)?;
    old.require_confidential()?;
    new.require_confidential()?;
    Ok((
        old.open(KeyRole::ServiceUnwrap)?,
        new.open(KeyRole::ServiceUnwrap)?,
    ))
}
fn require_acceptance(
    path: Option<PathBuf>,
    config: &std::path::Path,
    verification: bool,
) -> Result<Option<vault_rs::readiness::VerifiedDeployment>> {
    if verification {
        anyhow::ensure!(
            path.is_none(),
            "verification mode cannot assert production acceptance"
        );
        eprintln!("VERIFICATION RUN: production_ready=false; no production acceptance claimed");
        return Ok(None);
    }
    let path=path.ok_or_else(||anyhow::anyhow!("production start requires --acceptance; use explicit --verification-run only for tests"))?;
    vault_rs::runner::protected_path(&path)?;
    let files = serde_json::from_slice(&vault_rs::runner::read_bounded(&path, 65536)?)?;
    let accepted = vault_rs::readiness::check_configuration(&files, config)?;
    let deadline = accepted.deadline;
    // Evidence is a lease, not a permanent boolean. Stop accepting operations
    // when it expires; a new signed acceptance requires an explicit restart.
    std::thread::spawn(move || loop {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        if !now.is_ok_and(|t| t.as_secs() < deadline) {
            eprintln!("production acceptance expired or clock unavailable; stopping service");
            std::process::exit(78);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    });
    Ok(Some(accepted))
}
async fn run(
    path: PathBuf,
    witness: bool,
    verification: bool,
    accepted: Option<vault_rs::readiness::VerifiedDeployment>,
) -> Result<()> {
    use std::sync::Arc;
    use vault_rs::service_config::{Backend, ServiceConfig};
    use vault_rs::{
        store::Gate,
        witness::{ProofSigner, RemoteWitness, WitnessAuthority},
    };
    anyhow::ensure!(
        nix::unistd::getuid().is_root() && nix::unistd::geteuid().is_root(),
        "service requires the administrator identity, isolated from the AI account"
    );
    vault_rs::runner::protected_path(&path)?;
    let bytes = match &accepted {
        Some(a) => a.configuration.bytes().to_vec(),
        None => vault_rs::runner::read_bounded(&path, 1_000_000)?,
    };
    let config: ServiceConfig = serde_json::from_slice(&bytes)?;
    if !verification {
        config.require_confidential()?;
    }
    vault_rs::runner::protected_path(&config.certificate)?;
    vault_rs::runner::protected_path(
        config
            .database
            .parent()
            .ok_or_else(|| anyhow::anyhow!("database parent missing"))?,
    )?;
    if let Some(ca) = &config.witness_ca {
        vault_rs::runner::protected_path(ca)?;
    }
    if let Some(provider) = &config.postgres {
        vault_rs::runner::protected_path(&provider.connection_envelope)?;
        if let Some(ca) = &provider.ca {
            vault_rs::runner::protected_path(ca)?;
        }
    }
    let listen = config.listen;
    anyhow::ensure!(
        !verification || listen.ip().is_loopback(),
        "verification servers must bind loopback"
    );
    let tls = vault_rs::native_tls::configuration(&config.certificate, config.tls_signing.clone())?;
    let router = tokio::task::spawn_blocking(move || -> Result<axum::Router> {
        use anyhow::Context;
        let (signer, decryption): (Box<dyn ProofSigner>, Option<Arc<dyn ShareUnwrapper>>) =
            match config.backend {
                Backend::Native {
                    signing,
                    decryption,
                } => (
                    signing.open(KeyRole::ServiceSigning)? as Box<dyn ProofSigner>,
                    decryption
                        .map(|c| {
                            c.open(KeyRole::ServiceUnwrap)
                                .map(|k| Arc::from(k as Box<dyn ShareUnwrapper>))
                        })
                        .transpose()?,
                ),
                #[cfg(feature = "pkcs11")]
                Backend::Pkcs11 {
                    module,
                    signing,
                    decryption,
                } => {
                    let module = vault_rs::hardware::HardwareModule::open(&module)?;
                    let key = module.key(signing)?;
                    key.check()?;
                    let d = decryption
                        .map(|c| -> Result<Arc<dyn ShareUnwrapper>> {
                            let k = module.key(c)?;
                            k.check()?;
                            Ok(Arc::new(k))
                        })
                        .transpose()?;
                    (Box::new(key), d)
                }
            };
        let generation = accepted
            .as_ref()
            .map(|a| a.configuration.database_generation(&config.database))
            .transpose()?;
        if witness {
            let operator = config
                .operator_public_key
                .context("operator_public_key required")?;
            let protector = decryption.context("witness storage decryption key required")?;
            let authority = match generation {
                Some(pin) => WitnessAuthority::open_pinned(
                    &config.database,
                    operator,
                    signer,
                    protector.as_ref(),
                    pin,
                )?,
                None => {
                    WitnessAuthority::open(&config.database, operator, signer, protector.as_ref())?
                }
            };
            Ok(vault_rs::server::witness_router(Arc::new(authority)))
        } else {
            let decryption = decryption.context("decryption key required")?;
            let ca = config.witness_ca.map(std::fs::read).transpose()?;
            let remote = RemoteWitness::new(
                config.witness_url.context("witness_url required")?,
                config
                    .witness_public_key
                    .context("witness_public_key required")?,
                signer,
                ca.as_deref(),
            )?;
            let trust = config.trust.context("trust required")?;
            let gate = match generation {
                Some(pin) => Gate::open_pinned(
                    &config.database,
                    trust,
                    Arc::new(remote),
                    decryption.clone(),
                    pin,
                )?,
                None => Gate::open(
                    &config.database,
                    trust,
                    Arc::new(remote),
                    decryption.clone(),
                )?,
            };
            let issuer = config
                .postgres
                .map(|p| -> Result<Arc<dyn vault_rs::extension::Issuer>> {
                    let bytes = std::fs::read(&p.connection_envelope)?;
                    anyhow::ensure!(bytes.len() <= 100000, "configuration too large");
                    let envelope: vault_rs::storage::ProtectedConfig =
                        serde_json::from_slice(&bytes)?;
                    let connection = envelope.open(decryption.as_ref())?;
                    let issuer: Arc<dyn vault_rs::extension::Issuer> =
                        Arc::new(vault_rs::extension::PostgresIssuer::connect(
                            std::str::from_utf8(&connection)?.trim(),
                            p.ca.as_deref(),
                            p.policy,
                        )?);
                    if let Some(config) = p.extension {
                        Ok(Arc::new(vault_rs::extension_host::SandboxedIssuer::new(
                            issuer,
                            vault_rs::extension_host::ProposalModule::load(&config)?,
                        )))
                    } else {
                        Ok(issuer)
                    }
                })
                .transpose()?;
            if let Some(worker) = issuer.clone() {
                // Independent expiry sweep. DB VALID UNTIL also blocks new logins.
                // Active-session expiry during an issuer outage is NOT guaranteed.
                std::thread::spawn(move || loop {
                    if let Ok(t) =
                        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    {
                        if worker.expire(t.as_secs()).is_err() {
                            eprintln!("lease expiry sweep failed; retrying");
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                });
            }
            Ok(vault_rs::server::router_with_issuer(Arc::new(gate), issuer))
        }
    })
    .await??;
    axum_server::bind_rustls(listen, tls)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}
