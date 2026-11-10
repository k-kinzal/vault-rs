//! SQLCipher page/WAL encryption. The wrapping private key stays in its provider;
//! the database key necessarily exists in the trusted service while unlocked.
use crate::crypto::*;
use anyhow::{ensure, Context, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Trusted service configuration, not an E2E user secret. A service must learn
/// its provider credential while running; its on-disk copy is hardware-wrapped.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedConfig {
    id: Uuid,
    public_hash: String,
    wrapped: String,
    nonce: String,
    ciphertext: String,
}
impl ProtectedConfig {
    pub fn rewrap(&self, old: &dyn ShareUnwrapper, new_public: &str) -> Result<Self> {
        Self::seal(new_public, &self.open(old)?)
    }
    pub fn seal(public: &str, plaintext: &[u8]) -> Result<Self> {
        ensure!(plaintext.len() <= 65536, "configuration too large");
        let id = Uuid::new_v4();
        let label = format!("vault-rs/v1/provider-config/{id}");
        let mut key = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(key.as_mut());
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_ref())?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: label.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("configuration encryption failed"))?;
        Ok(Self {
            id,
            public_hash: wrapping_key_hash(public)?,
            wrapped: encode(&wrap_share(public, &label, key.as_ref())?),
            nonce: encode(&nonce),
            ciphertext: encode(&ciphertext),
        })
    }
    pub fn open(&self, protector: &dyn ShareUnwrapper) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            self.public_hash == wrapping_key_hash(protector.public_key())?,
            "wrong configuration protector"
        );
        let label = format!("vault-rs/v1/provider-config/{}", self.id);
        let key = protector.unwrap(&decode(&self.wrapped)?, &label)?;
        Ok(Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(key.as_ref())?
                .decrypt(
                    XNonce::from_slice(&fixed::<24>(&self.nonce)?),
                    Payload {
                        msg: &decode(&self.ciphertext)?,
                        aad: label.as_bytes(),
                    },
                )
                .map_err(|_| anyhow::anyhow!("configuration authentication failed"))?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    id: Uuid,
    public_hash: String,
    wrapped: String,
}
fn label(id: Uuid) -> String {
    format!("vault-rs/v1/storage/{id}")
}

fn private_regular_file(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.nlink() == 1
                    && m.uid() == nix::unistd::geteuid().as_raw()
                    && m.mode() & 0o077 == 0,
                "database files must be private, singly-linked regular files owned by this service"
            );
            crate::runner::reject_extended_acl(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn validate_files(path: &Path) -> Result<()> {
    for suffix in [
        "",
        ".lock",
        ".key-envelope.json",
        "-wal",
        "-shm",
        "-journal",
    ] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        private_regular_file(Path::new(&name))?;
    }
    Ok(())
}

pub struct Database {
    connection: Connection,
    _lease: nix::fcntl::Flock<std::fs::File>,
}
impl std::ops::Deref for Database {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.connection
    }
}
impl std::ops::DerefMut for Database {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}
fn lease(path: &Path, exclusive: bool) -> Result<nix::fcntl::Flock<std::fs::File>> {
    validate_files(path)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(std::path::PathBuf::from(name))?;
    ensure!(
        file.metadata()?.is_file(),
        "database lease must be a regular file"
    );
    nix::fcntl::Flock::lock(
        file,
        if exclusive {
            nix::fcntl::FlockArg::LockExclusiveNonblock
        } else {
            nix::fcntl::FlockArg::LockSharedNonblock
        },
    )
    .map_err(|(_, e)| anyhow::anyhow!("database in use: {e}"))
}
pub fn open(path: &Path, protector: &dyn ShareUnwrapper) -> Result<Database> {
    open_generation(path, protector, None)
}
/// Use a digest from an authenticated deployment manifest, never one freshly
/// read from the potentially replaced envelope itself.
pub fn open_pinned(
    path: &Path,
    protector: &dyn ShareUnwrapper,
    expected_sha256: &str,
) -> Result<Database> {
    open_generation(path, protector, Some(expected_sha256))
}
fn open_generation(
    path: &Path,
    protector: &dyn ShareUnwrapper,
    expected: Option<&str>,
) -> Result<Database> {
    let guard = lease(path, false)?;
    Ok(Database {
        connection: open_unleased(path, protector, expected)?,
        _lease: guard,
    })
}
fn open_unleased(
    path: &Path,
    protector: &dyn ShareUnwrapper,
    expected: Option<&str>,
) -> Result<Connection> {
    validate_files(path)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(".key-envelope.json");
    let envelope_path = std::path::PathBuf::from(name);
    ensure!(
        expected.is_none() || envelope_path.exists(),
        "accepted database generation is missing"
    );
    if !envelope_path.exists() {
        ensure!(
            !path.exists(),
            "existing database has no key envelope; recovery required"
        );
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        let id = Uuid::new_v4();
        let envelope = Envelope {
            id,
            public_hash: wrapping_key_hash(protector.public_key())?,
            wrapped: encode(&wrap_share(
                protector.public_key(),
                &label(id),
                key.as_ref(),
            )?),
        };
        // Interrupted creation fails closed; never overwrite or regenerate a key.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&envelope_path)?;
        file.write_all(&serde_json::to_vec(&envelope)?)?;
        file.sync_all()?;
        std::fs::File::open(path.parent().context("database needs parent directory")?)?
            .sync_all()?;
    }
    private_regular_file(&envelope_path)?;
    let bytes = crate::runner::read_bounded(&envelope_path, 4096)?;
    if let Some(expected) = expected {
        use sha2::{Digest, Sha256};
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == expected,
            "database key generation differs from accepted manifest"
        );
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    ensure!(
        envelope.public_hash == wrapping_key_hash(protector.public_key())?,
        "wrong database key protector"
    );
    let key = protector.unwrap(&decode(&envelope.wrapped)?, &label(envelope.id))?;
    if !path.exists() {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
            .sync_all()?;
    }
    private_regular_file(path)?;
    // macOS exposes its temporary directory through /var -> /private/var.
    // Resolve only the parent; SQLITE_OPEN_NOFOLLOW still rejects a leaf link.
    // Production configuration separately requires a protected canonical parent.
    let sqlite_path = path
        .parent()
        .context("database parent missing")?
        .canonicalize()?
        .join(path.file_name().context("database filename missing")?);
    let db = Connection::open_with_flags(
        sqlite_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let version: String = db.query_row("PRAGMA cipher_version", [], |r| r.get(0))?;
    ensure!(
        !version.is_empty(),
        "SQLCipher is required; no plaintext fallback"
    );
    let pragma = Zeroizing::new(format!("x'{}'", hex::encode(key.as_ref())));
    db.pragma_update(None, "key", pragma.as_str())?;
    db.execute_batch(
        "PRAGMA cipher_memory_security=ON; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON;",
    )?;
    db.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })?;
    Ok(db)
}

/// Explicit administrative initialization. A failed/partial existing generation
/// is never overwritten. The caller must authenticate the returned digest.
pub fn initialize_generation(path: &Path, protector: &dyn ShareUnwrapper) -> Result<String> {
    ensure!(!path.exists(), "database already exists");
    let mut envelope = path.as_os_str().to_os_string();
    envelope.push(".key-envelope.json");
    let envelope = std::path::PathBuf::from(envelope);
    ensure!(!envelope.exists(), "database generation already exists");
    let _lease = lease(path, true)?;
    let db = open_unleased(path, protector, None)?;
    // Forces an encrypted first page without introducing application tables.
    db.execute_batch("PRAGMA user_version=1")?;
    drop(db);
    std::fs::File::open(path)?.sync_all()?;
    std::fs::File::open(path.parent().context("database parent missing")?)?.sync_all()?;
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(crate::runner::read_bounded(
        &envelope, 4096,
    )?)))
}

/// Offline generation rotation. The old database remains an immutable recovery
/// generation. A new random DEK makes the old envelope unable to open new data.
/// Switching the server's accepted config to `destination` publishes the result.
pub fn rotate_generation(
    source: &Path,
    destination: &Path,
    old: &dyn ShareUnwrapper,
    new: &dyn ShareUnwrapper,
) -> Result<()> {
    ensure!(
        source != destination && source.exists() && !destination.exists(),
        "rotation requires a new database generation"
    );
    let _source_lease = lease(source, true)?;
    let _destination_lease = lease(destination, true)?;
    let source_db = open_unleased(source, old, None)?;
    source_db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    let destination_db = open_unleased(destination, new, None)?;
    drop(destination_db);
    let mut name = destination.as_os_str().to_os_string();
    name.push(".key-envelope.json");
    let envelope: Envelope = serde_json::from_slice(&crate::runner::read_bounded(
        &std::path::PathBuf::from(name),
        4096,
    )?)?;
    let key = new.unwrap(&decode(&envelope.wrapped)?, &label(envelope.id))?;
    let raw = Zeroizing::new(hex::encode(key.as_ref()));
    let password = Zeroizing::new(format!("x'{}'", raw.as_str()));
    source_db.execute(
        "ATTACH DATABASE ?1 AS rotated KEY ?2",
        rusqlite::params![
            destination.to_str().context("non-UTF8 database path")?,
            password.as_str()
        ],
    )?;
    source_db.query_row("SELECT sqlcipher_export('rotated')", [], |_| Ok(()))?;
    source_db.execute_batch("DETACH DATABASE rotated")?;
    drop(source_db);
    let verified = open_unleased(destination, new, None)?;
    let integrity: String = verified.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure!(
        integrity == "ok",
        "rotated database failed integrity verification"
    );
    drop(verified);
    std::fs::File::open(destination)?.sync_all()?;
    std::fs::File::open(destination.parent().context("missing rotation parent")?)?.sync_all()?;
    Ok(())
}
