//! Root-managed native workload boundary. The AI never runs under the broker
//! identity. Workloads get an inherited one-way plaintext pipe, never a key or
//! a reusable Vault capability. Every process UID is allocated once by witness.
use crate::{
    crypto::*,
    witness::{Checkpoint, Witness},
};
use anyhow::{ensure, Context, Result};
use nix::unistd::{geteuid, getgid, getuid, Gid, Group, Uid, User};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const MAX_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub contents: String,
    pub executable: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub entrypoint: String,
    pub arguments: Vec<String>,
    pub files: Vec<BundleFile>,
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-./".contains(&b))
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && !path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
}
fn bundle_bytes(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    ensure!(
        value.len() as u64 <= MAX_BUNDLE_BYTES * 2,
        "bundle file too large"
    );
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value)?)
}
/// Verify every component, never merely the final filename. No mutable trusted
/// paths under /tmp or an AI-owned home directory are accepted.
pub fn protected_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical absolute path required"
    );
    for part in path.ancestors() {
        let metadata = fs::symlink_metadata(part)?;
        ensure!(
            !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "path is not administrator-controlled"
        );
        reject_extended_acl(part)?;
    }
    Ok(())
}

/// POSIX mode bits include the ACL mask on Linux. Darwin ACLs are independent
/// of those bits, so even a root-owned 0600 file can grant another user access.
pub(crate) fn reject_extended_acl(path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // /bin/ls belongs to the sealed system volume (OS primitive assumption).
        // Do not recursively call protected_path on the tool used for inspection.
        let inspector = Path::new("/bin/ls");
        ensure!(
            inspector.canonicalize()? == inspector,
            "ACL inspector symlink"
        );
        let m = fs::metadata(inspector)?;
        ensure!(
            m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted ACL inspector"
        );
        let mut child = Command::new(inspector)
            .arg("-dben")
            .arg(path)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("ACL output missing")?
            .take(65537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("oversized ACL output");
        }
        ensure!(child.wait()?.success(), "ACL inspection failed");
        let text = std::str::from_utf8(&bytes)?;
        let mut lines = text.lines();
        let first = lines.next().context("missing ACL result")?;
        ensure!(
            first.len() >= 10 && !lines.any(|line| !line.trim().is_empty()),
            "extended ACL on protected path refused"
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
    Ok(())
}
pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "regular file required");
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "file too large");
    Ok(bytes)
}
impl Bundle {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            relative(&self.entrypoint) && !self.files.is_empty() && self.files.len() <= 512,
            "invalid bundle layout"
        );
        ensure!(
            self.arguments.len() <= 64
                && self
                    .arguments
                    .iter()
                    .all(|a| a.len() <= 4096 && !a.contains('\0')),
            "invalid arguments"
        );
        let mut names = BTreeSet::new();
        let mut size = 0usize;
        let mut entry = false;
        for file in &self.files {
            ensure!(
                relative(&file.path) && names.insert(file.path.clone()),
                "invalid or duplicate bundle path"
            );
            let bytes = bundle_bytes(&file.contents)?;
            size = size
                .checked_add(bytes.len())
                .context("bundle size overflow")?;
            ensure!(size <= MAX_BUNDLE_BYTES as usize, "bundle too large");
            entry |= file.path == self.entrypoint && file.executable;
        }
        ensure!(entry, "entrypoint must be an executable regular file");
        Ok(())
    }
    pub fn hash(&self) -> Result<String> {
        self.validate()?;
        object_hash(self)
    }
    pub fn stage(&self, base: &Path) -> Result<StagedBundle> {
        ensure!(
            getuid().is_root() && geteuid().is_root(),
            "broker requires a dedicated administrator service identity"
        );
        protected_path(base)?;
        self.validate()?;
        let dir = base.join(Uuid::new_v4().to_string());
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let result = (|| -> Result<StagedBundle> {
            for file in &self.files {
                let path = dir.join(&file.path);
                fs::create_dir_all(path.parent().context("missing parent")?)?;
                let mut output = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o400)
                    .open(&path)?;
                output.write_all(&bundle_bytes(&file.contents)?)?;
                output.sync_all()?;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if file.executable { 0o555 } else { 0o444 }),
                )?;
            }
            // Directory creation happens while the outer directory is root-only.
            fn seal_dirs(path: &Path) -> Result<()> {
                for entry in fs::read_dir(path)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        seal_dirs(&entry.path())?;
                    }
                }
                fs::set_permissions(path, fs::Permissions::from_mode(0o555))?;
                Ok(())
            }
            seal_dirs(&dir)?;
            fs::File::open(base)?.sync_all()?;
            Ok(StagedBundle {
                directory: dir.clone(),
                entrypoint: self.entrypoint.clone(),
                arguments: self.arguments.clone(),
                hash: self.hash()?,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        result
    }
}
pub struct StagedBundle {
    directory: PathBuf,
    entrypoint: String,
    arguments: Vec<String>,
    hash: String,
}
impl StagedBundle {
    pub fn hash(&self) -> &str {
        &self.hash
    }
}
impl Drop for StagedBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub struct WorkerIdentity {
    uid: u32,
}
fn allocation_hash(namespace: Uuid, uid: u32) -> Result<String> {
    object_hash(&("vault-rs/worker-uid/v1", namespace, uid))
}
pub fn allocate_worker(
    witness: &dyn Witness,
    namespace: Uuid,
    base: u32,
    limit: u32,
    ai_uid: u32,
) -> Result<WorkerIdentity> {
    let old = witness.read(namespace)?;
    let revision = match &old {
        Some(old) => {
            let old_uid = vault_policy::worker_uid(base, limit, old.revision, ai_uid)
                .context("invalid UID allocation history")?;
            ensure!(
                old.hash == allocation_hash(namespace, old_uid)?,
                "UID range or witness was replaced"
            );
            old.revision
                .checked_add(1)
                .context("UID namespace exhausted")?
        }
        None => 0,
    };
    let uid = vault_policy::worker_uid(base, limit, revision, ai_uid)
        .context("UID namespace exhausted or identity collision")?;
    // Burn even an unusable slot; never silently recycle an identity.
    witness.advance(
        namespace,
        old,
        Checkpoint {
            revision,
            hash: allocation_hash(namespace, uid)?,
        },
    )?;
    ensure!(
        User::from_uid(Uid::from_raw(uid))?.is_none()
            && Group::from_gid(Gid::from_raw(uid))?.is_none(),
        "UID/GID range overlaps an OS account"
    );
    Ok(WorkerIdentity { uid })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSpec {
    directory: PathBuf,
    entrypoint: String,
    arguments: Vec<String>,
    uid: u32,
    broker: u32,
    ai: u32,
}

pub fn launch(
    executable: &Path,
    staged: &StagedBundle,
    identity: WorkerIdentity,
    ai_uid: u32,
    plaintext: &[u8],
    timeout: Duration,
) -> Result<i32> {
    ensure!(
        geteuid().is_root() && getuid().is_root(),
        "unprivileged broker refused"
    );
    ensure!(
        identity.uid != ai_uid && identity.uid >= 10_000,
        "invalid workload identity"
    );
    ensure!(
        plaintext.len() <= 65536 && !timeout.is_zero() && timeout <= Duration::from_secs(3600),
        "invalid workload bounds"
    );
    let executable = executable.canonicalize()?;
    protected_path(&executable)?;
    let spec = WorkerSpec {
        directory: staged.directory.clone(),
        entrypoint: staged.entrypoint.clone(),
        arguments: staged.arguments.clone(),
        uid: identity.uid,
        broker: 0,
        ai: ai_uid,
    };
    let mut child = Command::new(executable)
        .arg("isolated-worker")
        .arg("--spec")
        .arg(serde_json::to_string(&spec)?)
        .uid(identity.uid)
        .gid(identity.uid)
        .process_group(0)
        .current_dir(&staged.directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let started = Instant::now();
    // Pipe writer runs separately so a tool that never reads cannot block expiry.
    let mut input = child.stdin.take().context("missing private child pipe")?;
    let secret = zeroize::Zeroizing::new(plaintext.to_vec());
    let writer = std::thread::spawn(move || {
        let result = input.write_all(&secret);
        drop(input);
        result
    });
    let result = loop {
        if let Some(status) = child.try_wait()? {
            break Ok(status.code().unwrap_or(128));
        }
        if started.elapsed() >= timeout {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = child.kill();
            let _ = child.wait();
            break Err(anyhow::anyhow!("workload timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // A descendant retaining stdin may keep a writer alive; returning detaches it.
    // Bytes are only the already-authorized output, never a broker capability.
    if writer.is_finished() {
        let _ = writer.join();
    }
    result
}

/// Entered after std::process has dropped uid/gid and supplemental groups.
pub fn isolated_worker(spec: WorkerSpec) -> Result<()> {
    ensure!(
        getuid().as_raw() == spec.uid
            && geteuid() == getuid()
            && getgid().as_raw() == spec.uid
            && spec.uid >= 10_000
            && spec.uid != spec.ai
            && spec.uid != spec.broker,
        "wrong kernel workload identity"
    );
    verify_worker_groups(spec.uid)?;
    protected_path(&spec.directory)?;
    ensure!(relative(&spec.entrypoint), "invalid entrypoint");
    protected_path(&spec.directory.join(&spec.entrypoint))?;
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)?;
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, 64, 64)?;
    #[cfg(target_os = "linux")]
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NPROC, 32, 32)?;
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CPU, 60, 60)?;
    nix::sys::resource::setrlimit(
        nix::sys::resource::Resource::RLIMIT_AS,
        512 * 1024 * 1024,
        512 * 1024 * 1024,
    )?;
    #[cfg(target_os = "linux")]
    {
        nix::sys::prctl::set_no_new_privs()?;
        nix::sys::prctl::set_dumpable(false)?;
    }
    let error = Command::new(spec.directory.join(spec.entrypoint))
        .args(spec.arguments)
        .current_dir(spec.directory)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("HOME", "/nonexistent")
        .env("PYTHONNOUSERSITE", "1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
    Err(error.into())
}

fn verify_worker_groups(uid: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = uid;
        ensure!(
            nix::unistd::getgroups()?.is_empty(),
            "inherited supplemental groups refused"
        );
    }
    #[cfg(target_os = "macos")]
    {
        // nix deliberately excludes getgroups on Darwin: OpenDirectory affects
        // membership. Query the system's own identity resolver after the UID
        // drop. No account/group exists for a one-use worker ID. `id -G` includes
        // the primary group; every reported membership must be that same ID.
        protected_path(Path::new("/usr/bin/id"))?;
        let output = Command::new("/usr/bin/id")
            .arg("-G")
            .env_clear()
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 4096,
            "group lookup failed"
        );
        let groups = std::str::from_utf8(&output.stdout)?;
        let values = groups
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            !values.is_empty() && values.into_iter().all(|group| group == uid),
            "inherited or directory group membership refused"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires isolated root test runner; scripts/test-isolation.sh or macOS CI"]
    fn os_isolation_with_real_uids_and_inherited_pipe() {
        use std::sync::Mutex;
        struct W(Mutex<Option<Checkpoint>>);
        impl Witness for W {
            fn read(&self, _: Uuid) -> Result<Option<Checkpoint>> {
                Ok(self.0.lock().unwrap().clone())
            }
            fn advance(&self, _: Uuid, old: Option<Checkpoint>, new: Checkpoint) -> Result<()> {
                let mut v = self.0.lock().unwrap();
                ensure!(*v == old, "conflict");
                *v = Some(new);
                Ok(())
            }
        }
        assert!(getuid().is_root());
        let executable = PathBuf::from(std::env::var("VAULT_TEST_RUNNER_BIN").unwrap());
        let base = PathBuf::from("/opt/vault-isolation");
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let private = base.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let mut private_fd = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(private.join("key"))
            .unwrap();
        private_fd.write_all(b"SYNTHETIC ROOT-ONLY KEY").unwrap();
        #[cfg(target_os = "macos")]
        {
            let acl_file = base.join("acl-test");
            fs::write(&acl_file, b"synthetic").unwrap();
            fs::set_permissions(&acl_file, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(protected_path(&acl_file).is_ok());
            assert!(Command::new("/bin/chmod")
                .args(["+a", "everyone allow read,write,delete"])
                .arg(&acl_file)
                .env_clear()
                .status()
                .unwrap()
                .success());
            assert_eq!(fs::metadata(&acl_file).unwrap().mode() & 0o077, 0);
            assert!(
                protected_path(&acl_file).is_err(),
                "ACL must override apparently private POSIX permissions"
            );
            assert!(Command::new("/bin/chmod")
                .arg("-N")
                .arg(&acl_file)
                .env_clear()
                .status()
                .unwrap()
                .success());
            assert!(protected_path(&acl_file).is_ok());
            fs::remove_file(acl_file).unwrap();
            println!("PASS: extended ACL bypass is refused even with root-owned 0600 mode");
        }
        use std::os::fd::AsRawFd;
        let script = format!(
            r#"#!/usr/bin/python3
import os,sys,ctypes
assert os.getuid()>=10000 and os.getgid()==os.getuid()
assert all(g==os.getuid() for g in os.getgroups())
assert 'VAULT_PARENT_ONLY' not in os.environ and 'LD_PRELOAD' not in os.environ
for path in ['/opt/vault-isolation/private/key','/proc/{}/mem','/proc/{}/fd/{}']:
    try:
        open(path,'rb').read(1)
        raise AssertionError('broker key/memory/FD readable')
    except PermissionError: pass
    except FileNotFoundError:
        assert sys.platform=='darwin' and path.startswith('/proc/')
if sys.platform=='darwin':
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    task=ctypes.c_uint.in_dll(lib,'mach_task_self_').value
    port=ctypes.c_uint()
    assert lib.task_for_pid(task,{broker_pid},ctypes.byref(port))!=0
try:
    os.setuid(0)
    raise AssertionError('privilege escalation')
except PermissionError: pass
assert sys.stdin.buffer.read()==b'SYNTHETIC AUTHORIZED SECRET'
print('PASS: native worker received only the authorized plaintext; keys/memory/FDs denied')
"#,
            std::process::id(),
            std::process::id(),
            private_fd.as_raw_fd(),
            broker_pid = std::process::id()
        );
        let bundle = Bundle {
            entrypoint: "main.py".into(),
            arguments: vec![],
            files: vec![BundleFile {
                path: "main.py".into(),
                contents: encode(script.as_bytes()),
                executable: true,
            }],
        };
        let staged = bundle.stage(&base).unwrap();
        let attack = format!(
            r#"import os,subprocess,sys,ctypes
print('PROBE: isolated AI interpreter entered', flush=True)
assert os.getuid()==1000
for path in ['/opt/vault-isolation/private/key','/proc/{}/mem','{}/main.py']:
    try:
        open(path,'wb' if path.endswith('main.py') else 'rb')
        raise AssertionError('AI access accepted')
    except PermissionError: pass
    except FileNotFoundError:
        assert sys.platform=='darwin' and path.startswith('/proc/')
if sys.platform=='darwin':
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    task=ctypes.c_uint.in_dll(lib,'mach_task_self_').value
    port=ctypes.c_uint()
    assert lib.task_for_pid(task,{broker_pid},ctypes.byref(port))!=0
print('PROBE: direct broker invocation from AI identity', flush=True)
r=subprocess.run(['{}','broker','--config','/opt/vault-isolation/private/key','--verification-run'],capture_output=True, timeout=15)
assert r.returncode!=0
print('PASS: separate AI UID cannot read broker state, modify measured code, or invoke broker')
"#,
            std::process::id(),
            staged.directory.display(),
            executable.display(),
            broker_pid = std::process::id()
        );
        assert!(Command::new("/usr/bin/python3")
            .args(["-c", &attack])
            .current_dir(&base)
            .uid(1000)
            .gid(1000)
            .env_clear()
            .status()
            .unwrap()
            .success());
        let witness = W(Mutex::new(None));
        let namespace = Uuid::new_v4();
        let first = allocate_worker(&witness, namespace, 10000, 20000, 1000).unwrap();
        let first_uid = first.uid;
        std::env::set_var("VAULT_PARENT_ONLY", "SYNTHETIC PARENT SECRET");
        assert_eq!(
            launch(
                &executable,
                &staged,
                first,
                1000,
                b"SYNTHETIC AUTHORIZED SECRET",
                Duration::from_secs(5)
            )
            .unwrap(),
            0
        );
        std::env::remove_var("VAULT_PARENT_ONLY");
        let second = allocate_worker(&witness, namespace, 10000, 20000, 1000).unwrap();
        assert!(second.uid > first_uid);
        let sleeper = Bundle {
            entrypoint: "hang.py".into(),
            arguments: vec![],
            files: vec![BundleFile {
                path: "hang.py".into(),
                contents: encode(b"#!/usr/bin/python3\nwhile True: pass\n"),
                executable: true,
            }],
        }
        .stage(&base)
        .unwrap();
        assert!(launch(
            &executable,
            &sleeper,
            second,
            1000,
            b"SYNTHETIC",
            Duration::from_millis(100)
        )
        .is_err());
        println!("PASS: monotonic UID allocation and workload timeout");
    }
    #[test]
    fn executable_args_and_every_dependency_are_measured() {
        let mut b = Bundle {
            entrypoint: "bin/main".into(),
            arguments: vec!["read".into()],
            files: vec![BundleFile {
                path: "bin/main".into(),
                contents: encode(b"code"),
                executable: true,
            }],
        };
        let before = b.hash().unwrap();
        b.arguments.push("extra".into());
        assert_ne!(before, b.hash().unwrap());
        b.arguments.pop();
        b.files[0].contents = encode(b"changed");
        assert_ne!(before, b.hash().unwrap());
        for path in ["../escape", "/absolute", "a/../b", "a//b", "./main", "a\\b"] {
            b.files[0].path = path.into();
            assert!(b.validate().is_err());
        }
    }
}
