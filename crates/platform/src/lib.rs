//! Minimal OS primitive: Darwin's primary-only group set and permanent UID drop.
//! No protocol, cryptography, secret parsing, or policy logic belongs here.
#![cfg(target_os = "macos")]
use std::{io, os::unix::process::CommandExt, process::Command};

/// Configure a fresh child to drop all parent groups and root identities before
/// exec. The caller must not subsequently configure other identity/pre_exec hooks.
/// The worker independently validates UID/GID and OpenDirectory groups after exec.
#[allow(unsafe_code)]
pub fn configure_identity(command: &mut Command, uid: u32) -> io::Result<()> {
    if !(501..=2_000_000_000).contains(&uid) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: callback captures only a scalar. The Darwin/libSystem credential
    // primitives are relied on to perform no allocation or locking after fork;
    // this is an explicit OS contract, not a POSIX guarantee for setgroups.
    // The error paths construct only inline OS errors.
    // There is no heap allocation, locking, Rust unwinding, or foreign pointer
    // retained across calls. `group` is one live, aligned gid_t for setgroups(1).
    // Every syscall failure aborts spawn; no untrusted executable runs as root.
    unsafe {
        command.pre_exec(move || {
            if libc::getuid() != 0 || libc::geteuid() != 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            let group: libc::gid_t = uid;
            // Darwin setgroups(0, NULL) does not produce this explicit group set.
            // Set the primary-only list first, then change real/effective/saved
            // GID/UID while still privileged. setuid from root is irreversible.
            if libc::setgroups(1, &group) != 0 || libc::setgid(group) != 0 || libc::setuid(uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
