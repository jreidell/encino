//! Exclusive access to a vault.
//!
//! Index saves are read-modify-write and each document's content key lives
//! inside its index entry, so two concurrent saves means the second discards
//! the first's entries and destroys the only copy of those keys.
//!
//! The lock is an open file handle, not the presence of a file: on Windows the
//! holder opens `work.lock` denying write sharing, and SMB enforces the same
//! share mode across machines. The operating system releases the handle when
//! the process dies, so there are no stale locks and a leftover `work.lock` is
//! simply reused. The contents name the holder so a refusal can say who to look
//! at; read sharing is allowed for that.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Error, Result};

/// Who holds a vault open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockHolder {
    /// Machine the holder is running on.
    pub machine: String,
    /// Process id on that machine.
    pub pid: u32,
    /// When the lock was taken.
    #[serde(with = "time::serde::rfc3339")]
    pub since: OffsetDateTime,
}

impl LockHolder {
    fn current() -> Self {
        LockHolder { machine: machine_name(), pid: std::process::id(), since: OffsetDateTime::now_utc() }
    }
}

impl std::fmt::Display for LockHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "process {} on {}", self.pid, self.machine)
    }
}

/// Exclusive access to one vault, released when dropped.
#[derive(Debug)]
pub struct VaultLock {
    /// Closing this handle is what releases the lock.
    handle: Option<File>,
    path: PathBuf,
}

impl VaultLock {
    /// Take exclusive access, or report who already has it.
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            crate::fsutil::ensure_dir(parent)?;
        }

        match open_exclusive(path) {
            Ok(mut handle) => {
                // Best effort: failing to record the holder does not weaken the lock.
                if let Ok(json) = serde_json::to_vec_pretty(&LockHolder::current()) {
                    let _ = handle.write_all(&json);
                    let _ = handle.flush();
                }
                Ok(VaultLock { handle: Some(handle), path: path.to_path_buf() })
            }
            Err(e) if is_contention(&e) => Err(Error::VaultInUse {
                path: path.to_path_buf(),
                holder: read_holder(path).map(|h| h.to_string()),
            }),
            Err(e) => Err(Error::io("lock", path, e)),
        }
    }

    /// Release without waiting for the value to be dropped.
    pub fn release(mut self) {
        self.close();
    }

    fn close(&mut self) {
        // Close the handle before removing the file. Removal is cosmetic: the
        // next acquisition reuses the file whether or not it is there.
        self.handle.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        self.close();
    }
}

/// Open the lock file for writing while denying write sharing to anyone else.
#[cfg(windows)]
fn open_exclusive(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    /// Others may open for reading, to learn who holds the lock, but not for writing.
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    OpenOptions::new().write(true).create(true).truncate(true).share_mode(FILE_SHARE_READ).open(path)
}

/// Take an advisory exclusive lock on the file, without blocking.
///
/// The lock belongs to the open file description, so the kernel drops it when
/// the process exits for any reason and there are no stale locks to clear.
/// Advisory suffices: only encino needs to respect it. Over NFS `flock` may be
/// emulated or silently local, so two machines sharing a vault may not see each
/// other's locks. See `docs/threat-model.md`.
#[cfg(unix)]
fn open_exclusive(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{FlockOperation, flock};

    let file = OpenOptions::new().write(true).create(true).truncate(false).open(path)?;

    // Non-blocking: a held vault should be reported at once, not waited on.
    flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(std::io::Error::from)?;

    // Truncate only once the lock is held: truncating on open would wipe the
    // real owner's holder record.
    file.set_len(0)?;
    Ok(file)
}

/// Last-resort fallback for platforms that are neither Windows nor Unix.
///
/// Exclusive creation, so a crash leaves a lock nobody holds and nothing
/// clears. No such platform is targeted; this exists so the crate compiles.
#[cfg(not(any(windows, unix)))]
fn open_exclusive(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Whether an error means somebody else holds the lock.
#[cfg(windows)]
fn is_contention(error: &std::io::Error) -> bool {
    /// ERROR_SHARING_VIOLATION: the file is open with an incompatible share mode.
    const SHARING_VIOLATION: i32 = 32;
    /// ERROR_LOCK_VIOLATION.
    const LOCK_VIOLATION: i32 = 33;

    matches!(error.raw_os_error(), Some(SHARING_VIOLATION) | Some(LOCK_VIOLATION))
}

/// `flock` reports contention as `EWOULDBLOCK`, surfaced as `WouldBlock`.
#[cfg(unix)]
fn is_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
}

#[cfg(not(any(windows, unix)))]
fn is_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::AlreadyExists
}

/// Read the holder record, if it can be read at all.
fn read_holder(path: &Path) -> Option<LockHolder> {
    let mut contents = String::new();
    File::open(path).ok()?.read_to_string(&mut contents).ok()?;
    serde_json::from_str(&contents).ok()
}

fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "an unknown machine".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join(".encino").join("work.lock")
    }

    #[test]
    fn a_second_acquisition_is_refused_while_the_first_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let first = VaultLock::acquire(&path).unwrap();
        let second = VaultLock::acquire(&path);

        assert!(
            matches!(second, Err(Error::VaultInUse { .. })),
            "a second holder must be refused, got {second:?}"
        );
        drop(first);
    }

    #[test]
    fn the_refusal_names_who_is_holding_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let _held = VaultLock::acquire(&path).unwrap();
        let refusal = VaultLock::acquire(&path).unwrap_err();

        let message = refusal.to_string();
        assert!(message.contains("in use"), "unhelpful message: {message}");
        assert!(
            message.contains(&std::process::id().to_string()),
            "the refusal should say who holds it: {message}"
        );
    }

    #[test]
    fn releasing_makes_the_vault_available_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let first = VaultLock::acquire(&path).unwrap();
        drop(first);

        VaultLock::acquire(&path).expect("the vault should be free once the holder lets go");
    }

    #[test]
    fn a_lock_file_nobody_holds_is_not_a_stale_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);
        crate::fsutil::ensure_dir(path.parent().unwrap()).unwrap();

        // What a killed process leaves: the file, naming a process that is gone.
        std::fs::write(
            &path,
            serde_json::to_vec(&LockHolder {
                machine: "some-other-machine".into(),
                pid: 999_999,
                since: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            })
            .unwrap(),
        )
        .unwrap();

        // Only a held handle blocks; the file's existence means nothing.
        VaultLock::acquire(&path).expect("a leftover lock file must not block the vault");
    }

    #[test]
    fn the_lock_file_is_tidied_away_on_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let held = VaultLock::acquire(&path).unwrap();
        assert!(path.exists());
        held.release();
        assert!(!path.exists());
    }

    #[test]
    fn acquiring_creates_the_vault_directory_if_needed() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("work.lock");
        let _held = VaultLock::acquire(&nested).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn the_holder_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let _held = VaultLock::acquire(&path).unwrap();
        let holder = read_holder(&path).expect("the holder record should be readable while held");

        assert_eq!(holder.pid, std::process::id());
        assert!(!holder.machine.is_empty());
    }
}
