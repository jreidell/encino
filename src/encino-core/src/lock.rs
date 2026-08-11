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

/// How many times to re-open when the lock file is replaced underneath us.
///
/// Each retry needs a release to land in a window of a few instructions, so more
/// than a couple in a row is not contention but something pathological.
#[cfg(unix)]
const MAX_LOCK_ATTEMPTS: u32 = 8;

/// Take an advisory exclusive lock on the file, without blocking.
///
/// The lock belongs to the open file description, so the kernel drops it when
/// the process exits for any reason and there are no stale locks to clear.
/// Advisory suffices: only encino needs to respect it. Over NFS `flock` may be
/// emulated or silently local, so two machines sharing a vault may not see each
/// other's locks. See `docs/threat-model.md`.
///
/// The lock file is unlinked on release, and that is what makes the identity
/// check below necessary rather than paranoid. A process can open the file,
/// be preempted, and have the holder release *and unlink* before its own
/// `flock` runs — at which point the lock is granted on an inode with no name,
/// while the next process along creates a fresh file at the same path and locks
/// that. Both would then believe they hold the vault, and two concurrent index
/// saves destroy the content keys of whichever entries the loser wrote. So the
/// descriptor is confirmed to still be the file at `path` before the lock is
/// trusted, and the attempt starts over if it is not.
#[cfg(unix)]
fn open_exclusive(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{FlockOperation, flock};

    for _ in 0..MAX_LOCK_ATTEMPTS {
        let file = OpenOptions::new().write(true).create(true).truncate(false).open(path)?;

        // Non-blocking: a held vault should be reported at once, not waited on.
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(std::io::Error::from)?;

        if !still_named(&file, path)? {
            // Dropping releases the lock on the orphaned inode.
            continue;
        }

        // Truncate only once the lock is held: truncating on open would wipe the
        // real owner's holder record.
        file.set_len(0)?;
        return Ok(file);
    }

    // Somebody is churning the lock file. Reported as contention, which is what
    // it amounts to from the caller's side.
    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
}

/// Whether `file` is still the file living at `path`.
///
/// Compared by device and inode rather than by opening again, because the
/// question is precisely whether the name still resolves to this object.
#[cfg(unix)]
fn still_named(file: &File, path: &Path) -> std::io::Result<bool> {
    let held = rustix::fs::fstat(file)?;
    match rustix::fs::stat(path) {
        Ok(named) => Ok(named.st_dev == held.st_dev && named.st_ino == held.st_ino),
        // Unlinked between the lock and this check: not ours to hold.
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
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

    #[cfg(unix)]
    #[test]
    fn a_handle_is_only_the_lock_while_it_is_still_the_named_file() {
        // The guard that closes the release-and-unlink race. Without it a handle
        // could win its `flock` on an inode that had just lost its name, while
        // the next process created a fresh file at that name and locked that —
        // two holders, and two concurrent index saves.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work.lock");

        let file = OpenOptions::new().write(true).create(true).truncate(false).open(&path).unwrap();
        assert!(still_named(&file, &path).unwrap(), "an untouched lock file is its own name");

        // Released and unlinked by the holder, which is what `close` does.
        std::fs::remove_file(&path).unwrap();
        assert!(!still_named(&file, &path).unwrap(), "an unlinked inode must not count as the lock");

        // And the name now belongs to a different file entirely.
        let _successor = OpenOptions::new().write(true).create(true).truncate(false).open(&path).unwrap();
        assert!(!still_named(&file, &path).unwrap(), "a replaced lock file must not count as the lock");
    }

    #[cfg(unix)]
    #[test]
    fn a_recreated_lock_file_is_itself_exclusive() {
        // Deleting `work.lock` by hand while it is held does strand the original
        // holder on an unnamed inode, and the newcomer legitimately takes the
        // recreated name — so for that one span there are two. Nothing can be
        // done about a user removing the file; what must not follow is the
        // recreated name being lockable twice over as well.
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let held = VaultLock::acquire(&path).unwrap();

        // Someone deletes the lock file while it is held — by hand, or by a
        // process that crashed midway through releasing.
        std::fs::remove_file(&path).ok();

        // The newcomer legitimately gets the recreated name. What must not
        // happen is the original still being usable as an exclusive claim.
        let newcomer = VaultLock::acquire(&path).unwrap();
        assert!(
            matches!(VaultLock::acquire(&path), Err(Error::VaultInUse { .. })),
            "the recreated lock file must itself be exclusive"
        );

        drop(newcomer);
        drop(held);
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
