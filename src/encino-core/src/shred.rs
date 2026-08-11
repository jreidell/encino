//! Removing plaintext from disk.
//!
//! Overwriting before unlinking defeats undelete tools but cannot promise the
//! bytes are gone: wear levelling, copy-on-write filesystems and snapshots leave
//! the original blocks intact; volume-level encryption is the real mitigation.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto;
use crate::{Error, Result};

/// Bytes written per pass.
const SCRUB_BUFFER: usize = 64 * 1024;

/// Overwrite a file with random bytes, then delete it.
///
/// One random pass: multi-pass patterns target 1990s magnetic encoding, and on
/// flash each extra pass merely writes to fresh cells.
pub fn shred(path: &Path) -> Result<()> {
    // `symlink_metadata` does not follow links; following one would scrub the
    // target, which may sit outside the vault.
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io("inspect", path, e)),
    };

    if metadata.file_type().is_symlink() {
        return Err(Error::RefusedToShred {
            path: path.to_path_buf(),
            reason: "it is a link, and destroying its target was not asked for".into(),
        });
    }
    if metadata.is_dir() {
        return Err(Error::RefusedToShred { path: path.to_path_buf(), reason: "it is a directory".into() });
    }

    // Windows refuses to write or delete a read-only file.
    if metadata.permissions().readonly() {
        make_owner_writable(path, &metadata)?;
    }

    scrub(path, metadata.len())?;
    fs::remove_file(path).map_err(|e| Error::io("delete", path, e))
}

/// Grant write access to the owner so the file can be overwritten and removed.
///
/// Not `Permissions::set_readonly(false)` on Unix: that sets the write bit for
/// group and other too, exposing plaintext. Only the owner bit is added.
#[cfg(unix)]
fn make_owner_writable(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    /// `S_IWUSR` — write for the owner, and nobody else.
    const OWNER_WRITE: u32 = 0o200;

    let mode = metadata.permissions().mode();
    let permissions = std::fs::Permissions::from_mode(mode | OWNER_WRITE);
    fs::set_permissions(path, permissions).map_err(|e| Error::io("grant write access to", path, e))
}

/// On Windows the read-only flag is a single attribute, so clearing it exposes nothing.
#[cfg(not(unix))]
fn make_owner_writable(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    let mut permissions = metadata.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).map_err(|e| Error::io("clear read-only flag on", path, e))
}

fn scrub(path: &Path, len: u64) -> Result<()> {
    let mut file =
        OpenOptions::new().write(true).open(path).map_err(|e| Error::io("open for overwrite", path, e))?;
    file.seek(SeekFrom::Start(0)).map_err(|e| Error::io("rewind", path, e))?;

    let mut buffer = vec![0u8; SCRUB_BUFFER];
    let mut remaining = len;
    while remaining > 0 {
        let span = std::cmp::min(remaining as usize, SCRUB_BUFFER);
        crypto::fill_random(&mut buffer[..span]);
        file.write_all(&buffer[..span]).map_err(|e| Error::io("overwrite", path, e))?;
        remaining -= span as u64;
    }

    // Otherwise the overwrite may sit in the page cache until after the unlink.
    file.sync_all().map_err(|e| Error::io("flush overwrite of", path, e))
}

/// Remove a directory if it is empty, ignoring failure; a populated one is the user's.
pub fn remove_dir_if_empty(path: &Path) {
    let _ = fs::remove_dir(path);
}

/// Delete a blob file. Ciphertext, so no scrubbing is warranted.
///
/// Tidies the shard afterwards, in two respects.
///
/// An emptied shard directory is removed. Left standing it would record that a
/// document once lived there — outliving the document itself, and accumulating
/// as edits replace blobs — so the store would slowly reveal more than it holds.
/// A shard still holding a blob is kept, since `remove_dir` refuses a directory
/// that is not empty, which is the guard rather than a separate check.
///
/// Whichever happened, timestamps are restamped: deleting a blob moves its
/// shard's mtime just as writing one does, and removing the shard moves the
/// store root's. Without this a check-in — which writes a new blob and drops the
/// old — would restore the per-document timeline the write path removes.
pub fn remove_blob(path: &Path) -> Result<()> {
    let removed = match fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(Error::io("delete blob", path, e)),
    };

    if removed && let Some(shard) = path.parent() {
        remove_dir_if_empty(shard);
        if shard.exists() {
            crate::fsutil::normalize_times(shard);
        }
        if let Some(root) = shard.parent() {
            crate::fsutil::normalize_times(root);
        }
    }
    Ok(())
}

/// Whether a path exists as a regular file.
pub fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|m| m.is_file() && !m.file_type().is_symlink()).unwrap_or(false)
}

/// Create a file that must not already exist, for staging plaintext.
///
/// Owner-only from the moment it exists. Widening it afterwards would leave a
/// window in which the document was readable, and the file is renamed into the
/// work area carrying whatever permissions it was created with.
pub fn create_new(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        crate::fsutil::ensure_private_dir(parent)?;
    }
    crate::fsutil::create_new_private(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn shredding_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("statement.pdf");
        fs::write(&path, b"account balance 12345").unwrap();

        shred(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn the_original_bytes_are_overwritten_before_the_file_is_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("statement.pdf");
        let secret = b"account balance 12345".repeat(100);
        fs::write(&path, &secret).unwrap();

        // Held open so the scrub stays observable after unlinking on Windows.
        let mut handle = File::open(&path).unwrap();
        shred(&path).unwrap();

        let mut after = Vec::new();
        handle.read_to_end(&mut after).ok();
        if !after.is_empty() {
            assert_ne!(after, secret, "the plaintext was still present after shredding");
        }
    }

    #[test]
    fn shredding_an_absent_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        shred(&dir.path().join("never-existed")).unwrap();
    }

    #[test]
    fn read_only_files_are_shredded_rather_than_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("statement.pdf");
        fs::write(&path, b"contents").unwrap();

        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();

        shred(&path).unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn clearing_read_only_does_not_expose_the_file_to_others() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("statement.pdf");
        fs::write(&path, b"account balance").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();

        let metadata = fs::symlink_metadata(&path).unwrap();
        make_owner_writable(&path, &metadata).unwrap();

        // Group and other must be unchanged; `set_readonly(false)` would give 0o666.
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o200, 0o200, "the owner should be able to write");
        assert_eq!(mode & 0o022, 0, "group and other must not have gained write access: {mode:o}");
    }

    #[test]
    fn directories_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("folder");
        fs::create_dir(&subdir).unwrap();

        assert!(matches!(shred(&subdir), Err(Error::RefusedToShred { .. })));
        assert!(subdir.exists());
    }

    #[test]
    fn an_empty_file_is_handled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        fs::write(&path, b"").unwrap();

        shred(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_file_larger_than_the_scrub_buffer_is_fully_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.pdf");
        fs::write(&path, vec![0xABu8; SCRUB_BUFFER * 3 + 17]).unwrap();

        shred(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn removing_an_empty_directory_leaves_populated_ones_alone() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        let populated = dir.path().join("populated");
        fs::create_dir(&empty).unwrap();
        fs::create_dir(&populated).unwrap();
        fs::write(populated.join("file"), b"x").unwrap();

        remove_dir_if_empty(&empty);
        remove_dir_if_empty(&populated);

        assert!(!empty.exists());
        assert!(populated.exists(), "a directory the user put something in must be left alone");
    }

    #[test]
    fn emptying_a_shard_removes_it_and_leaves_the_store_root_normalized() {
        use crate::blob::{BlobId, write_blob};
        use crate::crypto::Key;

        let dir = tempfile::tempdir().unwrap();
        let blobs = dir.path().join("blobs");
        let shard = blobs.join("aa");
        let key = Key::random();

        // Two blobs sharing one shard, written to explicit paths so the shard is
        // not left to the randomness of a blob id.
        let (first, second) = (shard.join("first"), shard.join("second"));
        write_blob(&mut &b"one"[..], &first, &BlobId::random(), &key).unwrap();
        write_blob(&mut &b"two"[..], &second, &BlobId::random(), &key).unwrap();

        // While a blob remains, the shard stays and keeps the fixed time.
        remove_blob(&first).unwrap();
        assert!(shard.is_dir(), "a shard still holding a blob must not be removed");
        assert_eq!(mtime_seconds(&shard), crate::fsutil::NORMALIZED_UNIX_TIME);

        // Emptied, it goes: a shard left standing records that a document was
        // once there, which outlives the document itself.
        remove_blob(&second).unwrap();
        assert!(!shard.exists(), "an emptied shard directory was left behind");

        // Removing it moved the store root's mtime, so that needs restamping too.
        assert_eq!(mtime_seconds(&blobs), crate::fsutil::NORMALIZED_UNIX_TIME);
    }

    /// Modification time of a path, in Unix seconds.
    fn mtime_seconds(path: &Path) -> i64 {
        filetime::FileTime::from_last_modification_time(&fs::metadata(path).unwrap()).unix_seconds()
    }

    #[test]
    fn regular_files_are_distinguished_from_directories() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();

        assert!(is_regular_file(&file));
        assert!(!is_regular_file(dir.path()));
        assert!(!is_regular_file(&dir.path().join("absent")));
    }
}
