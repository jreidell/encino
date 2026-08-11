//! Filesystem helpers with the durability guarantees this crate depends on.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::{Error, Result};

/// Create a directory and any missing parents.
pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| Error::io("create directory", path, e))
}

/// Create a directory only its owner may enter.
///
/// For `.encino` and the staging area beneath it, which holds plaintext while a
/// checkout is assembled. The mode is applied best-effort: a vault on a network
/// share may sit on a filesystem with no Unix permissions to set, and that must
/// not fail an import. On Windows a new directory inherits the ACL of its
/// parent; see `docs/threat-model.md` for what that does and does not give.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    ensure_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Permissions for a file holding plaintext: the owner, and nobody else.
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Create a file that must not already exist, readable only by its owner.
///
/// Every file this crate writes plaintext into goes through here or
/// [`create_private`]. `File::create` would take `0666 & !umask` — 0644 under
/// the usual umask — which leaves a checked-out document readable by every
/// account on the machine, one of the cases `docs/threat-model.md` puts in
/// scope.
pub fn create_new_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    open_private(options, path)
}

/// Create or replace a file, readable only by its owner.
pub fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let file = open_private(options, path)?;

    // `mode` applies only when the open creates the file, so a path that was
    // already there would keep whatever permissions it arrived with.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE));
    }
    Ok(file)
}

fn open_private(mut options: OpenOptions, path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    options.open(path).map_err(|e| Error::io("create", path, e))
}

/// Flush a directory's own entries to physical storage.
///
/// Renaming a file into place is atomic, but the rename is not *durable* until
/// the directory holding it is flushed: a power failure can otherwise leave a
/// fully synced file that no name points at. That matters here because the
/// journal reads the index as the record of what happened — an index whose
/// rename was lost reads as an operation that never completed, and `add` has by
/// then already shredded the original.
///
/// Best-effort, and deliberately so. There is no portable directory `fsync`:
/// Windows has no handle to open this way, and some network filesystems refuse.
/// A vault on a share must keep working, so a refusal is not allowed to fail an
/// import — the same trade [`normalize_times`] makes.
#[cfg(unix)]
pub fn sync_dir(path: &Path) {
    let _ = File::open(path).and_then(|dir| dir.sync_all());
}

/// No counterpart on Windows: a directory cannot be opened for flushing without
/// `FILE_FLAG_BACKUP_SEMANTICS`, and NTFS journals the metadata regardless.
#[cfg(not(unix))]
pub fn sync_dir(_path: &Path) {}

/// Resolve a path to a single canonical form.
///
/// Path comparisons across the crate are textual, and [`std::fs::canonicalize`]
/// yields `\\?\C:\Docs`, which silently fails to match the `C:\Docs` a user
/// typed, so the extended-length prefix is stripped back off.
pub fn canonical(path: &Path) -> Result<PathBuf> {
    let resolved = path.canonicalize().map_err(|e| Error::io("resolve", path, e))?;
    Ok(strip_verbatim_prefix(&resolved))
}

/// Turn `\\?\C:\x` into `C:\x` and `\\?\UNC\s\share` into `\\s\share`.
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();

    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        // Device paths such as `\\?\Volume{...}` are invalid without the prefix.
        if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
            return PathBuf::from(rest);
        }
    }
    path.to_path_buf()
}

/// The timestamp every blob and blob-store directory carries.
///
/// `2001-01-01T00:00:00Z`. A constant rather than the vault's creation time,
/// which would vary per vault for no gain, and not the Unix epoch, which some
/// backup tools read as a missing or damaged timestamp.
pub const NORMALIZED_UNIX_TIME: i64 = 978_307_200;

/// Stamp a file or directory with [`NORMALIZED_UNIX_TIME`].
///
/// A blob is written once and never modified — an edited document is stored
/// under a fresh random id — so its mtime would otherwise be exactly when that
/// document last changed. Across the snapshots a backup accumulates, that is a
/// per-document activity timeline readable with no credential at all.
///
/// Deliberately best-effort and infallible. A filesystem that refuses the change
/// must not fail an import: the document is durably stored either way, and the
/// timestamp is a privacy property rather than a correctness one.
///
/// Not for `index.enc` or `vault.json`. Those are replaced in place, keeping
/// their names and sometimes their sizes, so a backup tool deciding what to copy
/// from name, size and mtime could silently skip a changed index — and losing
/// the index loses every document.
pub fn normalize_times(path: &Path) {
    let stamp = filetime::FileTime::from_unix_time(NORMALIZED_UNIX_TIME, 0);
    let _ = filetime::set_file_times(path, stamp, stamp);
}

/// Whether a path still carries [`NORMALIZED_UNIX_TIME`].
///
/// [`normalize_times`] is best-effort, so a filesystem that quietly refused the
/// change would leave the blob store naming when each document last changed and
/// nothing else would report it. `verify` uses this to say so.
///
/// Modification time only. Reading a blob updates its access time — `verify`
/// itself does exactly that — so testing atime would report every vault on a
/// filesystem that tracks it.
pub fn is_normalized(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| filetime::FileTime::from_last_modification_time(&m).unix_seconds() == NORMALIZED_UNIX_TIME)
        .unwrap_or(false)
}

/// Replace a file's contents atomically: a flushed temporary sibling renamed
/// over the target, so a crash leaves old or new contents, never a truncation.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    ensure_dir(parent)?;

    let temp = temp_sibling(path);

    // Closed before the rename; Windows will not replace a file with an open handle.
    {
        let mut file = File::create(&temp).map_err(|e| Error::io("create temporary file", &temp, e))?;
        file.write_all(contents).map_err(|e| Error::io("write", &temp, e))?;
        file.sync_all().map_err(|e| Error::io("flush to disk", &temp, e))?;
    }

    if let Err(e) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(Error::io("replace", path, e));
    }

    // The contents were flushed above; this is what makes the *name* durable.
    sync_dir(parent);
    Ok(())
}

/// Write a file that must not already exist, flushing it to physical storage.
/// Blob names are random, so a collision means the random source has failed.
pub fn write_new_synced(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let mut file = File::create_new(path).map_err(|e| Error::io("create", path, e))?;
    file.write_all(contents).map_err(|e| Error::io("write", path, e))?;
    file.sync_all().map_err(|e| Error::io("flush to disk", path, e))?;
    drop(file);

    if let Some(parent) = path.parent() {
        sync_dir(parent);
    }
    Ok(())
}

/// Read a whole file.
pub fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| Error::io("read", path, e))
}

/// Remove a file, tolerating its absence.
pub fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io("remove", path, e)),
    }
}

/// Copy a file's contents over another path atomically.
pub fn copy_atomic(from: &Path, to: &Path) -> Result<()> {
    let contents = read(from)?;
    write_atomic(to, &contents)
}

/// A uniquely named sibling of `path`, used as a staging file.
fn temp_sibling(path: &Path) -> PathBuf {
    let suffix = hex::encode(crypto::random_array::<8>());
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.{suffix}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_existing_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");

        write_atomic(&path, b"first").unwrap();
        assert_eq!(read(&path).unwrap(), b"first");

        write_atomic(&path, b"second").unwrap();
        assert_eq!(read(&path).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_leaves_no_temporary_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        write_atomic(&dir.path().join("data.bin"), b"contents").unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "staging files were left behind: {leftovers:?}");
    }

    #[test]
    fn atomic_write_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("data.bin");
        write_atomic(&path, b"contents").unwrap();
        assert_eq!(read(&path).unwrap(), b"contents");
    }

    #[test]
    fn write_new_refuses_to_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");

        write_new_synced(&path, b"original").unwrap();
        assert!(write_new_synced(&path, b"replacement").is_err());
        assert_eq!(read(&path).unwrap(), b"original");
    }

    #[test]
    fn canonical_paths_compare_equal_however_they_were_spelled() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        ensure_dir(&nested).unwrap();

        let direct = canonical(&nested).unwrap();
        let roundabout = canonical(&dir.path().join("a").join("..").join("a").join("b")).unwrap();

        assert_eq!(direct, roundabout);

        // `starts_with` and `strip_prefix` across the crate rely on a canonical
        // child textually starting with its canonical parent.
        let root = canonical(dir.path()).unwrap();
        assert!(direct.starts_with(&root), "{direct:?} should sit under {root:?}");
        assert_eq!(direct.strip_prefix(&root).unwrap(), Path::new("a").join("b"));
    }

    #[test]
    fn canonical_paths_carry_no_extended_length_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = canonical(dir.path()).unwrap();

        // `\\?\C:\x` would not match the `C:\x` a user typed, and silently so.
        assert!(
            !resolved.to_string_lossy().starts_with(r"\\?\"),
            "extended-length prefix survived: {resolved:?}"
        );
    }

    #[test]
    fn verbatim_prefixes_are_stripped_only_where_it_is_safe() {
        assert_eq!(strip_verbatim_prefix(Path::new(r"\\?\C:\Docs")), PathBuf::from(r"C:\Docs"));
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\UNC\server\share")),
            PathBuf::from(r"\\server\share")
        );
        let device = r"\\?\Volume{12345678-0000-0000-0000-000000000000}\x";
        assert_eq!(strip_verbatim_prefix(Path::new(device)), PathBuf::from(device));
        assert_eq!(strip_verbatim_prefix(Path::new(r"C:\Docs")), PathBuf::from(r"C:\Docs"));
    }

    #[test]
    fn normalizing_sets_a_fixed_time_on_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blob");
        fs::write(&file, b"contents").unwrap();

        normalize_times(&file);
        normalize_times(dir.path());

        for path in [file.clone(), dir.path().to_path_buf()] {
            let stamped = filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
            assert_eq!(
                stamped.unix_seconds(),
                NORMALIZED_UNIX_TIME,
                "{path:?} did not take the normalized time"
            );
        }
    }

    #[test]
    fn normalizing_a_path_that_is_not_there_is_silent() {
        // Best-effort by design: a filesystem that refuses must not fail an import.
        let dir = tempfile::tempdir().unwrap();
        normalize_times(&dir.path().join("never-existed"));
    }

    #[test]
    fn removing_an_absent_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        remove_if_present(&dir.path().join("never-existed")).unwrap();
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn a_file_holding_plaintext_is_readable_only_by_its_owner() {
        // `File::create` would give 0644 under the usual umask, leaving a
        // checked-out document readable by every account on the machine.
        let dir = tempfile::tempdir().unwrap();

        let fresh = dir.path().join("checkout");
        drop(create_new_private(&fresh).unwrap());
        assert_eq!(mode_of(&fresh), 0o600, "a staged document must not be group- or world-readable");

        let replaced = dir.path().join("export");
        drop(create_private(&replaced).unwrap());
        assert_eq!(mode_of(&replaced), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_was_already_there_has_its_permissions_narrowed() {
        use std::os::unix::fs::PermissionsExt;

        // `mode` on the open applies only when the open creates the file, so a
        // path left behind by something else would otherwise keep its own.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export");

        fs::write(&path, b"left over").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

        drop(create_private(&path).unwrap());
        assert_eq!(mode_of(&path), 0o600, "an existing file kept its permissions");
    }

    #[cfg(unix)]
    #[test]
    fn a_private_directory_admits_nobody_else() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vault-dir");

        ensure_private_dir(&target).unwrap();
        assert_eq!(mode_of(&target), 0o700);

        // Idempotent, and corrects a directory left wide open by an older build.
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&target).unwrap();
        assert_eq!(mode_of(&target), 0o700);
    }

    #[test]
    fn creating_a_file_that_already_exists_is_still_refused() {
        // The permission work must not have loosened the anti-clobber guarantee
        // blob writing depends on.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");

        drop(create_new_private(&path).unwrap());
        assert!(create_new_private(&path).is_err());
    }

    #[test]
    fn syncing_a_directory_is_silent_whatever_the_platform_thinks_of_it() {
        // Best-effort: a filesystem that refuses must not fail an import, and on
        // Windows there is nothing to open at all.
        let dir = tempfile::tempdir().unwrap();
        sync_dir(dir.path());
        sync_dir(&dir.path().join("never-existed"));
    }
}
