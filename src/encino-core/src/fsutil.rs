//! Filesystem helpers with the durability guarantees this crate depends on.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::{Error, Result};

/// Create a directory and any missing parents.
pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| Error::io("create directory", path, e))
}

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
    fn removing_an_absent_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        remove_if_present(&dir.path().join("never-existed")).unwrap();
    }
}
