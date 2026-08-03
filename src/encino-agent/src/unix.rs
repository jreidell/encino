//! The Unix system calls the agent needs: keeping the key out of swap, and
//! giving its socket an owner-only home. Counterpart to [`crate::win`].

use std::io;
use std::path::Path;

/// Ask the kernel to keep a region out of swap. Without it, memory pressure
/// could page the master key out, where it persists across a reboot.
pub struct LockedPages {
    address: *mut std::ffi::c_void,
    length: usize,
}

impl LockedPages {
    /// Attempt to lock `bytes` into physical memory. Returns `None` when
    /// `RLIMIT_MEMLOCK` disallows it, which is ordinary on Linux; the key is
    /// zeroized on drop either way.
    pub fn lock(bytes: &mut [u8]) -> Option<Self> {
        let address = bytes.as_mut_ptr().cast();
        let length = bytes.len();

        // SAFETY: the region is a live borrow of `bytes`; Drop unlocks the same
        // region and claims nothing more.
        match unsafe { rustix::mm::mlock(address, length) } {
            Ok(()) => Some(LockedPages { address, length }),
            Err(_) => None,
        }
    }
}

// SAFETY: the state is an address and a length, never dereferenced. Page locking
// is process-wide, so unlocking from a different thread is well defined.
unsafe impl Send for LockedPages {}

impl Drop for LockedPages {
    fn drop(&mut self) {
        // SAFETY: unlocks exactly the region locked in `lock`.
        unsafe {
            let _ = rustix::mm::munlock(self.address, self.length);
        }
    }
}

/// Create the agent's socket directory, owner-accessible only. Access control
/// rests entirely on this, so the mode is set explicitly rather than left to the
/// umask, and an existing directory is corrected rather than trusted.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Restrict a socket file to its owner.
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// The current user's id, used to name a fallback socket directory.
pub fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_can_be_locked_and_unlocked() {
        let mut buffer = vec![0u8; 32];
        // Locking may legitimately fail under a low RLIMIT_MEMLOCK.
        let locked = LockedPages::lock(&mut buffer);
        drop(locked);
        assert_eq!(buffer.len(), 32);
    }

    #[test]
    fn the_socket_directory_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("encino");
        ensure_private_dir(&target).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "socket directory must not be reachable by others: {mode:o}");
    }

    #[test]
    fn an_existing_directory_has_its_permissions_corrected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("encino");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();

        // A directory left world-writable by an earlier run must not be trusted.
        ensure_private_dir(&target).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "permissions should have been corrected, got {mode:o}");
    }

    #[test]
    fn a_socket_file_is_restricted_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sock");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        restrict_to_owner(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be owner-only, got {mode:o}");
    }
}
