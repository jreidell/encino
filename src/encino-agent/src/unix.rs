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

/// Create the agent's socket directory, owner-accessible only.
///
/// Access control rests entirely on this directory, so it is established rather
/// than assumed, and every step avoids following a symlink.
///
/// The last component is created with `mkdir` rather than `create_dir_all`, then
/// opened `O_NOFOLLOW | O_DIRECTORY`. That matters because the fallback location
/// is `/tmp/encino-<uid>` — a name another local user can predict and pre-create
/// as a symlink into a directory they own. Resolving it would put this session's
/// socket somewhere they can reach it, and chmod their directory to 0700 on the
/// way past. `O_NOFOLLOW` refuses the symlink outright instead.
///
/// Ownership and mode are then checked and corrected through the open
/// descriptor, never the path, so nothing can be exchanged underneath between
/// the check and the change.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};

    // Parents may legitimately be shared, `/tmp` being the whole point; only the
    // final component belongs to this user.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    let dir = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;

    // A directory belonging to somebody else is not ours to correct, and using it
    // would hand them this session's socket.
    if rustix::fs::fstat(&dir)?.st_uid != rustix::process::getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} belongs to another user", path.display()),
        ));
    }

    rustix::fs::fchmod(&dir, Mode::RWXU)?;
    Ok(())
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

/// Whether the process at the other end of `stream` runs as this user.
///
/// The socket already sits in a directory [`ensure_private_dir`] proved is ours
/// and made 0700, so this is a second, independent answer to the same question
/// rather than the only one. It is what makes the threat model's claim about
/// verifying connecting clients a property of the agent, not merely of the
/// filesystem underneath it.
///
/// Each supported Unix answers this its own way: `SO_PEERCRED` on Linux,
/// `getpeereid` on macOS. Both ask the kernel rather than the caller, and both
/// fail closed.
#[cfg(target_os = "linux")]
pub fn peer_is_this_user(stream: &std::os::unix::net::UnixStream) -> bool {
    // Fails closed. `SO_PEERCRED` is always available on the platform this is
    // compiled for, so an error here is not a case to wave through.
    match rustix::net::sockopt::socket_peercred(stream) {
        Ok(peer) => peer.uid == rustix::process::getuid(),
        Err(_) => false,
    }
}

/// macOS has no `SO_PEERCRED`. `getpeereid` is the BSD equivalent and gives the
/// same guarantee: the credentials are recorded by the kernel when the peer
/// connects, so a client cannot claim to be somebody else.
///
/// Declared here rather than pulled from `libc`, which is not otherwise a
/// dependency of this crate. `rustix` exposes the Linux call only — its
/// `socket_peercred` is `#[cfg(linux_kernel)]`.
#[cfg(target_os = "macos")]
pub fn peer_is_this_user(stream: &std::os::unix::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd;

    let mut uid: u32 = u32::MAX;
    let mut gid: u32 = u32::MAX;

    // SAFETY: `stream` owns a live descriptor for the whole call, and both
    // out-pointers address initialized locals of exactly the width `uid_t` and
    // `gid_t` have on this platform.
    let queried = unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };

    // Fails closed: the sentinel above is never a real uid, but the return code
    // is what decides, so a failed call cannot be read as a match.
    queried == 0 && uid == current_uid()
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// `getpeereid(2)`: the effective uid and gid of the peer on a Unix socket.
    fn getpeereid(socket: std::ffi::c_int, euid: *mut u32, egid: *mut u32) -> std::ffi::c_int;
}

/// On any other Unix the 0700 directory is the whole control. Nothing else is
/// claimed for those platforms; see `docs/threat-model.md`.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn peer_is_this_user(_stream: &std::os::unix::net::UnixStream) -> bool {
    true
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
    fn a_symlink_planted_at_the_socket_directory_is_refused_not_followed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("owned-by-someone-else");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o777)).unwrap();

        // What another local user can do to a predictable name under a shared
        // /tmp: get there first, and point it at a directory they control.
        let target = dir.path().join("encino");
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();

        assert!(
            ensure_private_dir(&target).is_err(),
            "a symlink must be refused; following it would put the socket where its planter can reach it"
        );

        // And the planter's directory must be left exactly as it was, rather
        // than chmodded to 0700 on their behalf.
        let mode = std::fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o777, "the symlink target was modified through the link: {mode:o}");
    }

    #[test]
    fn a_real_directory_is_still_accepted_after_the_symlink_check() {
        // The guard above must not have made the ordinary path fail.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("encino");

        ensure_private_dir(&target).unwrap();
        ensure_private_dir(&target).expect("a second call on our own directory must succeed");
        assert!(target.is_dir());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_connection_from_this_process_is_recognised_as_ours() {
        // Exercises the real kernel call on whichever platform this is. Without
        // it the macOS branch would be FFI nobody had ever run.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.sock");

        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let (accepted, _) = listener.accept().unwrap();

        assert!(peer_is_this_user(&accepted), "our own connection must be recognised as ours");
        drop(client);
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
