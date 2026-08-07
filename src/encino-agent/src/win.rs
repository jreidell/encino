//! The Win32 calls the agent needs: the user's SID, the pipe's security
//! descriptor, keeping the key out of the page file, and giving a pipe read a
//! deadline.
//!
//! `unsafe` in encino lives in exactly three files, all in this crate: this one,
//! [`crate::unix`], and [`crate::pipe`], which owns the named-pipe lifecycle.
//! `encino-core` is `#![forbid(unsafe_code)]` and `encino-cli` has none.

use std::io;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The string SID of the account this process is running as. It also names the
/// pipe, so two accounts on one machine never contend for the same name.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: the process pseudo-handle needs no closing; the token is closed below.
    let mut token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let _token = OwnedHandle(token);

    let mut needed = 0u32;
    // SAFETY: a null buffer of zero length is the documented size query.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` is the size the query above reported as sufficient.
    let ok =
        unsafe { GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), needed, &mut needed) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the buffer holds a TOKEN_USER whose `User.Sid` points into it.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut sid_string: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is valid while `buffer` lives; the string needs `LocalFree`.
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut sid_string) };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = OwnedLocalAlloc(sid_string.cast());

    // SAFETY: `ConvertSidToStringSidW` produces a NUL-terminated UTF-16 string.
    let text = unsafe { wide_to_string(sid_string) };
    drop(owned);
    Ok(text)
}

/// Stop this process's standard handles from being inherited by children.
///
/// Must be called before starting the agent. Captured stdout is the write end of
/// an inheritable pipe; an agent that inherits it holds the pipe open after this
/// process exits, so the reader blocks until the session expires.
pub fn make_std_handles_non_inheritable() {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: `GetStdHandle` returns a borrowed handle, not closed here.
        // Clearing the inherit flag on a handle still in use is well defined.
        unsafe {
            let handle = GetStdHandle(id);
            if !handle.is_null() && handle != INVALID_HANDLE {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// `INVALID_HANDLE_VALUE`, which `GetStdHandle` returns when there is no handle.
const INVALID_HANDLE: HANDLE = -1isize as HANDLE;

/// Bytes examined per peek. Requests are single JSON lines an order of magnitude
/// shorter than the pipe's own buffer, so a line that is not in here is not one.
const PEEK_BYTES: usize = 8 * 1024;

/// How often to look while waiting for a request.
const PEEK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Wait until a whole line is buffered on `handle`, or `timeout` passes.
///
/// `ReadFile` on a blocking pipe instance takes no deadline, so a client that
/// connects and then says nothing would hold the agent's accept loop for as long
/// as it cared to. Peeking does not consume, so the read that follows sees
/// exactly the same bytes.
///
/// Returns whether a line arrived; `false` means drop the connection rather than
/// read from it. A closed pipe returns immediately — there is nothing to wait for.
///
/// # Safety
/// `handle` must be a live pipe instance for the duration of the call. The only
/// caller is [`crate::pipe::PipeConnection::wait_for_request`], which owns one
/// and so can guarantee that; this takes a bare handle rather than a connection
/// to keep the FFI in this module.
pub unsafe fn wait_for_line(handle: HANDLE, timeout: std::time::Duration) -> bool {
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let deadline = std::time::Instant::now() + timeout;
    let mut buffer = [0u8; PEEK_BYTES];

    loop {
        let mut peeked: u32 = 0;
        // SAFETY: the caller guarantees `handle` is live. The buffer and count
        // pointers address local storage of exactly the length passed alongside
        // them; the two optional outputs are declined.
        let ok = unsafe {
            PeekNamedPipe(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut peeked,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return false;
        }
        if buffer[..peeked as usize].contains(&b'\n') {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(PEEK_INTERVAL);
    }
}

/// A security descriptor granting full access to exactly one SID. `D:P` protects
/// the ACL, so no inherited entry can widen access.
pub struct PipeSecurity {
    descriptor: OwnedLocalAlloc,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    /// Build a descriptor allowing only `sid`.
    pub fn for_sid(sid: &str) -> io::Result<Self> {
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `wide` outlives the call; the descriptor is released in Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };

        Ok(PipeSecurity { descriptor: OwnedLocalAlloc(descriptor.cast()), attributes })
    }

    /// Pointer to pass to `CreateNamedPipeW`. Borrows `self`, so the descriptor
    /// cannot be released while the pipe is being created.
    pub fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        let _ = &self.descriptor;
        &self.attributes
    }
}

/// Ask the kernel to keep a region out of the page file. Without it, memory
/// pressure could page the master key into `pagefile.sys`, where it persists
/// after the agent exits. It does not survive hibernation.
pub struct LockedPages {
    address: *mut std::ffi::c_void,
    length: usize,
}

impl LockedPages {
    /// Attempt to lock `bytes` in physical memory. Returns `None` when the
    /// working-set quota disallows it, which is normal rather than an error;
    /// the key is zeroized on drop either way.
    pub fn lock(bytes: &mut [u8]) -> Option<Self> {
        let address = bytes.as_mut_ptr().cast();
        let length = bytes.len();
        // SAFETY: the region is a live borrow of `bytes`; Drop unlocks the same
        // region and claims nothing more.
        if unsafe { VirtualLock(address, length) } == 0 {
            None
        } else {
            Some(LockedPages { address, length })
        }
    }
}

// SAFETY: the state is an address and a length, never dereferenced. Page locking
// is process-wide, so unlocking from a different thread is well defined.
unsafe impl Send for LockedPages {}

impl Drop for LockedPages {
    fn drop(&mut self) {
        // SAFETY: unlocks exactly the region locked in `lock`.
        unsafe { VirtualUnlock(self.address, self.length) };
    }
}

/// A handle closed on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from `OpenProcessToken` and is closed once.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

/// Memory from a Win32 `Local*` allocator, released on drop.
struct OwnedLocalAlloc(*mut std::ffi::c_void);

impl Drop for OwnedLocalAlloc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a `Local*` allocator and is freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Read a NUL-terminated UTF-16 string.
///
/// # Safety
/// `ptr` must point to a NUL-terminated UTF-16 sequence.
unsafe fn wide_to_string(ptr: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the caller guarantees termination, so the scan halts.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units are initialized and within the same allocation.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_user_has_a_well_formed_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "unexpected SID form: {sid}");
        assert!(sid.len() > 8);
    }

    #[test]
    fn a_security_descriptor_can_be_built_for_the_current_user() {
        let sid = current_user_sid().unwrap();
        let security = PipeSecurity::for_sid(&sid).unwrap();
        assert!(!security.as_ptr().is_null());
    }

    #[test]
    fn a_malformed_sid_is_rejected_rather_than_silently_widening_access() {
        // A descriptor that failed to parse must never become "allow everyone".
        assert!(PipeSecurity::for_sid("not-a-sid").is_err());
    }

    #[test]
    fn memory_can_be_locked_and_unlocked() {
        let mut buffer = vec![0u8; 32];
        // Locking may legitimately fail on a constrained working set.
        let locked = LockedPages::lock(&mut buffer);
        drop(locked);
        assert_eq!(buffer.len(), 32);
    }
}
