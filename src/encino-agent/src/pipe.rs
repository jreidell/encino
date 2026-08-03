//! A named pipe server restricted to one account.
//!
//! Each client gets its own pipe instance. With a single reused instance, the
//! next client binds the moment the previous one closes, and the server's
//! `DisconnectNamedPipe` for the finished transaction tears down that new
//! client's connection. The server therefore creates the replacement instance
//! before serving the one it accepted.

use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;

use crate::win::PipeSecurity;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Bytes buffered in each direction; requests and replies are single JSON lines.
const BUFFER_SIZE: u32 = 8 * 1024;

/// A named pipe only the owning account may open.
pub struct PipeServer {
    name: Vec<u16>,
    listener: HANDLE,
    security: PipeSecurity,
}

impl PipeServer {
    /// Create the pipe, failing if one of this name already exists.
    ///
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE` fails when the name is taken, so a
    /// squatter cannot answer this agent's clients; only the first instance may
    /// carry it. `PIPE_REJECT_REMOTE_CLIENTS` refuses connections over the network.
    pub fn create(name: &str, owner_sid: &str) -> io::Result<Self> {
        let security = PipeSecurity::for_sid(owner_sid)?;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let listener = create_instance(&wide, &security, true)?;
        Ok(PipeServer { name: wide, listener, security })
    }

    /// Wait for a client and return its connection.
    pub fn accept(&mut self) -> io::Result<PipeConnection> {
        // SAFETY: `self.listener` is a valid pipe instance owned by this server.
        let connected = unsafe { ConnectNamedPipe(self.listener, std::ptr::null_mut()) };

        if connected == 0 {
            let error = io::Error::last_os_error();
            // A client attached before this call is success, not failure.
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                return Err(error);
            }
        }

        // A fresh instance goes in place before this one is served, so the name
        // never lacks a listener and closing the served instance affects nobody.
        let served =
            std::mem::replace(&mut self.listener, create_instance(&self.name, &self.security, false)?);

        Ok(PipeConnection { handle: served })
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        if self.listener != INVALID_HANDLE_VALUE {
            // SAFETY: closing a handle this type owns, exactly once.
            unsafe { CloseHandle(self.listener) };
        }
    }
}

fn create_instance(name: &[u16], security: &PipeSecurity, first: bool) -> io::Result<HANDLE> {
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    // SAFETY: `name` is NUL-terminated UTF-16 and `security` is borrowed from the
    // server that owns it, so both outlive this call.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            security.as_ptr().cast_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

/// One accepted client connection, owning its own pipe instance. Reads and
/// writes go through a borrowed [`File`] rather than further hand-written FFI.
pub struct PipeConnection {
    handle: HANDLE,
}

impl PipeConnection {
    fn as_file(&self) -> std::mem::ManuallyDrop<File> {
        // SAFETY: the handle outlives the borrow, and `ManuallyDrop` stops the
        // `File` closing a handle it does not own.
        std::mem::ManuallyDrop::new(unsafe { File::from_raw_handle(self.handle.cast()) })
    }
}

impl io::Read for &PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut &*self.as_file(), buf)
    }
}

impl io::Write for &PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self.as_file(), buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut &*self.as_file())
    }
}

impl Drop for PipeConnection {
    fn drop(&mut self) {
        // SAFETY: `handle` is this connection's own pipe instance, released once.
        // Flushing first is required or the last write can be discarded.
        unsafe {
            FlushFileBuffers(self.handle);
            DisconnectNamedPipe(self.handle);
            CloseHandle(self.handle);
        }
    }
}
