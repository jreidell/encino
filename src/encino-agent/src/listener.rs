//! A Unix-domain socket server restricted to one account. Counterpart to
//! `pipe.rs`, but simpler: `accept` returns an independent connection each time,
//! so there is no instance reuse to guard against.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::unix;

/// A socket only its owner may reach.
pub struct SocketServer {
    listener: UnixListener,
    path: PathBuf,
}

impl SocketServer {
    /// Bind the socket, failing if another agent already holds it.
    ///
    /// The directory is 0700 and the socket 0600; that is what keeps other
    /// accounts out. A leftover socket is told apart from a live one by trying to
    /// connect — a refused connection means the owning agent is gone.
    pub fn bind(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            unix::ensure_private_dir(parent)?;
        }

        if path.exists() {
            match UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "an agent is already running for this vault",
                    ));
                }
                // Nobody is listening, so the file is a remnant of a dead
                // process. Clearing it makes a crash self-healing.
                Err(_) => std::fs::remove_file(path)?,
            }
        }

        let listener = UnixListener::bind(path)?;
        unix::restrict_to_owner(path)?;

        Ok(SocketServer { listener, path: path.to_path_buf() })
    }

    /// Wait for a client.
    pub fn accept(&mut self) -> io::Result<UnixStream> {
        self.listener.accept().map(|(stream, _)| stream)
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        // Removing the socket saves the next `bind` the connect-and-unlink probe.
        let _ = std::fs::remove_file(&self.path);
    }
}
