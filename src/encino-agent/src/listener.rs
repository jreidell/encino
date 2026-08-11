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
    /// Device and inode of the socket this server bound.
    ///
    /// Drop removes the socket by name, and by then the name may belong to a
    /// successor: an agent shutting down while another starts for the same vault
    /// would otherwise unlink the newcomer's socket, leaving it listening on
    /// something no client can reach. Recorded so Drop can tell them apart.
    identity: Option<(u64, u64)>,
}

/// Device and inode of whatever `path` currently names.
fn identity_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
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

        Ok(SocketServer { listener, path: path.to_path_buf(), identity: identity_of(path) })
    }

    /// Wait for a client.
    pub fn accept(&mut self) -> io::Result<UnixStream> {
        self.listener.accept().map(|(stream, _)| stream)
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        // Removing the socket saves the next `bind` the connect-and-unlink
        // probe — but only ours, never one that replaced it in the meantime.
        if self.identity.is_some() && identity_of(&self.path) == self.identity {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
