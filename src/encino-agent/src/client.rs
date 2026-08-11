//! Talking to a running agent, and starting one.

#[cfg(windows)]
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::protocol::{Request, Response};

/// Why a request to the agent did not succeed.
#[derive(Debug)]
pub enum AgentError {
    /// No agent is running for this vault, so there is no session.
    NotRunning,
    /// The agent answered with a failure.
    Refused(String),
    /// The connection itself failed.
    Io(std::io::Error),
    /// The agent's reply could not be understood.
    Protocol(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::NotRunning => f.write_str("no session is open (run `encino unlock` first)"),
            AgentError::Refused(m) => write!(f, "the session agent refused: {m}"),
            AgentError::Io(e) => write!(f, "could not reach the session agent: {e}"),
            AgentError::Protocol(m) => write!(f, "the session agent replied unexpectedly: {m}"),
        }
    }
}

impl std::error::Error for AgentError {}

/// A stream to the agent: a named pipe on Windows, a Unix socket elsewhere.
#[cfg(windows)]
type Connection = std::fs::File;
#[cfg(unix)]
type Connection = std::os::unix::net::UnixStream;

/// A connection to the agent serving one vault.
pub struct AgentClient {
    /// Pipe name on Windows, socket path on Unix.
    endpoint: String,
}

impl AgentClient {
    /// Address the agent for `vault_id`.
    #[cfg(windows)]
    pub fn for_vault(vault_id: &str) -> Result<Self, AgentError> {
        let sid = crate::win::current_user_sid().map_err(AgentError::Io)?;
        Ok(AgentClient { endpoint: crate::protocol::pipe_name(vault_id, &sid) })
    }

    /// Address the agent for `vault_id`.
    #[cfg(unix)]
    pub fn for_vault(vault_id: &str) -> Result<Self, AgentError> {
        let path = crate::protocol::socket_path(vault_id);
        Ok(AgentClient { endpoint: path.to_string_lossy().into_owned() })
    }

    /// Whether an agent is listening and answering. Requires a real reply, so a
    /// wedged agent does not read as a healthy session.
    pub fn is_running(&self) -> bool {
        self.status().is_ok()
    }

    /// Fetch the master key, or discover that no session is open.
    pub fn master_key(&self) -> Result<(Zeroizing<Vec<u8>>, Duration), AgentError> {
        match self.send(&Request::MasterKey)? {
            Response::MasterKey { mut key, expires_in } => {
                use base64::Engine;
                use zeroize::Zeroize;

                let decoded = base64::engine::general_purpose::STANDARD.decode(&key);
                // Before any early return, so no path leaves the encoded key behind.
                key.zeroize();

                let bytes =
                    decoded.map_err(|e| AgentError::Protocol(format!("key was not valid base64: {e}")))?;
                if bytes.len() != 32 {
                    return Err(AgentError::Protocol("key was the wrong length".into()));
                }
                Ok((Zeroizing::new(bytes), Duration::from_secs(expires_in)))
            }
            Response::Error { message } => Err(AgentError::Refused(message)),
            other => Err(AgentError::Protocol(format!("expected a key, got {other:?}"))),
        }
    }

    /// Ask what the agent is holding.
    pub fn status(&self) -> Result<(String, Duration), AgentError> {
        match self.send(&Request::Status)? {
            Response::Status { vault, expires_in } => Ok((vault, Duration::from_secs(expires_in))),
            Response::Error { message } => Err(AgentError::Refused(message)),
            other => Err(AgentError::Protocol(format!("expected status, got {other:?}"))),
        }
    }

    /// Reset the session deadline.
    pub fn set_timeout(&self, timeout: Duration) -> Result<(), AgentError> {
        match self.send(&Request::SetTimeout { seconds: timeout.as_secs() })? {
            Response::Done => Ok(()),
            Response::Error { message } => Err(AgentError::Refused(message)),
            other => Err(AgentError::Protocol(format!("expected acknowledgement, got {other:?}"))),
        }
    }

    /// Tell the agent to forget its key and exit.
    pub fn lock(&self) -> Result<(), AgentError> {
        match self.send(&Request::Lock) {
            Ok(Response::Done) => Ok(()),
            Ok(Response::Error { message }) => Err(AgentError::Refused(message)),
            Ok(other) => Err(AgentError::Protocol(format!("expected acknowledgement, got {other:?}"))),
            // The agent exits as it replies, so a dropped connection means done.
            Err(AgentError::Io(_)) | Err(AgentError::NotRunning) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn send(&self, request: &Request) -> Result<Response, AgentError> {
        let stream = self.connect()?;
        let mut writer = &stream;
        let line = serde_json::to_string(request)
            .map_err(|e| AgentError::Protocol(format!("could not encode the request: {e}")))?;
        writer.write_all(line.as_bytes()).map_err(AgentError::Io)?;
        writer.write_all(b"\n").map_err(AgentError::Io)?;
        writer.flush().map_err(AgentError::Io)?;

        // Holds the whole reply, master key included, so it is wiped rather than
        // dropped — on every path, including the failures.
        let mut reply = String::new();
        let read = BufReader::new(&stream).read_line(&mut reply).map_err(AgentError::Io);

        let parsed = read.and_then(|_| {
            if reply.trim().is_empty() {
                Err(AgentError::Protocol("the agent closed the connection without replying".into()))
            } else {
                serde_json::from_str(reply.trim())
                    .map_err(|e| AgentError::Protocol(format!("could not decode the reply: {e}")))
            }
        });

        zeroize::Zeroize::zeroize(&mut reply);
        parsed
    }

    /// Open the pipe, retrying while every instance is busy. An absent pipe
    /// means "no session"; `ERROR_PIPE_BUSY` does not, since the agent replaces
    /// its listening instance just after accepting.
    #[cfg(windows)]
    fn connect(&self) -> Result<Connection, AgentError> {
        const ERROR_PIPE_BUSY: i32 = 231;

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match OpenOptions::new().read(true).write(true).open(&self.endpoint) {
                Ok(pipe) => return Ok(pipe),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AgentError::NotRunning);
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(AgentError::Io(e));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(AgentError::Io(e)),
            }
        }
    }

    /// Connect to the agent's socket. An absent socket and a stale one left by
    /// a dead agent both mean "no session", so both map to `NotRunning`.
    #[cfg(unix)]
    fn connect(&self) -> Result<Connection, AgentError> {
        use std::io::ErrorKind;

        match Connection::connect(&self.endpoint) {
            Ok(stream) => Ok(stream),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                Err(AgentError::NotRunning)
            }
            Err(e) => Err(AgentError::Io(e)),
        }
    }
}

/// Start an agent holding `master_key` for `vault`. The key goes to the child
/// on stdin; a command-line argument would be visible to process listings.
pub fn spawn(
    vault_root: &Path,
    vault_id: &str,
    master_key: &[u8],
    timeout: Duration,
) -> Result<(), AgentError> {
    use base64::Engine;
    use std::process::{Command, Stdio};

    // Re-execute this binary rather than a separate agent executable: encino
    // ships as one file, so the halves cannot disagree about a version.
    let self_path = std::env::current_exe().map_err(AgentError::Io)?;

    // Must precede the child, or it inherits our stdout for the whole session
    // and any caller capturing our output hangs until the session expires.
    #[cfg(windows)]
    crate::win::make_std_handles_non_inheritable();

    let mut command = Command::new(&self_path);
    command
        .arg("agent")
        .arg("--vault")
        .arg(vault_root)
        .arg("--vault-id")
        .arg(vault_id)
        .arg("--timeout")
        .arg(timeout.as_secs().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // The agent outlives the starting shell and must not flash a console.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group, so closing the terminal SIGHUPs the shell and not
        // the agent. No inheritance step: Rust opens files close-on-exec.
        command.process_group(0);
    }

    let mut handle = command.spawn().map_err(AgentError::Io)?;

    {
        let mut stdin = handle
            .stdin
            .take()
            .ok_or_else(|| AgentError::Protocol("could not hand the key to the agent".into()))?;
        let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(master_key));
        stdin.write_all(encoded.as_bytes()).map_err(AgentError::Io)?;
        stdin.write_all(b"\n").map_err(AgentError::Io)?;
        stdin.flush().map_err(AgentError::Io)?;
        // Dropping closes the pipe, signalling that the key is complete.
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_agent_means_no_session_rather_than_an_obscure_error() {
        let client = AgentClient::for_vault("00000000-0000-0000-0000-000000000000").unwrap();
        assert!(matches!(client.master_key(), Err(AgentError::NotRunning)));
        assert!(!client.is_running());
    }

    #[test]
    fn locking_a_vault_with_no_session_is_not_an_error() {
        let client = AgentClient::for_vault("00000000-0000-0000-0000-000000000001").unwrap();
        assert!(client.lock().is_ok());
    }

    #[test]
    fn errors_read_as_advice() {
        assert!(AgentError::NotRunning.to_string().contains("encino unlock"));
    }
}
