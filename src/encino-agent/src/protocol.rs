//! Wire protocol between the CLI and the session agent.
//!
//! One request and one response per connection, each a single line of JSON. The
//! absence of state or framing is deliberate.

use serde::{Deserialize, Serialize};

/// What a client is asking for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Fetch the master key for this session. See [`crate`] for why the key
    /// itself crosses the pipe.
    MasterKey,
    /// Ask what the agent is holding and for how long.
    Status,
    /// Reset how long the session has left. The agent owns the deadline because
    /// it is the only process outliving the command that still holds the key.
    SetTimeout {
        /// Seconds from now until the session ends.
        seconds: u64,
    },
    /// Forget the key and exit.
    Lock,
}

/// What the agent answers.
///
/// `Debug` is written by hand rather than derived: every unexpected-response
/// path in the client formats one into an error message, and a derived `Debug`
/// would print the master key into it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    /// The master key, base64-encoded.
    MasterKey {
        /// Base64 of the 32-byte key.
        key: String,
        /// Seconds until the session expires.
        expires_in: u64,
    },
    /// Current session state.
    Status {
        /// Vault folder the agent is attached to.
        vault: String,
        /// Seconds until the session expires.
        expires_in: u64,
    },
    /// The request succeeded and carries nothing.
    Done,
    /// The request failed.
    Error {
        /// Why.
        message: String,
    },
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::MasterKey { expires_in, .. } => {
                write!(f, "MasterKey {{ key: <redacted>, expires_in: {expires_in} }}")
            }
            Response::Status { vault, expires_in } => {
                write!(f, "Status {{ vault: {vault:?}, expires_in: {expires_in} }}")
            }
            Response::Done => f.write_str("Done"),
            Response::Error { message } => write!(f, "Error {{ message: {message:?} }}"),
        }
    }
}

impl Response {
    /// Wipe any key material this response is carrying.
    ///
    /// [`Response::MasterKey`] holds base64 of the master key. Dropping it
    /// normally leaves that copy in freed heap, which can be paged out — which
    /// would undo much of what locking the key into physical memory buys the
    /// agent in the first place.
    ///
    /// Best-effort by nature: only the buffer the `String` currently owns can be
    /// reached, so a reallocation made while parsing is out of reach. It closes
    /// the copy that is certainly there rather than every copy that might be.
    pub fn zeroize_secrets(&mut self) {
        use zeroize::Zeroize;

        if let Response::MasterKey { key, .. } = self {
            key.zeroize();
        }
    }
}

/// Name of the pipe serving one vault for one user. The vault id stops separate
/// vaults sharing an agent; the SID stops two accounts colliding on one name.
#[cfg(windows)]
pub fn pipe_name(vault_id: &str, user_sid: &str) -> String {
    // SIDs are digits and hyphens, vault ids hex and hyphens, so neither can
    // introduce a path separator.
    format!(r"\\.\pipe\encino.{vault_id}.{user_sid}")
}

/// Directory holding this user's agent sockets.
///
/// Prefers `$XDG_RUNTIME_DIR`: per-user, mode 0700, cleared on logout. Falls
/// back to a per-uid directory under the temporary directory, created 0700 by
/// the caller. Access control rests entirely on those directory permissions.
/// Kept short because `sockaddr_un` caps the path at about 108 bytes.
#[cfg(unix)]
pub fn socket_dir() -> std::path::PathBuf {
    use std::path::PathBuf;

    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("encino");
    }
    std::env::temp_dir().join(format!("encino-{}", crate::unix::current_uid()))
}

/// Shorten a vault id for use in a socket name.
///
/// `sockaddr_un` caps the whole path at 104 bytes on macOS and 108 on Linux, and
/// the directory it sits in is not this crate's to shorten: macOS hands out a
/// per-user `TMPDIR` around 50 bytes long all by itself. A full 36-character
/// UUID left roughly three bytes of headroom there, which is not headroom.
///
/// The first 64 bits of the id are kept — enough that two vaults on one machine
/// colliding is not a practical concern — and the hyphens dropped, which is 20
/// bytes back. Only the name changes; nothing about it is relied on for
/// security, since the enclosing directory is what keeps other accounts out.
#[cfg(unix)]
fn short_vault_id(vault_id: &str) -> String {
    vault_id.chars().filter(char::is_ascii_alphanumeric).take(16).collect()
}

/// Path of the socket serving one vault.
#[cfg(unix)]
pub fn socket_path(vault_id: &str) -> std::path::PathBuf {
    socket_dir().join(format!("{}.sock", short_vault_id(vault_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_as_single_json_lines() {
        for request in
            [Request::MasterKey, Request::Status, Request::SetTimeout { seconds: 60 }, Request::Lock]
        {
            let line = serde_json::to_string(&request).unwrap();
            assert!(!line.contains('\n'), "a request must fit on one line");
            let parsed: Request = serde_json::from_str(&line).unwrap();
            assert_eq!(std::mem::discriminant(&parsed), std::mem::discriminant(&request));
        }
    }

    #[test]
    fn responses_round_trip() {
        let response = Response::MasterKey { key: "AAAA".into(), expires_in: 1800 };
        let line = serde_json::to_string(&response).unwrap();
        assert!(!line.contains('\n'));

        match serde_json::from_str::<Response>(&line).unwrap() {
            Response::MasterKey { key, expires_in } => {
                assert_eq!(key, "AAAA");
                assert_eq!(expires_in, 1800);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn pipe_names_separate_vaults_and_users() {
        let a = pipe_name("vault-one", "S-1-5-21-1");
        let b = pipe_name("vault-two", "S-1-5-21-1");
        let c = pipe_name("vault-one", "S-1-5-21-2");

        assert_ne!(a, b, "separate vaults must not share an agent");
        assert_ne!(a, c, "separate users must not collide on one pipe name");
        assert!(a.starts_with(r"\\.\pipe\"));
    }

    #[cfg(unix)]
    #[test]
    fn socket_paths_separate_vaults_and_stay_within_the_length_limit() {
        let a = socket_path("9f1c2d3e-4b5a-6c7d-8e9f-0a1b2c3d4e5f");
        let b = socket_path("00000000-0000-0000-0000-000000000000");

        assert_ne!(a, b, "separate vaults must not share an agent");
        assert!(a.starts_with(socket_dir()));

        // `sun_path` is 104 bytes on macOS and 108 on Linux, so the tighter of
        // the two is the budget. The margin matters: this ran with three bytes
        // to spare on macOS, whose per-user TMPDIR is around fifty on its own.
        assert!(
            a.as_os_str().len() < 100,
            "socket path is too long for sockaddr_un: {} bytes",
            a.as_os_str().len()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_shortened_vault_id_stays_distinguishing_and_carries_no_separators() {
        // A path separator smuggled in here would put the socket somewhere else
        // entirely, so only alphanumerics survive.
        assert_eq!(short_vault_id("9f1c2d3e-4b5a-6c7d-8e9f-0a1b2c3d4e5f"), "9f1c2d3e4b5a6c7d");
        assert_eq!(short_vault_id("../../etc/passwd"), "etcpasswd");
        assert!(!short_vault_id("a/b/c-d").contains('/'));

        // 64 bits of the id is kept, which two vaults on one machine will not
        // collide on; ids differing only past that point are not a real case.
        assert_ne!(
            short_vault_id("9f1c2d3e-4b5a-6c7d-8e9f-0a1b2c3d4e5f"),
            short_vault_id("9f1c2d3e-4b5a-6c7e-8e9f-0a1b2c3d4e5f")
        );
    }

    #[test]
    fn a_response_never_prints_the_master_key() {
        // Every unexpected-response path in the client formats one of these into
        // an error message, which is then printed. A derived Debug leaks the key.
        let response = Response::MasterKey { key: "c3VwZXItc2VjcmV0LWtleQ==".into(), expires_in: 1800 };
        let rendered = format!("{response:?}");

        assert!(!rendered.contains("c3VwZXI"), "the key reached a debug rendering: {rendered}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("1800"), "the harmless fields should still be legible");
    }

    #[test]
    fn wiping_a_response_clears_the_key_it_carried() {
        let mut response = Response::MasterKey { key: "c3VwZXItc2VjcmV0".into(), expires_in: 60 };
        response.zeroize_secrets();

        match response {
            Response::MasterKey { key, .. } => assert!(key.is_empty(), "the key was left in place"),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_socket_directory_is_per_user() {
        // Two accounts must never share a directory, or the first to start an
        // agent owns it and the second cannot create one.
        let dir = socket_dir().to_string_lossy().into_owned();
        let uid = crate::unix::current_uid().to_string();
        assert!(
            dir.contains(&uid) || std::env::var_os("XDG_RUNTIME_DIR").is_some(),
            "fallback directory must be distinguished by uid: {dir}"
        );
    }
}
