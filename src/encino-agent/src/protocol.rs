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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Path of the socket serving one vault.
#[cfg(unix)]
pub fn socket_path(vault_id: &str) -> std::path::PathBuf {
    socket_dir().join(format!("{vault_id}.sock"))
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

        // sockaddr_un caps the path at roughly 108 bytes.
        assert!(
            a.as_os_str().len() < 100,
            "socket path is too long for sockaddr_un: {} bytes",
            a.as_os_str().len()
        );
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
