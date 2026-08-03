//! Error type for the vault engine.

use std::path::PathBuf;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Failures the vault engine can report.
///
/// Note what is deliberately *absent*: there is no variant distinguishing "wrong
/// passphrase" from "corrupted key material" from "tampered ciphertext". All
/// three collapse into [`Error::AuthenticationFailed`]. Telling them apart would
/// hand an attacker an oracle for probing a vault, and the distinction is of no
/// use to a legitimate user, who in every case must supply correct credentials
/// against intact data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Decryption or key unwrapping failed authentication.
    #[error("authentication failed: wrong credentials, or the data has been altered")]
    AuthenticationFailed,

    /// The target directory is not a encino vault.
    #[error("no vault found at {0} (run `encino init` first)")]
    NotAVault(PathBuf),

    /// The target directory already contains a vault.
    #[error("a vault already exists at {0}")]
    VaultExists(PathBuf),

    /// The vault was written by an incompatible format version.
    #[error("vault format version {found} is not supported (this build understands {supported})")]
    UnsupportedVersion {
        /// Version recorded in `vault.json`.
        found: u32,
        /// Version this build can read.
        supported: u32,
    },

    /// Vault metadata could not be parsed.
    #[error("vault metadata at {path} is malformed: {detail}")]
    MalformedMetadata {
        /// File that failed to parse.
        path: PathBuf,
        /// What went wrong.
        detail: String,
    },

    /// A passphrase of that many words was asked for and refused.
    #[error("a suggested passphrase must be between {min} and {max} words, not {requested}")]
    InvalidWordCount {
        /// What was asked for.
        requested: usize,
        /// Fewest allowed.
        min: usize,
        /// Most allowed.
        max: usize,
    },

    /// A recovery mnemonic was not a valid BIP39 phrase.
    #[error("recovery code is not valid: {0}")]
    InvalidRecoveryCode(String),

    /// A document was requested that the index does not contain.
    #[error("no document named {0} in this vault")]
    NoSuchDocument(String),

    /// A logical document name is unusable or unsafe.
    #[error("{path:?} is not a usable document name: {reason}")]
    InvalidDocumentPath {
        /// The offending name.
        path: String,
        /// Why it was refused.
        reason: String,
    },

    /// A file was not destroyed because doing so looked unsafe.
    #[error("refused to shred {path}: {reason}")]
    RefusedToShred {
        /// The file left alone.
        path: PathBuf,
        /// Why it was left alone.
        reason: String,
    },

    /// Another session holds the vault.
    #[error("{} is in use{}", .path.display(), match .holder {
        Some(who) => format!(" by {who}"),
        None => String::new(),
    })]
    VaultInUse {
        /// The lock file that could not be taken.
        path: PathBuf,
        /// Who holds it, when that could be determined.
        holder: Option<String>,
    },

    /// A document is already checked out.
    #[error("{0} is already open; close it before opening it again")]
    AlreadyOpen(String),

    /// A document is not checked out.
    #[error("{0} is not open")]
    NotOpen(String),

    /// Something occupies the path a document needs.
    #[error("{path} is in the way of {document}")]
    PathOccupied {
        /// The obstruction.
        path: PathBuf,
        /// Document that needs the path.
        document: String,
    },

    /// Stored data does not match the format this build expects.
    #[error("{path} is corrupt or not a encino file: {detail}")]
    CorruptData {
        /// File involved.
        path: PathBuf,
        /// What was wrong.
        detail: String,
    },

    /// A document with that logical path is already in the index.
    #[error("a document named {0} is already in this vault")]
    DuplicateDocument(String),

    /// Underlying filesystem failure, with the path that caused it.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// What the engine was attempting.
        operation: &'static str,
        /// Path involved.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// Attach path and operation context to an [`std::io::Error`].
    pub fn io(operation: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io { operation, path: path.into(), source }
    }
}
