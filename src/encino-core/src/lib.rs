//! Vault engine for encino.
//!
//! This crate owns everything dangerous: key derivation and wrapping, the
//! encrypted index, the blob store, and the crash-recovery journal. It performs
//! no terminal I/O and never prompts — passphrases arrive as borrowed `&str`
//! that the caller owns and wipes, key material lives in [`crypto::Key`], which
//! zeroizes on drop and refuses to print itself, and failures leave as [`Error`].
//! So the whole surface is directly testable and can be driven by a CLI, a GUI,
//! or a filesystem mount without change.
//!
//! See `docs/format.md` for the on-disk format and `docs/threat-model.md` for
//! what this design does and does not protect against.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod blob;
pub mod crypto;
pub mod docpath;
pub mod error;
pub mod fsutil;
pub mod index;
pub mod journal;
pub mod keyring;
pub mod lock;
pub mod passphrase;
pub mod session;
pub mod shred;
pub mod vault;

pub use blob::BlobId;
pub use docpath::DocPath;
pub use error::{Error, Result};
pub use index::{DocumentEntry, Index};
pub use keyring::{KdfConfig, RecoveryCode};
pub use session::{CheckinOutcome, RecoveryAction, Session, VerifyIssue};
pub use vault::{Vault, VaultMeta};

/// Name of the vault metadata directory created inside a managed folder.
pub const VAULT_DIR: &str = ".encino";

/// On-disk format version. Written to `vault.json` at init and checked on every
/// open, so that a revision — hiding the document count, for one — is refused
/// outright rather than misread.
pub const FORMAT_VERSION: u32 = 1;
