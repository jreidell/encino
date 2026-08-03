//! Command-line front-end for encino. Prompting and terminal output only;
//! vault logic lives in `encino-core`.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

mod commands;
mod prompt;

#[derive(Parser)]
#[command(
    name = "encino",
    version,
    about = "Local encrypted document vault",
    long_about = "Encrypts a folder's documents at rest, hiding both contents and filenames.\n\
                  Documents are checked out individually and re-encrypted when you are done."
)]
struct Cli {
    /// Vault folder to operate on. Defaults to the current directory.
    #[arg(long, short = 'C', global = true, value_name = "FOLDER")]
    vault: Option<PathBuf>,

    /// Read passphrases and answers from standard input rather than prompting.
    ///
    /// For scripting; a piped passphrase may land in shell history.
    #[arg(long, global = true)]
    passphrase_stdin: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a vault in a folder and set its passphrase.
    Init {
        /// Folder to turn into a vault.
        folder: PathBuf,
    },

    /// Import files or folders into the vault, encrypting them.
    Add {
        /// Paths to import. Folders are imported recursively.
        paths: Vec<PathBuf>,

        /// Leave every original in place, including those inside the vault.
        #[arg(long, conflicts_with = "move_originals")]
        keep: bool,

        /// Also shred originals that live outside the vault folder.
        #[arg(long = "move", conflicts_with = "keep")]
        move_originals: bool,
    },

    /// List the documents held in the vault.
    Ls {
        /// Emit machine-readable JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Decrypt documents into the vault folder for use.
    Open {
        /// Documents to check out.
        paths: Vec<String>,

        /// Check out every document in the vault.
        #[arg(long, conflicts_with = "paths")]
        all: bool,

        /// Automatically re-encrypt after this long, e.g. 30m or 2h.
        #[arg(long, value_name = "DURATION")]
        timer: Option<String>,

        /// Launch each document in its default application after decrypting.
        #[arg(long)]
        with: bool,
    },

    /// Re-encrypt checked-out documents and shred the plaintext.
    Close {
        /// Documents to check in.
        paths: Vec<String>,

        /// Check in every open document.
        #[arg(long, conflicts_with = "paths")]
        all: bool,
    },

    /// Start a session so later commands do not re-prompt.
    Unlock {
        /// End the session automatically after this long. Defaults to 30m.
        #[arg(long, value_name = "DURATION")]
        timer: Option<String>,
    },

    /// Show session state, open documents, and time remaining.
    Status,

    /// Close everything, stop the agent, and forget the key.
    Lock,

    /// Suggest a strong passphrase. Touches no vault and saves nothing.
    Passphrase {
        /// How many words to draw. Six is about 77 bits.
        #[arg(long, default_value_t = encino_core::passphrase::DEFAULT_WORDS)]
        words: usize,
    },

    /// Change the passphrase. Rewraps the master key; does not re-encrypt documents.
    Passwd,

    /// Unlock using the 24-word recovery code instead of the passphrase.
    Recover,

    /// Authenticate every stored blob against the index.
    Verify,

    /// Decrypt the entire vault into a directory.
    Export {
        /// Destination directory. Must be empty or nonexistent.
        dest: PathBuf,
    },

    /// Run as the session daemon. Started by `unlock`; not meant to be typed.
    ///
    /// `unlock` re-executes this same binary, which lets encino ship as a single file. The master key arrives on stdin.
    #[command(hide = true)]
    Agent {
        /// Vault the session belongs to.
        #[arg(long)]
        vault: PathBuf,

        /// Identifies the vault, and with it the socket or pipe to serve on.
        #[arg(long = "vault-id")]
        vault_id: String,

        /// Seconds until the session ends.
        #[arg(long, default_value_t = encino_agent::DEFAULT_TIMEOUT_SECS)]
        timeout: u64,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    prompt::use_stdin(cli.passphrase_stdin);

    let root = || -> anyhow::Result<PathBuf> {
        match &cli.vault {
            Some(path) => Ok(path.clone()),
            None => std::env::current_dir().map_err(Into::into),
        }
    };

    match cli.command {
        Command::Init { ref folder } => commands::credentials::init(folder),
        // Needs no vault, so it never resolves a root.
        Command::Passphrase { words } => commands::credentials::suggest(words),
        Command::Agent { ref vault, ref vault_id, timeout } => {
            encino_agent::server::serve(vault.clone(), vault_id, Duration::from_secs(timeout))
        }
        Command::Passwd => commands::credentials::passwd(&root()?),
        Command::Recover => commands::credentials::recover(&root()?),
        Command::Add { ref paths, keep, move_originals } => {
            commands::documents::add(&root()?, paths, keep, move_originals)
        }
        Command::Ls { json } => commands::documents::list(&root()?, json),
        Command::Open { ref paths, all, ref timer, with } => {
            commands::documents::open(&root()?, paths, all, with)?;
            if let Some(timer) = timer {
                commands::session::set_auto_lock(&root()?, timer)?;
            }
            Ok(())
        }
        Command::Close { ref paths, all } => commands::documents::close(&root()?, paths, all),
        Command::Unlock { ref timer } => commands::session::unlock(&root()?, timer.as_deref()),
        Command::Status => commands::session::status(&root()?),
        Command::Lock => commands::session::lock(&root()?),
        Command::Verify => commands::documents::verify(&root()?),
        Command::Export { ref dest } => commands::documents::export(&root()?, dest),
    }
}
