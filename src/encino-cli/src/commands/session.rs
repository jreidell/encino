//! `unlock`, `status`, and `lock` — commands that manage the session.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use encino_agent::client::{AgentClient, AgentError};
use encino_agent::{format_remaining, parse_duration};
use encino_core::{Session, Vault};

use crate::prompt;

/// Resolve a vault, its agent, and an unlocked session.
///
/// With a session running the key comes from the agent, otherwise it is derived for this command only. Nothing is written to disk.
pub fn open_session(root: &Path) -> Result<Session> {
    let vault = Vault::open(root)?;
    let client = AgentClient::for_vault(&vault.id().to_string())?;

    match client.master_key() {
        Ok((key, _)) => {
            let master = encino_core::crypto::Key::from_slice(&key)?;
            Ok(Session::from_master(vault, &master)?)
        }
        Err(AgentError::NotRunning) => {
            prompt::require_interactive()?;
            let passphrase = prompt::passphrase("Passphrase: ")?;
            Ok(Session::unlock(vault, &passphrase)?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Start a session so later commands do not re-prompt.
pub fn unlock(root: &Path, timer: Option<&str>) -> Result<()> {
    let vault = Vault::open(root)?;
    let client = AgentClient::for_vault(&vault.id().to_string())?;

    if let Ok((_, remaining)) = client.status() {
        println!("A session is already open, {} remaining.", format_remaining(remaining.as_secs()));
        return Ok(());
    }

    let timeout = match timer {
        Some(text) => parse_duration(text).map_err(|e| anyhow::anyhow!(e))?,
        None => Duration::from_secs(encino_agent::DEFAULT_TIMEOUT_SECS),
    };

    prompt::require_interactive()?;
    let passphrase = prompt::passphrase("Passphrase: ")?;

    // The only Argon2id pass of the session; the result is handed to the agent.
    let master = vault.unlock(&passphrase)?;

    // Prove the key opens the vault before starting an agent to hold it, so a damaged index surfaces now.
    let session = Session::from_master(vault.clone(), &master)?;
    let held = session.len();
    drop(session);

    encino_agent::client::spawn(root, &vault.id().to_string(), master.expose(), timeout)
        .context("could not start the session agent")?;

    // The agent needs a moment to create its pipe before a client can connect.
    let ready_by = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < ready_by && !client.is_running() {
        std::thread::sleep(Duration::from_millis(20));
    }
    if !client.is_running() {
        bail!("the session agent did not start; try again, or run commands without a session");
    }

    println!(
        "Session open for {}. Holding {held} document{}.",
        format_remaining(timeout.as_secs()),
        if held == 1 { "" } else { "s" }
    );
    println!("Nothing has been decrypted — use `encino open <name>` for that.");
    Ok(())
}

/// Reset the session deadline so a bulk checkout re-encrypts itself on time.
pub fn set_auto_lock(root: &Path, timer: &str) -> Result<()> {
    let timeout = parse_duration(timer).map_err(|e| anyhow::anyhow!(e))?;
    let vault = Vault::open(root)?;
    let client = AgentClient::for_vault(&vault.id().to_string())?;

    match client.set_timeout(timeout) {
        Ok(()) => {
            println!(
                "\nThese will be re-encrypted automatically in {}.",
                format_remaining(timeout.as_secs())
            );
            Ok(())
        }
        // Without a running agent nothing outlives this command, so no auto-close can happen.
        Err(AgentError::NotRunning) => {
            println!(
                "\nNote: no session is running, so nothing will re-encrypt these automatically.\n\
                 Run `encino unlock --timer {timer}` first if you want that, or close them yourself\n\
                 with `encino close --all`."
            );
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Report the session and anything currently decrypted.
pub fn status(root: &Path) -> Result<()> {
    let vault = Vault::open(root)?;
    let client = AgentClient::for_vault(&vault.id().to_string())?;

    println!("Vault:   {}", vault.root().display());

    match client.status() {
        Ok((_, remaining)) => {
            println!("Session: unlocked, {} remaining", format_remaining(remaining.as_secs()));
        }
        Err(AgentError::NotRunning) => {
            println!("Session: locked");
            println!("\nRun `encino unlock` to start one.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    let session = open_session(root)?;
    let open = session.open_documents();

    println!("Holding: {} document{}", session.len(), if session.len() == 1 { "" } else { "s" });

    if open.is_empty() {
        println!("\nNothing is decrypted.");
    } else {
        println!(
            "\nDECRYPTED RIGHT NOW — {} document{}:",
            open.len(),
            if open.len() == 1 { "" } else { "s" }
        );
        for entry in &open {
            println!("  {}", entry.path);
        }
        println!("\nRun `encino close --all` when you are done with them.");
    }
    Ok(())
}

/// Close everything and end the session.
pub fn lock(root: &Path) -> Result<()> {
    let vault = Vault::open(root)?;
    let client = AgentClient::for_vault(&vault.id().to_string())?;

    // Check documents back in before dropping the key: re-encrypting them needs it.
    if client.is_running() {
        let mut session = open_session(root)?;
        let open: Vec<_> = session.open_documents().iter().map(|e| e.path.clone()).collect();

        if !open.is_empty() {
            println!("Closing {} open document{}...", open.len(), if open.len() == 1 { "" } else { "s" });
            let mut failures = 0;
            for name in &open {
                match session.checkin(name) {
                    Ok(_) => println!("  {name}"),
                    Err(e) => {
                        eprintln!("  {name}: {e}");
                        failures += 1;
                    }
                }
            }
            if failures > 0 {
                bail!(
                    "{failures} document(s) could not be closed, so their plaintext is still on disk.\n\
                     The session has been left open deliberately: locking now would leave you unable\n\
                     to re-encrypt them without entering the passphrase again."
                );
            }
        }
    }

    client.lock()?;
    println!("Locked. The key has been forgotten.");
    Ok(())
}
