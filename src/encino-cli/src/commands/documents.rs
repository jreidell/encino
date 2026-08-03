//! `add`, `ls`, `open`, `close`, `verify`, and `export`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use encino_core::{CheckinOutcome, DocPath, Session};

use crate::commands::session::open_session;
use crate::prompt;

/// One file queued for import.
struct Import {
    source: PathBuf,
    name: DocPath,
    /// Whether the file already lives inside the vault folder.
    inside_vault: bool,
}

/// Import files and folders into the vault.
///
/// Only originals already inside the vault folder are destroyed by default;
/// anything from elsewhere is copied in and left where it was. This bounds the
/// blast radius of `encino add .` run from the wrong directory to a stray copy
/// rather than lost work. `--move` opts into destroying outside originals and
/// asks first; `--keep` preserves everything.
pub fn add(root: &Path, paths: &[PathBuf], keep: bool, move_originals: bool) -> Result<()> {
    if paths.is_empty() {
        bail!("name at least one file or folder to import");
    }

    let mut session = open_session(root)?;
    let vault_root = session.vault().root().to_path_buf();

    let mut imports = Vec::new();
    for path in paths {
        collect(path, &vault_root, &mut imports)?;
    }
    if imports.is_empty() {
        bail!("nothing to import: no files were found at the paths given");
    }

    let outside = imports.iter().filter(|i| !i.inside_vault).count();

    if move_originals && outside > 0 {
        println!(
            "{outside} of these {} file{} live outside the vault folder.",
            imports.len(),
            if outside == 1 { "" } else { "s" }
        );
        println!("--move will shred those originals where they sit:\n");
        for import in imports.iter().filter(|i| !i.inside_vault).take(10) {
            println!("  {}", import.source.display());
        }
        if outside > 10 {
            println!("  ... and {} more", outside - 10);
        }
        println!();
        if !prompt::confirm("Shred these originals?")? {
            println!("Nothing was imported.");
            return Ok(());
        }
        println!();
    }

    let mut added = 0;
    let mut shredded = 0;
    let mut left_alone = 0;
    let mut problems = Vec::new();

    for import in &imports {
        let keep_this = keep || (!import.inside_vault && !move_originals);

        match session.add(&import.source, &import.name, keep_this) {
            Ok(()) => {
                println!("  {}", import.name);
                added += 1;
                if keep_this {
                    left_alone += 1;
                } else {
                    shredded += 1;
                }
            }
            Err(e) => problems.push(format!("{}: {e}", import.name)),
        }
    }

    println!("\nImported {added} document{}.", if added == 1 { "" } else { "s" });
    if shredded > 0 {
        println!("  {shredded} original{} shredded.", if shredded == 1 { " was" } else { "s were" });
    }
    if left_alone > 0 {
        // Believing originals are gone when they are not is a false sense of
        // security, so say it plainly.
        println!(
            "  {left_alone} original{} left in place{}.",
            if left_alone == 1 { "" } else { "s" },
            if keep { "" } else { " because they are outside the vault folder" }
        );
        if !keep {
            println!("  Delete them yourself, or re-run with --move, once you are satisfied.");
        }
    }

    if !problems.is_empty() {
        eprintln!("\n{} could not be imported:", problems.len());
        for problem in &problems {
            eprintln!("  {problem}");
        }
        bail!("{} of the documents named were not imported", problems.len());
    }
    Ok(())
}

/// Expand one command-line path into the documents it names.
///
/// A document's name is its path relative to a base. Inside the vault that base
/// is the vault root; outside it is the parent of the path named, so the named
/// folder becomes the top of the imported tree, as `cp -r` does. Naming outside
/// files by filename alone would flatten trees and collide on names such as
/// `2023/statement.pdf` and `2024/statement.pdf`.
fn collect(argument: &Path, vault_root: &Path, out: &mut Vec<Import>) -> Result<()> {
    // Must be spelled the same way as the vault root, or `strip_prefix` fails to
    // match files that already live inside the vault.
    let absolute = encino_core::fsutil::canonical(argument)
        .with_context(|| format!("{} does not exist", argument.display()))?;

    // Parent of what was named, so the named item itself tops the imported tree.
    let base = absolute.parent().unwrap_or(&absolute).to_path_buf();
    gather(&absolute, &base, vault_root, out)
}

/// Walk one path, naming everything found relative to `base`.
fn gather(path: &Path, base: &Path, vault_root: &Path, out: &mut Vec<Import>) -> Result<()> {
    if path.is_file() {
        let (name, inside_vault) = match path.strip_prefix(vault_root) {
            Ok(relative) => (DocPath::from_relative(relative)?, true),
            Err(_) => {
                let relative = path.strip_prefix(base).unwrap_or(path);
                (DocPath::from_relative(relative)?, false)
            }
        };
        out.push(Import { source: path.to_path_buf(), name, inside_vault });
        return Ok(());
    }

    if path.is_dir() {
        // Never walk into the vault's own storage.
        if path.file_name().map(|n| n == encino_core::VAULT_DIR).unwrap_or(false) {
            return Ok(());
        }
        let listing =
            std::fs::read_dir(path).with_context(|| format!("could not read {}", path.display()))?;
        for item in listing {
            gather(&item?.path(), base, vault_root, out)?;
        }
    }
    Ok(())
}

/// List the documents held in the vault.
pub fn list(root: &Path, json: bool) -> Result<()> {
    let session = open_session(root)?;

    if json {
        let documents: Vec<_> = session
            .documents()
            .map(|d| {
                serde_json::json!({
                    "path": d.path.as_str(),
                    "size": d.size,
                    "sha256": d.sha256,
                    "modified": d.modified.to_string(),
                    "added": d.added.to_string(),
                    "open": session.is_open(&d.path),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&documents)?);
        return Ok(());
    }

    if session.is_empty() {
        println!("The vault is empty. Use `encino add <files>` to bring documents in.");
        return Ok(());
    }

    let widest = session.documents().map(|d| d.path.as_str().len()).max().unwrap_or(0).min(60);

    for entry in session.documents() {
        let state = if session.is_open(&entry.path) { "  DECRYPTED" } else { "" };
        println!("  {:<widest$}  {:>10}{}", entry.path.as_str(), human_size(entry.size), state);
    }

    println!(
        "\n{} document{}, {} total.",
        session.len(),
        if session.len() == 1 { "" } else { "s" },
        human_size(session.total_size())
    );
    Ok(())
}

/// Decrypt documents into the vault folder.
pub fn open(root: &Path, names: &[String], all: bool, launch: bool) -> Result<()> {
    let mut session = open_session(root)?;

    let targets: Vec<DocPath> = if all {
        session.documents().map(|d| d.path.clone()).collect()
    } else {
        names.iter().map(|n| DocPath::new(n)).collect::<encino_core::Result<_>>()?
    };

    if targets.is_empty() {
        bail!(if all { "the vault is empty" } else { "name at least one document to open" });
    }

    if all && targets.len() > 1 {
        println!(
            "This will decrypt all {} documents into {}.",
            targets.len(),
            session.vault().root().display()
        );
        println!("They stay readable to anything running as you until you close them.\n");
        if !prompt::confirm("Continue?")? {
            println!("Nothing was decrypted.");
            return Ok(());
        }
        println!();
    }

    let mut opened = 0;
    let mut problems = Vec::new();

    for name in &targets {
        match session.checkout(name) {
            Ok(path) => {
                println!("  {name}");
                opened += 1;
                if launch {
                    launch_default_app(&path);
                }
            }
            Err(e) => problems.push(format!("{name}: {e}")),
        }
    }

    if opened > 0 {
        println!("\n{opened} document{} decrypted.", if opened == 1 { "" } else { "s" });
        println!("Run `encino close --all` when you are done.");
    }

    if !problems.is_empty() {
        eprintln!("\n{} could not be opened:", problems.len());
        for problem in &problems {
            eprintln!("  {problem}");
        }
        bail!("{} of the documents named were not opened", problems.len());
    }
    Ok(())
}

/// Re-encrypt documents and shred their plaintext.
pub fn close(root: &Path, names: &[String], all: bool) -> Result<()> {
    let mut session = open_session(root)?;

    let targets: Vec<DocPath> = if all {
        session.open_documents().iter().map(|d| d.path.clone()).collect()
    } else {
        names.iter().map(|n| DocPath::new(n)).collect::<encino_core::Result<_>>()?
    };

    if targets.is_empty() {
        println!("{}", if all { "Nothing is open." } else { "Name at least one document to close." });
        return Ok(());
    }

    let mut closed = 0;
    let mut problems = Vec::new();

    for name in &targets {
        match session.checkin(name) {
            Ok(CheckinOutcome::Unchanged) => {
                println!("  {name}");
                closed += 1;
            }
            Ok(CheckinOutcome::Updated) => {
                println!("  {name}  (re-encrypted after edits)");
                closed += 1;
            }
            Err(e) => problems.push(format!("{name}: {e}")),
        }
    }

    if closed > 0 {
        println!("\n{closed} document{} closed and shredded.", if closed == 1 { "" } else { "s" });
    }

    if !problems.is_empty() {
        eprintln!("\n{} could not be closed:", problems.len());
        for problem in &problems {
            eprintln!("  {problem}");
        }
        bail!("{} document(s) still have plaintext on disk", problems.len());
    }
    Ok(())
}

/// Authenticate every stored blob against the index.
pub fn verify(root: &Path) -> Result<()> {
    let session = open_session(root)?;

    println!("Checking {} document{}...\n", session.len(), if session.len() == 1 { "" } else { "s" });
    let issues = session.verify()?;

    if issues.is_empty() {
        println!("No problems found. Every document decrypts and matches its recorded digest.");
        return Ok(());
    }

    for issue in &issues {
        match &issue.document {
            Some(name) => eprintln!("  {name}: {}", issue.problem),
            None => eprintln!("  {}", issue.problem),
        }
    }

    bail!("\n{} problem(s) found", issues.len());
}

/// Decrypt the whole vault into a directory.
pub fn export(root: &Path, dest: &Path) -> Result<()> {
    let session = open_session(root)?;

    if dest.exists() {
        let occupied = std::fs::read_dir(dest).map(|mut d| d.next().is_some()).unwrap_or(false);
        if occupied {
            bail!("{} already has something in it; export needs an empty or new folder", dest.display());
        }
    }

    println!("This writes every document to {} in plain, readable form.\n", dest.display());
    if !prompt::confirm("Continue?")? {
        println!("Nothing was exported.");
        return Ok(());
    }

    let count = session.export(dest)?;
    println!("\nExported {count} document{} to {}.", if count == 1 { "" } else { "s" }, dest.display());
    println!("Those files are not protected by encino. Move or delete them when you are done.");
    Ok(())
}

/// Hand a decrypted file to whatever normally opens it.
fn launch_default_app(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd").args(["/C", "start", ""]).arg(path).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

/// Render a byte count for a human.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// Keeps the `Session` import honest if `open_session` changes shape.
#[allow(dead_code)]
fn _assert_session_type(_: &Session) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(1024 * 1024), "1.0 MB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}
