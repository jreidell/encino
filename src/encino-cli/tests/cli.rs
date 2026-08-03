//! Tests that drive the real `encino` binary.
//!
//! Every command runs with its working directory inside the vault, so relative
//! paths such as `add .` resolve to the vault and not to some other tree. No
//! agent is started: each command derives the key for itself, so these stay
//! independent of session state and of each other.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const PASSPHRASE: &str = "a-long-vault-passphrase";

struct Vault {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Vault {
    /// Create a vault with some documents already staged in the work area.
    fn with_files(files: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Financial");
        std::fs::create_dir_all(&root).unwrap();

        let vault = Vault { _dir: dir, root };
        for (name, contents) in files {
            vault.write(name, contents);
        }

        vault
            .command("init")
            .arg(&vault.root)
            .write_stdin(format!("{PASSPHRASE}\n{PASSPHRASE}\ny\n"))
            .assert()
            .success();
        vault
    }

    /// A command run from inside the vault folder, as a user would. Relative
    /// paths resolve against the working directory, so pointing `-C` at the
    /// vault from elsewhere would make `add .` mean a different folder.
    fn command(&self, subcommand: &str) -> Command {
        let mut command = Command::cargo_bin("encino").unwrap();
        command.current_dir(&self.root).arg("--passphrase-stdin").arg(subcommand);
        command
    }

    /// Run a command that needs only the passphrase.
    fn run(&self, subcommand: &str, args: &[&str]) -> assert_cmd::assert::Assert {
        self.command(subcommand).args(args).write_stdin(format!("{PASSPHRASE}\n")).assert()
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// Everything in the work area, excluding the vault's own storage.
    fn work_area(&self) -> Vec<String> {
        fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
            for item in std::fs::read_dir(dir).unwrap().flatten() {
                let path = item.path();
                if path.file_name().unwrap() == ".encino" {
                    continue;
                }
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    out.push(path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &self.root, &mut out);
        out.sort();
        out
    }
}

fn stdout(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn stderr(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stderr).into_owned()
}

#[test]
fn a_folder_becomes_a_vault_and_its_documents_disappear_from_view() {
    let vault = Vault::with_files(&[
        ("chase-statement.pdf", "closing balance 4102.55"),
        ("taxes/2024/w2-acme.pdf", "wages 120000"),
    ]);

    vault.run("add", &["."]).success();

    // The directories go too: their names would reveal what the vault holds.
    assert!(vault.work_area().is_empty(), "work area still holds {:?}", vault.work_area());
    assert!(!vault.root.join("taxes").exists());

    // The nested document keeps its folder path rather than its bare filename.
    let listing = stdout(&vault.run("ls", &[]).success());
    assert!(listing.contains("taxes/2024/w2-acme.pdf"), "listing was:\n{listing}");
    assert!(listing.contains("chase-statement.pdf"));
}

#[test]
fn importing_a_folder_from_outside_keeps_its_structure() {
    let vault = Vault::with_files(&[]);

    let archive = vault.root.parent().unwrap().join("Archive");
    for year in ["2023", "2024"] {
        let dir = archive.join("taxes").join(year);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("w2.pdf"), format!("wages for {year}")).unwrap();
    }

    let assert = vault
        .command("add")
        .arg(archive.join("taxes"))
        .write_stdin(format!("{PASSPHRASE}\n"))
        .assert()
        .success();
    assert!(stdout(&assert).contains("Imported 2 documents"), "output was:\n{}", stdout(&assert));

    // The named folder becomes the top of the imported tree, as `cp -r` does.
    let listing = stdout(&vault.run("ls", &[]).success());
    assert!(listing.contains("taxes/2023/w2.pdf"), "listing was:\n{listing}");
    assert!(listing.contains("taxes/2024/w2.pdf"), "listing was:\n{listing}");

    // The contents must not be crossed over.
    vault.run("open", &["taxes/2023/w2.pdf"]).success();
    assert_eq!(std::fs::read_to_string(vault.root.join("taxes/2023/w2.pdf")).unwrap(), "wages for 2023");
}

#[test]
fn a_single_file_from_outside_is_imported_under_its_own_name() {
    // Naming a file must not drag its parent folder in as a prefix.
    let vault = Vault::with_files(&[]);

    let elsewhere = vault.root.parent().unwrap().join("Downloads");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("statement.pdf"), "closing balance").unwrap();

    vault
        .command("add")
        .arg(elsewhere.join("statement.pdf"))
        .write_stdin(format!("{PASSPHRASE}\n"))
        .assert()
        .success();

    let listing = stdout(&vault.run("ls", &[]).success());
    assert!(listing.contains("statement.pdf"), "listing was:\n{listing}");
    assert!(!listing.contains("Downloads"), "a named file must not gain a folder prefix:\n{listing}");
}

#[test]
fn originals_outside_the_vault_are_never_destroyed_by_default() {
    let vault = Vault::with_files(&[]);

    // A file that has nothing to do with the vault, in a sibling folder.
    let elsewhere = vault.root.parent().unwrap().join("work");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let bystander = elsewhere.join("important-notes.txt");
    std::fs::write(&bystander, "work that must not be destroyed").unwrap();

    let assert =
        vault.command("add").arg(&elsewhere).write_stdin(format!("{PASSPHRASE}\n")).assert().success();

    // The original is untouched, and the user is told so: believing an original
    // is gone when it is not is its own hazard.
    assert!(stdout(&assert).contains("left in place"), "output was:\n{}", stdout(&assert));
    assert!(bystander.exists(), "an original outside the vault was destroyed");
    assert_eq!(std::fs::read_to_string(&bystander).unwrap(), "work that must not be destroyed");

    assert!(stdout(&vault.run("ls", &[]).success()).contains("important-notes.txt"));
}

#[test]
fn moving_an_outside_original_requires_saying_so_and_confirming() {
    let vault = Vault::with_files(&[]);
    let elsewhere = vault.root.parent().unwrap().join("work");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let original = elsewhere.join("statement.pdf");
    std::fs::write(&original, "closing balance").unwrap();

    // Declining the confirmation must leave everything exactly as it was.
    vault
        .command("add")
        .arg(&elsewhere)
        .arg("--move")
        .write_stdin(format!("{PASSPHRASE}\nn\n"))
        .assert()
        .success();
    assert!(original.exists(), "declining the prompt must not destroy anything");

    vault
        .command("add")
        .arg(&elsewhere)
        .arg("--move")
        .write_stdin(format!("{PASSPHRASE}\ny\n"))
        .assert()
        .success();
    assert!(!original.exists(), "--move with confirmation should have shredded the original");
}

#[test]
fn documents_come_back_exactly_and_leave_nothing_behind() {
    let vault = Vault::with_files(&[("taxes/2024/w2.pdf", "wages 120000 ssn 123-45-6789")]);
    vault.run("add", &["."]).success();

    vault.run("open", &["taxes/2024/w2.pdf"]).success();
    let decrypted = vault.root.join("taxes/2024/w2.pdf");
    assert_eq!(std::fs::read_to_string(&decrypted).unwrap(), "wages 120000 ssn 123-45-6789");

    // While open, the exposure must be visible in the listing.
    assert!(stdout(&vault.run("ls", &[]).success()).contains("DECRYPTED"));

    vault.run("close", &["--all"]).success();
    assert!(!decrypted.exists());
    assert!(vault.work_area().is_empty());
}

#[test]
fn edits_made_while_a_document_is_open_are_kept() {
    let vault = Vault::with_files(&[("notes.txt", "before")]);
    vault.run("add", &["."]).success();

    vault.run("open", &["notes.txt"]).success();
    std::fs::write(vault.root.join("notes.txt"), "after, and rather longer than before").unwrap();
    vault.run("close", &["--all"]).success();

    vault.run("open", &["notes.txt"]).success();
    assert_eq!(
        std::fs::read_to_string(vault.root.join("notes.txt")).unwrap(),
        "after, and rather longer than before"
    );
}

#[test]
fn the_wrong_passphrase_reveals_nothing() {
    let vault = Vault::with_files(&[("statement.pdf", "closing balance 4102.55")]);
    vault.run("add", &["."]).success();

    let assert = vault.command("ls").write_stdin("not-the-passphrase\n").assert().failure();

    assert!(stderr(&assert).contains("authentication failed"));
    assert!(!stderr(&assert).contains("statement.pdf"), "a failed unlock must not name documents");
}

#[test]
fn a_vault_can_always_be_emptied_back_out_again() {
    let vault = Vault::with_files(&[("statement.pdf", "closing balance"), ("taxes/2024/w2.pdf", "wages")]);
    vault.run("add", &["."]).success();

    let destination = vault.root.parent().unwrap().join("exported");
    vault.command("export").arg(&destination).write_stdin(format!("{PASSPHRASE}\ny\n")).assert().success();

    assert_eq!(std::fs::read_to_string(destination.join("statement.pdf")).unwrap(), "closing balance");
    assert_eq!(std::fs::read_to_string(destination.join("taxes/2024/w2.pdf")).unwrap(), "wages");

    // Exporting must not disturb the vault.
    vault.run("verify", &[]).success();
}

#[test]
fn tampering_with_stored_data_is_reported() {
    let vault = Vault::with_files(&[("statement.pdf", "closing balance 4102.55")]);
    vault.run("add", &["."]).success();
    vault.run("verify", &[]).success();

    let blob = walk_files(&vault.root.join(".encino/blobs")).into_iter().next().unwrap();
    let mut raw = std::fs::read(&blob).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    std::fs::write(&blob, &raw).unwrap();

    vault.run("verify", &[]).failure();
    // The document must not be handed over as if it were intact.
    vault.run("open", &["statement.pdf"]).failure();
}

#[test]
fn importing_can_leave_the_originals_alone_when_asked() {
    let vault = Vault::with_files(&[("statement.pdf", "closing balance")]);
    vault.run("add", &[".", "--keep"]).success();

    assert!(vault.root.join("statement.pdf").exists(), "--keep must not shred the original");
    assert_eq!(stdout(&vault.run("ls", &[]).success()).matches("statement.pdf").count(), 1);
}

#[test]
fn a_passphrase_can_be_changed_without_touching_the_documents() {
    let vault = Vault::with_files(&[("statement.pdf", "closing balance 4102.55")]);
    vault.run("add", &["."]).success();

    vault
        .command("passwd")
        .write_stdin(format!("{PASSPHRASE}\nan-entirely-new-passphrase\nan-entirely-new-passphrase\n"))
        .assert()
        .success();

    vault.command("ls").write_stdin(format!("{PASSPHRASE}\n")).assert().failure();

    let assert = vault
        .command("open")
        .arg("statement.pdf")
        .write_stdin("an-entirely-new-passphrase\n")
        .assert()
        .success();
    assert!(stdout(&assert).contains("statement.pdf"));
    assert_eq!(std::fs::read_to_string(vault.root.join("statement.pdf")).unwrap(), "closing balance 4102.55");
}

#[test]
fn a_folder_that_is_not_a_vault_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let assert = Command::cargo_bin("encino")
        .unwrap()
        .current_dir(dir.path())
        .args(["--passphrase-stdin", "ls"])
        .write_stdin("whatever\n")
        .assert()
        .failure();

    assert!(stderr(&assert).contains("no vault found"), "unhelpful message: {}", stderr(&assert));
    assert!(stderr(&assert).contains("encino init"), "the message should say what to do");
}

#[test]
fn commands_needing_a_secret_refuse_to_read_it_from_a_pipe_by_accident() {
    let dir = tempfile::tempdir().unwrap();
    // Without --passphrase-stdin, a redirected stdin must not be mistaken for a
    // typed passphrase.
    let assert = Command::cargo_bin("encino")
        .unwrap()
        .arg("init")
        .arg(dir.path().join("vault"))
        .write_stdin("some-passphrase\nsome-passphrase\ny\n")
        .assert()
        .failure();

    assert!(stderr(&assert).contains("interactive terminal"), "unexpected: {}", stderr(&assert));
    assert!(stderr(&assert).contains("--passphrase-stdin"), "should offer the way forward");
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(listing) = std::fs::read_dir(dir) {
        for item in listing.flatten() {
            let path = item.path();
            if path.is_dir() {
                out.extend(walk_files(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}
