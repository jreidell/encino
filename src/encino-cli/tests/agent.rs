//! Regression tests for the session agent and its named pipe.
//!
//! Each client needs its own pipe instance, created before the previous one is
//! served: with a single instance the next client's `CreateFile` can bind to it
//! before `DisconnectNamedPipe` tears down a connection that now belongs to
//! someone else. The race is intermittent, hence rapid back-to-back commands.
//!
//! Each vault gets its own id and therefore its own pipe name, so these tests do
//! not interfere with each other, and every test tears its agent down even when
//! it fails.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const PASSPHRASE: &str = "a-long-vault-passphrase";

/// No command here should take anything like this long. The limit is the test:
/// without it, a command that returns only when the session expires reads as a
/// slow test rather than a hang.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// A vault with a running agent, locked again when the test ends.
struct Session {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Session {
    fn start(documents: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Financial");
        std::fs::create_dir_all(&root).unwrap();

        let session = Session { _dir: dir, root };
        for (name, contents) in documents {
            let path = session.root.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, contents).unwrap();
        }

        session.piped("init").arg(&session.root).write_stdin(init_input()).assert().success();
        session.piped("add").arg(".").write_stdin(pass_input()).assert().success();
        session.piped("unlock").args(["--timer", "300s"]).write_stdin(pass_input()).assert().success();
        session
    }

    /// A command that supplies the passphrase on stdin.
    fn piped(&self, subcommand: &str) -> Command {
        let mut command = Command::cargo_bin("encino").unwrap();
        command.current_dir(&self.root).arg("--passphrase-stdin").arg(subcommand).timeout(LIMIT);
        command
    }

    /// A command with no passphrase at all, which therefore can only succeed by
    /// getting the key from the agent.
    fn via_agent(&self, subcommand: &str) -> Command {
        let mut command = Command::cargo_bin("encino").unwrap();
        command.current_dir(&self.root).arg(subcommand).timeout(LIMIT);
        command
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Stop the agent even if the test failed, or it outlives the run.
        let _ = Command::cargo_bin("encino")
            .unwrap()
            .current_dir(&self.root)
            .arg("lock")
            .timeout(std::time::Duration::from_secs(30))
            .assert();
    }
}

fn init_input() -> String {
    format!("{PASSPHRASE}\n{PASSPHRASE}\ny\n")
}

fn pass_input() -> String {
    format!("{PASSPHRASE}\n")
}

fn output_of(assert: &assert_cmd::assert::Assert) -> String {
    let out = assert.get_output();
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

#[test]
fn rapid_back_to_back_commands_all_reach_the_agent() {
    let session = Session::start(&[("statement.pdf", "closing balance 4102.55")]);

    // Each iteration opens and closes its own connection: that is the race.
    for attempt in 1..=20 {
        let assert = session.via_agent("status").assert();
        let text = output_of(&assert);

        assert!(
            assert.get_output().status.success(),
            "command {attempt} of 20 failed against a running agent:\n{text}"
        );
        assert!(text.contains("unlocked"), "command {attempt} did not see the session:\n{text}");
        // The specific symptom of the race, named so a regression is recognisable.
        assert!(
            !text.contains("No process is on the other end"),
            "the named-pipe race is back at command {attempt}:\n{text}"
        );
        assert!(
            !text.contains("no session is open"),
            "the agent became unreachable at command {attempt}:\n{text}"
        );
    }
}

#[test]
fn a_full_cycle_of_work_runs_without_re_entering_the_passphrase() {
    let session = Session::start(&[
        ("statement.pdf", "closing balance 4102.55"),
        ("taxes/2024/w2.pdf", "wages 120000"),
    ]);

    // None of these supplies a passphrase, so failing to reach the agent fails.
    session.via_agent("ls").assert().success();
    session.via_agent("open").arg("statement.pdf").assert().success();
    session.via_agent("open").arg("taxes/2024/w2.pdf").assert().success();
    session.via_agent("status").assert().success();

    assert_eq!(
        std::fs::read_to_string(session.root.join("statement.pdf")).unwrap(),
        "closing balance 4102.55"
    );

    session.via_agent("close").arg("--all").assert().success();
    session.via_agent("verify").assert().success();

    assert!(!session.root.join("statement.pdf").exists());
}

#[test]
fn locking_stops_the_agent_and_leaves_no_plaintext() {
    let session = Session::start(&[("statement.pdf", "closing balance")]);

    session.via_agent("open").arg("--all").write_stdin("y\n").assert().success();
    assert!(session.root.join("statement.pdf").exists());

    // `lock` must re-encrypt before dropping the key.
    session.via_agent("lock").assert().success();
    assert!(!session.root.join("statement.pdf").exists(), "lock left plaintext behind");

    let assert = session.via_agent("status").assert().success();
    assert!(output_of(&assert).contains("locked"));

    // With no session, a command needing the key must ask for it.
    session.via_agent("ls").assert().failure();
}

#[test]
fn a_session_leaves_no_trace_of_itself_on_disk() {
    // Diagnostics are opt-in: a record inside the vault of when the agent ran is
    // a record of when someone worked with their documents.
    let session = Session::start(&[("statement.pdf", "contents")]);
    session.via_agent("status").assert().success();
    session.via_agent("open").arg("statement.pdf").assert().success();
    session.via_agent("close").arg("--all").assert().success();

    assert!(!vault_contains_log(&session.root), "a log appeared inside the vault");
}

fn vault_contains_log(root: &Path) -> bool {
    fn walk(dir: &Path) -> bool {
        std::fs::read_dir(dir)
            .map(|listing| {
                listing.flatten().any(|item| {
                    let path = item.path();
                    if path.is_dir() {
                        walk(&path)
                    } else {
                        path.extension().and_then(|e| e.to_str()) == Some("log")
                    }
                })
            })
            .unwrap_or(false)
    }
    walk(root)
}
