//! An opt-in trail the agent can leave when something goes wrong.
//!
//! Nothing is written unless `ENCINO_AGENT_DEBUG` is set: no file, no panic
//! hook, no trace of having run. Off by default because a log is a durable
//! record of *when* the vault was used, which is precisely what the encrypted
//! index exists to hide.
//!
//! When enabled it records failures and the agent's start and stop: no key
//! material, passphrase, recovery code, document name, or vault path.
//!
//! The file lives under `%LOCALAPPDATA%`, never inside `.encino`, where it
//! would become plaintext metadata beside the encrypted data.

use std::io::Write;
use std::path::PathBuf;

/// Environment variable that turns diagnostics on.
pub const SWITCH: &str = "ENCINO_AGENT_DEBUG";

/// Whether the agent should record anything at all.
pub fn enabled() -> bool {
    interprets_as_on(std::env::var_os(SWITCH))
}

/// Split out from [`enabled`] to be testable without mutating the environment.
fn interprets_as_on(value: Option<std::ffi::OsString>) -> bool {
    match value {
        Some(v) => !v.is_empty() && v != "0",
        None => false,
    }
}

/// Where the log lives, if a home for it can be determined.
///
/// The `$HOME/.local/state` fallback matters because `XDG_STATE_HOME` is unset
/// on most systems, and diagnostics would otherwise silently do nothing.
pub fn log_path() -> Option<PathBuf> {
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(local_app_data).join("encino").join("agent.log"));
    }
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        return Some(PathBuf::from(state).join("encino").join("agent.log"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local").join("state").join("encino").join("agent.log"))
}

/// Record an event, if diagnostics were asked for. Never panics or fails the
/// caller.
pub fn record(message: &str) {
    if !enabled() {
        return;
    }

    let Some(path) = log_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let stamp =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "[unix:{stamp} pid:{}] {message}", std::process::id());
    }
}

/// Route panics into the log, but only when diagnostics are enabled. A panic
/// message is arbitrary text, so this is the one path whose contents cannot be
/// bounded in advance.
pub fn install_panic_hook() {
    if !enabled() {
        return;
    }

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        record(&format!("agent panicked: {info}"));
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn diagnostics_are_off_unless_explicitly_asked_for() {
        assert!(!interprets_as_on(None), "an unset switch must mean off");
        assert!(!interprets_as_on(Some(OsString::from(""))), "an empty value must mean off");
        assert!(!interprets_as_on(Some(OsString::from("0"))), "0 must mean off");
    }

    #[test]
    fn any_meaningful_value_turns_diagnostics_on() {
        for value in ["1", "true", "yes", "on"] {
            assert!(interprets_as_on(Some(OsString::from(value))), "{value:?} should turn it on");
        }
    }

    #[test]
    fn a_log_location_can_be_determined_on_this_machine() {
        let path = log_path().expect("a log location should be available");
        assert!(path.ends_with("encino/agent.log") || path.ends_with(r"encino\agent.log"));
        // Never inside a vault: it would become plaintext metadata.
        assert!(!path.to_string_lossy().contains(".encino"));
    }

    #[test]
    fn recording_is_silent_and_safe_when_disabled() {
        record("this must not be written unless diagnostics are enabled");
    }
}
