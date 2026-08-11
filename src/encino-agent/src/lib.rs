//! Session agent for encino: key custody and the client that talks to it.
//!
//! Argon2id derivation takes about a second, so the agent derives once and holds
//! the result rather than repeating it per command.
//!
//! Clients receive the master key itself rather than delegating operations to
//! the agent. The transport admits exactly one account — a DACL naming the
//! owning SID on Windows, a 0600 socket in a verified-0700 directory plus an
//! `SO_PEERCRED` check on Linux — and a process running as that account could
//! read the agent's memory anyway; the boundary defended is the disk, not
//! sibling processes. The key never touches disk, and reaches the agent over the
//! child's stdin rather than its command line.
//!
//! Each connection is given a deadline to state its business, because the accept
//! loop serves clients in turn and a blocking read has none of its own.

pub mod client;
pub mod diag;
pub mod protocol;
pub mod server;

/// The server's transport, one module per platform.
#[cfg(unix)]
mod listener;
#[cfg(windows)]
mod pipe;

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod win;

pub use protocol::{Request, Response};

#[cfg(windows)]
pub use protocol::pipe_name;
#[cfg(unix)]
pub use protocol::{socket_dir, socket_path};

/// Default session lifetime.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30 * 60;

/// Parse a duration such as `30m`, `2h`, or `90s`.
///
/// A bare number is read as minutes.
pub fn parse_duration(text: &str) -> Result<std::time::Duration, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("a duration is required, for example 30m".into());
    }

    let (digits, unit) = match trimmed.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => trimmed.split_at(at),
        None => (trimmed, "m"),
    };

    let value: u64 = digits.parse().map_err(|_| format!("{text:?} is not a duration, for example 30m"))?;
    let per_unit: u64 = match unit.trim().to_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600,
        other => return Err(format!("{other:?} is not a unit of time; use s, m, or h")),
    };

    // Checked, because the multiplication is on a number the user typed. A
    // wrapping one turns an absurd figure into a small plausible one — 12 hours
    // in minutes, for instance, lands inside the cap below rather than being
    // refused by it — so the session would silently be far shorter than asked
    // for. Release builds wrap; debug builds panic outright.
    let seconds =
        value.checked_mul(per_unit).ok_or_else(|| format!("{text:?} is longer than any session may last"))?;

    if seconds == 0 {
        return Err("a session must last at least a second".into());
    }
    // Matches the agent's own SetTimeout cap.
    if seconds > 12 * 3600 {
        return Err("a session may not last longer than 12 hours".into());
    }
    Ok(std::time::Duration::from_secs(seconds))
}

/// Render a remaining duration as `MM:SS` or `H:MM:SS`.
pub fn format_remaining(seconds: u64) -> String {
    let (hours, minutes, secs) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    if hours > 0 { format!("{hours}:{minutes:02}:{secs:02}") } else { format!("{minutes:02}:{secs:02}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_in_the_forms_people_type() {
        assert_eq!(parse_duration("30m").unwrap().as_secs(), 1800);
        assert_eq!(parse_duration("2h").unwrap().as_secs(), 7200);
        assert_eq!(parse_duration("90s").unwrap().as_secs(), 90);
        assert_eq!(parse_duration("45").unwrap().as_secs(), 2700, "a bare number means minutes");
        assert_eq!(parse_duration(" 15m ").unwrap().as_secs(), 900);
        assert_eq!(parse_duration("1HOUR").unwrap().as_secs(), 3600);
    }

    #[test]
    fn nonsense_durations_are_refused() {
        for bad in ["", "   ", "soon", "m", "-5m", "5 fortnights", "0", "0s"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should have been refused");
        }
    }

    #[test]
    fn a_session_cannot_be_set_to_outlast_the_day() {
        assert!(parse_duration("12h").is_ok());
        assert!(parse_duration("13h").is_err());
        assert!(parse_duration("999h").is_err());
    }

    #[test]
    fn a_duration_too_large_to_multiply_is_refused_rather_than_wrapped() {
        // Unchecked, `value * 60` on this input wraps to 44 seconds, which walks
        // straight through the 12-hour cap and silently gives a session three
        // orders of magnitude shorter than the one asked for. In a debug build
        // the same multiplication panics instead.
        for absurd in ["307445734561825861m", "5124095576030431h", "18446744073709551615m"] {
            assert!(parse_duration(absurd).is_err(), "{absurd:?} should have been refused");
        }

        // The seconds path has no multiplication, so the cap is the only guard.
        assert!(parse_duration("18446744073709551615s").is_err());
    }

    #[test]
    fn remaining_time_reads_naturally() {
        assert_eq!(format_remaining(0), "00:00");
        assert_eq!(format_remaining(59), "00:59");
        assert_eq!(format_remaining(1800), "30:00");
        assert_eq!(format_remaining(3600), "1:00:00");
        assert_eq!(format_remaining(3661), "1:01:01");
    }
}
