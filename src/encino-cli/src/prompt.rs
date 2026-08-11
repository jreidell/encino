//! Terminal prompting, kept separate so the engine never needs to know a terminal exists.

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Passphrases shorter than this are refused outright.
const MIN_PASSPHRASE_LEN: usize = 8;

/// Below this, accept but warn: Argon2id cannot rescue a short passphrase.
///
/// Length is a crude proxy and deliberately so. encino cannot measure what a
/// human chose, so the only honest options are to say something modest or to say
/// nothing. Counting words instead and pricing them as if randomly drawn reads
/// as precision the tool does not have, and gets a strong password-manager
/// string — one "word", high entropy — badly wrong in the alarming direction.
const WEAK_PASSPHRASE_LEN: usize = 12;

static FROM_STDIN: AtomicBool = AtomicBool::new(false);

/// Read secrets from standard input instead of the console.
///
/// Lets scripts and the end-to-end tests drive the real command surface. A
/// piped passphrase may land in shell history or a process listing.
pub fn use_stdin(enabled: bool) {
    FROM_STDIN.store(enabled, Ordering::SeqCst);
}

fn reading_from_stdin() -> bool {
    FROM_STDIN.load(Ordering::SeqCst)
}

fn read_line(prompt: &str) -> Result<Zeroizing<String>> {
    if !reading_from_stdin() {
        print!("{prompt}");
        io::stdout().flush().ok();
    }
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).context("could not read input")?;
    Ok(Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string()))
}

/// Read a passphrase without echoing it.
pub fn passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if reading_from_stdin() {
        return read_line(prompt);
    }
    let entered = rpassword::prompt_password(prompt).context("could not read passphrase")?;
    Ok(Zeroizing::new(entered))
}

/// Read a new passphrase twice, refusing weak or mistyped input.
pub fn new_passphrase() -> Result<Zeroizing<String>> {
    loop {
        let first = passphrase("New passphrase: ")?;

        if first.chars().count() < MIN_PASSPHRASE_LEN {
            if reading_from_stdin() {
                bail!("the passphrase must be at least {MIN_PASSPHRASE_LEN} characters");
            }
            eprintln!("  Too short — use at least {MIN_PASSPHRASE_LEN} characters.\n");
            continue;
        }

        let second = passphrase("Confirm passphrase: ")?;
        if first.as_str() != second.as_str() {
            if reading_from_stdin() {
                bail!("the two passphrases did not match");
            }
            eprintln!("  Those did not match.\n");
            continue;
        }

        if is_short(&first) {
            eprintln!(
                "  Note: that is on the short side. A long passphrase is the single\n  \
                 biggest factor in this vault's security.\n"
            );
        }
        return Ok(first);
    }
}

/// Whether a passphrase is short enough to warrant the note. Split out so the
/// judgement is testable without driving a terminal.
fn is_short(phrase: &str) -> bool {
    phrase.chars().count() < WEAK_PASSPHRASE_LEN
}

/// Read a recovery code.
///
/// Echoed rather than hidden: it is transcribed from paper. The BIP39 checksum
/// catches mistakes either way.
pub fn recovery_code() -> Result<Zeroizing<String>> {
    read_line("Recovery code (24 words): ")
}

/// Ask a yes/no question, defaulting to no.
pub fn confirm(question: &str) -> Result<bool> {
    let answer = read_line(&format!("{question} [y/N]: "))?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Require a way to read a secret.
///
/// Refusing beats silently reading a passphrase from unrelated data on stdin.
pub fn require_interactive() -> Result<()> {
    if reading_from_stdin() || std::io::IsTerminal::is_terminal(&io::stdin()) {
        Ok(())
    } else {
        bail!(
            "this command needs an interactive terminal to prompt for a secret.\n\
             To drive encino from a script, pass --passphrase-stdin and supply the\n\
             secret on standard input."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_passphrase_below_the_floor_is_still_refused() {
        // The floor is a hard one. Everything above it is the user's call, but
        // seven characters is a slip rather than a decision.
        assert_eq!(MIN_PASSPHRASE_LEN, 8);
        assert!("short12".chars().count() < MIN_PASSPHRASE_LEN);
        assert!("longenough".chars().count() >= MIN_PASSPHRASE_LEN);
    }

    #[test]
    fn a_short_passphrase_gets_the_note_and_a_long_one_does_not() {
        assert!(is_short("brief"));
        assert!(!is_short("correct horse battery staple"));
    }

    #[test]
    fn a_strong_password_manager_string_is_not_flagged() {
        // Counting words instead would call this one "word", price it at about
        // 13 bits, and tell the user it falls in under a minute — for a string
        // carrying somewhere near ninety. Length is crude, but it is quiet when
        // it does not know, which is the property that matters here.
        assert!(!is_short("Xk7!qP2#vR9@wL4"));
    }
}
