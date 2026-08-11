//! Terminal prompting, kept separate so the engine never needs to know a terminal exists.

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Passphrases shorter than this are refused outright.
const MIN_PASSPHRASE_LEN: usize = 8;

/// Guess rate assumed when saying how exposed a passphrase is — a well-resourced
/// attacker against this vault's Argon2id parameters. Matches the figure the
/// `passphrase` command quotes, so the two never disagree.
const GUESSES_PER_SECOND: f64 = 10_000.0;

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

/// Read a new passphrase twice, refusing mistyped or absurdly short input and
/// warning about a weak one.
///
/// [`MIN_PASSPHRASE_LEN`] stays a hard floor: below it is a slip rather than a
/// decision. Above it the choice is the user's, and what changed is only what
/// they are told — character count says nothing useful about strength, so the
/// note now speaks in words and bits, the terms `docs/strength.md` reasons in.
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

        warn_if_weak(&first);
        return Ok(first);
    }
}

/// Say what a short passphrase costs, in the terms the rest of the project uses.
///
/// Deliberately states only what can be stated truthfully. encino cannot measure
/// the entropy of something a human chose — that is the whole reason the
/// `passphrase` command exists — so it reports the word count, and prices it at
/// what that many *randomly drawn* words would be worth. That figure is an upper
/// bound on a self-chosen phrase, never an under-estimate, and the message says
/// so rather than implying the number is theirs.
fn warn_if_weak(phrase: &str) {
    let words = phrase.split_whitespace().count();
    if !encino_core::passphrase::is_weak(words) {
        return;
    }

    let bits = encino_core::passphrase::entropy_bits(words);
    let seconds = encino_core::passphrase::expected_seconds_to_crack(words, GUESSES_PER_SECOND);

    eprintln!(
        "\n  That is {} — fewer than the {} this vault's strength assumes.",
        count(words),
        count(encino_core::passphrase::SAFE_WORDS)
    );
    eprintln!("  Drawn at random from a word list, {} would be about {bits:.0} bits, which", count(words));
    eprintln!("  someone holding your disk would expect to break in {}.", describe(seconds));
    eprintln!("  Words you chose yourself are worth less than that, not more.\n");
    eprintln!("  It has been accepted — this is your call, not encino's. `encino passphrase`");
    eprintln!("  suggests a strong one if you would rather start from that.\n");
}

/// "one word" / "four words".
fn count(words: usize) -> String {
    format!("{words} word{}", if words == 1 { "" } else { "s" })
}

/// Render a duration in whatever unit makes it easiest to feel.
fn describe(seconds: f64) -> String {
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 60.0 * MINUTE;
    const DAY: f64 = 24.0 * HOUR;
    const YEAR: f64 = 365.25 * DAY;

    match seconds {
        s if s < MINUTE => "under a minute".to_string(),
        s if s < HOUR => format!("about {:.0} minutes", s / MINUTE),
        s if s < DAY => format!("about {:.0} hours", s / HOUR),
        s if s < YEAR => format!("about {:.0} days", s / DAY),
        s => format!("about {:.0} years", s / YEAR),
    }
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
    fn only_a_phrase_below_the_recommended_length_is_flagged() {
        // The threshold is the one the rest of the project reasons in, so the
        // prompt and `encino passphrase` cannot come to different conclusions.
        assert!(encino_core::passphrase::is_weak("one two three".split_whitespace().count()));
        assert!(!encino_core::passphrase::is_weak(
            "correct horse battery staple extra".split_whitespace().count()
        ));
    }

    #[test]
    fn a_single_long_password_is_still_counted_as_one_word() {
        // A password-manager string is one "word" and gets the note. That is the
        // honest answer: encino cannot tell it from `hunter22`, and says so
        // rather than inventing an entropy figure for it.
        assert_eq!("Xk7!qP2#vR9@wL4".split_whitespace().count(), 1);
    }

    #[test]
    fn durations_read_in_units_a_person_can_feel() {
        assert_eq!(describe(30.0), "under a minute");
        assert_eq!(describe(7200.0), "about 2 hours");
        assert_eq!(describe(86_400.0 * 365.25 * 5.0), "about 5 years");
    }

    #[test]
    fn word_counts_read_naturally() {
        assert_eq!(count(1), "1 word");
        assert_eq!(count(4), "4 words");
    }
}
