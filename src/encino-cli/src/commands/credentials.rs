//! `init`, `passwd`, and `recover` — the commands that deal in credentials.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use encino_core::{KdfConfig, RecoveryCode, Vault};

use crate::prompt;

/// How long a passphrase derivation should take on this machine.
const KDF_TARGET: Duration = Duration::from_millis(1000);

/// Create a vault and print its recovery code.
pub fn init(folder: &Path) -> Result<()> {
    prompt::require_interactive()?;

    if !folder.exists() {
        std::fs::create_dir_all(folder).with_context(|| format!("could not create {}", folder.display()))?;
    }
    let folder = encino_core::fsutil::canonical(folder)
        .with_context(|| format!("could not resolve {}", folder.display()))?;

    println!("Creating a vault in {}\n", folder.display());
    print_loss_warning();

    let passphrase = prompt::new_passphrase()?;

    print!("Calibrating key derivation... ");
    std::io::stdout().flush().ok();
    let kdf = KdfConfig::calibrate(KDF_TARGET);
    println!("{} MiB, {} passes", kdf.memory_kib / 1024, kdf.iterations);

    let (vault, recovery) = Vault::init(&folder, &passphrase, kdf)?;

    println!("\nVault created.\n");
    print_recovery_code(&recovery);

    println!("\n  This is the only copy. It is shown once and stored nowhere.");
    println!("  Write it on paper now, before going further.\n");
    println!("  It opens the vault outright, exactly as your passphrase does, so");
    println!("  keep it somewhere a burglar would not look for a password.\n");

    while !prompt::confirm("Have you written down all 24 words?")? {
        println!("\n  Take your time — the vault exists either way, but this is the");
        println!("  only time the code will be shown.\n");
        print_recovery_code(&recovery);
        println!();
    }

    println!("\nVault: {}", vault.root().display());
    println!("Next: `encino add <files>` to bring documents in.");

    // Kept apart from the loss warning so neither dilutes the other.
    println!("\nOne thing for later: shredding cannot guarantee erasure on an SSD,");
    println!("so run this on a BitLocker-encrypted volume if you want that.");
    Ok(())
}

/// The one warning `init` gives, printed before anything is chosen.
///
/// Shown once and never repeated by another command, so that it is still read.
/// It states rather than asks; the only prompt in this flow is the later,
/// checkable question of whether the recovery words were written down.
fn print_loss_warning() {
    let rule = "─".repeat(66);
    println!("  {rule}");
    println!("   Read this once. encino will not show it again.");
    println!();
    println!("   There is no reset, no backdoor, and no support path. If you");
    println!("   lose BOTH your passphrase AND the recovery code shown at the");
    println!("   end of this setup, every document in this vault becomes");
    println!("   permanently unreadable — by you, by me, by anyone.");
    println!();
    println!("   That is the design working, not a failure of it. Nothing can");
    println!("   be done afterwards, so decide now where both will live.");
    println!("  {rule}");
    println!();
}

/// Change the passphrase, leaving every document untouched.
pub fn passwd(root: &Path) -> Result<()> {
    prompt::require_interactive()?;

    let mut vault = Vault::open(root)?;
    let current = prompt::passphrase("Current passphrase: ")?;
    let master = vault.unlock(&current)?;

    println!();
    let replacement = prompt::new_passphrase()?;
    vault.change_passphrase(&master, &replacement)?;

    println!("\nPassphrase changed. No document was re-encrypted — only the wrapped");
    println!("master key was rewritten.");
    println!("\nYour existing recovery code still works and is unchanged.");
    Ok(())
}

/// Verify that the recovery code opens the vault, and offer to reset the
/// passphrase with it.
pub fn recover(root: &Path) -> Result<()> {
    prompt::require_interactive()?;

    let vault = Vault::open(root)?;
    println!("Recovering {}\n", vault.root().display());

    let entered = prompt::recovery_code()?;
    let code = RecoveryCode::parse(&entered)?;
    let master = vault.recover(&code)?;

    println!("\nRecovery code accepted.\n");

    if prompt::confirm("Set a new passphrase now?")? {
        println!();
        let replacement = prompt::new_passphrase()?;
        let mut vault = vault;
        vault.change_passphrase(&master, &replacement)?;
        println!("\nPassphrase set. Your recovery code is unchanged and still works.");
    } else {
        println!("\nNo change made. The vault still opens with its existing passphrase.");
    }
    Ok(())
}

/// Suggest a passphrase drawn from the word list.
///
/// Prints exactly one and never offers a choice: picking a favourite from
/// several reduces the entropy below the figure reported.
pub fn suggest(words: usize) -> Result<()> {
    let phrase = encino_core::passphrase::generate(words)?;

    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdout());

    // Only the passphrase goes to stdout, so redirecting it yields a usable file
    // with nothing to strip. Commentary goes to stderr.
    if interactive {
        println!("\n  {}\n", phrase.as_str());
    } else {
        println!("{}", phrase.as_str());
    }

    // Warns even when the output is being piped, which is exactly when nobody is
    // watching the screen.
    if encino_core::passphrase::is_weak(words) {
        let seconds = encino_core::passphrase::expected_seconds_to_crack(words, GUESSES_PER_SECOND);
        eprintln!(
            "\n  NOT STRONG ENOUGH FOR A VAULT — about {:.0} bits.",
            encino_core::passphrase::entropy_bits(words)
        );
        eprintln!(
            "  Someone holding your disk would expect to find this in about {}.",
            describe_duration(seconds)
        );
        eprintln!("  Use at least {} words for that.\n", encino_core::passphrase::SAFE_WORDS);
    } else if interactive {
        eprintln!(
            "  {words} words from EFF's list of {} — about {:.0} bits of entropy.",
            encino_core::passphrase::WORDLIST_LEN,
            encino_core::passphrase::entropy_bits(words)
        );
    }

    if interactive {
        eprintln!("\n  Take it as it came. Swapping a word you dislike, or reordering");
        eprintln!("  them into something that reads nicely, throws away the randomness");
        eprintln!("  that makes it strong.");
        eprintln!("\n  This was not saved anywhere. Nothing has been changed.");
    }
    Ok(())
}

/// Guess rate assumed when describing how exposed a short passphrase is.
///
/// A well-resourced attacker against this vault's Argon2id parameters — on the
/// order of twenty high-end GPUs. Deliberately pessimistic.
const GUESSES_PER_SECOND: f64 = 10_000.0;

/// Render a duration in whatever unit makes it easiest to feel.
fn describe_duration(seconds: f64) -> String {
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 60.0 * MINUTE;
    const DAY: f64 = 24.0 * HOUR;
    const YEAR: f64 = 365.25 * DAY;

    match seconds {
        s if s < MINUTE => "under a minute".to_string(),
        s if s < HOUR => format!("{:.0} minutes", s / MINUTE),
        s if s < DAY => format!("{:.0} hours", s / HOUR),
        s if s < YEAR => format!("{:.0} days", s / DAY),
        s => format!("{:.0} years", s / YEAR),
    }
}

/// Print the recovery code as a numbered grid.
///
/// Numbered because the failure guarded against is transcription: two words
/// swapped on paper fail the checksum months later.
fn print_recovery_code(code: &RecoveryCode) {
    let words = code.words();
    println!("  RECOVERY CODE — write this down and store it offline");
    println!("  {}", "─".repeat(52));
    for row in 0..(words.len().div_ceil(4)) {
        let line: Vec<String> = (0..4)
            .filter_map(|col| {
                let i = row * 4 + col;
                words.get(i).map(|w| format!("{:>2}. {:<9}", i + 1, w))
            })
            .collect();
        println!("   {}", line.join(" "));
    }
    println!("  {}", "─".repeat(52));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_in_units_a_person_can_feel() {
        assert_eq!(describe_duration(30.0), "under a minute");
        assert_eq!(describe_duration(600.0), "10 minutes");
        assert_eq!(describe_duration(7200.0), "2 hours");
        assert_eq!(describe_duration(86_400.0 * 3.0), "3 days");
        assert_eq!(describe_duration(86_400.0 * 365.25 * 5.0), "5 years");
    }

    #[test]
    fn a_two_word_suggestion_is_described_as_falling_within_hours() {
        // The warning must convey urgency in units a person feels, not in bits.
        let seconds = encino_core::passphrase::expected_seconds_to_crack(2, GUESSES_PER_SECOND);
        let described = describe_duration(seconds);
        assert!(
            described.contains("hour") || described.contains("minute"),
            "two words should read as hours or less, got {described:?}"
        );
    }
}
