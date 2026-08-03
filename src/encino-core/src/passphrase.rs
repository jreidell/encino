//! Suggesting passphrases.
//!
//! The passphrase is the only human-chosen part of the design; everything else is
//! 256 bits of machine randomness, so the passphrase's entropy is the vault's
//! practical strength. Machine selection from a published list makes that entropy
//! exactly statable rather than hoped for.

use zeroize::Zeroizing;

use crate::crypto;
use crate::{Error, Result};

/// EFF's Long Wordlist, compiled in so there is no data file to install or lose.
/// See `wordlists/README.md` for provenance and licence.
const WORDLIST: &str = include_str!("../wordlists/eff_large_wordlist.txt");

/// Words the list is expected to hold: 6⁵, one per outcome of five dice.
pub const WORDLIST_LEN: usize = 7776;

/// Fewest words this will produce. Short output has uses that are not vault
/// passphrases, so anything below [`SAFE_WORDS`] is flagged rather than blocked.
/// One word is refused outright: 7,776 possibilities is not a secret.
pub const MIN_WORDS: usize = 2;

/// Below this, a suggestion is worth warning about. At roughly 10,000 guesses per
/// second against this vault's Argon2id parameters, two words fall in about an hour
/// and three inside a year; five is beyond reach.
pub const SAFE_WORDS: usize = 5;

/// Most words this will produce; the limit only stops a typo generating something absurd.
pub const MAX_WORDS: usize = 24;

/// Words in a suggestion when none is requested. Six gives about 77.5 bits, beyond
/// any feasible search while staying short enough to type and remember.
pub const DEFAULT_WORDS: usize = 6;

/// The word list, parsed once. Each line is `dice-roll<TAB>word`; parsing the published
/// format rather than a stripped copy keeps the vendored file byte-comparable with EFF's.
fn wordlist() -> &'static [&'static str] {
    use std::sync::OnceLock;
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();

    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            .filter_map(|line| line.split('\t').nth(1))
            .map(str::trim)
            .filter(|word| !word.is_empty())
            .collect()
    })
}

/// Bits of entropy each word contributes.
pub fn bits_per_word() -> f64 {
    (wordlist().len() as f64).log2()
}

/// Bits of entropy in a passphrase of `words` words.
pub fn entropy_bits(words: usize) -> f64 {
    words as f64 * bits_per_word()
}

/// Whether a passphrase of this many words is too short to guard a vault.
pub fn is_weak(words: usize) -> bool {
    words < SAFE_WORDS
}

/// Seconds an attacker at `guesses_per_second` would need, on average, to find a
/// passphrase of `words` words. Halved because the average search finishes midway
/// through the space; the guess rate is the uncertain term.
pub fn expected_seconds_to_crack(words: usize, guesses_per_second: f64) -> f64 {
    (2f64.powf(entropy_bits(words)) / 2.0) / guesses_per_second
}

/// Generate a passphrase of `words` words, separated by spaces. Words are drawn with
/// replacement: removing repeats would shrink the space below the entropy reported.
pub fn generate(words: usize) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&words) {
        return Err(Error::InvalidWordCount { requested: words, min: MIN_WORDS, max: MAX_WORDS });
    }

    let list = wordlist();
    let mut phrase = Zeroizing::new(String::with_capacity(words * 8));

    for position in 0..words {
        if position > 0 {
            phrase.push(' ');
        }
        phrase.push_str(list[uniform_index(list.len())]);
    }
    Ok(phrase)
}

/// A uniformly distributed index below `bound`, from the OS random source.
/// Rejection sampling, because `random % bound` is biased whenever `bound` does not
/// divide 2³² — 7776 does not — which would quietly lower the real entropy.
fn uniform_index(bound: usize) -> usize {
    debug_assert!(bound > 0 && bound <= u32::MAX as usize);
    let bound = bound as u32;
    let zone = (u32::MAX / bound) * bound;

    loop {
        let value = u32::from_le_bytes(crypto::random_array::<4>());
        if value < zone {
            return (value % bound) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_vendored_list_is_the_size_it_claims_to_be() {
        // A list quietly short of words would lower every passphrase's entropy
        // invisibly; nothing else can catch it.
        assert_eq!(wordlist().len(), WORDLIST_LEN);
        assert_eq!(WORDLIST_LEN, 6usize.pow(5), "the list should hold one word per five-dice outcome");
    }

    #[test]
    fn every_word_is_distinct_and_usable() {
        let words = wordlist();
        let unique: HashSet<_> = words.iter().collect();
        assert_eq!(unique.len(), words.len(), "duplicates would reduce real entropy");

        // Lowercase ASCII, plus the hyphen four entries carry (`drop-down`,
        // `felt-tip`, `t-shirt`, `yo-yo`).
        for word in words {
            assert!(!word.is_empty());
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{word:?} contains something other than lowercase ASCII and hyphens"
            );
            assert!(!word.contains(' '), "a word containing a space would break the separator");
        }
    }

    #[test]
    fn entropy_matches_the_published_figure() {
        assert!((bits_per_word() - 12.925).abs() < 0.001, "got {}", bits_per_word());
        assert!((entropy_bits(6) - 77.5).abs() < 0.1, "got {}", entropy_bits(6));
    }

    #[test]
    fn a_suggestion_has_the_requested_shape() {
        for count in [MIN_WORDS, DEFAULT_WORDS, 8, MAX_WORDS] {
            let phrase = generate(count).unwrap();
            let words: Vec<&str> = phrase.split(' ').collect();

            assert_eq!(words.len(), count);
            for word in words {
                assert!(wordlist().contains(&word), "{word:?} is not from the list");
            }
        }
    }

    #[test]
    fn absurd_word_counts_are_refused() {
        for count in [0, 1, MAX_WORDS + 1, 1000] {
            assert!(generate(count).is_err(), "{count} words should have been refused");
        }
    }

    #[test]
    fn short_suggestions_are_allowed_but_flagged() {
        // Short output has uses that are not vault passphrases, so it is produced
        // and flagged rather than blocked.
        for count in [2, 3, 4] {
            assert!(generate(count).is_ok(), "{count} words should be produced");
            assert!(is_weak(count), "{count} words should be flagged as weak");
        }
        for count in [SAFE_WORDS, DEFAULT_WORDS, 8] {
            assert!(!is_weak(count), "{count} words should not be flagged");
        }
    }

    #[test]
    fn the_weakness_threshold_reflects_a_real_difference_in_exposure() {
        // A serious attacker's rate against this vault's Argon2id parameters.
        let rate = 10_000.0;
        let year = 365.25 * 24.0 * 3600.0;

        assert!(expected_seconds_to_crack(2, rate) < 86_400.0);
        assert!(expected_seconds_to_crack(SAFE_WORDS, rate) > 1_000_000.0 * year);
    }

    #[test]
    fn suggestions_do_not_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            assert!(seen.insert(generate(DEFAULT_WORDS).unwrap().to_string()), "a suggestion repeated");
        }
    }

    #[test]
    fn word_selection_is_not_visibly_biased() {
        // A modulo shortcut would bias the first 3,232 words by about one part in
        // 1.3 million, too small to see here; this checks spread, not uniformity.
        let list_len = wordlist().len();
        let draws = 200_000;
        let mut counts = vec![0u32; list_len];
        for _ in 0..draws {
            counts[uniform_index(list_len)] += 1;
        }

        let expected = draws as f64 / list_len as f64;
        let max = *counts.iter().max().unwrap() as f64;
        let min = *counts.iter().min().unwrap() as f64;

        assert!(max < expected * 3.0, "one word came up far too often: {max} vs {expected:.1}");
        assert!(min > 0.0, "some word was never selected in {draws} draws");
        assert_eq!(counts.iter().map(|&c| c as u64).sum::<u64>(), draws as u64);
    }

    #[test]
    fn indices_stay_in_range() {
        for bound in [1usize, 2, 6, 7776, 65536] {
            for _ in 0..1000 {
                assert!(uniform_index(bound) < bound);
            }
        }
    }
}
