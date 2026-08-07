//! Key derivation, the master key, and the wraps that protect it.
//!
//! The master key is 32 random bytes, never derived from the passphrase, and stored
//! only in wrapped form under a passphrase-derived key and a recovery-derived key.
//! Either opens the vault; rotating the passphrase rewraps it and touches no document.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, Key, SALT_LEN};
use crate::{Error, Result};

/// Associated data prefix binding a wrap to its vault.
const WRAP_AAD_PREFIX: &[u8] = b"encino:wrap:v1";

/// Words in a recovery code. 24 words carries 256 bits, matching the master key.
pub const RECOVERY_WORDS: usize = 24;

const RECOVERY_ENTROPY_BYTES: usize = 32;

/// OWASP's floor for Argon2id, used as the lower bound during calibration.
const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MIN_ITERATIONS: u32 = 2;

/// Upper bound accepted when reading a vault; a hostile `vault.json` must not demand
/// a terabyte of memory before any credential is checked.
const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 64;

/// Ceiling applied when calibrating. Parameters are baked into the vault, so one chosen
/// on a fast machine must stay openable wherever the vault is later restored; beyond
/// this point cost is bought with iterations, which need no extra memory.
const CALIBRATION_MEMORY_CEILING_KIB: u32 = 256 * 1024;

/// Iterations are raised only until here; beyond it the wait outweighs the gain.
const CALIBRATION_ITERATION_CEILING: u32 = 10;

/// Argon2id parameters, recorded in `vault.json` rather than hardcoded. The cost
/// that opens a vault must be the cost that created it, so it belongs to the vault
/// rather than to the build — which is what allows the defaults to be raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfConfig {
    /// Always `argon2id` in format version 1.
    pub algorithm: String,
    /// Argon2 version number; `19` is 0x13.
    pub version: u32,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost (passes).
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl KdfConfig {
    /// The minimum acceptable parameters.
    pub fn floor() -> Self {
        KdfConfig {
            algorithm: "argon2id".into(),
            version: 0x13,
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    /// Deliberately weak parameters for tests. Never written by `init`.
    #[doc(hidden)]
    pub fn testing() -> Self {
        KdfConfig {
            algorithm: "argon2id".into(),
            version: 0x13,
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Pick parameters taking roughly `target` here, by timing one derivation at the
    /// floor and scaling memory by the shortfall. Approximate; the result is recorded.
    pub fn calibrate(target: Duration) -> Self {
        let mut config = KdfConfig::floor();

        let started = Instant::now();
        let mut probe = [0u8; crypto::KEY_LEN];
        if config.derive_into(b"calibration probe", &[0u8; SALT_LEN], &mut probe).is_err() {
            return config;
        }
        let elapsed = started.elapsed();

        if elapsed.is_zero() {
            return config;
        }

        let scale = target.as_secs_f64() / elapsed.as_secs_f64();
        if scale <= 1.0 {
            return config;
        }

        // Memory first, as it is what costs custom hardware; iterations once capped.
        let wanted = config.memory_kib as f64 * scale;
        config.memory_kib = wanted.min(CALIBRATION_MEMORY_CEILING_KIB as f64) as u32;

        if wanted > CALIBRATION_MEMORY_CEILING_KIB as f64 {
            let leftover = wanted / CALIBRATION_MEMORY_CEILING_KIB as f64;
            let iterations = (config.iterations as f64 * leftover).round() as u32;
            config.iterations = iterations.clamp(MIN_ITERATIONS, CALIBRATION_ITERATION_CEILING);
        }
        config
    }

    /// Reject parameters that are unsupported or out of bounds.
    pub fn validate(&self) -> Result<()> {
        let bad = |detail: String| Error::MalformedMetadata { path: "vault.json".into(), detail };

        if self.algorithm != "argon2id" {
            return Err(bad(format!("unsupported KDF algorithm {:?}", self.algorithm)));
        }
        if self.version != 0x13 {
            return Err(bad(format!("unsupported Argon2 version {}", self.version)));
        }
        if !(1..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(bad(format!("KDF memory cost {} KiB is out of range", self.memory_kib)));
        }
        if !(1..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(bad(format!("KDF iteration count {} is out of range", self.iterations)));
        }
        if !(1..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(bad(format!("KDF parallelism {} is out of range", self.parallelism)));
        }
        Ok(())
    }

    fn derive_into(&self, secret: &[u8], salt: &[u8], out: &mut [u8; crypto::KEY_LEN]) -> Result<()> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(crypto::KEY_LEN))
            .map_err(|e| Error::MalformedMetadata {
            path: "vault.json".into(),
            detail: format!("invalid KDF parameters: {e}"),
        })?;

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(secret, salt, out)
            .map_err(|e| Error::MalformedMetadata {
                path: "vault.json".into(),
                detail: format!("key derivation failed: {e}"),
            })
    }

    /// Derive a key-encryption key from a secret and salt.
    pub fn derive_kek(&self, secret: &str, salt: &[u8]) -> Result<Key> {
        self.validate()?;
        let mut out = [0u8; crypto::KEY_LEN];
        self.derive_into(secret.as_bytes(), salt, &mut out)?;
        Ok(Key::from_bytes(out))
    }
}

/// Which credential a wrap is protected by. A diagnostic label only; unwrapping is
/// authenticated, so a mislabelled entry fails to open rather than misbehaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WrapKind {
    /// Protected by the user's passphrase.
    Passphrase,
    /// Protected by the 24-word recovery code.
    Recovery,
}

impl WrapKind {
    /// Human-readable name for messages.
    pub fn describe(self) -> &'static str {
        match self {
            WrapKind::Passphrase => "passphrase",
            WrapKind::Recovery => "recovery code",
        }
    }
}

/// One encryption of the master key under one credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyWrap {
    /// Which credential opens this wrap.
    pub kind: WrapKind,
    /// Salt for this wrap's key derivation. Per-wrap, never shared.
    #[serde(with = "crate::crypto::b64")]
    pub salt: Vec<u8>,
    /// AEAD nonce.
    #[serde(with = "crate::crypto::b64")]
    pub nonce: Vec<u8>,
    /// The wrapped master key.
    #[serde(with = "crate::crypto::b64")]
    pub ciphertext: Vec<u8>,
}

/// Associated data binding a wrap to one vault, so a wrap cannot be pasted into another.
fn wrap_aad(vault_id: &Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD_PREFIX.len() + 16);
    aad.extend_from_slice(WRAP_AAD_PREFIX);
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

/// Encrypt the master key under a secret, producing a storable wrap.
pub fn wrap_master(
    master: &Key,
    secret: &str,
    kind: WrapKind,
    kdf: &KdfConfig,
    vault_id: &Uuid,
) -> Result<KeyWrap> {
    let salt = crypto::random_array::<SALT_LEN>();
    let kek = kdf.derive_kek(secret, &salt)?;
    let (nonce, ciphertext) = crypto::seal(&kek, &wrap_aad(vault_id), master.expose());

    Ok(KeyWrap { kind, salt: salt.to_vec(), nonce: nonce.to_vec(), ciphertext })
}

/// Recover the master key from a wrap, given the right secret.
pub fn unwrap_master(wrap: &KeyWrap, secret: &str, kdf: &KdfConfig, vault_id: &Uuid) -> Result<Key> {
    let kek = kdf.derive_kek(secret, &wrap.salt)?;
    let plaintext = crypto::open(&kek, &wrap.nonce, &wrap_aad(vault_id), &wrap.ciphertext)?;
    Key::from_slice(&plaintext)
}

/// A 24-word BIP39 recovery code, as powerful as the passphrase: it opens the vault.
pub struct RecoveryCode(Mnemonic);

impl RecoveryCode {
    /// Generate a fresh recovery code from the OS random source.
    pub fn generate() -> Result<Self> {
        let entropy = Zeroizing::new(crypto::random_array::<RECOVERY_ENTROPY_BYTES>());
        Mnemonic::from_entropy(entropy.as_ref())
            .map(RecoveryCode)
            .map_err(|e| Error::InvalidRecoveryCode(e.to_string()))
    }

    /// Parse a user-supplied recovery code. Tolerant of spacing and case; the BIP39
    /// checksum catches transcription errors, which is the reason for a word list.
    pub fn parse(input: &str) -> Result<Self> {
        let normalized = input.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        Mnemonic::parse(&normalized).map(RecoveryCode).map_err(|e| Error::InvalidRecoveryCode(e.to_string()))
    }

    /// The canonical phrase, used for display and as KDF input. Deriving from the
    /// canonical form is what makes tolerant parsing safe: every spelling gives one key.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.words().collect::<Vec<_>>().join(" "))
    }

    /// The phrase split into words, for numbered display.
    pub fn words(&self) -> Vec<&'static str> {
        self.0.words().collect()
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault_id() -> Uuid {
        Uuid::from_bytes([7u8; 16])
    }

    #[test]
    fn master_key_round_trips_through_a_passphrase_wrap() {
        let kdf = KdfConfig::testing();
        let vault = test_vault_id();
        let master = Key::random();

        let wrap =
            wrap_master(&master, "correct horse battery staple", WrapKind::Passphrase, &kdf, &vault).unwrap();
        let recovered = unwrap_master(&wrap, "correct horse battery staple", &kdf, &vault).unwrap();

        assert_eq!(recovered.expose(), master.expose());
    }

    #[test]
    fn wrong_passphrase_fails_without_saying_why() {
        let kdf = KdfConfig::testing();
        let vault = test_vault_id();
        let wrap = wrap_master(&Key::random(), "right", WrapKind::Passphrase, &kdf, &vault).unwrap();

        let err = unwrap_master(&wrap, "wrong", &kdf, &vault).unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));

        let rendered = err.to_string();
        assert!(!rendered.contains("passphrase"), "message leaks which credential failed: {rendered}");
    }

    #[test]
    fn a_wrap_cannot_be_moved_between_vaults() {
        let kdf = KdfConfig::testing();
        let wrap =
            wrap_master(&Key::random(), "secret", WrapKind::Passphrase, &kdf, &test_vault_id()).unwrap();

        let other_vault = Uuid::from_bytes([9u8; 16]);
        assert!(matches!(
            unwrap_master(&wrap, "secret", &kdf, &other_vault),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampering_with_a_wrap_is_detected() {
        let kdf = KdfConfig::testing();
        let vault = test_vault_id();
        let original = wrap_master(&Key::random(), "secret", WrapKind::Passphrase, &kdf, &vault).unwrap();

        for field in 0..3 {
            for byte in 0..8 {
                let mut wrap = original.clone();
                match field {
                    0 => wrap.salt[byte] ^= 0x01,
                    1 => wrap.nonce[byte] ^= 0x01,
                    _ => wrap.ciphertext[byte] ^= 0x01,
                }
                assert!(
                    matches!(unwrap_master(&wrap, "secret", &kdf, &vault), Err(Error::AuthenticationFailed)),
                    "tampering with field {field} byte {byte} went undetected"
                );
            }
        }
    }

    #[test]
    fn two_wraps_of_one_master_key_both_open_it() {
        let kdf = KdfConfig::testing();
        let vault = test_vault_id();
        let master = Key::random();
        let recovery = RecoveryCode::generate().unwrap();

        let by_pass = wrap_master(&master, "passphrase", WrapKind::Passphrase, &kdf, &vault).unwrap();
        let by_code = wrap_master(&master, &recovery.phrase(), WrapKind::Recovery, &kdf, &vault).unwrap();

        assert_eq!(unwrap_master(&by_pass, "passphrase", &kdf, &vault).unwrap().expose(), master.expose());
        assert_eq!(
            unwrap_master(&by_code, &recovery.phrase(), &kdf, &vault).unwrap().expose(),
            master.expose()
        );

        // Independent salts, so the two wraps share nothing an attacker can use.
        assert_ne!(by_pass.salt, by_code.salt);
    }

    #[test]
    fn rotating_a_passphrase_preserves_the_master_key() {
        let kdf = KdfConfig::testing();
        let vault = test_vault_id();
        let master = Key::random();

        let old = wrap_master(&master, "old passphrase", WrapKind::Passphrase, &kdf, &vault).unwrap();
        let recovered = unwrap_master(&old, "old passphrase", &kdf, &vault).unwrap();
        let new = wrap_master(&recovered, "new passphrase", WrapKind::Passphrase, &kdf, &vault).unwrap();

        // The point of the indirection: documents never move.
        assert_eq!(unwrap_master(&new, "new passphrase", &kdf, &vault).unwrap().expose(), master.expose());
        assert!(unwrap_master(&new, "old passphrase", &kdf, &vault).is_err());
    }

    #[test]
    fn recovery_codes_are_24_words_and_unique() {
        let a = RecoveryCode::generate().unwrap();
        let b = RecoveryCode::generate().unwrap();
        assert_eq!(a.words().len(), RECOVERY_WORDS);
        assert_ne!(a.phrase().as_str(), b.phrase().as_str());
    }

    #[test]
    fn recovery_code_parsing_tolerates_formatting_but_not_errors() {
        let code = RecoveryCode::generate().unwrap();
        let canonical = code.phrase();

        let messy = format!("  {}  ", canonical.to_uppercase().replace(' ', "\n  "));
        assert_eq!(RecoveryCode::parse(&messy).unwrap().phrase().as_str(), canonical.as_str());

        // A single altered word must fail the checksum rather than derive another key.
        let mut words: Vec<&str> = canonical.split(' ').collect();
        words[0] = if words[0] == "abandon" { "ability" } else { "abandon" };
        assert!(matches!(RecoveryCode::parse(&words.join(" ")), Err(Error::InvalidRecoveryCode(_))));

        assert!(RecoveryCode::parse("not actually a mnemonic at all").is_err());
        assert!(RecoveryCode::parse("").is_err());
    }

    #[test]
    fn recovery_code_debug_never_reveals_the_phrase() {
        let code = RecoveryCode::generate().unwrap();
        let rendered = format!("{code:?}");
        assert_eq!(rendered, "RecoveryCode(<redacted>)");
        assert!(!rendered.contains(code.words()[0]));
    }

    #[test]
    fn hostile_kdf_parameters_are_rejected_before_use() {
        let mut config = KdfConfig::floor();

        config.memory_kib = u32::MAX;
        assert!(config.validate().is_err());

        config = KdfConfig::floor();
        config.iterations = 0;
        assert!(config.validate().is_err());

        config = KdfConfig::floor();
        config.algorithm = "md5".into();
        assert!(config.validate().is_err());

        config = KdfConfig::floor();
        config.version = 0x10;
        assert!(config.validate().is_err());

        assert!(KdfConfig::floor().validate().is_ok());
    }

    #[test]
    fn floor_meets_owasp_guidance() {
        let floor = KdfConfig::floor();
        assert!(floor.memory_kib >= 19 * 1024);
        assert!(floor.iterations >= 2);
    }

    #[test]
    fn calibration_never_returns_parameters_below_the_floor() {
        let config = KdfConfig::calibrate(Duration::from_millis(50));
        assert!(config.memory_kib >= MIN_MEMORY_KIB);
        assert!(config.iterations >= MIN_ITERATIONS);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn calibration_stays_within_limits_a_future_machine_can_still_meet() {
        // Neither cost may run away, or a restored vault stops being openable.
        for target in [Duration::from_millis(1), Duration::from_secs(1), Duration::from_secs(600)] {
            let config = KdfConfig::calibrate(target);
            assert!(
                config.memory_kib <= CALIBRATION_MEMORY_CEILING_KIB,
                "memory cost {} KiB exceeds the portability ceiling",
                config.memory_kib
            );
            assert!(config.iterations <= CALIBRATION_ITERATION_CEILING);
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn an_unreachable_target_buys_iterations_once_memory_is_capped() {
        // A ten-minute target cannot be met with 256 MiB alone; the remainder must land somewhere.
        let config = KdfConfig::calibrate(Duration::from_secs(600));
        assert_eq!(config.memory_kib, CALIBRATION_MEMORY_CEILING_KIB);
        assert!(config.iterations > MIN_ITERATIONS, "iterations should have absorbed the remainder");
    }

    #[test]
    fn kdf_config_survives_a_json_round_trip() {
        let config = KdfConfig::floor();
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(serde_json::from_str::<KdfConfig>(&json).unwrap(), config);
    }
}
