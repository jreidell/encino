//! Cryptographic primitives: thin wrappers over `chacha20poly1305`, `hkdf`, and
//! the OS random source, giving the crate one reviewable way to encrypt.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key as CipherKey, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Length of every symmetric key in this design.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length. At 192 bits, random nonces collide
/// negligibly often, so no counter state need be persisted.
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;
/// Argon2id salt length.
pub const SALT_LEN: usize = 16;

/// HKDF context for the key that seals the index.
pub const CTX_INDEX: &str = "encino:index:v1";
/// HKDF context for the key that wraps per-document content keys.
pub const CTX_BLOB_KEY: &str = "encino:blobkey:v1";

/// A 32-byte symmetric key, wiped when dropped. No `Display` or `Serialize` and
/// a redacting `Debug`, so [`Key::expose`] is the only greppable route to the
/// bytes.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    /// Generate a key from the operating system's random source.
    pub fn random() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        fill_random(&mut bytes);
        Key(Zeroizing::new(bytes))
    }

    /// Wrap existing key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Key(Zeroizing::new(bytes))
    }

    /// Build a key from a slice, which must be exactly [`KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::AuthenticationFailed)?;
        Ok(Key::from_bytes(array))
    }

    /// Borrow the raw key bytes.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// Fill a buffer from the operating system's random source.
pub fn fill_random(buf: &mut [u8]) {
    rand::rng().fill_bytes(buf);
}

/// Generate `N` random bytes.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    fill_random(&mut bytes);
    bytes
}

/// Derive a purpose-specific subkey from the master key. Distinct context
/// strings ensure no two roles share key material.
pub fn derive_subkey(master: &Key, context: &str) -> Key {
    let hk = Hkdf::<Sha256>::new(None, master.expose());
    let mut out = [0u8; KEY_LEN];
    hk.expand(context.as_bytes(), &mut out).expect("32 bytes is always a valid HKDF-SHA256 output length");
    Key::from_bytes(out)
}

/// Encrypt with a fresh random nonce, returning `(nonce, ciphertext ‖ tag)`.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let nonce_bytes = random_array::<NONCE_LEN>();
    let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(key.expose()));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), Payload { msg: plaintext, aad })
        .expect("AEAD encryption of an in-memory buffer cannot fail");
    (nonce_bytes, ciphertext)
}

/// Decrypt and authenticate. Every failure returns the same
/// [`Error::AuthenticationFailed`], so no failure mode is distinguishable.
pub fn open(key: &Key, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::AuthenticationFailed);
    }
    let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(key.expose()));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::AuthenticationFailed)
}

/// SHA-256 of a byte slice, used to record plaintext digests for `verify`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Incremental SHA-256, for hashing a document without holding it in memory.
#[derive(Default)]
pub struct Sha256Stream(Sha256);

impl Sha256Stream {
    /// Start a new digest.
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    /// Add more bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Finish and return the digest.
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// Base64 helpers for the binary fields embedded in `vault.json` and the index.
pub mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Encode bytes as standard padded base64.
    pub fn encode(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// Decode standard padded base64.
    pub fn decode(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
        STANDARD.decode(text)
    }

    /// `serde` serializer for `Vec<u8>` fields. Takes `&Vec<u8>` because
    /// `#[serde(with = ...)]` passes the field's own type; a slice does not
    /// compile, clippy's advice notwithstanding.
    #[allow(clippy::ptr_arg)]
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(bytes))
    }

    /// `serde` deserializer for `Vec<u8>` fields.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        decode(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open_round_trip() {
        let key = Key::random();
        let (nonce, ct) = seal(&key, b"aad", b"secret document");
        let pt = open(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(&pt[..], b"secret document");
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let (nonce, ct) = seal(&Key::random(), b"aad", b"secret");
        assert!(matches!(open(&Key::random(), &nonce, b"aad", &ct), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn wrong_aad_fails_authentication() {
        let key = Key::random();
        let (nonce, ct) = seal(&key, b"aad-one", b"secret");
        assert!(matches!(open(&key, &nonce, b"aad-two", &ct), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn every_flipped_ciphertext_bit_fails_authentication() {
        let key = Key::random();
        let (nonce, ct) = seal(&key, b"aad", b"secret document");

        // Exhaustive rather than sampled: partial detection is not authentication.
        for byte in 0..ct.len() {
            for bit in 0..8 {
                let mut tampered = ct.clone();
                tampered[byte] ^= 1 << bit;
                assert!(
                    matches!(open(&key, &nonce, b"aad", &tampered), Err(Error::AuthenticationFailed)),
                    "flipping bit {bit} of byte {byte} was not detected"
                );
            }
        }
    }

    #[test]
    fn truncated_ciphertext_fails_authentication() {
        let key = Key::random();
        let (nonce, ct) = seal(&key, b"aad", b"secret document");
        for len in 0..ct.len() {
            assert!(matches!(open(&key, &nonce, b"aad", &ct[..len]), Err(Error::AuthenticationFailed)));
        }
    }

    #[test]
    fn malformed_nonce_is_rejected_not_panicked_on() {
        let key = Key::random();
        let (_, ct) = seal(&key, b"aad", b"secret");
        assert!(matches!(open(&key, &[0u8; 8], b"aad", &ct), Err(Error::AuthenticationFailed)));
        assert!(matches!(open(&key, &[], b"aad", &ct), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn nonces_do_not_repeat() {
        let key = Key::random();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let (nonce, _) = seal(&key, b"", b"x");
            assert!(seen.insert(nonce), "nonce reuse would be catastrophic here");
        }
    }

    #[test]
    fn subkeys_differ_by_context_and_are_deterministic() {
        let master = Key::random();
        let index_a = derive_subkey(&master, CTX_INDEX);
        let index_b = derive_subkey(&master, CTX_INDEX);
        let blob = derive_subkey(&master, CTX_BLOB_KEY);

        assert_eq!(index_a.expose(), index_b.expose(), "derivation must be deterministic");
        assert_ne!(index_a.expose(), blob.expose(), "contexts must not collide");
        assert_ne!(index_a.expose(), master.expose());
    }

    #[test]
    fn debug_never_reveals_key_material() {
        let key = Key::from_bytes([0xAB; KEY_LEN]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "Key(<redacted>)");
        assert!(!rendered.contains("ab") && !rendered.contains("171"));
    }

    // Known-answer test for RFC 5869 HKDF-SHA256, case 1: checks the primitive
    // is called correctly.
    #[test]
    fn hkdf_matches_rfc5869_vector() {
        let ikm = [0x0b; 22];
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&[], &mut okm).unwrap();
        // Expected output for salt=None (all-zero salt), info empty, L=42.
        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap();
        assert_eq!(&okm[..], &expected[..]);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn streaming_sha256_matches_one_shot() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut stream = Sha256Stream::new();
        for chunk in data.chunks(997) {
            stream.update(chunk);
        }
        assert_eq!(stream.finish(), sha256(&data));
    }

    #[test]
    fn base64_round_trips() {
        let bytes = random_array::<40>();
        assert_eq!(b64::decode(&b64::encode(&bytes)).unwrap(), bytes);
    }
}
