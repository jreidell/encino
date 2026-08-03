//! The encrypted document index. Filenames and directory structure exist only here
//! and the blob store is flat, so losing this file loses every document: it is
//! replaced atomically and kept one generation back.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::blob::{BlobId, BlobStats};
use crate::crypto::{self, Key, NONCE_LEN};
use crate::docpath::DocPath;
use crate::{Error, Result, fsutil};

/// Magic prefix, also bound into the index's associated data.
pub const INDEX_MAGIC: &[u8; 8] = b"ENCINOI1";

/// Associated data for a wrapped per-document content key.
const CONTENT_KEY_AAD_PREFIX: &[u8] = b"encino:contentkey:v1";

/// A per-document content key, encrypted under the blob-key-wrapping key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// AEAD nonce.
    #[serde(with = "crate::crypto::b64")]
    pub nonce: Vec<u8>,
    /// The wrapped key.
    #[serde(with = "crate::crypto::b64")]
    pub ciphertext: Vec<u8>,
}

/// Binds a content key to the blob it decrypts, so two entries' keys cannot be swapped.
fn content_key_aad(blob_id: &BlobId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CONTENT_KEY_AAD_PREFIX.len() + blob_id.as_bytes().len());
    aad.extend_from_slice(CONTENT_KEY_AAD_PREFIX);
    aad.extend_from_slice(blob_id.as_bytes());
    aad
}

/// Encrypt a content key for storage in the index.
pub fn wrap_content_key(content_key: &Key, blob_id: &BlobId, wrapping_key: &Key) -> WrappedKey {
    let (nonce, ciphertext) = crypto::seal(wrapping_key, &content_key_aad(blob_id), content_key.expose());
    WrappedKey { nonce: nonce.to_vec(), ciphertext }
}

/// Recover a content key from the index.
pub fn unwrap_content_key(wrapped: &WrappedKey, blob_id: &BlobId, wrapping_key: &Key) -> Result<Key> {
    let plaintext =
        crypto::open(wrapping_key, &wrapped.nonce, &content_key_aad(blob_id), &wrapped.ciphertext)?;
    Key::from_slice(&plaintext)
}

/// One document's record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentEntry {
    /// Logical name, including any subfolders.
    pub path: DocPath,
    /// Which blob holds the ciphertext.
    pub blob_id: BlobId,
    /// This document's content key, wrapped.
    pub wrapped_key: WrappedKey,
    /// Plaintext size in bytes.
    pub size: u64,
    /// SHA-256 of the plaintext, in hex.
    pub sha256: String,
    /// Modification time carried over from the imported file.
    #[serde(with = "time::serde::rfc3339")]
    pub modified: OffsetDateTime,
    /// When the document was imported.
    #[serde(with = "time::serde::rfc3339")]
    pub added: OffsetDateTime,
}

impl DocumentEntry {
    /// Whether stored statistics match what was just read back.
    pub fn matches(&self, stats: &BlobStats) -> bool {
        self.size == stats.size && self.sha256 == hex::encode(stats.sha256)
    }
}

/// The document index, keyed by logical path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    documents: BTreeMap<DocPath, DocumentEntry>,
}

impl Index {
    /// An index holding no documents.
    pub fn new() -> Self {
        Index::default()
    }

    /// Number of documents held.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether the vault holds no documents.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Look up one document.
    pub fn get(&self, path: &DocPath) -> Option<&DocumentEntry> {
        self.documents.get(path)
    }

    /// Whether a document exists.
    pub fn contains(&self, path: &DocPath) -> bool {
        self.documents.contains_key(path)
    }

    /// Every document, ordered by logical path.
    pub fn iter(&self) -> impl Iterator<Item = &DocumentEntry> {
        self.documents.values()
    }

    /// Total plaintext bytes held.
    pub fn total_size(&self) -> u64 {
        self.documents.values().map(|d| d.size).sum()
    }

    /// Add a document, refusing to displace an existing one, or one differing only by
    /// case: Linux stores `W2.pdf` beside `w2.pdf`, but a checkout on Windows or macOS
    /// would have the second overwrite the first, so the vault must stay portable.
    pub fn insert(&mut self, entry: DocumentEntry) -> Result<()> {
        if let Some(existing) = self.colliding_path(&entry.path) {
            return Err(Error::DuplicateDocument(existing.to_string()));
        }
        self.documents.insert(entry.path.clone(), entry);
        Ok(())
    }

    /// An existing name equal to `path`, or differing only by case.
    fn colliding_path(&self, path: &DocPath) -> Option<&DocPath> {
        if let Some((existing, _)) = self.documents.get_key_value(path) {
            return Some(existing);
        }
        let folded = path.as_str().to_lowercase();
        self.documents.keys().find(|held| held.as_str().to_lowercase() == folded)
    }

    /// Add or replace a document.
    pub fn replace(&mut self, entry: DocumentEntry) -> Option<DocumentEntry> {
        self.documents.insert(entry.path.clone(), entry)
    }

    /// Remove a document, returning its record.
    pub fn remove(&mut self, path: &DocPath) -> Result<DocumentEntry> {
        self.documents.remove(path).ok_or_else(|| Error::NoSuchDocument(path.to_string()))
    }

    /// Decrypt an index from disk. The vault id is bound into the associated data, so
    /// an index lifted from one vault cannot be substituted into another.
    pub fn load(path: &Path, index_key: &Key, vault_id: &Uuid) -> Result<Self> {
        let raw = fsutil::read(path)?;
        Index::decode(&raw, index_key, vault_id, path)
    }

    /// Decrypt an index, falling back to the backup generation if the primary is
    /// unreadable. Its loss costs every document, so a damaged primary is retried.
    pub fn load_with_fallback(
        primary: &Path,
        backup: &Path,
        index_key: &Key,
        vault_id: &Uuid,
    ) -> Result<(Self, bool)> {
        match Index::load(primary, index_key, vault_id) {
            Ok(index) => Ok((index, false)),
            Err(primary_error) => {
                if !backup.exists() {
                    return Err(primary_error);
                }
                match Index::load(backup, index_key, vault_id) {
                    Ok(index) => Ok((index, true)),
                    // The primary's failure is the informative one.
                    Err(_) => Err(primary_error),
                }
            }
        }
    }

    /// Encrypt and write the index, retaining the previous generation.
    pub fn save(&self, path: &Path, backup: &Path, index_key: &Key, vault_id: &Uuid) -> Result<()> {
        if path.exists() {
            fsutil::copy_atomic(path, backup)?;
        }
        fsutil::write_atomic(path, &self.encode(index_key, vault_id)?)
    }

    fn aad(vault_id: &Uuid) -> Vec<u8> {
        let mut aad = Vec::with_capacity(INDEX_MAGIC.len() + 16);
        aad.extend_from_slice(INDEX_MAGIC);
        aad.extend_from_slice(vault_id.as_bytes());
        aad
    }

    fn encode(&self, index_key: &Key, vault_id: &Uuid) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(|e| Error::CorruptData {
            path: "index.enc".into(),
            detail: format!("could not serialize the index: {e}"),
        })?;

        let (nonce, ciphertext) = crypto::seal(index_key, &Index::aad(vault_id), &json);

        let mut out = Vec::with_capacity(INDEX_MAGIC.len() + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(INDEX_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decode(raw: &[u8], index_key: &Key, vault_id: &Uuid, path: &Path) -> Result<Self> {
        if raw.len() < INDEX_MAGIC.len() + NONCE_LEN {
            return Err(Error::CorruptData {
                path: path.to_path_buf(),
                detail: "file is too short to be an index".into(),
            });
        }
        if &raw[..INDEX_MAGIC.len()] != INDEX_MAGIC {
            return Err(Error::CorruptData { path: path.to_path_buf(), detail: "wrong file magic".into() });
        }

        let nonce = &raw[INDEX_MAGIC.len()..INDEX_MAGIC.len() + NONCE_LEN];
        let ciphertext = &raw[INDEX_MAGIC.len() + NONCE_LEN..];
        let plaintext = crypto::open(index_key, nonce, &Index::aad(vault_id), ciphertext)?;

        serde_json::from_slice(&plaintext).map_err(|e| Error::CorruptData {
            path: path.to_path_buf(),
            detail: format!("index contents are malformed: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> DocumentEntry {
        let blob_id = BlobId::random();
        DocumentEntry {
            path: DocPath::new(path).unwrap(),
            blob_id,
            wrapped_key: wrap_content_key(&Key::random(), &blob_id, &Key::random()),
            size: 1234,
            sha256: hex::encode([0u8; 32]),
            modified: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            added: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        }
    }

    fn populated() -> Index {
        let mut index = Index::new();
        index.insert(entry("taxes/2024/w2.pdf")).unwrap();
        index.insert(entry("chase-statement-01.pdf")).unwrap();
        index.insert(entry("relevé-bancaire.pdf")).unwrap();
        index
    }

    #[test]
    fn an_index_survives_a_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let key = Key::random();
        let vault = Uuid::new_v4();

        let original = populated();
        original.save(&path, &backup, &key, &vault).unwrap();

        let loaded = Index::load(&path, &key, &vault).unwrap();
        assert_eq!(loaded.len(), original.len());
        for doc in original.iter() {
            let found = loaded.get(&doc.path).expect("document should survive the round trip");
            assert_eq!(found.blob_id, doc.blob_id);
            assert_eq!(found.size, doc.size);
            assert_eq!(found.sha256, doc.sha256);
            assert_eq!(found.modified, doc.modified);
        }
    }

    #[test]
    fn filenames_do_not_appear_in_the_encrypted_file() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));

        populated().save(&path, &backup, &Key::random(), &Uuid::new_v4()).unwrap();

        let raw = std::fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&raw);
        for fragment in ["taxes", "w2.pdf", "chase", "relevé", ".pdf"] {
            assert!(!text.contains(fragment), "{fragment:?} leaked into the index file");
        }
    }

    #[test]
    fn the_wrong_key_cannot_read_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let vault = Uuid::new_v4();

        populated().save(&path, &backup, &Key::random(), &vault).unwrap();
        assert!(matches!(Index::load(&path, &Key::random(), &vault), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn an_index_cannot_be_moved_between_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let key = Key::random();

        populated().save(&path, &backup, &key, &Uuid::new_v4()).unwrap();
        assert!(matches!(Index::load(&path, &key, &Uuid::new_v4()), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn tampering_with_the_index_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let key = Key::random();
        let vault = Uuid::new_v4();
        populated().save(&path, &backup, &key, &vault).unwrap();

        let original = std::fs::read(&path).unwrap();
        for byte in [8, 20, original.len() / 2, original.len() - 1] {
            let mut tampered = original.clone();
            tampered[byte] ^= 0x01;
            std::fs::write(&path, &tampered).unwrap();
            assert!(Index::load(&path, &key, &vault).is_err(), "tampering at byte {byte} went undetected");
        }
    }

    #[test]
    fn saving_retains_the_previous_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let key = Key::random();
        let vault = Uuid::new_v4();

        let first = populated();
        first.save(&path, &backup, &key, &vault).unwrap();
        assert!(!backup.exists(), "there is no previous generation to keep on the first save");

        let mut second = first.clone();
        second.insert(entry("new-document.pdf")).unwrap();
        second.save(&path, &backup, &key, &vault).unwrap();

        assert_eq!(Index::load(&path, &key, &vault).unwrap().len(), 4);
        assert_eq!(Index::load(&backup, &key, &vault).unwrap().len(), 3);
    }

    #[test]
    fn a_damaged_index_falls_back_to_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let key = Key::random();
        let vault = Uuid::new_v4();

        populated().save(&path, &backup, &key, &vault).unwrap();
        let mut grown = populated();
        grown.insert(entry("new-document.pdf")).unwrap();
        grown.save(&path, &backup, &key, &vault).unwrap();

        std::fs::write(&path, b"corrupted beyond repair").unwrap();

        let (recovered, used_backup) = Index::load_with_fallback(&path, &backup, &key, &vault).unwrap();
        assert!(used_backup, "the caller must be told the backup was used");
        assert_eq!(recovered.len(), 3);
    }

    #[test]
    fn fallback_reports_the_primary_failure_when_both_are_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let key = Key::random();
        let vault = Uuid::new_v4();

        populated().save(&path, &backup, &key, &vault).unwrap();
        std::fs::write(&path, b"corrupt").unwrap();
        std::fs::write(&backup, b"also corrupt").unwrap();

        assert!(Index::load_with_fallback(&path, &backup, &key, &vault).is_err());
    }

    #[test]
    fn content_keys_round_trip_but_cannot_be_exchanged() {
        let wrapping = Key::random();
        let content = Key::random();
        let blob = BlobId::random();

        let wrapped = wrap_content_key(&content, &blob, &wrapping);
        assert_eq!(unwrap_content_key(&wrapped, &blob, &wrapping).unwrap().expose(), content.expose());

        // Bound to its blob: an entry cannot be repointed at another blob.
        assert!(matches!(
            unwrap_content_key(&wrapped, &BlobId::random(), &wrapping),
            Err(Error::AuthenticationFailed)
        ));
        assert!(matches!(
            unwrap_content_key(&wrapped, &blob, &Key::random()),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn duplicate_paths_are_refused_but_replacement_is_explicit() {
        let mut index = Index::new();
        index.insert(entry("w2.pdf")).unwrap();

        assert!(matches!(index.insert(entry("w2.pdf")), Err(Error::DuplicateDocument(_))));
        assert_eq!(index.len(), 1);

        assert!(index.replace(entry("w2.pdf")).is_some());
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn names_differing_only_by_case_are_refused() {
        // A case-insensitive filesystem would overwrite the first on checkout.
        let mut index = Index::new();
        index.insert(entry("taxes/2024/w2.pdf")).unwrap();

        for clash in ["taxes/2024/W2.pdf", "Taxes/2024/w2.pdf", "TAXES/2024/W2.PDF"] {
            assert!(
                matches!(index.insert(entry(clash)), Err(Error::DuplicateDocument(_))),
                "{clash} should collide with the document already held"
            );
        }

        assert!(index.insert(entry("taxes/2024/w2-spouse.pdf")).is_ok());
        assert!(index.insert(entry("taxes/2023/w2.pdf")).is_ok());
        assert_eq!(index.len(), 3);
    }

    #[test]
    fn removing_a_missing_document_is_an_error() {
        let mut index = populated();
        let path = DocPath::new("not-here.pdf").unwrap();
        assert!(matches!(index.remove(&path), Err(Error::NoSuchDocument(_))));

        let existing = DocPath::new("taxes/2024/w2.pdf").unwrap();
        assert!(index.remove(&existing).is_ok());
        assert!(!index.contains(&existing));
    }

    #[test]
    fn documents_are_listed_in_a_stable_order() {
        let names: Vec<String> = populated().iter().map(|d| d.path.to_string()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "listing order must not depend on insertion order");
    }

    #[test]
    fn an_index_holding_a_traversal_path_will_not_deserialize() {
        // Authenticated, so this needs the key, but a buggy future build must still not
        // be able to talk this one into writing outside the vault folder.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.enc");
        let key = Key::random();
        let vault = Uuid::new_v4();

        let hostile = serde_json::json!({
            "documents": {
                "../../escape.txt": {
                    "path": "../../escape.txt",
                    "blob_id": BlobId::random().to_hex(),
                    "wrapped_key": { "nonce": "", "ciphertext": "" },
                    "size": 1,
                    "sha256": "00",
                    "modified": "2026-01-01T00:00:00Z",
                    "added": "2026-01-01T00:00:00Z"
                }
            }
        });

        let (nonce, ciphertext) =
            crypto::seal(&key, &Index::aad(&vault), serde_json::to_vec(&hostile).unwrap().as_slice());
        let mut raw = INDEX_MAGIC.to_vec();
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ciphertext);
        std::fs::write(&path, &raw).unwrap();

        assert!(matches!(Index::load(&path, &key, &vault), Err(Error::CorruptData { .. })));
    }

    #[test]
    fn a_file_that_is_not_an_index_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.enc");

        for contents in [b"short".to_vec(), b"not an index file at all, but long enough".to_vec()] {
            std::fs::write(&path, &contents).unwrap();
            assert!(matches!(
                Index::load(&path, &Key::random(), &Uuid::new_v4()),
                Err(Error::CorruptData { .. })
            ));
        }
    }

    #[test]
    fn an_empty_index_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let (path, backup) = (dir.path().join("index.enc"), dir.path().join("index.enc.bak"));
        let key = Key::random();
        let vault = Uuid::new_v4();

        Index::new().save(&path, &backup, &key, &vault).unwrap();
        let loaded = Index::load(&path, &key, &vault).unwrap();
        assert!(loaded.is_empty());
        assert_eq!(loaded.total_size(), 0);
    }
}
