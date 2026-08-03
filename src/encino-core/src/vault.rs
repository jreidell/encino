//! Vault metadata and the credential operations that act on it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::Key;
use crate::keyring::{self, KdfConfig, KeyWrap, RecoveryCode, WrapKind};
use crate::{Error, FORMAT_VERSION, Result, VAULT_DIR, fsutil};

/// Contents of `vault.json`. Plaintext by design: only KDF parameters, salts and
/// wrapped key material, none of which are secret, so a vault stays migratable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    /// On-disk format version.
    pub format_version: u32,
    /// Identifies this vault; bound into associated data so material cannot be transplanted.
    pub vault_id: Uuid,
    /// When the vault was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    /// Argon2id parameters chosen at `init`.
    pub kdf: KdfConfig,
    /// Independent encryptions of the same master key.
    pub wraps: Vec<KeyWrap>,
}

impl VaultMeta {
    /// Reject metadata this build cannot safely act on.
    fn validate(&self, path: &Path) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion { found: self.format_version, supported: FORMAT_VERSION });
        }
        self.kdf.validate()?;

        if self.wraps.is_empty() {
            return Err(Error::MalformedMetadata {
                path: path.to_path_buf(),
                detail: "vault has no key wraps, so it can never be opened".into(),
            });
        }
        Ok(())
    }

    fn wrap_of(&self, kind: WrapKind) -> Option<&KeyWrap> {
        self.wraps.iter().find(|w| w.kind == kind)
    }
}

/// A vault on disk, opened but not necessarily unlocked. Holding one grants no
/// access to documents; reading requires a master key from [`Vault::unlock`].
#[derive(Debug, Clone)]
pub struct Vault {
    root: PathBuf,
    meta: VaultMeta,
}

impl Vault {
    /// Create a vault in `root`, returning it alongside the recovery code, which is
    /// handed back once and never stored in recoverable form.
    pub fn init(root: &Path, passphrase: &str, kdf: KdfConfig) -> Result<(Self, RecoveryCode)> {
        kdf.validate()?;

        let vault_dir = root.join(VAULT_DIR);
        if vault_dir.exists() {
            return Err(Error::VaultExists(root.to_path_buf()));
        }

        let vault_id = Uuid::new_v4();
        let master = Key::random();
        let recovery = RecoveryCode::generate()?;

        let wraps = vec![
            keyring::wrap_master(&master, passphrase, WrapKind::Passphrase, &kdf, &vault_id)?,
            keyring::wrap_master(&master, &recovery.phrase(), WrapKind::Recovery, &kdf, &vault_id)?,
        ];

        let meta = VaultMeta {
            format_version: FORMAT_VERSION,
            vault_id,
            created: OffsetDateTime::now_utc(),
            kdf,
            wraps,
        };

        fsutil::ensure_dir(&vault_dir)?;
        // Canonical from here on, so later path comparisons use one spelling of the root.
        let vault = Vault { root: fsutil::canonical(root)?, meta };
        fsutil::ensure_dir(&vault.blobs_dir())?;
        fsutil::ensure_dir(&vault.journal_dir())?;
        fsutil::ensure_dir(&vault.staging_dir())?;
        vault.save_meta()?;

        // Seed an empty index so that a missing index is an error routed to the backup
        // generation, rather than being read as a vault holding no documents.
        let index_key = crate::crypto::derive_subkey(&master, crate::crypto::CTX_INDEX);
        crate::index::Index::new().save(
            &vault.index_path(),
            &vault.index_backup_path(),
            &index_key,
            &vault_id,
        )?;

        Ok((vault, recovery))
    }

    /// Open an existing vault without unlocking it.
    pub fn open(root: &Path) -> Result<Self> {
        let meta_path = root.join(VAULT_DIR).join("vault.json");
        if !meta_path.exists() {
            return Err(Error::NotAVault(root.to_path_buf()));
        }

        let bytes = fsutil::read(&meta_path)?;
        let meta: VaultMeta = serde_json::from_slice(&bytes)
            .map_err(|e| Error::MalformedMetadata { path: meta_path.clone(), detail: e.to_string() })?;
        meta.validate(&meta_path)?;

        Ok(Vault { root: fsutil::canonical(root)?, meta })
    }

    /// Derive the master key from the passphrase.
    pub fn unlock(&self, passphrase: &str) -> Result<Key> {
        self.unlock_with(WrapKind::Passphrase, passphrase)
    }

    /// Derive the master key from the recovery code.
    pub fn recover(&self, code: &RecoveryCode) -> Result<Key> {
        self.unlock_with(WrapKind::Recovery, &code.phrase())
    }

    /// Unwrap the master key using one specific credential. Targeting a single wrap
    /// keeps a failed attempt to one Argon2id derivation.
    fn unlock_with(&self, kind: WrapKind, secret: &str) -> Result<Key> {
        let wrap = self.meta.wrap_of(kind).ok_or(Error::AuthenticationFailed)?;
        keyring::unwrap_master(wrap, secret, &self.meta.kdf, &self.meta.vault_id)
    }

    /// Replace the passphrase, given the master key obtained from the old one. No
    /// document is rewritten, which is why the master key is not derived from the
    /// passphrase directly.
    pub fn change_passphrase(&mut self, master: &Key, new_passphrase: &str) -> Result<()> {
        let replacement = keyring::wrap_master(
            master,
            new_passphrase,
            WrapKind::Passphrase,
            &self.meta.kdf,
            &self.meta.vault_id,
        )?;

        let mut wraps = self.meta.wraps.clone();
        match wraps.iter_mut().find(|w| w.kind == WrapKind::Passphrase) {
            Some(existing) => *existing = replacement,
            None => wraps.push(replacement),
        }

        // Rolled back on a failed write, so no unknown passphrase can be left in place.
        let previous = std::mem::replace(&mut self.meta.wraps, wraps);
        if let Err(e) = self.save_meta() {
            self.meta.wraps = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Persist `vault.json`.
    pub fn save_meta(&self) -> Result<()> {
        let json = serde_json::to_vec_pretty(&self.meta)
            .map_err(|e| Error::MalformedMetadata { path: self.meta_path(), detail: e.to_string() })?;
        fsutil::write_atomic(&self.meta_path(), &json)
    }

    /// The folder this vault manages, which doubles as the plaintext work area.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Vault metadata.
    pub fn meta(&self) -> &VaultMeta {
        &self.meta
    }

    /// This vault's identifier.
    pub fn id(&self) -> &Uuid {
        &self.meta.vault_id
    }

    /// The `.encino` directory.
    pub fn vault_dir(&self) -> PathBuf {
        self.root.join(VAULT_DIR)
    }

    /// Path to `vault.json`.
    pub fn meta_path(&self) -> PathBuf {
        self.vault_dir().join("vault.json")
    }

    /// Path to the sealed index.
    pub fn index_path(&self) -> PathBuf {
        self.vault_dir().join("index.enc")
    }

    /// Path to the previous generation of the index.
    pub fn index_backup_path(&self) -> PathBuf {
        self.vault_dir().join("index.enc.bak")
    }

    /// Root of the blob store.
    pub fn blobs_dir(&self) -> PathBuf {
        self.vault_dir().join("blobs")
    }

    /// Directory holding journal records.
    pub fn journal_dir(&self) -> PathBuf {
        self.vault_dir().join("journal")
    }

    /// The file whose open handle grants exclusive access to this vault.
    pub fn lock_path(&self) -> PathBuf {
        self.vault_dir().join("work.lock")
    }

    /// Where plaintext is assembled before moving into the work area. Inside `.encino`
    /// to share a volume with the destination, so the final move is an atomic rename.
    pub fn staging_dir(&self) -> PathBuf {
        self.vault_dir().join("staging")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_vault(root: &Path) -> (Vault, RecoveryCode) {
        Vault::init(root, "correct horse battery staple", KdfConfig::testing()).unwrap()
    }

    #[test]
    fn a_new_vault_opens_with_its_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = init_vault(dir.path());

        let master = vault.unlock("correct horse battery staple").unwrap();
        let reopened = Vault::open(dir.path()).unwrap();
        let again = reopened.unlock("correct horse battery staple").unwrap();

        assert_eq!(master.expose(), again.expose(), "the key must survive a round trip through disk");
    }

    #[test]
    fn a_new_vault_opens_with_its_recovery_code() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, recovery) = init_vault(dir.path());

        let by_passphrase = vault.unlock("correct horse battery staple").unwrap();
        let by_recovery = vault.recover(&recovery).unwrap();

        assert_eq!(by_passphrase.expose(), by_recovery.expose());
    }

    #[test]
    fn the_recovery_code_still_works_after_the_passphrase_is_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, recovery) = init_vault(dir.path());
        let original = vault.unlock("correct horse battery staple").unwrap();

        vault.change_passphrase(&original, "a passphrase nobody will recall").unwrap();
        drop(vault);

        let reopened = Vault::open(dir.path()).unwrap();
        assert!(reopened.unlock("correct horse battery staple").is_err());

        let rescued = reopened.recover(&recovery).unwrap();
        assert_eq!(rescued.expose(), original.expose());
    }

    #[test]
    fn a_recovery_code_from_another_vault_does_not_open_this_one() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let (vault_a, _) = init_vault(dir_a.path());
        let (_, recovery_b) = init_vault(dir_b.path());

        assert!(matches!(vault_a.recover(&recovery_b), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn changing_the_passphrase_leaves_the_master_key_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _) = init_vault(dir.path());
        let master = vault.unlock("correct horse battery staple").unwrap();

        vault.change_passphrase(&master, "a better passphrase").unwrap();

        let reopened = Vault::open(dir.path()).unwrap();
        assert!(reopened.unlock("correct horse battery staple").is_err());
        assert_eq!(reopened.unlock("a better passphrase").unwrap().expose(), master.expose());
    }

    #[test]
    fn init_refuses_to_overwrite_an_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());

        assert!(matches!(
            Vault::init(dir.path(), "another passphrase", KdfConfig::testing()),
            Err(Error::VaultExists(_))
        ));

        // A refused init must not have damaged the existing vault.
        assert!(Vault::open(dir.path()).unwrap().unlock("correct horse battery staple").is_ok());
    }

    #[test]
    fn opening_a_plain_folder_reports_that_it_is_not_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(Vault::open(dir.path()), Err(Error::NotAVault(_))));
    }

    #[test]
    fn a_future_format_version_is_refused_rather_than_guessed_at() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = init_vault(dir.path());

        let mut raw: serde_json::Value =
            serde_json::from_slice(&fsutil::read(&vault.meta_path()).unwrap()).unwrap();
        raw["format_version"] = serde_json::json!(FORMAT_VERSION + 1);
        fsutil::write_atomic(&vault.meta_path(), &serde_json::to_vec(&raw).unwrap()).unwrap();

        assert!(matches!(Vault::open(dir.path()), Err(Error::UnsupportedVersion { .. })));
    }

    #[test]
    fn hostile_kdf_parameters_in_metadata_are_refused_at_open_time() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = init_vault(dir.path());

        // Checked before any derivation, or a corrupt vault.json becomes a denial of service.
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fsutil::read(&vault.meta_path()).unwrap()).unwrap();
        raw["kdf"]["memory_kib"] = serde_json::json!(u32::MAX);
        fsutil::write_atomic(&vault.meta_path(), &serde_json::to_vec(&raw).unwrap()).unwrap();

        assert!(matches!(Vault::open(dir.path()), Err(Error::MalformedMetadata { .. })));
    }

    #[test]
    fn corrupt_metadata_is_reported_rather_than_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = init_vault(dir.path());
        fsutil::write_atomic(&vault.meta_path(), b"{ this is not json").unwrap();

        assert!(matches!(Vault::open(dir.path()), Err(Error::MalformedMetadata { .. })));
    }

    #[test]
    fn metadata_never_contains_the_master_key() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, recovery) = init_vault(dir.path());
        let master = vault.unlock("correct horse battery staple").unwrap();

        let raw = fsutil::read(&vault.meta_path()).unwrap();
        let text = String::from_utf8_lossy(&raw);

        assert!(!text.contains(&hex::encode(master.expose())));
        assert!(!text.contains(&crate::crypto::b64::encode(master.expose())));
        assert!(!text.contains("correct horse battery staple"));
        assert!(!text.contains(recovery.words()[0]) || recovery.words()[0].len() < 4);
    }

    #[test]
    fn init_lays_out_the_directories_the_rest_of_the_engine_expects() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = init_vault(dir.path());

        assert!(vault.vault_dir().is_dir());
        assert!(vault.blobs_dir().is_dir());
        assert!(vault.journal_dir().is_dir());
        assert!(vault.meta_path().is_file());
    }
}
