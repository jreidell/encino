//! An unlocked vault: the operations that need the master key. Creating a
//! [`Session`] costs an Argon2id derivation, so the agent holds one.

use std::fs::File;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::blob::{self, BlobId, BlobStats};
use crate::crypto::{self, CTX_BLOB_KEY, CTX_INDEX, Key, Sha256Stream};
use crate::docpath::DocPath;
use crate::index::{DocumentEntry, Index};
use crate::journal::{Journal, OpKind, Stage};
use crate::lock::VaultLock;
use crate::vault::Vault;
use crate::{Error, RecoveryCode, Result, fsutil, shred};

/// What happened when a document was checked in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckinOutcome {
    /// Unchanged byte-for-byte; the stored ciphertext was kept.
    Unchanged,
    /// The document had been edited, so it was re-encrypted under a new key.
    Updated,
}

/// Something reconciled after an interrupted run.
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// An import never reached the index; its orphaned ciphertext was removed.
    DiscardedIncompleteImport(DocPath),
    /// A partially written plaintext file was destroyed.
    RemovedPartialCheckout(DocPath),
    /// A check-in had reached the index, so it was carried to completion.
    FinishedCheckin(DocPath),
    /// A check-in had not reached the index; it was rolled back and stays open.
    RolledBackCheckin(DocPath),
    /// A deletion had reached the index, so its ciphertext was removed.
    FinishedRemoval(DocPath),
}

impl std::fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryAction::DiscardedIncompleteImport(p) => {
                write!(f, "discarded an incomplete import of {p}")
            }
            RecoveryAction::RemovedPartialCheckout(p) => {
                write!(f, "removed a partially decrypted copy of {p}")
            }
            RecoveryAction::FinishedCheckin(p) => write!(f, "completed the check-in of {p}"),
            RecoveryAction::RolledBackCheckin(p) => {
                write!(f, "rolled back an interrupted check-in of {p}; it is still open")
            }
            RecoveryAction::FinishedRemoval(p) => write!(f, "completed the removal of {p}"),
        }
    }
}

/// A problem found by [`Session::verify`].
#[derive(Debug, Clone)]
pub struct VerifyIssue {
    /// Document affected, if the problem belongs to one.
    pub document: Option<DocPath>,
    /// What is wrong.
    pub problem: String,
}

/// An unlocked vault. Holding one holds the vault lock, so sessions are
/// short-lived — one per command — rather than kept around.
pub struct Session {
    vault: Vault,
    index_key: Key,
    blob_wrap_key: Key,
    index: Index,
    journal: Journal,
    /// Declared last so it outlives the fields whose writes it protects.
    _lock: VaultLock,
}

impl Session {
    /// Unlock with a passphrase.
    pub fn unlock(vault: Vault, passphrase: &str) -> Result<Self> {
        let master = vault.unlock(passphrase)?;
        Session::from_master(vault, &master)
    }

    /// Unlock with a recovery code.
    pub fn recover_with(vault: Vault, code: &RecoveryCode) -> Result<Self> {
        let master = vault.recover(code)?;
        Session::from_master(vault, &master)
    }

    /// Build a session from an already-derived master key. The lock is taken
    /// before the index is read: reading first leaves a window in which another
    /// session could replace the index between the two.
    pub fn from_master(vault: Vault, master: &Key) -> Result<Self> {
        // Report the vault folder rather than the lock file inside it; naming
        // internal bookkeeping only invites someone to delete it.
        let lock = VaultLock::acquire(&vault.lock_path()).map_err(|e| match e {
            Error::VaultInUse { holder, .. } => {
                Error::VaultInUse { path: vault.root().to_path_buf(), holder }
            }
            other => other,
        })?;

        let index_key = crypto::derive_subkey(master, CTX_INDEX);
        let blob_wrap_key = crypto::derive_subkey(master, CTX_BLOB_KEY);
        let journal = Journal::new(vault.journal_dir());

        let (index, _used_backup) = Index::load_with_fallback(
            &vault.index_path(),
            &vault.index_backup_path(),
            &index_key,
            vault.id(),
        )?;

        let mut session = Session { vault, index_key, blob_wrap_key, index, journal, _lock: lock };
        session.reconcile()?;
        Ok(session)
    }

    /// The vault this session is attached to.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Every document, ordered by name.
    pub fn documents(&self) -> impl Iterator<Item = &DocumentEntry> {
        self.index.iter()
    }

    /// How many documents the vault holds.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the vault holds no documents.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Total plaintext bytes held.
    pub fn total_size(&self) -> u64 {
        self.index.total_size()
    }

    /// Look up one document.
    pub fn get(&self, name: &DocPath) -> Option<&DocumentEntry> {
        self.index.get(name)
    }

    /// Where a document's plaintext lives while it is checked out.
    pub fn plaintext_path(&self, name: &DocPath) -> Result<PathBuf> {
        name.resolve_under(self.vault.root())
    }

    /// Whether a document is currently checked out. Determined from the
    /// filesystem rather than stored state, which could drift out of step.
    pub fn is_open(&self, name: &DocPath) -> bool {
        self.plaintext_path(name).map(|p| shred::is_regular_file(&p)).unwrap_or(false)
    }

    /// Every document currently checked out.
    pub fn open_documents(&self) -> Vec<&DocumentEntry> {
        self.index.iter().filter(|d| self.is_open(&d.path)).collect()
    }

    /// Import a file, encrypting it into the vault. Unless `keep_source` is set,
    /// the original is shredded once the ciphertext is durable and indexed.
    pub fn add(&mut self, source: &Path, name: &DocPath, keep_source: bool) -> Result<()> {
        // The same rule `Index::insert` enforces, applied before any work: a name
        // differing only by case reaches that check having already written a blob
        // and a journal record, which the next session then has to reconcile away.
        if let Some(existing) = self.index.colliding_path(name) {
            return Err(Error::DuplicateDocument(existing.to_string()));
        }

        let metadata = std::fs::symlink_metadata(source).map_err(|e| Error::io("inspect", source, e))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::InvalidDocumentPath {
                path: source.display().to_string(),
                reason: "only regular files can be imported".into(),
            });
        }
        let modified =
            metadata.modified().map(OffsetDateTime::from).unwrap_or_else(|_| OffsetDateTime::now_utc());

        let blob_id = BlobId::random();
        let mut op = self.journal.begin(OpKind::Add, name, Some(blob_id), None)?;

        let content_key = Key::random();
        let blob_path = blob_id.path_under(&self.vault.blobs_dir());
        let mut file = File::open(source).map_err(|e| Error::io("open", source, e))?;
        let stats = blob::write_blob(&mut file, &blob_path, &blob_id, &content_key)?;
        drop(file);
        op.advance(Stage::DataWritten)?;

        self.index.insert(DocumentEntry {
            path: name.clone(),
            blob_id,
            wrapped_key: crate::index::wrap_content_key(&content_key, &blob_id, &self.blob_wrap_key),
            size: stats.size,
            sha256: hex::encode(stats.sha256),
            modified,
            added: OffsetDateTime::now_utc(),
        })?;
        self.save_index()?;
        op.advance(Stage::IndexUpdated)?;

        // Empty folders are tidied too: a stripped-out `taxes/2024/federal/` tree
        // left standing would leak the structure the encrypted index conceals.
        if !keep_source {
            shred::shred(source)?;
            self.tidy_empty_parents(source);
        }
        op.complete()
    }

    /// Decrypt a document into the vault folder. The plaintext is staged inside
    /// `.encino` and moved into place only once it matches the index digest.
    pub fn checkout(&mut self, name: &DocPath) -> Result<PathBuf> {
        let entry = self.index.get(name).cloned().ok_or_else(|| Error::NoSuchDocument(name.to_string()))?;
        let dest = self.plaintext_path(name)?;

        if dest.exists() {
            return if shred::is_regular_file(&dest) {
                Err(Error::AlreadyOpen(name.to_string()))
            } else {
                Err(Error::PathOccupied { path: dest, document: name.to_string() })
            };
        }

        let mut op = self.journal.begin(OpKind::Checkout, name, None, Some(entry.blob_id))?;
        let staging = self.vault.staging_dir().join(op.op_id());

        let result = self.materialize(&entry, &staging, &dest);
        if result.is_err() {
            let _ = shred::shred(&staging);
        }
        result?;

        op.advance(Stage::DataWritten)?;
        op.complete()?;
        Ok(dest)
    }

    fn materialize(&self, entry: &DocumentEntry, staging: &Path, dest: &Path) -> Result<()> {
        let content_key =
            crate::index::unwrap_content_key(&entry.wrapped_key, &entry.blob_id, &self.blob_wrap_key)?;
        let blob_path = entry.blob_id.path_under(&self.vault.blobs_dir());

        let mut out = shred::create_new(staging)?;
        let stats = blob::read_blob(&blob_path, &mut out, &entry.blob_id, &content_key)?;
        out.sync_all().map_err(|e| Error::io("flush", staging, e))?;
        drop(out);

        // The AEAD proves the ciphertext intact; this proves index and blob agree.
        if !entry.matches(&stats) {
            return Err(Error::CorruptData {
                path: blob_path,
                detail: format!(
                    "{} decrypted to {} bytes but the index records {}",
                    entry.path, stats.size, entry.size
                ),
            });
        }

        if let Some(parent) = dest.parent() {
            fsutil::ensure_dir(parent)?;
        }
        std::fs::rename(staging, dest).map_err(|e| Error::io("move into place", dest, e))
    }

    /// Re-encrypt a checked-out document and destroy its plaintext.
    pub fn checkin(&mut self, name: &DocPath) -> Result<CheckinOutcome> {
        let entry = self.index.get(name).cloned().ok_or_else(|| Error::NoSuchDocument(name.to_string()))?;
        let source = self.plaintext_path(name)?;
        if !shred::is_regular_file(&source) {
            return Err(Error::NotOpen(name.to_string()));
        }

        // Hashing first buys a pass over the file: an unchanged document, the common case, needs no new ciphertext.
        let stats = hash_file(&source)?;
        if entry.matches(&stats) {
            let op = self.journal.begin(OpKind::Checkin, name, None, None)?;
            shred::shred(&source)?;
            self.tidy_empty_parents(&source);
            op.complete()?;
            return Ok(CheckinOutcome::Unchanged);
        }

        let new_blob = BlobId::random();
        let mut op = self.journal.begin(OpKind::Checkin, name, Some(new_blob), Some(entry.blob_id))?;

        let content_key = Key::random();
        let blob_path = new_blob.path_under(&self.vault.blobs_dir());
        let mut file = File::open(&source).map_err(|e| Error::io("open", &source, e))?;
        let written = blob::write_blob(&mut file, &blob_path, &new_blob, &content_key)?;
        drop(file);
        op.advance(Stage::DataWritten)?;

        let modified = std::fs::metadata(&source)
            .and_then(|m| m.modified())
            .map(OffsetDateTime::from)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());

        self.index.replace(DocumentEntry {
            path: name.clone(),
            blob_id: new_blob,
            wrapped_key: crate::index::wrap_content_key(&content_key, &new_blob, &self.blob_wrap_key),
            size: written.size,
            sha256: hex::encode(written.sha256),
            modified,
            added: entry.added,
        });
        self.save_index()?;
        op.advance(Stage::IndexUpdated)?;

        // Both only once the new state is durable; the old blob is now unreachable.
        shred::remove_blob(&entry.blob_id.path_under(&self.vault.blobs_dir()))?;
        shred::shred(&source)?;
        self.tidy_empty_parents(&source);
        op.complete()?;

        Ok(CheckinOutcome::Updated)
    }

    /// Decrypt every document into `dest`, leaving the vault untouched.
    pub fn export(&self, dest: &Path) -> Result<usize> {
        fsutil::ensure_dir(dest)?;

        let mut exported = 0;
        for entry in self.index.iter() {
            let target = entry.path.resolve_under(dest)?;
            if let Some(parent) = target.parent() {
                fsutil::ensure_dir(parent)?;
            }

            let content_key =
                crate::index::unwrap_content_key(&entry.wrapped_key, &entry.blob_id, &self.blob_wrap_key)?;
            let blob_path = entry.blob_id.path_under(&self.vault.blobs_dir());

            let mut out = File::create(&target).map_err(|e| Error::io("create", &target, e))?;
            let stats = blob::read_blob(&blob_path, &mut out, &entry.blob_id, &content_key)?;
            out.sync_all().map_err(|e| Error::io("flush", &target, e))?;

            if !entry.matches(&stats) {
                return Err(Error::CorruptData {
                    path: blob_path,
                    detail: format!("{} does not match the index", entry.path),
                });
            }
            exported += 1;
        }
        Ok(exported)
    }

    /// Authenticate every stored blob against the index.
    pub fn verify(&self) -> Result<Vec<VerifyIssue>> {
        let mut issues = Vec::new();
        let mut referenced = std::collections::HashSet::new();

        for entry in self.index.iter() {
            referenced.insert(entry.blob_id);
            let blob_path = entry.blob_id.path_under(&self.vault.blobs_dir());

            if !blob_path.exists() {
                issues.push(VerifyIssue {
                    document: Some(entry.path.clone()),
                    problem: "its encrypted data is missing".into(),
                });
                continue;
            }

            let content_key = match crate::index::unwrap_content_key(
                &entry.wrapped_key,
                &entry.blob_id,
                &self.blob_wrap_key,
            ) {
                Ok(key) => key,
                Err(_) => {
                    issues.push(VerifyIssue {
                        document: Some(entry.path.clone()),
                        problem: "its stored key does not authenticate".into(),
                    });
                    continue;
                }
            };

            match blob::read_blob(&blob_path, &mut std::io::sink(), &entry.blob_id, &content_key) {
                Ok(stats) if entry.matches(&stats) => {}
                Ok(stats) => issues.push(VerifyIssue {
                    document: Some(entry.path.clone()),
                    problem: format!(
                        "it decrypts to {} bytes but the index records {}",
                        stats.size, entry.size
                    ),
                }),
                Err(e) => issues.push(VerifyIssue {
                    document: Some(entry.path.clone()),
                    problem: format!("it failed to decrypt: {e}"),
                }),
            }
        }

        for orphan in self.orphan_blobs(&referenced)? {
            issues.push(VerifyIssue {
                document: None,
                problem: format!("{orphan} is stored but no document refers to it"),
            });
        }

        Ok(issues)
    }

    /// Blob files the index does not reference.
    fn orphan_blobs(&self, referenced: &std::collections::HashSet<BlobId>) -> Result<Vec<String>> {
        let blobs_dir = self.vault.blobs_dir();
        if !blobs_dir.exists() {
            return Ok(Vec::new());
        }

        let mut orphans = Vec::new();
        let shards = std::fs::read_dir(&blobs_dir).map_err(|e| Error::io("list", &blobs_dir, e))?;
        for shard in shards {
            let shard = shard.map_err(|e| Error::io("list", &blobs_dir, e))?.path();
            if !shard.is_dir() {
                continue;
            }
            for item in std::fs::read_dir(&shard).map_err(|e| Error::io("list", &shard, e))? {
                let item = item.map_err(|e| Error::io("list", &shard, e))?;
                let name = item.file_name().to_string_lossy().into_owned();
                match BlobId::from_hex(&name) {
                    Ok(id) if !referenced.contains(&id) => orphans.push(name),
                    Ok(_) => {}
                    Err(_) => orphans.push(name),
                }
            }
        }
        orphans.sort();
        Ok(orphans)
    }

    /// Reconcile anything an interrupted run left behind. The index is the arbiter:
    /// it is replaced atomically, so it cannot be caught half-written.
    pub fn reconcile(&mut self) -> Result<Vec<RecoveryAction>> {
        let mut actions = Vec::new();

        for record in self.journal.pending()? {
            let indexed_blob = self.index.get(&record.path).map(|e| e.blob_id);

            match record.kind {
                OpKind::Add => {
                    if indexed_blob.is_none() || indexed_blob != record.new_blob {
                        // Never reached the index, so the ciphertext is unreachable.
                        if let Some(blob) = record.new_blob {
                            shred::remove_blob(&blob.path_under(&self.vault.blobs_dir()))?;
                        }
                        actions.push(RecoveryAction::DiscardedIncompleteImport(record.path.clone()));
                    }
                }

                OpKind::Checkout => {
                    // A checkout changes no vault state; only the plaintext can be partial.
                    if let (Some(entry), Ok(path)) =
                        (self.index.get(&record.path).cloned(), self.plaintext_path(&record.path))
                        && shred::is_regular_file(&path)
                        && !hash_file(&path).map(|s| entry.matches(&s)).unwrap_or(false)
                    {
                        shred::shred(&path)?;
                        actions.push(RecoveryAction::RemovedPartialCheckout(record.path.clone()));
                    }
                }

                OpKind::Checkin => {
                    if record.new_blob.is_some() && indexed_blob == record.new_blob {
                        // The index already points at the new ciphertext, so the rest is safe to finish.
                        if let Some(old) = record.old_blob {
                            shred::remove_blob(&old.path_under(&self.vault.blobs_dir()))?;
                        }
                        let path = self.plaintext_path(&record.path)?;
                        shred::shred(&path)?;
                        self.tidy_empty_parents(&path);
                        actions.push(RecoveryAction::FinishedCheckin(record.path.clone()));
                    } else if let Some(new) = record.new_blob {
                        // The index still points at the old ciphertext, so the new blob is unreachable.
                        shred::remove_blob(&new.path_under(&self.vault.blobs_dir()))?;
                        actions.push(RecoveryAction::RolledBackCheckin(record.path.clone()));
                    }
                }

                OpKind::Remove => {
                    if indexed_blob.is_none()
                        && let Some(old) = record.old_blob
                    {
                        shred::remove_blob(&old.path_under(&self.vault.blobs_dir()))?;
                        actions.push(RecoveryAction::FinishedRemoval(record.path.clone()));
                    }
                }
            }

            self.journal.clear(&record.op_id)?;
        }

        Ok(actions)
    }

    fn save_index(&self) -> Result<()> {
        self.index.save(
            &self.vault.index_path(),
            &self.vault.index_backup_path(),
            &self.index_key,
            self.vault.id(),
        )
    }

    /// Remove now-empty subfolders left behind by a check-in, stopping at the vault root.
    fn tidy_empty_parents(&self, from: &Path) {
        let root = self.vault.root();

        // Canonicalise before comparing against the root: `Path::starts_with`
        // compares components byte for byte, so an equivalent-but-differently-spelled
        // path (Windows 8.3 short names, differing case) fails containment and
        // tidying silently leaves the folder tree standing.
        let mut current = from.parent().and_then(|p| fsutil::canonical(p).ok());

        while let Some(dir) = current {
            if dir == root || !dir.starts_with(root) {
                break;
            }
            shred::remove_dir_if_empty(&dir);
            if dir.exists() {
                break;
            }
            current = dir.parent().map(Path::to_path_buf);
        }
    }
}

/// Size and digest of a file, streamed.
fn hash_file(path: &Path) -> Result<BlobStats> {
    use std::io::Read;

    let mut file = File::open(path).map_err(|e| Error::io("open", path, e))?;
    let mut digest = Sha256Stream::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;

    loop {
        let filled = file.read(&mut buffer).map_err(|e| Error::io("read", path, e))?;
        if filled == 0 {
            break;
        }
        digest.update(&buffer[..filled]);
        size += filled as u64;
    }

    Ok(BlobStats { size, sha256: digest.finish() })
}
