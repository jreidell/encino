//! Crash-recovery journal.
//!
//! One record per in-flight mutation, written before it begins and deleted
//! after it completes; a leftover record means an interrupted run.
//!
//! A record says what was attempted and which files were involved, not how far
//! it got: a stage marker can itself be stale, since the process can die between
//! a step and recording it. Recovery consults the index, which is replaced
//! atomically and is the only reliable statement of vault contents.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::blob::BlobId;
use crate::docpath::DocPath;
use crate::{Error, Result, crypto, fsutil};

/// What a journal record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpKind {
    /// Importing a document.
    Add,
    /// Decrypting a document for use.
    Checkout,
    /// Re-encrypting a document and removing its plaintext.
    Checkin,
    /// Deleting a document.
    Remove,
}

/// How far an operation had got. Advisory only — see the module note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// Nothing durable has happened yet.
    Started,
    /// Ciphertext or plaintext has been written and flushed.
    DataWritten,
    /// The index has been replaced.
    IndexUpdated,
}

/// One in-flight operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Unique identifier, and the record's filename stem.
    pub op_id: String,
    /// What was being attempted.
    pub kind: OpKind,
    /// Document involved.
    pub path: DocPath,
    /// Blob being written, if any.
    pub new_blob: Option<BlobId>,
    /// Blob being superseded, if any.
    pub old_blob: Option<BlobId>,
    /// Advisory progress marker.
    pub stage: Stage,
}

/// The journal directory.
#[derive(Debug, Clone)]
pub struct Journal {
    dir: PathBuf,
}

impl Journal {
    /// Open the journal rooted at `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Journal { dir }
    }

    /// Record the start of an operation.
    pub fn begin(
        &self,
        kind: OpKind,
        path: &DocPath,
        new_blob: Option<BlobId>,
        old_blob: Option<BlobId>,
    ) -> Result<ActiveOp> {
        let entry = JournalEntry {
            op_id: hex::encode(crypto::random_array::<8>()),
            kind,
            path: path.clone(),
            new_blob,
            old_blob,
            stage: Stage::Started,
        };

        let record = self.dir.join(format!("{}.json", entry.op_id));
        write_record(&record, &entry)?;
        Ok(ActiveOp { record, entry })
    }

    /// Every record left behind by an interrupted run.
    pub fn pending(&self) -> Result<Vec<JournalEntry>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }

        let listing = std::fs::read_dir(&self.dir).map_err(|e| Error::io("list journal", &self.dir, e))?;

        let mut entries = Vec::new();
        for item in listing {
            let item = item.map_err(|e| Error::io("list journal", &self.dir, e))?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            match std::fs::read(&path) {
                // An unparseable record is crash evidence; keeping it would block every run.
                Ok(bytes) => match serde_json::from_slice::<JournalEntry>(&bytes) {
                    Ok(entry) => entries.push(entry),
                    Err(_) => fsutil::remove_if_present(&path)?,
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::io("read journal record", &path, e)),
            }
        }

        entries.sort_by(|a, b| a.op_id.cmp(&b.op_id));
        Ok(entries)
    }

    /// Delete a record once its operation is settled.
    pub fn clear(&self, op_id: &str) -> Result<()> {
        fsutil::remove_if_present(&self.dir.join(format!("{op_id}.json")))
    }

    /// Whether any operation is outstanding.
    pub fn is_clean(&self) -> Result<bool> {
        Ok(self.pending()?.is_empty())
    }
}

/// A journal record for an operation currently underway.
///
/// Dropping this without calling [`ActiveOp::complete`] leaves the record in
/// place, so a run unwinding from an error is reconciled next time.
#[derive(Debug)]
pub struct ActiveOp {
    record: PathBuf,
    entry: JournalEntry,
}

impl ActiveOp {
    /// Update the advisory progress marker.
    pub fn advance(&mut self, stage: Stage) -> Result<()> {
        self.entry.stage = stage;
        write_record(&self.record, &self.entry)
    }

    /// Record the blob this operation is writing, once its id is known.
    pub fn set_new_blob(&mut self, blob: BlobId) -> Result<()> {
        self.entry.new_blob = Some(blob);
        write_record(&self.record, &self.entry)
    }

    /// The operation's identifier.
    pub fn op_id(&self) -> &str {
        &self.entry.op_id
    }

    /// Mark the operation settled and remove its record.
    pub fn complete(self) -> Result<()> {
        fsutil::remove_if_present(&self.record)
    }
}

fn write_record(path: &Path, entry: &JournalEntry) -> Result<()> {
    let json = serde_json::to_vec_pretty(entry).map_err(|e| Error::CorruptData {
        path: path.to_path_buf(),
        detail: format!("could not serialize a journal record: {e}"),
    })?;
    fsutil::write_atomic(path, &json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> (tempfile::TempDir, Journal) {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path().join("journal"));
        fsutil::ensure_dir(&journal.dir).unwrap();
        (dir, journal)
    }

    fn doc() -> DocPath {
        DocPath::new("taxes/w2.pdf").unwrap()
    }

    #[test]
    fn a_completed_operation_leaves_nothing_behind() {
        let (_dir, journal) = journal();
        assert!(journal.is_clean().unwrap());

        let op = journal.begin(OpKind::Add, &doc(), Some(BlobId::random()), None).unwrap();
        assert!(!journal.is_clean().unwrap());

        op.complete().unwrap();
        assert!(journal.is_clean().unwrap());
    }

    #[test]
    fn an_abandoned_operation_is_still_pending() {
        let (_dir, journal) = journal();
        let blob = BlobId::random();

        // Dropped without completing, as an interrupted process would.
        {
            let _op = journal.begin(OpKind::Checkin, &doc(), Some(blob), None).unwrap();
        }

        let pending = journal.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, OpKind::Checkin);
        assert_eq!(pending[0].path, doc());
        assert_eq!(pending[0].new_blob, Some(blob));
    }

    #[test]
    fn records_survive_being_reread_from_disk() {
        let (_dir, journal) = journal();
        let (new, old) = (BlobId::random(), BlobId::random());

        let mut op = journal.begin(OpKind::Checkin, &doc(), Some(new), Some(old)).unwrap();
        op.advance(Stage::DataWritten).unwrap();

        let pending = journal.pending().unwrap();
        assert_eq!(pending[0].stage, Stage::DataWritten);
        assert_eq!(pending[0].new_blob, Some(new));
        assert_eq!(pending[0].old_blob, Some(old));
    }

    #[test]
    fn a_blob_id_can_be_recorded_after_the_operation_starts() {
        let (_dir, journal) = journal();
        let mut op = journal.begin(OpKind::Add, &doc(), None, None).unwrap();

        let blob = BlobId::random();
        op.set_new_blob(blob).unwrap();

        assert_eq!(journal.pending().unwrap()[0].new_blob, Some(blob));
    }

    #[test]
    fn several_operations_are_tracked_independently() {
        let (_dir, journal) = journal();

        let first = journal.begin(OpKind::Add, &DocPath::new("a.pdf").unwrap(), None, None).unwrap();
        let _second = journal.begin(OpKind::Add, &DocPath::new("b.pdf").unwrap(), None, None).unwrap();

        let id = first.op_id().to_string();
        first.complete().unwrap();

        let pending = journal.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0].op_id, id);
    }

    #[test]
    fn a_record_torn_mid_write_is_discarded_rather_than_blocking_recovery() {
        let (_dir, journal) = journal();
        std::fs::write(journal.dir.join("torn.json"), b"{ \"op_id\": ").unwrap();

        // Unparseable means the crash happened while writing the record, before work began.
        assert!(journal.pending().unwrap().is_empty());
        assert!(!journal.dir.join("torn.json").exists());
    }

    #[test]
    fn unrelated_files_in_the_journal_directory_are_ignored() {
        let (_dir, journal) = journal();
        std::fs::write(journal.dir.join("notes.txt"), b"unrelated").unwrap();

        assert!(journal.pending().unwrap().is_empty());
        assert!(journal.dir.join("notes.txt").exists());
    }

    #[test]
    fn an_absent_journal_directory_reads_as_clean() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path().join("never-created"));
        assert!(journal.is_clean().unwrap());
    }

    #[test]
    fn clearing_is_idempotent() {
        let (_dir, journal) = journal();
        let op = journal.begin(OpKind::Remove, &doc(), None, Some(BlobId::random())).unwrap();
        let id = op.op_id().to_string();
        drop(op);

        journal.clear(&id).unwrap();
        journal.clear(&id).unwrap();
        assert!(journal.is_clean().unwrap());
    }
}
