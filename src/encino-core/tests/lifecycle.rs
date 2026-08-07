//! End-to-end tests over a real vault on a real filesystem.
//!
//! The crash-recovery cases construct the exact on-disk state an interrupted run
//! would leave — a journal record plus whatever files had been written — and then
//! open a session, which is the only thing that triggers reconciliation. That is
//! a faithful reproduction: nothing about recovery depends on the process that
//! crashed still being around to tell us anything.

use std::path::{Path, PathBuf};

use encino_core::blob::{self, BlobId};
use encino_core::crypto::{self, Key};
use encino_core::journal::{Journal, OpKind};
use encino_core::session::{CheckinOutcome, RecoveryAction};
use encino_core::{DocPath, Error, KdfConfig, Session, Vault};

const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        std::fs::create_dir_all(&root).unwrap();
        Vault::init(&root, PASSPHRASE, KdfConfig::testing()).unwrap();
        Fixture { _dir: dir, root }
    }

    fn session(&self) -> Session {
        Session::unlock(Vault::open(&self.root).unwrap(), PASSPHRASE).unwrap()
    }

    fn master(&self) -> Key {
        Vault::open(&self.root).unwrap().unlock(PASSPHRASE).unwrap()
    }

    /// Create a loose file in the work area, as a user would before importing.
    fn stage_file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn add(&self, name: &str, contents: &[u8]) {
        let source = self.stage_file(name, contents);
        let mut session = self.session();
        session.add(&source, &DocPath::new(name).unwrap(), false).unwrap();
    }

    fn journal(&self) -> Journal {
        Journal::new(Vault::open(&self.root).unwrap().journal_dir())
    }

    fn blobs_dir(&self) -> PathBuf {
        Vault::open(&self.root).unwrap().blobs_dir()
    }
}

/// Everything in the vault folder other than `.encino`.
fn work_area_contents(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        for item in std::fs::read_dir(dir).unwrap().flatten() {
            let path = item.path();
            if path.file_name().unwrap() == ".encino" {
                continue;
            }
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                out.push(path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// Every byte stored under `.encino`, for leak checking.
fn all_stored_bytes(root: &Path) -> Vec<u8> {
    fn walk(dir: &Path, out: &mut Vec<u8>) {
        for item in std::fs::read_dir(dir).unwrap().flatten() {
            let path = item.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.extend_from_slice(&std::fs::read(&path).unwrap_or_default());
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join(".encino"), &mut out);
    out
}

#[test]
fn a_document_survives_being_imported_and_checked_out_again() {
    let fixture = Fixture::new();
    let contents = b"Chase statement, closing balance $4,102.55";
    fixture.add("chase-statement.pdf", contents);

    // Importing destroys the original: the work area is empty once locked.
    assert!(work_area_contents(&fixture.root).is_empty());

    let mut session = fixture.session();
    let name = DocPath::new("chase-statement.pdf").unwrap();
    let path = session.checkout(&name).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), contents);
    assert!(session.is_open(&name));

    assert_eq!(session.checkin(&name).unwrap(), CheckinOutcome::Unchanged);
    assert!(!path.exists());
    assert!(work_area_contents(&fixture.root).is_empty());
}

#[test]
fn filenames_and_contents_are_absent_from_disk_when_locked() {
    let fixture = Fixture::new();
    fixture.add("taxes/2024/w2-acme-corp.pdf", b"Wages: 120000. SSN 123-45-6789");
    fixture.add("mortgage-payoff.pdf", b"Principal remaining 210,340.11");

    let stored = String::from_utf8_lossy(&all_stored_bytes(&fixture.root)).to_lowercase();
    for secret in
        ["w2-acme-corp", "taxes", "mortgage", "payoff", "123-45-6789", "120000", "210,340.11", ".pdf"]
    {
        assert!(!stored.contains(secret), "{secret:?} is recoverable from disk without the passphrase");
    }

    // The directory structure must not survive either — the blob store is flat.
    assert!(!fixture.root.join("taxes").exists());
}

#[test]
fn an_edited_document_is_re_encrypted_on_check_in() {
    let fixture = Fixture::new();
    fixture.add("notes.txt", b"original contents");

    let name = DocPath::new("notes.txt").unwrap();
    let mut session = fixture.session();
    let original_blob = session.get(&name).unwrap().blob_id;

    let path = session.checkout(&name).unwrap();
    std::fs::write(&path, b"contents after editing, rather longer than before").unwrap();
    assert_eq!(session.checkin(&name).unwrap(), CheckinOutcome::Updated);
    // A session holds the vault lock, so it must be let go before another can
    // be opened. Shadowing the binding would not do it — the first session
    // would live until the end of the function.
    drop(session);

    let mut session = fixture.session();
    let entry = session.get(&name).unwrap().clone();
    assert_ne!(entry.blob_id, original_blob, "an edited document must not reuse its blob");

    let reopened = session.checkout(&name).unwrap();
    assert_eq!(std::fs::read(&reopened).unwrap(), b"contents after editing, rather longer than before");

    // The superseded ciphertext must be gone, not merely unreferenced.
    assert!(!original_blob.path_under(&fixture.blobs_dir()).exists());
}

#[test]
fn an_unchanged_document_keeps_its_ciphertext() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"unchanging contents");

    let name = DocPath::new("statement.pdf").unwrap();
    let mut session = fixture.session();
    let original_blob = session.get(&name).unwrap().blob_id;

    session.checkout(&name).unwrap();
    assert_eq!(session.checkin(&name).unwrap(), CheckinOutcome::Unchanged);
    drop(session);

    // Reading a statement and closing it again should cost no re-encryption.
    assert_eq!(fixture.session().get(&name).unwrap().blob_id, original_blob);
}

#[test]
fn subfolder_structure_is_restored_on_checkout_and_tidied_on_check_in() {
    let fixture = Fixture::new();
    fixture.add("taxes/2024/federal/w2.pdf", b"wages");

    let name = DocPath::new("taxes/2024/federal/w2.pdf").unwrap();
    let mut session = fixture.session();
    let path = session.checkout(&name).unwrap();

    assert!(path.ends_with("w2.pdf"));
    assert_eq!(work_area_contents(&fixture.root), vec!["taxes/2024/federal/w2.pdf"]);

    session.checkin(&name).unwrap();
    assert!(work_area_contents(&fixture.root).is_empty());
    assert!(!fixture.root.join("taxes").exists(), "empty subfolders should not be left behind");
}

#[test]
fn a_vault_opened_by_an_awkwardly_spelled_path_still_tracks_its_own_files() {
    // Regression: the vault root and the paths handed to `add` were canonicalized
    // differently, so `strip_prefix` and `starts_with` both silently failed. The
    // symptoms were a document filed under its bare filename instead of its
    // folder path, and empty directories left standing in the work area — which
    // leaks exactly the structure the index exists to hide.
    let fixture = Fixture::new();

    let roundabout = fixture.root.join("taxes").join("..");
    std::fs::create_dir_all(fixture.root.join("taxes")).unwrap();

    let source = fixture.stage_file("taxes/2024/w2.pdf", b"wages");
    let vault = Vault::open(&roundabout).unwrap();
    let mut session = Session::from_master(vault, &fixture.master()).unwrap();

    let name = DocPath::from_relative(Path::new("taxes/2024/w2.pdf")).unwrap();
    session.add(&source, &name, false).unwrap();

    assert!(session.get(&name).is_some(), "the document should keep its folder path");
    assert!(work_area_contents(&fixture.root).is_empty());
    assert!(!fixture.root.join("taxes").exists(), "empty folders must not survive an import");
}

#[test]
fn documents_of_awkward_sizes_round_trip_exactly() {
    let fixture = Fixture::new();
    let sizes = [0usize, 1, 4096, blob::CHUNK_SIZE - 1, blob::CHUNK_SIZE, blob::CHUNK_SIZE + 1];

    for (i, size) in sizes.iter().enumerate() {
        let contents: Vec<u8> = (0..*size).map(|n| (n % 251) as u8).collect();
        fixture.add(&format!("doc-{i}.bin"), &contents);
    }

    let mut session = fixture.session();
    for (i, size) in sizes.iter().enumerate() {
        let name = DocPath::new(&format!("doc-{i}.bin")).unwrap();
        let path = session.checkout(&name).unwrap();
        let expected: Vec<u8> = (0..*size).map(|n| (n % 251) as u8).collect();
        assert_eq!(std::fs::read(&path).unwrap(), expected, "document of {size} bytes did not round trip");
        session.checkin(&name).unwrap();
    }
}

#[test]
fn a_document_cannot_be_checked_out_twice_or_added_twice() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"contents");

    let name = DocPath::new("statement.pdf").unwrap();
    let mut session = fixture.session();
    session.checkout(&name).unwrap();

    assert!(matches!(session.checkout(&name), Err(Error::AlreadyOpen(_))));

    let another = fixture.stage_file("elsewhere.pdf", b"different contents");
    assert!(matches!(session.add(&another, &name, true), Err(Error::DuplicateDocument(_))));
}

#[test]
fn checking_in_a_document_that_is_not_open_is_refused() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"contents");

    let mut session = fixture.session();
    let name = DocPath::new("statement.pdf").unwrap();
    assert!(matches!(session.checkin(&name), Err(Error::NotOpen(_))));

    let missing = DocPath::new("never-existed.pdf").unwrap();
    assert!(matches!(session.checkout(&missing), Err(Error::NoSuchDocument(_))));
}

#[test]
fn the_wrong_passphrase_opens_nothing() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"contents");

    let vault = Vault::open(&fixture.root).unwrap();
    assert!(matches!(Session::unlock(vault, "not the passphrase"), Err(Error::AuthenticationFailed)));
}

#[test]
fn verify_passes_on_a_healthy_vault_and_reports_tampering() {
    let fixture = Fixture::new();
    fixture.add("a.pdf", b"first document");
    fixture.add("b.pdf", b"second document");

    assert!(fixture.session().verify().unwrap().is_empty());

    // Flip a byte of ciphertext, well past the header.
    let entry = fixture.session().get(&DocPath::new("a.pdf").unwrap()).unwrap().clone();
    let blob_path = entry.blob_id.path_under(&fixture.blobs_dir());
    let mut raw = std::fs::read(&blob_path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    std::fs::write(&blob_path, &raw).unwrap();

    // Rewriting the file moved its mtime, which `verify` now reports in its own
    // right. Put it back so this test stays about ciphertext tampering; the
    // timestamp check has a test of its own.
    let stamp = filetime::FileTime::from_unix_time(encino_core::fsutil::NORMALIZED_UNIX_TIME, 0);
    filetime::set_file_times(&blob_path, stamp, stamp).unwrap();

    let issues = fixture.session().verify().unwrap();
    assert_eq!(issues.len(), 1, "expected only the tampering issue, got {issues:?}");
    assert_eq!(issues[0].document.as_ref().unwrap().as_str(), "a.pdf");
}

#[test]
fn verify_reports_missing_and_orphaned_ciphertext() {
    let fixture = Fixture::new();
    fixture.add("a.pdf", b"first document");

    let entry = fixture.session().get(&DocPath::new("a.pdf").unwrap()).unwrap().clone();
    std::fs::remove_file(entry.blob_id.path_under(&fixture.blobs_dir())).unwrap();

    let orphan = BlobId::random();
    blob::write_blob(
        &mut &b"nobody refers to this"[..],
        &orphan.path_under(&fixture.blobs_dir()),
        &orphan,
        &Key::random(),
    )
    .unwrap();

    let issues = fixture.session().verify().unwrap();
    assert_eq!(issues.len(), 2);
    assert!(issues.iter().any(|i| i.document.is_some() && i.problem.contains("missing")));
    assert!(issues.iter().any(|i| i.document.is_none() && i.problem.contains("no document refers")));
}

#[test]
fn a_name_colliding_only_by_case_is_refused_before_any_ciphertext_is_written() {
    let fixture = Fixture::new();
    fixture.add("w2.pdf", b"wages and withholding");
    let before = stored_blobs(&fixture);

    let source = fixture.stage_file("W2.pdf", b"a different document entirely");
    let mut session = fixture.session();
    let refused = session.add(&source, &DocPath::new("W2.pdf").unwrap(), false);

    assert!(matches!(refused, Err(Error::DuplicateDocument(_))), "got {refused:?}");

    // The refusal used to happen inside the index, by which point a blob and a
    // journal record already existed and the next session had to reconcile them
    // away. Nothing should have been written at all.
    assert_eq!(stored_blobs(&fixture), before, "a blob was written for a document that was refused");
    assert!(fixture.journal().is_clean().unwrap(), "a journal record was left behind by a refused import");

    // And the original is untouched, since nothing was imported to replace it.
    assert!(source.exists(), "the source of a refused import must not be shredded");
}

/// How many blob files the store holds, across every shard.
fn stored_blobs(fixture: &Fixture) -> usize {
    let root = fixture.blobs_dir();
    std::fs::read_dir(&root)
        .map(|shards| {
            shards
                .flatten()
                .filter(|shard| shard.path().is_dir())
                .filter_map(|shard| std::fs::read_dir(shard.path()).ok())
                .map(|files| files.flatten().count())
                .sum()
        })
        .unwrap_or(0)
}

#[test]
fn verify_reports_a_blob_left_carrying_a_real_timestamp() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"closing balance 4102.55");

    let name = DocPath::new("statement.pdf").unwrap();
    let entry = fixture.session().get(&name).unwrap().clone();
    let blob = entry.blob_id.path_under(&fixture.blobs_dir());

    // Exactly what a filesystem that quietly refused the timestamp set would
    // leave behind: a blob naming when its document last changed. Setting it is
    // best-effort, so without this check nothing would ever say so.
    let real = filetime::FileTime::from_unix_time(1_786_000_000, 0);
    filetime::set_file_times(&blob, real, real).unwrap();

    let issues = fixture.session().verify().unwrap();
    assert_eq!(issues.len(), 1, "expected exactly one issue, got {issues:?}");
    assert_eq!(issues[0].document.as_ref().unwrap(), &name);
    assert!(
        issues[0].problem.contains("timestamp"),
        "the report should name the problem plainly: {}",
        issues[0].problem
    );
}

#[test]
fn blob_timestamps_do_not_reveal_which_document_changed() {
    let fixture = Fixture::new();
    fixture.add("a.pdf", b"first document");
    fixture.add("b.pdf", b"second document");
    fixture.add("c.pdf", b"third document");

    // Edit exactly one, which is what made the leak legible: two blobs shared a
    // timestamp and the edited one stood seconds apart.
    let name = DocPath::new("a.pdf").unwrap();
    let mut session = fixture.session();
    let path = session.checkout(&name).unwrap();
    std::fs::write(&path, b"first document, after editing").unwrap();
    session.checkin(&name).unwrap();
    drop(session);

    // The superseded blob's shard must not outlive it. An emptied shard left
    // standing records that a document was once there, and they accumulate with
    // every edit.
    let shards: Vec<_> = std::fs::read_dir(fixture.blobs_dir())
        .unwrap()
        .flatten()
        .map(|s| s.path())
        .filter(|s| s.is_dir())
        .collect();
    for shard in &shards {
        assert!(
            std::fs::read_dir(shard).unwrap().next().is_some(),
            "{shard:?} is an empty shard left behind by a check-in"
        );
    }

    let times = blob_mtimes(&fixture.blobs_dir());
    assert_eq!(times.len(), 3, "expected one blob per document, got {}", times.len());

    let distinct: std::collections::HashSet<(i64, u32)> = times.into_iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "blob mtimes differ, which says which document changed and when: {distinct:?}"
    );
    assert_eq!(
        distinct.into_iter().next().unwrap(),
        (encino_core::fsutil::NORMALIZED_UNIX_TIME, 0),
        "blobs agree on a timestamp, but it is a real one rather than the fixed one"
    );
}

/// Modification time of every blob in the store, to full precision.
///
/// Seconds alone would make the assertion above vacuous: this test writes and
/// edits well inside one second, so truncated timestamps would agree whether or
/// not anything normalized them.
fn blob_mtimes(blobs_dir: &Path) -> Vec<(i64, u32)> {
    let mut out = Vec::new();
    for shard in std::fs::read_dir(blobs_dir).unwrap().flatten() {
        if !shard.path().is_dir() {
            continue;
        }
        for blob in std::fs::read_dir(shard.path()).unwrap().flatten() {
            let metadata = std::fs::metadata(blob.path()).unwrap();
            let at = filetime::FileTime::from_last_modification_time(&metadata);
            out.push((at.unix_seconds(), at.nanoseconds()));
        }
    }
    out
}

#[test]
fn export_reproduces_the_original_tree() {
    let fixture = Fixture::new();
    fixture.add("taxes/2024/w2.pdf", b"wages and withholding");
    fixture.add("statement.pdf", b"closing balance");
    fixture.add("scans/passport.jpg", b"\xff\xd8\xff\xe0 binary-ish content");

    let destination = fixture.root.parent().unwrap().join("exported");
    assert_eq!(fixture.session().export(&destination).unwrap(), 3);

    assert_eq!(std::fs::read(destination.join("taxes/2024/w2.pdf")).unwrap(), b"wages and withholding");
    assert_eq!(std::fs::read(destination.join("statement.pdf")).unwrap(), b"closing balance");
    assert_eq!(
        std::fs::read(destination.join("scans/passport.jpg")).unwrap(),
        b"\xff\xd8\xff\xe0 binary-ish content"
    );

    // Exporting must not disturb the vault.
    assert!(fixture.session().verify().unwrap().is_empty());
    assert!(work_area_contents(&fixture.root).is_empty());
}

#[test]
fn a_recovery_code_reaches_the_documents_after_the_passphrase_is_lost() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    std::fs::create_dir_all(&root).unwrap();

    let (_, recovery) = Vault::init(&root, PASSPHRASE, KdfConfig::testing()).unwrap();

    let source = root.join("statement.pdf");
    std::fs::write(&source, b"closing balance 4102.55").unwrap();
    let mut session = Session::unlock(Vault::open(&root).unwrap(), PASSPHRASE).unwrap();
    session.add(&source, &DocPath::new("statement.pdf").unwrap(), false).unwrap();
    drop(session);

    // The passphrase is now forgotten. The recovery code is the only way in, and
    // an untested recovery path is the same as no recovery path.
    let mut recovered = Session::recover_with(Vault::open(&root).unwrap(), &recovery).unwrap();
    let name = DocPath::new("statement.pdf").unwrap();
    let path = recovered.checkout(&name).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"closing balance 4102.55");
}

// ---------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------

#[test]
fn an_import_interrupted_before_the_index_was_written_is_discarded() {
    let fixture = Fixture::new();

    // The state a crash between "blob written" and "index saved" leaves: a
    // complete blob that nothing refers to, and a journal record naming it.
    let orphan = BlobId::random();
    blob::write_blob(
        &mut &b"a document that never made it"[..],
        &orphan.path_under(&fixture.blobs_dir()),
        &orphan,
        &Key::random(),
    )
    .unwrap();
    let name = DocPath::new("interrupted.pdf").unwrap();
    std::mem::forget(fixture.journal().begin(OpKind::Add, &name, Some(orphan), None).unwrap());

    let session = fixture.session();

    assert!(session.get(&name).is_none());
    assert!(!orphan.path_under(&fixture.blobs_dir()).exists(), "orphaned ciphertext should be cleaned up");
    assert!(fixture.journal().is_clean().unwrap());
    assert!(session.verify().unwrap().is_empty());
}

#[test]
fn a_check_in_interrupted_after_the_index_was_written_is_carried_to_completion() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"original contents");

    let name = DocPath::new("statement.pdf").unwrap();
    let mut session = fixture.session();
    let old_blob = session.get(&name).unwrap().blob_id;
    let path = session.checkout(&name).unwrap();
    std::fs::write(&path, b"edited contents").unwrap();
    session.checkin(&name).unwrap();
    drop(session);

    let new_blob = fixture.session().get(&name).unwrap().blob_id;

    // Rewind to the moment after the index was replaced but before the old blob
    // was removed and the plaintext shredded: both still present.
    std::fs::write(&path, b"edited contents").unwrap();
    blob::write_blob(
        &mut &b"stand-in for the superseded ciphertext"[..],
        &old_blob.path_under(&fixture.blobs_dir()),
        &old_blob,
        &Key::random(),
    )
    .unwrap();
    std::mem::forget(
        fixture.journal().begin(OpKind::Checkin, &name, Some(new_blob), Some(old_blob)).unwrap(),
    );

    let session = fixture.session();

    // The index already reflected the new state, so recovery finishes the job
    // rather than undoing it.
    assert!(!path.exists(), "the plaintext should have been shredded");
    assert!(!old_blob.path_under(&fixture.blobs_dir()).exists(), "the old blob should have been removed");
    assert_eq!(session.get(&name).unwrap().blob_id, new_blob);
    assert!(fixture.journal().is_clean().unwrap());
}

#[test]
fn a_check_in_interrupted_before_the_index_was_written_is_rolled_back() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"original contents");

    let name = DocPath::new("statement.pdf").unwrap();
    let mut session = fixture.session();
    let current_blob = session.get(&name).unwrap().blob_id;
    let path = session.checkout(&name).unwrap();
    std::fs::write(&path, b"edited but not yet committed").unwrap();
    drop(session);

    // A new blob was written, but the index still points at the old one.
    let abandoned = BlobId::random();
    blob::write_blob(
        &mut &b"edited but not yet committed"[..],
        &abandoned.path_under(&fixture.blobs_dir()),
        &abandoned,
        &Key::random(),
    )
    .unwrap();
    std::mem::forget(
        fixture.journal().begin(OpKind::Checkin, &name, Some(abandoned), Some(current_blob)).unwrap(),
    );

    let session = fixture.session();

    // Nothing durable had changed, so the document stays open with its edits
    // intact and the unreachable blob is discarded. Losing the user's edits here
    // would be far worse than leaving the document checked out.
    assert!(path.exists(), "the document should still be open");
    assert_eq!(std::fs::read(&path).unwrap(), b"edited but not yet committed");
    assert!(!abandoned.path_under(&fixture.blobs_dir()).exists());
    assert_eq!(session.get(&name).unwrap().blob_id, current_blob);
    assert!(fixture.journal().is_clean().unwrap());
}

#[test]
fn a_partially_written_checkout_is_destroyed_rather_than_left_looking_whole() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"the complete and correct contents of this document");

    let name = DocPath::new("statement.pdf").unwrap();

    // A truncated plaintext file, as an interrupted decrypt would leave.
    let path = fixture.root.join("statement.pdf");
    std::fs::write(&path, b"the complete and cor").unwrap();
    std::mem::forget(fixture.journal().begin(OpKind::Checkout, &name, None, None).unwrap());

    let mut session = fixture.session();

    assert!(!path.exists(), "a partial document must not be left in the work area");
    assert!(fixture.journal().is_clean().unwrap());

    // And the real document is still intact.
    let reopened = session.checkout(&name).unwrap();
    assert_eq!(std::fs::read(&reopened).unwrap(), b"the complete and correct contents of this document");
}

#[test]
fn a_complete_checkout_interrupted_before_its_record_was_cleared_is_left_alone() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"contents that decrypted fully");

    let name = DocPath::new("statement.pdf").unwrap();
    let mut session = fixture.session();
    let path = session.checkout(&name).unwrap();
    drop(session);

    // The plaintext is complete; only the journal record was never removed.
    std::mem::forget(fixture.journal().begin(OpKind::Checkout, &name, None, None).unwrap());

    let session = fixture.session();

    assert!(path.exists(), "a complete checkout must not be thrown away");
    assert_eq!(std::fs::read(&path).unwrap(), b"contents that decrypted fully");
    assert!(session.is_open(&name));
    assert!(fixture.journal().is_clean().unwrap());
}

#[test]
fn recovery_reports_what_it_did() {
    let fixture = Fixture::new();

    let orphan = BlobId::random();
    blob::write_blob(
        &mut &b"never indexed"[..],
        &orphan.path_under(&fixture.blobs_dir()),
        &orphan,
        &Key::random(),
    )
    .unwrap();
    let name = DocPath::new("interrupted.pdf").unwrap();
    std::mem::forget(fixture.journal().begin(OpKind::Add, &name, Some(orphan), None).unwrap());

    let vault = Vault::open(&fixture.root).unwrap();
    let mut session = Session::from_master(vault, &fixture.master()).unwrap();

    // The session already reconciled on open, so a second pass finds nothing.
    assert!(session.reconcile().unwrap().is_empty());

    // Re-stage the same situation to observe the report itself.
    blob::write_blob(
        &mut &b"never indexed"[..],
        &orphan.path_under(&fixture.blobs_dir()),
        &orphan,
        &Key::random(),
    )
    .unwrap();
    std::mem::forget(fixture.journal().begin(OpKind::Add, &name, Some(orphan), None).unwrap());

    let actions = session.reconcile().unwrap();
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], RecoveryAction::DiscardedIncompleteImport(_)));
    assert!(actions[0].to_string().contains("interrupted.pdf"));
}

#[test]
fn a_deleted_index_falls_back_to_the_backup_generation() {
    let fixture = Fixture::new();
    fixture.add("first.pdf", b"first document");
    fixture.add("second.pdf", b"second document");

    let vault = Vault::open(&fixture.root).unwrap();
    std::fs::remove_file(vault.index_path()).unwrap();

    // The backup is one generation behind, so the most recent import is gone —
    // but the vault opens and the rest of the documents are reachable, which is
    // the point of keeping it.
    let session = fixture.session();
    assert!(session.get(&DocPath::new("first.pdf").unwrap()).is_some());
}

#[test]
fn a_vault_with_no_readable_index_at_all_refuses_to_open() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"contents");

    let vault = Vault::open(&fixture.root).unwrap();
    std::fs::write(vault.index_path(), b"destroyed").unwrap();
    std::fs::write(vault.index_backup_path(), b"also destroyed").unwrap();

    // Presenting a vault full of documents as empty would be far worse than
    // failing loudly.
    assert!(Session::unlock(Vault::open(&fixture.root).unwrap(), PASSPHRASE).is_err());
}

#[test]
fn a_second_session_is_refused_rather_than_allowed_to_destroy_the_first_ones_work() {
    // Before the vault lock existed, this scenario silently and permanently
    // destroyed a document. Index saves are read-modify-write, so the second
    // session's save discarded the first's entry — and because each document's
    // content key lives inside its index entry, discarding the entry destroyed
    // the only copy of that key. The blob became undecryptable noise and the
    // original had already been shredded.
    //
    // A vault on a network share invites exactly this: two machines, one folder.
    let fixture = Fixture::new();
    fixture.add("first.pdf", b"first");

    let mut held = fixture.session();

    // `Session` has no `Debug` on purpose — it holds key material — so unwrap
    // the outcome by hand rather than formatting it.
    let refusal = match Session::from_master(Vault::open(&fixture.root).unwrap(), &fixture.master()) {
        Ok(_) => panic!("a second session opened while the vault was already held"),
        Err(e) => e,
    };
    assert!(matches!(refusal, Error::VaultInUse { .. }), "unexpected error: {refusal}");

    // The refusal must be actionable rather than a bare failure.
    let message = refusal.to_string();
    assert!(message.contains("in use"), "unhelpful refusal: {message}");

    // The holder is unaffected and can still work.
    let source = fixture.stage_file("second.pdf", b"second");
    held.add(&source, &DocPath::new("second.pdf").unwrap(), false).unwrap();
    drop(held);

    // Once released, the vault opens normally with both documents intact.
    let after = fixture.session();
    assert_eq!(after.len(), 2);
    assert!(after.get(&DocPath::new("first.pdf").unwrap()).is_some());
    assert!(after.get(&DocPath::new("second.pdf").unwrap()).is_some());
    assert!(after.verify().unwrap().is_empty(), "no orphaned or unreachable ciphertext");
}

#[test]
fn a_vault_left_locked_by_a_killed_process_is_not_stuck() {
    // The lock is a held file handle, not the presence of a file, so a process
    // that dies without tidying up leaves nothing to clear. Without that
    // property a crash on a network share would strand the vault behind a lock
    // nobody holds, and the only escape would be a --force flag that is far more
    // dangerous than the problem it solves.
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"contents");

    let vault = Vault::open(&fixture.root).unwrap();
    std::fs::write(vault.lock_path(), br#"{"machine":"gone","pid":999999,"since":"2026-01-01T00:00:00Z"}"#)
        .unwrap();

    let session = fixture.session();
    assert_eq!(session.len(), 1);
}

#[test]
fn the_master_key_is_never_written_to_disk() {
    let fixture = Fixture::new();
    fixture.add("statement.pdf", b"contents");

    let master = fixture.master();
    let stored = all_stored_bytes(&fixture.root);

    let key_hex = hex::encode(master.expose());
    let key_b64 = crypto::b64::encode(master.expose());

    assert!(!String::from_utf8_lossy(&stored).contains(&key_hex));
    assert!(!String::from_utf8_lossy(&stored).contains(&key_b64));
    assert!(!stored.windows(32).any(|w| w == master.expose()), "the raw master key bytes appear on disk");
}

#[cfg(windows)]
#[test]
fn folders_are_tidied_even_when_the_source_is_spelled_differently() {
    // Regression, found by CI on a Windows runner rather than by any local run.
    //
    // `tidy_empty_parents` compared the source's parent against the vault root
    // with `Path::starts_with`, which compares components byte for byte. Any
    // equivalent-but-differently-spelled path therefore failed the containment
    // check and tidying silently did nothing, leaving the folder tree standing
    // in the work area — the exact structure the encrypted index exists to hide.
    //
    // GitHub's Windows runners expose this because their temporary directory is
    // an 8.3 short name (`C:\Users\RUNNER~1\…` for `runneradmin`), which no
    // developer machine here happened to use. Differing case reproduces the same
    // class of failure portably, which is what this test does.
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.root.join("taxes").join("2024")).unwrap();
    std::fs::write(fixture.root.join("taxes").join("2024").join("w2.pdf"), b"wages").unwrap();

    let oddly_spelled = PathBuf::from(fixture.root.to_string_lossy().to_uppercase())
        .join("taxes")
        .join("2024")
        .join("w2.pdf");

    let mut session = fixture.session();
    session.add(&oddly_spelled, &DocPath::new("taxes/2024/w2.pdf").unwrap(), false).unwrap();
    drop(session);

    assert!(work_area_contents(&fixture.root).is_empty());
    assert!(!fixture.root.join("taxes").exists(), "empty folders survived — structure leaked");
}
