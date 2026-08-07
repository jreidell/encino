# Blob Timestamp Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stamp every blob file and blob-store directory with a fixed timestamp, so the filesystem stops revealing when each document last changed.

**Architecture:** A single best-effort helper in `encino-core`'s `fsutil` sets both mtime and atime to a constant. It is called from the two places that disturb blob-store timestamps: `blob::write_blob` (the blob, its shard, and `blobs/`) and `shred::remove_blob` (the shard, since deletion bumps it too). `index.enc` and `vault.json` are deliberately untouched.

**Tech Stack:** Rust 2024, `filetime` 0.2 (new), existing `tempfile` for tests.

**Spec:** `docs/superpowers/specs/2026-08-07-blob-timestamp-normalization-design.md`

## Global Constraints

- `encino-core` is `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]` — every new public item needs a doc comment, and no `unsafe` may be introduced.
- The normalized timestamp is exactly `2001-01-01T00:00:00Z` = **978307200** Unix seconds.
- Normalization is **best-effort**: a failure to set times must never fail an import or check-in.
- **Never normalize `index.enc` or `vault.json`.** They are replaced in place, keeping their names, so a backup tool that decides from name/size/mtime could silently skip a changed index — the one file whose loss loses every document.
- No `format_version` bump. Timestamps are not part of the on-disk format.
- Do not set `RUSTFLAGS`; it replaces `.cargo/config.toml` rather than merging.
- "Done" means all four pass on Windows **and** Linux: `cargo build --release`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`.
- Linux is tested from Windows via WSL with `CARGO_TARGET_DIR` outside the mount:
  `wsl.exe -e bash -c 'source $HOME/.cargo/env && cd /mnt/e/Projects/encino && CARGO_TARGET_DIR=/tmp/enc cargo test --workspace'`

---

### Task 1: The dependency and the normalize helper

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`)
- Modify: `src/encino-core/Cargo.toml` (`[dependencies]`)
- Modify: `src/encino-core/src/fsutil.rs`
- Test: `src/encino-core/src/fsutil.rs` (inline `mod tests`)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub const encino_core::fsutil::NORMALIZED_UNIX_TIME: i64` and `pub fn encino_core::fsutil::normalize_times(path: &Path)` — takes any file or directory path, returns nothing, never fails.

- [ ] **Step 1: Add the dependency**

In workspace `Cargo.toml`, under `[workspace.dependencies]`, after the `hex`/`base64` group:

```toml
# Setting file times has no std API. `filetime` adds exactly one crate to the
# tree — its only dependencies, cfg-if and libc, are already present, and it
# carries its own Win32 externs rather than pulling windows-sys. The alternative
# was hand-rolled FFI inside the crate that holds all the cryptography, at the
# cost of its `forbid(unsafe_code)`.
filetime = "0.2"
```

In `src/encino-core/Cargo.toml`, under `[dependencies]`, after `base64.workspace = true`:

```toml
filetime.workspace = true
```

- [ ] **Step 2: Write the failing test**

Append to the `mod tests` block at the foot of `src/encino-core/src/fsutil.rs`:

```rust
    #[test]
    fn normalizing_sets_a_fixed_time_on_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blob");
        std::fs::write(&file, b"contents").unwrap();

        normalize_times(&file);
        normalize_times(dir.path());

        for path in [&file, &dir.path().to_path_buf()] {
            let stamped = filetime::FileTime::from_last_modification_time(
                &std::fs::metadata(path).unwrap(),
            );
            assert_eq!(
                stamped.unix_seconds(),
                NORMALIZED_UNIX_TIME,
                "{path:?} did not take the normalized time"
            );
        }
    }

    #[test]
    fn normalizing_a_path_that_is_not_there_is_silent() {
        // Best-effort by design: a filesystem that refuses must not fail an import.
        let dir = tempfile::tempdir().unwrap();
        normalize_times(&dir.path().join("never-existed"));
    }
```

- [ ] **Step 3: Run the test and watch it fail**

Run: `cargo test -p encino-core fsutil::tests::normalizing`
Expected: FAIL to compile — `cannot find function normalize_times` and `cannot find value NORMALIZED_UNIX_TIME`.

- [ ] **Step 4: Write the implementation**

In `src/encino-core/src/fsutil.rs`, after the `canonical`/`strip_verbatim_prefix` pair and before `write_atomic`:

```rust
/// The timestamp every blob and blob-store directory carries.
///
/// `2001-01-01T00:00:00Z`. A constant rather than the vault's creation time,
/// which would vary per vault for no gain, and not the Unix epoch, which some
/// backup tools read as a missing or damaged timestamp.
pub const NORMALIZED_UNIX_TIME: i64 = 978_307_200;

/// Stamp a file or directory with [`NORMALIZED_UNIX_TIME`].
///
/// A blob is written once and never modified — an edited document is stored
/// under a fresh random id — so its mtime would otherwise be exactly when that
/// document last changed. Across the snapshots a backup accumulates, that is a
/// per-document activity timeline readable with no credential at all.
///
/// Deliberately best-effort and infallible. A filesystem that refuses the change
/// must not fail an import: the document is durably stored either way, and the
/// timestamp is a privacy property rather than a correctness one.
///
/// Not for `index.enc` or `vault.json`. Those are replaced in place, keeping
/// their names and sometimes their sizes, so a backup tool deciding what to copy
/// from name, size and mtime could silently skip a changed index — and losing
/// the index loses every document.
pub fn normalize_times(path: &Path) {
    let stamp = filetime::FileTime::from_unix_time(NORMALIZED_UNIX_TIME, 0);
    let _ = filetime::set_file_times(path, stamp, stamp);
}
```

- [ ] **Step 5: Run the test and watch it pass**

Run: `cargo test -p encino-core fsutil::tests::normalizing`
Expected: PASS, 2 tests.

- [ ] **Step 6: Confirm the dependency footprint is one crate**

Run: `git diff --stat Cargo.lock` and `grep -c '^name = ' Cargo.lock`
Expected: crate count goes from 141 to **142**, and the only added package block is `filetime`.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/encino-core/Cargo.toml src/encino-core/src/fsutil.rs
git commit -m "Add a helper that stamps a fixed time on a file or directory"
```

---

### Task 2: Normalize on the write path

**Files:**
- Modify: `src/encino-core/src/blob.rs` (end of `write_blob`, and the inline `mod tests`)

**Interfaces:**
- Consumes: `fsutil::normalize_times(&Path)`, `fsutil::NORMALIZED_UNIX_TIME` from Task 1.
- Produces: no new API. `write_blob` keeps its signature `pub fn write_blob<R: Read>(source: &mut R, dest: &Path, id: &BlobId, key: &Key) -> Result<BlobStats>`.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `src/encino-core/src/blob.rs`:

```rust
    /// Modification time of a path, in Unix seconds.
    fn mtime_of(path: &Path) -> i64 {
        filetime::FileTime::from_last_modification_time(&std::fs::metadata(path).unwrap())
            .unix_seconds()
    }

    #[test]
    fn a_written_blob_and_its_directories_carry_the_normalized_time() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = dir.path().join("blobs");
        let id = BlobId::random();
        let path = id.path_under(&blobs);

        write_blob(&mut &b"statement"[..], &path, &id, &Key::random()).unwrap();

        // The blob itself, its shard, and the store root: a shard directory's
        // mtime moves whenever a blob lands in it, and with 256 shards that is
        // nearly per-document granularity on its own.
        for target in [&path, &path.parent().unwrap().to_path_buf(), &blobs] {
            assert_eq!(
                mtime_of(target),
                crate::fsutil::NORMALIZED_UNIX_TIME,
                "{target:?} was left with a real timestamp"
            );
        }
    }

    #[test]
    fn two_blobs_written_at_different_times_are_indistinguishable() {
        // The observed leak: documents imported together and one edited later
        // showed three distinct mtimes, which is an activity timeline.
        let dir = tempfile::tempdir().unwrap();
        let key = Key::random();

        let (first_id, second_id) = (BlobId::random(), BlobId::random());
        let first = first_id.path_under(dir.path());
        let second = second_id.path_under(dir.path());

        write_blob(&mut &b"one"[..], &first, &first_id, &key).unwrap();
        write_blob(&mut &b"two"[..], &second, &second_id, &key).unwrap();

        assert_eq!(mtime_of(&first), mtime_of(&second));
        // Asserted against the constant too, so this cannot pass merely because
        // a coarse filesystem gave both the same real time.
        assert_eq!(mtime_of(&first), crate::fsutil::NORMALIZED_UNIX_TIME);
    }
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cargo test -p encino-core blob::tests::a_written_blob_and blob::tests::two_blobs_written`
Expected: FAIL — mtimes are the current time, not 978307200.

- [ ] **Step 3: Implement**

In `src/encino-core/src/blob.rs`, in `write_blob`, replace the tail:

```rust
    file.seek(SeekFrom::Start(0)).map_err(|e| Error::io("rewind blob", dest, e))?;
    write_header(&mut file, CHUNK_SIZE as u32, index, size)
        .map_err(|e| Error::io("finalize blob header", dest, e))?;
    file.sync_all().map_err(|e| Error::io("flush blob to disk", dest, e))?;

    Ok(BlobStats { size, sha256: digest.finish() })
```

with:

```rust
    file.seek(SeekFrom::Start(0)).map_err(|e| Error::io("rewind blob", dest, e))?;
    write_header(&mut file, CHUNK_SIZE as u32, index, size)
        .map_err(|e| Error::io("finalize blob header", dest, e))?;
    file.sync_all().map_err(|e| Error::io("flush blob to disk", dest, e))?;
    // Closed before its times are set: Windows is happier stamping a file that
    // nothing holds open.
    drop(file);

    // The blob, its shard, and the store root. Writing the blob moved all three,
    // and a shard's mtime alone would still say when a document changed.
    crate::fsutil::normalize_times(dest);
    if let Some(shard) = dest.parent() {
        crate::fsutil::normalize_times(shard);
        if let Some(root) = shard.parent() {
            crate::fsutil::normalize_times(root);
        }
    }

    Ok(BlobStats { size, sha256: digest.finish() })
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cargo test -p encino-core blob::`
Expected: PASS, all blob tests including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add src/encino-core/src/blob.rs
git commit -m "Stamp blobs and their directories with the normalized time on write"
```

---

### Task 3: Normalize on the removal path

**Files:**
- Modify: `src/encino-core/src/shred.rs` (`remove_blob`, and the inline `mod tests`)

**Interfaces:**
- Consumes: `fsutil::normalize_times(&Path)`, `fsutil::NORMALIZED_UNIX_TIME` from Task 1; `blob::write_blob` from Task 2.
- Produces: no new API. `remove_blob` keeps `pub fn remove_blob(path: &Path) -> Result<()>`.

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `src/encino-core/src/shred.rs`:

```rust
    #[test]
    fn removing_a_blob_leaves_its_shard_directory_normalized() {
        use crate::blob::{BlobId, write_blob};
        use crate::crypto::Key;

        let dir = tempfile::tempdir().unwrap();
        let id = BlobId::random();
        let path = id.path_under(dir.path());
        write_blob(&mut &b"superseded"[..], &path, &id, &Key::random()).unwrap();

        let shard = path.parent().unwrap().to_path_buf();
        remove_blob(&path).unwrap();

        // Deleting moves the directory's mtime just as writing did, so a
        // check-in would otherwise restore the timeline the write path removed.
        let stamped =
            filetime::FileTime::from_last_modification_time(&fs::metadata(&shard).unwrap());
        assert_eq!(stamped.unix_seconds(), crate::fsutil::NORMALIZED_UNIX_TIME);
    }
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `cargo test -p encino-core shred::tests::removing_a_blob_leaves`
Expected: FAIL — the shard carries the real deletion time.

- [ ] **Step 3: Implement**

In `src/encino-core/src/shred.rs`, replace `remove_blob`:

```rust
/// Delete a blob file. Ciphertext, so no scrubbing is warranted.
///
/// The shard directory is restamped afterwards: deleting moves its mtime just as
/// writing does, so a check-in — which writes a new blob and drops the old —
/// would otherwise restore the per-document timeline the write path removes.
pub fn remove_blob(path: &Path) -> Result<()> {
    let removed = match fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(Error::io("delete blob", path, e)),
    };

    if removed && let Some(shard) = path.parent() {
        crate::fsutil::normalize_times(shard);
    }
    Ok(())
}
```

- [ ] **Step 4: Run the test and watch it pass**

Run: `cargo test -p encino-core shred::`
Expected: PASS, all shred tests.

- [ ] **Step 5: Commit**

```bash
git add src/encino-core/src/shred.rs
git commit -m "Restamp a blob's shard directory after the blob is deleted"
```

---

### Task 4: End-to-end regression test

**Files:**
- Modify: `src/encino-core/tests/lifecycle.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–3, plus the existing `Fixture` helper in this file (`Fixture::new()`, `Fixture::add(name, contents)`, `Fixture::session()`, `Fixture::blobs_dir()`).
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

Add to `src/encino-core/tests/lifecycle.rs`, before `fn export_reproduces_the_original_tree`:

```rust
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

    let times = blob_mtimes(&fixture.blobs_dir());
    assert_eq!(times.len(), 3, "expected one blob per document, got {}", times.len());

    let distinct: std::collections::HashSet<i64> = times.into_iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "blob mtimes differ, which says which document changed and when: {distinct:?}"
    );
}

/// Modification time of every blob in the store, in Unix seconds.
fn blob_mtimes(blobs_dir: &Path) -> Vec<i64> {
    let mut out = Vec::new();
    for shard in std::fs::read_dir(blobs_dir).unwrap().flatten() {
        if !shard.path().is_dir() {
            continue;
        }
        for blob in std::fs::read_dir(shard.path()).unwrap().flatten() {
            let metadata = std::fs::metadata(blob.path()).unwrap();
            out.push(filetime::FileTime::from_last_modification_time(&metadata).unix_seconds());
        }
    }
    out
}
```

- [ ] **Step 2: Add `filetime` as a dev-dependency of the test**

`lifetime.rs` is an integration test, so it links `encino-core` as an external crate and needs `filetime` in its own scope. In `src/encino-core/Cargo.toml`, under `[dev-dependencies]`:

```toml
filetime.workspace = true
```

(It is already a normal dependency; this makes it nameable from `tests/`.)

- [ ] **Step 3: Run the test and watch it pass**

Run: `cargo test -p encino-core --test lifecycle blob_timestamps_do_not_reveal`
Expected: PASS. (Tasks 2 and 3 already implement the behaviour; this test proves it end to end through a real session, including the check-in that deletes a superseded blob.)

- [ ] **Step 4: Prove the test is not vacuous**

Temporarily change `NORMALIZED_UNIX_TIME` in `src/encino-core/src/fsutil.rs` to a value derived from the clock so blobs get distinct times — replace the body of `normalize_times` with `let _ = path;` — then re-run:

Run: `cargo test -p encino-core --test lifecycle blob_timestamps_do_not_reveal`
Expected: **FAIL** with "blob mtimes differ, which says which document changed and when".

Restore `normalize_times` to its real body and re-run to confirm PASS. Confirm with `git diff src/encino-core/src/fsutil.rs` that nothing was left behind.

- [ ] **Step 5: Commit**

```bash
git add src/encino-core/Cargo.toml src/encino-core/tests/lifecycle.rs
git commit -m "Prove end to end that blob timestamps no longer name the edited document"
```

---

### Task 5: Documentation and full verification

**Files:**
- Modify: `docs/format.md` (the "Reserved for future versions" list, and a new note under Blobs)
- Modify: `docs/threat-model.md` (Assets table)
- Modify: `README.md` (Platforms table)

**Interfaces:**
- Consumes: the behaviour from Tasks 1–4.
- Produces: nothing.

- [ ] **Step 1: Update `docs/format.md`**

Remove this bullet from "Reserved for future versions":

```markdown
- **Hiding access times.** Filesystem timestamps on blobs reveal when a document
  was last checked in.
```

Add a new subsection at the end of the `## Blobs` section, after "Chunk associated data":

```markdown
### Timestamps

Every blob, every shard directory, and `blobs/` itself carries a fixed
modification and access time of `2001-01-01T00:00:00Z`.

A blob is written once and never modified — an edited document is stored under a
fresh random id — so without this a blob's mtime is exactly when that document
last changed, and a shard's mtime is when one of its documents last changed.
Across the snapshots a backup accumulates, that is a per-document activity
timeline available without any credential.

This is a property of what encino writes, not of the format: a version 1 reader
never consults a timestamp. `encino verify` reports any blob left carrying
the times it was given.

**On Unix, ctime is not covered**, because no userspace call can set it — and
setting mtime updates it. An attacker reading the raw filesystem still sees when
each blob was written. What this does cover is every backup and archive format,
none of which carry ctime, which is the case where a timeline accumulates.

`index.enc` and `vault.json` are deliberately excluded. They are replaced in
place, keeping their names, so a tool deciding what to back up from name, size
and mtime could silently skip a changed index — and the index is the one file
whose loss loses every document.
```

- [ ] **Step 2: Update `docs/threat-model.md`**

In the Assets table, replace:

```markdown
| Access times | **No** — filesystem timestamps on blobs are visible |
```

with:

```markdown
| Access times | Mostly — blob timestamps are normalized; Unix `ctime` is not settable |
```

And add after the paragraph beginning "The count and the access times remain visible":

```markdown
Blob timestamps are normalized to a fixed value, so the blob store no longer says
when each document last changed. On Unix the inode change time remains, since no
userspace call can set it; it is absent from every backup and archive format, so
what it exposes is raw filesystem access rather than a leaked copy. See
`format.md` for the detail.
```

Then correct the sentence that precedes it so it no longer claims access times remain visible — it should read:

```markdown
The count remains visible, and is recorded in `format.md` as a candidate for a
future revision. Hiding it needs decoy blobs, which carry an ongoing storage cost
rather than a one-off one.
```

- [ ] **Step 3: Update `README.md`**

In the Platforms table, add a row after "Key kept out of swap":

```markdown
| Blob timestamps | normalized, including creation time | normalized; `ctime` not settable |
```

- [ ] **Step 4: Verify every documentation claim**

Run each and confirm:

```bash
grep -n "Hiding access times" docs/format.md          # expect: no match
grep -n "978_307_200" src/encino-core/src/fsutil.rs   # expect: the constant
```

- [ ] **Step 5: Full verification on Windows**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```
Expected: clippy silent, all tests pass, release builds.

- [ ] **Step 6: Full verification on Linux**

```bash
wsl.exe -e bash -c 'source $HOME/.cargo/env && cd /mnt/e/Projects/encino && CARGO_TARGET_DIR=/tmp/enc cargo fmt --all --check && CARGO_TARGET_DIR=/tmp/enc cargo clippy --workspace --all-targets -- -D warnings && CARGO_TARGET_DIR=/tmp/enc cargo test --workspace'
```
Expected: fmt clean, clippy silent, all tests pass.

- [ ] **Step 7: Confirm the binary is unchanged in shape**

```bash
ls -l target/release/encino.exe
grep -a -o -iE "[A-Za-z0-9_.-]+\.dll" target/release/encino.exe | tr 'A-Z' 'a-z' | sort -u
```
Expected: still one executable; the DLL list still exactly `advapi32 api-ms-win-core-synch-l1-2-0 bcryptprimitives dbghelp kernel32 ntdll`, with **no** `vcruntime`. Baseline size before this work was 1,785,856 bytes; record the delta.

- [ ] **Step 8: Update the README test counts**

Run `cargo test --workspace` and the WSL equivalent, sum the `test result: ok. N passed` lines for each platform, and update this line in `README.md` (currently 212 / 206):

```markdown
Everything is verified on both: N tests on Windows, M on Linux.
```

- [ ] **Step 9: Commit**

```bash
git add README.md docs/format.md docs/threat-model.md
git commit -m "Document blob timestamp normalization and its ctime limit"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| Constant `2001-01-01T00:00:00Z`, mtime + atime | 1 |
| Set after `sync_all` in `write_blob` | 2 |
| Blob file, shard directory, `blobs/` | 2 |
| Restamp shard after removal | 3 |
| `index.enc` / `vault.json` excluded | Global Constraints; enforced by touching neither |
| `filetime` dependency, +1 crate | 1 (step 6 verifies the count) |
| ctime not closed on Unix | 5 (documented in all three docs) |
| Best-effort, non-fatal | 1 (`normalize_times` returns `()`; test covers a missing path) |
| Tests: constant, identical mtimes, shard on write and remove, lifecycle | 2, 3, 4 |
| `verify` reports a blob left with a real timestamp | added after review |
| No `format_version` bump | Global Constraints; no version touched |

**Placeholder scan:** none — every step carries the literal code or command.

**Type consistency:** `NORMALIZED_UNIX_TIME: i64` and `normalize_times(&Path)` are defined in Task 1 and used under those exact names in Tasks 2, 3, and 4. `filetime::FileTime::from_last_modification_time(&Metadata) -> FileTime` and `.unix_seconds() -> i64` are used consistently in all four test sites.
