//! The encrypted blob store: one file per document, named by random bytes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{self, Key, NONCE_LEN, Sha256Stream, TAG_LEN};
use crate::{Error, Result};

/// Length of a blob identifier.
pub const BLOB_ID_LEN: usize = 16;

/// File magic, also the first field of every chunk's associated data.
pub const BLOB_MAGIC: &[u8; 8] = b"ENCINOB1";

/// Plaintext bytes per chunk in format version 1.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Largest chunk size accepted when reading. The header is unauthenticated, so
/// a hostile chunk size must be bounded before any buffer is allocated.
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Size every document is padded up to at minimum, so that short documents are
/// all exactly the same size on disk.
pub const MIN_BLOB_BYTES: u64 = 4096;

/// Largest document the format admits. Far beyond any real document; it exists
/// to bound [`padded_len`] arithmetic, since the length it works from arrives in
/// an unauthenticated header.
pub const MAX_PLAINTEXT_LEN: u64 = 1 << 48;

/// Header: magic ‖ chunk_size (u32) ‖ chunk_count (u64) ‖ plaintext_len (u64).
const HEADER_LEN: usize = 8 + 4 + 8 + 8;

/// Associated data: magic ‖ blob id ‖ chunk index ‖ final flag ‖ length field.
const AAD_LEN: usize = 8 + BLOB_ID_LEN + 8 + 1 + 8;

/// A random blob identifier. Not content-derived: identical names would reveal
/// duplicate documents and confirm a guessed document by hashing a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId([u8; BLOB_ID_LEN]);

impl BlobId {
    /// Generate a fresh identifier.
    pub fn random() -> Self {
        BlobId(crypto::random_array::<BLOB_ID_LEN>())
    }

    /// Raw bytes, as bound into chunk associated data.
    pub fn as_bytes(&self) -> &[u8; BLOB_ID_LEN] {
        &self.0
    }

    /// Lowercase hex, as used for filenames.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex.
    pub fn from_hex(text: &str) -> Result<Self> {
        let bytes = hex::decode(text).map_err(|e| Error::CorruptData {
            path: PathBuf::from("index.enc"),
            detail: format!("blob id {text:?} is not hex: {e}"),
        })?;
        let array: [u8; BLOB_ID_LEN] = bytes.as_slice().try_into().map_err(|_| Error::CorruptData {
            path: PathBuf::from("index.enc"),
            detail: format!("blob id {text:?} is the wrong length"),
        })?;
        Ok(BlobId(array))
    }

    /// Location of this blob under a blob-store root. Sharded by the first byte
    /// to bound directory sizes; not a security property.
    pub fn path_under(&self, blobs_dir: &Path) -> PathBuf {
        blobs_dir.join(hex::encode(&self.0[..1])).join(self.to_hex())
    }
}

impl Serialize for BlobId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        BlobId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// What was written, for recording in the index.
#[derive(Debug, Clone, Copy)]
pub struct BlobStats {
    /// Plaintext length in bytes.
    pub size: u64,
    /// SHA-256 of the plaintext, used by `verify`.
    pub sha256: [u8; 32],
}

/// Round a document's length up to its padding bucket.
///
/// This is Padmé, from the PURB paper: keep the leading `floor(log2 E) + 1` bits
/// of the length, where `E = floor(log2 len)`, and round the rest up. Overhead is
/// at most 11.9%, and what a file's size still reveals is roughly `log log len`
/// bits — enough to tell a note from a scan, not enough to tell two similar PDFs
/// apart.
///
/// The floor is what Padmé alone does not provide. Padmé bounds the *relative*
/// leak, so a 200-byte note pads to 200 bytes and stays exactly as identifying as
/// it was; [`MIN_BLOB_BYTES`] makes every short document indistinguishable
/// instead, for a few kilobytes each.
pub fn padded_len(len: u64) -> u64 {
    if len <= MIN_BLOB_BYTES {
        return MIN_BLOB_BYTES;
    }

    // `len` exceeds MIN_BLOB_BYTES, so both logarithms have a defined result.
    let e = 63 - len.leading_zeros();
    let significant = 31 - e.leading_zeros() + 1;
    let mask = (1u64 << (e - significant)) - 1;

    // Every caller bounds `len` by MAX_PLAINTEXT_LEN, so this cannot overflow.
    // Saturating rather than wrapping keeps a hostile header out of a panic.
    len.saturating_add(mask) & !mask
}

/// Associated data for one chunk: document, position, final-chunk flag, and — on
/// the final chunk only — the document's true length.
///
/// The header's chunk count is unauthenticated, so only the flag catches
/// truncation: the new last chunk was sealed as non-final and fails to open.
/// Binding the count instead is impossible, as a streaming writer seals each
/// chunk before the total is known.
///
/// `plaintext_len` is unauthenticated for the same reason, and padding is what
/// makes that dangerous: with slack after the document, an attacker who could
/// re-declare the length would truncate the plaintext while every chunk still
/// verified. Binding it into the final chunk closes that, and the final chunk is
/// the one place a streaming writer already knows the total. One binding is
/// enough, since no other chunk can become final with `is_final` bound too.
fn chunk_aad(id: &BlobId, index: u64, is_final: bool, plaintext_len: u64) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..8].copy_from_slice(BLOB_MAGIC);
    aad[8..24].copy_from_slice(id.as_bytes());
    aad[24..32].copy_from_slice(&index.to_le_bytes());
    aad[32] = u8::from(is_final);
    if is_final {
        aad[33..41].copy_from_slice(&plaintext_len.to_le_bytes());
    }
    aad
}

fn write_header<W: Write>(
    out: &mut W,
    chunk_size: u32,
    chunk_count: u64,
    plaintext_len: u64,
) -> std::io::Result<()> {
    out.write_all(BLOB_MAGIC)?;
    out.write_all(&chunk_size.to_le_bytes())?;
    out.write_all(&chunk_count.to_le_bytes())?;
    out.write_all(&plaintext_len.to_le_bytes())
}

/// Encrypt `source` into the blob file at `dest`, padded to [`padded_len`].
///
/// Streams in [`CHUNK_SIZE`] pieces with one chunk of lookahead, so real data is
/// sealed as it arrives rather than materialized in RAM. The padding cannot be
/// sized until the source is exhausted, so the last chunk of real data is held
/// back, zero-extended, and followed by whole zero chunks up to the padded
/// length; the last of those ends the blob. The count and the true length are
/// patched into the header afterwards, hence `dest` must be seekable.
///
/// An empty document is stored as one [`MIN_BLOB_BYTES`] chunk of padding, so a
/// header-only truncation stays distinguishable from an empty document.
///
/// The returned statistics describe the *real* plaintext, not the padded stream.
pub fn write_blob<R: Read>(source: &mut R, dest: &Path, id: &BlobId, key: &Key) -> Result<BlobStats> {
    if let Some(parent) = dest.parent() {
        crate::fsutil::ensure_dir(parent)?;
    }

    let mut file = File::create_new(dest).map_err(|e| Error::io("create blob", dest, e))?;
    write_header(&mut file, CHUNK_SIZE as u32, 0, 0).map_err(|e| Error::io("write blob header", dest, e))?;

    let mut digest = Sha256Stream::new();
    let mut size: u64 = 0;
    let mut index: u64 = 0;
    let mut emitted: u64 = 0;

    let mut current = vec![0u8; CHUNK_SIZE];
    let mut lookahead = vec![0u8; CHUNK_SIZE];
    let mut current_len = read_full(source, &mut current).map_err(|e| Error::io("read source", dest, e))?;

    // Seal every chunk that is certainly followed by more real data. Whether the
    // last one ends the blob depends on the padding, which is not yet known.
    loop {
        // A short read means the source is exhausted.
        let next_len = if current_len == CHUNK_SIZE {
            read_full(source, &mut lookahead).map_err(|e| Error::io("read source", dest, e))?
        } else {
            0
        };
        if next_len == 0 {
            break;
        }

        digest.update(&current[..current_len]);
        size += current_len as u64;
        seal_chunk(&mut file, dest, key, id, index, false, 0, &current[..current_len])?;
        index += 1;
        emitted += current_len as u64;

        std::mem::swap(&mut current, &mut lookahead);
        current_len = next_len;
    }

    // `current` holds the tail of the document, and the source is spent.
    digest.update(&current[..current_len]);
    size += current_len as u64;

    // Zero-extend that tail and follow it with whole zero chunks. `remaining` is
    // at least `current_len`, since the padded length never falls below the real
    // one, so the tail is never truncated by this.
    current[current_len..].fill(0);
    let mut remaining = padded_len(size) - emitted;
    loop {
        let taken = remaining.min(CHUNK_SIZE as u64) as usize;
        remaining -= taken as u64;
        let is_final = remaining == 0;
        seal_chunk(&mut file, dest, key, id, index, is_final, size, &current[..taken])?;
        index += 1;
        if is_final {
            break;
        }
        // Everything past the first of these chunks is padding alone.
        current.fill(0);
    }

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
}

/// Seal one chunk and append it. `plaintext_len` is bound in only when
/// `is_final`; see [`chunk_aad`].
#[allow(clippy::too_many_arguments)]
fn seal_chunk(
    file: &mut File,
    dest: &Path,
    key: &Key,
    id: &BlobId,
    index: u64,
    is_final: bool,
    plaintext_len: u64,
    plaintext: &[u8],
) -> Result<()> {
    let (nonce, ciphertext) = crypto::seal(key, &chunk_aad(id, index, is_final, plaintext_len), plaintext);
    file.write_all(&nonce).map_err(|e| Error::io("write blob chunk", dest, e))?;
    file.write_all(&ciphertext).map_err(|e| Error::io("write blob chunk", dest, e))
}

/// Decrypt the blob at `src`, writing plaintext to `out`. Returns size and
/// digest so the caller can check them against the index without a second pass.
///
/// Padding is stripped: only the first `plaintext_len` bytes reach `out`, feed
/// the digest, or count towards the returned size.
pub fn read_blob<W: Write>(src: &Path, out: &mut W, id: &BlobId, key: &Key) -> Result<BlobStats> {
    let mut file = File::open(src).map_err(|e| Error::io("open blob", src, e))?;

    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header).map_err(|_| Error::CorruptData {
        path: src.to_path_buf(),
        detail: "file is too short to be a blob".into(),
    })?;

    if &header[..8] != BLOB_MAGIC {
        return Err(Error::CorruptData { path: src.to_path_buf(), detail: "wrong file magic".into() });
    }

    let chunk_size = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
    let chunk_count = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let plaintext_len = u64::from_le_bytes(header[20..28].try_into().unwrap());

    // The header is unauthenticated; bound its values before trusting them.
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::CorruptData {
            path: src.to_path_buf(),
            detail: format!("implausible chunk size {chunk_size}"),
        });
    }
    if chunk_count == 0 {
        return Err(Error::CorruptData {
            path: src.to_path_buf(),
            detail: "blob claims to hold no chunks; every blob has at least one".into(),
        });
    }
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(Error::CorruptData {
            path: src.to_path_buf(),
            detail: format!("implausible document length {plaintext_len}"),
        });
    }

    // Derived from the authenticated length, never read from the file: a padding
    // length the file could choose would be a padding length an attacker chooses.
    let padded = padded_len(plaintext_len);

    let mut digest = Sha256Stream::new();
    let mut size: u64 = 0;
    let mut total: u64 = 0;
    let mut buffer = vec![0u8; NONCE_LEN + chunk_size + TAG_LEN];

    for index in 0..chunk_count {
        let filled = read_full(&mut file, &mut buffer).map_err(|e| Error::io("read blob", src, e))?;
        if filled < NONCE_LEN + TAG_LEN {
            return Err(Error::CorruptData {
                path: src.to_path_buf(),
                detail: format!("blob ends after {index} of {chunk_count} chunks"),
            });
        }

        let (nonce, ciphertext) = buffer[..filled].split_at(NONCE_LEN);
        let is_final = index + 1 == chunk_count;
        let plaintext = crypto::open(key, nonce, &chunk_aad(id, index, is_final, plaintext_len), ciphertext)?;

        // Split the chunk where the document ends and its padding begins.
        let real = (plaintext_len - size).min(plaintext.len() as u64) as usize;
        digest.update(&plaintext[..real]);
        out.write_all(&plaintext[..real]).map_err(|e| Error::io("write plaintext", src, e))?;
        size += real as u64;

        // No attacker can forge sealed padding, so this catches no attack. It
        // makes the format normative: an implementation that pads differently
        // fails a test rather than quietly producing divergent vaults.
        if plaintext[real..].iter().any(|&byte| byte != 0) {
            return Err(Error::CorruptData {
                path: src.to_path_buf(),
                detail: format!("chunk {index} carries padding that is not zero-filled"),
            });
        }
        total += plaintext.len() as u64;
    }

    if total != padded {
        return Err(Error::CorruptData {
            path: src.to_path_buf(),
            detail: format!("blob holds {total} padded bytes where {padded} were expected"),
        });
    }

    let mut trailing = [0u8; 1];
    if file.read(&mut trailing).map_err(|e| Error::io("read blob", src, e))? != 0 {
        return Err(Error::CorruptData {
            path: src.to_path_buf(),
            detail: "blob has trailing data after its last chunk".into(),
        });
    }

    Ok(BlobStats { size, sha256: digest.finish() })
}

/// Read until the buffer is full or the source is exhausted. Treating a short
/// read as end-of-input would split chunks and corrupt the document.
fn read_full<R: Read>(source: &mut R, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(content: &[u8]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();

        let written = write_blob(&mut &content[..], &path, &id, &key).unwrap();
        assert_eq!(written.size, content.len() as u64);
        assert_eq!(written.sha256, crypto::sha256(content));

        let mut out = Vec::new();
        let read = read_blob(&path, &mut out, &id, &key).unwrap();
        assert_eq!(read.size, written.size);
        assert_eq!(read.sha256, written.sha256);
        out
    }

    /// Size of the blob file holding `content`.
    fn blob_size_of(content: &[u8]) -> u64 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        write_blob(&mut &content[..], &path, &BlobId::random(), &Key::random()).unwrap();
        std::fs::metadata(&path).unwrap().len()
    }

    /// Modification time of a path, in Unix seconds.
    fn mtime_of(path: &Path) -> i64 {
        filetime::FileTime::from_last_modification_time(&std::fs::metadata(path).unwrap()).unix_seconds()
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
        for target in [path.clone(), path.parent().unwrap().to_path_buf(), blobs.clone()] {
            assert_eq!(
                mtime_of(&target),
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

    #[test]
    fn documents_survive_a_round_trip_at_every_interesting_size() {
        // Chunk boundaries are where a streaming implementation goes wrong, and
        // padding adds boundaries of its own: the floor, and the point where a
        // padded document spills into a chunk the real data never reached.
        let floor = MIN_BLOB_BYTES as usize;
        for size in [
            0,
            1,
            floor - 1,
            floor,
            floor + 1,
            5000,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            2 * CHUNK_SIZE + 12345,
        ] {
            let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            assert_eq!(round_trip(&content), content, "failed at size {size}");
        }
    }

    #[test]
    fn an_empty_document_is_stored_as_one_padded_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        write_blob(&mut &b""[..], &path, &BlobId::random(), &Key::random()).unwrap();

        // Zero chunks would make a header-only truncation look like an empty
        // document, and an unpadded one would announce itself by its size.
        let expected = HEADER_LEN as u64 + NONCE_LEN as u64 + MIN_BLOB_BYTES + TAG_LEN as u64;
        assert_eq!(std::fs::metadata(&path).unwrap().len(), expected);
    }

    #[test]
    fn padded_len_rounds_up_to_a_bucket_and_never_below_the_floor() {
        assert_eq!(padded_len(0), MIN_BLOB_BYTES);
        assert_eq!(padded_len(1), MIN_BLOB_BYTES);
        assert_eq!(padded_len(MIN_BLOB_BYTES), MIN_BLOB_BYTES);

        // Padmé keeps floor(log2 E) + 1 significant bits. Above the floor,
        // E = 12, so 8 low bits are rounded away.
        assert_eq!(padded_len(4097), 4352);
        assert_eq!(padded_len(5000), 5120);
        assert_eq!(padded_len(10_000), 10_240);
        assert_eq!(padded_len(100_000), 100_352);
        assert_eq!(padded_len(5_000_000), 5_111_808);

        // An exact bucket boundary must not be pushed into the next bucket.
        assert_eq!(padded_len(5120), 5120);
        assert_eq!(padded_len(CHUNK_SIZE as u64), CHUNK_SIZE as u64);
    }

    #[test]
    fn padding_never_shrinks_a_document_or_costs_more_than_an_eighth() {
        let mut previous = 0;
        for len in 0..30_000u64 {
            let padded = padded_len(len);
            assert!(padded >= len, "padded_len({len}) = {padded} lost data");
            // A non-monotonic bucket function would let a larger document
            // produce a smaller file, leaking more than the padding hides.
            assert!(padded >= previous, "padded_len({len}) fell below its predecessor");
            previous = padded;

            if len > MIN_BLOB_BYTES {
                assert!(padded <= len + len / 8, "padded_len({len}) = {padded} exceeds 12.5% overhead");
            }
        }

        // Spot-check the same properties across the range the format admits.
        for exponent in 13..48 {
            let len = 1u64 << exponent;
            for probe in [len - 1, len, len + 1] {
                assert!(padded_len(probe) >= probe);
                assert!(padded_len(probe) <= probe + probe / 8);
            }
        }
    }

    #[test]
    fn documents_in_one_bucket_are_the_same_size_on_disk() {
        // The property the whole feature exists for: file size must not track
        // plaintext size closely enough to fingerprint a known document.
        let short = vec![1u8; 200];
        let longer = vec![2u8; 3_000];
        assert_eq!(blob_size_of(&short), blob_size_of(&longer), "small documents must be indistinguishable");

        let a = vec![3u8; 5_000];
        let b = vec![4u8; 5_100];
        assert_eq!(blob_size_of(&a), blob_size_of(&b), "same-bucket documents must be indistinguishable");

        // And a document genuinely larger still lands in a larger file, or
        // padding would be hiding nothing by making everything one size.
        assert!(blob_size_of(&vec![5u8; 50_000]) > blob_size_of(&a));
    }

    #[test]
    fn the_declared_length_cannot_be_edited_to_reveal_or_hide_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();

        let content: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        write_blob(&mut &content[..], &path, &id, &key).unwrap();
        let original = std::fs::read(&path).unwrap();

        // Shrinking the length would truncate the document while every chunk
        // still verified, were the length not bound into the final chunk. This
        // is the attack padding introduces and the binding exists to stop.
        for forged in [100u64, 4096, 5100, 0] {
            let mut tampered = original.clone();
            tampered[20..28].copy_from_slice(&forged.to_le_bytes());
            std::fs::write(&path, &tampered).unwrap();

            let mut out = Vec::new();
            assert!(
                read_blob(&path, &mut out, &id, &key).is_err(),
                "a declared length of {forged} was accepted for a 5000-byte document"
            );
        }

        // A forged length inside the same padding bucket reaches the chunk's
        // associated data rather than the structural check, so it must be the
        // authentication that refuses it.
        let mut tampered = original.clone();
        tampered[20..28].copy_from_slice(&5100u64.to_le_bytes());
        std::fs::write(&path, &tampered).unwrap();
        let mut out = Vec::new();
        assert!(matches!(read_blob(&path, &mut out, &id, &key), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn an_implausible_declared_length_is_refused_before_it_can_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();
        write_blob(&mut &b"statement"[..], &path, &id, &key).unwrap();

        let mut hostile = std::fs::read(&path).unwrap();
        hostile[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
        std::fs::write(&path, &hostile).unwrap();

        let mut out = Vec::new();
        assert!(matches!(read_blob(&path, &mut out, &id, &key), Err(Error::CorruptData { .. })));
    }

    #[test]
    fn the_wrong_key_cannot_read_a_blob() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();

        write_blob(&mut &b"financial statement"[..], &path, &id, &Key::random()).unwrap();

        let mut out = Vec::new();
        assert!(matches!(read_blob(&path, &mut out, &id, &Key::random()), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn a_blob_cannot_be_read_under_another_blobs_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let key = Key::random();

        write_blob(&mut &b"financial statement"[..], &path, &BlobId::random(), &key).unwrap();

        // The id is bound into each chunk's associated data, so blob files
        // swapped between index entries fail to open.
        let mut out = Vec::new();
        assert!(matches!(
            read_blob(&path, &mut out, &BlobId::random(), &key),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampering_with_any_byte_of_a_blob_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();
        write_blob(&mut &b"financial statement"[..], &path, &id, &key).unwrap();

        let original = std::fs::read(&path).unwrap();
        for byte in HEADER_LEN..original.len() {
            let mut tampered = original.clone();
            tampered[byte] ^= 0x01;
            std::fs::write(&path, &tampered).unwrap();

            let mut out = Vec::new();
            assert!(
                read_blob(&path, &mut out, &id, &key).is_err(),
                "tampering with byte {byte} went undetected"
            );
        }
    }

    #[test]
    fn truncating_a_blob_and_correcting_its_header_is_still_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();

        let content: Vec<u8> = (0..CHUNK_SIZE * 3).map(|i| (i % 251) as u8).collect();
        write_blob(&mut &content[..], &path, &id, &key).unwrap();

        // The attack the final-chunk flag exists to stop: drop the last chunk
        // and correct the unauthenticated count. Surviving chunks still verify.
        let full = std::fs::read(&path).unwrap();
        let stride = NONCE_LEN + CHUNK_SIZE + TAG_LEN;
        let mut truncated = full[..HEADER_LEN + 2 * stride].to_vec();
        truncated[12..20].copy_from_slice(&2u64.to_le_bytes());
        std::fs::write(&path, &truncated).unwrap();

        let mut out = Vec::new();
        assert!(
            matches!(read_blob(&path, &mut out, &id, &key), Err(Error::AuthenticationFailed)),
            "silent truncation was not detected"
        );
    }

    #[test]
    fn a_truncated_blob_with_an_untouched_header_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();

        let content: Vec<u8> = (0..CHUNK_SIZE * 2 + 500).map(|i| (i % 251) as u8).collect();
        write_blob(&mut &content[..], &path, &id, &key).unwrap();

        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..HEADER_LEN + NONCE_LEN + CHUNK_SIZE + TAG_LEN]).unwrap();

        let mut out = Vec::new();
        assert!(read_blob(&path, &mut out, &id, &key).is_err());
    }

    #[test]
    fn appending_a_duplicate_chunk_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();

        let content: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
        write_blob(&mut &content[..], &path, &id, &key).unwrap();

        let full = std::fs::read(&path).unwrap();
        let stride = NONCE_LEN + CHUNK_SIZE + TAG_LEN;
        let mut extended = full.clone();
        extended.extend_from_slice(&full[HEADER_LEN..HEADER_LEN + stride]);
        extended[12..20].copy_from_slice(&3u64.to_le_bytes());
        std::fs::write(&path, &extended).unwrap();

        let mut out = Vec::new();
        assert!(read_blob(&path, &mut out, &id, &key).is_err(), "chunk extension went undetected");
    }

    #[test]
    fn reordered_chunks_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();

        let content: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
        write_blob(&mut &content[..], &path, &id, &key).unwrap();

        let full = std::fs::read(&path).unwrap();
        let stride = NONCE_LEN + CHUNK_SIZE + TAG_LEN;
        let mut swapped = full[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&full[HEADER_LEN + stride..HEADER_LEN + 2 * stride]);
        swapped.extend_from_slice(&full[HEADER_LEN..HEADER_LEN + stride]);
        std::fs::write(&path, &swapped).unwrap();

        let mut out = Vec::new();
        assert!(read_blob(&path, &mut out, &id, &key).is_err(), "chunk reordering went undetected");
    }

    #[test]
    fn chunks_cannot_be_spliced_between_documents() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::random();
        let (id_a, id_b) = (BlobId::random(), BlobId::random());
        let (path_a, path_b) = (dir.path().join("a"), dir.path().join("b"));

        let content: Vec<u8> = (0..CHUNK_SIZE + 10).map(|i| (i % 251) as u8).collect();
        write_blob(&mut &content[..], &path_a, &id_a, &key).unwrap();
        write_blob(&mut &content[..], &path_b, &id_b, &key).unwrap();

        // Both blobs share a key, so only the bound blob id prevents this graft.
        let a = std::fs::read(&path_a).unwrap();
        let mut b = std::fs::read(&path_b).unwrap();
        let stride = NONCE_LEN + CHUNK_SIZE + TAG_LEN;
        b[HEADER_LEN..HEADER_LEN + stride].copy_from_slice(&a[HEADER_LEN..HEADER_LEN + stride]);
        std::fs::write(&path_b, &b).unwrap();

        let mut out = Vec::new();
        assert!(matches!(read_blob(&path_b, &mut out, &id_b, &key), Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn trailing_data_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();

        // Two routes: appended bytes join a short final chunk and break its tag,
        // whereas after a full final chunk the trailing check catches them. Both
        // must refuse, hence no assertion on a single error kind.
        for content in [b"statement".to_vec(), vec![7u8; CHUNK_SIZE]] {
            std::fs::remove_file(&path).ok();
            write_blob(&mut &content[..], &path, &id, &key).unwrap();

            let mut contents = std::fs::read(&path).unwrap();
            contents.extend_from_slice(b"appended");
            std::fs::write(&path, &contents).unwrap();

            let mut out = Vec::new();
            assert!(
                read_blob(&path, &mut out, &id, &key).is_err(),
                "appended data went undetected for a {}-byte document",
                content.len()
            );
        }
    }

    #[test]
    fn implausible_header_values_are_refused_before_allocating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();
        write_blob(&mut &b"statement"[..], &path, &id, &key).unwrap();
        let original = std::fs::read(&path).unwrap();

        // A chunk size of 4 GiB must not become a 4 GiB allocation.
        let mut hostile = original.clone();
        hostile[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &hostile).unwrap();
        let mut out = Vec::new();
        assert!(matches!(read_blob(&path, &mut out, &id, &key), Err(Error::CorruptData { .. })));

        // Zero chunks is never legitimate, since empty documents store one.
        let mut empty_claim = original.clone();
        empty_claim[12..20].copy_from_slice(&0u64.to_le_bytes());
        std::fs::write(&path, &empty_claim).unwrap();
        assert!(matches!(read_blob(&path, &mut out, &id, &key), Err(Error::CorruptData { .. })));
    }

    #[test]
    fn a_file_that_is_not_a_blob_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let mut out = Vec::new();

        std::fs::write(&path, b"this is just some text file").unwrap();
        assert!(matches!(
            read_blob(&path, &mut out, &BlobId::random(), &Key::random()),
            Err(Error::CorruptData { .. })
        ));

        std::fs::write(&path, b"tiny").unwrap();
        assert!(matches!(
            read_blob(&path, &mut out, &BlobId::random(), &Key::random()),
            Err(Error::CorruptData { .. })
        ));
    }

    #[test]
    fn writing_refuses_to_overwrite_an_existing_blob() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let key = Key::random();

        write_blob(&mut &b"first"[..], &path, &BlobId::random(), &key).unwrap();
        // A collision means the random source failed; refusing beats overwriting.
        assert!(write_blob(&mut &b"second"[..], &path, &BlobId::random(), &key).is_err());
    }

    #[test]
    fn blob_ids_are_random_so_identical_documents_do_not_collide() {
        let a = BlobId::random();
        let b = BlobId::random();
        assert_ne!(a, b);
        assert_eq!(BlobId::from_hex(&a.to_hex()).unwrap(), a);
        assert!(BlobId::from_hex("not hex").is_err());
        assert!(BlobId::from_hex("aabb").is_err());
    }

    #[test]
    fn identical_documents_produce_unrelated_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::random();
        let content = b"identical financial statement";

        let (path_a, path_b) = (dir.path().join("a"), dir.path().join("b"));
        write_blob(&mut &content[..], &path_a, &BlobId::random(), &key).unwrap();
        write_blob(&mut &content[..], &path_b, &BlobId::random(), &key).unwrap();

        // Equal plaintexts must not yield equal ciphertexts, or duplicates leak.
        let a = std::fs::read(&path_a).unwrap();
        let b = std::fs::read(&path_b).unwrap();
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    }

    #[test]
    fn blob_paths_are_sharded_by_their_first_byte() {
        let id = BlobId::from_hex("0f3a91c700000000000000000000ffff").unwrap();
        let path = id.path_under(Path::new("blobs"));
        assert!(path.ends_with("0f3a91c700000000000000000000ffff"));
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "0f");
    }

    #[test]
    fn short_reads_from_the_source_do_not_corrupt_the_document() {
        /// A reader that returns one byte at a time, as a slow pipe would.
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let id = BlobId::random();
        let key = Key::random();
        let content: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();

        write_blob(&mut Trickle(&content), &path, &id, &key).unwrap();

        let mut out = Vec::new();
        read_blob(&path, &mut out, &id, &key).unwrap();
        assert_eq!(out, content);
    }
}
