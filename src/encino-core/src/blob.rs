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

/// Header: magic ‖ chunk_size (u32) ‖ chunk_count (u64).
const HEADER_LEN: usize = 8 + 4 + 8;

/// Associated data: magic ‖ blob id ‖ chunk index ‖ final flag.
const AAD_LEN: usize = 8 + BLOB_ID_LEN + 8 + 1;

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

/// Associated data for one chunk: document, position, and final-chunk flag.
/// The header's chunk count is unauthenticated, so only the flag catches
/// truncation: the new last chunk was sealed as non-final and fails to open.
/// Binding the count instead is impossible, as a streaming writer seals each
/// chunk before the total is known.
fn chunk_aad(id: &BlobId, index: u64, is_final: bool) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..8].copy_from_slice(BLOB_MAGIC);
    aad[8..24].copy_from_slice(id.as_bytes());
    aad[24..32].copy_from_slice(&index.to_le_bytes());
    aad[32] = u8::from(is_final);
    aad
}

fn write_header<W: Write>(out: &mut W, chunk_size: u32, chunk_count: u64) -> std::io::Result<()> {
    out.write_all(BLOB_MAGIC)?;
    out.write_all(&chunk_size.to_le_bytes())?;
    out.write_all(&chunk_count.to_le_bytes())
}

/// Encrypt `source` into the blob file at `dest`. Streams in [`CHUNK_SIZE`]
/// pieces with one chunk of lookahead, so each chunk is sealed knowing whether
/// it is the last; the count is patched into the header afterwards, hence `dest`
/// must be seekable. An empty document is stored as one empty final chunk, so a
/// header-only truncation stays distinguishable from an empty document.
pub fn write_blob<R: Read>(source: &mut R, dest: &Path, id: &BlobId, key: &Key) -> Result<BlobStats> {
    if let Some(parent) = dest.parent() {
        crate::fsutil::ensure_dir(parent)?;
    }

    let mut file = File::create_new(dest).map_err(|e| Error::io("create blob", dest, e))?;
    write_header(&mut file, CHUNK_SIZE as u32, 0).map_err(|e| Error::io("write blob header", dest, e))?;

    let mut digest = Sha256Stream::new();
    let mut size: u64 = 0;
    let mut index: u64 = 0;

    let mut current = vec![0u8; CHUNK_SIZE];
    let mut lookahead = vec![0u8; CHUNK_SIZE];
    let mut current_len = read_full(source, &mut current).map_err(|e| Error::io("read source", dest, e))?;

    loop {
        // A short read means the source is exhausted.
        let next_len = if current_len == CHUNK_SIZE {
            read_full(source, &mut lookahead).map_err(|e| Error::io("read source", dest, e))?
        } else {
            0
        };
        let is_final = next_len == 0;

        let plaintext = &current[..current_len];
        digest.update(plaintext);
        size += current_len as u64;

        let (nonce, ciphertext) = crypto::seal(key, &chunk_aad(id, index, is_final), plaintext);
        file.write_all(&nonce).map_err(|e| Error::io("write blob chunk", dest, e))?;
        file.write_all(&ciphertext).map_err(|e| Error::io("write blob chunk", dest, e))?;
        index += 1;

        if is_final {
            break;
        }
        std::mem::swap(&mut current, &mut lookahead);
        current_len = next_len;
    }

    file.seek(SeekFrom::Start(0)).map_err(|e| Error::io("rewind blob", dest, e))?;
    write_header(&mut file, CHUNK_SIZE as u32, index)
        .map_err(|e| Error::io("finalize blob header", dest, e))?;
    file.sync_all().map_err(|e| Error::io("flush blob to disk", dest, e))?;

    Ok(BlobStats { size, sha256: digest.finish() })
}

/// Decrypt the blob at `src`, writing plaintext to `out`. Returns size and
/// digest so the caller can check them against the index without a second pass.
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

    let mut digest = Sha256Stream::new();
    let mut size: u64 = 0;
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
        let plaintext = crypto::open(key, nonce, &chunk_aad(id, index, is_final), ciphertext)?;

        digest.update(&plaintext);
        size += plaintext.len() as u64;
        out.write_all(&plaintext).map_err(|e| Error::io("write plaintext", src, e))?;
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

    #[test]
    fn documents_survive_a_round_trip_at_every_interesting_size() {
        // Chunk boundaries are where a streaming implementation goes wrong.
        for size in [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE, 2 * CHUNK_SIZE + 12345]
        {
            let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            assert_eq!(round_trip(&content), content, "failed at size {size}");
        }
    }

    #[test]
    fn an_empty_document_is_stored_as_one_empty_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        write_blob(&mut &b""[..], &path, &BlobId::random(), &Key::random()).unwrap();

        // Zero chunks would make a header-only truncation look like an empty document.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), (HEADER_LEN + NONCE_LEN + TAG_LEN) as u64);
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
