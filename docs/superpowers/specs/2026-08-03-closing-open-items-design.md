# Closing encino's open items

Design for the work that finishes the gaps recorded in `docs/handoff.md`: size
padding, hibernation guidance, and the named-pipe race. Two items on that list —
macOS and the race's *provability* — are addressed by saying plainly what remains
open rather than by pretending otherwise.

encino has never been released. There are no vaults on disk anywhere that this
work has to keep reading, so the format changes are made in place: version 1 is
simply defined to include padding. No compatibility path, no migration, no
version dispatch.

## Contents

- [Scope](#scope)
- [1. Size padding](#1-size-padding)
- [2. The named-pipe race](#2-the-named-pipe-race)
- [3. Hibernation guidance](#3-hibernation-guidance)
- [4. Documentation](#4-documentation)
- [Testing](#testing)
- [What stays open](#what-stays-open)

---

## Scope

| Open item | Disposition |
|---|---|
| Size padding unimplemented | Implemented. Padmé with a 4 KiB floor, in format version 1. |
| Hibernation guidance is one line | Written into `threat-model.md`, `strength.md`, `cli.md`. |
| Named-pipe race has a probabilistic test | Race eliminated structurally; the invariant is tested deterministically. |
| Win32 FFI is the least-tested code | `pipe.rs` gains unit tests. `win.rs` and `unix.rs` already had them. |
| macOS untested | Stays open. Requires a Mac. |

`handoff.md` is deleted. It existed to carry state into this work, not to be an
ongoing map; the durable parts of it belong in the documents that own them, and
the rest is now false.

## 1. Size padding

### The leak

A blob's file size is roughly its document's plaintext size. Anyone with the disk
can therefore see how many documents a vault holds and how large each is, which
is enough to fingerprint a known document — a specific tax form, a specific
scanned contract — without any ability to decrypt it.

### Padding function

```
MIN_BLOB_BYTES = 4096

padded_len(L):
    if L <= MIN_BLOB_BYTES: return MIN_BLOB_BYTES
    E = floor(log2 L)
    S = floor(log2 E) + 1
    z = E - S
    return L rounded up to a multiple of 2^z
```

This is Padmé, from the PURB paper, with a floor. Padmé bounds *relative* leak:
overhead is at most 11.9%, and the size that remains visible is roughly
`log log L` bits — enough to distinguish a 3 KB note from a 30 MB scan, not
enough to distinguish two 4 MB PDFs. The floor adds what Padmé alone lacks, which
is that every small document becomes exactly the same size on disk; without it a
200-byte note is padded to 200 bytes and stays as identifying as it was.

Powers of two were rejected: up to 100% storage overhead for one extra bucket
boundary is a bad trade for a tool that stores scanned documents.

### Encoding

The header gains one field. Magic is unchanged.

```
header (28 bytes, was 20)
  magic          8    "ENCINOB1"
  chunk_size     4    plaintext bytes per chunk
  chunk_count    8    number of chunks that follow
  plaintext_len  8    true document length, before padding

chunks           chunk_count × (24-byte nonce ‖ ciphertext ‖ 16-byte tag)
```

The chunk stream covers `padded_len(plaintext_len)` bytes: the document followed
by zeros. Padding is inside the AEAD, so it is indistinguishable from content.

### Associated data

```
AAD = "ENCINOB1" ‖ blob_id (16) ‖ chunk_index (8) ‖ is_final (1) ‖ len_field (8)

len_field = plaintext_len   on the final chunk
          = 0               on every other chunk
```

`plaintext_len` lives in an unauthenticated header, and padding is what makes
that dangerous: with slack after the document, an attacker who could re-declare
the length would silently truncate the plaintext while every chunk still
verified. Without padding there was no slack and so no such attack.

Binding the length into the final chunk's associated data closes it. Editing the
header field makes the final chunk fail to open, and no other chunk can become
final because `is_final` is bound too.

**Why only the final chunk.** The true length is unknown until the source is
exhausted. Binding it into every chunk would mean no chunk could be sealed until
the whole document had been read, which forfeits streaming — the property that
lets a multi-gigabyte document be written without materialising it in RAM. One
authenticated binding is sufficient to make the field unforgeable, and the final
chunk is the one place a streaming writer already knows it.

This is the same reasoning that put `is_final` in the associated data rather than
`chunk_count`, and it is recorded in `format.md` for the same reason.

### Writing

Unchanged up to the point the source runs dry, then:

1. `plaintext_len` is now known; compute `padded = padded_len(plaintext_len)`.
2. Zero-extend the chunk in hand, and emit further all-zero chunks, until
   `padded` bytes of plaintext have been sealed.
3. Seal the last of them with `is_final = true` and `len_field = plaintext_len`.
4. Patch `chunk_count` and `plaintext_len` into the header.

Chunking is unchanged: every chunk is full except the last. An empty document is
one 4096-byte all-zero final chunk, which preserves the existing rule that a
header-only truncation stays distinguishable from an empty document.

`BlobStats.size` and `.sha256` continue to describe the **real** plaintext, so
the index, `verify`, and every caller are untouched.

### Reading

After the existing header bounds checks:

- total decrypted plaintext must equal `padded_len(plaintext_len)`. The padding
  length is *derived* from the authenticated length, never taken from the file.
- padding bytes must be zero.
- only the first `plaintext_len` bytes are written to the output, and only those
  bytes feed the digest and the returned size.

The zero check catches no attack — an attacker cannot forge sealed padding — but
it makes the format normative and turns an implementation slip into a test
failure rather than a silently divergent vault.

`plaintext_len` is bounded before it is trusted, in the same spirit as the
existing `chunk_size` bound: a header claiming a 2⁶⁴-byte document must not
become an arithmetic overflow in `padded_len`.

## 2. The named-pipe race

### What the race actually is

```rust
ConnectNamedPipe(self.listener)        // a client attaches to the only instance
                                       // ← no instance is listening here
let served = replace(&mut self.listener, create_instance(...)?);
```

Between `ConnectNamedPipe` returning and the replacement instance existing, the
pipe name has no instance in the listening state. A client calling `CreateFileW`
in that window gets `ERROR_PIPE_BUSY`.

The client already retries on exactly that error for five seconds
(`client.rs`), which is why the fault has never been observed. But the retry is
load-bearing rather than a backstop, and a window that must be *timed* to hit is
a window that can only be tested probabilistically. That is the real complaint in
the handoff document, and it is a design problem, not a test problem.

### Fix: hold a spare instance

The server keeps two instances, `current` and `spare`, both created and both
listening. `accept` becomes:

1. `ConnectNamedPipe(current)` — returns when a client attaches, or immediately
   with `ERROR_PIPE_CONNECTED` if one attached already.
2. Serve `current`.
3. Promote `spare` to `current`.
4. Create a fresh `spare`.

At no instant is there zero listening instances: during step 4, `current` is
listening; at every other point both are. A client that attaches to the spare
while the server is still blocked in step 1 is picked up on the next `accept` by
the existing `ERROR_PIPE_CONNECTED` path, which already treats a pre-attached
client as success.

Only the very first instance carries `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the
squatter defence is unchanged: the spare is created after the name exists and
must not carry the flag.

### A latent bug on the same line

```rust
let served = std::mem::replace(&mut self.listener, create_instance(...)?);
```

`create_instance(...)?` is evaluated *inside* the `replace` call. If it fails,
the function returns early with `self.listener` still holding the handle that was
just connected to a client. The next `accept` then finds it already connected,
returns `ERROR_PIPE_CONNECTED`, and hands out a connection to a client that has
been abandoned. The restructure fixes this by creating the new instance into a
local first and mutating server state only once it has succeeded.

### Testing the invariant instead of the race

The property that makes the race impossible — *a client can always attach without
waiting* — is testable with no timing at all:

> Two clients connect back-to-back, with the server not calling `accept` between
> them. Both must succeed.

Under the current design the second client gets `ERROR_PIPE_BUSY`. Under the
spare-instance design both connect. No sleeps, no repetition counts, no
flakiness. The same assertion is repeated after an `accept` to cover the steady
state rather than only the freshly created server.

The existing `rapid_back_to_back_commands` integration test stays as a
regression net.

### Two faults found while doing this

Neither was on the open-items list; both surfaced from writing the tests.

**`encino-agent` did not declare `Win32_System_Console`.** `win.rs` uses it, but
the feature was never listed in that crate's `Cargo.toml`. It compiled only
because `rpassword` enables it and Cargo unifies features across a workspace
build. `cargo test -p encino-agent` alone fails outright, and a change to
rpassword's features would have broken the workspace build for no visible reason.
Every feature the crate's own code uses is now declared.

**`PipeServer` and `PipeConnection` were not `Send`.** A raw `HANDLE` is a
pointer type, so the auto-trait did not apply, and the server could not be moved
onto a thread. Win32 handles are process-wide kernel references and both types
own theirs exclusively, so the `unsafe impl` is sound; it is now written down
with the reasoning rather than left as an obstacle to testing.

## 3. Hibernation guidance

`mlock` and `VirtualLock` keep the master key out of the page file. Hibernation
defeats both, because it writes all of physical memory — locked pages included —
to `hiberfil.sys` or the swap device. Sleep-then-hibernate does the same after
its timer expires, which is the default on most laptops and is the case users
will actually meet.

The advice, currently written nowhere:

- Run `encino lock` before closing the lid. It is the only action that removes
  the key from memory.
- `--timer` bounds the exposure but does not eliminate it: a machine that
  hibernates while a session is live writes the key out before the timer fires.
- Full-volume encryption covers the hibernation file. BitLocker protects
  `hiberfil.sys` on Windows; on Linux the swap device must be encrypted too, as
  encrypting only the root filesystem leaves swap in the clear.

Placement, each in the voice of the document that owns it:

- `threat-model.md`, under **Memory capture** — the mechanism and why locking
  does not help.
- `strength.md`, in the numbered list of threats entropy cannot touch — the
  practical instruction, alongside the existing BitLocker item.
- `cli.md`, under `unlock` — one line pointing at the threat model, where the
  reader is already thinking about session lifetime.

## 4. Documentation

- `format.md` — the header field, the padding function, the associated-data
  change and its reasoning. Size padding moves out of "Reserved for future
  versions". Updated in the same commit as the format change, per that
  document's own rule.
- `threat-model.md`, `strength.md`, `cli.md` — hibernation, as above. The threat
  model's statement that document sizes are visible is narrowed to what remains
  visible after padding.
- `README.md` — checked for claims the format change invalidates.
- `handoff.md` — deleted.

## Testing

**Padding** (`blob.rs`):

- round trips at every interesting size, extended with the sizes padding makes
  interesting: the 4 KiB floor, either side of a Padmé bucket boundary, and an
  exact multiple of `CHUNK_SIZE`.
- `padded_len` unit tests: the floor, monotonicity, the 11.9% overhead bound,
  and known values.
- on-disk size falls into the expected bucket, and two documents of different
  but same-bucket sizes produce identically sized files. This is the property
  the feature exists for, so it is asserted directly.
- editing `plaintext_len` in the header is detected.
- shrinking `plaintext_len` to hide a suffix inside the padding is detected —
  the attack the associated-data binding exists to stop.
- a `plaintext_len` large enough to overflow `padded_len` is refused rather than
  panicking.
- every existing tamper test still passes.

**Pipe** (`pipe.rs`, Windows only): the two-clients-without-accept invariant
described above, before and after an `accept`; a request/reply round trip; a
second `PipeServer::create` on the same name failing; and a served connection
being dropped without disturbing the next client. Pipe names are made unique per
test from the process id and a counter so tests do not collide.

Not tested: that the descriptor denies other accounts. It needs a second user
account and cannot be done in-process. This is stated in the test module rather
than approximated by an assertion that would pass without proving anything.

## What stays open

**macOS.** Untested, and this work does not change that. It takes the Unix paths
throughout and should work; `mlock` limits and the absence of `XDG_RUNTIME_DIR`
are the two things to check first.

**Traffic analysis of the vault as a whole.** Padding hides an individual
document's size within its bucket. It does not hide how many documents a vault
holds, nor when they were written — `verify` and the blob store's directory
listing both still reveal the count. Hiding the count needs decoy blobs, which
is a different feature with a different cost, and is not proposed here.
