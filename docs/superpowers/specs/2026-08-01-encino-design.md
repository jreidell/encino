# encino — design

Date: 2026-08-01
Status: approved, in implementation

## Problem

A folder of sensitive personal documents — financial statements, tax records —
sits in plaintext on a Windows machine. A stolen laptop, a leaked backup, a
cloud-sync copy, or another account on the same box exposes all of it. We want a
local tool that makes such a folder unreadable, contents *and* filenames, to
anyone without a secret.

No network component, no service, no account. One binary, one machine.

The precise boundaries of the guarantee are in [threat-model.md](../../threat-model.md);
the on-disk format is specified in [format.md](../../format.md).

## Decisions and rationale

### Per-file checkout, not whole-folder lock/unlock

Encrypted is the resting state. `open <doc>` decrypts one document into the
vault folder's root; `close` re-encrypts and shreds it.

The alternative — lock and unlock the whole folder — fails for a human reason
rather than a cryptographic one: its security depends on the user remembering to
re-lock, every time, forever. Unlock to fetch a W-2 in April, get distracted, and
the folder sits in plaintext until August. That design makes "insecure" the state
you drift into. Per-file checkout inverts it.

Three supporting reasons: reading one statement should not expose all forty-seven
(blast radius); whole-folder cycles rewrite everything, so an interruption
mid-cycle has a large window to leave damage; and a folder that flips wholesale
between plaintext and ciphertext leaks plaintext revisions into a sync provider's
version history, where the user cannot delete them.

Bulk access is preserved as `open --all` — a *scope argument to the same verb*,
not a second mode. One on-disk format, one code path, no per-vault mode flag to
reason about. It carries an auto-close timer so the forgot-to-re-lock failure
cannot recur.

### `unlock` authenticates; `open` exposes

These are separate verbs because they are separate ideas. `unlock` derives the
key and starts a session, writing nothing to disk. `open` is the only thing that
puts plaintext on the filesystem. Keeping authentication and exposure independent
is also the property a future filesystem mount needs.

### Random master key, wrapped twice

The master key is 32 random bytes, never derived from the passphrase. An
Argon2id-derived key from the passphrase wraps it; a key derived from a 24-word
BIP39 recovery code wraps it independently.

Rotating the passphrase then rewraps the master key and rewrites one small file
instead of re-encrypting every document. The recovery code is the only way back
from a forgotten passphrase — and, as the threat model notes, is exactly as
sensitive as the passphrase itself.

### Blobs in `.encino/`, root as work area

The vault folder's root holds nothing but `.encino` when locked, so anything
visible in the root is by definition decrypted. Exposure is legible at a glance,
and `encino status` has an obvious ground truth to report.

Rejected: encrypting files in place, which preserves and thus leaks the directory
tree shape and mixes plaintext with ciphertext in one directory.

### Rust

Single static binary with no runtime to install, mature audited crypto crates,
and — the deciding factor — `zeroize`/`secrecy` for scrubbing key material from
memory. Go and .NET both have garbage collectors that copy values, so secrets
linger in RAM beyond the program's control. For a tool whose entire job is key
custody, that is disqualifying.

### Engine library, thin CLI

`encino-core` holds the dangerous surface — crypto, index, journal — and performs
no terminal I/O. The CLI owns prompting and output and nothing else.

This is not ceremony. It means the risky code is directly testable without
driving a UI, and it means a GUI or a WinFsp mount later is an additional
front-end rather than a refactor of crypto code under pressure. Getting the
durable layer right and keeping the surface swappable is the same reasoning that
drove the format decisions.

### Background session agent

Argon2id is about a second by design, so prompting on every command is not merely
annoying — it pushes the user toward `open --all` to avoid the friction, which
defeats the access model. The agent holds the key in locked, non-swappable
memory, never writes it to disk, and expires on a timer.

Rejected: a DPAPI-sealed session file, which puts key material on disk guarded
only by the Windows account being intact.

## Command surface

```
encino init <folder>              create vault; set passphrase; print recovery code
encino add <path>...              import file/folder into the vault (recursive)
encino ls [--json]                list documents
encino open <path>... [--with]    materialize plaintext; --with launches default app
encino open --all [--timer 30m]   bulk checkout, auto-closes on expiry
encino close <path>... | --all    re-encrypt and shred plaintext
encino status                     session state, open files, time remaining
encino lock                       close everything, stop agent, zeroize
encino passwd                     rotate passphrase (rewraps master key only)
encino recover                    unlock via recovery code
encino verify                     authenticate every blob against the index
encino export <dest>              decrypt entire vault to a directory
```

`export` exists so the vault is never a roach motel. A user must always be able
to walk away with their documents.

## Structure

```
src/encino-core/     crypto, keyring, index, blob store, journal, shred
src/encino-agent/    named-pipe server, locked-memory key custody
src/encino-cli/      clap front-end; prompting and output only
```

## Build sequence

Each milestone ends in a working, tested state.

1. Workspace, format spec, threat model.
2. Keyring: Argon2id calibration, master key, dual wrapping, recovery code.
3. Blob store and encrypted index; `add`, `ls`.
4. Checkout: `open`, `close`, journal, crash recovery, shred.
5. Session agent: named pipe with restricted DACL, locked memory, expiry.
6. Bulk operations and integrity: `open --all`, `verify`, `export`.

## Verification

Known-answer tests against published vectors for Argon2id and
XChaCha20-Poly1305, confirming we call the primitives correctly — something tests
of our own code cannot establish. Round-trip property tests across chunk
boundaries and hostile filenames. Tamper tests asserting that any flipped byte
fails authentication rather than yielding wrong plaintext. Crash injection at
every journal checkpoint, asserting recovery leaves the old state or the new one
and never a half-written or lost document. Wrong-credential tests confirming
failures do not reveal *which* input was wrong.

The recovery-code path gets a real end-to-end test. An untested recovery path is
the same as no recovery path.

## Deferred

Size padding (format is versioned for it), multiple vaults under one agent, and
the GUI and WinFsp mount — the latter being the reason `encino-core` is a
library.
