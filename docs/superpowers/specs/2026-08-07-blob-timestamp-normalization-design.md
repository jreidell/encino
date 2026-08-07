# Normalizing blob timestamps

Blob files carry the time each document last changed. That is an activity
timeline for the vault, readable from a directory listing with no credential,
and it survives into every backup taken of the folder.

This closes it for the threat it most affects, and states plainly where it does
not reach.

## Contents

- [The leak](#the-leak)
- [Why this and not the document count](#why-this-and-not-the-document-count)
- [Design](#design)
- [What must not be normalized](#what-must-not-be-normalized)
- [Mechanics](#mechanics)
- [What this does not close](#what-this-does-not-close)
- [Error handling](#error-handling)
- [Testing](#testing)
- [Documentation](#documentation)
- [What stays open](#what-stays-open)

## The leak

A blob is written once and never modified: an edited document is stored under a
fresh random blob id and the old blob is deleted. So a blob's mtime is exactly
when that document last changed.

Observed on a vault holding three documents, one of which was then edited:

```
$ find .encino/blobs -type f -printf "%TH:%TM:%TS  %s bytes\n" | sort
04:59:57.4087656000  4164 bytes
04:59:57.4278020000  4164 bytes
05:00:01.7683028000  4164 bytes
```

Padding is doing its work — all three are identical in size regardless of their
contents. The timestamps undo a good deal of it. Two documents were imported
together; one was changed four seconds later. Nothing here required the
passphrase.

Repeated over the snapshots a backup or sync provider accumulates, this yields a
working pattern: which days the vault was touched, how many documents changed
each time, and which changed together. That is the class of information the
encrypted index exists to hide, leaking around it through the filesystem.

## Why this and not the document count

The count was the leak on the roadmap; `format.md` reserved it for a future
version and proposed decoy blobs. Examined properly, it is the weaker of the two
and the more expensive to close.

Decoys buy a *bucketed* count rather than concealment, and they introduce a new
problem: decoy sizes must plausibly match real ones, or an attacker separates
them and recovers the exact count, leaving the feature doing nothing. They also
leak at bucket transitions.

The alternative — packing every blob into one container file — hides the count
outright and would take access times with it, but it reintroduces the failure
the per-blob layout exists to avoid. Every change would rewrite the container,
so a sync provider re-uploads the whole vault on each `close` and retains a
version of it. The threat model designs explicitly for the leaked-backup case;
that trade moves the tool backwards in it.

Timestamps, meanwhile, are the sharper leak, and normalizing them is contained,
cheap, and needs no format change. This is the better use of the effort.

## Design

Every blob file is stamped with a fixed time — `2001-01-01T00:00:00Z` — for both
mtime and atime, set immediately after `sync_all` in `write_blob`.

A constant rather than the vault's `created` time, which would add per-vault
variation for nothing, and not the Unix epoch, which some backup tools treat as
a missing or damaged timestamp.

That the value is obviously synthetic costs nothing. encino is open source and
the blob store's shape already identifies the tool; the secret was never *that*
timestamps are normalized, only *when each document changed*.

**Directories are in scope too.** Normalizing files alone is insufficient:
`blobs/0f/` updates whenever a blob is added to or removed from that shard, and
with 256 shards and few documents that is nearly per-document granularity. So:

| Path | Normalized when |
|---|---|
| `blobs/<xx>/<blob id>` | after the blob is written |
| `blobs/<xx>/` | after a blob is written **or removed** in it |
| `blobs/` | after a shard directory is created |

Removal matters as much as writing. Deleting a superseded blob during check-in
bumps its shard's mtime, so `remove_blob` must restamp the parent.

## What must not be normalized

`index.enc` and `vault.json` are deliberately excluded, and the reason is the
same property that makes this safe for blobs.

Blobs are immutable and randomly named: a changed document produces a new file
rather than a rewritten one, so backup and sync tools detect the change by name
and a constant mtime breaks nothing.

`index.enc` is the opposite. It is replaced in place, keeping its name and
sometimes its size. A tool that decides what to copy from name, size, and mtime
could silently skip a changed index — and the index is the single point of total
failure for the vault. Losing it loses every document.

The leak this leaves is that the vault was touched at some time, which is far
weaker than a per-document timeline, and not worth risking a backup that quietly
omits the one file nothing can be recovered without.

Journal and staging files are transient and absent at rest. Left alone.

## Mechanics

`std` offers no way to set a file's times. Unix could use `rustix`, already a
dependency, but Windows needs `SetFileTime`, and `encino-core` is
`#![forbid(unsafe_code)]`. `encino-agent` holds the project's FFI but depends on
core rather than the reverse, so it cannot serve.

`encino-core` therefore gains the `filetime` crate. It adds exactly one crate to
the tree: its only dependencies are `cfg-if` and `libc`, both already present,
and it declares no `windows-sys`, carrying its own Win32 externs. 141 crates
becomes 142.

The `unsafe` moves into a dependency rather than disappearing. That is the
trade, and it is the right one: the alternative is hand-rolled FFI inside the
crate that holds all the cryptography, in exchange for dropping the strongest
structural guarantee it makes.

## What this does not close

**On Unix, ctime cannot be set by any userspace call.** Setting mtime updates
ctime as a side effect. An attacker with raw filesystem access still reads when
each blob was written, and no amount of care changes that.

Verified:

```
$ echo x > f && sleep 1.2 && touch -d "2001-01-01 00:00:00" f
$ stat -c "mtime=%y%nctime=%z" f
mtime=2001-01-01 00:00:00.000000000 -0500
ctime=2026-08-07 05:07:00.506052761 -0400
```

On Windows all three times are settable, so the leak is fully closed there.

This still lands where it matters most. `tar`, `zip`, and effectively every
backup format carry mtime and discard ctime — so a leaked backup or a synced
copy, the case where an observer sees the vault repeatedly over time, arrives
with normalized timestamps and no timeline. The raw-disk case on Unix retains
it.

The documentation must say this rather than claim access times are hidden.

## Error handling

Best-effort and non-fatal. A filesystem that refuses a timestamp set — an
unusual network share, a read-only mount — must not fail the import. The
document is correctly and durably stored either way; the timestamp is a privacy
property, not a correctness one.

The risk this accepts is silent non-delivery, and it is the reason `verify`
reports any blob left carrying a real timestamp. Every other property here fails
loudly at the time; this one can simply not happen, so it needs something that
looks. On a filesystem that cannot set times that report is correct rather than
noise — the privacy property genuinely is not held.

## Testing

- a written blob carries exactly the constant mtime
- two blobs written seconds apart carry **identical** mtimes
- a shard directory is normalized after a write, and again after a removal
- lifecycle: import three documents, edit one, check it in, and assert every
  blob mtime is identical — the regression test for the leak as observed above

## Documentation

- `format.md` — "Hiding access times" leaves the reserved list, replaced by a
  description of what is normalized and the ctime limit
- `threat-model.md` — the Assets table's `Access times | **No**` becomes a
  qualified yes, with the Unix ctime caveat stated
- `README.md` — a line in the platform table

No `format_version` bump. Timestamps are not part of the on-disk format and a
version 1 reader never consults them.

## What stays open

**The document count remains visible**, for the reasons above. It stays on the
reserved list in `format.md`.

**ctime on Unix**, as described. There is no fix for this short of not touching
the filesystem, which is not available to a tool that stores files.
