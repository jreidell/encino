# Working on encino

Orientation for anyone picking this up — what exists, how to verify it, and the
constraints that are not visible from reading the code.

For what encino *is*, read the [README](../README.md). This document is about
working on it.

## Contents

- [State](#state)
- [Layout](#layout)
- [Building and verifying](#building-and-verifying)
- [Testing on Linux from Windows](#testing-on-linux-from-windows)
- [Constraints that will bite you](#constraints-that-will-bite-you)
- [Invariants not to undo](#invariants-not-to-undo)
- [Where the reasoning lives](#where-the-reasoning-lives)
- [Open items](#open-items)

---

## State

Working and verified end to end on Windows and Linux from one source tree.

| | |
|---|---|
| Tests | 196 Windows, 197 Linux (the extra three cover Unix permissions and socket paths) |
| Lints | `clippy --workspace --all-targets -- -D warnings` clean |
| Output | a single executable, `encino`, ~1.8 MB |
| Toolchain | Rust 1.95 on Windows, 1.97 in WSL; edition 2024, needs ≥ 1.85 |
| Licence | MIT OR Apache-2.0 |
| Unsafe | 24 blocks, confined to `encino-agent/src/{win,unix,pipe}.rs` |

Every command in the CLI is implemented. There is no scaffolding, no
placeholder, and no `todo!()`.

## Layout

Three crates, **one binary**.

```
src/encino-core/     vault engine — crypto, keyring, index, blob store,
                     journal, shred, lock. #![forbid(unsafe_code)] and no
                     terminal I/O, so it is directly testable.
src/encino-agent/    session daemon and its client. All unsafe lives here.
src/encino-cli/      the `encino` command. The ONLY binary target.
```

`encino-core` and `encino-agent` are libraries compiled into `encino-cli`.

The session daemon is a **hidden `agent` subcommand** of the same executable.
`unlock` starts it by re-executing itself. There is deliberately no second
binary: nothing to install alongside, nothing to separate, and no way for two
halves to be at different versions.

## Building and verifying

```bash
cargo build --release          # target/release/encino
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

"Done" means all four pass on **both** platforms. CI enforces exactly this.

A full manual check, which catches things unit tests do not:

```bash
mkdir vault && cd vault
encino init .
encino add .
ls -a                    # only .encino should remain
encino unlock --timer 5m
encino open <name>
encino close --all
encino verify
encino lock
```

The strongest single check is to copy `encino` alone into an empty directory
and run that cycle from there. It proves the single-binary property, which is
easy to break by accident.

## Testing on Linux from Windows

Linux is a supported target, not an aspiration, so changes need testing there.
WSL is set up for it:

```bash
wsl.exe -e bash -c 'source $HOME/.cargo/env && cd /mnt/e/Projects/encino \
  && CARGO_TARGET_DIR=/tmp/enc cargo test --workspace'
```

Two details matter. WSL's distro Rust is too old for edition 2024, so a current
toolchain was installed via rustup — hence the `source $HOME/.cargo/env`. And
`CARGO_TARGET_DIR` must point somewhere outside `/mnt/e`, both because building
across the mount is slow and because it would otherwise fight the Windows
`target/`.

## Constraints that will bite you

These are the non-obvious ones. Each has cost real debugging time.

### `RUSTFLAGS` replaces `.cargo/config.toml`, it does not merge

`.cargo/config.toml` sets `-C target-feature=+crt-static` per target, which is
what makes the binary need no Visual C++ redistributable. Setting the
`RUSTFLAGS` environment variable — in a shell profile, a CI workflow, anywhere
— **discards that flag entirely**.

The only symptom is a release binary that fails to start on a machine without
the redistributable, with an unhelpful Windows error. CI asserts the release
binary imports no `vcruntime`, specifically to catch this.

Pass lint flags to the tool instead: `cargo clippy -- -D warnings`.

### `cargo test` does not build another package's binaries

It builds the binaries of the package being tested, and no others. This is why
the `agent` subcommand lives in `encino-cli` rather than `encino-agent`: the
integration tests drive a real session daemon, so the binary has to exist, and
Cargo only guarantees that for the package under test.

Do not move the binary target to `encino-agent`. Tests will pass locally, where
a stale binary is lying around, and fail on a clean clone.

### Path comparison is byte-wise, and Windows spells paths several ways

`Path::starts_with` and `strip_prefix` compare components byte for byte.
Windows offers 8.3 short names (`C:\Users\RUNNER~1\…` for `runneradmin`,
which GitHub's runners use) and case-insensitive but case-preserving paths.
Two spellings of the same directory therefore fail containment checks silently.

Resolve paths with `fsutil::canonical` before comparing them. Anything that
takes a caller-supplied path and compares it against the vault root needs this.

### Public items need doc comments

`encino-core` sets `#![warn(missing_docs)]`, and CI denies warnings. Removing a
`///` on a public item compiles locally with a warning and then fails CI.

### Line endings and the vendored word list

`.gitattributes` normalises the tree to LF and marks
`src/encino-core/wordlists/eff_large_wordlist.txt` as `-text`.

That file's SHA-256 is recorded in its README so a reader can verify the copy
against EFF's published file. Line-ending conversion changes every one of its
7,776 lines and makes that verification fail. Do not remove the `-text` rule.

## Invariants not to undo

Changing any of these silently weakens the tool. Each is commented at the site,
but they are collected here because they are easy to "simplify" without seeing
the consequence.

**Blob ids are random, not content-derived.** Content addressing would give
identical documents identical names, revealing duplicates and letting an
attacker confirm a guessed document by hashing a candidate.

**Chunk associated data binds a final-chunk flag.** The blob header is not
authenticated, so an attacker can edit the chunk count. Without the flag,
dropping the last chunk and decrementing the count yields silent truncation
where every surviving chunk still verifies. Every blob therefore holds at least
one chunk, so a header-only truncation is distinguishable from an empty
document.

**The vault lock is a held file handle, not a marker file.** Windows share
modes and Unix `flock` both tie the lock to an open handle, so the kernel
releases it however the process dies. A leftover `work.lock` grants nothing.
There is deliberately no timeout and no `--force`.

**The lock is taken before the index is read.** Reading first leaves a window
in which another session replaces the index in between — which is a lost
update, and because content keys live inside index entries, a lost update
destroys documents rather than merely reordering history.

**Every failure to authenticate returns one error.** Wrong passphrase, altered
ciphertext, and wrong associated data are indistinguishable to the caller. Do
not add a more "helpful" error that tells an attacker which input was wrong.

**`add` shreds originals only inside the vault folder.** Files imported from
elsewhere are copied and left alone unless `--move` is given and confirmed.
`encino add .` from the wrong directory would otherwise destroy that directory.

**Standard handles are marked non-inheritable before the daemon starts.**
Otherwise the daemon inherits the CLI's stdout, holds it open for the session,
and any caller capturing output blocks until the session expires.

## Where the reasoning lives

- [format.md](format.md) — the on-disk format, in enough detail to audit or
  reimplement. Any format change needs this updated in the same commit.
- [threat-model.md](threat-model.md) — what encino defends against and, more
  importantly, what it does not.
- [strength.md](strength.md) — cryptographic parameters, entropy maths, and
  passphrase guidance, with the commands to re-derive every figure.
- [cli.md](cli.md) — every command and switch, including behaviour `--help`
  cannot convey.
- [SECURITY.md](../SECURITY.md) — reporting policy and what is in scope.

## Open items

Nothing is broken. These are known gaps.

**macOS is untested.** It takes the Unix paths throughout and should work, but
nothing has been run there. The two things to check first are `mlock` limits
and the absence of `XDG_RUNTIME_DIR` — the temp-directory fallback covers the
latter, but it deserves a real run.

**The named-pipe race has a probabilistic test.** `rapid_back_to_back_commands`
fires twenty commands in sequence and passes, but a timing race cannot be
proven absent by testing. If session commands ever fail intermittently on
Windows with `ERROR_PIPE_NOT_CONNECTED`, start there.

**Hibernation guidance is one line.** The threat model notes that `mlock` and
`VirtualLock` do not survive hibernation, since it writes all of RAM to disk.
The practical advice — lock before closing the lid, and BitLocker covers
`hiberfil.sys` — is not written down anywhere and probably should be.

**Size padding is unimplemented.** Document count and approximate sizes are
visible to anyone with the disk. The format carries a version field so padding
can be added later; see the reserved section of `format.md`.

**The Win32 FFI is the least-tested code.** Roughly 200 lines across
`win.rs`, `unix.rs` and `pipe.rs`, holding all 24 `unsafe` blocks. It is
exercised by the integration tests but has no unit tests of its own, and it is
the first place to look for a subtle bug.
