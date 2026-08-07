# encino

A local encrypted vault for a folder of sensitive documents. Contents *and*
filenames are encrypted at rest; documents are checked out one at a time and
re-encrypted when you are done.

No network, no service, no account. One binary on one machine.

```
encino init C:\Docs\Financial     # set a passphrase, save the recovery code
encino add .                      # import documents; originals are shredded
encino unlock                     # start a session (nothing is written to disk)
encino open 2024-w2.pdf           # decrypt just this one document
encino close 2024-w2.pdf          # re-encrypt and shred the plaintext
encino lock                       # end the session, forget the key
```

When locked, the folder contains nothing but an opaque `.encino` directory.
Anything visible in the folder root is, by definition, currently decrypted.

## Contents

- [How it works](#how-it-works)
- [Before you trust it with anything](#before-you-trust-it-with-anything)
- [Choosing a passphrase](#choosing-a-passphrase)
- [Command reference](#command-reference) — [global options](#global-options),
  [exit codes](#exit-codes), [durations](#durations), [scripting](#scripting)
- [Vaults on a network share](#vaults-on-a-network-share)
- [If a session will not stay open](#if-a-session-will-not-stay-open)
- [Building](#building) · [Platforms](#platforms) · [Layout](#layout)
- [Contributing](#contributing) · [License](#license)

Deeper reference lives in `docs/`: the [on-disk format](docs/format.md), the
[threat model](docs/threat-model.md), and [how strong this is](docs/strength.md)
— cipher parameters, entropy maths, and how many words a passphrase needs.

## How it works

A random 256-bit master key encrypts everything. Your passphrase never encrypts
a document directly — it derives a key (Argon2id) that *wraps* the master key, so
changing your passphrase rewrites one small file instead of re-encrypting your
documents. A 24-word recovery code wraps the same master key independently.

Each document gets its own content key and is stored as a blob under a **random**
name — not a hash of its contents, which would reveal when two documents are
identical. Filenames and folder structure live only in an encrypted index, so the
blob store is flat.

Blobs are padded, so their sizes fall into buckets rather than tracking the
documents they hold: every document under 4 KiB is exactly the same size on disk,
and above that the padding costs at most 12%. What an observer with the disk
learns is how many documents you have and roughly which bucket each falls in —
enough to tell a note from a scan, not enough to confirm a document by its size.

Full details in [docs/format.md](docs/format.md).

## Before you trust it with anything

Read [the threat model](docs/threat-model.md). Four things especially:

**Run encino on a BitLocker-encrypted volume.** Shredding cannot guarantee
erasure on an SSD — wear levelling means overwriting a logical block does not
reliably erase the physical one. Volume encryption is the real mitigation.

**Lock before the machine hibernates.** Hibernating writes all of memory to
disk, including the locked pages holding the master key. Closing a laptop lid is
enough, since sleep escalates to hibernation on a timer. `encino lock` is the
only thing that removes the key from memory; whole-volume encryption covers the
hibernation file for the times you forget.

**The recovery code is as sensitive as the passphrase.** It opens the vault
outright. Losing both means the documents are gone permanently: no backdoor, no
reset, no support path.

**This protects against a stolen laptop, a leaked backup, a synced cloud copy, or
another account on the machine.** It does not protect against malware running as
you while the vault is unlocked. That is the fundamental limit of at-rest
encryption, and no design here changes it.

This has not been independently audited.

## Choosing a passphrase

Your passphrase is the only part of this design a human picks, which makes it
the only part with any slack. The master key, the per-document keys, and the
recovery code are all 256 bits of machine randomness. Nobody attacks the cipher;
they attack the passphrase.

```
encino passphrase              # six words, ~77 bits
encino passphrase --words 8    # ~103 bits
```

Fewer than five words is allowed but flagged, because the gap is stark:

| Words | Entropy | Expected time to crack¹ |
|---|---|---|
| 2 | 26 bits | ~50 minutes |
| 3 | 39 bits | ~9 months |
| 4 | 52 bits | ~5,700 years |
| 5 | 65 bits | ~44 million years |
| 6 | 78 bits | beyond meaningful measure |

¹ At ~10,000 guesses/sec against this vault's Argon2id parameters — roughly
twenty high-end GPUs. Memory-hardness is what keeps that rate so low; against a
fast hash it would be billions per second and even five words would fall.

Take the suggestion as it came: swapping a word you dislike or reordering them
into something that reads nicely throws away the randomness that makes it strong.

Words are drawn with the OS random source from
[EFF's Long Wordlist](https://www.eff.org/dice) (7,776 words, 12.925 bits each),
compiled into the binary. Rolling five dice against the printed list is just as
good and trusts nothing at all.

Self-invented passphrases are the trap: length is no defence, because people
draw from a far smaller space than they think and attackers model that space
well. A memorable six-word phrase may carry twenty-odd bits where a random one
carries seventy-odd.

Substituting `@` for `a` and `3` for `e` adds **nothing** if the rule is
predictable — password crackers have applied leet rules by default for twenty
years. Adding a word beats it on every axis. The reasoning, with measured
numbers, is in **[docs/strength.md](docs/strength.md)**, along with the dice
method, the cipher parameters, and why recovery codes use a different word list.

## Command reference

Every command and switch, including the behaviour `--help` cannot convey.

```
encino init <folder>              create vault; set passphrase; print recovery code
encino passphrase [--words N]     suggest a strong passphrase; changes nothing
encino add <path>...              import files or folders (recursive)
encino ls [--json]                list documents
encino open <name>... [--with]    decrypt; --with opens in the default app
encino open --all [--timer 30m]   decrypt everything, auto-close on expiry
encino close <name>... | --all    re-encrypt and shred the plaintext
encino unlock [--timer 30m]       start a session so later commands do not prompt
encino status                     session state, what is decrypted, time left
encino lock                       close everything and forget the key
encino passwd                     change the passphrase
encino recover                    unlock with the 24-word recovery code
encino verify                     authenticate every stored document
encino export <dest>              decrypt the whole vault to a folder
```

There is one command not listed. `agent` runs the session daemon and is hidden
from `--help`, because it is plumbing rather than something to type: `unlock`
re-executes this same binary with it, which is what lets encino be one file. Run
by hand it does nothing useful, since it waits on stdin for a master key only
`unlock` can supply.

### Global options

Accepted by every command, though not every command uses them.

#### `-C <FOLDER>`, `--vault <FOLDER>`

The vault to operate on. Defaults to the current directory.

```
encino -C C:\Docs\Financial ls
```

**Two exceptions worth knowing**, because `--help` lists this flag everywhere:

- **`init` ignores it.** That command takes the folder as its own argument, so
  `encino -C A init B` creates the vault at `B` and does nothing to `A`.
- **`passphrase` has no use for it.** It touches no vault at all.

**It does not affect how other paths are resolved.** Arguments to `add` and
`export` resolve against your *working directory*, not against `-C`. So

```
cd C:\Elsewhere
encino -C C:\Docs\Financial add .
```

imports the contents of `C:\Elsewhere`. Prefer `cd`-ing into the vault.

#### `--passphrase-stdin`

Read passphrases and yes/no answers from standard input instead of prompting.

Without it, any command needing a secret refuses to run unless standard input is
a terminal — so a redirected file or pipe is never mistaken for a typed
passphrase. See [Scripting](#scripting).

A piped passphrase can end up in shell history, a script file, or a process
listing. Type it when a human is present.

#### `-h`, `--help` · `-V`, `--version`

`-h` gives a summary; `--help` gives the full text including the longer notes.
Works per command: `encino open --help`. `-V` prints the version and exits,
reading and writing nothing.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Anything else — wrong passphrase, vault in use, a document that would not open, `verify` finding problems |

Commands that act on several documents report each failure individually and
still exit `1` if any failed, so a partial success is never reported as success.

### `init`

```
encino init <FOLDER>
```

Creates a vault and sets its passphrase. The folder is created if it does not
exist, and may already contain documents — they are left alone until you `add`
them.

Prints a 24-word recovery code **once**, and asks you to confirm you have written
it down. It is not stored anywhere and cannot be shown again.

Calibrates Argon2id to about one second on the machine doing the work, then
records those parameters in the vault, so the cost is right for your hardware
and the vault stays openable later.

Refuses if a vault already exists there, so a mistyped repeat cannot destroy
your keys.

**Arguments**

- `<FOLDER>` — required. Relative paths resolve against the working directory.

### `passphrase`

```
encino passphrase [--words N]
```

Suggests a passphrase drawn from EFF's Long Wordlist using the operating
system's random source. **Touches no vault, saves nothing, changes nothing** —
it works before you have created a vault.

Prints exactly one suggestion and never a menu: picking a favourite from several
is a human choice layered over a random one, which is what machine selection
exists to prevent.

The passphrase goes to **stdout** and everything else to **stderr**, so
`encino passphrase > file` gives a clean file while any warning still reaches
you.

**Options**

- `--words <N>` — how many words. Default `6` (~77 bits). Accepts `2`–`24`.
  Below `5` it still produces one but warns, with how long it would take to
  crack. One word is refused outright.

See [Choosing a passphrase](#choosing-a-passphrase) for why this matters, and
[docs/strength.md](docs/strength.md) for the numbers.

### `add`

```
encino add <PATHS>... [--keep] [--move]
```

Imports files and folders, encrypting them into the vault. Folders are walked
recursively. The vault's own `.encino` directory is never descended into.

**How documents are named.** A document's name is its path relative to the folder
you named, so the named folder becomes the top of the imported tree — the same
rule as `cp -r`:

```
encino add C:\Archive\taxes    ->  taxes/2023/w2.pdf, taxes/2024/w2.pdf
encino add C:\Archive\w2.pdf   ->  w2.pdf
encino add .                   ->  paths as they sit in the vault folder
```

Files already inside the vault keep their position in it, so `add .` after
dropping documents into the folder preserves whatever structure you put there.

**What gets destroyed.** By default, originals are shredded **only if they were
already inside the vault folder**. Anything imported from elsewhere is copied in
and left where it was, and encino says which happened.

That default is deliberate, and it matters more than it sounds: `encino add .`
run from the wrong directory would otherwise shred every file in that directory,
with nothing to alert you until you went looking for something.

**Options**

- `--keep` — leave every original in place, including those inside the vault.
- `--move` — also shred originals outside the vault folder. Lists what it is
  about to destroy and asks first.

`--keep` and `--move` are mutually exclusive.

**Arguments**

- `<PATHS>...` — files or folders. Resolved against the working directory.

A name that already exists is refused, as is one differing from an existing
document only by case — so a vault written on Linux stays openable on Windows
and macOS.

### `ls`

```
encino ls [--json]
```

Lists the documents held, ordered by name, with sizes and a total. Anything
currently decrypted is marked `DECRYPTED`. Sizes shown are the documents' real
sizes, not their padded sizes on disk.

**Options**

- `--json` — machine-readable output instead of a table. Each entry carries
  `path`, `size`, `sha256`, `modified`, `added` and `open`.

### `open`

```
encino open <PATHS>... [--with]
encino open --all [--timer <DURATION>] [--with]
```

Decrypts documents into the vault folder, where they stay until you `close`
them. Subfolders are recreated as needed.

Plaintext is staged inside `.encino` and moved into place only once it
decrypts and matches the digest recorded in the index, so a failure never leaves
a partial document that looks whole.

**Options**

- `--all` — check out every document. Mutually exclusive with naming paths. When
  more than one document is involved it asks for confirmation first, since the
  whole vault becomes readable to anything running as you.
- `--timer <DURATION>` — re-encrypt everything automatically after this long.
  **Requires a running session**: the agent performs the auto-close, so without
  one there is nothing to do it later and encino says so rather than implying
  a timer that will never fire. Start a session with [`unlock`](#unlock) first.
- `--with` — launch each document in its default application after decrypting.

**Arguments**

- `<PATHS>...` — document names as shown by `ls`, using forward slashes.

Opening a document that is already open is refused.

### `close`

```
encino close <PATHS>...
encino close --all
```

Re-encrypts documents and shreds their plaintext.

A document that comes back byte-for-byte unchanged keeps its existing
ciphertext — reading a statement and closing it again costs no re-encryption.
One that was edited is re-encrypted under a fresh key and its old ciphertext is
removed.

Empty folders left behind are tidied away, so the vault folder returns to holding
nothing but `.encino`.

**Options**

- `--all` — check in everything currently open. Mutually exclusive with naming
  paths.

If any document cannot be closed, the command says which and exits `1` — its
plaintext is still on disk.

### `unlock`

```
encino unlock [--timer <DURATION>]
```

Starts a session so later commands do not prompt again. Derives the key once —
Argon2id is deliberately about a second — and hands it to a background agent
that holds it in memory locked out of swap.

**Writes nothing to disk and decrypts nothing.** Authentication and exposure are
separate: `unlock` proves who you are, `open` is the only thing that puts
plaintext on the filesystem.

If a session is already running it says how long remains and does nothing else.

**Options**

- `--timer <DURATION>` — how long the session lasts. Default `30m`, maximum
  `12h`. On expiry the agent re-encrypts anything still open before forgetting
  the key.

**Lock before the machine hibernates.** Hibernation writes all of memory to disk,
including the locked pages holding the key, and a timer still running does not
help. See [the threat model](docs/threat-model.md).

### `status`

```
encino status
```

Reports the vault path, whether a session is open and how long it has left, how
many documents are held, and — loudly — anything currently decrypted.

Works without a session, in which case it reports `locked` and stops there
without asking for a passphrase.

### `lock`

```
encino lock
```

Closes everything still open, stops the agent, and forgets the key.

Documents are re-encrypted *before* the key is dropped, since re-encrypting them
needs it. If any cannot be closed, the session is deliberately left open and the
command exits `1` — locking would otherwise leave plaintext on disk with no way
to re-encrypt it short of entering the passphrase again.

Safe to run when no session exists; it does nothing and succeeds.

### `passwd`

```
encino passwd
```

Changes the passphrase. Asks for the current one, then the new one twice.

Rewrites only the wrapped master key, so **no document is re-encrypted** however
many the vault holds. Your recovery code is unchanged and still works.

### `recover`

```
encino recover
```

Opens the vault with the 24-word recovery code instead of the passphrase, and
offers to set a new passphrase.

The code is read with echo on — it is transcribed from paper, and twenty-four
words typed blind is how a recovery fails at the worst moment. Spacing and case
do not matter; the BIP39 checksum catches transcription errors before anything is
attempted.

Declining to set a new passphrase changes nothing.

### `verify`

```
encino verify
```

Authenticates every stored document against the index: confirms each blob is
present, its key unwraps, it decrypts, and its digest matches what was recorded.
Also reports stored blobs no document refers to.

Reads everything in the vault, so it takes time proportional to total size.
Exits `1` if anything is wrong.

### `export`

```
encino export <DEST>
```

Decrypts the whole vault into a directory, preserving folder structure. The vault
is left untouched.

Asks for confirmation, because the result is plain readable files that encino
no longer protects.

**Arguments**

- `<DEST>` — must be empty or not yet exist.

This exists so a vault is never a one-way door. Worth running once on a test
vault to prove you can always walk away with your documents.

### Durations

Used by `--timer`.

| Form | Meaning |
|---|---|
| `90s` | seconds |
| `30m` | minutes |
| `2h` | hours |
| `45` | a bare number means **minutes** |

Case-insensitive, and longer spellings work (`30 minutes`, `2 hours`). Minimum
one second, maximum twelve hours — a session outliving the working day defeats
the point of having one.

### Scripting

With `--passphrase-stdin`, secrets and confirmations are read from standard input
in the order the command asks for them:

| Command | Lines expected |
|---|---|
| `init` | passphrase, passphrase again, `y` |
| `passwd` | current passphrase, new, new again |
| `recover` | recovery code, `y` or `n`, then new passphrase twice if `y` |
| `open --all` (more than one document) | passphrase, `y` |
| `export` | passphrase, `y` |
| everything else needing a key | passphrase |

Commands served by a running session need no passphrase line at all.

```bash
printf 'my-passphrase\n' | encino --passphrase-stdin ls
printf 'my-passphrase\ny\n' | encino --passphrase-stdin export ./out
```

Without `--passphrase-stdin`, these commands refuse to run when standard input is
not a terminal, rather than risk reading a passphrase from whatever happens to be
piped in.

## Vaults on a network share

Works on a UNC path or a mapped drive, and a vault is portable between them —
`Z:\Docs` and `\\server\share\Docs` reach the same vault interchangeably.

One session may hold a vault at a time. A second is refused and told who has it:

```
Error: \\server\share\Financial is in use by process 8412 on DESKTOP-ABC
```

That refusal is doing real work. Sessions replace the index wholesale, and each
document's content key lives inside its index entry — so two concurrent writers
would mean the later save destroying the earlier one's key, leaving an
undecryptable blob and a shredded original. The document would be gone.

The lock is a held file handle, not a marker file, so a crash or a dropped
connection releases it immediately. A leftover `.encino/work.lock` is not a stale
lock and needs no cleaning up.

**Shredding is close to meaningless on a share**, because overwrites go to the
server, where snapshots and backups keep the originals. See
[the threat model](docs/threat-model.md) for the rest.

## If a session will not stay open

encino writes no logs. The session agent runs detached with its output
discarded, so when it dies unexpectedly there is nothing to look at.

Set `ENCINO_AGENT_DEBUG` to anything other than `0` or empty to turn on
diagnostics for as long as you need them:

```powershell
$env:ENCINO_AGENT_DEBUG = "1"
encino unlock
# reproduce the problem, then:
Get-Content "$env:LOCALAPPDATA\encino\agent.log"
Remove-Item Env:\ENCINO_AGENT_DEBUG
```

**Off by default, and nothing is written when off** — no file is created and no
panic hook is installed. When on, failures plus the agent starting and stopping
are appended to:

- Windows — `%LOCALAPPDATA%\encino\agent.log`
- Unix — `$XDG_STATE_HOME/encino/agent.log`, or `~/.local/state/encino/agent.log`

It records no key material, no passphrase, no document names and no vault
contents, and lives outside the vault so it cannot become metadata attached to
your encrypted folder.

It is off by default because when a session ran is a record of when you worked
with your documents — the sort of thing the encrypted index exists to hide. Turn
it on while investigating, then turn it off.

## Building

```
cargo build --release      # target\release\encino.exe
cargo test --workspace
```

**One file is the whole installation.** Copy `encino.exe` anywhere and run it.
Nothing beside it, no installer, no registry, no config — everything else lives
in the vault folder.

The session daemon is a hidden `agent` subcommand of that same binary, which
`unlock` starts by re-executing itself. So there is no second file to lose,
separate, or leave at a different version.

**There is no runtime to install and no redistributable.** `.cargo/config.toml`
links the C runtime statically, so the binary imports nothing but Windows
itself:

```
kernel32.dll  ntdll.dll  advapi32.dll  bcryptprimitives.dll  dbghelp.dll
api-ms-win-core-synch-l1-2-0.dll
```

Without that, Rust's MSVC target pulls in `vcruntime140.dll` from the Visual C++
redistributable — present on most machines, guaranteed on none, and when absent
the program simply fails to start with an unhelpful error. Static linking costs
about 100 KB per binary and removes the failure mode entirely.

### Platforms

Windows and Linux, from the same source. macOS should work — it takes the Unix
paths throughout — but has not been tested.

Everything is verified on both: 218 tests on Windows, 212 on Linux. The
difference is not coverage but platform: the Windows-only tests cover named
pipes and SIDs, the Linux-only ones file permissions, socket paths, and the
peer-credential check on an accepted connection.

The platform differences are confined to these, and each takes the same shape on
both systems:

| | Windows | Unix |
|---|---|---|
| Vault lock | file opened denying write sharing | `flock(LOCK_EX \| LOCK_NB)` |
| Agent transport | named pipe, DACL'd to your SID | `0600` socket in a `0700` directory |
| Who may connect | the DACL, plus remote clients refused | the directory, plus `SO_PEERCRED` on Linux |
| Key kept out of swap | `VirtualLock` | `mlock` |
| Blob timestamps | normalized, creation time included | normalized; `ctime` not settable |

The lock relies on the same property on both: it is a *held handle*, so the
kernel releases it when the process dies and there are no stale locks to clear.

Windows x86-64 by default, with `aarch64-pc-windows-msvc` configured for static
linking too. On Linux, `--target x86_64-unknown-linux-musl` gives an equally
self-contained binary.

## Layout

```
src/encino-core/    vault engine: crypto, index, blob store, journal
src/encino-agent/   session daemon and its client
src/encino-cli/     the encino command — the only binary
docs/               on-disk format, threat model, strength analysis
```

Three crates, one executable. `encino-core` and `encino-agent` are libraries
compiled into `encino-cli`, which produces the single `encino` binary.

`encino-core` forbids `unsafe` and does no terminal I/O, so the risky code is
directly testable and a future GUI or filesystem mount is another front-end
rather than a rewrite.

## Contributing

Issues and pull requests are welcome. "Done" means all four of these pass, on
both Windows and Linux — which is what CI enforces:

```bash
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

CI also runs `cargo audit --deny warnings`, weekly as well as on every push.
`Cargo.lock` is committed, so builds are pinned to exact versions and hashes and
a malicious *new* release of a dependency cannot reach you. The gap that leaves
is the reverse — an advisory filed against a version already pinned, which
nothing surfaces by itself. Treat `cargo update` as the step that deserves
attention, since it is the only thing that moves you off known-good pins.

A third job builds against the `rust-version` in `Cargo.toml` — currently 1.88 —
which it reads from the manifest rather than repeating, so the two cannot drift.
Every other job runs on stable, so without it that number would never be
exercised and would quietly become fiction the first time a dependency raised
the real floor.

Linux is a supported target rather than an aspiration, and is tested from
Windows through WSL. `CARGO_TARGET_DIR` must point outside the mount, both
because building across it is slow and because it otherwise fights the Windows
`target/`:

```bash
wsl.exe -e bash -c 'source $HOME/.cargo/env && cd /mnt/e/Projects/encino \
  && CARGO_TARGET_DIR=/tmp/enc cargo test --workspace'
```

Two constraints that are invisible from reading the code:

**Do not set `RUSTFLAGS`.** It replaces `.cargo/config.toml` rather than merging
with it, discarding the `-C target-feature=+crt-static` that lets the binary run
without the Visual C++ redistributable. The only symptom is a release build that
fails to start on a clean machine, so CI asserts the binary imports no
`vcruntime`. Pass lint flags to the tool instead: `cargo clippy -- -D warnings`.

**The `agent` subcommand lives in `encino-cli` on purpose.** `cargo test` builds
the binaries of the package under test and no others, and the integration tests
drive a real session daemon. Moving the binary target into `encino-agent` passes
locally, where a stale binary is lying around, and fails on a clean clone.

The engine (`encino-core`) forbids `unsafe` and does no terminal I/O — please
keep it that way, since it is what makes the risky code directly testable.

Changes to the on-disk format need a matching update to
[docs/format.md](docs/format.md); the spec is meant to be sufficient to audit or
reimplement from, and drifts into fiction the moment code changes without it.

Found a security problem? Please report it privately — see
[SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option. This is the usual arrangement in the Rust ecosystem: MIT is short
and universally understood, while Apache-2.0 adds an explicit patent grant, and
offering both keeps the code usable in either context.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

### Third-party material

One vendored file is separately licensed. EFF's Long Wordlist
(`src/encino-core/wordlists/eff_large_wordlist.txt`) is by Joseph Bonneau for the
Electronic Frontier Foundation, licensed CC-BY-4.0 and redistributed verbatim
with attribution. Provenance and a recorded SHA-256 are in
[its README](src/encino-core/wordlists/README.md).

Rust dependencies are not vendored; Cargo fetches them and they remain under
their own licences.
