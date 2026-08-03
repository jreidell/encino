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

## How it works

A random 256-bit master key encrypts everything. Your passphrase never encrypts
a document directly — it derives a key (Argon2id) that *wraps* the master key, so
changing your passphrase rewrites one small file instead of re-encrypting your
documents. A 24-word recovery code wraps the same master key independently.

Each document gets its own content key and is stored as a blob under a **random**
name — not a hash of its contents, which would reveal when two documents are
identical. Filenames and folder structure live only in an encrypted index, so the
blob store is flat and tells an observer nothing but how many documents you have
and roughly how large they are.

Full details in [docs/format.md](docs/format.md). For how strong all of this
actually is — cipher parameters, entropy maths, and how many words your
passphrase needs — see [docs/strength.md](docs/strength.md).

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

The passphrase goes to stdout and everything else to stderr, so
`encino passphrase > file` yields a clean file while the weak-passphrase warning
still reaches you.

It touches no vault, saves nothing, and prints exactly one suggestion — offering
several would let you pick a favourite, and choosing over random output is what
destroys the entropy in the first place. Take it as it came: swapping a word you
dislike or reordering them into something that reads nicely throws away the
randomness that makes it strong.

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

## Commands

```
encino init <folder>              create vault; set passphrase; print recovery code
encino passphrase [--words N]     suggest a strong passphrase; changes nothing
encino add <path>...              import files or folders (recursive)
encino ls [--json]                list documents
encino open <name>... [--with]    decrypt; --with opens in the default app
encino open --all [--timer 30m]   decrypt everything, auto-close on expiry
encino close <name>... | --all    re-encrypt and shred the plaintext
encino status                     session state, what is decrypted, time left
encino lock                       close everything and forget the key
encino passwd                     change the passphrase
encino recover                    unlock with the 24-word recovery code
encino verify                     authenticate every stored document
encino export <dest>              decrypt the whole vault to a folder
```

`--vault <folder>` (or `-C`) operates on a vault elsewhere. `--passphrase-stdin`
reads secrets from a pipe for scripting.

**[docs/cli.md](docs/cli.md) documents every command and switch**, including what
`--help` cannot convey: which flags a given command ignores, the order a script
should feed answers on stdin, exit codes, duration formats, and the environment
variable that controls agent diagnostics.

### How imported documents get their names

A document's name is its path relative to the folder you named, so the named
folder becomes the top of the imported tree — the same rule as `cp -r`:

```
encino add C:\Archive\taxes    ->  taxes/2023/w2.pdf, taxes/2024/w2.pdf
encino add C:\Archive\w2.pdf   ->  w2.pdf
encino add .                   ->  paths as they sit in the vault folder
```

Files already inside the vault keep their position in it, so `add .` after
dropping documents into the folder preserves whatever structure you put there.

### What `add` destroys

By default `add` shreds originals **only if they were already inside the vault
folder**. A file imported from anywhere else is copied in and left where it was,
and encino says so.

This matters more than it sounds. `encino add .` run from the wrong directory
would otherwise shred every file in that directory, and you would have no way to
notice until you went looking for something. Use `--move` to shred outside
originals too (it asks first), or `--keep` to preserve everything.

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

## Before you trust it with anything

Read [the threat model](docs/threat-model.md). Three things especially:

**Run encino on a BitLocker-encrypted volume.** Shredding cannot guarantee
erasure on an SSD — wear levelling means overwriting a logical block does not
reliably erase the physical one. Volume encryption is the real mitigation.

**The recovery code is as sensitive as the passphrase.** It opens the vault
outright. Losing both means the documents are gone permanently: no backdoor, no
reset, no support path.

**This protects against a stolen laptop, a leaked backup, a synced cloud copy, or
another account on the machine.** It does not protect against malware running as
you while the vault is unlocked. That is the fundamental limit of at-rest
encryption, and no design here changes it.

This has not been independently audited.

## If a session will not stay open

encino writes no logs. The session agent runs detached with its output
discarded, so when it dies unexpectedly there is nothing to look at.

Set `ENCINO_AGENT_DEBUG=1` to turn on diagnostics for as long as you need them:

```powershell
$env:ENCINO_AGENT_DEBUG = "1"
encino unlock
# reproduce the problem, then:
Get-Content "$env:LOCALAPPDATA\encino\agent.log"
Remove-Item Env:\ENCINO_AGENT_DEBUG
```

It records failures plus the agent starting and stopping — never key material,
document names, or vault contents — and the file lives outside the vault so it
cannot become metadata attached to your encrypted folder. It is off by default
because when a session ran is a record of when you worked with your documents,
which is the sort of thing the encrypted index exists to hide.

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

Everything is verified on both: 175 tests on Windows, 178 on Linux (the extra
three cover Unix file permissions and socket paths).

The platform differences are confined to two things, and both take the same
shape on each system:

| | Windows | Unix |
|---|---|---|
| Vault lock | file opened denying write sharing | `flock(LOCK_EX \| LOCK_NB)` |
| Agent transport | named pipe, DACL'd to your SID | Unix socket, `0600` in a `0700` directory |
| Key kept out of swap | `VirtualLock` | `mlock` |

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
docs/                 on-disk format, threat model, CLI reference
```

Three crates, one executable. `encino-core` and `encino-agent` are libraries
compiled into `encino-cli`, which produces the single `encino` binary.

`encino-core` forbids `unsafe` and does no terminal I/O, so the risky code is
directly testable and a future GUI or filesystem mount is another front-end
rather than a rewrite.

## Contributing

Issues and pull requests are welcome. Two things worth knowing before you start:

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
