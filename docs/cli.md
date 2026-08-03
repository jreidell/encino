# Command reference

Every command and switch, what it does, and the behaviour that is not obvious
from `--help`.

Nothing here needs a network connection, a service, or an account, and encino
ships as a single executable — `encino` and nothing beside it.

There is one command not listed below. `agent` runs the session daemon and is
hidden from `--help`, because it is plumbing rather than something to type:
`unlock` re-executes this same binary with it, which is what lets encino be one
file. Run by hand it does nothing useful, since it waits on stdin for a master
key only `unlock` can supply.

## Contents

- [Global options](#global-options)
- [Exit codes](#exit-codes)
- [`init`](#init) · [`passphrase`](#passphrase)
- [`add`](#add) · [`ls`](#ls)
- [`open`](#open) · [`close`](#close)
- [`unlock`](#unlock) · [`status`](#status) · [`lock`](#lock)
- [`passwd`](#passwd) · [`recover`](#recover)
- [`verify`](#verify) · [`export`](#export)
- [Durations](#durations)
- [Scripting](#scripting)
- [Environment variables](#environment-variables)

---

## Global options

These are accepted by every command, though not every command uses them.

### `-C <FOLDER>`, `--vault <FOLDER>`

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

### `--passphrase-stdin`

Read passphrases and yes/no answers from standard input instead of prompting.

Without it, any command needing a secret refuses to run unless standard input is
a terminal — so a redirected file or pipe is never mistaken for a typed
passphrase. See [Scripting](#scripting).

A piped passphrase can end up in shell history, a script file, or a process
listing. Type it when a human is present.

### `-h`, `--help`

`-h` gives a summary; `--help` gives the full text including the longer notes.
Works per command: `encino open --help`.

### `-V`, `--version`

Prints the version and exits. Nothing is read or written.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Anything else — wrong passphrase, vault in use, a document that would not open, `verify` finding problems |

Commands that act on several documents report each failure individually and
still exit `1` if any failed, so a partial success is never reported as success.

---

## `init`

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

---

## `passphrase`

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

See [strength.md](strength.md) for the reasoning and the numbers.

---

## `add`

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

**What gets destroyed.** By default, originals are shredded **only if they were
already inside the vault folder**. Anything imported from elsewhere is copied in
and left where it was, and `encino` says which happened.

That default is deliberate: `encino add .` run from the wrong directory would
otherwise shred every file in that directory, with nothing to alert you until you
went looking for something.

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

---

## `ls`

```
encino ls [--json]
```

Lists the documents held, ordered by name, with sizes and a total. Anything
currently decrypted is marked `DECRYPTED`.

**Options**

- `--json` — machine-readable output instead of a table. Each entry carries
  `path`, `size`, `sha256`, `modified`, `added` and `open`.

---

## `open`

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
  one there is nothing to do it later and `encino` says so rather than implying
  a timer that will never fire. Start a session with
  [`unlock`](#unlock) first.
- `--with` — launch each document in its default application after decrypting.

**Arguments**

- `<PATHS>...` — document names as shown by `ls`, using forward slashes.

Opening a document that is already open is refused.

---

## `close`

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

---

## `unlock`

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

---

## `status`

```
encino status
```

Reports the vault path, whether a session is open and how long it has left, how
many documents are held, and — loudly — anything currently decrypted.

Works without a session, in which case it reports `locked` and stops there
without asking for a passphrase.

---

## `lock`

```
encino lock
```

Closes everything still open, stops the agent, and forgets the key.

Documents are re-encrypted *before* the key is dropped, since re-encrypting them
needs it. If any cannot be closed, the session is deliberately left open and the
command exits `1` — locking would otherwise leave plaintext on disk with no way
to re-encrypt it short of entering the passphrase again.

Safe to run when no session exists; it does nothing and succeeds.

---

## `passwd`

```
encino passwd
```

Changes the passphrase. Asks for the current one, then the new one twice.

Rewrites only the wrapped master key, so **no document is re-encrypted** however
many the vault holds. Your recovery code is unchanged and still works.

---

## `recover`

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

---

## `verify`

```
encino verify
```

Authenticates every stored document against the index: confirms each blob is
present, its key unwraps, it decrypts, and its digest matches what was recorded.
Also reports stored blobs no document refers to.

Reads everything in the vault, so it takes time proportional to total size.
Exits `1` if anything is wrong.

---

## `export`

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

---

## Durations

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

---

## Scripting

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

---

## Environment variables

### `ENCINO_AGENT_DEBUG`

Set to anything other than `0` or empty to turn on agent diagnostics.

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
it on while investigating a session that will not stay open, then turn it off.
