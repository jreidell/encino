# Security

## This has not been audited

encino was written carefully and is extensively tested, but it has had **no
independent security review**. Do not treat it as equivalent to a tool that has.
If your documents would cause you serious harm if exposed, use something with an
audit behind it.

The design and its limits are documented rather than implied:

- [docs/threat-model.md](docs/threat-model.md) — what this defends against, and
  the things it explicitly does not
- [docs/strength.md](docs/strength.md) — the cryptographic parameters, with the
  reasoning and the numbers behind them
- [docs/format.md](docs/format.md) — the on-disk format, in enough detail to
  audit or reimplement

## Reporting a vulnerability

Please report privately rather than opening a public issue, so a fix can exist
before the details do.

Use GitHub's **Report a vulnerability** button under the Security tab, which
opens a private advisory.

Useful things to include: what an attacker gains, the conditions needed, and a
way to reproduce it. A concrete failing case is worth more than a description.

I will acknowledge reports as soon as I reasonably can. This is a personal
project with no team behind it, so please do not expect a same-day response.

## What counts

**In scope** — anything that breaks a promise the threat model makes:

- Recovering document contents or filenames from a locked vault
- Defeating authentication on the index, a blob, or a key wrap
- Silent data loss or corruption, including anything that survives the journal
- A path that leaves plaintext on disk after `close` or `lock` reports success
- One user reaching another's session agent
- Escaping the vault folder through a crafted document name

**Out of scope** — the documented limits, which are design decisions rather than
defects:

- Attacks requiring code execution as the user while the vault is unlocked. The
  threat model concedes this outright; the boundary defended is the disk, not
  other processes of the same user.
- Recovering plaintext from an SSD after shredding. Overwriting cannot guarantee
  erasure on flash; volume encryption is the mitigation, and the tool says so at
  `init`.
- Weak passphrases. Argon2id raises the cost of guessing; it cannot rescue a
  poor choice.
- The number of documents, and each one's padded size bucket, being visible on
  disk. Known leakage, recorded in the format spec. Sizes are padded; the count
  is not hidden, and hiding it is reserved for a future version.

If you are unsure which side something falls on, report it. A judgement call in
your favour costs me a few minutes; the opposite could cost someone their
documents.

## Scope of the code

The dangerous surface is deliberately small and concentrated:

- `src/encino-core/` — all cryptography, the index, the blob store, and the
  crash journal. Compiled with `#![forbid(unsafe_code)]` and performs no
  terminal I/O, so it can be exercised directly.
- `src/encino-agent/src/win.rs` and `unix.rs` — every `unsafe` block in the
  project, roughly 200 lines of platform calls. The least-tested part, and the
  first place I would look.

Both are libraries compiled into the single `encino` executable; there is no
separate daemon binary. The session daemon runs as a hidden `agent` subcommand
of that same executable, started by `unlock` re-executing itself, so a session
never depends on a second file being present or being the same version.
