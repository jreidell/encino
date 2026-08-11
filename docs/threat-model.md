# encino threat model

This document states plainly what encino protects against and what it does not.
A security tool that overstates its guarantees is worse than no tool, because it
changes the user's behaviour without changing their exposure.

For what encino is and how to use it, start at the [README](../README.md).

## What encino is for

A folder of sensitive personal documents — financial statements, tax records,
scans of identity documents — living on a personal Windows machine. Without
encino these sit in plaintext, readable by anyone or anything that can read the
disk.

## Assets

| Asset | Protected? |
|---|---|
| Document contents | Yes — XChaCha20-Poly1305, per-document keys |
| Document filenames | Yes — held only in the encrypted index |
| Folder and subfolder structure | Yes — the blob store is flat |
| Document count | **No** — the number of blobs is visible |
| Document sizes | Partly — padded to a bucket, so only the bucket shows |
| Access times | Mostly — blob timestamps are normalized; Unix `ctime` is not settable |

Sizes are padded with Padmé, floored at 4 KiB: every document under 4 KiB is
exactly the same size on disk, and above that the padding costs at most 12% and
leaves roughly `log log n` bits of the size visible. That is enough to tell a
note from a scan, and not enough to confirm a specific document by its size —
which is the attack that mattered. See `format.md` for the construction.

Blob timestamps are normalized to a fixed value, so the blob store no longer
says when each document last changed. On Unix the inode change time remains,
since no userspace call can set it; it is absent from every backup and archive
format, so what it exposes is raw filesystem access rather than a leaked copy.
See `format.md` for the detail.

The count remains visible, and is recorded in `format.md` as a candidate for a
future revision. Hiding it needs decoy blobs, which carry an ongoing storage cost
rather than a one-off one.

## In scope — attacks encino defends against

**Lost or stolen machine.** The vault is at rest. An attacker with the disk
learns the number of documents and each one's size bucket, and nothing else.
Recovering contents requires the passphrase or the recovery code.

**Leaked backup or cloud-sync copy.** Because the vault's resting state is
encrypted, a backup captures ciphertext. This is the reason for per-file
checkout: a design that decrypts the whole folder would leak plaintext revisions
into a sync provider's version history, where the user cannot delete them.

**Another account on the same machine.** Blobs carry no filenames and the index
is sealed. A *checked-out* document is plaintext by definition, so on Unix it is
created mode 0600 and `.encino` — which holds the staging area and the lock
file — is created 0700; neither is left to the umask. On Windows both inherit the
ACL of the folder the vault was created in, which is the right answer inside a
user profile and the wrong one under a permissive drive root, so put the vault
somewhere only you can read. The work area itself is your folder and encino does
not change its permissions.

The session agent is reachable only by the account that started it,
enforced twice on each platform so that neither mechanism is load-bearing alone:

- **Windows** — the pipe's security descriptor grants access to the owning SID
  and nothing else (`D:P(A;;GA;;;<sid>)`, protected so no inherited entry can
  widen it), and `PIPE_REJECT_REMOTE_CLIENTS` refuses connections over the
  network.
- **Linux** — the socket is 0600 inside a 0700 directory this process has
  verified it owns, and each accepted connection's `SO_PEERCRED` uid is checked
  against our own before the request is read.
- **macOS** — the same directory and socket modes, with `getpeereid(2)` in place
  of `SO_PEERCRED`, which is Linux-specific. Both ask the kernel for credentials
  it recorded when the peer connected, so a client cannot claim to be somebody
  else, and both fail closed.

On any other Unix the directory mode stands alone, and nothing further is claimed
for those platforms. Windows, Linux and macOS are the three CI runs on.

**Casual inspection.** Someone who opens the folder while it is locked sees an
empty directory and a `.encino` folder of opaque blobs.

## Out of scope — attacks encino does not defend against

These are stated so the design is not mistaken for something stronger.

**Code execution on the machine while the vault is unlocked.** Malware running
as the user can ask the agent to unwrap documents, or read the plaintext of a
checked-out file directly. The session agent limits the window but cannot close
it. This is the fundamental limit of at-rest encryption on a compromised host.

**Keylogging.** A kernel or user-mode keylogger captures the passphrase as it is
typed. No amount of key stretching helps.

**Memory capture.** A full memory dump or a kernel debugger can expose the master
key. `VirtualLock` prevents the key from reaching the pagefile but does not
defend against an attacker who can read process memory.

**Hibernation while unlocked.** This deserves its own entry, because it is the
one case in this section that happens by accident rather than by an attacker's
effort. Hibernating writes all of physical memory to `hiberfil.sys` or the swap
device, and locked pages are not exempt: `VirtualLock` and `mlock` keep the key
out of the page file, which is a different thing. Closing a laptop lid is enough,
since sleep escalates to hibernation once its timer expires — the default on most
laptops. So:

- Run `encino lock` before closing the lid. It is the only action that removes
  the key from memory.
- `--timer` bounds the exposure but does not remove it. A machine that hibernates
  while a session is live writes the key out before the timer can fire.
- Encrypt the whole volume, which covers the hibernation file. BitLocker protects
  `hiberfil.sys`; on Linux the swap device must be encrypted too, as encrypting
  only the root filesystem leaves swap in the clear; on macOS FileVault covers
  the sleep image, and closing the lid is the same trap it is everywhere else.

**Physical coercion.** encino has no duress passphrase or deniable volume. If
you can be compelled to reveal the passphrase, the documents are revealed.

**Guaranteed erasure on SSDs.** `close` overwrites plaintext before unlinking,
but on flash storage wear levelling and the FTL mean overwriting a logical block
does not reliably erase the physical one. On APFS there is a second reason
independent of the hardware: the filesystem does not promise the overwrite lands
on the same physical extents, and a Time Machine local snapshot taken while a
document was checked out preserves the original blocks outright, where no amount
of overwriting reaches them. The real mitigation is volume-level encryption.
**Run encino on an encrypted volume — BitLocker, FileVault, or LUKS.** The CLI
states this once at `init` rather than implying a guarantee it cannot make.

**A weak passphrase.** Argon2id raises the cost of guessing but cannot rescue a
passphrase that is short or reused. The passphrase and the recovery code are the
entire security of the vault. See [strength.md](strength.md) for how much
passphrase is enough, and why the answer is "six random words" rather than
anything involving punctuation.

## Vaults on network storage

A vault works on a UNC path or a mapped drive, and a vault is portable between
the two — nothing path-dependent is stored, so `Z:\Docs` and
`\\server\share\Docs` reach the same vault interchangeably. Three things change,
and two of them weaken the guarantees above.

**Shredding becomes close to meaningless.** Overwriting a file writes to the
*server's* storage, where shadow copies, NAS snapshots, copy-on-write
filesystems, and server-side backups all preserve the original blocks. The advice
to run on an encrypted volume does not transfer, because the encryption you need
is on a machine you may not administer. Treat plaintext that has ever been
checked out on a network share as recoverable by whoever runs the server.

**The server sees every checkout.** Blobs cross the wire encrypted and the server
learns nothing of their contents or names, but it does see which blob was read
and when. Over time that access pattern reveals which documents you use and how
often — metadata the local case does not leak.

**Concurrent access is refused rather than merged.** A vault admits one session at
a time, enforced by a held file handle whose share mode the SMB server applies
across machines. A second machine is told the vault is in use and by whom.

That refusal is deliberate and is not a limitation to work around. Sessions
replace the index wholesale, so two writers would mean the later save discarding
the earlier one's entry — and since each document's content key is stored inside
its index entry, discarding the entry destroys the only copy of that key. The
blob becomes undecryptable noise and the original has already been shredded. The
document is unrecoverable, and `verify` can report the orphan but restore
nothing. Refusing the second session is the only safe answer.

Because the lock is a held handle rather than a marker file, a crashed process or
a dropped connection releases it automatically. A leftover `work.lock` file is
not a stale lock and needs no cleaning up. On Unix the same guarantee comes from
`flock`, whose lock belongs to the open file description and is dropped by the
kernel when the process exits.

The NFS caveat mirrors the SMB one, and is worse: `flock` over NFS is emulated
through the lock manager on some systems and is silently local on others, so two
machines sharing a vault over NFS may not see each other's locks at all. Treat a
vault on NFS as single-machine unless you have verified that locking works.

**Interruptions are handled.** A dropped connection mid-operation looks exactly
like a crash, which the journal already covers: the next session rolls the
operation forward or back.

## Trust assumptions

encino assumes the operating system, the Rust toolchain, and the audited crypto
crates it depends on are not themselves compromised, and that the OS CSPRNG is
sound. It makes no network connections and has no remote component, so there is
no server to trust and no traffic to intercept.

## Recovery, and the risk it carries

The master key is wrapped independently under a passphrase-derived key and a
24-word BIP39 recovery code. Either opens the vault, which means **the recovery
code is exactly as sensitive as the passphrase.** Written on paper in a drawer,
it is a bypass of every other protection here. It belongs in a safe or a safe
deposit box.

Losing both is unrecoverable. There is no backdoor, no vendor reset, and no
support path. `init` says so in plain language before accepting a passphrase.
