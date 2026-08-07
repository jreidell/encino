# Strength: what actually protects an encino vault

Every figure here was measured against this build and the word lists it ships,
not quoted from memory. The commands used are noted so they can be re-run.

For what encino is and how to use it, start at the [README](../README.md).

The short version, if you read nothing else:

> Your documents are protected by a 256-bit random key nobody will ever guess.
> That key is guarded by your passphrase, which is the only part of the system a
> human chooses and therefore the only part with any slack in it. **Six random
> words from a published list is enough, and effort spent beyond that is better
> spent elsewhere.**

## Contents

- [What the cipher actually is](#what-the-cipher-actually-is)
- [Why the passphrase is the only soft spot](#why-the-passphrase-is-the-only-soft-spot)
- [Argon2id, and why guess rates are so low](#argon2id-and-why-guess-rates-are-so-low)
- [Entropy, in one page](#entropy-in-one-page)
- [The EFF word list and the dice method](#the-eff-word-list-and-the-dice-method)
- [How many words](#how-many-words)
- [Substituting numbers and symbols](#substituting-numbers-and-symbols)
- [Capitalisation](#capitalisation)
- [Why recovery codes use a different list](#why-recovery-codes-use-a-different-list)
- [Does any of this apply to other passwords?](#does-any-of-this-apply-to-other-passwords)
- [Quantum](#quantum)
- [Where effort actually pays](#where-effort-actually-pays)

---

## What the cipher actually is

| | |
|---|---|
| Cipher | XChaCha20-Poly1305 |
| Key size | 256-bit |
| Nonce | 192-bit, random per chunk |
| Authentication tag | 128-bit Poly1305 |
| Key derivation | Argon2id v19 — 256 MiB, 8 passes, 16-byte salt |
| Master key | 256 bits from the OS random source |
| Per-document keys | 256 bits, independent per document |
| Subkey derivation | HKDF-SHA256, distinct context string per purpose |
| Recovery code | 256 bits (24-word BIP39) |

The Argon2id parameters above are what this machine calibrated to; they are
stored in each vault's `vault.json` and can differ per vault. Check yours:

```powershell
Get-Content .encino\vault.json | Select-String -Context 0,5 '"kdf"'
```

Against the ciphertext alone — someone holding your disk, with no credentials —
there is no attack better than trying all 2²⁵⁶ keys. That number is within a few
orders of magnitude of the count of atoms in the observable universe. Forging an
authentication tag succeeds with probability 2⁻¹²⁸ per attempt. The 192-bit
nonce is large enough that random per-chunk nonces never collide in practice.

**This part is not the weak link and never will be.** Everything below is about
the part that is.

## Why the passphrase is the only soft spot

Your passphrase never encrypts a document. It guards *one of two doors* to a key
that does:

```
passphrase ──Argon2id──► KEK ──unwraps──┐
                                         ├──► master key (256-bit) ──► documents
recovery code ──Argon2id──► KEK ────────┘
```

An attacker does not have to break the cipher. They attack the cheapest door.
The master key and the recovery code are both 256 bits of machine randomness, so
neither is guessable. Your passphrase is the only element chosen by a person.

Your effective security is therefore the **minimum** of those paths, never the
sum. A weak passphrase does not weaken the cipher — it means nobody needs to
bother with the cipher.

One consequence worth internalising: **a longer passphrase does not make the
encryption stronger.** The encryption is 256-bit regardless. A longer passphrase
makes the *door* harder to force. Conflating the two is what leads people to
believe a clever-looking password has improved their cryptography.

## Argon2id, and why guess rates are so low

Argon2id is deliberately slow and, more importantly, **memory-hard**. At the
parameters above, each guess must hold 256 MiB and make 8 passes over it —
roughly 2 GiB of memory traffic per attempt.

That is what constrains an attacker. A 24 GB GPU can hold about 90 attempts in
flight, and memory bandwidth caps it further; a high-end card manages on the
order of hundreds of guesses per second, not millions. Against a fast hash like
unsalted SHA-256, the same hardware does billions.

Three scenarios are used throughout this document:

| Rate | Roughly what that is |
|---|---|
| 10³/s | A determined individual with a good GPU |
| 10⁴/s | A serious rig — on the order of twenty high-end GPUs |
| 10⁶/s | A well-funded organisation; generous, given memory-hardness |

These are estimates. The guess rate is the uncertain term in every calculation
below, and it depends entirely on how much hardware someone is willing to buy.
The conclusions are insensitive to it: the gap between four words and six words
is a factor of ten million, which no plausible revision to the rate closes.

## Entropy, in one page

Entropy measures *how many equally likely possibilities an attacker must search*,
expressed as a power of two. 50 bits means 2⁵⁰ possibilities.

The critical point, and the one most often missed:

> **Entropy is a property of how something was chosen, not of what it looks
> like.**

`Tr0ub4dor&3` looks random and carries roughly 28 bits, because it was built by
a human applying predictable transformations to a common word. Six words drawn
by dice look mundane and carry 77.5 bits. An attacker does not search the space
of things that *look* random; they search the space of things people *produce*,
and they model that space extremely well.

This is why self-invented passphrases fail. People draw from a far smaller pool
than they believe, favour certain letters and structures, and reuse patterns
across sites. Length is no defence: a memorable six-word phrase you composed
yourself may carry twenty-odd bits where a random one carries seventy-odd.

Machine or dice selection removes the guesswork and makes the entropy something
that can be *stated exactly* rather than hoped for. That is its entire value.

## The EFF word list and the dice method

encino uses **EFF's Long Wordlist**, published in 2016 by Joseph Bonneau.

| | |
|---|---|
| Source | https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt |
| Background | https://www.eff.org/dice |
| Words | **7,776** — exactly 6⁵ |
| Entropy | log₂(7776) = **12.925 bits per word** |
| Word length | 3–9 characters, average 6.99 |
| Licence | CC-BY 4.0 |

7,776 is 6⁵ by design: five dice select one word with **no bias and no
rerolls**. Every outcome maps to exactly one entry, which is why the list is
that specific size.

The file ships as `dice-roll<TAB>word`:

```
11111	abacus
11112	abdomen
...
66666	zoom
```

### Rolling it by hand

Roll five dice, read them left to right as a five-digit number, look it up.
Repeat for each word. Nothing to trust, nothing to install, and you can verify
the entropy yourself.

Two habits quietly destroy the maths:

- **Rerolling a word you dislike.** You have now chosen, and the space you drew
  from is smaller than 7,776.
- **Rearranging them into something that reads nicely.** Order carries entropy
  too, and imposing a pleasant order discards it.

Take the words as they come, in the order they came. If a phrase is memorable
because you shaped it, it is weaker than one that is not.

### Or let encino do it

```
encino passphrase              # six words
encino passphrase --words 8
```

It draws from the same list using the OS random source, touches no vault, and
saves nothing. It prints exactly one suggestion and never a menu — picking a
favourite from several is a human choice layered over a random one, which is
precisely what machine selection exists to prevent.

Selection uses **rejection sampling**, not `random % 7776`. The modulo shortcut
is biased because 7,776 does not divide 2³², and while the bias is about one
part in 1.3 million, it would make some words likelier than others and put the
real entropy quietly below the figure reported.

The list is compiled into the binary, so there is no data file to install, lose,
or tamper with. Its SHA-256 is recorded in
[`src/encino-core/wordlists/README.md`](../src/encino-core/wordlists/README.md)
so the vendored copy can be checked against EFF's — a list with words silently
removed would weaken every passphrase generated from it, and nothing in the
output would look wrong.

## How many words

Expected time to find the passphrase — half the space, since the average search
finds it midway:

| Words | Entropy | 10³/s | 10⁴/s | 10⁶/s |
|---|---|---|---|---|
| 2 | 25.8 bits | 8 hours | 50 min | 30 sec |
| 3 | 38.8 bits | 7 years | 272 days | 3 days |
| 4 | 51.7 bits | 5.8 × 10⁴ years | 5.8 × 10³ years | 58 years |
| 5 | 64.6 bits | 4.5 × 10⁸ years | 4.5 × 10⁷ years | 4.5 × 10⁵ years |
| **6** | **77.5 bits** | **3.5 × 10¹²** | **3.5 × 10¹¹** | **3.5 × 10⁹ years** |
| 7 | 90.5 bits | 2.7 × 10¹⁶ | 2.7 × 10¹⁵ | 2.7 × 10¹³ years |
| 8 | 103.4 bits | 2.1 × 10²⁰ | 2.1 × 10¹⁹ | 2.1 × 10¹⁷ years |
| 10 | 129.2 bits | 1.3 × 10²⁸ | 1.3 × 10²⁷ | 1.3 × 10²⁵ years |

Reading it:

- **Two words is crackable over a lunch break.** encino produces it on request
  but warns, because 26 bits is not a secret.
- **Three words falls within a year** to a serious attacker. Not enough.
- **Four words** is defensible against an individual but only 58 years against a
  well-funded one — thinner than it looks.
- **Five words** is beyond any practical attack.
- **Six words** exceeds the age of the universe by a factor of twenty-five even
  at the highest rate. This is the default, and it is the right one.
- **Beyond six** is decoration. The number is already unreachable; adding words
  changes an impossible problem into a differently impossible problem.

## Substituting numbers and symbols

Does replacing letters with digits and symbols — `a`→`@`, `e`→`3` — help? It
depends entirely on *how*, and the difference between the cases is the whole
answer.

A 6-word EFF passphrase averages **47 characters** with **23.7 positions** that
are candidates for substitution (`a e i o s t l b g z`).

| Approach | Added | Total | Practical effect |
|---|---|---|---|
| Fixed rule (`a`→`@` always) | **+0.0 bits** | 77.5 | None whatsoever |
| Chosen by hand, memorably | a few bits | ~80 | Negligible |
| Truly random, per character | +23.7 bits | 101.3 | Real, but see below |
| **+1 word instead** | +12.9 bits | 90.5 | Real, and free |
| **+2 words instead** | +25.8 bits | 103.4 | Real, and free |

**Why a fixed rule adds nothing.** Hashcat and John the Ripper have shipped leet
rule sets for two decades. They generate your substituted variant automatically
from the base word at essentially zero cost. If the rule is predictable — and
every rule a human can remember is predictable — the attacker applies it too.
This is what almost everyone actually does, and it buys precisely nothing.

**Why hand-picked substitution adds almost nothing.** Human choices cluster
hard: the first vowel, or every instance of one favourite letter. Crackers model
those patterns directly.

**Why truly random substitution is self-defeating.** It genuinely adds ~23.7
bits. But entropy *is* unpredictability, and unpredictability is exactly what
makes something unmemorable. If you can remember which of 24 positions were
substituted, the pattern was not random. So you must write it down — and now you
are typing 47 characters of `h@tchl1ng gut$ tr0p1c@l…` blind into a hidden
prompt on every unlock.

**The comparison that settles it:**

- Random substitution: **+23.7 bits**, unmemorable, error-prone to type
- Two more words: **+25.8 bits**, still memorable, still typeable

Two more words wins on every axis — more entropy, less friction, and a figure
that is exactly known rather than estimated.

There is a practical failure mode too. Mistype a 47-character substituted string
often enough and the temptation is to shorten it, or write it somewhere
convenient. That is a real loss traded against a theoretical gain.

### A note on where the "special characters" advice came from

Composition rules (*must contain a digit and a symbol*) were designed for short
passwords attacked character by character, where the character set genuinely
expands the search space. Passphrases are not attacked that way. A 47-character
string is already beyond character-level brute force by an absurd margin; the
attack that matters is at the *word* level, and a `@` does not change the fact
that you chose from 7,776 words. Substitutions strengthen you against an attack
that was never feasible in the first place.

## Capitalisation

**The passphrase is case-sensitive.** It is passed to Argon2id as raw bytes, so
`Correct horse` and `correct horse` derive entirely different keys.

**The recovery code is not.** It is lowercased before parsing, deliberately: it
is transcribed from handwriting months later, and insisting on case would turn
a legible code into an unusable one. Its 256 bits come from the word choice, so
nothing is lost by normalising.

Does mixing case in your passphrase help? The same three cases as substitution,
with larger numbers — because *every* letter can toggle, where only about four
per word are substitution candidates.

A 6-word EFF passphrase averages **41.9 letters**.

| Approach | Added | Total | Practical effect |
|---|---|---|---|
| Fixed rule (`Capitalise Each Word`) | **+0.0 bits** | 77.5 | None whatsoever |
| One capital where you'll remember it | ~1 bit | 78.5 | Negligible, and see below |
| Truly random, per letter | +41.9 bits | 119.5 | Real, but unmemorable |
| **+3 words instead** | +38.8 bits | 116.3 | Comparable, and memorable |
| **+4 words instead** | +51.7 bits | 129.2 | Better, and memorable |

Capitalising the first letter of each word — far and away the most common habit
— adds **nothing**. Hashcat's rule engine has had capitalise, toggle-case, and
uppercase-first rules since forever; they are in the default rule sets. If the
pattern is one you can remember, it is one the attacker already tries.

Random case is worth about three extra words, and loses to them for the same
reason random substitution does: 42 independently random case decisions cannot
be remembered, so they must be written down.

### Clever algorithmic schemes

A natural next thought: rather than capitalising the first letter of each word,
use an *algorithm*. Capitalise the 2nd letter of word one, the 3rd of word two,
the 4th of word three, and so on. It is unquestionably harder to guess than
`Capitalise Each Word`. Does it help?

**Almost not at all**, and it is the most dangerous sort of almost-nothing,
because it feels clever enough to justify a weaker passphrase elsewhere.

Here is the principle that governs it:

> **Entropy lives in the choice, not in the complexity of the transformation.**
>
> A complicated deterministic function applied to a known input produces a known
> output. The only thing an attacker does not know is *which function you
> picked* — so that, and only that, is what the scheme adds.

Assume, as you must, that the attacker knows you use *some* positional
capitalisation rule. How many such rules would they enumerate? Dozens, perhaps a
few hundred. That is the entire contribution:

| What the attacker must search | Bits added |
|---|---|
| 10 plausible rules | 3.3 |
| 100 plausible rules | 6.6 |
| 1,000 plausible rules | 10.0 |
| **One more word instead** | **12.9** |

Even the theoretical ceiling does not rescue it. If the six capitalised
positions were chosen *at random* rather than by a rule — which is a different
scheme, and an unmemorable one — that would be C(42,6) ≈ 5.2 million
possibilities, or **22.3 bits**. Still less than two extra words.

And the tooling already covers this ground. Hashcat ships
`toggles1.rule` … `toggles5.rule`, which enumerate every combination of toggling
one to five characters in a candidate. Positional case tricks are not an
overlooked corner; they are a stock rule file.

So the scheme buys perhaps 3–10 bits, against 12.9 for pressing space and typing
one more word. It costs:

- **Executing an algorithm under a no-echo prompt, every single unlock.**
  Counting to the *n*th letter of the *m*th word while typing blind.
- **A second thing to forget.** You can remember all six words perfectly and
  still be locked out because you have forgotten the *procedure*. The words are
  rehearsed by use; the rule is not.
- **False confidence**, which is the real cost. A scheme that feels strong
  invites shortening the passphrase to compensate, and the shortening loses far
  more than the trick gained.

The same reasoning dismisses every variant of this idea: interleaving digits by
position, reversing alternate words, inserting a symbol every *n*th character.
All are deterministic functions of the words. All add only the uncertainty about
which function. None comes close to the cost of pressing the space bar once
more.

### The reason to prefer lowercase, which is not about entropy

Case is where people mistype, and this tool punishes mistyping more than most.

Caps Lock, shift-key timing, and mobile auto-capitalisation all produce case
errors, and encino prompts with **no echo** — you cannot see what you typed. A
passphrase whose correctness depends on remembering that the fourth word had a
capital in the middle is a lockout waiting to happen.

And a lockout here is not a minor inconvenience. It sends you to the recovery
code; lose that as well and the documents are gone permanently, with no reset
and no support path.

All-lowercase, more words is therefore the better trade twice over: more
entropy per unit of memory, and far less chance of locking yourself out. That is
why `encino passphrase` emits lowercase words and does not offer a "add
capitals" option — it would be selling a typo risk as a security feature.

## Why recovery codes use a different list

Recovery codes use **BIP39** (2,048 words, 11 bits each, 24 words = 256 bits),
not the EFF list. Two measured reasons:

| | BIP39 | EFF Long |
|---|---|---|
| Words | 2,048 | 7,776 |
| Bits per word | 11.000 | 12.925 |
| Words for 256 bits | 24 | 20 |
| **4-char prefix collisions** | **0** | **4,028** |
| Checksum | Yes, in the final word | None |

Verified directly against both lists — EFF collides on pairs like
`abdomen`/`abdominal` and `absence`/`absentee`.

The two credentials have genuinely different jobs:

- A **recovery code** is machine-generated, written on paper, and transcribed
  back months or years later, possibly under stress, possibly from someone
  else's handwriting. It needs **error detection**. BIP39's checksum catches a
  wrong or misordered word immediately — "this is not a valid recovery code" —
  rather than the ambiguous "authentication failed", which cannot distinguish a
  typo from a damaged vault. Guaranteed unique four-letter prefixes mean a
  smudged ending is still recoverable.
- A **passphrase** is typed regularly and memorised. Mistakes announce
  themselves at once, so a checksum buys nothing, and memorability matters more.

There is a second, structural difference. The BIP39 list is **normative**: a
recovery code must parse against exactly that list years later, which is why it
is frozen by specification. The EFF list is only a *source of randomness at the
moment of generation* — once produced, a passphrase is just a string and is
never checked against the list again. That is why encino can pin one and rely on
the standard for the other.

Four words shorter is not worth losing the checksum on the one credential you
can never re-derive.

## Does any of this apply to other passwords?

The **principles** are universal. Several of the **numbers** are specific to
encino, and treating them as general advice would be a serious mistake.

### What transfers everywhere

- Entropy lives in the choice, not the transformation.
- Deterministic rules — leet, capitalisation, positional tricks — add only the
  uncertainty about which rule, which is a handful of bits at best.
- Human-invented passwords cluster in a small, well-modelled space; length is no
  substitute for randomness.
- Adding a random word beats adding cleverness, every time.

Those follow from information theory and from how cracking tools actually work.
They hold for your bank, your laptop, and your email.

### What does not transfer: the crack times

Every duration in this document assumes **encino's** Argon2id parameters. Other
systems store credentials very differently, and the same passphrase can be
unbreakable in one place and trivial in another:

| Stored as | 3 words | 4 words | 5 words | 6 words |
|---|---|---|---|---|
| MD5 | 2 sec | **5 hours** | 5 years | 4 × 10⁴ years |
| SHA-256 | 24 sec | 2 days | 45 years | 4 × 10⁵ years |
| NTLM (Windows) | 2 sec | **5 hours** | 5 years | 4 × 10⁴ years |
| bcrypt (cost 12) | 272 days | 5,793 years | 5 × 10⁷ years | 4 × 10¹¹ years |
| **encino (Argon2id)** | 25 years | 2 × 10⁵ years | 2 × 10⁹ years | 1 × 10¹³ years |

One high-end GPU, using these assumed rates — order-of-magnitude figures that
vary by GPU generation, and the term to revise if you want to redo the sums:

| Stored as | Guesses/sec | Why so different |
|---|---|---|
| MD5 | 10¹¹ | Fast by design; no salt, no work factor |
| SHA-256 | 10¹⁰ | Fast by design; built for hashing data, not passwords |
| NTLM | 10¹¹ | MD4-based, unsalted, still used for Windows credentials |
| bcrypt (cost 12) | 10⁴ | Deliberately slow, but only ~4 KB of memory |
| encino (Argon2id) | 3 × 10² | Deliberately slow **and** 256 MiB per guess |

The gap between the top three and the bottom two is the difference between a
hash designed to be fast and one designed to resist guessing. bcrypt and
Argon2id differ again on memory: bcrypt's small footprint lets a GPU run
thousands of instances in parallel, while 256 MiB each caps a 24 GB card at
about ninety.

**Seven orders of magnitude, for the identical passphrase.** Four words is
200,000 years here and five hours against a leaked MD5 database.

The decisive point: **you control encino's KDF and you do not control anyone
else's.** A website will not tell you whether it uses Argon2id or an unsalted
hash from 2005, and you will find out only when it is breached. For anything you
do not control, assume the worst row of that table.

### Online versus offline

Guess rates only apply once an attacker has the stored form. A live login that
rate-limits gives them perhaps ten tries an hour, where even a poor password
survives.

That distinction evaporates the instant a service is breached — the attack
becomes offline and runs at the rates above, against a database dumped months
before anyone noticed. Design for the offline case, because you will not be
consulted about the transition.

### Reuse is the threat encino does not have

A vault has one passphrase and one door. General passwords have a failure mode
this document has ignored entirely: **reuse**. One breached site hands attackers
a working credential for every other site where you used it, and no amount of
entropy helps — they are not guessing, they are logging in.

Credential stuffing is the most common real-world account compromise, and it is
a problem of reuse rather than strength.

### So what should you actually do

Split passwords into two groups.

**The few you must type from memory** — a password manager's master password,
disk encryption, an OS login, encino. These need to be memorable *and* strong,
which is exactly what a dice-generated word list is for. Six words, unique to
each. There should only be a handful.

**Everything else** — every website and service. These should be long random
strings from a password manager, unique per site, never memorised and never
typed. Memorability is irrelevant when software does the remembering, so there
is no reason to accept less than the maximum the site allows.

The passphrase advice in this document is for the first group. For the second,
the winning move is not choosing better passwords but not choosing them at all.

## Quantum

There is no asymmetric cryptography anywhere in this design, so nothing here is
exposed to Shor's algorithm — no RSA, no elliptic curves, no key exchange.

Grover's algorithm would nominally halve the symmetric margin, taking 256-bit
keys to an effective 128 bits, which remains far beyond reach. Argon2id's
memory-hardness is likewise not something a quantum computer helps with.

A vault written today does not have a quantum expiry date.

## Where effort actually pays

At six words you are at 3.5 × 10¹¹ years against a serious attacker. Nobody will
ever attack your passphrase directly. The realistic threats are the ones no
amount of entropy touches:

1. **Run on a BitLocker-encrypted volume.** Shredding cannot guarantee erasure
   on an SSD — wear levelling means overwriting a logical block does not
   reliably erase the physical one. Volume encryption is the actual mitigation,
   and it matters more than any passphrase decision on this page.
2. **Store the recovery code properly.** It opens the vault outright. On paper,
   in a safe — not photographed, not in a password manager beside the
   passphrase, and not split across two places, which turns an impossible
   problem into a feasible one.
3. **Close documents when finished.** Malware running as you while a document is
   checked out reads it as plainly as you do. `encino status` shows what is
   exposed; the auto-close timer exists for the times you forget.
4. **Lock before closing the lid.** Hibernating writes all of memory to disk, and
   the locked pages holding the master key are not exempt — locking them keeps
   them out of the page file, which is a different file. Sleep becomes
   hibernation on a timer on most laptops, so shutting the lid is enough. `encino
   lock` is the only thing that removes the key from memory; volume encryption
   covers the hibernation file for the times you forget.
5. **Keep the machine clean.** A keylogger captures the passphrase as you type
   it, and no key-stretching helps.

See [threat-model.md](threat-model.md) for the full boundary, including what
changes when a vault lives on a network share.

---

## Reproducing these numbers

Entropy and crack-time tables, from the vendored list:

```bash
awk -F'\t' '{ w=$2; n=length(w); tl+=n; c=0
  for(i=1;i<=n;i++){ch=substr(w,i,1); if(ch~/[aeiostlbgz]/) c++}
  ts+=c; cnt++ }
END{ bpw=log(7776)/log(2)
  printf "bits/word %.3f  avg len %.2f  avg substitutable %.2f\n", bpw, tl/cnt, ts/cnt
  for(k=2;k<=10;k++) printf "%2d words: %.1f bits\n", k, k*bpw }' \
  src/encino-core/wordlists/eff_large_wordlist.txt
```

Prefix collisions:

```bash
cut -f2 src/encino-core/wordlists/eff_large_wordlist.txt \
  | cut -c1-4 | sort -u | wc -l     # 3748 distinct -> 4028 collisions
```

Expected time to crack, in seconds: `2^bits / 2 / guesses_per_second`.

The cross-algorithm table, which is the one most worth re-running as hardware
moves — change the rates on the `split` line and re-read the result:

```bash
awk 'function lg(x){return log(x)/log(2)}
function fmt(s,  yr){yr=365.25*24*3600
  if(s<60) return sprintf("%.0f sec",s)
  if(s<3600) return sprintf("%.0f min",s/60)
  if(s<86400) return sprintf("%.0f hours",s/3600)
  if(s<yr) return sprintf("%.0f days",s/86400)
  if(s<1e4*yr) return sprintf("%.0f years",s/yr)
  return sprintf("%.0e years",s/yr)}
BEGIN{ bpw=lg(7776)
  split("MD5:1e11 SHA-256:1e10 NTLM:1e11 bcrypt(c12):1e4 encino-Argon2id:3e2", h, " ")
  for(i=1;i<=5;i++){ split(h[i],p,":")
    line=sprintf("%-18s", p[1])
    for(w=3;w<=6;w++) line=line sprintf(" %14s", fmt((2^(w*bpw)/2)/(p[2]+0)))
    print line } }'
```

Hashrates come from published benchmarks for consumer GPUs and should be treated
as approximations. They only need to be right to an order of magnitude: the
conclusions turn on a spread of 10⁸ between the fastest and slowest rows, which
no plausible revision closes.
