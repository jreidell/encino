# Vendored word list

## eff_large_wordlist.txt

EFF's Long Wordlist, used by `encino passphrase` to suggest passphrases.

- **Source:** https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
- **Background:** https://www.eff.org/dice
- **Author:** Joseph Bonneau, Electronic Frontier Foundation (2016)
- **Licence:** Creative Commons Attribution 4.0 International (CC-BY 4.0),
  per https://www.eff.org/copyright — separate from the project's own
  MIT OR Apache-2.0 terms, and compatible with both
- **SHA-256:** `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`
- **Retrieved:** 2026-08-02

7,776 words — exactly 6⁵, so five dice rolls select one word with no bias and
no rerolls. That works out to log₂(7776) ≈ 12.925 bits per word.

## Why it is vendored verbatim

Stored exactly as published, dice numbers and all, rather than stripped down to
a bare word list. Keeping the original bytes means the SHA-256 above can be
checked against EFF's copy, so anyone auditing this can confirm the list has not
been altered — a list with words quietly removed would silently reduce the
entropy of every passphrase generated from it, and nothing in the output would
look wrong.

It is compiled into the binary rather than read from disk, so `encino` has no
data files to install, lose, or have tampered with at runtime.

## On the dates in the URL

`/files/2016/07/18/` is the site's upload path, not a version number, and the
`_2_0` in the short lists reads as "list two, revision zero". The lists were
published in 2016 and are not a moving target.

It would not matter much if they were. This list is a *source of randomness at
the moment a passphrase is generated*, nothing more. Once generated, a
passphrase is just a string of characters; it is never checked against the list
again, so it stays valid regardless of what EFF publishes later.

That is the opposite of the BIP39 list used for recovery codes, which is
normative: a recovery code must parse against exactly the same list years later,
which is why that list is frozen by specification rather than by us pinning it.

The only thing a changed list could affect is the entropy this tool *claims*.
A shorter list would quietly make every future passphrase weaker while the
reported figure stayed the same — so the word count is asserted in a test rather
than trusted.

## Updating

The list is a fixed part of a given build. If a future release adopts a
different or corrected list, it ships as a new binary with this file and its
recorded hash updated together.
