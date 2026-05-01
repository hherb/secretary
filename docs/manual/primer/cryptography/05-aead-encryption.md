# 5. Authenticated encryption (AEAD)

We've covered hashing and we've covered the idea of a symmetric key. Now we look at how Secretary actually uses a key to scramble your data — and crucially, how it ensures the scrambling cannot be tampered with without detection.

## Why "encryption alone" isn't enough

The naive picture of encryption is: take your plaintext, mix it with a key, get ciphertext. The cloud-folder host sees ciphertext; without the key, the host cannot recover the plaintext. Confidentiality, achieved.

But confidentiality without integrity is dangerous. Consider an attacker who can't *read* your encrypted file, but can *modify* it. Depending on the encryption algorithm, flipping bits in the ciphertext flips bits in the plaintext in predictable ways. The attacker who knows your record contains the field `amount: 100` might be able to flip a few bits in the ciphertext and produce a record that decrypts cleanly to `amount: 900`. They can't read what's there, but they can change it — and you'd never notice.

This sounds theoretical until you realise that essentially every real-world attack against poorly-designed encryption schemes works this way. Protocols that encrypted but didn't authenticate have been broken repeatedly: SSL 3.0 (POODLE), early TLS modes (Lucky 13), pre-2010 IPSEC configurations, the original WEP wireless standard. Any time encryption-without-authentication is shipped, attackers eventually find a way to exploit it.

The lesson, learned the hard way: *encryption and authentication must always travel together*. The combined primitive that does both is called **AEAD** — Authenticated Encryption with Associated Data.

## What AEAD does

AEAD takes:

- A **key** (32 bytes, in Secretary's case)
- A **nonce** (24 bytes — more on this in a moment)
- The **plaintext** (whatever you want to protect)
- Optional **associated data** (the AAD; data that should be authenticated but not encrypted)

…and produces:

- A **ciphertext** (the same length as the plaintext)
- A **tag** (16 bytes, in Secretary's case)

To decrypt, the receiver provides the same key, nonce, ciphertext, AAD, and tag. If anything has been altered — the ciphertext, the AAD, the tag, the nonce — the AEAD function returns a single answer: *fail*. There is no partial decryption, no "well, here's what we got, hope it's right." Tampering is binary and visible.

A useful analogy: think of an AEAD ciphertext as a tamper-evident envelope. The contents are sealed inside (confidentiality). The flap is sealed with a holographic sticker that visibly destroys itself if peeled (integrity). The address on the front is written on the sticker too, so if anyone changes the address the sticker tears (associated data). Open the envelope and find the sticker damaged: you know not to trust the contents.

## What is a nonce, and why is it 24 bytes?

A *nonce* is a "**n**umber used **once**." For most stream ciphers, AEAD designs included, the nonce together with the key uniquely determines the keystream that scrambles the plaintext. If you ever encrypt two different plaintexts with the same key *and* the same nonce, both encryptions are immediately broken — an attacker who sees both ciphertexts can XOR them and learn things they shouldn't.

So nonces must never repeat for a given key. That's where the size matters. Two common nonce sizes in modern AEAD ciphers:

- **96 bits (12 bytes)**: used by AES-GCM, ChaCha20-Poly1305. This is fine *if* you're careful — usually by maintaining a counter that increments per message — but accidental random reuse becomes plausible after about 2^32 messages (the birthday bound).
- **192 bits (24 bytes)**: used by XChaCha20-Poly1305, the variant Secretary uses. With 24 random bytes, the birthday bound is at 2^96, which is so large you can simply pick the nonce randomly and never worry about collisions.

Secretary picks a fresh random nonce for every encryption operation. With XChaCha20's 24-byte nonces, the chance of a collision over the lifetime of the universe is negligible. The trade-off is a slightly larger ciphertext (24 bytes of nonce instead of 12), which is not material.

## Why XChaCha20-Poly1305

The full name spells out the construction: **XChaCha20** is the cipher (the part that turns plaintext into ciphertext) and **Poly1305** is the message authentication code (the part that produces the tamper-detection tag). Combined, they form an AEAD.

ChaCha20 was designed by Daniel J. Bernstein and is notable for several things:

- It's fast in software, on every CPU. Many modern CPUs have hardware acceleration for AES (Intel AES-NI, ARM's Cryptography Extensions), but on hardware without it — older phones, low-end embedded devices — AES becomes slow and timing-leaky. ChaCha20 doesn't use any data-dependent branches or memory accesses, so it runs at the same speed regardless of input, which both helps performance and prevents *timing side-channels* (an attacker measuring how long encryption takes can sometimes learn information about the key; ChaCha20 leaks nothing this way).
- It's well-analysed. The cipher has been studied for nearly fifteen years and shows no weakness; the standard "12-round ChaCha20" used here has very large security margins.
- It's simple. The whole specification fits on a page. Simplicity makes review easier and bugs less likely.

Poly1305 is similarly simple, similarly fast, and pairs naturally with ChaCha20 (they share a common mathematical structure that makes the combined implementation efficient).

The "X" in XChaCha20 is the extension to 24-byte nonces. That's it; everything else about XChaCha20 is the same as ChaCha20.

A short summary of the choice: XChaCha20-Poly1305 is the safest "no surprises" AEAD currently available in widely-reviewed software. It runs everywhere, has no known weaknesses, and tolerates random nonces by design. It's not the only good choice (AES-GCM is also fine if used carefully), but it's the most forgiving.

## Where Secretary uses AEAD

Almost everywhere data is at rest:

- **Block contents** are AEAD-encrypted with the *Block Content Key*. The header bytes of the block file (its UUID, its format version, etc.) are passed in as the AAD, so any tampering with header fields invalidates the tag.
- **The Manifest** — the index that tells Secretary which blocks exist, who they're shared with, and what their fingerprints are — is AEAD-encrypted under the *Identity Block Key*.
- **The Identity Bundle** — the file holding your secret keys — is AEAD-encrypted under the *Identity Block Key* on the inside, and the Identity Block Key itself is then AEAD-wrapped twice, under the Master KEK and under the Recovery KEK.
- **Per-recipient wraps** of block keys (which we'll meet in [chapter 6](06-key-encapsulation.md)) are themselves AEAD ciphertexts, with a wrap key derived from the hybrid KEM transcript.

In every case, the same primitive (XChaCha20-Poly1305) and the same parameters are used. Standardising on one cipher reduces the amount of code that needs auditing, and ensures that improvements (or in the worst case, fixes) only need to be made in one place.

## Domain separation: why AAD has tags like `secretary-v1-block-key-wrap`

If you peek at Secretary's [crypto-design.md](../../../crypto-design.md), you'll see lots of AAD strings starting with `secretary-v1-`. Each one is a *domain-separation tag* — a fixed string that identifies which role this particular AEAD operation is playing. The block-key wrap uses one tag, the identity-bundle encryption uses another, the recovery-key wrap uses a third.

The reason is subtle but important. Without domain separation, an attacker who could induce the system to encrypt some chosen plaintext under one key could potentially replay that ciphertext in a different role and have it accepted. Different roles have different security implications, and the same key being used for two different jobs is a classic recipe for cross-protocol attacks. By including a tag specific to each role in the AAD, the AEAD's tag check guarantees that a wrap meant for one job cannot pass verification when treated as a wrap for a different job.

This is invisible to users — you'll never type one of these tags — but it's a load-bearing piece of the design's robustness.

## Summary

- AEAD provides confidentiality *and* integrity in one primitive — never use one without the other.
- Secretary uses XChaCha20-Poly1305 throughout: fast in software, no hardware dependencies, large nonces that tolerate random sampling.
- A nonce must never repeat for a given key. With 24-byte random nonces, repetition is statistically impossible.
- The AAD lets header bytes be authenticated without being encrypted, so tampering with cleartext metadata is detected.
- Domain-separation tags in the AAD ensure that a ciphertext for one role cannot be replayed in another.

The next chapter answers the question we deferred in chapter 2: how do we get a fresh symmetric key into the hands of a recipient using only their public key?
