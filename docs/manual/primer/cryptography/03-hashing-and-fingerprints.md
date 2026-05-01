# 3. Hashing and fingerprints

A *hash function* takes any input — a single byte, an entire library of books, a 4 GB video file — and produces a fixed-size, seemingly random output. For the hash function Secretary uses most often (BLAKE3), the output is 32 bytes, no matter how big the input is.

Two things make this useful:

- **The same input always produces the same output.** Hash the file twice, get the same 32 bytes both times.
- **The output is *one-way*.** Given the 32-byte hash, there is no practical way to recover the input that produced it.

A reasonable mental picture: imagine an industrial blender. You drop fruit in, you get smoothie out. Same fruit, same smoothie, every time. But if you hand someone a glass of smoothie, they cannot reconstruct which strawberries went in.

Hashing is not encryption. There is no key, no secret, and no inverse operation. Any two people running the same hash function on the same input get the same output; there is nothing private about it.

## What hashes are good for

### 1. Fingerprints

If you want a short, fixed-size identifier for a piece of data, the data's hash is the natural choice. Two different files have, with overwhelming probability, two different hashes. (We'll come back to "with overwhelming probability" in a moment.)

Secretary uses hashes as fingerprints in several places:

- Each block file has a BLAKE3 fingerprint, and that fingerprint is recorded in the encrypted manifest. If the cloud-folder host swaps a block file for a different one, the fingerprints don't match and the swap is detected.
- A user's *Contact Card* — the public artifact you exchange when you want someone to be able to share with you — has a fingerprint computed over its full contents. That fingerprint is what you compare with your sister, over the phone or in person, to be sure her contact card hasn't been tampered with on its way to you. (This is the *out-of-band verification* problem of [chapter 9](09-the-trust-problem.md).)

For human comparison, a 32-byte fingerprint is too long. Secretary truncates to 16 bytes (still enough to make collisions astronomically unlikely for human-comparison purposes — about 1 in 2^128) and presents those 16 bytes either as 12 BIP-39 words (so you can read them out loud) or as grouped hexadecimal (so you can compare them visually on a screen).

### 2. Integrity checks

If you want to be sure a file hasn't changed since you last looked at it, store its hash. To verify, hash the file again and compare. Any modification — even a single bit — produces a completely different hash.

This is more powerful than it sounds. The hash function is designed so that flipping one bit anywhere in the input flips, on average, half of the bits in the output. There is no "small" change that produces a similarly small change in the hash; every change is, in effect, a large one.

### 3. Key derivation

When you want to turn one secret into another secret of a specific size, hashing is the foundation. Given a 256-bit master key and a context tag like "block-key", a hash-based construction can produce a fresh 256-bit key derived from both. The HKDF construction (used in Secretary's hybrid KEM in [chapter 6](06-key-encapsulation.md)) is a careful wrapper around hashing for exactly this purpose.

### 4. Message authentication

A *MAC* (Message Authentication Code) is essentially "hashing with a secret." Given a secret key and a message, the MAC produces a tag that anyone with the same secret key can verify. The Poly1305 component of Secretary's `XChaCha20-Poly1305` cipher is a MAC; it's what gives the cipher its tamper-evidence.

## What makes a hash function good

A hash function is *cryptographic* (rather than merely useful for hash tables in your favourite programming language) when it satisfies three properties:

- **Preimage resistance.** Given a hash output, finding any input that produces it is computationally infeasible. (You cannot un-blend the smoothie.)
- **Second-preimage resistance.** Given an input and its hash, finding a *different* input with the same hash is infeasible. (Given a strawberry smoothie, you can't make a different smoothie that tastes identical down to the molecule.)
- **Collision resistance.** Finding *any* two inputs with the same hash is infeasible. (You can't even cheat by choosing both inputs.)

The last property is the strongest, and it's the one that fails first when a hash function is broken. MD5 (1992) lost collision resistance in the early 2000s and is now trivial to break. SHA-1 (1995) lost it in the 2010s. Modern functions like SHA-256, SHA-3, and BLAKE3 remain unbroken.

### Why two hashes? BLAKE3 and SHA-256

Secretary uses BLAKE3 as its general-purpose hash (fingerprints, transcripts, integrity) and SHA-256 inside its HKDF construction. Why two?

- **BLAKE3** is fast (often several gigabytes per second on modern hardware) and has a clean, well-analysed design. It's the right default when we have free choice.
- **SHA-256** is the hash function specified by HKDF (RFC 5869), which is the standard key-derivation construction Secretary uses for its hybrid KEM. Standardisation matters here: for an interoperable specification, we follow the RFC rather than substitute.

Both are believed secure; using both in different roles costs nothing and aligns each role with the most appropriate choice.

## "Astronomically unlikely" — a digression

When we say two different inputs are extremely unlikely to share a 256-bit hash, we mean roughly the following: there are 2^256 possible 32-byte outputs. That number is about 10^77. The estimated number of atoms in the observable universe is about 10^80. Even the *birthday bound* (the size of a collection at which random collisions become likely, which kicks in at roughly the square root of the output space) is 2^128, which is itself a number larger than the number of grains of sand on Earth.

So when cryptographers say "collisions are infeasible," they're not saying "very unlikely" in any human-intuitive sense. They're saying "the entire computing capacity of the planet, run for the age of the universe, would not produce one." That is what allows hashes to be used as identifiers without ever needing a central registry: nobody has to coordinate, because the chance of clashes is, for practical purposes, zero.

This argument breaks down only when the hash function itself is broken — when someone discovers a structural flaw that lets them produce collisions far faster than brute force. That has happened to MD5 and SHA-1; it has not happened to the modern hashes Secretary uses, but the suite-ID mechanism in Secretary's vault format ([crypto-design.md §1, §12](../../../crypto-design.md)) ensures that if it ever does, the algorithms can be replaced without breaking the format.

## Summary

- A hash function turns any input into a fixed-size pseudo-random output.
- It is one-way: you can hash, but you can't un-hash.
- Hashes are used for fingerprints, integrity, key derivation, and (with a secret key) message authentication.
- Secretary uses BLAKE3 for general hashing, SHA-256 inside its standardised key-derivation step.
- The output space is so large that accidental collisions are practically impossible — provided the hash function itself is sound.

Next we look at how passwords (which humans choose, and choose badly) become cryptographic keys (which need to be 256 bits of pure randomness).
