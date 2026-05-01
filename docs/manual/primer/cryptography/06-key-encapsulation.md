# 6. Key encapsulation: sharing a key with someone

This is the most layered chapter so far. We need to combine three things you've already met — symmetric encryption, public-key cryptography, and hashing — to solve the central design problem: *how does Alice get the symmetric key for a block into Bob's hands using nothing but his public key?* The construction Secretary uses is called a **hybrid Key Encapsulation Mechanism** (KEM), and unpacking it is what most of this chapter is about.

## The shape of the problem

Alice has just created a block. The block is encrypted with a fresh 256-bit *Block Content Key*, which Alice generated on her own device and which only she knows. She wants Bob (and possibly Carol, and possibly her future self on a different device) to be able to decrypt the block.

Alice has Bob's public keys, copied from his Contact Card. Alice does not have any secret of Bob's, and never will — Bob's secrets stay on Bob's devices. Alice writes the encrypted block to a folder both of them can read (a shared cloud folder, say), and somehow Bob, when he picks up the file, must be able to recover the Block Content Key.

The mechanism that solves this — *take a recipient's public key and a fresh symmetric key, produce a ciphertext that only the recipient's secret key can turn back into the symmetric key* — is called a **Key Encapsulation Mechanism**, or KEM.

## What a KEM is, mechanically

A KEM has two operations:

- **Encapsulate** (run by the sender, using the recipient's public key): produces a *shared secret* and a *ciphertext*. The shared secret is a fresh random value the sender now knows; the ciphertext is what gets sent to the recipient.

- **Decapsulate** (run by the recipient, using their own secret key and the received ciphertext): recovers the same shared secret. Now both sides know the shared secret.

Once both sides have the shared secret, they can use it as a symmetric key — or, more typically, derive a symmetric key from it using HKDF, with appropriate domain separation. That symmetric key is then used to wrap (encrypt) the actual content key Alice cares about.

Note the indirection: the KEM doesn't directly encrypt Alice's chosen Block Content Key. Instead it produces a *fresh* shared secret — call it the *wrap key* — and Alice uses the wrap key to AEAD-encrypt the Block Content Key. Two reasons for the extra step:

1. KEMs are designed to deliver *random* secrets, not chosen ones. The cleanest interface is "give me a fresh random secret"; sticking to that interface keeps the design simple and the security analysis clean.
2. The wrap step is an AEAD encryption with associated data, which lets Secretary bind the wrap to context like the block UUID and a transcript hash. Tampering with any of that context invalidates the wrap.

## Why "hybrid" — combining classical and post-quantum

Now the second word: hybrid. Secretary's KEM is not one KEM, but two run in parallel and combined.

- The *classical* KEM is **X25519**, an elliptic-curve construction. X25519 has been deployed for over a decade, has been thoroughly studied, and is the workhorse of nearly every modern secure protocol (TLS, SSH, Signal, WireGuard).
- The *post-quantum* KEM is **ML-KEM-768** (formerly known as Kyber, standardised by NIST in 2024 as FIPS 203). It's based on a different mathematical problem entirely — module-lattice problems — and is designed to resist attack by sufficiently large quantum computers (which we'll cover properly in [chapter 8](08-quantum-threat.md)).

Why both? Because each has a different failure mode, and we don't want to bet everything on one of them being correct.

- X25519 is mature and battle-tested, but a future quantum computer would break it (Shor's algorithm; chapter 8).
- ML-KEM-768 is theoretically post-quantum-secure, but it's much newer. Lattice cryptography has been studied for over thirty years, but the specific construction in ML-KEM-768 was only standardised in 2024. There's a small but non-zero risk that a flaw will be found.

By running both and combining their outputs, Secretary requires an attacker to break *both* to recover plaintext. A quantum adversary breaks X25519 but cannot break ML-KEM-768, and the combination remains secure. A surprise classical attack on ML-KEM-768 (lattice cryptanalysis improves dramatically tomorrow, say) doesn't break X25519, and the combination remains secure.

The analogy: you have two locks on your front door, made by completely different manufacturers using completely different mechanisms. To get in, a burglar must defeat both. If one manufacturer turns out to have shipped a bad batch of locks, the other still holds.

This is sometimes called a *belt and suspenders* approach. It costs a bit more (the post-quantum ciphertext is large — about 1 KB per recipient — and the encapsulation takes more time than X25519 alone), but the cost is small relative to the cost of being wrong.

## How the two halves are combined

The sketch of what Secretary does (full details in [crypto-design.md §7](../../../crypto-design.md)):

1. Encapsulate with X25519, producing classical ciphertext `ct_x` and shared secret `ss_x`.
2. Encapsulate with ML-KEM-768, producing post-quantum ciphertext `ct_pq` and shared secret `ss_pq`.
3. Compute a *transcript hash* — a BLAKE3 hash of both ciphertexts together with the sender's and recipient's identity fingerprints. This binds the wrap key to who-sent-it-to-whom.
4. Run HKDF over `ss_x ‖ ss_pq ‖ ct_x ‖ ct_pq ‖ sender_pubkey_bundle ‖ recipient_pubkey_bundle`, with domain-separation tags, producing a 32-byte wrap key.
5. AEAD-encrypt the Block Content Key under the wrap key, with the block UUID and the transcript hash in the AAD.
6. Store on disk: `ct_x`, `ct_pq`, the AEAD nonce and ciphertext+tag, and a fingerprint of the recipient. That bundle is the *per-recipient wrap*; the block file contains one such wrap for each recipient.

When the recipient opens the block, they run the dual operations: ML-KEM-decap with their secret key to recover `ss_pq`, X25519-decap to recover `ss_x`, recompute the transcript and the wrap key, and AEAD-decrypt the wrapped Block Content Key. From there, the block contents themselves can be decrypted with the AEAD primitive of [chapter 5](05-aead-encryption.md).

A critical property of the construction: every input to the HKDF call influences the wrap key, and a change to any of them produces a completely different wrap key. An attacker who, say, tries to substitute their own ML-KEM ciphertext while leaving the X25519 part alone produces a different transcript hash, hence a different wrap key, hence an AEAD failure. This defends against a class of "KEM-sneak" attacks where a flawed combiner would let an adversary bypass the post-quantum half by manipulating the classical half.

## "But why doesn't Alice just encrypt the Block Content Key directly with Bob's public key?"

This is a natural question, and the answer is: she could, in principle, with X25519 alone (using the older "DH-then-symmetric-encrypt" pattern). But:

- KEM-style APIs are cleaner and harder to misuse than direct public-key encryption.
- For the post-quantum half, ML-KEM is *defined* as a KEM. There is no "encrypt this chosen plaintext with the recipient's ML-KEM public key" operation. The KEM interface is the only interface.
- Hybrid combiners are well-defined for KEMs (NIST has published guidance on how to combine them) and not really defined for direct public-key encryption.

So Secretary uses KEMs for both halves, and the resulting design fits the way modern post-quantum schemes are intended to be used.

## Sizes — why post-quantum cryptography is bulkier

Worth noting, because users sometimes wonder why Secretary's blocks are bigger than (say) PGP-encrypted files. ML-KEM-768 ciphertexts are 1088 bytes; ML-DSA-65 signatures are 3309 bytes; the public keys are similarly large. A Secretary recipient wrap is about 1.2 KB per recipient, dominated by the ML-KEM ciphertext.

Compared to X25519-only, this is a roughly 30× increase in wrap size. For a block shared with five recipients, the recipient table is about 6 KB. This is a fixed overhead per block; the encrypted record contents are (for typical password-manager records) much smaller than even one wrap. The size cost of going post-quantum is real but manageable for the use case — vaults are not bandwidth-bound in any practical scenario.

## Summary

- A KEM is the standard primitive for delivering a fresh symmetric key to a recipient using only their public key.
- Secretary's KEM is *hybrid*: X25519 (classical, mature) and ML-KEM-768 (post-quantum, NIST-standardised) run in parallel, with their outputs combined via HKDF.
- An attacker must break both halves to recover plaintext, providing a margin against either kind of cryptanalytic surprise.
- The wrap key is bound to the full transcript (ciphertexts + identity public-key bundles + fingerprints), which prevents an attacker from substituting one half while leaving the other alone.
- Post-quantum sizes are larger than classical ones; the cost is acceptable.

Next we look at the dual operation — proving who wrote something — using digital signatures.
