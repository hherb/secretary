# 8. The quantum threat

This is the chapter people usually skim and then have strong opinions about. It's worth reading carefully, because much of the conversation around "quantum computers will break cryptography" is misleading at best, and the precise truth is a lot more interesting.

## What a quantum computer is — barely

A *[quantum computer](13-glossary.md#quantum-computer)* is a machine that uses quantum-mechanical phenomena (superposition, entanglement) to perform certain kinds of computation that classical computers cannot do efficiently. We don't need to understand the physics to discuss what it would do to cryptography. The relevant facts are:

- Quantum computers are not "faster classical computers." They don't speed up everyday computation; an Excel spreadsheet would not run faster on one. They are dramatically faster at very specific kinds of problems and unhelpful for almost everything else.
- They exist today only in small experimental form. The largest publicly-disclosed quantum computers as of the mid-2020s have on the order of hundreds to thousands of "qubits," but most of those qubits are noisy, error-prone, and only partially usable. Breaking real cryptography requires *millions* of high-quality qubits operating coherently for hours. Nobody is close.
- Whether large quantum computers will ever exist is genuinely uncertain. The engineering challenges are enormous and may turn out to be insurmountable. But betting against them — for cryptography that needs to remain secure for decades — would be reckless.

## The two algorithms that matter

For cryptography, two specific quantum algorithms matter:

### Shor's algorithm (1994)

[Shor's algorithm](13-glossary.md#shors-algorithm) efficiently solves two related mathematical problems: integer factorisation, and the discrete logarithm in finite groups. These two problems are the foundation of essentially all classical public-key cryptography deployed today:

- **[RSA](13-glossary.md#rsa)** relies on the hardness of factoring. Shor's algorithm factors RSA keys efficiently.
- **Elliptic-curve cryptography** (X25519, Ed25519, [ECDSA](13-glossary.md#ecdsa), etc.) relies on the elliptic-curve discrete logarithm. Shor's algorithm solves it efficiently too.

So a sufficiently large quantum computer running Shor's algorithm would break:

- All TLS public-key handshakes (with classical-only ciphersuites)
- All SSH key authentication
- All Bitcoin / Ethereum / most-cryptocurrency wallet signatures
- All Signal protocol forward secrecy that relied on classical Diffie-Hellman alone
- Most PGP keypairs
- And, relevant here, **X25519 and Ed25519** — the classical halves of Secretary's hybrid constructions.

This is the thing people mean when they say "quantum computers will break cryptography." It's a real concern, and the fix — post-quantum algorithms based on different mathematical problems — is exactly what NIST has been standardising.

### Grover's algorithm (1996)

[Grover's algorithm](13-glossary.md#grovers-algorithm) provides a quadratic speedup for unstructured search. In practice, this means that a brute-force search through a key space of size 2^N takes about 2^(N/2) operations on a quantum computer instead of 2^N on a classical one.

For symmetric encryption, this halves the *effective* key strength. A 128-bit symmetric key under Grover's attack provides only 64 bits of security, which is inadequate. A 256-bit symmetric key provides 128 bits of security, which is comfortable.

Two takeaways:

- Symmetric ciphers (AES, ChaCha20) are not catastrophically broken by quantum computers — just halved. Move from 128-bit to 256-bit keys (which Secretary does for its symmetric cipher) and you're fine.
- Hash functions are similarly weakened — collision resistance for an N-bit hash drops from 2^(N/2) to 2^(N/3). Modern 256-bit hashes (BLAKE3, SHA-256) still have ~85 bits of collision resistance against quantum attack, which is comfortable.

So Grover's algorithm is a real consideration but not an emergency. The structural break is Shor's, against asymmetric cryptography.

## What survives

A short table of where various cryptographic primitives stand:

| Primitive | Classical security | Quantum security |
|---|---|---|
| RSA-2048 | ~112 bits | broken (Shor) |
| X25519 | ~128 bits | broken (Shor) |
| Ed25519 | ~128 bits | broken (Shor) |
| AES-256 | 256 bits | ~128 bits (Grover) |
| XChaCha20-Poly1305 | 256 bits | ~128 bits (Grover) |
| SHA-256 | 256 bits collision-resistance | ~85 bits (Grover variant) |
| BLAKE3 | 256 bits | ~85 bits |
| Argon2id | depends on parameters | mildly affected |
| ML-KEM-768 | ~192 bits | ~192 bits |
| ML-DSA-65 | ~192 bits | ~192 bits |

The pattern is clear: all the deployed *asymmetric* primitives are broken by Shor, while the *symmetric* primitives remain comfortable when their key sizes are large enough. The post-quantum primitives ML-KEM-768 and ML-DSA-65 are designed precisely to fill the asymmetric gap.

## "But quantum computers don't exist yet" — why we care today

There is a stock objection to caring about quantum computers now: they don't exist at scale, they may never exist at scale, building cryptography for them is premature, etc.

This objection is wrong for one specific reason: **[harvest-now, decrypt-later](13-glossary.md#harvest-now-decrypt-later)**.

A motivated adversary today — a nation-state intelligence agency, say, or any other entity with substantial storage capacity — can simply *record* encrypted traffic and stored ciphertext now, and decrypt it whenever a sufficiently large quantum computer becomes available. The data is stored at rest, costing them only disk space. If a quantum computer arrives in 2040, all the X25519-protected data ever recorded becomes legible at that moment.

For most communication this is unfortunate but bounded — most of what TLS protects has a useful life of weeks or months. For Secretary, it's a critical concern. The whole reason Secretary exists is to protect credentials over decades. A vault written today and shared with a child for inheritance reasons has, by design, a 30-50 year lifespan. Any encryption applied to it today must remain secure against the adversary of 2055, not the adversary of 2025.

Hence: post-quantum starting from version 1, not "we'll add it later when we have to."

## Why hybrid, not post-quantum-only

If post-quantum algorithms are the future, why not just drop the classical algorithms and use ML-KEM-768 and ML-DSA-65 alone?

The honest answer is that we don't trust them quite enough yet. Lattice-based cryptography has been studied for decades, and the specific lattice problem underlying ML-KEM is believed to be hard, but the standardised constructions are new — finalised by NIST in 2024. Cryptographic constructions sometimes have subtle flaws that take years to surface; in 2022, one of the late-stage NIST candidates (SIKE) was completely broken by a classical attack. Other late-stage candidates have had less dramatic but still concerning results.

So the responsible position is: deploy the post-quantum primitive (because we need it for the harvest-now-decrypt-later threat), but also keep the classical primitive (because it's the most heavily-studied thing in modern cryptography), and combine them so the system is secure if *either* holds. If the classical one falls to a future quantum computer, the post-quantum half still protects. If the post-quantum one falls to a future classical attack, the classical half still protects. The system is broken only if both fall.

This is a deliberately conservative choice. Once ML-KEM has another decade of analysis behind it without surprises, future Secretary versions might drop the classical half. For now, the cost of carrying both is small (a few extra kilobytes per block, a few milliseconds of computation) and the safety margin is large.

## What this looks like in Secretary

Concretely:

- **Recipient wraps** combine X25519 and ML-KEM-768 (chapter 6).
- **Signatures** combine Ed25519 and ML-DSA-65 (chapter 7).
- **Symmetric encryption** uses XChaCha20-Poly1305 with 256-bit keys (chapter 5), large enough to remain comfortable under Grover's attack.
- **Hashing** uses BLAKE3 with 256-bit outputs, large enough that even quantum-attack-reduced collision resistance is comfortable.
- **Password derivation** uses Argon2id with 256 MiB of memory, which is mildly affected by quantum attack but remains broadly resistant because memory-hardness is hard to parallelise even on quantum hardware.

You'll see the pattern: every primitive in Secretary either is naturally post-quantum (symmetric ciphers, hashes, KDFs at large key sizes) or has both a classical and a post-quantum half.

## A note on what *can't* be made quantum-resistant by primitive choice

Some properties of cryptographic systems aren't really about which primitives are used. *Forward secrecy* — the property that compromising a long-term key doesn't reveal past traffic — is a *protocol* property, achieved by using ephemeral keys for each session rather than the long-term identity key. Secretary's v1 design does not have forward secrecy at the record level, because providing it for a *file-based, no-server* system that needs to remain readable to its recipients indefinitely is genuinely hard. (See [chapter 12](12-limitations.md).)

Quantum computers do not change this. A future Secretary version with forward secrecy would still need the same protocol-level mechanisms; the primitives just get swapped to post-quantum versions.

## Summary

- Quantum computers, if built at sufficient scale, would break all currently-deployed asymmetric cryptography (RSA, ECC) via Shor's algorithm.
- They would not break symmetric cryptography catastrophically, only halving its effective strength via Grover's algorithm — which is why 256-bit symmetric keys are the new standard.
- Quantum computers don't exist at scale today and may never. The reason to care now is *harvest-now-decrypt-later*: encrypted data captured today and decrypted decades from now.
- Secretary uses post-quantum primitives (ML-KEM-768, ML-DSA-65) alongside classical ones (X25519, Ed25519) in a hybrid construction, requiring both to be broken before security is lost.

The next chapter looks at the trust problem — the hardest unsolved problem in any decentralised cryptographic system, and the one place where Secretary asks you to do a small piece of work yourself.
