# 7. Digital signatures

A [digital signature](13-glossary.md#digital-signature) is the cryptographic equivalent of a wax seal on an old letter. The seal proves two things: this letter was sealed by the person whose seal-stamp was used, and the letter has not been opened or altered since the seal was applied. Anyone with a copy of the seal-stamp's *imprint* can verify; only the holder of the *stamp itself* can produce new seals.

This is the same basic shape as public-key encryption (chapter 2), with the roles reversed. In encryption, the public key encrypts and the secret key decrypts. In signing, the secret key signs and the public key verifies. Same key pair; opposite directions.

## What a signature actually is

To sign a message:

1. The signer takes their secret key and the message bytes.
2. The signing algorithm produces a signature — a fixed-size value (64 bytes for Ed25519, 3309 bytes for ML-DSA-65).
3. The signature is attached to the message and shipped together.

To verify:

1. The verifier takes the signer's public key, the message bytes, and the signature.
2. The verification algorithm returns either *valid* or *invalid*. Nothing in between.
3. If valid, two things are guaranteed: the message has not been altered since signing, and the signer was someone in possession of the secret key matching this public key.

That second guarantee is conditional on the *secret key actually being secret*. If your secret key has leaked, an attacker can produce signatures that will verify as if they came from you. This is why so much of cryptographic system design is really about key management.

A signature is *not* encryption. The message itself remains in plaintext (or whatever form it was in); the signature is appended. Anyone can read the message; only the holder of the public key can verify the signature.

## What signatures are good for

In Secretary, signatures appear in three places:

1. **Block files.** Every block file is hybrid-signed by the user (or device) that wrote it. When you read a block, the signature is verified against the appropriate identity's public keys. If verification fails — bytes have been altered, signature was forged, or you're looking at a block your trusted contacts didn't sign — the block is rejected.

2. **The Manifest.** Every manifest update is signed. The manifest enumerates all the blocks in the vault and includes a fingerprint of each one; signing the manifest binds your view of the vault to a specific consistent state. An attacker who tampers with any block, or substitutes blocks, breaks the manifest signature on the next read.

3. **[Contact Cards](13-glossary.md#contact-card).** A contact card carries the user's public keys and is *self-signed* by the user — that is, the card is signed using the same secret keys whose public counterparts are listed in the card. The self-signature proves the card is internally consistent: someone who holds the secret keys vouched for this exact set of public keys. (It does not, on its own, prove the card belongs to who it claims to belong to. That's the *trust problem* of [chapter 9](09-the-trust-problem.md).)

## Hybrid signatures: same idea as the hybrid KEM

The same logic that drives the hybrid KEM applies to signatures: classical algorithms are mature but quantum-vulnerable; post-quantum algorithms are quantum-secure but newer and less battle-tested. Combine both.

Secretary's [hybrid signature](13-glossary.md#hybrid-signature) is the conjunction of:

- **[Ed25519](13-glossary.md#ed25519)** — an elliptic-curve signature scheme (specified in RFC 8032), widely deployed in SSH, TLS, the Tor protocol, the Cosmos blockchain, and many others. About 64-byte signatures, fast.
- **[ML-DSA-65](13-glossary.md#ml-dsa-65)** — Module-Lattice Digital Signature Algorithm at security level 3, standardised by NIST in 2024 as FIPS 204 (formerly known as Dilithium). About 3309-byte signatures, slower but post-quantum-secure.

To sign, the signer produces *both* an Ed25519 signature and an ML-DSA-65 signature over the exact same message. To verify, the verifier checks *both*. The signature is treated as valid if and only if both halves verify (logical AND, not OR). If either half fails, the signature is rejected.

Why AND rather than OR? Because OR is dangerous — an attacker who breaks just one of the two algorithms could forge a signature that verifies via that broken half alone. The AND construction means an attacker must break both algorithms to forge a signature, which is the property we wanted from "hybrid" all along.

There is a cost: signing is slower (you do both signatures), verifying is slower (you do both verifications), and the combined signature is larger (about 3.4 KB per signature). For password-manager-scale data, this cost is invisible.

## A subtle point: signatures sign *fixed bytes*

A signature is computed over a specific sequence of bytes. If the bytes change in any way — even for reasons that are semantically harmless, like reordering map keys or using a longer length encoding — the signature stops verifying.

This matters for any structured-data format that gets signed. Secretary uses [CBOR](13-glossary.md#cbor) (Concise Binary Object Representation) for its structured data, and specifically the *[deterministic](13-glossary.md#determinism) encoding profile* of CBOR: map keys sorted, integers in their shortest form, no floats, no tags. Any compliant CBOR encoder produces the same bytes for the same data, so the signature verifies regardless of which language or library wrote the file.

This is invisible to users, but it's the kind of detail that makes the difference between "implementations that interoperate" and "implementations that work fine with each other today and start failing mysteriously in three years when one is updated." Determinism is non-negotiable for signed data.

## Domain separation in signatures

Just as AEAD operations include a domain-separation tag in the AAD, signatures include one in the signed message. Secretary's tags are like:

- `secretary-v1-block-sig` — for signatures on block files
- `secretary-v1-manifest-sig` — for signatures on manifests
- `secretary-v1-card-sig` — for the self-signature on Contact Cards

The tag is prepended to the message bytes before signing. If an attacker captures a block-signed message and tries to present it as a manifest-signed one (or vice versa), the tag mismatch causes verification to fail. This isn't a hypothetical concern — protocols that didn't include such tags have, in the past, been broken by exactly this kind of cross-context replay.

## What signatures don't do

A few things to keep in mind:

- **Signatures don't prove identity by themselves.** A signature proves *the holder of this secret key* signed the message. Whether that holder is the person you think it is depends on how you got the public key and how confident you are in its provenance. We deal with this in [chapter 9](09-the-trust-problem.md).

- **Signatures don't prevent the holder from signing anything.** If your sister's device is compromised and the attacker can get her to sign a malicious block, the signature on that block will verify perfectly — because it really was signed with her secret key. The signature mechanism cannot tell "intentional" from "tricked." That's an endpoint-security problem, not a cryptography problem.

- **Signatures don't prevent replay.** A valid signature over an old message remains valid forever. If an attacker captures an old, signed message and re-presents it later, the signature still verifies. Defenses against replay are protocol-level: timestamps, sequence numbers, nonces. Secretary's vector clocks (chapter 11) play this role for vault state.

- **Signatures don't expire.** Or rather, they don't expire on their own. The signing algorithm doesn't care what time it is. Secretary's design avoids relying on clock-based signature validity; instead, it uses vector clocks and manifest fingerprints to detect rollback and stale state.

## Why we don't ship just one signature

A natural question: why bother with the ML-DSA part now, when quantum computers don't exist? Why not just use Ed25519 today and migrate to a post-quantum signature when we have to?

Two reasons:

- **Long-lived signatures need to verify in the future.** A block signed today might be relevant in 2055. If Ed25519 has been broken by then, the signature becomes worthless retroactively — an attacker can forge "old" Ed25519 signatures that look like they came from you decades ago, and there's no way to tell forgeries apart from genuine ones. Adding the ML-DSA half today means future verifiers can still check authenticity even if Ed25519 is gone.

- **Algorithm migration is harder than algorithm addition.** Migrating an existing system from one signature scheme to another retroactively — re-signing every old artifact, getting all clients to update, handling old-format data forever — is a project. Adding the post-quantum signature alongside the classical one from day one means there's nothing to migrate later; old vaults already have post-quantum signatures.

We will likely live in a world of "we don't know exactly when Ed25519 falls" for the next two or three decades. The hybrid design lets Secretary not have to predict.

## Summary

- A signature is a way for a secret-key holder to prove authorship of a message; anyone with the public key can verify but not produce signatures.
- Secretary uses a hybrid signature: Ed25519 (classical) AND ML-DSA-65 (post-quantum), both must verify.
- Signatures are computed over fixed bytes; deterministic encoding (CBOR) is what makes signatures portable across implementations.
- Domain-separation tags prevent a signature for one role being replayed in another.
- Signatures verify *who held the secret key*, not necessarily *who you think they are* — that's a separate problem we tackle in chapter 9.

The next chapter goes deeper into the quantum threat: what a quantum computer would actually break, what it can't, and why the conservative answer is "post-quantum starting now."
