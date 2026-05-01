# A cryptography primer for Secretary users

This primer explains the cryptographic ideas that Secretary is built on, in plain language, without assuming any prior background. By the end of it you should understand *why* Secretary works the way it does, what its protection actually buys you, and — just as importantly — what it cannot do and what no software can do for you.

It is written for the curious user. We don't assume you know the difference between symmetric and asymmetric encryption, what a hash function is, or what people mean when they talk about quantum computers being a threat to cryptography. We do assume you have read or skimmed the project's [README](../../../../README.md), so you have some sense of what Secretary is for.

We also won't shy away from naming the algorithms Secretary uses. Knowing that a piece of your data is protected by `XChaCha20-Poly1305` rather than just "encryption" lets you go and read about it, ask other people about it, or check whether the algorithm has been broken in some news story you might encounter years from now. Names matter for accountability.

## How the primer is organised

The chapters build on each other. If you read them in order, each one only relies on what came before. If you want to skip around, the [glossary](13-glossary.md) at the end defines every technical term in one place.

1. [Why cryptography matters here](01-why-cryptography.md) — the problem Secretary is trying to solve and why it is unusually hard.
2. [Symmetric and asymmetric encryption](02-symmetric-vs-asymmetric.md) — the foundational split that almost every concept in cryptography rests on.
3. [Hashing and fingerprints](03-hashing-and-fingerprints.md) — one-way functions and what they're good for.
4. [Passwords and key derivation](04-passwords-and-kdfs.md) — why a password is not a key, and how Argon2id bridges the gap.
5. [Authenticated encryption](05-aead-encryption.md) — encrypting data so it stays both secret *and* unmodified.
6. [Key encapsulation: sharing a key with someone](06-key-encapsulation.md) — how a sender can hand a symmetric key to a recipient who is nowhere nearby.
7. [Digital signatures](07-digital-signatures.md) — proving who wrote something.
8. [The quantum threat](08-quantum-threat.md) — what quantum computers will and won't be able to break, and why Secretary plans for both.
9. [The trust problem](09-the-trust-problem.md) — how do you know that this public key really belongs to the person you think it does?
10. [Randomness](10-randomness.md) — why "really random" is harder than it sounds and why it matters.
11. [Rollback resistance and integrity](11-rollback-and-integrity.md) — protecting against an adversary who can modify your cloud-folder copy.
12. [Limits of cryptography](12-limitations.md) — what no cryptographic system can do, and what Secretary specifically does not promise.
13. [Glossary](13-glossary.md) — every term in this primer, defined.

## A note on analogies

Cryptography is mathematical, but the underlying ideas are mostly intuitive once you find the right picture. We use a lot of analogies — locks, mailboxes, sealed envelopes, wax seals — to introduce ideas. Analogies are pedagogical scaffolding: they help you grasp the shape of an idea, but they are not the idea itself, and any analogy pushed too hard will eventually mislead. We will note where each analogy breaks down.

If you finish the primer and want the precise, normative description, the project's [docs/crypto-design.md](../../../crypto-design.md) is the authoritative specification — written for implementers, with no analogies.

## What this primer is *not*

It is not a course in cryptography. It will not teach you to design new protocols or evaluate someone else's. It will not turn you into a cryptographer. It is meant to give an interested layperson enough vocabulary and intuition to understand the choices Secretary has made, evaluate whether those choices match your own threat model, and follow the broader public conversation about post-quantum cryptography over the coming decades.

If reading it makes you want to learn more, good. The references at the end of each chapter are a starting point.
