# 2. Symmetric and asymmetric encryption

Almost everything in modern cryptography rests on a single distinction: whether the [key](13-glossary.md#key) used to encrypt is the same as the key used to decrypt. This chapter explains both kinds, why we need both, and how they're combined.

## Symmetric encryption: one key, two operations

Imagine a sturdy lockbox with a single key. Anyone who has the key can put things in, take things out, and lock or unlock the box at will. There's only one key, and it does both jobs.

That's [symmetric encryption](13-glossary.md#symmetric-encryption). The same secret key turns [plaintext](13-glossary.md#plaintext) into [ciphertext](13-glossary.md#ciphertext) ([encrypt](13-glossary.md#encryption)) and turns it back ([decrypt](13-glossary.md#decryption)). If you and a friend both know the key, you can exchange encrypted messages safely. If a stranger sees the ciphertext, they see noise.

Symmetric encryption is fast. Modern symmetric [ciphers](13-glossary.md#cipher) can encrypt many gigabytes per second on ordinary hardware. The algorithms are also well-studied: the cipher Secretary uses — [XChaCha20-Poly1305](13-glossary.md#xchacha20-poly1305), which we'll meet properly in [chapter 5](05-aead-encryption.md) — has been thoroughly analysed and is a NIST-style "preferred" choice.

The catch is the bit before the encryption starts: **how did you and your friend agree on the key in the first place?** If you can already securely exchange a key, you can already securely exchange the message — so what was the encryption for? This is called the *[key-distribution problem](13-glossary.md#key-distribution-problem)*, and for the first few thousand years of cryptography, the answer was always some flavour of "meet in person and exchange keys ahead of time." Diplomats, spies, and military couriers would carry physical key books and replace them on a schedule.

In Secretary, symmetric encryption is what protects the actual contents of your [records](13-glossary.md#record). Each *[block](13-glossary.md#block)* (the unit of encryption that holds one or more records) gets its own random 256-bit *[Block Content Key](13-glossary.md#block-content-key)*. That key is generated freshly on the device that creates the block; the cloud-folder host never sees it.

The key-distribution problem is then: how do we get that block key into the hands of the [recipients](13-glossary.md#recipient) you want to share with, without the cloud-folder host ever seeing it? That's where asymmetric cryptography enters.

## Asymmetric encryption: two keys, two roles

Now imagine a different kind of mailbox. It has two slots. The front slot is open to anyone — strangers can drop letters in. But the back of the mailbox, where letters accumulate, is locked, and only the owner has the key. Anyone in the street can deposit a letter; only the owner can collect.

That's the shape of [asymmetric encryption](13-glossary.md#asymmetric-encryption) (also called *public-key cryptography*). Each user has a *pair* of keys: a *[public key](13-glossary.md#public-key)* and a *[secret key](13-glossary.md#secret-key)* (also called a *[private key](13-glossary.md#private-key)*). The public key is meant to be shared widely — printed on business cards, posted online, sent to everyone the user might communicate with. The secret key is kept by the owner and never shared.

The two keys are mathematically linked, but in a one-way way: anyone with the public key can encrypt a message that only the holder of the matching secret key can decrypt. Or, in the dual role we'll see in [chapter 7](07-digital-signatures.md), the holder of the secret key can produce a signature that anyone with the public key can verify. The public key cannot decrypt; the secret key cannot be derived from the public key.

This is, on the face of it, an extraordinary thing. It seems to violate basic intuition about locks. Surely a lock that can only be opened by one key is also closed by that same key? Mathematically, no — the trick is to build the key pair from a problem that is easy in one direction and hard in the other. Multiplying two large primes is fast; factoring the product back into those primes is slow. Computing a point on an elliptic curve is fast; reversing the computation is slow. The asymmetry lives in those mathematical *trapdoor* problems, and the entire security of every public-key system depends on them being genuinely hard.

The catch with asymmetric cryptography is that it's *slow* — anywhere from hundreds to many thousands of times slower than symmetric encryption, depending on the algorithm and the hardware. You don't want to encrypt a 10 MB block of records with it directly.

In Secretary, asymmetric cryptography is used for two specific jobs:

- **Wrapping the symmetric block-content key** so that each recipient can recover it. The block contents themselves are still symmetrically encrypted; only the small (32-byte) symmetric key is delivered using public-key cryptography. This is called a *[Key Encapsulation Mechanism](13-glossary.md#kem)*, or KEM, and it's the subject of [chapter 6](06-key-encapsulation.md).

- **Signing data** to prove who wrote it. [Signatures](13-glossary.md#digital-signature) are the mirror image of public-key encryption: secret-key-in, public-key-verify. We'll meet them in [chapter 7](07-digital-signatures.md).

## Why we use both — the hybrid pattern

The standard pattern, used by essentially every modern secure protocol from HTTPS to Signal to Secretary, is:

1. Generate a fresh random *symmetric* key for the message you want to send.
2. Encrypt the message symmetrically (fast, large data).
3. Use *asymmetric* cryptography to deliver the small symmetric key to the recipient (slow, small data).
4. The recipient uses their secret key to recover the symmetric key, then uses the symmetric key to decrypt the message.

This is sometimes called a *[hybrid](13-glossary.md#hybrid)* construction, and it's the bread and butter of modern crypto. (Confusingly, when we later talk about Secretary's *[post-quantum](13-glossary.md#post-quantum-cryptography) hybrid*, we mean something different — combining a [classical](13-glossary.md#classical) algorithm with a post-quantum one. This older "hybrid" usage refers to combining symmetric and asymmetric. Both meanings are standard and both apply to Secretary; the context usually makes it clear which one is meant.)

## Where the analogy breaks

The lockbox / mailbox picture is a starting point, not the truth. Three places where pushing it leads astray:

- A real lockbox is a physical object you can examine. A symmetric key is just a 256-bit number; "having the key" means knowing the number, and the number can be copied without trace.
- Real public-key cryptography doesn't quite "encrypt" with the public key in the way you encrypt with a symmetric key. Most modern systems use the public key to perform a key *agreement* ([Diffie-Hellman](13-glossary.md#diffie-hellman)) or key *encapsulation* (a KEM), with the actual encryption still being symmetric. The mailbox-with-two-slots analogy gets the user-visible behaviour right but smooths over the mechanism.
- Asymmetric algorithms are not interchangeable. Encrypting with [X25519](13-glossary.md#x25519) (an [elliptic-curve](13-glossary.md#elliptic-curve-cryptography) algorithm) and encrypting with ML-KEM (a lattice-based algorithm) involve very different mathematics, even though both fit the "public key in, secret key out" shape.

Hold the analogies loosely. Use them to navigate; replace them with the real concepts as you go.

## Summary

- **Symmetric**: same key on both ends, fast, but you have to share the key safely first.
- **Asymmetric**: two keys per user, public can be shared, secret is kept private; slow but solves the key-distribution problem.
- **Hybrid**: every modern protocol uses both — asymmetric to deliver a fresh symmetric key, symmetric to do the actual work.
- In Secretary, your block contents are symmetrically encrypted; the per-recipient delivery of the block key is asymmetric.

The next chapter introduces a third primitive that isn't quite encryption at all but underpins almost everything else: hashing.
