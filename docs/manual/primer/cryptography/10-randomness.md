# 10. Randomness

Every cryptographic [key](13-glossary.md#key) in Secretary — every [Block Content Key](13-glossary.md#block-content-key), every [nonce](13-glossary.md#nonce), every signing keypair, every fresh symmetric secret — is a number drawn from a pool of randomness. If that pool is good, the keys are unguessable. If it's bad, *every* key derived from it inherits the badness, and the whole tower of cryptography sitting on top is hollow.

Randomness is the unglamorous foundation of practical cryptography. It's also the layer at which several spectacular real-world failures have happened. This chapter is about why.

## What "random" means here

The intuition of "random" — flipping a coin, rolling dice, drawing a card — is *unpredictability*. From the outside, you cannot guess what the next outcome will be, even with full knowledge of all prior outcomes.

For cryptographic purposes we need exactly this: a sequence of values such that an attacker who has seen any number of past values, and who knows everything about how the values were generated *except* for the seed of randomness used, cannot predict the next one with better-than-chance probability.

A stream of values that satisfies this is called *cryptographically secure*. There are two distinctions worth keeping in mind:

- **True randomness** comes from physical processes that are believed to be fundamentally non-deterministic — radioactive decay, thermal noise, quantum measurement. These are sources of *[entropy](13-glossary.md#entropy)*.
- **[Pseudo-random](13-glossary.md#pseudo-random) number generators ([PRNGs](13-glossary.md#prng))** are deterministic algorithms that take a small *seed* and stretch it into a long stream of apparently-random values. The output is only as good as the seed; a PRNG given a predictable seed produces a predictable stream.

A *cryptographically secure* PRNG ([CSPRNG](13-glossary.md#csprng)) is one designed so that, given a sufficiently random seed, no computational shortcut lets an attacker predict outputs better than [brute-forcing](13-glossary.md#brute-force) the seed. Modern operating systems combine entropy harvesting (from hardware sources, timing jitter, interrupt patterns) with a CSPRNG on top to give every program a near-infinite supply of high-quality randomness.

## How randomness is generated in practice

Every modern operating system provides a system call for cryptographic randomness:

- **Linux**: `getrandom(2)`, backed by the kernel's CSPRNG, which is itself seeded from hardware noise sources and continuously re-seeded.
- **macOS / iOS / BSD**: `arc4random_buf`, backed by a similar kernel-level CSPRNG.
- **Windows**: `BCryptGenRandom`, similarly backed.
- **Android**: same as Linux underneath, with platform-specific entropy contributions from hardware sensors.

Secretary uses the `getrandom` Rust crate, which calls into whichever of these is appropriate for the host OS. The resulting bytes are treated as uniformly random, and Secretary uses them everywhere randomness is needed:

- The 256-bit Block Content Keys for each block
- The 24-byte nonces for every AEAD encryption
- The 256-bit Identity Block Keys
- The 256-bit recovery mnemonic entropy
- The asymmetric keypairs (X25519 secret key, ML-KEM secret key, Ed25519 secret key, ML-DSA secret key)
- The 32-byte Argon2id salt
- All the UUIDs that identify vaults, blocks, records, contacts, and devices

If `getrandom` ever fails — which means the OS reports that it cannot deliver cryptographic randomness, which is essentially never on a modern system — Secretary refuses to operate. There is no fallback, no software-only PRNG that takes over from time stamps and process state and hopes for the best. A system that can't deliver randomness is a system in which Secretary cannot function safely, and it says so.

## What goes wrong when randomness fails

The worth of these protections becomes clear from the cases where they failed.

### Debian OpenSSL, 2008

A Debian maintainer commented out a couple of lines in OpenSSL's random-number code that they suspected were causing valgrind warnings. The lines turned out to be the main source of randomness used to seed the PRNG. The result: for nearly two years, every cryptographic key generated on a Debian or Ubuntu system was drawn from a tiny pool of about 32,000 possible seeds. SSH keys, TLS certificates, GPG keys — all reduced to one of 32,000 predictable values. The fix required Debian to revoke and regenerate millions of keys.

What this teaches: the randomness layer can be silently broken without any cryptographic primitive being broken. The keys "looked" random; they passed all surface tests. They were, however, drawn from a pool small enough to enumerate.

### Sony PS3 ECDSA, 2010

Sony shipped firmware that used ECDSA (an elliptic-curve signature algorithm) to verify code-signing on the PlayStation 3. ECDSA requires a fresh random nonce for every signature. Sony, somehow, used the same nonce for every signature. This is a critical violation of the algorithm's preconditions: from any two signatures sharing a nonce, the secret signing key can be recovered algebraically. The PS3's master signing key was extracted, and every game console could thereafter be jailbroken.

What this teaches: when an algorithm says "this must be random and unique," it really must be random and unique. There is no "in practice this is probably fine."

### Bitcoin Android wallet, 2013

A bug in the Java SecureRandom implementation on early Android versions caused some apps to receive predictable randomness. Bitcoin wallet apps using ECDSA signing on Android suffered key recovery similar to the PS3 case; multiple wallets were emptied by attackers who scanned the blockchain for repeated nonces.

### What's common across these stories

In every case, the cryptographic primitives themselves were perfectly fine. ECDSA isn't broken; OpenSSL's encryption isn't broken; the Bitcoin protocol isn't broken. What broke was the assumption that the code generating the keys (or nonces) had access to genuine randomness. That assumption is invisible from outside the system; the resulting failures are total.

This is the reason cryptographers care so much about how randomness is sourced and audited. The primitive can be perfect, but if the seed is predictable, the security is zero.

## Why Secretary trusts the OS

A reasonable question: why does Secretary trust the operating system's CSPRNG? Wouldn't it be safer to mix in additional entropy sources, or implement its own?

Two reasons we don't:

- **The OS CSPRNG is the highest-quality entropy source available to a user-space application.** It has access to hardware random-number generators, timing jitter from interrupts, network packet arrival times, and other entropy sources that an application running as a normal user simply cannot reach. Any application that "rolls its own" entropy is producing worse randomness than what the OS already provides.

- **Mixing in extra "entropy" can hurt rather than help.** If the application's mixing code has a subtle flaw — and they often do — the mixed output is worse than the OS output alone. Cryptographers' rule of thumb: trust the OS, don't try to outsmart it.

If the OS CSPRNG has been silently broken (the Debian case), Secretary inherits the breakage. There is no way around this — every cryptographic application on the same system is similarly compromised. Detecting CSPRNG failure is the OS's job, not the application's.

For high-assurance scenarios, the right answer isn't to add more user-space randomness; it's to use a trustworthy operating system on trustworthy hardware. That's an environmental choice, not a software one.

## Randomness in the recovery mnemonic

A practical example: when you create a vault, Secretary generates 256 bits of OS-CSPRNG entropy and encodes it as a 24-word BIP-39 mnemonic ("about gentle rural finger sword..."). Those 256 bits are the only randomness in the entire recovery system; everything else (the Recovery KEK, the AEAD nonces used to wrap the Identity Block Key under the Recovery KEK) is derived deterministically from them.

If the OS CSPRNG produced a predictable mnemonic, the Recovery KEK is predictable, the wrap is decryptable by the attacker, and the vault is open. The 24 words are the most security-critical 33 bytes in your system.

This is also why, when you write down your recovery mnemonic, you should treat it like a printed copy of your master password. Anyone who has the mnemonic has the vault.

## A small philosophical note

The deepest sense in which cryptography depends on randomness is this: every secret in cryptography is, in the end, a randomly-chosen number. You cannot generate a secret without randomness. You cannot derive it from anything. A secret that came from a deterministic process is, in principle, recoverable by anyone who runs the same process — which means it isn't really a secret.

The randomness layer is, in this strong sense, where secrets are *born*. Everything else in cryptography is just operating on the secrets that randomness provides. When the randomness is good, the cryptography is meaningful. When it isn't, nothing else matters.

## Summary

- Every key, nonce, salt, and asymmetric secret in Secretary comes from the OS-provided CSPRNG.
- A broken CSPRNG silently breaks every cryptographic primitive that depends on it; the primitives don't have to be flawed for the system to fail.
- Real-world examples (Debian OpenSSL, PS3 ECDSA, Android Bitcoin wallets) illustrate how total such failures are.
- Secretary trusts the OS CSPRNG and refuses to fall back to anything else; if `getrandom` reports failure, Secretary stops.
- Randomness is the layer at which cryptographic secrets are born. It's invisible in normal use but absolutely foundational.

The next chapter shifts focus from "is this data secret?" to "is this data the *current* version, or has someone substituted an old one?" — the rollback problem.
