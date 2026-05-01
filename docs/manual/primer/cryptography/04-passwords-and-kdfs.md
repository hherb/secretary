# 4. Passwords and key derivation

A cryptographic key is, ideally, 256 bits of pure randomness — a number a human could not possibly remember, and would never want to type. A password is, almost always, a sequence of letters and numbers that a human can hold in their head. The two are not the same kind of thing, and turning one into the other is a job that needs to be done very carefully. This chapter explains how, and why the difference matters.

## How much "secret" is in a password?

The technical term is *entropy*, and it's a measure of how unpredictable a value is. A truly random 256-bit number has 256 bits of entropy: an attacker has to try, on average, 2^255 values to guess it. That's the gold standard.

A password chosen by a human is much worse. Consider a few realistic estimates:

| Password kind | Approximate entropy |
|---|---|
| `password` | ~5 bits (it's the most common password in every leaked database) |
| `Tr0ub4dor&3` | ~28 bits (substituting digits for letters does very little) |
| `correct horse battery staple` (4 random words) | ~44 bits |
| 6-word random Diceware passphrase | ~77 bits |
| 256-bit random key | 256 bits |

Each bit of entropy doubles the work an attacker has to do. The gap between 28 bits and 256 bits is not "about ten times harder"; it's a factor of 2^228, which is a number with sixty-eight zeros after it.

So we cannot just take the user's password, hash it once, and call it a 256-bit key. The hash output has 256 bits of *length*, but only the entropy of the input — maybe 30 or 40 bits, if the user is reasonably careful. An attacker brute-forcing the password tries those 2^40 candidates one by one; the hash function does not help.

What we need is a way to *make each guess expensive enough that the attacker can't try very many of them*. That's the job of a Key Derivation Function tuned for passwords, and Secretary's choice is **Argon2id**.

## Why a slow function is exactly what we want

This is the part that often confuses newcomers. We are deliberately choosing a function that is slow to compute. Hundreds of milliseconds, sometimes seconds. Slow on purpose. *Why?*

Because the function runs once when the legitimate user types their password, and the user happily waits a fraction of a second. But it runs *billions of times* when an attacker is trying to brute-force the password offline, and a fraction of a second per attempt times a billion attempts is years of wall-clock time. The slow function is fine for the user and ruinous for the attacker.

A useful analogy: imagine a turnstile at the entrance to a hotel. If the slow turnstile takes legitimate guests an extra five seconds, no guest minds — they only pass through it once. If a thief is trying to walk through it 10,000 times in a row, the slow turnstile becomes a serious obstacle. The asymmetry between one legitimate use and millions of attacker attempts is what makes the cost worthwhile.

## Memory-hard, not just slow

There's a second trick. Older password-stretching functions (like PBKDF2 and bcrypt) are slow in CPU time, which is good but not enough. Modern attackers don't use ordinary CPUs; they use specialised hardware — GPUs, FPGAs, or ASICs — that can compute many CPU-style operations in parallel for a small fraction of the cost.

Argon2id is *memory-hard*, which means each computation requires not just time but also a substantial amount of working RAM. Secretary configures Argon2id to use **256 MiB of memory per attempt**. A modern GPU has, say, 24 GB of RAM, so it can run perhaps 80 attempts in parallel — which sounds like a lot, but compare it to the millions of parallel attempts the same GPU could do against a CPU-only function. Memory is the dominant cost on parallel hardware, and Argon2id picks that fight deliberately.

The full Argon2id parameters Secretary uses by default:

- Algorithm variant: Argon2id (a hybrid of Argon2i and Argon2d, balancing side-channel resistance with brute-force resistance)
- Memory: 256 MiB
- Iterations: 3
- Parallelism: 1 (single-threaded, intentionally — parallelism reduces the attacker's per-guess memory cost relative to the user's)
- Output: 32 bytes (this becomes the *Master KEK*)

These parameters are stored in `vault.toml` in cleartext. They're not secret; they need to be readable so the same vault can be opened on a phone (which would have struggled to *create* the vault with these parameters, but can decrypt with them once the vault exists). Secretary's policy is that parameters can be raised on rotation, never lowered.

## The salt

There is one more ingredient: a *salt*, which is a random 32-byte value generated when the vault is created and stored alongside the parameters in `vault.toml`. The salt isn't secret; its job is to ensure that two different vaults with the same password produce two different KEKs.

Why does that matter? Without a salt, an attacker could pre-compute a table of (common-password → KEK) pairs once, and then attack any number of vaults using lookups instead of fresh computation. Two users with the same weak password would have the same KEK, and breaking either of them would break both. With a per-vault salt, the attacker must redo all the work for every vault. (This is also why salts must be long enough that two random salts effectively never collide — 32 bytes is far more than enough.)

## Recovery mnemonic — a different problem

Secretary also gives you a 24-word *recovery mnemonic* at vault creation. This is generated by the program from 256 bits of OS-provided randomness; it has the full 256 bits of entropy by construction. Because the mnemonic is itself already a high-entropy random secret, Secretary does *not* run Argon2id on it. Argon2id is the right tool for stretching a low-entropy password; running it on already-strong material is just slower and gains nothing.

Instead, the mnemonic is processed through HKDF — a much faster key-derivation function that performs key shaping but no stretching. The result is the *Recovery KEK*, which can independently unlock the vault if the master password is forgotten.

A useful framing: Argon2id is for *human-chosen* secrets that need to be made resilient against brute force. HKDF is for *already-random* secrets that just need to be reshaped or contextualised. Using each one for its proper job is a small but consequential design choice.

## Where the password actually lives

Secretary never stores your master password anywhere — not on disk, not in the vault, not even hashed. The Master KEK derived from it is never stored either. When you unlock the vault:

1. You type the password.
2. Argon2id runs (a fraction of a second), turning password + salt + parameters into the Master KEK.
3. The Master KEK is used immediately to unwrap the *Identity Block Key*.
4. Both the password and the Master KEK are scrubbed from memory.
5. Only the Identity Block Key remains, and only for as long as the vault is unlocked.

If the cloud-folder host or a thief obtains your vault folder, they get the salt and the parameters, but they don't get the password or the KEK. Their only path forward is to *guess* the password and re-do the Argon2id computation per guess. That's the whole point of the construction.

## Summary

- Passwords have far less entropy than cryptographic keys; you can't just hash one to get the other.
- A password-hardening KDF (Argon2id) deliberately makes each guess expensive, so legitimate users barely notice but attackers face a wall.
- Memory-hardness defeats GPU-style parallel attacks.
- A per-vault salt prevents pre-computed attacks from spanning multiple users.
- The recovery mnemonic is high-entropy by construction and does not need stretching; it's processed with HKDF instead.

The next chapter introduces the symmetric encryption primitive that does the actual work of protecting your data once a key is in place.
