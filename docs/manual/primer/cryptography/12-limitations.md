# 12. The limits of cryptography

A cryptographic system that says "we protect you against everything" is, almost by definition, lying. Every real system has a *threat model* — a list of things it defends against, and an equally important list of things it explicitly does not. Knowing the second list is at least as important as knowing the first, because it tells you what *else* you need to worry about and which problems no software can solve.

This chapter is the second list, written plainly. Some items are limits of cryptography in general; others are deliberate scope decisions for Secretary's v1 design. We've tried to be explicit about which is which.

## What cryptography fundamentally cannot do

### It cannot defend secrets that have already been decrypted

Cryptography protects data while it is in encrypted form. Once Secretary unwraps a Block Content Key and decrypts a record into RAM, the plaintext exists in your computer's memory. A program with sufficient privileges to read your memory — malware, a debugger, an OS-level rootkit — can read the plaintext. The decryption boundary is where cryptographic protection ends; after that, the data is at the mercy of the operating system and everything else running on it.

Secretary tries to minimise this window: keys and plaintext are *[zeroized](13-glossary.md#zeroize)* (overwritten with zeros) as soon as they aren't needed, so even a process that briefly gains access to memory has only a short snapshot to work from. This is good practice but not a complete defense. A keylogger that captures your master password as you type it bypasses every other protection.

### It cannot detect compromised inputs

If your computer's keyboard secretly logs every keystroke, the password you think you're typing is also being delivered to an attacker. No amount of cryptography on the resulting key changes that. The data in `getrandom`'s output is only as good as the OS believes its entropy sources to be; if the OS is compromised, so is the randomness.

Cryptography depends on the rest of the trusted computing base — the CPU, the firmware, the OS, the libraries — being honest. When they aren't, cryptography sits on top of a lie and produces lies in turn.

### It cannot resist coercion

If someone with a wrench (or a subpoena, or a warrant) demands that you type your master password, no cryptographic mechanism prevents it. The cryptography protects against adversaries who don't have you; it doesn't protect against adversaries who do.

There are partial mitigations — *plausible deniability* schemes that let you produce a "duress password" revealing a decoy vault — but they have their own complications, and Secretary's v1 does not include them. (The format leaves room for them in future versions.)

### It cannot solve the trust problem on its own

Chapter 9 discussed this at length. Whether a public key really belongs to the person you think it does is a question cryptography can't answer; you have to verify out-of-band. Cryptography reduces "is this data secret?" to "is this key valid?" — but it doesn't, by itself, answer the second question.

### It cannot make a forgotten secret recoverable

Strong cryptography is exactly as hard for the legitimate user to defeat as for the attacker. If you forget both your master password and your recovery mnemonic, the vault is gone. There is no "I forgot my password" link; there is no support team that can reset it; there is no master key held by the developer. This is the price of true zero-knowledge encryption.

Take this seriously when setting up Secretary. The recovery mnemonic exists precisely so you have a second path; write it down on paper, store it somewhere safe, and treat it as the most important piece of paper in your house.

## What cryptography can do but Secretary v1 doesn't

### Forward secrecy at the record level

*[Forward secrecy](13-glossary.md#forward-secrecy)* is the property that if your long-term key is compromised today, the attacker cannot retroactively decrypt data they captured yesterday. Modern secure-messaging apps (Signal, Wire) achieve this by using ephemeral keys that are deleted after each message; even if the device is compromised next week, the keys for last week's messages are gone.

Secretary's v1 does not have forward secrecy at the record level. If your Identity Block Key is compromised, all current and past block contents (within reach of your current key wraps) are decryptable to the attacker. The reason is structural: a password manager that needs to remain readable to its recipient indefinitely, *without* the recipient periodically re-deriving keys, is at odds with the per-message ephemerality that forward secrecy requires.

Compensating controls: keep the Identity Block Key in the OS keystore (where the OS protects it with biometric / hardware-token gating), zeroize aggressively, and treat the master password as the credential that gates access. If your device is compromised in a way that lets an attacker extract keystore-protected keys, you have bigger problems than Secretary's design.

A future version of Secretary might add a forward-secrecy mode for selected high-value blocks at the cost of some sharing convenience. It is on the roadmap; it is not in v1.

### Revocation of already-shared blocks

Once you've shared a block with Bob and Bob has fetched the file, Bob has the bytes. He has the wrap of the Block Content Key for those bytes. If you later decide Bob should not have access — perhaps because he's no longer in your family, or because his device has been compromised — you can rotate the block (generate a new content key, re-wrap for the new recipient list, write a new file). But Bob's local copy of the *prior* version is unchanged, and the wrap in that prior version is still decryptable by his keys.

This is mathematically inherent to a no-server design. Real revocation requires a central authority (server, trusted third party) to refuse to deliver the data; Secretary has no such authority.

What you *can* do: rotate the content key (so that future updates to the block are not visible to Bob), revoke Bob's contact card (so that future shares don't include him), and assume that whatever Bob has already seen is in Bob's possession permanently. Plan accordingly.

### Defense against equivocation

As [chapter 11](11-rollback-and-integrity.md) discussed, a malicious cloud-folder host could in principle serve different versions of the vault to different devices of yours. Secretary detects this on the next sync but cannot prevent it. Prevention would require a synchronisation server with a global ordering — exactly what Secretary's architecture rejects.

This is acceptable because detection happens within the next sync (typically minutes to hours), and the attack requires the cloud host to be actively malicious rather than merely compromised.

### Anonymity / metadata privacy from the cloud host

The cloud-folder host knows you have a Secretary vault. They know roughly how many blocks it has, when each one was last modified, when you access it, and how much data each block contains. They cannot read the contents but they can study patterns — when you access a particular block, how often you create new blocks, when blocks are shared, how big the recipient table is.

Defending against this would require *traffic-analysis-resistant* constructions: constant-size files, padding, decoy operations, oblivious-RAM protocols. These are research-grade and add substantial complexity, and Secretary v1 explicitly does not attempt them.

If your threat model includes an adversary who cares about traffic analysis, Secretary on a public cloud folder is the wrong tool. You can mitigate by using your own WebDAV server, an encrypted mount point, or an air-gapped USB sync — but the design does not pretend to provide anonymity.

## What's outside the scope of any software-only system

### Side-channel attacks

A *[side channel](13-glossary.md#side-channel)* is information leakage through a path the algorithm wasn't designed to use: timing variation, power consumption, electromagnetic emissions, acoustic noise from CPUs, even the heat signature of the device. Sophisticated attackers have extracted cryptographic keys from all of these.

Secretary uses constant-time implementations where the underlying cryptographic crates provide them (X25519, Ed25519, AEAD operations are all designed to run in fixed time regardless of input). But measuring side-channels of an arbitrary running program on arbitrary hardware is beyond what a cross-platform application can defend against. If your threat model includes adversaries with physical access and side-channel capabilities, you need air-gapped specialised hardware, not a general-purpose computer.

### Hardware compromise

If the CPU has a backdoor, if the firmware has been tampered with, if the disk controller is exfiltrating data — Secretary cannot detect or defend against any of this. The hardware is part of the trusted computing base, and trust is not divisible. You either trust your hardware or you don't.

For most users this is not a concern; the realistic adversaries are not nation-states with hardware-modification capabilities. For users for whom it is a concern, no consumer software is the right answer. (See [trusted computing base](13-glossary.md#trusted-computing-base).)

### Supply-chain compromise

Secretary depends on dozens of open-source libraries for its cryptographic primitives, file I/O, UI rendering, and so on. If any of those libraries is compromised — replaced upstream with a malicious version, or signed by attackers who have stolen a maintainer's key — the resulting Secretary build could exfiltrate keys, accept malformed inputs, or otherwise behave maliciously.

The mitigations are reproducible builds (so anyone can verify that the binary matches the source), signed releases, and dependency review. The full problem is, as the threat-model document puts it, "an industry-wide unsolved problem." Secretary takes the same precautions everyone else does and hopes they are enough; pretending we have a complete answer would be dishonest.

### Denial of service

An attacker who deletes your cloud-folder copy, corrupts every file, or fills your folder with junk is making a *denial-of-service* attack, not a confidentiality attack. They aren't reading your data; they're preventing you from reading it.

The defense is backups, and the responsibility for backups is yours. Secretary tries to ensure that when you restore from a backup, the restored vault is correctly authenticated (via signatures and high-water marks) and either current or detectably stale. Beyond that, availability is a backup problem, not a cryptography problem.

## How to think about the limits

The pattern across all of this is: cryptography defends a *boundary*. On one side of the boundary — encrypted data, in flight or at rest — strong protection. Across the boundary — into your decrypted memory, into your typed password, into the running OS — cryptography hands the problem to the platform.

A useful self-check when reasoning about your own threat model: is the adversary you're worried about *outside the boundary* or *inside it*? If outside, Secretary's design probably handles them. If inside (malware, coercion, hardware compromise, you forgetting your password), no cryptography can fix it; you need either operational practice or different tools.

## The honest summary

For the realistic adversaries of personal and family use — a stolen laptop, a compromised cloud-folder host, a future quantum computer attempting to decrypt material harvested today, an impersonator on a sharing channel — Secretary's design is appropriate, and the cryptography in this primer holds.

For more sophisticated adversaries — state-level actors, adversaries with hardware access and unlimited time, or scenarios involving coercion — Secretary alone is not the answer. The hardening guide in [docs/manual/hardening-security.md](../../hardening-security.md) describes what you can layer on top, but ultimately such threat models are outside what a software-only personal secrets manager can promise.

What we can promise is: within the boundaries set by this chapter, Secretary's cryptography is sound, post-quantum, well-tested, and built from algorithms standardised by people who have been doing this for decades. That is what cryptography can give you. The rest is operational practice, environmental choices, and judgement.

The final chapter is a glossary of every term used in this primer.
