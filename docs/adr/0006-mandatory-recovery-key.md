# ADR 0006 — Mandatory BIP-39 24-word recovery key at vault creation

**Status:** Accepted (2026-04-25)
**Supersedes:** none
**Superseded by:** none

## Context

If a user forgets their master password, they lose access to their vault. With true zero-knowledge architecture and no operated service, there is no support process to recover anything — the cryptography is doing exactly what it claims to do.

Empirically, every password manager that has shipped without a recovery mechanism receives a steady stream of users who lose their data and are upset about it. The harm is real even though the design is correct.

Options considered:

1. **Mandatory recovery key.** At vault creation, generate a high-entropy secret, show it to the user, and force them to acknowledge they have saved it before proceeding. Vault is unlockable by either password OR recovery key.
2. **Optional recovery key.** Same mechanism, but skippable. Most users skip optional flows; many of those then forget.
3. **No recovery, true zero-knowledge.** Brutal but philosophically pure. Best for a power-user audience that knows what it is signing up for.
4. **Shamir Secret Sharing in v1.** Split the recovery key into N shares distributed to trusted contacts; k-of-N reconstructs.

The inheritance use case (parent shares blocks with child) is *not* a recovery use case. Inheritance works through normal sharing while the parent is alive — the child has access to specific blocks via their own identity. A child cannot recover the parent's *vault* (and shouldn't — the parent's other secrets are not the child's business). So recovery and inheritance are independent concerns.

## Decision

Adopt **option 1: mandatory recovery key**.

At vault creation, Secretary generates 256 bits of OS-CSPRNG entropy and encodes it as a 24-word BIP-39 mnemonic from the standard English wordlist. This mnemonic, the *Recovery Mnemonic*, is shown to the user. The user cannot proceed past vault creation without:

1. Viewing the 24-word mnemonic.
2. Confirming they have saved it. The confirmation requires the user to type the last four words back into the UI to demonstrate they actually saved it (and didn't just click "yes I saved it" without doing anything).

The Recovery Mnemonic derives the *Recovery KEK* via HKDF-SHA-256. The Recovery KEK independently wraps the *Identity Block Key* alongside the password-derived wrap. Either the password or the recovery mnemonic suffices to unlock the vault.

The Recovery Mnemonic is *not* persisted anywhere by Secretary. After display + confirmation, it is zeroized. To rotate the mnemonic later, the user invokes a "rotate recovery key" flow that generates a new mnemonic, derives a new Recovery KEK, re-wraps the Identity Block Key, and discards the old one.

## Consequences

**Positive:**
- Users who forget their password have a deterministic recovery path that they own.
- The "I have saved this" confirmation gates progress, so users who skip the save will discover it immediately rather than years later.
- BIP-39 24-word format is industry-standard, transcribable on paper, has built-in checksum (so a single typo is detectable), and has well-vetted libraries in every language.
- Future Shamir Secret Sharing (option 4) layers naturally on top: the mnemonic can itself be split into N shares without touching the base format.

**Negative:**
- The mnemonic is now a high-value target for theft; users must store it carefully (paper, safe, separate password manager, or actual safe deposit box). A user who stores it digitally on the same device as the vault has not improved their security materially.
- Any user who saves it badly (loses the paper, throws it out, takes a photo and the cloud sync sees the photo) loses the recovery option silently. We can warn but cannot enforce safe storage.
- Adds UI complexity at vault creation: a single screen showing the mnemonic plus a re-type confirmation. Minor.
- Code complexity: every credential-changing flow (set password, change password, rotate recovery key) must handle dual wraps consistently.

**Risks:**
- Users may confuse the mnemonic with the master password. UI must distinguish them clearly: the password is what you type to unlock daily; the mnemonic is what you keep in a safe and only retrieve if you forget the password.
- A user who saves the mnemonic poorly (e.g., in an email to themselves) has effectively published it to their email provider. Documentation must address this; UI cannot prevent it.

## Revisit when

- Significant user research shows the mandatory step is too punishing for casual users. Possible mitigation: allow the user to set up the vault without the mnemonic if they explicitly check "I understand losing my password means losing all data forever."
- Shamir Secret Sharing or another threshold-recovery scheme is wanted as a first-class feature. Layering it on top of the recovery mnemonic is straightforward and does not require a new ADR.
