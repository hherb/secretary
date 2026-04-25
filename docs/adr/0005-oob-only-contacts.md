# ADR 0005 — Contact cards imported via out-of-band channels only; no auto-discovery

**Status:** Accepted (2026-04-25)
**Supersedes:** none
**Superseded by:** none

## Context

To share a block with another Secretary user, the sender must have the recipient's *Contact Card* — specifically, their X25519, ML-KEM-768, Ed25519, and ML-DSA-65 public keys.

With no server, contact-card distribution falls to the users themselves. The mechanisms considered:

- **In-person QR code** — one user displays, another scans.
- **File / paste-string** — export a small file (~3 KB) or copy/paste a base64 string into another channel (email, Signal, paper).
- **Shared-folder auto-discovery** — when a user writes a shared block to a folder, also write their card; the recipient's app finds and imports it.

The first two require explicit user action. The third is convenient (especially for remote family members the user can't meet in person) but introduces a class of attacks: a cloud-folder host with write access to the shared folder can substitute a card with their own keys. The user's app, on detecting "a new card from the folder you trust," might import it silently and the user might then encrypt their next share to the attacker's keys.

The policy choices:

1. **OOB only.** Cards are imported only via QR, file, or paste. Maximum friction for remote contacts but maximum security.
2. **OOB plus opt-in folder discovery, with explicit verification states.** Hybrid: support all three transports but discovered cards default to "unverified" with a UI warning; user clears the warning by performing OOB fingerprint check.
3. **Aggressive auto-discovery default-on.** Lowest friction, highest MITM risk.

Given the multi-decade ciphertext lifespans and the strong inheritance use case, where mistakes echo for decades, the defensive posture matters.

## Decision

**Option 1: OOB only.** Contact cards are imported into a Secretary vault exclusively through one of:

- **QR code** — one device displays, the other scans. Used in-person.
- **File** — `.card` file imported via a file picker.
- **Paste string** — base64-encoded card pasted into a "import contact" UI.

The Secretary application provides no UI affordance for importing cards from shared folders, and the Rust core API does not include a "find cards in this directory" function.

Each contact carries a verification state:
- `imported` — the card has been imported but no OOB verification has been performed. Sharing to this contact warns prominently.
- `fingerprint-verified` — the user has confirmed the 12-word fingerprint mnemonic via a separate channel from the import channel.
- `qr-verified` — the card was imported via QR code, which inherently provides OOB verification.

The verification state is shown on every screen that involves the contact (when sharing a block, when listing recipients, when enumerating contacts). The user cannot upgrade `imported` → `fingerprint-verified` without explicitly invoking the verification UI.

## Consequences

**Positive:**
- The cloud-folder host has no path to substitute a contact's identity. The attacker would need to compromise the QR scan (physical proximity), the file transport channel *and* the verification channel simultaneously, or the device's storage directly.
- The verification state is visible and reversible: a user who "verified" by accident can revert to `imported` and re-verify.
- The user's understanding of "I trust Bob's keys because I checked them with Bob" is preserved — there is no automatic step that bypasses their judgment.

**Negative:**
- Sharing with a remote family member requires more steps than other password managers: send the card by file/email, then call them to confirm the fingerprint. A reasonable one-time onboarding cost per pair, but real friction.
- New users may not understand fingerprint verification. UI must make this concept clear without scaring people. (A non-verified card is still usable; the warning is informational, not blocking.)
- For the inheritance use case specifically, a parent must onboard each child before sharing. If a parent dies before a child has been onboarded, blocks shared to the not-yet-imported child are inaccessible to them. The user must plan ahead. This is consistent with the "we don't operate a service" stance — there is no Secretary-controlled fallback.

**Risks:**
- Users may bypass the verification step ("yeah, I'll verify later") and never come back to it. The UI should keep `imported` warnings persistent enough that users feel the friction until they verify, but not so persistent that they're trained to ignore the warning.

## Revisit when

- Real-world UX shows users systematically ignoring the verification step, suggesting the warning fatigues rather than informs. A possible v2 enhancement is a "trust this contact for amounts under N records, require verification for more" graduated trust scheme.
- A future feature like "trusted introducer" (Bob vouches for Carol, and Alice already trusts Bob, so Alice can import Carol via a Bob-signed card) emerges as worthwhile. This is straightforward to add as additive metadata without breaking the OOB-only invariant for the base case.
