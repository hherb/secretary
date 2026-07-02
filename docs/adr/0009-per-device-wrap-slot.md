# ADR 0009 — Per-device wrap slot for hardware-backed / biometric unlock

**Status:** Accepted (2026-06-10)
**Supersedes:** none
**Superseded by:** none

## Context

ADR 0008 chose native mobile to reach hardware-backed, biometric-bound key release
(Secure Enclave / StrongBox). To unlock after a biometric check without storing the
human master password — and to revoke one device without rotating that password — the
core needs a third way to recover the Identity Block Key (IBK), independent of the
master-password slot (`wrap_pw`, §5) and the recovery-mnemonic slot (`wrap_rec`, §5).

The vault format is frozen for v1: vaults written today must stay byte-readable for
decades. `identity.bundle.enc` (`file_kind 0x0001`) is fixed.

## Decision

Add a **per-device wrap file**, `devices/<device-uuid>.wrap` (`file_kind 0x0004`),
each wrapping the same 32-byte IBK under a per-device KEK:

    device_secret : 32 bytes of OS-CSPRNG entropy (generated at enroll; never stored in the vault)
    device_kek    = HKDF-SHA-256(ikm = device_secret, salt = 32×0x00,
                                 info = "secretary-v1-device-kek", len = 32)
    wrap_dev      = XChaCha20-Poly1305(key = device_kek,
                                       aad = "secretary-v1-id-wrap-dev" || vault_uuid,
                                       plaintext = identity_block_key)

HKDF (not Argon2id), mirroring the recovery KEK (§4): the device secret is high-entropy
CSPRNG output, so password stretching is unnecessary and only slows legitimate use.

`identity.bundle.enc` is **unchanged** — the device slot is an additive, optional, separate
file. A vault with no enrolled devices has no `devices/` directory; a reader that does not
recognise `file_kind 0x0004` opens v1 vaults unchanged.

## Consequences

- **Master password stays off the device.** Full device compromise yields only a
  vault-scoped device secret, never the top-level (possibly reused) password.
- **Per-device revocation.** Delete `devices/<uuid>.wrap`; master password and other
  devices are untouched. Multi-device = multiple files.

  **Revocation boundary (v1 has no IBK rotation).** Deleting a wrap file removes only
  *that copy* of the IBK wrap. It does **not** re-key the vault, so it protects only
  against a device that no longer possesses its 128-byte wrap bytes. It is **not**
  effective against a *compromised* device that retained a copy of its own
  `devices/<uuid>.wrap` plus its `device_secret` (that pair decrypts the IBK forever), nor
  against a cloud provider's version history serving the deleted file back. This is the
  opposite of the block-content-key path, which rotates `K` on every share/revoke and so
  is forward-secret (crypto-design §7.3, vault-format §6.5.1). A genuinely compromised
  device therefore means the whole vault identity is compromised (the IBK decrypts the
  entire bundle); recovering from that requires creating a new vault, not a slot deletion.
  Effective device-level revocation-under-compromise would need IBK rotation + re-wrap of
  every remaining slot — deferred beyond v1.
- **Frozen format preserved.** No change to `identity.bundle.enc`; `golden_vault_001`
  stays byte-identical. The new format is enforced from `docs/` alone by `conformance.py`.

## Alternatives considered

- **Evolve `identity.bundle.enc` in place** (versioned `file_kind` / appended slot) —
  rejected: mutates the frozen file, one slot per file (no multi-device), revoke rewrites
  a shared file (atomicity risk).
- **Store device wraps inside the IBK-encrypted bundle CBOR** — impossible: recovering the
  IBK is the slot's job, so it cannot live behind IBK encryption (circular).
- **Cache the master password under the enclave** — rejected: persists the crown-jewel
  credential and couples revocation to password rotation. See the B.1 design doc.

## Related

- ADR 0008 — native mobile via uniffi (this slot is its key-release foundation).
- ADR 0006 — mandatory recovery key (the second existing wrap slot).
- `docs/superpowers/specs/2026-06-10-b1-device-wrap-slot-design.md` — full design.
- Follow-ups: #201 (B.2 FFI projection), #202 (B.3 iOS Secure Enclave).
