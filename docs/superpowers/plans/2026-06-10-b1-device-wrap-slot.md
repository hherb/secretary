# B.1 — Per-device wrap-slot format & crypto — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third, per-device credential to the vault — a high-entropy random *device secret* that recovers the Identity Block Key (IBK) via its own wrap file (`devices/<uuid>.wrap`, `file_kind 0x0004`) — so a device can later unlock after a biometric check (B.3) without storing the human master password, and can be revoked independently.

**Architecture:** Mirror the existing two-layer split. **Pure layer** (`core/src/unlock/`, `core/src/crypto/`): byte-in/byte-out codec + HKDF-SHA-256 device-KEK derivation + XChaCha20-Poly1305 wrap/unwrap, no I/O. **Folder layer** (`core/src/vault/`): reads/writes the vault directory atomically. The device KEK is derived exactly like `recovery_kek` (HKDF, never Argon2id — the secret is already CSPRNG entropy). `identity.bundle.enc` is **never touched**, so all v1 vaults stay byte-readable.

**Tech Stack:** Rust (stable, `#![forbid(unsafe_code)]`), `hkdf`/`sha2`, `chacha20poly1305` (via `crypto::aead`), `zeroize`; Python stdlib for the clean-room conformance replay.

---

## File structure

**Create:**
- `docs/adr/0009-per-device-wrap-slot.md` — the ADR.
- `core/src/unlock/device_file.rs` — `DeviceWrapFile` struct + `encode`/`decode` + `DeviceFileError` (sibling of `bundle_file.rs`).
- `core/src/unlock/device.rs` — pure crypto ops: `wrap_device_slot`, `unwrap_device_slot`, `open_with_device_secret`.
- `core/src/vault/device_slot.rs` — folder orchestrators: `EnrolledDevice`, `add_device_slot`, `open_identity_with_device_secret`, `remove_device_slot`.
- `core/tests/device_slot.rs` — integration tests (enroll → open → revoke, multi-device, golden-vault KAT guard).

**Modify:**
- `docs/crypto-design.md` — new §5a (device-KEK + device-slot wrap).
- `docs/vault-format.md` — new §3a (`devices/<uuid>.wrap` format) + §1 folder-layout line.
- `docs/glossary.md` — device secret / device slot / device KEK.
- `core/src/crypto/kdf.rs` — `TAG_DEVICE_KEK`, `TAG_ID_WRAP_DEV` consts + `derive_device_kek`.
- `core/src/unlock/mod.rs` — `pub mod device_file; pub mod device;`, new `UnlockError` variants, `compose_aad` → `pub(crate)`.
- `core/src/vault/mod.rs` — `pub mod device_slot;` + `VaultError` variants, `Unlocker::Device`.
- `core/src/vault/orchestrators.rs` — route `Unlocker::Device` (and the `devices/` subdir constant).
- `core/tests/python/conformance.py` — clean-room device-slot replay section.
- `core/tests/data/golden_vault_001/devices/<uuid>.wrap` + the golden inputs JSON — the KAT fixture.
- `README.md`, `ROADMAP.md`, `CLAUDE.md` — status + the new `file_kind 0x0004` note.

**Why these boundaries:** `unlock/mod.rs` is already 635 lines; the new pure ops go in their own `device.rs` rather than growing it ([[feedback_split_files_proactively]]). `orchestrators.rs` is ~1200 lines; folder ops go in their own `device_slot.rs`. The codec is its own file exactly like `bundle_file.rs`.

---

## Task 0: Spec-first — ADR 0009 + normative format docs

Spec is the contract; it changes before code (`CLAUDE.md` "Spec is normative"). No tests here — this task produces the normative text the rest of the plan implements.

**Files:**
- Create: `docs/adr/0009-per-device-wrap-slot.md`
- Modify: `docs/crypto-design.md`, `docs/vault-format.md`, `docs/glossary.md`

- [ ] **Step 1: Write ADR 0009**

Create `docs/adr/0009-per-device-wrap-slot.md` following the existing ADR shape (see `0006-mandatory-recovery-key.md` / `0008-native-mobile-via-uniffi.md` for tone):

```markdown
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
```

- [ ] **Step 2: Add crypto-design.md §5a**

Insert a new section after §5 (Identity Bundle wrap) and before §6. Match the numbered-step
style of §4/§5:

````markdown
## 5a. Device-slot wrap (per-device credential)

A vault MAY carry zero or more *device slots*, each an independent way to recover the
Identity Block Key (IBK) defined in §5. A device slot is created when a device enrolls for
hardware-backed/biometric unlock (ADR 0009).

Given a fresh `device_secret` (32 bytes from the OS CSPRNG, generated at enrollment and
never persisted inside the vault):

```
device_kek = HKDF-SHA-256(
    ikm  = device_secret,
    salt = 32 bytes of 0x00,
    info = "secretary-v1-device-kek",
    len  = 32,
)
(ct_dev, tag_dev) = XChaCha20-Poly1305-Encrypt(
    key       = device_kek,
    nonce     = 24 bytes from the OS CSPRNG,
    aad       = "secretary-v1-id-wrap-dev" || vault_uuid,
    plaintext = identity_block_key,        # the SAME 32-byte IBK as wrap_pw / wrap_rec (§5)
)
```

As with the recovery KEK (§4), Argon2id is deliberately NOT used: the device secret carries
256 bits of CSPRNG entropy, so stretching is unnecessary. The `device_secret` and
`device_kek` are zeroized after wrapping/unwrapping.

Decryption: derive `device_kek` from the supplied `device_secret`, then AEAD-decrypt
`(ct_dev, tag_dev)` to recover the IBK. AEAD tag failure means a wrong device secret (or
corruption — indistinguishable to the cryptography, matching §13), surfaced to the UI as
wrong-secret. The on-disk container is `docs/vault-format.md` §3a.
````

- [ ] **Step 3: Add vault-format.md §3a + the folder-layout line**

In §1 folder layout, add a `devices/` entry after `contacts/`:

```
  devices/
    <device-uuid>.wrap                    # per-device IBK wrap (file_kind 0x0004); see §3a
    ...
```

Insert §3a after §3:

````markdown
## 3a. `devices/<device-uuid>.wrap` — per-device IBK wrap

An optional, additive file (ADR 0009). Each enrolled device has one. Big-endian integers,
same header discipline as §3. A vault with no enrolled devices has no `devices/` directory.

```
┌──────────────────────────────────────────────────────────────┐
│ magic              (4 bytes)  = MAGIC                         │
│ format_version     (2 bytes)  = u16, v1: 0x0001              │
│ file_kind          (2 bytes)  = u16, device-wrap: 0x0004     │
│ vault_uuid         (16 bytes)                                 │
│ device_uuid        (16 bytes)                                 │
│ wrap_dev_nonce     (24 bytes) = XChaCha20 nonce              │
│ wrap_dev_ct_len    (4 bytes)  = u32, must be 32              │
│ wrap_dev_ct        (32 bytes) = AEAD ciphertext of the IBK   │
│ wrap_dev_tag       (16 bytes) = Poly1305 tag                 │
└──────────────────────────────────────────────────────────────┘
```

- `suite_id` is omitted, matching §3 (identity-layer files fix the suite at v1; only
  manifest/block *content* files carry `suite_id`).
- `wrap_dev_ct_len` records the **unwrapped** key length (32), matching §3's
  `wrap_pw_ct_len` / `wrap_rec_ct_len` convention.
- `vault_uuid` MUST equal the vault's `vault.toml` `vault_uuid`; a mismatch is rejected.
- `device_uuid` in the header MUST equal the `<device-uuid>` in the filename.
- AEAD AAD = `"secretary-v1-id-wrap-dev" || vault_uuid`; `device_kek` derivation is
  `docs/crypto-design.md` §5a.

Filenames use the lowercase-hyphenated 8-4-4-4-12 UUID form, as for blocks/contacts (§1).
````

- [ ] **Step 4: Add glossary entries**

Append to `docs/glossary.md` (match existing entry style):

```markdown
- **Device secret** — 32 bytes of OS-CSPRNG entropy generated when a device enrolls for
  hardware-backed/biometric unlock. Recovers the IBK via the device slot. Never stored in
  the vault; held off-device (e.g. iOS Secure Enclave) by the platform layer. See ADR 0009.
- **Device slot** — a `devices/<uuid>.wrap` file wrapping the IBK under a device KEK; a
  third unlock path alongside the master-password and recovery slots. See vault-format §3a.
- **Device KEK** — `HKDF-SHA-256(device_secret)`; the AEAD key for a device slot
  (crypto-design §5a).
```

- [ ] **Step 5: Verify docs build cleanly and commit**

Run: `cd /Users/hherb/src/secretary/.worktrees/b1-device-wrap-slot && grep -n "5a\|3a\|0x0004\|device-kek\|id-wrap-dev" docs/crypto-design.md docs/vault-format.md`
Expected: the new section headers, the `0x0004` kind, and both new tag strings appear.

```bash
git add docs/adr/0009-per-device-wrap-slot.md docs/crypto-design.md docs/vault-format.md docs/glossary.md
git commit -m "docs(spec): ADR 0009 + §5a/§3a per-device wrap slot (file_kind 0x0004)"
```

---

## Task 1: `derive_device_kek` + domain-separation tags

**Files:**
- Modify: `core/src/crypto/kdf.rs`
- Test: `core/src/crypto/kdf.rs` (in its `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add to the test module in `core/src/crypto/kdf.rs` (find the existing `mod tests`; if
`derive_recovery_kek` has tests there, place these beside them):

```rust
#[test]
fn device_kek_is_deterministic_and_independent_of_recovery_kek() {
    // Same secret → same device_kek (deterministic HKDF).
    let secret = Sensitive::new([0x5Au8; 32]);
    let a = derive_device_kek(&secret);
    let b = derive_device_kek(&secret);
    assert_eq!(a.expose(), b.expose());

    // The device-KEK info string differs from the recovery-KEK info string, so the
    // two KEKs derived from the SAME 32 bytes must differ (domain separation).
    let recovery = derive_recovery_kek(&secret);
    assert_ne!(a.expose(), recovery.expose());
}

#[test]
fn device_kek_matches_independent_hkdf_reference() {
    // Independent recomputation from the spec (crypto-design §5a) using the same
    // primitive, asserting the info string and salt are exactly as documented.
    use hkdf::Hkdf;
    use sha2::Sha256;
    let secret = Sensitive::new([0x11u8; 32]);
    let mut expected = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), secret.expose())
        .expand(b"secretary-v1-device-kek", &mut expected)
        .unwrap();
    assert_eq!(derive_device_kek(&secret).expose(), &expected);
}

#[test]
fn device_kek_tag_value_matches_spec() {
    assert_eq!(TAG_DEVICE_KEK, b"secretary-v1-device-kek");
    assert_eq!(TAG_ID_WRAP_DEV, b"secretary-v1-id-wrap-dev");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release -p secretary-core --lib crypto::kdf 2>&1 | tail -20`
Expected: FAIL — `cannot find function derive_device_kek` / `cannot find value TAG_DEVICE_KEK`.

- [ ] **Step 3: Add the consts and the function**

In `core/src/crypto/kdf.rs`, beside the other `TAG_*` consts, add:

```rust
/// HKDF info for Device KEK derivation (§5a). Distinct from [`TAG_RECOVERY_KEK`]
/// so the same 32 bytes never derive the same KEK in both roles.
pub const TAG_DEVICE_KEK: &[u8] = b"secretary-v1-device-kek";

/// AEAD AAD prefix for wrapping the Identity Block Key under a Device KEK (§5a).
pub const TAG_ID_WRAP_DEV: &[u8] = b"secretary-v1-id-wrap-dev";
```

Beside `derive_recovery_kek`, add its verbatim sibling (only the `info` arg differs):

```rust
/// Derive a Device KEK from a 32-byte device secret, per crypto-design §5a.
///
/// HKDF-SHA-256 with `salt = [0u8; 32]` and `info = "secretary-v1-device-kek"`.
/// The device secret carries 256 bits of CSPRNG entropy, so — exactly like the
/// recovery mnemonic (§4) — no Argon2id stretching is performed.
///
/// SECURITY: same `hkdf` 0.12 PRK-residue caveat documented on
/// [`derive_recovery_kek`]; the `Hkdf` instance is tightly scoped.
#[must_use]
pub fn derive_device_kek(secret: &Sensitive<[u8; 32]>) -> Sensitive<[u8; 32]> {
    let salt = [0u8; 32];
    let mut out = [0u8; 32];
    {
        let hk = Hkdf::<Sha256>::new(Some(&salt), secret.expose());
        hk.expand(TAG_DEVICE_KEK, &mut out)
            .expect("32 bytes is well within HKDF-SHA-256 output limits");
    }
    let kek = Sensitive::new(out);
    out.zeroize();
    kek
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --release -p secretary-core --lib crypto::kdf 2>&1 | tail -20`
Expected: PASS (all three new tests).

- [ ] **Step 5: Commit**

```bash
git add core/src/crypto/kdf.rs
git commit -m "feat(crypto): derive_device_kek + device-slot domain-separation tags (§5a)"
```

---

## Task 2: `device_file.rs` codec (`file_kind 0x0004`)

**Files:**
- Create: `core/src/unlock/device_file.rs`
- Modify: `core/src/unlock/mod.rs` (add `pub mod device_file;`)
- Test: `core/src/unlock/device_file.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Register the module**

In `core/src/unlock/mod.rs`, in the module declarations near the top
(`pub mod bundle; pub mod bundle_file; ...`), add:

```rust
pub mod device_file;
```

- [ ] **Step 2: Write the codec with its failing tests**

Create `core/src/unlock/device_file.rs`. This mirrors `bundle_file.rs` (same big-endian
helpers, same error shape) but with the §3a layout (no `created_at_ms`; a `device_uuid`;
a single wrap):

```rust
//! `devices/<device-uuid>.wrap` binary envelope (`docs/vault-format.md` §3a).
//!
//! Big-endian throughout. One AEAD payload (`wrap_dev`), stored as
//! `nonce || ct_len(=32) || ct || tag`. Sibling of `bundle_file.rs`; the
//! header shares the `MAGIC || format_version || file_kind || vault_uuid`
//! prefix and then diverges (a `device_uuid` replaces §3's `created_at_ms`).

use crate::version::{FORMAT_VERSION, MAGIC};

/// File-kind identifier for a per-device wrap file (§3a). Distinct from
/// identity-bundle (0x0001), manifest (0x0002), block (0x0003).
pub(crate) const FILE_KIND_DEVICE_WRAP: u16 = 0x0004;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const WRAP_CT_PLUS_TAG_LEN: usize = 32 + 16; // identity_block_key + tag

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWrapFile {
    pub vault_uuid: [u8; 16],
    pub device_uuid: [u8; 16],
    pub wrap_dev_nonce: [u8; NONCE_LEN],
    pub wrap_dev_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN],
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceFileError {
    #[error("file truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("trailing bytes after parse at offset {offset}")]
    TrailingBytes { offset: usize },
    #[error("bad magic: expected SECR, got {got:#010x}")]
    BadMagic { got: u32 },
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unsupported file kind: {0}")]
    UnsupportedFileKind(u16),
    #[error("declared length for wrap_dev: expected 32, got {declared}")]
    WrapLengthMismatch { declared: u32 },
}

/// Serialize a [`DeviceWrapFile`] to its §3a byte form.
pub fn encode(file: &DeviceWrapFile) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 2 + 16 + 16 + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN);
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&FILE_KIND_DEVICE_WRAP.to_be_bytes());
    out.extend_from_slice(&file.vault_uuid);
    out.extend_from_slice(&file.device_uuid);
    out.extend_from_slice(&file.wrap_dev_nonce);
    // wrap_dev_ct_len = 32 (unwrapped IBK size), per §3a, matching §3's convention.
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&file.wrap_dev_ct_with_tag);
    out
}

pub fn decode(bytes: &[u8]) -> Result<DeviceWrapFile, DeviceFileError> {
    let mut pos = 0;
    let magic = read_u32_be(bytes, &mut pos)?;
    if magic != MAGIC {
        return Err(DeviceFileError::BadMagic { got: magic });
    }
    let format_version = read_u16_be(bytes, &mut pos)?;
    if format_version != FORMAT_VERSION {
        return Err(DeviceFileError::UnsupportedFormatVersion(format_version));
    }
    let file_kind = read_u16_be(bytes, &mut pos)?;
    if file_kind != FILE_KIND_DEVICE_WRAP {
        return Err(DeviceFileError::UnsupportedFileKind(file_kind));
    }
    let vault_uuid = read_array::<16>(bytes, &mut pos)?;
    let device_uuid = read_array::<16>(bytes, &mut pos)?;
    let wrap_dev_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let wrap_dev_ct_len = read_u32_be(bytes, &mut pos)?;
    if wrap_dev_ct_len != 32 {
        return Err(DeviceFileError::WrapLengthMismatch { declared: wrap_dev_ct_len });
    }
    let wrap_dev_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    if pos != bytes.len() {
        return Err(DeviceFileError::TrailingBytes { offset: pos });
    }
    Ok(DeviceWrapFile {
        vault_uuid,
        device_uuid,
        wrap_dev_nonce,
        wrap_dev_ct_with_tag,
    })
}

fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, DeviceFileError> {
    Ok(u16::from_be_bytes(read_array::<2>(bytes, pos)?))
}
fn read_u32_be(bytes: &[u8], pos: &mut usize) -> Result<u32, DeviceFileError> {
    Ok(u32::from_be_bytes(read_array::<4>(bytes, pos)?))
}
fn read_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], DeviceFileError> {
    if *pos + N > bytes.len() {
        return Err(DeviceFileError::Truncated { offset: *pos });
    }
    let out: [u8; N] = bytes[*pos..*pos + N]
        .try_into()
        .expect("bounds check above guarantees N bytes");
    *pos += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DeviceWrapFile {
        DeviceWrapFile {
            vault_uuid: [0x11; 16],
            device_uuid: [0x22; 16],
            wrap_dev_nonce: [0x33; NONCE_LEN],
            wrap_dev_ct_with_tag: [0x44; WRAP_CT_PLUS_TAG_LEN],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let f = sample();
        assert_eq!(decode(&encode(&f)).unwrap(), f);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = encode(&sample());
        bytes[0] ^= 0xFF;
        assert!(matches!(decode(&bytes).unwrap_err(), DeviceFileError::BadMagic { .. }));
    }

    #[test]
    fn decode_rejects_bad_format_version() {
        let mut bytes = encode(&sample());
        bytes[5] = 0x02;
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DeviceFileError::UnsupportedFormatVersion(2)
        ));
    }

    #[test]
    fn decode_rejects_bad_file_kind() {
        let mut bytes = encode(&sample());
        bytes[7] = 0x01; // pretend to be an identity bundle
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DeviceFileError::UnsupportedFileKind(1)
        ));
    }

    #[test]
    fn decode_rejects_wrap_length_mismatch() {
        let bytes = encode(&sample());
        // offset: magic(4)+ver(2)+kind(2)+vault_uuid(16)+device_uuid(16)+nonce(24)
        let len_off = 4 + 2 + 2 + 16 + 16 + NONCE_LEN;
        assert_eq!(len_off, 64);
        let mut tampered = bytes.clone();
        tampered[len_off..len_off + 4].copy_from_slice(&64u32.to_be_bytes());
        assert!(matches!(
            decode(&tampered).unwrap_err(),
            DeviceFileError::WrapLengthMismatch { declared: 64 }
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&sample());
        bytes.push(0xAA);
        assert!(matches!(decode(&bytes).unwrap_err(), DeviceFileError::TrailingBytes { .. }));
    }

    #[test]
    fn decode_rejects_truncated_at_every_boundary() {
        let bytes = encode(&sample());
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err(), "must fail on [..{n}]");
        }
        decode(&bytes).expect("full bytes decode");
    }
}
```

- [ ] **Step 3: Run the codec tests to verify they pass**

Run: `cargo test --release -p secretary-core --lib unlock::device_file 2>&1 | tail -20`
Expected: PASS (all device_file tests).

- [ ] **Step 4: Lint**

Run: `cargo clippy --release -p secretary-core --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add core/src/unlock/device_file.rs core/src/unlock/mod.rs
git commit -m "feat(unlock): device_file codec (vault-format §3a, file_kind 0x0004)"
```

---

## Task 3: Pure device crypto ops — `wrap`, `unwrap`, `open_with_device_secret`

**Files:**
- Create: `core/src/unlock/device.rs`
- Modify: `core/src/unlock/mod.rs` (`pub mod device;`, `compose_aad` → `pub(crate)`, new `UnlockError` variants)
- Test: `core/src/unlock/device.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Expose `compose_aad` and add error variants**

In `core/src/unlock/mod.rs`:

1. Change `fn compose_aad(` to `pub(crate) fn compose_aad(` (line ~289).
2. Add the module declaration beside `pub mod device_file;`:

```rust
pub mod device;
```

3. Add two variants to `enum UnlockError` (beside `WrongMnemonicOrCorrupt`):

```rust
    #[error("wrong device secret or vault corruption")]
    WrongDeviceSecretOrCorrupt,
    #[error("malformed device wrap file: {0}")]
    MalformedDeviceFile(#[from] device_file::DeviceFileError),
    #[error("device secret must be exactly 32 bytes, got {len}")]
    MalformedDeviceSecret { len: usize },
```

- [ ] **Step 2: Write the failing tests**

Create `core/src/unlock/device.rs` with the test module first (the impl follows in Step 4):

```rust
//! Pure (no-I/O) per-device wrap-slot crypto: wrap/unwrap the Identity Block
//! Key under a device KEK, and open a vault from a device secret. The byte
//! container is `device_file`; the KEK is `crypto::kdf::derive_device_kek`.
//! Folder-level enroll/open/revoke live in `crate::vault::device_slot`.
//! See `docs/crypto-design.md` §5a and `docs/vault-format.md` §3a.

use crate::crypto::aead::{decrypt, encrypt, random_nonce, AeadNonce};
use crate::crypto::kdf::{derive_device_kek, TAG_ID_BUNDLE, TAG_ID_WRAP_DEV};
use crate::crypto::secret::{SecretBytes, Sensitive};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize as _;

use super::bundle;
use super::compose_aad;
use super::device_file::{self, DeviceWrapFile, WRAP_CT_PLUS_TAG_LEN};
use super::vault_toml;
use super::{vault_toml_not_utf8, UnlockError, UnlockedIdentity};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2idParams;
    use crate::unlock::{create_vault_unchecked, open_with_password};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    fn fresh_secret(seed: u8) -> Sensitive<[u8; 32]> {
        Sensitive::new([seed; 32])
    }

    #[test]
    fn wrap_then_unwrap_roundtrips_the_ibk() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let ibk = fresh_secret(0xAB);
        let secret = fresh_secret(0x5A);
        let file = wrap_device_slot(&ibk, [9u8; 16], [7u8; 16], &secret, random_nonce(&mut rng));
        let recovered = unwrap_device_slot(&file, &secret).expect("unwrap");
        assert_eq!(recovered.expose(), ibk.expose());
    }

    #[test]
    fn unwrap_with_wrong_secret_is_typed_error() {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let ibk = fresh_secret(0xCD);
        let file = wrap_device_slot(&ibk, [9u8; 16], [7u8; 16], &fresh_secret(0x01), random_nonce(&mut rng));
        let err = unwrap_device_slot(&file, &fresh_secret(0x02)).unwrap_err();
        assert!(matches!(err, UnlockError::WrongDeviceSecretOrCorrupt));
    }

    #[test]
    fn unwrap_rejects_cross_vault_aad() {
        // A slot wrapped for vault A must not unwrap when its header says vault B
        // (the AAD binds vault_uuid; tampering the header breaks the tag).
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let ibk = fresh_secret(0xEF);
        let secret = fresh_secret(0x5A);
        let mut file = wrap_device_slot(&ibk, [0xAA; 16], [7u8; 16], &secret, random_nonce(&mut rng));
        file.vault_uuid = [0xBB; 16]; // pretend it belongs to another vault
        let err = unwrap_device_slot(&file, &secret).unwrap_err();
        assert!(matches!(err, UnlockError::WrongDeviceSecretOrCorrupt));
    }

    #[test]
    fn open_with_device_secret_yields_same_identity_as_password() {
        let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let v = create_vault_unchecked(&password, "Alice", 0, Argon2idParams::new(8, 1, 1), &mut rng)
            .unwrap();

        // Enroll a device by wrapping the just-created IBK.
        let secret = fresh_secret(0x77);
        let file = wrap_device_slot(
            &v.identity_block_key,
            // vault_uuid is the first 16 bytes the bundle file carries; read it back via
            // the password open path below for the cross-check. Here we re-decode it.
            super::device_file_vault_uuid(&v.identity_bundle_bytes),
            [0x42; 16],
            &secret,
            random_nonce(&mut rng),
        );
        let device_wrap_bytes = device_file::encode(&file);

        let secret_bytes = SecretBytes::new(secret.expose().to_vec());
        let by_dev = open_with_device_secret(
            &v.vault_toml_bytes,
            &device_wrap_bytes,
            &v.identity_bundle_bytes,
            &secret_bytes,
        )
        .expect("open with device secret");
        let by_pw = open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &password).unwrap();
        assert_eq!(by_dev.identity_block_key.expose(), by_pw.identity_block_key.expose());
        assert_eq!(by_dev.identity.user_uuid, by_pw.identity.user_uuid);
    }

    #[test]
    fn open_with_device_secret_rejects_wrong_length_secret() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let v = create_vault_unchecked(&password, "Alice", 0, Argon2idParams::new(8, 1, 1), &mut rng)
            .unwrap();
        let secret = fresh_secret(0x77);
        let file = wrap_device_slot(
            &v.identity_block_key,
            super::device_file_vault_uuid(&v.identity_bundle_bytes),
            [0x42; 16],
            &secret,
            random_nonce(&mut rng),
        );
        let device_wrap_bytes = device_file::encode(&file);
        let short = SecretBytes::new(vec![0u8; 31]);
        let err = open_with_device_secret(
            &v.vault_toml_bytes,
            &device_wrap_bytes,
            &v.identity_bundle_bytes,
            &short,
        )
        .unwrap_err();
        assert!(matches!(err, UnlockError::MalformedDeviceSecret { len: 31 }));
    }
}
```

> Note: the test references a tiny private helper `device_file_vault_uuid`; define it in the
> impl below. It decodes a `BundleFile` only to read its `vault_uuid`, used purely to wire the
> tests (production callers pass the vault_uuid they already hold).

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --release -p secretary-core --lib unlock::device 2>&1 | tail -20`
Expected: FAIL — `cannot find function wrap_device_slot` etc.

- [ ] **Step 4: Write the implementation**

Insert above the `#[cfg(test)] mod tests` block in `core/src/unlock/device.rs`:

```rust
/// Convert a boundary `SecretBytes` device secret into the fixed 32-byte form
/// the KEK derivation needs, copying then zeroizing the stack array. A
/// non-32-byte secret is a typed error (external callers in B.2/B.3 supply it).
fn secret_to_array(secret: &SecretBytes) -> Result<Sensitive<[u8; 32]>, UnlockError> {
    let exposed = secret.expose();
    if exposed.len() != 32 {
        return Err(UnlockError::MalformedDeviceSecret { len: exposed.len() });
    }
    let mut arr: [u8; 32] = exposed.try_into().expect("length checked above");
    let out = Sensitive::new(arr);
    arr.zeroize();
    Ok(out)
}

/// Wrap a 32-byte IBK under a device KEK derived from `device_secret` (§5a).
/// Pure and deterministic given `nonce`. The caller supplies the vault and
/// device UUIDs (both are bound into the file; `vault_uuid` is in the AEAD AAD).
pub fn wrap_device_slot(
    ibk: &Sensitive<[u8; 32]>,
    vault_uuid: [u8; 16],
    device_uuid: [u8; 16],
    device_secret: &Sensitive<[u8; 32]>,
    nonce: AeadNonce,
) -> DeviceWrapFile {
    let device_kek = derive_device_kek(device_secret);
    let aad = compose_aad(TAG_ID_WRAP_DEV, &vault_uuid);
    let ct_with_tag = encrypt(&device_kek, &nonce, &aad, ibk.expose())
        .expect("AEAD encrypt of 32-byte IBK is structurally infallible");
    let wrap_dev_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN] = ct_with_tag
        .as_slice()
        .try_into()
        .expect("32-byte plaintext + 16-byte tag = 48 bytes");
    DeviceWrapFile {
        vault_uuid,
        device_uuid,
        wrap_dev_nonce: nonce,
        wrap_dev_ct_with_tag,
    }
}

/// Recover the IBK from a device slot using `device_secret`. AEAD tag failure →
/// [`UnlockError::WrongDeviceSecretOrCorrupt`] (wrong secret, header tampering,
/// or corruption — indistinguishable to the cryptography, per §13).
pub fn unwrap_device_slot(
    file: &DeviceWrapFile,
    device_secret: &Sensitive<[u8; 32]>,
) -> Result<Sensitive<[u8; 32]>, UnlockError> {
    let device_kek = derive_device_kek(device_secret);
    let aad = compose_aad(TAG_ID_WRAP_DEV, &file.vault_uuid);
    let ibk_bytes = decrypt(&device_kek, &file.wrap_dev_nonce, &aad, &file.wrap_dev_ct_with_tag)
        .map_err(|_| UnlockError::WrongDeviceSecretOrCorrupt)?;
    let mut ibk_arr: [u8; 32] = ibk_bytes
        .expose()
        .try_into()
        .map_err(|_| UnlockError::CorruptVault)?;
    let ibk = Sensitive::new(ibk_arr);
    ibk_arr.zeroize();
    Ok(ibk)
}

/// Open a vault from a device secret (the §5a device-slot unlock path). Pure:
/// operates on the three files' bytes, mirroring `open_with_recovery`.
pub fn open_with_device_secret(
    vault_toml_bytes: &[u8],
    device_wrap_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    device_secret: &SecretBytes,
) -> Result<UnlockedIdentity, UnlockError> {
    let vt_str = std::str::from_utf8(vault_toml_bytes).map_err(|_| vault_toml_not_utf8())?;
    let vt = vault_toml::decode(vt_str)?;
    let df = device_file::decode(device_wrap_bytes)?;
    // The device file must belong to this vault. (The identity bundle's own
    // vault_uuid is AEAD-checked when we decrypt the bundle below.)
    if df.vault_uuid != vt.vault_uuid {
        return Err(UnlockError::VaultMismatch);
    }
    let bf = super::bundle_file::decode(identity_bundle_bytes)?;
    if bf.vault_uuid != vt.vault_uuid || bf.created_at_ms != vt.created_at_ms {
        return Err(UnlockError::VaultMismatch);
    }

    let secret = secret_to_array(device_secret)?;
    let identity_block_key = unwrap_device_slot(&df, &secret)?;

    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vt.vault_uuid);
    let bundle_plaintext = decrypt(
        &identity_block_key,
        &bf.bundle_nonce,
        &bundle_aad,
        &bf.bundle_ct_with_tag,
    )
    .map_err(|_| UnlockError::CorruptVault)?;
    let identity = bundle::IdentityBundle::from_canonical_cbor(bundle_plaintext.expose())?;
    Ok(UnlockedIdentity {
        identity_block_key,
        identity,
    })
}

/// Test-only helper: read just the `vault_uuid` out of an encoded identity
/// bundle, so unit tests can wire a wrap without re-plumbing the UUID.
#[cfg(test)]
pub(super) fn device_file_vault_uuid(identity_bundle_bytes: &[u8]) -> [u8; 16] {
    super::bundle_file::decode(identity_bundle_bytes)
        .expect("test bundle decodes")
        .vault_uuid
}
```

> If clippy flags `bundle` or `vault_toml` imports as unused, prune to the exact set the
> compiler reports — the list above matches the functions used.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --release -p secretary-core --lib unlock::device 2>&1 | tail -20`
Expected: PASS (all five tests).

- [ ] **Step 6: Lint and commit**

Run: `cargo clippy --release -p secretary-core --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

```bash
git add core/src/unlock/device.rs core/src/unlock/mod.rs
git commit -m "feat(unlock): pure device-slot wrap/unwrap + open_with_device_secret (§5a)"
```

---

## Task 4: Folder orchestrators — enroll, open, revoke

**Files:**
- Create: `core/src/vault/device_slot.rs`
- Modify: `core/src/vault/mod.rs` (`pub mod device_slot;`, `VaultError::DeviceSlotNotFound`)
- Test: `core/tests/device_slot.rs` (integration; created here)

- [ ] **Step 1: Add the module + error variant**

In `core/src/vault/mod.rs`: add `pub mod device_slot;` beside the other `pub mod`
declarations, and add to `enum VaultError`:

```rust
    /// No `devices/<device-uuid>.wrap` file for the requested device.
    #[error("device slot not found")]
    DeviceSlotNotFound,
```

> Check whether `VaultError` already has an `Io { context, .. }` variant (it does — used by
> `orchestrators.rs`). Reuse it for filesystem errors below; only add `DeviceSlotNotFound`.

- [ ] **Step 2: Write the integration test (failing)**

Create `core/tests/device_slot.rs`:

```rust
//! Folder-level device-slot integration: enroll → open → revoke, multi-device,
//! and the read-only-fixture hygiene from [[feedback_smoke_test_temp_copy_golden_vault]].

use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::device_slot::{add_device_slot, open_identity_with_device_secret, remove_device_slot};

/// Create a fresh on-disk vault in an empty temp dir; return (dir, password).
fn make_vault(seed: u8) -> (tempfile::TempDir, SecretBytes) {
    let dir = tempfile::tempdir().unwrap();
    let password = SecretBytes::new(b"hunter2".to_vec());
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    // create_vault signature: (folder, password, display_name, kdf_params, created_at_ms, rng)
    secretary_core::vault::create_vault(
        dir.path(),
        &password,
        "Alice",
        Argon2idParams::new(8, 1, 1),
        0,
        &mut rng,
    )
    .expect("create_vault");
    (dir, password)
}

#[test]
fn enroll_then_open_with_device_secret_roundtrips() {
    let (dir, password) = make_vault(1);
    let mut rng = ChaCha20Rng::from_seed([20u8; 32]);
    let enrolled = add_device_slot(dir.path(), &password, &mut rng).expect("enroll");

    // The wrap file exists under devices/.
    let wrap = dir.path().join("devices").join(format!(
        "{}.wrap",
        secretary_core::vault::format_uuid_hyphenated(&enrolled.device_uuid)
    ));
    assert!(wrap.exists(), "device wrap file should be written");

    // Opening with the returned secret yields the same identity as the password path.
    let opened = open_identity_with_device_secret(dir.path(), &enrolled.device_uuid, &enrolled.device_secret)
        .expect("open by device secret");
    let by_pw = open_identity_with_password(dir.path(), &password);
    assert_eq!(opened.identity_block_key.expose(), by_pw.identity_block_key.expose());
}

#[test]
fn revoke_then_open_fails_not_found() {
    let (dir, password) = make_vault(2);
    let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
    let enrolled = add_device_slot(dir.path(), &password, &mut rng).expect("enroll");
    remove_device_slot(dir.path(), &enrolled.device_uuid).expect("revoke");
    let err = open_identity_with_device_secret(dir.path(), &enrolled.device_uuid, &enrolled.device_secret)
        .unwrap_err();
    assert!(matches!(err, secretary_core::vault::VaultError::DeviceSlotNotFound));
}

#[test]
fn two_devices_open_independently() {
    let (dir, password) = make_vault(3);
    let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
    let a = add_device_slot(dir.path(), &password, &mut rng).expect("enroll a");
    let b = add_device_slot(dir.path(), &password, &mut rng).expect("enroll b");
    assert_ne!(a.device_uuid, b.device_uuid);

    let oa = open_identity_with_device_secret(dir.path(), &a.device_uuid, &a.device_secret).unwrap();
    let ob = open_identity_with_device_secret(dir.path(), &b.device_uuid, &b.device_secret).unwrap();
    assert_eq!(oa.identity_block_key.expose(), ob.identity_block_key.expose());

    // Revoking A leaves B working.
    remove_device_slot(dir.path(), &a.device_uuid).unwrap();
    assert!(open_identity_with_device_secret(dir.path(), &a.device_uuid, &a.device_secret).is_err());
    assert!(open_identity_with_device_secret(dir.path(), &b.device_uuid, &b.device_secret).is_ok());
}

#[test]
fn enroll_with_wrong_password_writes_nothing() {
    let (dir, _password) = make_vault(4);
    let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
    let bad = SecretBytes::new(b"wrong".to_vec());
    assert!(add_device_slot(dir.path(), &bad, &mut rng).is_err());
    let devices = dir.path().join("devices");
    let count = devices.exists().then(|| std::fs::read_dir(&devices).unwrap().count()).unwrap_or(0);
    assert_eq!(count, 0, "no wrap file may be written on a failed enroll");
}

/// Local helper mirroring the password open path to get an UnlockedIdentity from a folder.
fn open_identity_with_password(
    folder: &Path,
    password: &SecretBytes,
) -> secretary_core::unlock::UnlockedIdentity {
    let vt = std::fs::read(folder.join("vault.toml")).unwrap();
    let ib = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    secretary_core::unlock::open_with_password(&vt, &ib, password).unwrap()
}
```

> This test references the public re-exports `secretary_core::vault::{create_vault,
> format_uuid_hyphenated, VaultError, device_slot::*}`, `secretary_core::unlock::{Argon2idParams,
> UnlockedIdentity, open_with_password}`, and `secretary_core::crypto::secret::SecretBytes`.
> If any is not already `pub` at that path, add the re-export in the relevant `mod.rs` as part
> of Step 4 (the crypto/unlock items are already public; confirm `device_slot` is exported).

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test --release -p secretary-core --test device_slot 2>&1 | tail -20`
Expected: FAIL — `device_slot` module / functions not found.

- [ ] **Step 4: Implement the folder orchestrators**

Create `core/src/vault/device_slot.rs`. Reuse `format_uuid_hyphenated`, `write_atomic`, and
the file-reading pattern from `orchestrators.rs`:

```rust
//! Folder-level per-device wrap-slot operations (ADR 0009 / vault-format §3a):
//! enroll (`add_device_slot`), open (`open_identity_with_device_secret`), and
//! revoke (`remove_device_slot`). Pure crypto/codec lives in
//! `crate::unlock::device`; this layer is the directory I/O edge.

use std::path::Path;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize as _;

use super::io::write_atomic;
use super::orchestrators::format_uuid_hyphenated;
use super::VaultError;
use crate::crypto::aead::random_nonce;
use crate::crypto::secret::{SecretBytes, Sensitive};
use crate::unlock::device::{open_with_device_secret, wrap_device_slot};
use crate::unlock::{device_file, open_with_password, UnlockedIdentity};

const VAULT_TOML_FILENAME: &str = "vault.toml";
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";
const DEVICES_SUBDIR: &str = "devices";

/// The outcome of enrolling a device. `device_secret` is the only copy that
/// exits the core — the caller (B.3) wraps it into the Secure Enclave. It is
/// zeroize-typed and never written into the vault.
pub struct EnrolledDevice {
    pub device_uuid: [u8; 16],
    pub device_secret: SecretBytes,
}

fn read_vault_file(folder: &Path, name: &str) -> Result<Vec<u8>, VaultError> {
    std::fs::read(folder.join(name)).map_err(|e| VaultError::Io {
        context: "failed to read vault file for device-slot op",
        source: e,
    })
}

fn device_wrap_path(folder: &Path, device_uuid: &[u8; 16]) -> std::path::PathBuf {
    folder
        .join(DEVICES_SUBDIR)
        .join(format!("{}.wrap", format_uuid_hyphenated(device_uuid)))
}

/// Enroll a new device: recover the IBK with `password`, mint a fresh device
/// secret + UUID, and write `devices/<uuid>.wrap` atomically. Returns the
/// device UUID and secret. A wrong password errors before any file is written.
pub fn add_device_slot(
    folder: &Path,
    password: &SecretBytes,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EnrolledDevice, VaultError> {
    let vt_bytes = read_vault_file(folder, VAULT_TOML_FILENAME)?;
    let ib_bytes = read_vault_file(folder, IDENTITY_BUNDLE_FILENAME)?;

    // Recover the IBK (and validate the password) before generating any secret.
    let opened = open_with_password(&vt_bytes, &ib_bytes, password).map_err(VaultError::Unlock)?;
    let vault_uuid = device_file_vault_uuid(&ib_bytes)?;

    let mut device_uuid = [0u8; 16];
    rng.fill_bytes(&mut device_uuid);
    let mut secret_arr = [0u8; 32];
    rng.fill_bytes(&mut secret_arr);
    let device_secret = Sensitive::new(secret_arr);

    let file = wrap_device_slot(
        &opened.identity_block_key,
        vault_uuid,
        device_uuid,
        &device_secret,
        random_nonce(rng),
    );
    let bytes = device_file::encode(&file);

    let devices_dir = folder.join(DEVICES_SUBDIR);
    std::fs::create_dir_all(&devices_dir).map_err(|e| VaultError::Io {
        context: "failed to create devices/ directory",
        source: e,
    })?;
    write_atomic(&device_wrap_path(folder, &device_uuid), &bytes).map_err(|e| VaultError::Io {
        context: "failed to write device wrap file",
        source: e,
    })?;

    // Hand the secret out as the boundary SecretBytes type; zeroize the stack copy.
    let out = SecretBytes::new(secret_arr.to_vec());
    secret_arr.zeroize();
    Ok(EnrolledDevice {
        device_uuid,
        device_secret: out,
    })
}

/// Open a vault's identity using a device secret. Errors with
/// [`VaultError::DeviceSlotNotFound`] if the device has no wrap file.
pub fn open_identity_with_device_secret(
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &SecretBytes,
) -> Result<UnlockedIdentity, VaultError> {
    let wrap_path = device_wrap_path(folder, device_uuid);
    let wrap_bytes = match std::fs::read(&wrap_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultError::DeviceSlotNotFound)
        }
        Err(e) => {
            return Err(VaultError::Io {
                context: "failed to read device wrap file",
                source: e,
            })
        }
    };
    let vt_bytes = read_vault_file(folder, VAULT_TOML_FILENAME)?;
    let ib_bytes = read_vault_file(folder, IDENTITY_BUNDLE_FILENAME)?;
    open_with_device_secret(&vt_bytes, &wrap_bytes, &ib_bytes, device_secret)
        .map_err(VaultError::Unlock)
}

/// Revoke a device by deleting its wrap file. Idempotent only in the sense that
/// a missing file is reported as [`VaultError::DeviceSlotNotFound`].
pub fn remove_device_slot(folder: &Path, device_uuid: &[u8; 16]) -> Result<(), VaultError> {
    let wrap_path = device_wrap_path(folder, device_uuid);
    match std::fs::remove_file(&wrap_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(VaultError::DeviceSlotNotFound),
        Err(e) => Err(VaultError::Io {
            context: "failed to remove device wrap file",
            source: e,
        }),
    }
}

/// Read the `vault_uuid` out of the encoded identity bundle (its first
/// authenticated field), so enroll binds the wrap to the right vault.
fn device_file_vault_uuid(identity_bundle_bytes: &[u8]) -> Result<[u8; 16], VaultError> {
    let bf = crate::unlock::bundle_file::decode(identity_bundle_bytes)
        .map_err(|e| VaultError::Unlock(crate::unlock::UnlockError::MalformedBundleFile(e)))?;
    Ok(bf.vault_uuid)
}
```

> Confirm exact names against `orchestrators.rs`: the `VaultError::Io { context, source }`
> field names (the grep in this plan shows `context:`; verify `source:` is the second field)
> and that `format_uuid_hyphenated` / `write_atomic` are reachable (`pub` or `pub(crate)`).
> If `VaultError::Unlock` wraps `UnlockError`, the `.map_err(VaultError::Unlock)` calls compile
> as written; adjust the variant name if it differs.

- [ ] **Step 5: Run the integration test to verify it passes**

Run: `cargo test --release -p secretary-core --test device_slot 2>&1 | tail -25`
Expected: PASS (all four integration tests).

- [ ] **Step 6: Lint and commit**

Run: `cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -8`
Expected: clean.

```bash
git add core/src/vault/device_slot.rs core/src/vault/mod.rs core/tests/device_slot.rs
git commit -m "feat(vault): folder device-slot orchestrators — enroll, open, revoke (ADR 0009)"
```

---

## Task 5: Conformance — clean-room replay + golden-vault KAT

The spec-is-normative gate. A stdlib-only Python replay proves `docs/` alone suffices to open
the vault via a device secret, and a golden-vault fixture pins the bytes.

**Confirmed facts (don't re-discover):**
- The published-inputs file is `core/tests/data/golden_vault_001_inputs.json` (a *sibling* of
  the vault dir, NOT inside it). It is read by Python via `load_json_fixture(...)` → a dict
  (`inputs["password"]`, etc.) and by Rust via the typed `load_inputs(&inputs_path())` helper
  in `core/tests/golden_vault_001.rs`. It already has a `device_uuid` key (used elsewhere) —
  use **distinct** keys (`device_slot_*`) to avoid collision.
- `conformance.py` already defines: `MAGIC` (an `int`, `0x53454352`), `hkdf_sha256(salt, ikm,
  info, length)`, and `aead_decrypt(key, nonce, aad, ct_with_tag)`. Reuse these — add no deps.
- `core/tests/golden_vault_001.rs` already imports `open_with_password`,
  `format_uuid_hyphenated`, `load_inputs`, and has `inputs_path()`. The generator + guard go
  HERE (where `load_inputs` + the password field are already in scope), not in `device_slot.rs`.

**Files:**
- Create: `core/tests/data/golden_vault_001/devices/<device-uuid>.wrap` (generated)
- Modify: `core/tests/data/golden_vault_001_inputs.json` (add `device_slot_secret_hex` + `device_slot_uuid_hex`)
- Modify: `core/tests/python/conformance.py` (device-slot replay section)
- Modify: `core/tests/golden_vault_001.rs` (an `#[ignore]` generator + an always-run KAT guard)

- [ ] **Step 1: Read the existing golden password-access pattern**

Run: `cd /Users/hherb/src/secretary/.worktrees/b1-device-wrap-slot && sed -n '120,200p' core/tests/golden_vault_001.rs`
Expected: a test (e.g. `golden_vault_001_opens_with_password`) showing exactly how it gets the
password from `load_inputs(&inputs_path())` and the vault dir path. Note the field name for the
password and the dir helper — the generator below mirrors them. Also note the
`load_inputs` return type so you can read `.password` correctly.

- [ ] **Step 2: Add the published device-slot KAT values to the inputs JSON**

Edit `core/tests/data/golden_vault_001_inputs.json`, adding two top-level keys (match the
file's existing 2-space indentation and key style). These are the published KAT inputs the
Python clean-room reads and that the Rust constants must mirror:

```json
"device_slot_uuid_hex": "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
"device_slot_secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
```

- [ ] **Step 3: Add the `#[ignore]` generator (in `golden_vault_001.rs`)**

Append to `core/tests/golden_vault_001.rs`. Adjust `inputs.password` / the dir helper to the
exact names seen in Step 1. The device secret/uuid are module consts whose hex MUST equal the
JSON from Step 2; the AEAD nonce comes from a seeded RNG (not a literal), per
[[feedback_test_crypto_random_not_hardcoded]]:

```rust
/// Golden device-slot KAT inputs — MUST match `device_slot_*_hex` in the inputs JSON.
const GOLDEN_DEVICE_SECRET: [u8; 32] = {
    let mut s = [0u8; 32];
    let mut i = 0;
    while i < 32 { s[i] = i as u8; i += 1; }
    s
};
const GOLDEN_DEVICE_UUID: [u8; 16] = [0xD0; 16];

#[test]
#[ignore = "regenerates the golden device-slot fixture; run explicitly + human-review the diff"]
fn generate_golden_device_slot() {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    let inputs = load_inputs(&inputs_path());
    // Mirror the dir + password access from the existing opens_with_password test (Step 1).
    let dir = golden_vault_dir(); // <- use the actual helper name from Step 1
    let vt = std::fs::read(dir.join("vault.toml")).unwrap();
    let ib = std::fs::read(dir.join("identity.bundle.enc")).unwrap();
    let password = secretary_core::crypto::secret::SecretBytes::new(inputs.password.clone().into_bytes());
    let opened = open_with_password(&vt, &ib, &password).expect("golden password opens");

    let mut vault_uuid = [0u8; 16];
    vault_uuid.copy_from_slice(&ib[8..24]); // magic(4)+ver(2)+kind(2)=8, then vault_uuid(16)

    let secret = secretary_core::crypto::secret::Sensitive::new(GOLDEN_DEVICE_SECRET);
    let mut rng = ChaCha20Rng::from_seed([0xAB; 32]);
    let file = secretary_core::unlock::device::wrap_device_slot(
        &opened.identity_block_key,
        vault_uuid,
        GOLDEN_DEVICE_UUID,
        &secret,
        secretary_core::crypto::aead::random_nonce(&mut rng),
    );
    let bytes = secretary_core::unlock::device_file::encode(&file);
    let devices = dir.join("devices");
    std::fs::create_dir_all(&devices).unwrap();
    let path = devices.join(format!("{}.wrap", format_uuid_hyphenated(&GOLDEN_DEVICE_UUID)));
    std::fs::write(&path, &bytes).unwrap();
    eprintln!("wrote golden device slot: {}", path.display());
}
```

> If Step 1 shows the password field is already `Vec<u8>`/bytes rather than `String`, drop the
> `.into_bytes()`. If the dir helper has a different name, substitute it. These are the only
> two names to bind from Step 1.

- [ ] **Step 4: Generate the fixture**

Run: `cargo test --release -p secretary-core --test golden_vault_001 -- --ignored generate_golden_device_slot --nocapture 2>&1 | tail -5`
Expected: `wrote golden device slot: .../devices/d0d0d0d0-d0d0-d0d0-d0d0-d0d0d0d0d0d0.wrap`.

Verify the only new untracked file is that wrap:
Run: `git status --porcelain core/tests/data/golden_vault_001/`
Expected: exactly one `??` line for the new `devices/…​.wrap`; nothing else changed.

- [ ] **Step 5: Add the always-run Rust KAT guard (in `golden_vault_001.rs`)**

Append to `core/tests/golden_vault_001.rs` (no `#[ignore]` — runs every `cargo test`):

```rust
#[test]
fn golden_device_slot_opens_to_same_identity() {
    let dir = golden_vault_dir(); // same helper as the generator
    let secret = secretary_core::crypto::secret::SecretBytes::new(GOLDEN_DEVICE_SECRET.to_vec());
    let opened = secretary_core::vault::device_slot::open_identity_with_device_secret(
        &dir,
        &GOLDEN_DEVICE_UUID,
        &secret,
    )
    .expect("golden device slot opens");

    // Must recover the SAME IBK as the published password path.
    let inputs = load_inputs(&inputs_path());
    let vt = std::fs::read(dir.join("vault.toml")).unwrap();
    let ib = std::fs::read(dir.join("identity.bundle.enc")).unwrap();
    let password = secretary_core::crypto::secret::SecretBytes::new(inputs.password.clone().into_bytes());
    let by_pw = open_with_password(&vt, &ib, &password).unwrap();
    assert_eq!(opened.identity_block_key.expose(), by_pw.identity_block_key.expose());
}
```

> This guard reads the fixture in-place (read-only — never writes), so it does not violate
> [[feedback_smoke_test_temp_copy_golden_vault]] (that rule targets code that *mutates* the
> fixture; a pure open mirrors the existing golden read guards).

Run: `cargo test --release -p secretary-core --test golden_vault_001 golden_device_slot 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 6: Add the clean-room replay to `conformance.py`**

In `core/tests/python/conformance.py`, in `section2_golden_vault_001` (≈ line 1621) — right
after the IBK is recovered from `wrap_pw`/`wrap_rec` — call a new helper. Use the EXACT existing
helpers (`MAGIC` as an int, `hkdf_sha256`, `aead_decrypt`); no new dependencies:

```python
def verify_device_slot(base, inputs, ibk_expected):
    """Clean-room vault-format §3a / crypto-design §5a: derive device_kek via
    HKDF-SHA-256 and AEAD-unwrap the IBK from devices/<uuid>.wrap, asserting it
    matches the IBK recovered via the password path. Proves §3a is implementable
    from docs/ alone."""
    secret = bytes.fromhex(inputs["device_slot_secret_hex"])
    uuid_hex = inputs["device_slot_uuid_hex"]
    # filename is the lowercase-hyphenated 8-4-4-4-12 form (vault-format §1)
    h = uuid_hex
    fname = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}.wrap"
    with open(base / "devices" / fname, "rb") as fh:
        blob = fh.read()

    assert int.from_bytes(blob[0:4], "big") == MAGIC, "device wrap magic"
    assert int.from_bytes(blob[4:6], "big") == 1, "format_version"
    assert int.from_bytes(blob[6:8], "big") == 0x0004, "file_kind device-wrap"
    vault_uuid = blob[8:24]
    nonce = blob[40:64]
    assert int.from_bytes(blob[64:68], "big") == 32, "wrap_dev_ct_len"
    ct_with_tag = blob[68:68 + 48]

    device_kek = hkdf_sha256(
        salt=b"\x00" * 32, ikm=secret, info=b"secretary-v1-device-kek", length=32
    )
    aad = b"secretary-v1-id-wrap-dev" + vault_uuid
    ibk = aead_decrypt(device_kek, nonce, aad, ct_with_tag)
    assert ibk == ibk_expected, "device-slot IBK must match the password/recovery IBK"
    print("  device-slot (§3a/§5a): OK")
```

Call it inside `section2_golden_vault_001` with the recovered IBK and the loaded inputs, e.g.
`verify_device_slot(base, inputs, ibk)` (use the local variable names already present there for
the vault dir `base` and the recovered IBK). Confirm `hkdf_sha256`'s parameter order matches the
file (Step "Confirmed facts": `hkdf_sha256(salt, ikm, info, length)`).

- [ ] **Step 7: Run the conformance script**

Run: `uv run core/tests/python/conformance.py 2>&1 | tail -15`
Expected: existing checks PLUS `device-slot (§3a/§5a): OK`, overall success / exit 0.

- [ ] **Step 8: Commit**

```bash
git add core/tests/python/conformance.py core/tests/golden_vault_001.rs \
        core/tests/data/golden_vault_001_inputs.json core/tests/data/golden_vault_001/devices/
git commit -m "test(conformance): clean-room device-slot replay + golden-vault KAT (§3a/§5a)"
```

---

## Task 6: Full gauntlet + project docs

**Files:**
- Modify: `README.md`, `ROADMAP.md`, `CLAUDE.md`

- [ ] **Step 1: Run the complete workspace gauntlet**

Run, from the worktree root:

```bash
cargo fmt --all
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
```

Expected: fmt clean (no diff), clippy clean, all workspace tests pass, conformance OK,
spec-test-name freshness OK (if it flags the new test citations in `docs/`, add them to the
docs or the allowlist as that script instructs).

- [ ] **Step 2: Update `CLAUDE.md` crypto-layering note**

In `CLAUDE.md`, under "Crypto layering", add a bullet after the Argon2id one:

```markdown
- A **third, optional unlock path** exists as of ADR 0009: per-device wrap files
  `devices/<uuid>.wrap` (`file_kind 0x0004`) wrap the IBK under
  `device_kek = HKDF-SHA-256(device_secret)` (crypto-design §5a, vault-format §3a). It is
  additive — `identity.bundle.enc` is unchanged — and is the core foundation for B.3's
  Secure-Enclave/biometric key release. Folder ops live in `core/src/vault/device_slot.rs`;
  pure crypto in `core/src/unlock/device.rs`.
```

- [ ] **Step 3: Update `README.md` + `ROADMAP.md`**

In `README.md`, add a brief dot-point under the status/sub-project-B area (keep it terse, per
[[feedback_readme_style]]):

```markdown
- Per-device wrap slot (ADR 0009): a third unlock path enabling hardware-backed/biometric
  device unlock (B.1 core; FFI + iOS Secure Enclave are #201 / #202).
```

In `ROADMAP.md`, mark B.1 done with the date and link the follow-ups:

```markdown
- [x] **B.1 — Per-device wrap-slot format & crypto** (2026-06-10) — `devices/<uuid>.wrap`,
  `file_kind 0x0004`; HKDF device KEK; enroll/open/revoke; conformance KAT. → B.2 #201, B.3 #202.
```

> Match the exact heading/bullet style already in each file; if ROADMAP uses a different
> section structure for sub-project D / B, slot the entry where the sibling items live.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md CLAUDE.md
git commit -m "docs: record B.1 per-device wrap slot (ADR 0009); CLAUDE.md crypto-layering note"
```

---

## Self-review notes (for the implementer)

- **Both-halves / enforce-don't-assume:** every AEAD failure on the device path maps to a
  *typed* error (`WrongDeviceSecretOrCorrupt`), never a silent fallthrough — verify at each
  call site, per [[feedback_security_no_assumptions]].
- **Zeroize discipline:** `secret_arr` (enroll), `ibk_arr` (unwrap), `arr` (secret_to_array)
  are each `.zeroize()`-d after the `Sensitive::new` move — match the `open_with_password`
  pattern exactly.
- **Frozen-format invariant:** `identity.bundle.enc` bytes are never written or changed by
  any task here; only `devices/` is added. The golden-vault diff must be exactly the new
  `devices/<uuid>.wrap` file + the `device_slot` inputs JSON entry — review the `git diff`.
- **Spec-is-normative:** if Rust and `conformance.py` disagree, it is a Rust bug, a Python
  bug, or a spec ambiguity — resolve explicitly, never paper over (`CLAUDE.md`).
- **File-size discipline:** new pure ops live in `device.rs` and folder ops in
  `device_slot.rs` rather than growing the already-large `mod.rs` / `orchestrators.rs`.
```
