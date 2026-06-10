# B.1 — Per-device wrap-slot format & crypto (design)

**Date:** 2026-06-10
**Status:** Approved (brainstorm) — pending implementation plan
**Sub-project:** D.3 (native iOS via uniffi, ADR 0008), Option-B credential model
**Scope:** the Rust core + frozen-format spec only. No FFI, no Swift, no Secure Enclave.

## 1. Context & motivation

ADR 0008 chose native mobile specifically to reach **hardware-backed, biometric-bound key
release** (iOS Secure Enclave / Android StrongBox). The headline security goal is that a
device can unlock the vault after a biometric check **without the human master password ever
being stored on the device**, and that a lost/retired device can be **revoked independently**
of the master password.

Today the vault has exactly two ways to recover the *Identity Block Key* (IBK), both defined
in `docs/crypto-design.md` §3–§5 and `docs/vault-format.md` §3:

- `wrap_pw` — IBK wrapped under `master_kek = Argon2id(password, salt)`.
- `wrap_rec` — IBK wrapped under `recovery_kek = HKDF-SHA-256(mnemonic_entropy)`.

Both live in the fixed binary layout of `identity.bundle.enc` (`file_kind 0x0001`).

This slice (**B.1**) adds a **third, per-device credential**: a high-entropy random
*device secret* that recovers the IBK via its own wrap. The device secret is what a later
slice (B.3) will hold non-exportably in the Secure Enclave behind a biometric gate. B.1
delivers only the core crypto + on-disk format + operations to **mint, consume, and revoke**
a device slot — all headless and deterministically testable in Rust.

### Why a separate file (not a third slot inside `identity.bundle.enc`)

The hardest project constraint is that **vaults written today must stay byte-readable for
decades** (`identity.bundle.enc` is frozen at `file_kind 0x0001`). Three options were
weighed:

| Approach | Verdict |
|---|---|
| **Separate per-device wrap file** (`devices/<uuid>.wrap`, new `file_kind 0x0004`) — **chosen** | `identity.bundle.enc` stays byte-identical → `golden_vault_001` and every v1 vault untouched. Multi-device = multiple files. Per-device revoke = delete one file. |
| Evolve `identity.bundle.enc` in place (versioned `file_kind` / appended optional slot) | Mutates the frozen file; one slot per file (no multi-device); revoke rewrites a shared file (atomicity risk). Strictly worse. |
| Store device wraps *inside* the IBK-encrypted bundle CBOR | **Circular**: you need the IBK to read the bundle, but the slot's job is to *recover* the IBK. Impossible. |

The separate file is additive: a reader that has never heard of `file_kind 0x0004` opens
v1 vaults unchanged, and an old vault simply has an empty/absent `devices/` directory.

## 2. Credential model & threat-model rationale

The device secret is **256 bits of OS-CSPRNG entropy**, generated at enrollment, never
shown to the user, never persisted *inside the vault*. It is returned once from the core
to the caller (B.3 wraps it to the Secure Enclave; B.1 itself does not persist it). This
mirrors how the recovery mnemonic exits the core exactly once (`take_phrase`).

Versus caching the master password (the rejected Option A), this model:

- keeps the **human master password off the device entirely** — full device compromise
  yields only a vault-scoped device secret, never the top-level / possibly-reused password;
- gives **true per-device revocation** — drop the device's file; master password and all
  other devices are untouched;
- **decouples** device enrollment from master-password rotation.

The cost — accepted by the B-direct decision — is a frozen-format evolution, handled here
spec-first with full conformance enforcement.

## 3. Crypto (mirrors `recovery_kek` precisely)

The device secret is high-entropy, so — exactly like the recovery mnemonic (§4) — it is
**expanded with HKDF, never stretched with Argon2id**. Argon2id exists to slow down
guessing of low-entropy human passwords; it is wrong for a CSPRNG secret.

```
device_secret : 32 bytes  ← OS CSPRNG            # at enroll; never stored in the vault
device_kek = HKDF-SHA-256(
    ikm  = device_secret,
    salt = 32 bytes of 0x00,
    info = "secretary-v1-device-kek",
    len  = 32,
)
(ct_dev, tag_dev) = XChaCha20-Poly1305-Encrypt(
    key       = device_kek,
    nonce     = fresh 24 bytes (OS CSPRNG),
    aad       = "secretary-v1-id-wrap-dev" || vault_uuid,
    plaintext = identity_block_key,              # the SAME 32-byte IBK as wrap_pw/wrap_rec
)
```

`device_kek` is derived by a new `crypto::kdf::derive_device_kek(secret: &Sensitive<[u8;32]>)
-> Sensitive<[u8;32]>`, a near-verbatim sibling of `derive_recovery_kek` (same HKDF-SHA-256,
zero salt, only `info` differs). The wrap/unwrap reuse the existing
`crypto::aead` XChaCha20-Poly1305 helpers — no new AEAD code.

**Domain separation.** The `device_kek` info string (`secretary-v1-device-kek`) and the wrap
AAD (`secretary-v1-id-wrap-dev` ‖ `vault_uuid`) are both new and distinct from the `pw`/`rec`
constants. `vault_uuid` in the AAD binds the wrap to its vault. The `device_uuid` is bound by
being part of the same authenticated file header region (see §4); a file copied between
vaults or relabeled fails the AAD/`vault_uuid` check.

## 4. On-disk format — `devices/<device-uuid>.wrap` (`file_kind 0x0004`)

New `docs/vault-format.md` §3a. Layout follows the same header discipline as §3, encoded
with the existing big-endian helpers in `core/src/unlock/bundle_file.rs` (a sibling codec):

```
┌──────────────────────────────────────────────────────────────┐
│ magic              (4 bytes)  = MAGIC                         │
│ format_version     (2 bytes)  = u16, v1: 0x0001              │
│ file_kind          (2 bytes)  = u16, device-wrap: 0x0004     │
│ vault_uuid         (16 bytes)                                 │
│ device_uuid        (16 bytes)                                 │
│ wrap_dev_nonce     (24 bytes) = XChaCha20 nonce              │
│ wrap_dev_ct_len    (4 bytes)  = u32, must be 32              │
│ wrap_dev_ct        (32 bytes) = AEAD ciphertext of IBK       │
│ wrap_dev_tag       (16 bytes) = Poly1305 tag                 │
└──────────────────────────────────────────────────────────────┘
```

- `suite_id` is intentionally **not** in this header. Confirmed against §3: the
  `identity.bundle.enc` header (per `core/src/unlock/bundle_file.rs::encode`) is
  `MAGIC ‖ format_version ‖ file_kind ‖ vault_uuid ‖ created_at_ms`, with **no** `suite_id` —
  identity-layer files omit it (suite is fixed at v1); manifest/block *content* files carry
  it. The device wrap file is an identity-layer file, so it follows §3 and omits `suite_id`.
- The device file carries **no `created_at_ms`** (unlike §3); it is replaced by `device_uuid`
  in the corresponding header position. The two files share the leading
  `MAGIC ‖ format_version ‖ file_kind ‖ vault_uuid` prefix and then diverge by file kind.
- `wrap_dev_ct_len` records the **unwrapped** key length (32), matching the §3 convention
  for `wrap_pw_ct_len` / `wrap_rec_ct_len`.
- The filename `device_uuid` MUST equal the header `device_uuid`; a mismatch is a typed
  decode error (the file is self-describing; the filename is a convenience index).

Directory: a new `devices/` subdirectory alongside `contacts/`, `blocks/`, `trash/`:

```
<vault-folder>/
  devices/
    <device-uuid>.wrap          # per-device IBK wrap (file_kind 0x0004); see §3a
    ...
```

A vault with no enrolled devices has no `devices/` directory (or an empty one) — both are
valid and indistinguishable from a v1 vault to readers.

## 5. Operations (pure codec + thin orchestrators)

Following the project convention (pure functions in reusable modules; I/O at the edges;
[[feedback_pure_functions]]):

### Codec (pure, no I/O) — `core/src/unlock/device_file.rs`
- `encode(&DeviceWrapFile) -> Vec<u8>` / `decode(&[u8]) -> Result<DeviceWrapFile, DeviceFileError>`
  — sibling of `bundle_file.rs`. Split into its own file to stay well under the 500-line
  guidance ([[feedback_split_files_proactively]]).
- `wrap_device_slot(ibk: &Sensitive<[u8;32]>, vault_uuid, device_uuid, device_secret, rng)
   -> DeviceWrapFile` — derives `device_kek`, AEAD-wraps the IBK, builds the struct.
- `unwrap_device_slot(&DeviceWrapFile, device_secret) -> Result<Sensitive<[u8;32]>, _>` —
  derives `device_kek`, AEAD-unwraps → IBK; AEAD tag failure → `WrongDeviceSecretOrCorrupt`.

### Orchestrators (I/O) — in `core/src/unlock/mod.rs` (or a small `device.rs` if mod.rs grows)
- `add_device_slot(vault_dir, password: &SecretBytes, rng) -> Result<EnrolledDevice, _>`
  1. `open_with_password(vault_dir, password)` path to recover the IBK (re-derives
     `master_kek`, unwraps `wrap_pw`). The IBK stays internal — never exposed on a handle.
  2. Generate `device_uuid` (UUIDv4) + `device_secret` (32 B OS-CSPRNG).
  3. `wrap_device_slot(...)`, `encode`, `write_atomic` to `devices/<device_uuid>.wrap`
     (reuses the §9 atomic-write contract, `core/src/vault/io.rs`).
  4. Return `EnrolledDevice { device_uuid, device_secret: SecretBytes }`. The
     `device_secret` is zeroize-typed and exits the boundary exactly once (B.3 SE-wraps it).
- `open_with_device_secret(vault_dir, device_uuid, device_secret) -> Result<UnlockedIdentity, _>`
  1. Read+decode `devices/<device_uuid>.wrap` (→ `DeviceSlotNotFound` if absent).
  2. `unwrap_device_slot` → IBK.
  3. Share the existing post-IBK path with `open_with_password` (read+decrypt the bundle
     under the IBK → `UnlockedIdentity`). Factor that tail into a private helper if it is
     not already, so all three unlock paths converge on one IBK→identity routine.
- `remove_device_slot(vault_dir, device_uuid) -> Result<(), _>` — delete the file
  (`DeviceSlotNotFound` if absent). This is the per-device-revocation headline.

### Types
- `EnrolledDevice { device_uuid: [u8;16], device_secret: SecretBytes }` — `device_secret`
  is `Zeroize, ZeroizeOnDrop` (it is `SecretBytes`). **Type convention:** the derivation and
  codec operate on the secret as `Sensitive<[u8;32]>` internally (verbatim with
  `derive_recovery_kek`); it is exposed across the orchestrator boundary as `SecretBytes`
  (the variable-length zeroizing type used for all boundary-crossing secrets, e.g. passwords
  and recovery phrases), with a length-checked conversion at the edge.
- `DeviceWrapFile { vault_uuid, device_uuid, wrap_dev_nonce, wrap_dev_ct_with_tag }` — the
  parsed/encodable form, mirroring `BundleFile`.

## 6. Errors (typed; enforce-don't-assume)

New variants, mirroring the existing pattern and the both-halves discipline
([[feedback_security_no_assumptions]]):

- `WrongDeviceSecretOrCorrupt` — AEAD tag failure unwrapping the device slot (parallel to
  `WrongPasswordOrCorrupt`; UI assumes wrong-secret before corruption).
- `DeviceSlotNotFound` — no `devices/<device_uuid>.wrap`.
- `DeviceFileError` decode variants (bad magic/version, unsupported `file_kind`, length
  mismatch, `device_uuid` filename/header mismatch) — siblings of `BundleFileError`.

AEAD failure is surfaced as a typed error, **never** a silent fallthrough. No `unsafe`
(workspace `#![forbid(unsafe_code)]`).

## 7. Testing & conformance (spec-is-normative gate)

- **Rust unit tests** (per-module): codec round-trip; decode rejects bad
  magic/version/file_kind/length/uuid-mismatch; `wrap`/`unwrap` round-trip; wrong-secret →
  typed error; cross-vault AAD rejection (wrap from vault A fails under vault B's uuid).
- **Rust integration tests** (`core/tests/`): enroll → `open_with_device_secret` round-trip
  yields the same identity as `open_with_password`; revoke (`remove_device_slot`) → subsequent
  open fails with `DeviceSlotNotFound`; **multi-device** (two enrollments open independently);
  enroll-with-wrong-password fails before any file is written.
- **proptest**: `unwrap(wrap(ibk, secret), secret) == ibk` over arbitrary IBK + secret;
  `unwrap(wrap(ibk, s1), s2)` errors for `s1 != s2`.
- **Crypto values are runtime-random** (OsRng), never hardcoded
  ([[feedback_test_crypto_random_not_hardcoded]]); the one pinned KAT rides in a JSON fixture.
- **`conformance.py` (stdlib clean-room)**: a new section that, from `docs/` alone, derives
  `device_kek` via HKDF-SHA-256 and AEAD-unwraps the IBK from a device wrap file, recovering
  the golden identity — proving the new format is implementable from the spec.
- **KAT fixture**: extend `core/tests/data/golden_vault_001/` with a
  `devices/<device-uuid>.wrap` file plus the *published* `device_secret` and `device_uuid`
  added to the golden inputs JSON, round-tripping to the existing golden IBK/identity. An
  always-run Rust guard asserts the device slot opens to the same identity as the password
  path. Regenerating the fixture is a deliberate, human-reviewed diff scoped to the new
  device file + inputs entry.

## 8. Spec & ADR deliverables (spec-first)

- **ADR 0009** — "Per-device wrap slot for hardware-backed/biometric unlock (Option B)":
  records the credential model, the separate-file decision, HKDF (not Argon2id) rationale,
  and that it is additive to the frozen v1 format.
- **`docs/crypto-design.md`** — new section (after §5) defining `device_kek` derivation and
  the device-slot wrap, parallel to §4/§5.
- **`docs/vault-format.md`** — new §3a defining the `devices/<uuid>.wrap` file format and the
  `devices/` directory; update §1 folder layout.
- `docs/glossary.md` — add *device secret* / *device slot* / *device KEK* if helpful.
- `CLAUDE.md` — note the new `file_kind 0x0004` and the device-slot invariants if the crypto
  layering section warrants it (decide during implementation).

## 9. Explicitly out of scope (deferred, to be filed as follow-ups)

- **B.2 — FFI projection**: exposing `add_device_slot` / `open_with_device_secret` /
  `remove_device_slot` across uniffi (+ pyo3 parity), threading `FfiVaultError`, regenerating
  the conformance KAT JSON, and updating the Swift/Kotlin conformance harnesses
  ([[project_secretary_ffivaulterror_workspace_match]]).
- **B.3 — iOS Secure Enclave / biometric layer**: non-exportable SE P-256 key with biometric
  access control wrapping the `device_secret`, Keychain persistence, `LAContext` release →
  `open_with_device_secret`, and the unavailable/lockout failure modes. This is where the
  actual biometric verification (manual / simulator) lives.

## 10. Open decisions & risks

- **Golden-vault KAT regeneration** — adding a device file to the frozen golden vault is a
  deliberate fixture change; the diff must be scoped to the new file + inputs entry and
  human-reviewed, exactly like the documented `conformance_kat.json` regeneration workflow.
- **No new dependency** is expected (HKDF, XChaCha20-Poly1305, UUID, `rand`, `tempfile` are
  all already in-tree). If anything is added on this security path, it gets an exact pin +
  rationale comment, per the `tempfile` precedent.
- **Device-secret lifetime** — the secret crosses the core boundary once at enroll. Until B.3
  exists there is no caller that persists it hardware-backed; B.1's tests treat it as an
  in-memory value, consistent with slice-1's interim posture.
