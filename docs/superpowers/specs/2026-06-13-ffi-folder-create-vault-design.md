# FFI folder-writing `create_vault` — design

**Date:** 2026-06-13
**Slice:** 1 of 2 — *iOS vault create / import*
**Status:** approved (brainstorming) → ready for implementation plan

## Context

The iOS app now does **select → unlock → browse → record CRUD**. The next
feature is **create a new vault / import an existing one** (mirrors desktop
"D.1.3"). Splitting the same way the record-CRUD arc was split:

- **Slice 1 (this spec, Rust/FFI):** expose a folder-writing `create_vault`
  through the FFI bridge so a client can create a *complete, browsable* vault.
- **Slice 2 (next session, Swift):** the iOS provisioning view model + create
  wizard + import folder-detection UX, landing on this surface.

### Why a Rust/FFI slice is needed (not "Swift-only")

The existing bridge `create_vault` (B.3b, `create.rs`) is **identity-level
only**: it returns `vault_toml_bytes` + `identity_bundle_bytes` and pairs with
the *bytes-based* `open_with_password(vault_toml, identity_bundle, password)`.
It does **not** produce `manifest.cbor.enc` or the owner
`contacts/<uuid>.card`.

The iOS browse/CRUD flow opens via the *folder-based*
`open_vault_with_password(folder, …)`, which **validates a manifest signature +
owner contact card on disk**. A vault assembled from only the two
identity-level files would fail that open. The folder-writing
`core::vault::create_vault` — which atomically writes all four canonical files —
is **never exposed through the FFI**; only desktop (native Rust) calls it
directly. Swift cannot assemble the missing files itself, so the bridge must
expose the folder-writing path.

## Goal

Add a folder-writing `create_vault_in_folder` to the FFI bridge, projected onto
uniffi + pyo3, that delegates to the already-tested `core::vault::create_vault`.
Purely additive FFI surface.

**Non-goals / invariants preserved:**

- **No `core` change.** `core::vault::create_vault` already exists, is tested,
  and writes all four files atomically (`docs/vault-format.md` §9).
- **No on-disk-format / frozen-spec change.** Vault creation is already
  normatively specified; this slice only projects it through the FFI.
- **No weaker open.** Creation hardcodes `OsRng` + `Argon2idParams::V1_DEFAULT`;
  the resulting vault opens through the *same* verify-before-decrypt
  `open_vault_with_password` as every other open.

## Design

### 1. Bridge function

In `ffi/secretary-ffi-bridge/src/create.rs` (sibling to the existing bytes
`create_vault`; projected ~436 lines, stays under the 500-line split
threshold — split if it crosses):

```rust
pub fn create_vault_in_folder(
    folder: &Path,
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<MnemonicOutput, FfiVaultError>
```

- Hardcodes `OsRng` + `Argon2idParams::V1_DEFAULT` — no foreign RNG/KDF knobs
  (same rationale as the bytes `create_vault`: first-party clients always want
  the OS CSPRNG and the conservative KDF default; `WeakKdfParams` is
  structurally unreachable).
- Wraps `password` into `SecretBytes` (zeroizes on drop); caller still zeroizes
  its own input buffer (input-side caller-zeroize discipline).
- Delegates to `core::vault::create_vault`, which atomically writes
  `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`,
  `contacts/<owner-uuid-hyphenated>.card`.
- Returns the **existing** `MnemonicOutput` handle (one-shot `take_phrase`,
  zeroizing `Drop`).

**Two settled judgment calls:**

- **Return shape = mnemonic only, no auto-open.** The caller re-opens with
  `open_vault_with_password(folder, …)` to browse. Mirrors desktop's deliberate
  "no auto-open, re-enter password" UX and keeps the live-secret surface
  minimal (no unused live identity/manifest handle to wipe).
- **Bridge stays thin — caller supplies an existing empty directory.** Mirrors
  core's `ensure_empty_directory` contract. The `mkdir` / subfolder decision
  belongs to the platform layer (Slice 2's Swift, exactly as desktop's
  `create_dir_all` lives in the Tauri command, not the bridge).

### 2. New error variant — `FfiVaultError::VaultFolderNotEmpty`

`core::vault::create_vault` calls `ensure_empty_directory`, which returns
`VaultError::Io { ErrorKind::AlreadyExists }` for a non-empty folder. The
current `From<VaultError> for FfiVaultError` only routes `NotFound |
PermissionDenied` to the typed `FolderInvalid`; `AlreadyExists` falls through to
`CorruptVault` ("vault data integrity failure") — a **misleading** error for
"you picked a non-empty folder". Desktop has a dedicated `VaultFolderNotEmpty`.

Add a dedicated typed variant and refine the mapping in `error/vault/mod.rs`:

```
VaultError::Io { AlreadyExists }               -> VaultFolderNotEmpty   (new)
VaultError::Io { NotFound | PermissionDenied } -> FolderInvalid         (existing)
other Io kinds                                 -> CorruptVault          (existing fall-through)
```

`VaultFolderNotEmpty` is a unit variant (no payload): the condition is
fully described by its name, and the folder path is the caller's own input
(no need to echo it back). Display text: `"vault folder is not empty"`.

**Workspace-wide threading obligation** (per the project's
`FfiVaultError`-variant discipline — `cargo`/`clippy` cannot see the last two):

- bridge `From<VaultError>` mapping + the variant itself
- uniffi UDL `VaultError` enum + uniffi error conversion
- pyo3 error conversion
- any core-side exhaustive match over `FfiVaultError`
- `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`
- `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt`

### 3. Projections

- **uniffi:** UDL declaration
  `MnemonicOutput create_vault_in_folder(bytes folder_path, bytes password,
  string display_name, u64 created_at_ms)` `[Throws=VaultError]`, a
  `namespace/mod.rs` wrapper (bytes → `Path`, mirroring
  `open_vault_with_password`), and a wrapper-level unit test.
- **pyo3:** a wrapper in `unlock.rs` returning the existing `MnemonicOutput`
  pyclass, registered in `lib.rs`.

### 4. Tests (TDD — failing test first for each unit)

- **Bridge unit (`create.rs` tests):**
  - round-trip: `create_vault_in_folder` into a tempdir → assert all 4 files
    exist → `open_vault_with_password` opens and reports the expected
    `display_name` → `take_phrase` then `open_vault_with_recovery` opens.
  - non-empty folder → `VaultFolderNotEmpty`.
  - missing folder → `FolderInvalid`.
- **pyo3 pytest** (`uv`, never pip): round-trip + both error contracts.
- **uniffi Swift + Kotlin smoke:** create in a tempdir → open → assert
  `vault_uuid`; error-parity assertion for the new variant.
- **Conformance error harness:** add `VaultFolderNotEmpty` to
  `ConformanceErrors.{swift,kt}`.

**No conformance KAT regeneration.** Vault creation is generative/random
(vault UUID, Argon2id salt, AEAD nonce, mnemonic entropy); it cannot be a
fixed-output KAT. The only conformance touch is the **error-enum** harness.

### 5. Acceptance gauntlet

```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cd ffi/secretary-ffi-py && uv run --with pytest pytest        # pyo3 round-trip + errors
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh  # exercises ConformanceErrors.swift
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # exercises ConformanceErrors.kt
git diff main..HEAD --name-only | grep -E '^core/|\.rs$'      # core/ MUST be empty (ffi-only .rs)
```

(The last check: `.rs` changes are expected under `ffi/` only; **no `core/`
change**, no on-disk-format change.)

## Risks / open items

- **Naming asymmetry:** `create_vault` (bytes, identity-level) vs
  `create_vault_in_folder` (folder, complete vault). Accurate but slightly
  uneven. The bytes form is the established B.3b surface and is left unchanged
  (additive only); renaming it is out of scope.
- **`create.rs` size:** adding the folder fn + tests keeps the file under 500
  lines on current projection. If it crosses, split into
  `create.rs` (bytes) + a folder-create module at implementation time.
- **Workspace-match completeness:** the two conformance error harnesses are the
  easy-to-miss sites; the plan must run both `run_conformance.sh` scripts as
  explicit acceptance steps, not rely on `cargo`.

## Out of scope (→ Slice 2, next session)

iOS `VaultProvisioningViewModel`; the create wizard screen (folder → password +
confirm → 24-word recovery phrase + "I wrote it down" checkbox); import
folder empty-vs-vault detection; the `mkdir` / subfolder UX. All Swift, landing
on this slice's FFI surface.
