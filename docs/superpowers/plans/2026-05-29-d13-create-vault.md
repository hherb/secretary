# D.1.3 Create (desktop vault create wizard) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user create a brand-new v1 vault from the desktop app via a guided wizard (choose folder → set password+confirm → create → surface the 24-word recovery mnemonic → acknowledge → return to Unlock pre-filled), and close the D.1.1 plain-`String` password carry-forward.

**Architecture:** The create path wraps **core's atomic orchestrator** `secretary_core::vault::orchestrators::create_vault` (writes `vault.toml` + `identity.bundle.enc` + `manifest.cbor.enc` + owner `contacts/<uuid>.card` atomically, returns the `Mnemonic`) behind one IPC command — NOT the bytes-only bridge `create_vault`, which cannot emit a complete on-disk vault. The desktop already links `secretary-core` directly. The IPC password boundary becomes a zeroize-typed `Password` newtype, applied to the new command and retrofitted onto `unlock_with_password`. After create the app returns to the Unlock screen (one Argon2id derivation; password dropped immediately) rather than auto-opening.

**Tech Stack:** Rust (Tauri 2 commands + `*_impl` split, `serde` DTOs, `thiserror` `AppError`), `secretary-core` (orchestrator, `Argon2idParams::V1_DEFAULT`, `Mnemonic`, `SecretBytes`), `rand_core` 0.6 `OsRng`, Svelte 5 + TypeScript (Vitest), `@tauri-apps/plugin-clipboard-manager` (write-only, reused from D.1.2).

**Spec:** `docs/superpowers/specs/2026-05-29-d13-create-vault-design.md`

---

## File Structure

### Backend (Rust) — `desktop/src-tauri/`

| File | Status | Responsibility |
|---|---|---|
| `src/secret_arg.rs` | **Create** | `Password` newtype around `SecretBytes` with a zeroizing `Deserialize`. The zeroize-typed IPC password boundary. |
| `src/dtos/create.rs` | **Create** | `Serialize`-only `CreateVaultDto { mnemonic }` (the one widening point) + `CreateTargetProbeDto { exists, is_empty }`. camelCase. |
| `src/dtos/mod.rs` | Modify | Declare `mod create;` + re-export the two DTOs. |
| `src/commands/create.rs` | **Create** | `create_vault` + `probe_create_target` thin commands + `*_impl`. `create_vault_impl`: `create_dir_all` → own empty-check → core orchestrator → DTO. Session-stateless. |
| `src/commands/mod.rs` | Modify | Declare `pub mod create;`. |
| `src/commands/unlock.rs` | Modify | Retrofit the command shell: `password: String` → `password: Password`; `*_impl` (taking `&[u8]`) unchanged. |
| `src/errors.rs` | Modify | Add `VaultFolderNotEmpty { path }` + `VaultCreateFailed { detail (skip) }` variants + wire tests. |
| `src/lib.rs` | Modify | Declare `pub mod secret_arg;`. |
| `src/main.rs` | Modify | Register `create::create_vault` + `create::probe_create_target` in `invoke_handler`. |
| `Cargo.toml` | Modify | Add `rand_core = { version = "0.6", features = ["getrandom"] }` (compatible `OsRng` for core's `create_vault` bound). |
| `tests/ipc_integration.rs` | Modify | L3 tests: create over tempdir (random password) → 4 files + re-open; `VaultFolderNotEmpty`; dir-created-when-missing; probe flags. |

### Frontend (Svelte + TS) — `desktop/`

| File | Status | Responsibility |
|---|---|---|
| `src/lib/route.ts` | **Create** | Pre-unlock routing store: `appRoute: 'unlock' \| 'create'` + seed/created-path stores + `openCreateWizard`/`cancelCreateWizard`/`finishCreateWizard`. |
| `src/lib/create.ts` | **Create** | Pure wizard step machine + helpers (`passwordsMatch`, `joinSubfolder`, `groupMnemonicWords`). No IPC/DOM. |
| `src/lib/ipc.ts` | Modify | `createVault`, `probeCreateTarget` + DTO interfaces. |
| `src/lib/errors.ts` | Modify | Add `vault_folder_not_empty` + `vault_create_failed` codes/union/messages. |
| `src/components/create/FolderStep.svelte` | **Create** | Folder pick + probe + subfolder offer. |
| `src/components/create/CredentialsStep.svelte` | **Create** | Display name + password + confirm. |
| `src/components/create/MnemonicStep.svelte` | **Create** | 24-word display + copy + acknowledge gate. |
| `src/routes/CreateVault.svelte` | **Create** | Wizard host: switch on step; call `createVault`; advance to mnemonic; finish → Unlock. |
| `src/App.svelte` | Modify | When not unlocked, switch on `appRoute` (Unlock vs CreateVault). |
| `src/routes/Unlock.svelte` | Modify | "Not a vault" hint → "Create a vault here" button; accept pre-fill path + "Vault created" banner. |
| `src/theme.css` | Modify | `.wizard*`, `.mnemonic-grid` classes (Vite-6 preprocessCSS workaround, #153). |

### Frontend tests — `desktop/tests/`

| File | Status | Covers |
|---|---|---|
| `tests/route.test.ts` | **Create** | `appRoute` transitions. |
| `tests/create.test.ts` | **Create** | Pure helpers + step machine. |
| `tests/FolderStep.test.ts` | **Create** | Probe-driven subfolder offer. |
| `tests/CredentialsStep.test.ts` | **Create** | Confirm-match gating. |
| `tests/MnemonicStep.test.ts` | **Create** | Acknowledge gating + copy. |
| `tests/errors.test.ts` | Modify | New code messages. |
| `tests/ipc.test.ts` | Modify | `createVault`/`probeCreateTarget` mocks. |

### Modified docs (Task 6 / ship)

- `README.md` — D-row advances to "D.1.3 (create) shipped; D.1.4 (edit) next".
- `ROADMAP.md` — D.1.3 ✅, D.1.4 ⏳.
- `docs/handoffs/2026-05-29-d13-create-shipped.md` + retargeted `NEXT_SESSION.md` symlink.

---

## Task 1: Backend — `Password` zeroize-typed boundary + retrofit unlock + create DTOs

**Files:**
- Create: `desktop/src-tauri/src/secret_arg.rs`
- Modify: `desktop/src-tauri/src/lib.rs`
- Modify: `desktop/src-tauri/src/commands/unlock.rs:38-54`
- Create: `desktop/src-tauri/src/dtos/create.rs`
- Modify: `desktop/src-tauri/src/dtos/mod.rs`

- [ ] **Step 1: Write the failing `Password` unit tests**

Create `desktop/src-tauri/src/secret_arg.rs` with ONLY the test module first (the rest follows in Step 3):

```rust
//! `Password` — zeroize-typed wrapper for the password argument crossing
//! the Tauri IPC boundary. See Step 3 for the full module docs.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_from_json_string_exposes_password_bytes() {
        // Tauri deserializes command args from the JSON invoke payload via
        // serde; a JSON string must land as the right password bytes.
        let pw: Password = serde_json::from_str("\"hunter2\"").expect("deserialize");
        assert_eq!(pw.expose(), b"hunter2");
    }

    #[test]
    fn from_bytes_exposes_same_bytes_via_both_accessors() {
        let pw = Password::from_bytes(b"correct horse battery staple");
        assert_eq!(pw.expose(), b"correct horse battery staple");
        assert_eq!(pw.as_secret_bytes().expose(), b"correct horse battery staple");
    }

    #[test]
    fn deserialize_empty_string_is_allowed_and_empty() {
        // Emptiness is a frontend-validation concern (CredentialsStep gates
        // on non-empty); the boundary type itself accepts an empty password.
        let pw: Password = serde_json::from_str("\"\"").expect("deserialize");
        assert_eq!(pw.expose(), b"");
    }
}
```

Add the module declaration to `desktop/src-tauri/src/lib.rs` (alphabetical, after `reveal`):

```rust
pub mod reveal;
pub mod secret_arg;
pub mod session;
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `cd desktop/src-tauri && cargo test --release secret_arg 2>&1 | tail -20`
Expected: FAIL — `cannot find type Password in this scope`.

- [ ] **Step 3: Implement the `Password` newtype**

Prepend the implementation above the test module in `desktop/src-tauri/src/secret_arg.rs`:

```rust
//! `Password` — zeroize-typed wrapper for the password argument crossing
//! the Tauri IPC boundary.
//!
//! Replaces D.1.1's plain `password: String` argument on
//! `unlock_with_password` (a documented deferred-hardening item) and is the
//! argument type for the new `create_vault` command. Tauri deserializes
//! incoming command arguments from the JSON invoke payload via `serde`; this
//! newtype's `Deserialize` copies the password bytes into a zeroize-on-drop
//! `SecretBytes` and overwrites the intermediate `String`.
//!
//! HONEST LIMITATION (spec §13): this guarantees *our* copy of the password
//! is wiped on drop. It does NOT guarantee every byte the underlying
//! `serde_json` parser touched is wiped — the parser's internal buffer is
//! outside our control. A bounded improvement over `password: String` (which
//! left a plain heap `String` un-zeroized for the GC), not a perfect
//! end-to-end guarantee.

use secretary_core::crypto::secret::SecretBytes;
use serde::{Deserialize, Deserializer};
use zeroize::Zeroize;

/// Zeroize-typed password argument. Construct only via `Deserialize` (the IPC
/// boundary) or [`Password::from_bytes`] (tests).
pub struct Password(SecretBytes);

impl Password {
    /// Borrow the password bytes for a single bridge/core call that takes
    /// `&[u8]` (e.g. `unlock_with_password_impl`). Must not outlive `self`.
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Borrow as `&SecretBytes` for core APIs that take the wrapper directly
    /// (e.g. `orchestrators::create_vault`).
    pub fn as_secret_bytes(&self) -> &SecretBytes {
        &self.0
    }

    /// Test-only constructor. Hidden from rustdoc; not part of the IPC API.
    #[doc(hidden)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Password(SecretBytes::from(bytes))
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut s = String::deserialize(deserializer)?;
        let pw = SecretBytes::from(s.as_bytes());
        // Overwrite our owned intermediate. (The serde_json parse buffer is
        // outside our control — see the module-level HONEST LIMITATION.)
        s.zeroize();
        Ok(Password(pw))
    }
}
```

- [ ] **Step 4: Run the `Password` tests to verify they pass**

Run: `cd desktop/src-tauri && cargo test --release secret_arg 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 5: Retrofit `unlock_with_password` to take `Password`**

In `desktop/src-tauri/src/commands/unlock.rs`, change ONLY the command shell (the `*_impl` keeps `password: &[u8]`, so all existing impl logic + tests are untouched).

Add the import near the top (after `use crate::session::VaultSession;`):

```rust
use crate::secret_arg::Password;
```

Replace the shell (lines 37-54) with:

```rust
/// Tauri-side entry point. Thin delegating shell; logic lives in
/// [`unlock_with_password_impl`].
///
/// `password: Password` is the zeroize-typed IPC boundary (D.1.3 closed the
/// D.1.1 plain-`String` carry-forward). We hand `password.expose()` to the
/// `&[u8]`-taking impl; the `Password` (and its inner `SecretBytes`) zeroizes
/// when this shell returns.
#[tauri::command]
pub async fn unlock_with_password(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    password: Password,
) -> Result<ManifestDto, AppError> {
    unlock_with_password_impl(state.inner(), &folder_path, password.expose())
}
```

- [ ] **Step 6: Confirm the retrofit compiles and existing unlock tests pass**

Run: `cd desktop/src-tauri && cargo test --release --test ipc_integration unlock 2>&1 | tail -20`
Expected: PASS — the existing golden-vault unlock integration tests still pass (the wire arg is still a JSON string; `Password::Deserialize` accepts it).

- [ ] **Step 7: Write failing serde tests for the create DTOs**

Create `desktop/src-tauri/src/dtos/create.rs`:

```rust
//! Create-vault DTOs crossing the IPC boundary.
//!
//! `CreateVaultDto.mnemonic` is the single secret-bearing field in the create
//! slice (spec §5): the 24-word recovery phrase, produced once on an explicit
//! create and displayed once. `CreateTargetProbeDto` is non-secret.

/// Result of a successful `create_vault`. The `mnemonic` is the user's only
/// recovery path — displayed once, never persisted by the app.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultDto {
    pub mnemonic: String,
}

/// Result of `probe_create_target` — drives the wizard's empty-check +
/// subfolder offer. Non-secret.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTargetProbeDto {
    pub exists: bool,
    pub is_empty: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn to_value<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("serialize")).expect("parse")
    }

    #[test]
    fn create_vault_dto_serializes_mnemonic() {
        let v = to_value(&CreateVaultDto {
            mnemonic: "abandon ability able about above absent ...".to_string(),
        });
        assert_eq!(v["mnemonic"], "abandon ability able about above absent ...");
        assert_eq!(v.as_object().expect("object").len(), 1);
    }

    #[test]
    fn probe_dto_uses_camel_case_is_empty() {
        let v = to_value(&CreateTargetProbeDto {
            exists: true,
            is_empty: false,
        });
        assert_eq!(v["exists"], true);
        // camelCase: `is_empty` -> `isEmpty` on the wire.
        assert_eq!(v["isEmpty"], false);
        assert!(v.get("is_empty").is_none(), "snake_case must not leak");
    }
}
```

Wire the module into `desktop/src-tauri/src/dtos/mod.rs`:

```rust
mod browse;
mod create;
mod manifest;

pub use browse::{BlockDetailDto, FieldMetaDto, RecordDto, RevealedFieldDto};
pub use create::{CreateTargetProbeDto, CreateVaultDto};
pub use manifest::{BlockSummaryDto, ManifestDto, SettingsDto, SettingsInput};
```

- [ ] **Step 8: Run the DTO tests to verify they pass**

Run: `cd desktop/src-tauri && cargo test --release dtos::create 2>&1 | tail -20`
Expected: PASS (2 tests).

- [ ] **Step 9: Clippy + fmt + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all
cargo fmt --all -- --check
git add desktop/src-tauri/src/secret_arg.rs desktop/src-tauri/src/lib.rs \
        desktop/src-tauri/src/commands/unlock.rs \
        desktop/src-tauri/src/dtos/create.rs desktop/src-tauri/src/dtos/mod.rs
git commit -m "feat(d13): Password zeroize boundary + unlock retrofit + create DTOs

Close the D.1.1 plain-String password carry-forward with a Password
newtype (zeroizing Deserialize) and retrofit unlock_with_password to
use it (the *_impl keeps &[u8], so its logic + tests are unchanged).
Add CreateVaultDto/CreateTargetProbeDto (camelCase, serde-pinned).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Backend — `AppError::VaultFolderNotEmpty` + `VaultCreateFailed`

**Files:**
- Modify: `desktop/src-tauri/src/errors.rs:49-112` (variants) + test module

- [ ] **Step 1: Write failing wire-format tests for the two new variants**

Add to the `#[cfg(test)] mod tests` block in `desktop/src-tauri/src/errors.rs` (after `field_not_found_carries_name`):

```rust
    #[test]
    fn vault_folder_not_empty_carries_path() {
        let v = round_trip(&AppError::VaultFolderNotEmpty {
            path: "/Users/h/Documents".to_string(),
        });
        assert_eq!(v["code"], "vault_folder_not_empty");
        assert_eq!(v["path"], "/Users/h/Documents");
    }

    #[test]
    fn vault_create_failed_detail_is_stripped() {
        let v = round_trip(&AppError::VaultCreateFailed {
            detail: "argon2id derivation OOM".to_string(),
        });
        assert_eq!(v["code"], "vault_create_failed");
        assert!(v.get("detail").is_none(), "detail must NOT cross IPC");
    }
```

- [ ] **Step 2: Run to confirm they fail (variants don't exist)**

Run: `cd desktop/src-tauri && cargo test --release errors 2>&1 | tail -20`
Expected: FAIL — `no variant ... VaultFolderNotEmpty`.

- [ ] **Step 3: Add the two variants**

In `desktop/src-tauri/src/errors.rs`, add inside `pub enum AppError` (after the `FieldNotFound` variant, before `SettingsCorrupt`):

```rust
    #[error("Vault folder is not empty")]
    VaultFolderNotEmpty { path: String },

    #[error("Could not create the vault")]
    VaultCreateFailed {
        #[serde(skip_serializing)]
        detail: String,
    },
```

- [ ] **Step 4: Run the wire tests to verify they pass**

Run: `cd desktop/src-tauri && cargo test --release errors 2>&1 | tail -20`
Expected: PASS (all errors tests, including the 2 new).

- [ ] **Step 5: Clippy + fmt + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
git add desktop/src-tauri/src/errors.rs
git commit -m "feat(d13): typed AppError::VaultFolderNotEmpty + VaultCreateFailed

VaultFolderNotEmpty carries the user-picked path for a precise UI
affordance; VaultCreateFailed maps any core VaultError from the
orchestrator with its detail stripped at the IPC seam (logged via
tracing). Wire-format tests pin both.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Backend — `commands/create.rs` (probe + create) + L3 tests + register

**Files:**
- Create: `desktop/src-tauri/src/commands/create.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs`
- Modify: `desktop/src-tauri/Cargo.toml`
- Modify: `desktop/src-tauri/src/main.rs:73-83`
- Modify: `desktop/src-tauri/tests/ipc_integration.rs`

- [ ] **Step 1: Add the `rand_core` dependency**

Core's `orchestrators::create_vault` is generic over `impl rand_core::RngCore + rand_core::CryptoRng`; the compatible `OsRng` is `rand_core` **0.6**'s (the version core/bridge use — the desktop's existing `rand = "0.9"` exposes a 0.9 `OsRng` that does NOT satisfy core's 0.6 bound). Add to `desktop/src-tauri/Cargo.toml` under `[dependencies]` (near the `rand = "0.9"` block):

```toml
# `rand_core` 0.6 `OsRng` is the CSPRNG passed into core's
# `vault::orchestrators::create_vault` (D.1.3 create path). The version is
# pinned to 0.6 to match `core/` and `ffi/secretary-ffi-bridge/` — core's
# `impl RngCore + CryptoRng` bound is the 0.6 trait, which the desktop's
# existing `rand 0.9` OsRng does NOT satisfy. `getrandom` enables `OsRng`.
rand_core = { version = "0.6", features = ["getrandom"] }
```

Verify it resolves:

Run: `cd desktop/src-tauri && cargo build --release 2>&1 | tail -5`
Expected: builds (no new code yet; just the dep).

- [ ] **Step 2: Write the failing L3 integration tests**

Add to `desktop/src-tauri/tests/ipc_integration.rs`. First add the import for the new command module and `rand_core::OsRng` at the top (alongside the existing `use secretary_desktop::commands::{...}`):

```rust
use secretary_desktop::commands::create;
use secretary_desktop::secret_arg::Password;
```

Then append this test module at the end of the file:

```rust
// ============================================================================
// D.1.3 create-vault path. Hermetic: every vault is created in a fresh
// TempDir; the password is generated at runtime (no hardcoded crypto value —
// CodeQL). A created vault is asserted by RE-OPENING it with the same
// freshly-chosen password (round-trip), never against the golden fixture.
// ============================================================================

mod create_path {
    use super::*;
    use rand_core::{OsRng, RngCore};

    const CREATE_DISPLAY_NAME: &str = "D.1.3 test identity";

    /// A runtime-random ASCII password. Avoids a hardcoded crypto literal
    /// while staying valid UTF-8 for the `Password` boundary.
    fn random_password() -> Vec<u8> {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        // Map to printable hex so the value is a valid UTF-8 password.
        raw.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
    }

    #[test]
    fn create_writes_the_four_canonical_files() {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let path = dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        let dto = create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create_vault must succeed on an empty tempdir");

        // 24-word BIP-39 phrase.
        assert_eq!(dto.mnemonic.split_whitespace().count(), 24);

        // Four canonical files exist (spec §1).
        let p = dir.path();
        assert!(p.join("vault.toml").is_file(), "vault.toml");
        assert!(p.join("identity.bundle.enc").is_file(), "identity.bundle.enc");
        assert!(p.join("manifest.cbor.enc").is_file(), "manifest.cbor.enc");
        assert!(p.join("contacts").is_dir(), "contacts/ dir");
    }

    #[test]
    fn created_vault_reopens_with_the_same_password() {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let path = dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create");

        // Re-open via the existing unlock impl (proves a complete, valid
        // on-disk vault — not just files-present).
        let (state, _device_dir) = fresh_state();
        let manifest = unlock::unlock_with_password_impl(&state, path, &pw)
            .expect("freshly-created vault must open with the same password");
        // Fresh vault: zero blocks.
        assert_eq!(manifest.block_count, 0, "a new vault has no blocks");
    }

    #[test]
    fn create_into_nonempty_folder_yields_vault_folder_not_empty() {
        let dir = tempfile::tempdir().expect("vault tempdir");
        std::fs::write(dir.path().join("stray.txt"), b"hi").expect("stray file");
        let path = dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        let err = create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect_err("non-empty folder must be rejected");
        match err {
            AppError::VaultFolderNotEmpty { path: p } => assert_eq!(p, path),
            other => panic!("expected VaultFolderNotEmpty, got {other:?}"),
        }
    }

    #[test]
    fn create_makes_the_target_dir_when_missing() {
        let dir = tempfile::tempdir().expect("parent tempdir");
        // Subfolder does NOT exist yet (the "create a new subfolder" flow).
        let target = dir.path().join("my-vault");
        let path = target.to_str().expect("utf8 path");
        let pw = random_password();

        create::create_vault_impl(
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create must mkdir -p the missing target");
        assert!(target.join("vault.toml").is_file());
    }

    #[test]
    fn probe_reports_empty_existing_and_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().to_str().expect("utf8");
        let probe = create::probe_create_target_impl(empty);
        assert!(probe.exists && probe.is_empty, "empty dir: exists + is_empty");

        std::fs::write(dir.path().join("x"), b"x").expect("write");
        let probe = create::probe_create_target_impl(empty);
        assert!(probe.exists && !probe.is_empty, "non-empty dir");

        let missing = dir.path().join("nope");
        let probe = create::probe_create_target_impl(missing.to_str().expect("utf8"));
        assert!(!probe.exists && !probe.is_empty, "missing path");
    }
}
```

- [ ] **Step 3: Run to confirm they fail (module doesn't exist)**

Run: `cd desktop/src-tauri && cargo test --release --test ipc_integration create_path 2>&1 | tail -20`
Expected: FAIL — `could not find create in ... commands`.

- [ ] **Step 4: Implement `commands/create.rs`**

Create `desktop/src-tauri/src/commands/create.rs`:

```rust
//! `create_vault` + `probe_create_target` commands.
//!
//! The first WRITE path in Sub-project D (spec §6). `create_vault` wraps
//! core's atomic orchestrator (`vault::orchestrators::create_vault`), which
//! writes the four canonical files atomically and returns the 24-word
//! recovery `Mnemonic`. The command is session-stateless: it neither reads
//! nor mutates the unlocked session. After create the frontend returns to
//! Unlock (no auto-open), so no live identity/manifest handle is retained.
//!
//! `probe_create_target` is a read-only helper that drives the wizard's
//! empty-folder check + "create a subfolder" offer without granting the
//! WebView raw filesystem-read capability.

use std::path::Path;

use rand_core::{CryptoRng, OsRng, RngCore};

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::orchestrators;

use crate::auto_lock::now_ms;
use crate::dtos::{CreateTargetProbeDto, CreateVaultDto};
use crate::errors::AppError;
use crate::secret_arg::Password;

/// Tauri-side entry point for vault creation. Thin shell; logic in
/// [`create_vault_impl`]. Uses `OsRng` + the wall-clock `now_ms()`.
#[tauri::command]
pub async fn create_vault(
    folder_path: String,
    display_name: String,
    password: Password,
) -> Result<CreateVaultDto, AppError> {
    create_vault_impl(
        &folder_path,
        &display_name,
        password.as_secret_bytes(),
        now_ms(),
        &mut OsRng,
    )
}

/// Testable core. `created_at_ms` + `rng` are injected so integration tests
/// are hermetic (runtime-random `OsRng`, no hardcoded crypto value).
///
/// Steps (spec §6):
/// 1. `create_dir_all` the target (idempotent; supports the subfolder flow).
/// 2. Own empty-check → typed [`AppError::VaultFolderNotEmpty`] BEFORE any
///    core call (never string-match core's `Io`).
/// 3. `orchestrators::create_vault` with the hardcoded v1 KDF default; any
///    `VaultError` → [`AppError::VaultCreateFailed`] (detail logged, stripped
///    at the seam).
/// 4. Copy the phrase into the DTO; the `Mnemonic` zeroizes on drop.
pub fn create_vault_impl(
    folder_path: &str,
    display_name: &str,
    password: &SecretBytes,
    created_at_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreateVaultDto, AppError> {
    let folder = Path::new(folder_path);

    std::fs::create_dir_all(folder).map_err(|e| AppError::Io {
        detail: format!("failed to create vault folder {folder_path}: {e}"),
    })?;

    let non_empty = std::fs::read_dir(folder)
        .map_err(|e| AppError::Io {
            detail: format!("failed to read vault folder {folder_path}: {e}"),
        })?
        .next()
        .is_some();
    if non_empty {
        return Err(AppError::VaultFolderNotEmpty {
            path: folder_path.to_string(),
        });
    }

    let mnemonic = orchestrators::create_vault(
        folder,
        password,
        display_name,
        Argon2idParams::V1_DEFAULT,
        created_at_ms,
        rng,
    )
    .map_err(|e| {
        tracing::warn!(?e, "vault create failed");
        AppError::VaultCreateFailed {
            detail: format!("{e}"),
        }
    })?;

    Ok(CreateVaultDto {
        mnemonic: mnemonic.phrase().to_string(),
    })
    // `mnemonic` drops here → core `Mnemonic` zeroizes phrase + entropy.
}

/// Tauri-side entry point for the read-only create-target probe.
#[tauri::command]
pub async fn probe_create_target(
    folder_path: String,
) -> Result<CreateTargetProbeDto, AppError> {
    Ok(probe_create_target_impl(&folder_path))
}

/// Pure probe: does the path exist, and (if a directory) is it empty? A
/// non-existent path reports `exists:false, is_empty:false`; the wizard treats
/// "will be created fresh" separately. Read-only; no secrets.
pub fn probe_create_target_impl(folder_path: &str) -> CreateTargetProbeDto {
    let folder = Path::new(folder_path);
    let exists = folder.exists();
    let is_empty = exists
        && folder.is_dir()
        && std::fs::read_dir(folder)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false);
    CreateTargetProbeDto { exists, is_empty }
}
```

Declare the module in `desktop/src-tauri/src/commands/mod.rs` (alphabetical, before `lock`):

```rust
pub mod browse;
pub mod create;
pub mod lock;
pub mod settings;
pub mod unlock;
pub mod vault;
```

- [ ] **Step 5: Run the L3 tests to verify they pass**

Run: `cd desktop/src-tauri && cargo test --release --test ipc_integration create_path 2>&1 | tail -25`
Expected: PASS (5 tests). (Each runs a real Argon2id at `V1_DEFAULT` — ~1-2 s apiece; the suite stays well under the test timeout.)

- [ ] **Step 6: Register both commands in `main.rs`**

In `desktop/src-tauri/src/main.rs`, add to the `use secretary_desktop::commands::{...}` line and the `invoke_handler` macro:

```rust
use secretary_desktop::commands::{browse, create, lock, settings, unlock, vault};
```

```rust
        .invoke_handler(tauri::generate_handler![
            unlock::unlock_with_password,
            vault::list_blocks,
            vault::get_manifest,
            settings::get_settings,
            settings::set_settings,
            lock::lock,
            lock::notify_activity,
            browse::read_block,
            browse::reveal_field,
            create::create_vault,
            create::probe_create_target,
        ])
```

- [ ] **Step 7: Full backend gauntlet + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create
cargo build --release 2>&1 | tail -3            # main.rs registration compiles
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
cargo test --release --workspace 2>&1 | grep "^test result:" | tail -5
git add desktop/src-tauri/src/commands/create.rs desktop/src-tauri/src/commands/mod.rs \
        desktop/src-tauri/Cargo.toml desktop/src-tauri/Cargo.lock \
        desktop/src-tauri/src/main.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(d13): create_vault + probe_create_target IPC commands

create_vault_impl wraps core's atomic orchestrator (4-file write,
returns the 24-word mnemonic): create_dir_all → own empty-check →
V1_DEFAULT KDF → DTO. probe_create_target drives the wizard's empty
check without granting the WebView fs-read. L3 tests create over
tempdirs with runtime-random passwords and assert re-open round-trip.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Frontend — ipc + errors + routing store

**Files:**
- Modify: `desktop/src/lib/ipc.ts`
- Modify: `desktop/src/lib/errors.ts`
- Create: `desktop/src/lib/route.ts`
- Create: `desktop/tests/route.test.ts`
- Modify: `desktop/tests/errors.test.ts`
- Modify: `desktop/tests/ipc.test.ts`

- [ ] **Step 1: Add the two error codes (failing test first)**

Add to `desktop/tests/errors.test.ts` (inside the existing describe; mirror the existing message-shape assertions):

```ts
import { userMessageFor } from '../src/lib/errors';

it('vault_folder_not_empty surfaces the path + subfolder hint', () => {
  const m = userMessageFor({ code: 'vault_folder_not_empty', path: '/Users/h/Docs' });
  expect(m.title).toMatch(/empty/i);
  expect(m.detail).toContain('/Users/h/Docs');
  expect(m.actionHint).toMatch(/subfolder/i);
});

it('vault_create_failed has a retry hint', () => {
  const m = userMessageFor({ code: 'vault_create_failed' });
  expect(m.title).toMatch(/create/i);
  expect(m.actionHint).toMatch(/try again/i);
});
```

Run: `cd desktop && pnpm test errors 2>&1 | tail -15`
Expected: FAIL — type error (`vault_folder_not_empty` not in union) / missing arms.

- [ ] **Step 2: Extend `errors.ts`**

In `desktop/src/lib/errors.ts`:

Add to `APP_ERROR_CODES` (after `'field_not_found'`):

```ts
  'vault_folder_not_empty',
  'vault_create_failed',
```

Add to the `AppError` union (after the `field_not_found` member):

```ts
  | { code: 'vault_folder_not_empty'; path: string }
  | { code: 'vault_create_failed' }
```

Add to `userMessageFor`'s switch (after the `field_not_found` case):

```ts
    case 'vault_folder_not_empty':
      return {
        title: "Folder isn't empty",
        detail: `${err.path} already contains files.`,
        actionHint: 'Choose an empty folder or create a new subfolder.'
      };
    case 'vault_create_failed':
      return {
        title: "Couldn't create the vault",
        actionHint: 'Please try again.'
      };
```

Run: `cd desktop && pnpm test errors 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 3: Add `createVault` + `probeCreateTarget` to ipc.ts (failing test first)**

Add to `desktop/tests/ipc.test.ts` (mirror the existing `invoke` mock pattern used for `readBlock`):

```ts
import { createVault, probeCreateTarget } from '../src/lib/ipc';

it('createVault forwards camelCase args and returns the DTO', async () => {
  invokeMock.mockResolvedValueOnce({ mnemonic: 'word '.repeat(24).trim() });
  const dto = await createVault('/tmp/v', 'Me', 'pw');
  expect(invokeMock).toHaveBeenCalledWith('create_vault', {
    folderPath: '/tmp/v',
    displayName: 'Me',
    password: 'pw'
  });
  expect(dto.mnemonic.split(' ').length).toBe(24);
});

it('probeCreateTarget returns exists + isEmpty', async () => {
  invokeMock.mockResolvedValueOnce({ exists: true, isEmpty: true });
  const probe = await probeCreateTarget('/tmp/v');
  expect(invokeMock).toHaveBeenCalledWith('probe_create_target', { folderPath: '/tmp/v' });
  expect(probe).toEqual({ exists: true, isEmpty: true });
});
```

(If `invokeMock` is named differently in `ipc.test.ts`, reuse that file's existing mock handle — check the top of the file.)

Run: `cd desktop && pnpm test ipc 2>&1 | tail -15`
Expected: FAIL — `createVault is not exported`.

- [ ] **Step 4: Extend `ipc.ts`**

Add the DTO interfaces (after `RevealedFieldDto`):

```ts
export interface CreateVaultDto {
  mnemonic: string;
}

export interface CreateTargetProbeDto {
  exists: boolean;
  isEmpty: boolean;
}
```

Add the wrappers (after `unlockWithPassword`):

```ts
export async function createVault(
  folderPath: string,
  displayName: string,
  password: string
): Promise<CreateVaultDto> {
  return call<CreateVaultDto>('create_vault', { folderPath, displayName, password });
}

export async function probeCreateTarget(folderPath: string): Promise<CreateTargetProbeDto> {
  return call<CreateTargetProbeDto>('probe_create_target', { folderPath });
}
```

Run: `cd desktop && pnpm test ipc 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Write failing tests for the routing store**

Create `desktop/tests/route.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import {
  appRoute,
  createSeedPath,
  createdVaultPath,
  openCreateWizard,
  cancelCreateWizard,
  finishCreateWizard,
  _resetRouteForTest
} from '../src/lib/route';

describe('route store', () => {
  beforeEach(() => _resetRouteForTest());

  it('defaults to unlock with empty paths', () => {
    expect(get(appRoute)).toBe('unlock');
    expect(get(createSeedPath)).toBe('');
    expect(get(createdVaultPath)).toBe('');
  });

  it('openCreateWizard routes to create and seeds the folder', () => {
    openCreateWizard('/Users/h/Docs');
    expect(get(appRoute)).toBe('create');
    expect(get(createSeedPath)).toBe('/Users/h/Docs');
  });

  it('cancelCreateWizard returns to unlock and clears the seed', () => {
    openCreateWizard('/x');
    cancelCreateWizard();
    expect(get(appRoute)).toBe('unlock');
    expect(get(createSeedPath)).toBe('');
  });

  it('finishCreateWizard returns to unlock and records the created path', () => {
    openCreateWizard('/x');
    finishCreateWizard('/Users/h/new-vault');
    expect(get(appRoute)).toBe('unlock');
    expect(get(createdVaultPath)).toBe('/Users/h/new-vault');
    expect(get(createSeedPath)).toBe('');
  });
});
```

Run: `cd desktop && pnpm test route 2>&1 | tail -15`
Expected: FAIL — cannot import `../src/lib/route`.

- [ ] **Step 6: Implement `lib/route.ts`**

Create `desktop/src/lib/route.ts`:

```ts
// Pre-unlock app routing. The create-vault wizard is a UI mode shown in the
// locked context (no vault is open during create), so it lives OUTSIDE the
// session state machine (stores.ts) deliberately — keeping `SessionState`
// strictly about an open/closed vault.

import { writable } from 'svelte/store';

export type AppRoute = 'unlock' | 'create';

/** Which pre-unlock screen App.svelte shows. */
export const appRoute = writable<AppRoute>('unlock');

/** Folder to seed the wizard's first step (from the "Not a vault" hint). */
export const createSeedPath = writable<string>('');

/** Path of a just-created vault — Unlock pre-fills it and shows a banner. */
export const createdVaultPath = writable<string>('');

/** Open the wizard, optionally seeding the picked folder. */
export function openCreateWizard(seedPath = ''): void {
  createSeedPath.set(seedPath);
  appRoute.set('create');
}

/** Abandon the wizard; back to Unlock. */
export function cancelCreateWizard(): void {
  createSeedPath.set('');
  appRoute.set('unlock');
}

/** Finish the wizard: record the created path (for Unlock pre-fill + banner)
 *  and return to Unlock. */
export function finishCreateWizard(createdPath: string): void {
  createdVaultPath.set(createdPath);
  createSeedPath.set('');
  appRoute.set('unlock');
}

/** Test-only reset. Matches the `_resetSessionStateForTest` convention. */
export function _resetRouteForTest(): void {
  appRoute.set('unlock');
  createSeedPath.set('');
  createdVaultPath.set('');
}
```

Run: `cd desktop && pnpm test route 2>&1 | tail -15`
Expected: PASS (4 tests).

- [ ] **Step 7: Frontend gate + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create/desktop
pnpm test 2>&1 | tail -6
pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint
cd /Users/hherb/src/secretary/.worktrees/d13-create
git add desktop/src/lib/ipc.ts desktop/src/lib/errors.ts desktop/src/lib/route.ts \
        desktop/tests/route.test.ts desktop/tests/errors.test.ts desktop/tests/ipc.test.ts
git commit -m "feat(d13): frontend ipc/errors + pre-unlock routing store

createVault/probeCreateTarget IPC wrappers + DTO interfaces; two new
AppError codes (vault_folder_not_empty/vault_create_failed) with
messages; a route store (appRoute unlock|create + seed/created paths)
kept out of the session state machine.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Frontend — pure wizard logic + step components + host

**Files:**
- Create: `desktop/src/lib/create.ts`
- Create: `desktop/tests/create.test.ts`
- Create: `desktop/src/components/create/FolderStep.svelte`
- Create: `desktop/src/components/create/CredentialsStep.svelte`
- Create: `desktop/src/components/create/MnemonicStep.svelte`
- Create: `desktop/src/routes/CreateVault.svelte`
- Create: `desktop/tests/FolderStep.test.ts`, `CredentialsStep.test.ts`, `MnemonicStep.test.ts`
- Modify: `desktop/src/theme.css`

- [ ] **Step 1: Write failing tests for the pure wizard helpers**

Create `desktop/tests/create.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  startWizard,
  toCredentials,
  toMnemonic,
  passwordsMatch,
  joinSubfolder,
  groupMnemonicWords
} from '../src/lib/create';

describe('wizard step machine', () => {
  it('starts at folder', () => {
    expect(startWizard()).toEqual({ step: 'folder' });
  });
  it('advances to credentials carrying the folder', () => {
    expect(toCredentials('/v')).toEqual({ step: 'credentials', folder: '/v' });
  });
  it('advances to mnemonic carrying folder + phrase', () => {
    expect(toMnemonic('/v', 'a b c')).toEqual({ step: 'mnemonic', folder: '/v', mnemonic: 'a b c' });
  });
});

describe('passwordsMatch', () => {
  it('true only when non-empty and equal', () => {
    expect(passwordsMatch('hunter2', 'hunter2')).toBe(true);
    expect(passwordsMatch('a', 'b')).toBe(false);
    expect(passwordsMatch('', '')).toBe(false);
  });
});

describe('joinSubfolder', () => {
  it('joins with the parent separator', () => {
    expect(joinSubfolder('/Users/h/Docs', 'vault')).toBe('/Users/h/Docs/vault');
    expect(joinSubfolder('/Users/h/Docs/', 'vault')).toBe('/Users/h/Docs/vault');
  });
  it('rejects empty or separator-bearing names', () => {
    expect(joinSubfolder('/x', '  ')).toBeNull();
    expect(joinSubfolder('/x', 'a/b')).toBeNull();
    expect(joinSubfolder('/x', 'a\\b')).toBeNull();
  });
});

describe('groupMnemonicWords', () => {
  it('numbers words from 1 and drops blanks', () => {
    const out = groupMnemonicWords('alpha   bravo charlie');
    expect(out).toEqual([
      { index: 1, word: 'alpha' },
      { index: 2, word: 'bravo' },
      { index: 3, word: 'charlie' }
    ]);
  });
});
```

Run: `cd desktop && pnpm test create 2>&1 | tail -15`
Expected: FAIL — cannot import `../src/lib/create`.

- [ ] **Step 2: Implement `lib/create.ts`**

Create `desktop/src/lib/create.ts`:

```ts
// Pure wizard step state + helpers for the create-vault flow. No IPC, no DOM.
// The host component (CreateVault.svelte) owns the IPC calls and holds the
// step as Svelte $state; this module is the testable logic core.

export type WizardStep =
  | { step: 'folder' }
  | { step: 'credentials'; folder: string }
  | { step: 'mnemonic'; folder: string; mnemonic: string };

export function startWizard(): WizardStep {
  return { step: 'folder' };
}

export function toCredentials(folder: string): WizardStep {
  return { step: 'credentials', folder };
}

export function toMnemonic(folder: string, mnemonic: string): WizardStep {
  return { step: 'mnemonic', folder, mnemonic };
}

/** True iff both password fields are non-empty and identical. */
export function passwordsMatch(pw: string, confirm: string): boolean {
  return pw.length > 0 && pw === confirm;
}

/** Join a picked parent folder and a subfolder name into a target path.
 *  Returns null for an empty name or one containing a path separator
 *  (we create exactly one level, not a nested path). */
export function joinSubfolder(parent: string, name: string): string | null {
  const trimmed = name.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.includes('/') || trimmed.includes('\\')) return null;
  const sep = parent.includes('\\') ? '\\' : '/';
  const base = parent.endsWith(sep) ? parent.slice(0, -sep.length) : parent;
  return `${base}${sep}${trimmed}`;
}

export interface MnemonicWord {
  index: number;
  word: string;
}

/** Split a recovery phrase into numbered words for the display grid. */
export function groupMnemonicWords(phrase: string): MnemonicWord[] {
  return phrase
    .split(/\s+/)
    .filter((w) => w.length > 0)
    .map((word, i) => ({ index: i + 1, word }));
}
```

Run: `cd desktop && pnpm test create 2>&1 | tail -15`
Expected: PASS (all wizard-logic tests).

- [ ] **Step 3: Write failing FolderStep test, then implement**

Create `desktop/tests/FolderStep.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import FolderStep from '../src/components/create/FolderStep.svelte';

// Mock the IPC probe. The component imports { probeCreateTarget } from ipc.
vi.mock('../src/lib/ipc', () => ({
  probeCreateTarget: vi.fn()
}));
import { probeCreateTarget } from '../src/lib/ipc';

// Mock the dialog plugin used by PathPicker so a folder "pick" is scriptable.
vi.mock('@tauri-apps/plugin-dialog', () => ({
  open: vi.fn().mockResolvedValue('/Users/h/Docs')
}));

describe('FolderStep', () => {
  beforeEach(() => vi.clearAllMocks());

  it('offers the subfolder field when the picked folder is non-empty', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      exists: true,
      isEmpty: false
    });
    const onNext = vi.fn();
    const { getByText, findByLabelText } = render(FolderStep, {
      props: { seedPath: '/Users/h/Docs', onNext, onCancel: vi.fn() }
    });
    // Seed path triggers a probe on mount → non-empty → subfolder field shows.
    expect(await findByLabelText(/subfolder name/i)).toBeTruthy();
    expect(getByText(/already contains files/i)).toBeTruthy();
  });

  it('continues with the picked folder when it is empty', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      exists: true,
      isEmpty: true
    });
    const onNext = vi.fn();
    const { findByRole } = render(FolderStep, {
      props: { seedPath: '/Users/h/empty', onNext, onCancel: vi.fn() }
    });
    const cont = (await findByRole('button', { name: /continue/i })) as HTMLButtonElement;
    expect(cont.disabled).toBe(false);
    await fireEvent.click(cont);
    expect(onNext).toHaveBeenCalledWith('/Users/h/empty');
  });
});
```

Run: `cd desktop && pnpm test FolderStep 2>&1 | tail -15`
Expected: FAIL — cannot find the component.

Create `desktop/src/components/create/FolderStep.svelte`:

```svelte
<script lang="ts">
  import PathPicker from '../PathPicker.svelte';
  import { probeCreateTarget } from '../../lib/ipc';
  import { joinSubfolder } from '../../lib/create';

  // Props (Svelte 5 runes). `seedPath` pre-fills the pick (from the
  // "Not a vault" hint). `onNext(finalPath)` advances; `onCancel()` aborts.
  let {
    seedPath = '',
    onNext,
    onCancel
  }: { seedPath?: string; onNext: (folder: string) => void; onCancel: () => void } = $props();

  let picked = $state(seedPath);
  let probed = $state<{ exists: boolean; isEmpty: boolean } | null>(null);
  let subfolderName = $state('');
  let probing = $state(false);

  async function probe(path: string): Promise<void> {
    if (path.length === 0) {
      probed = null;
      return;
    }
    probing = true;
    try {
      probed = await probeCreateTarget(path);
    } finally {
      probing = false;
    }
  }

  // Probe on mount (seedPath) and whenever the user picks a new folder.
  $effect(() => {
    void probe(picked);
  });

  // A non-empty existing folder requires a subfolder; a missing or empty
  // folder is usable directly.
  const needsSubfolder = $derived(probed !== null && probed.exists && !probed.isEmpty);

  const finalPath = $derived(
    needsSubfolder ? joinSubfolder(picked, subfolderName) : picked.length > 0 ? picked : null
  );

  const canContinue = $derived(!probing && finalPath !== null);

  function onPick(p: string): void {
    picked = p;
    subfolderName = '';
  }
</script>

<div class="wizard-step">
  <h2 class="wizard-step__title">Choose a folder</h2>
  <p class="wizard-step__hint">Pick an empty folder, or a folder to create your vault inside.</p>

  <PathPicker value={picked} onSelect={onPick} disabled={probing} />

  {#if needsSubfolder}
    <p class="wizard-step__warn">{picked} already contains files.</p>
    <label class="wizard-step__field">
      <span>Subfolder name</span>
      <input type="text" bind:value={subfolderName} placeholder="my-vault" />
    </label>
    {#if finalPath}
      <p class="wizard-step__hint">Will create: {finalPath}</p>
    {/if}
  {:else if probed && picked.length > 0}
    <p class="wizard-step__hint">Ready to create in {picked}</p>
  {/if}

  <div class="wizard-step__actions">
    <button type="button" class="wizard-step__cancel" onclick={onCancel}>Cancel</button>
    <button
      type="button"
      class="wizard-step__next"
      disabled={!canContinue}
      onclick={() => finalPath && onNext(finalPath)}
    >
      Continue
    </button>
  </div>
</div>
```

Run: `cd desktop && pnpm test FolderStep 2>&1 | tail -15`
Expected: PASS (2 tests).

- [ ] **Step 4: Write failing CredentialsStep test, then implement**

Create `desktop/tests/CredentialsStep.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import CredentialsStep from '../src/components/create/CredentialsStep.svelte';

describe('CredentialsStep', () => {
  it('disables Create until name + matching passwords are present', async () => {
    const onCreate = vi.fn();
    const { getByLabelText, getByRole } = render(CredentialsStep, {
      props: { folder: '/v', submitting: false, onCreate, onBack: vi.fn() }
    });
    const create = getByRole('button', { name: /create vault/i }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);

    await fireEvent.input(getByLabelText(/display name/i), { target: { value: 'Me' } });
    await fireEvent.input(getByLabelText(/^password/i), { target: { value: 'hunter2' } });
    await fireEvent.input(getByLabelText(/confirm/i), { target: { value: 'hunter2' } });
    expect(create.disabled).toBe(false);

    await fireEvent.click(create);
    expect(onCreate).toHaveBeenCalledWith('Me', 'hunter2');
  });

  it('shows a mismatch message and keeps Create disabled', async () => {
    const { getByLabelText, getByRole, getByText } = render(CredentialsStep, {
      props: { folder: '/v', submitting: false, onCreate: vi.fn(), onBack: vi.fn() }
    });
    await fireEvent.input(getByLabelText(/display name/i), { target: { value: 'Me' } });
    await fireEvent.input(getByLabelText(/^password/i), { target: { value: 'hunter2' } });
    await fireEvent.input(getByLabelText(/confirm/i), { target: { value: 'hunterX' } });
    expect(getByText(/don.t match/i)).toBeTruthy();
    expect((getByRole('button', { name: /create vault/i }) as HTMLButtonElement).disabled).toBe(true);
  });
});
```

Run: `cd desktop && pnpm test CredentialsStep 2>&1 | tail -15`
Expected: FAIL — cannot find the component.

Create `desktop/src/components/create/CredentialsStep.svelte`:

```svelte
<script lang="ts">
  import { passwordsMatch } from '../../lib/create';

  let {
    folder,
    submitting = false,
    onCreate,
    onBack
  }: {
    folder: string;
    submitting?: boolean;
    onCreate: (displayName: string, password: string) => void;
    onBack: () => void;
  } = $props();

  let displayName = $state('');
  let password = $state('');
  let confirm = $state('');

  const match = $derived(passwordsMatch(password, confirm));
  const showMismatch = $derived(confirm.length > 0 && password !== confirm);
  const canCreate = $derived(!submitting && displayName.trim().length > 0 && match);

  function submit(): void {
    if (!canCreate) return;
    onCreate(displayName.trim(), password);
    // Drop the local password bindings immediately (JS strings are immutable
    // so this only minimises the live-reference window — same caveat as
    // Unlock.svelte). The phrase the user must record comes back separately.
    password = '';
    confirm = '';
  }
</script>

<div class="wizard-step">
  <h2 class="wizard-step__title">Set a password</h2>
  <p class="wizard-step__hint">Creating a vault in {folder}.</p>

  <label class="wizard-step__field">
    <span>Display name</span>
    <input type="text" bind:value={displayName} placeholder="Your name" disabled={submitting} />
  </label>

  <label class="wizard-step__field">
    <span>Password</span>
    <input type="password" bind:value={password} placeholder="••••••••" disabled={submitting} />
  </label>

  <label class="wizard-step__field">
    <span>Confirm password</span>
    <input type="password" bind:value={confirm} placeholder="••••••••" disabled={submitting} />
  </label>

  {#if showMismatch}
    <p class="wizard-step__warn">Passwords don't match.</p>
  {/if}

  <p class="wizard-step__hint">
    There is no password reset — your recovery phrase (shown next) is the only way back in.
  </p>

  <div class="wizard-step__actions">
    <button type="button" class="wizard-step__cancel" onclick={onBack} disabled={submitting}>Back</button>
    <button type="button" class="wizard-step__next" disabled={!canCreate} onclick={submit}>
      {submitting ? 'Creating…' : 'Create vault'}
    </button>
  </div>
</div>
```

Run: `cd desktop && pnpm test CredentialsStep 2>&1 | tail -15`
Expected: PASS (2 tests).

- [ ] **Step 5: Write failing MnemonicStep test, then implement**

Create `desktop/tests/MnemonicStep.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import MnemonicStep from '../src/components/create/MnemonicStep.svelte';

vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({
  writeText: vi.fn().mockResolvedValue(undefined)
}));
import { writeText } from '@tauri-apps/plugin-clipboard-manager';

const PHRASE = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(' ');

describe('MnemonicStep', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders 24 numbered words and gates Continue on acknowledge', async () => {
    const onDone = vi.fn();
    const { getAllByTestId, getByRole, getByLabelText } = render(MnemonicStep, {
      props: { mnemonic: PHRASE, onDone }
    });
    expect(getAllByTestId('mnemonic-word')).toHaveLength(24);

    const cont = getByRole('button', { name: /continue/i }) as HTMLButtonElement;
    expect(cont.disabled).toBe(true);

    await fireEvent.click(getByLabelText(/written down/i));
    expect(cont.disabled).toBe(false);
    await fireEvent.click(cont);
    expect(onDone).toHaveBeenCalled();
  });

  it('copy button writes the phrase to the clipboard', async () => {
    const { getByRole } = render(MnemonicStep, { props: { mnemonic: PHRASE, onDone: vi.fn() } });
    await fireEvent.click(getByRole('button', { name: /copy/i }));
    expect(writeText).toHaveBeenCalledWith(PHRASE);
  });
});
```

Run: `cd desktop && pnpm test MnemonicStep 2>&1 | tail -15`
Expected: FAIL — cannot find the component.

Create `desktop/src/components/create/MnemonicStep.svelte`:

```svelte
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { writeText } from '@tauri-apps/plugin-clipboard-manager';
  import { groupMnemonicWords } from '../../lib/create';
  import { CLIPBOARD_CLEAR_MS } from '../../lib/constants';

  // The phrase lives ONLY in this component's props/$state. It is dropped
  // when the component unmounts (onDone navigates away → unmount). Never
  // stored, cached, or logged.
  let { mnemonic, onDone }: { mnemonic: string; onDone: () => void } = $props();

  let acknowledged = $state(false);
  let copied = $state(false);
  const words = $derived(groupMnemonicWords(mnemonic));

  // Best-effort clipboard auto-clear, mirroring the D.1.2 field-copy timeout.
  let clearTimer: ReturnType<typeof setTimeout> | null = null;

  async function copy(): Promise<void> {
    await writeText(mnemonic);
    copied = true;
    if (clearTimer) clearTimeout(clearTimer);
    clearTimer = setTimeout(() => {
      void writeText('');
      copied = false;
    }, CLIPBOARD_CLEAR_MS);
  }

  onDestroy(() => {
    if (clearTimer) clearTimeout(clearTimer);
  });
</script>

<div class="wizard-step">
  <h2 class="wizard-step__title">Your recovery phrase</h2>
  <p class="wizard-step__warn">
    Write these 24 words down and keep them safe. This is the ONLY way to recover your vault if you
    forget your password.
  </p>

  <ol class="mnemonic-grid">
    {#each words as w (w.index)}
      <li class="mnemonic-grid__item" data-testid="mnemonic-word">
        <span class="mnemonic-grid__index">{w.index}</span>
        <span class="mnemonic-grid__word">{w.word}</span>
      </li>
    {/each}
  </ol>

  <button type="button" class="wizard-step__copy" onclick={copy}>
    {copied ? 'Copied ✓' : 'Copy'}
  </button>

  <label class="wizard-step__ack">
    <input type="checkbox" bind:checked={acknowledged} />
    <span>I have written down my recovery phrase</span>
  </label>

  <div class="wizard-step__actions">
    <button type="button" class="wizard-step__next" disabled={!acknowledged} onclick={onDone}>
      Continue
    </button>
  </div>
</div>
```

> If `CLIPBOARD_CLEAR_MS` is not yet exported from `desktop/src/lib/constants.ts` (it was added in D.1.2), add it there mirroring `REVEAL_AUTO_HIDE_MS` with the value `30_000` and a doc comment; otherwise import the existing constant.

Run: `cd desktop && pnpm test MnemonicStep 2>&1 | tail -15`
Expected: PASS (2 tests).

- [ ] **Step 6: Implement the wizard host `CreateVault.svelte`**

Create `desktop/src/routes/CreateVault.svelte`:

```svelte
<script lang="ts">
  import FolderStep from '../components/create/FolderStep.svelte';
  import CredentialsStep from '../components/create/CredentialsStep.svelte';
  import MnemonicStep from '../components/create/MnemonicStep.svelte';
  import { startWizard, toCredentials, toMnemonic, type WizardStep } from '../lib/create';
  import { createVault } from '../lib/ipc';
  import { userMessageFor } from '../lib/errors';
  import { createSeedPath, cancelCreateWizard, finishCreateWizard } from '../lib/route';
  import { get } from 'svelte/store';
  import type { AppError } from '../lib/errors';

  let state = $state<WizardStep>(startWizard());
  let submitting = $state(false);
  let errMsg = $state<ReturnType<typeof userMessageFor> | null>(null);
  const seed = get(createSeedPath);

  function gotoCredentials(folder: string): void {
    errMsg = null;
    state = toCredentials(folder);
  }

  async function create(displayName: string, password: string): Promise<void> {
    if (state.step !== 'credentials' || submitting) return;
    submitting = true;
    errMsg = null;
    const folder = state.folder;
    try {
      const dto = await createVault(folder, displayName, password);
      state = toMnemonic(folder, dto.mnemonic);
    } catch (err) {
      errMsg = userMessageFor(err as AppError);
    } finally {
      submitting = false;
    }
  }

  function done(): void {
    // state.step === 'mnemonic' here — record the created folder for the
    // Unlock pre-fill + banner, then leave the wizard.
    if (state.step === 'mnemonic') {
      finishCreateWizard(state.folder);
    }
  }
</script>

<main class="wizard">
  <div class="wizard__card">
    <h1 class="wizard__title">Create a vault</h1>

    {#if errMsg}
      <div class="wizard__error" role="alert">
        <div class="wizard__error-title">{errMsg.title}</div>
        {#if errMsg.detail}<div class="wizard__error-detail">{errMsg.detail}</div>{/if}
        {#if errMsg.actionHint}<div class="wizard__error-hint">{errMsg.actionHint}</div>{/if}
      </div>
    {/if}

    {#if state.step === 'folder'}
      <FolderStep seedPath={seed} onNext={gotoCredentials} onCancel={cancelCreateWizard} />
    {:else if state.step === 'credentials'}
      <CredentialsStep
        folder={state.folder}
        {submitting}
        onCreate={create}
        onBack={() => (state = startWizard())}
      />
    {:else}
      <MnemonicStep mnemonic={state.mnemonic} onDone={done} />
    {/if}
  </div>
</main>
```

- [ ] **Step 7: Add styles to `theme.css`**

Append to `desktop/src/theme.css` (reuse existing color tokens; mirror the `.unlock*` block conventions):

```css
/* D.1.3 create-vault wizard. Component-scoped <style> trips the Vite-6
   preprocessCSS bug under Vitest (#153), so visual rules live here. */
.wizard { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.wizard__card { width: min(560px, 92vw); padding: 2rem; }
.wizard__title { margin: 0 0 1rem; }
.wizard__error { border: 1px solid var(--danger, #b00); border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem; }
.wizard__error-title { font-weight: 600; }
.wizard-step__title { margin: 0 0 0.5rem; }
.wizard-step__hint { color: var(--muted, #888); font-size: 0.9rem; }
.wizard-step__warn { color: var(--danger, #b00); font-size: 0.9rem; }
.wizard-step__field { display: flex; flex-direction: column; gap: 0.25rem; margin: 0.75rem 0; }
.wizard-step__actions { display: flex; justify-content: space-between; margin-top: 1.25rem; gap: 0.5rem; }
.wizard-step__ack { display: flex; align-items: center; gap: 0.5rem; margin: 1rem 0; }
.mnemonic-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; padding: 0; margin: 1rem 0; list-style: none; }
.mnemonic-grid__item { display: flex; gap: 0.4rem; padding: 0.4rem 0.6rem; border: 1px solid var(--border, #3334); border-radius: 6px; }
.mnemonic-grid__index { color: var(--muted, #888); min-width: 1.4em; text-align: right; }
.mnemonic-grid__word { font-family: var(--mono, monospace); }
```

- [ ] **Step 8: Full frontend gate + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create/desktop
pnpm test 2>&1 | tail -6
pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint
cd /Users/hherb/src/secretary/.worktrees/d13-create
git add desktop/src/lib/create.ts desktop/src/components/create/ desktop/src/routes/CreateVault.svelte \
        desktop/src/theme.css desktop/src/lib/constants.ts \
        desktop/tests/create.test.ts desktop/tests/FolderStep.test.ts \
        desktop/tests/CredentialsStep.test.ts desktop/tests/MnemonicStep.test.ts
git commit -m "feat(d13): wizard logic + FolderStep/CredentialsStep/MnemonicStep + host

Pure lib/create.ts (step machine + passwordsMatch/joinSubfolder/
groupMnemonicWords) with three step components and the CreateVault
host. Mnemonic lives only in component \$state, dropped on unmount;
copy uses the write-only clipboard with a best-effort auto-clear.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Frontend wiring + ship (App route, Unlock hint/banner, gauntlet, docs, handoff)

**Files:**
- Modify: `desktop/src/App.svelte:86-99`
- Modify: `desktop/src/routes/Unlock.svelte`
- Modify: `desktop/tests/Unlock.test.ts` (if present) / add a wiring test
- Modify: `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-05-29-d13-create-shipped.md` + retarget `NEXT_SESSION.md`

- [ ] **Step 1: Route to the wizard from App.svelte (failing test first)**

Add to `desktop/tests/App.test.ts` (or create a minimal one mirroring the existing routing test; if App is not unit-tested, add this small test file `desktop/tests/AppRoute.test.ts`):

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte';
import App from '../src/App.svelte';
import { _resetSessionStateForTest } from '../src/lib/stores';
import { openCreateWizard, _resetRouteForTest } from '../src/lib/route';

describe('App pre-unlock routing', () => {
  beforeEach(() => {
    _resetSessionStateForTest();
    _resetRouteForTest();
  });

  it('shows the create wizard when appRoute is create', async () => {
    openCreateWizard('/tmp/v');
    const { findByRole } = render(App);
    // The wizard host renders an <h1>Create a vault</h1>.
    expect(await findByRole('heading', { name: /create a vault/i })).toBeTruthy();
  });
});
```

Run: `cd desktop && pnpm test AppRoute 2>&1 | tail -15`
Expected: FAIL — App still renders Unlock regardless of `appRoute`.

- [ ] **Step 2: Wire App.svelte to switch on `appRoute`**

In `desktop/src/App.svelte`, add the imports:

```ts
  import { appRoute } from './lib/route';
  import CreateVault from './routes/CreateVault.svelte';
```

Replace the `{:else}` arm (currently `<Unlock />`) so the locked context switches on the route:

```svelte
{:else if $appRoute === 'create'}
  <CreateVault />
{:else}
  <Unlock />
{/if}
```

Run: `cd desktop && pnpm test AppRoute 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 3: Wire the "Not a vault" hint + created-banner into Unlock (failing test first)**

Add to `desktop/tests/Unlock.test.ts` (or a new `desktop/tests/UnlockCreate.test.ts`):

```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import Unlock from '../src/routes/Unlock.svelte';
import { get } from 'svelte/store';
import { appRoute, createdVaultPath, _resetRouteForTest } from '../src/lib/route';
import { _resetSessionStateForTest } from '../src/lib/stores';

vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));

describe('Unlock ↔ create wiring', () => {
  beforeEach(() => {
    _resetSessionStateForTest();
    _resetRouteForTest();
  });

  it('pre-fills the folder and shows a banner after a create', () => {
    createdVaultPath.set('/Users/h/new-vault');
    const { getByText } = render(Unlock);
    expect(getByText(/vault created/i)).toBeTruthy();
  });

  it('"Create a vault here" opens the wizard seeded with the path', async () => {
    // Drive a not-a-vault error so the create affordance renders.
    _resetSessionStateForTest();
    // unlockFailed with a vault_path_not_a_vault error:
    const { unlockFailed } = await import('../src/lib/stores');
    unlockFailed({ code: 'vault_path_not_a_vault', path: '/Users/h/Docs' });
    const { getByRole } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /create a vault here/i }));
    expect(get(appRoute)).toBe('create');
  });
});
```

Run: `cd desktop && pnpm test UnlockCreate 2>&1 | tail -15`
Expected: FAIL — no banner / no "Create a vault here" button yet.

- [ ] **Step 4: Implement the Unlock.svelte changes**

In `desktop/src/routes/Unlock.svelte`, add imports + derived state in the `<script>`:

```ts
  import { openCreateWizard, createdVaultPath } from '../lib/route';
  import { get } from 'svelte/store';

  // Pre-fill from a just-created vault (set by finishCreateWizard).
  const created = get(createdVaultPath);
  if (created.length > 0 && folderPath.length === 0) {
    folderPath = created;
  }
  const showCreatedBanner = $derived(created.length > 0);

  // Is the current error the "not a vault" case? Then offer to create here.
  const offerCreate = $derived(
    $sessionState.status === 'locked' &&
      $sessionState.lastError?.code === 'vault_path_not_a_vault'
  );
```

Add the banner just inside `<form onsubmit={submit}>` (before the `{#if errMsg}` block):

```svelte
      {#if showCreatedBanner}
        <div class="unlock__banner" role="status">
          Vault created — enter your password to open it.
        </div>
      {/if}
```

Replace the static action-hint render (the `{#if errMsg.actionHint}` line inside the error block) so the not-a-vault case becomes an actionable button:

```svelte
          {#if errMsg.actionHint}
            {#if offerCreate}
              <button
                type="button"
                class="unlock__error-action"
                onclick={() => openCreateWizard(folderPath)}
              >
                Create a vault here
              </button>
            {:else}
              <div class="unlock__error-hint">{errMsg.actionHint}</div>
            {/if}
          {/if}
```

Add the two new style rules to `desktop/src/theme.css`:

```css
.unlock__banner { background: var(--ok-bg, #1b4); color: #fff; border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 1rem; }
.unlock__error-action { margin-top: 0.4rem; background: none; border: 1px solid currentColor; border-radius: 6px; padding: 0.3rem 0.6rem; cursor: pointer; }
```

Run: `cd desktop && pnpm test UnlockCreate 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Full automated gauntlet (the D.1.3 close)**

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -2
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -2
cd desktop && pnpm test 2>&1 | tail -4 && pnpm typecheck && pnpm svelte-check 2>&1 | tail -2 && pnpm lint && cd ..
```
Expected: Rust PASSED ≥ 1074 (1069 baseline + 5 create L3 tests + secret_arg/dtos unit tests) / 0 / 10; clippy clean; fmt clean; conformance PASS; spec-freshness PASS; Vitest 234 + new (route/create/3 steps/AppRoute/UnlockCreate) passing; typecheck/svelte-check/lint clean. Record exact counts in the handoff.

- [ ] **Step 6: Update README.md + ROADMAP.md**

- `README.md` (D-row status, brief): change the D.1.2-shipped note to "D.1.3 (vault create wizard) shipped; D.1.4 (edit) next."
- `ROADMAP.md`: mark D.1.3 ✅; D.1.4 ⏳ next.

Commit nothing yet — bundle with the ship commit in Step 8.

- [ ] **Step 7: Manual GUI smoke (user pre-merge gate — NOT headless)**

Record this block verbatim in the handoff; the user runs it against a **tempdir**, never the golden fixture:

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create/desktop
pnpm install && pnpm tauri build --debug
TARGET=$(mktemp -d)/new-vault   # a path inside an empty temp parent
./src-tauri/target/debug/secretary-desktop
```
Walk (spec §15): from the empty state (or trigger the "Not a vault" hint by pointing Unlock at a non-vault folder → click "Create a vault here") → pick the empty parent → name a subfolder (or pick an already-empty folder) → set display name + password + matching confirm → Create → see 24 words → Copy + paste elsewhere (matches) → tick acknowledge → Continue → land on Unlock with the path pre-filled + "Vault created" banner → unlock with the same password → empty browse view. Re-running create into the now-non-empty folder shows the typed "Folder isn't empty" message.

- [ ] **Step 8: Author the handoff baton + retarget the symlink + ship commit**

Author `docs/handoffs/2026-05-29-d13-create-shipped.md` capturing: (1) what shipped + commit SHAs, (2) what's next (D.1.4 edit) with acceptance criteria, (3) open decisions/risks (carry-forwards #153/#154/#161/#141 etc.; the recovery-mnemonic widening + zeroize-boundary limitation as the security-review surface), (4) exact resume commands, (5) the manual-smoke block from Step 7.

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create
ln -snf docs/handoffs/2026-05-29-d13-create-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md           # shows the -> target
head -3 NEXT_SESSION.md          # reads the handoff transparently
git add desktop/src/App.svelte desktop/src/routes/Unlock.svelte desktop/src/theme.css \
        desktop/tests/AppRoute.test.ts desktop/tests/UnlockCreate.test.ts \
        README.md ROADMAP.md docs/handoffs/2026-05-29-d13-create-shipped.md NEXT_SESSION.md
git commit -m "ship(d13): wizard routing + Unlock create affordance + docs/handoff

App routes to CreateVault on appRoute=create; Unlock turns the
'Not a vault' hint into a 'Create a vault here' button and shows a
'Vault created' banner with the path pre-filled after create.
README/ROADMAP mark D.1.3 shipped; handoff baton + symlink retargeted.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 9: Open the PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create
git push -u origin feature/d13-create
gh pr create --base main --title "D.1.3 — vault create wizard (first write slice)" \
  --body "$(cat <<'EOF'
Implements D.1.3 per docs/superpowers/specs/2026-05-29-d13-create-vault-design.md.

- Wraps core's atomic create orchestrator (4-file write, returns the mnemonic).
- Zeroize-typed Password IPC boundary; retrofits unlock_with_password.
- Wizard: folder (+empty-probe/subfolder) → credentials (+confirm) → mnemonic (display+acknowledge) → Unlock pre-filled.

Security-review surface: the recovery-mnemonic widening point + the zeroize-boundary's documented serde-buffer limitation (spec §13).
Manual GUI smoke (tempdir, NOT the golden fixture) is the pre-merge gate — see the handoff.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

**1. Spec coverage** — every spec section maps to a task:
- §3 architecture (wrap core orchestrator) → Task 3. Post-create return-to-Unlock → Task 6 (finishCreateWizard + banner).
- §4 layout → all files created across Tasks 1/3/4/5/6.
- §5 modules (secret_arg, dtos/create, commands/create, lib/create, route, components) → Tasks 1/3/4/5.
- §6 lifecycle (probe; create_dir_all→empty-check→orchestrator→DTO) → Task 3 Step 4.
- §8 mnemonic handling (display-only $state, copy, drop on unmount) → Task 5 Step 5.
- §9 error model (VaultFolderNotEmpty/VaultCreateFailed) → Task 2 + Task 4 Step 2.
- §10 testing (L1 secret_arg/dtos, L2 step/logic, L3 create round-trip) → Tasks 1/3/4/5.
- §11 deps (rand_core 0.6; no npm) → Task 3 Step 1.
- §12 UX → Task 5 components.
- §13 honesty items (WeakKdfParams unreachable; serde-buffer limitation) → encoded in secret_arg.rs module docs (Task 1) + not built for (no KDF UI).
- §14/§15 docs + acceptance → Task 6.

**2. Placeholder scan** — no "TBD"/"add error handling"/"similar to". Every code step shows complete code; the one conditional ("if CLIPBOARD_CLEAR_MS not exported, add it") gives the exact value + source to mirror.

**3. Type consistency** — `create_vault_impl(folder_path:&str, display_name:&str, password:&SecretBytes, created_at_ms:u64, rng:&mut impl RngCore+CryptoRng) -> Result<CreateVaultDto, AppError>` used identically in Task 3 impl + tests. `Password::expose()/as_secret_bytes()/from_bytes()` consistent across Task 1 + Task 3. Wizard helpers (`passwordsMatch`/`joinSubfolder`/`groupMnemonicWords`, `startWizard`/`toCredentials`/`toMnemonic`) consistent across Task 5 lib + components + tests. Route API (`appRoute`/`createSeedPath`/`createdVaultPath`/`openCreateWizard`/`cancelCreateWizard`/`finishCreateWizard`/`_resetRouteForTest`) consistent across Tasks 4/5/6. DTO field `isEmpty` (camelCase) consistent between Rust serde test (Task 1) and TS interface (Task 4).
