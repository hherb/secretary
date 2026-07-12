# Mobile per-vault settings — PR 1 (bridge module + FFI projection + desktop migration) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift the vault-settings schema/parse/validate logic out of the desktop Tauri layer into a single shared `secretary-ffi-bridge` module, project typed `read_settings` / `write_settings` onto uniffi + pyo3, and migrate desktop to consume the shared module — so the two mobile PRs (iOS, Android) can read/write the per-vault retention + re-auth-grace settings over one Rust source of truth.

**Architecture:** Settings are stored as a record inside the vault (block `__secretary_app_settings__`, record type `secretary.settings.v1`, four text fields). This PR moves the schema + `parse_settings_fields` / `serialize_settings` / `validate_save_settings` + `deterministic_uuid_16` into `ffi/secretary-ffi-bridge/src/settings/`, adds two orchestrators (`read_settings` / `write_settings`) composed from the existing bridge `read_block` / `save_block`, projects them onto uniffi + pyo3, and rewrites desktop's `settings/*` as a thin adapter over the bridge. No mobile change in this PR.

**Tech Stack:** Rust (stable), `secretary-ffi-bridge` (pure-safe bridge crate), `secretary-ffi-uniffi` (uniffi 0.3x UDL), `secretary-ffi-py` (pyo3 0.28), desktop Tauri Rust backend, `uv` for the python test.

## Global Constraints

- Stable Rust; `#![forbid(unsafe_code)]` at the workspace root — do not introduce `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`.
- Rustdoc gate on public items: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` — any `[[…]]` marker or intra-doc link in a **public** item's doc comment must resolve ([[project_secretary_rustdoc_gate_public_items_only]]).
- **No new `FfiVaultError` variant** — `read_settings` / `write_settings` propagate the existing errors of `read_block` / `save_block`. This keeps the Swift/Kotlin `ConformanceErrors.{swift,kt}` harnesses and the core-KAT match untouched ([[project_secretary_ffivaulterror_workspace_match]]).
- Bounds validation surfaces the **existing** `VaultError::InvalidArgument` (uniffi) / `ValueError` (pyo3) at the binding wrapper, per [[project_secretary_input_validation_at_binding_wrapper]] — the bridge orchestrator trusts its caller for bounds (out-of-range clamps on next load anyway; it is not a security surface).
- Settings on-disk format is **frozen**: block name `__secretary_app_settings__`, record type `secretary.settings.v1`, field names `auto_lock_timeout_ms` / `require_password_before_edits` / `reauth_grace_window_ms` / `retention_window_ms`, `deterministic_uuid_16(name) = SHA-256(name)[0..16]`. A mobile-written record must read back byte-identically on desktop.
- `deterministic_uuid_16` reuses `secretary_core::crypto::hash::sha256` (public; the bridge already imports `secretary_core::crypto::*`) — **no new bridge dependency**.
- Exact bound constants (copied verbatim from `desktop/src-tauri/src/constants.rs`):
  - `MS_PER_DAY = 86_400_000`
  - `RETENTION_WINDOW_DEFAULT_MS = secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS` (90 d), `RETENTION_WINDOW_MIN_MS = MS_PER_DAY` (1 d), `RETENTION_WINDOW_MAX_MS = 3650 * MS_PER_DAY`
  - `AUTO_LOCK_DEFAULT_MS = 600_000`, `AUTO_LOCK_MIN_MS = 60_000`, `AUTO_LOCK_MAX_MS = 86_400_000`
  - `REAUTH_WINDOW_DEFAULT_MS = 120_000`, `REAUTH_WINDOW_MIN_MS = 0`, `REAUTH_WINDOW_MAX_MS = 3_600_000`
  - `REQUIRE_PASSWORD_DEFAULT = true`
- Working directory: all edits target `.worktrees/mobile-vault-settings/…` on branch `feature/mobile-vault-settings` ([[feedback_edit_tool_targets_main_not_worktree]]). Verify with `pwd && git branch --show-current` before path-sensitive commands.
- Test/build gate for this PR (run from the worktree root):
  ```bash
  cargo test --release --workspace
  cargo clippy --release --workspace --tests -- -D warnings
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
  bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
  cd desktop && pnpm test && pnpm run svelte-check   # desktop behavior unchanged
  ```

---

## File Structure

**Bridge (new):**
- `ffi/secretary-ffi-bridge/src/settings/mod.rs` — module root + re-exports.
- `ffi/secretary-ffi-bridge/src/settings/schema.rs` — `Settings` value type, constants, `deterministic_uuid_16`.
- `ffi/secretary-ffi-bridge/src/settings/parse.rs` — `SettingsWarning` / `SettingsParseError` / `SettingsBoundsError` + `parse_settings_fields` / `serialize_settings` / `validate_save_settings`.
- `ffi/secretary-ffi-bridge/src/settings/orchestration.rs` — `read_settings` / `write_settings`.
- `ffi/secretary-ffi-bridge/tests/settings.rs` — integration tests (round-trip, field-preservation).
- `ffi/secretary-ffi-bridge/src/lib.rs` — add `pub mod settings;` + re-exports (modify).

**FFI (modify/new):**
- `ffi/secretary-ffi-uniffi/src/secretary.udl` — add `Settings` dictionary + `read_settings` / `write_settings` + settings-constants fns (modify).
- `ffi/secretary-ffi-uniffi/src/wrappers/settings.rs` — uniffi `Settings` value type (new).
- `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs` — `pub mod settings;` (modify).
- `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` — `read_settings` / `write_settings` / settings-constants namespace fns (modify).
- `ffi/secretary-ffi-py/src/settings.rs` — pyo3 `Settings` pyclass + `read_settings` / `write_settings` (new).
- `ffi/secretary-ffi-py/src/lib.rs` — `mod settings;` + registration (modify).
- `ffi/secretary-ffi-py/tests/test_settings.py` — python round-trip + field-preservation test (new).

**Desktop (modify):**
- `desktop/src-tauri/src/settings/parse.rs` — re-export bridge types + `AppError`/`AppWarning` mapping (rewrite).
- `desktop/src-tauri/src/settings/io.rs` — delegate to bridge `read_settings` / `write_settings` (modify the two facade fns).
- `desktop/src-tauri/src/constants.rs` — re-export settings/retention/reauth constants from the bridge; delete the local `deterministic_uuid_16` + `Sha256` use (modify).
- `desktop/src-tauri/Cargo.toml` — drop the now-unused `sha2` dependency if nothing else uses it (modify).

---

## Task 1: Bridge `settings/schema.rs` — value type, constants, deterministic UUID

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/settings/schema.rs`
- Create (stub this task, filled in Task 3): `ffi/secretary-ffi-bridge/src/settings/mod.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (add `pub mod settings;`)

**Interfaces:**
- Produces:
  - `pub struct Settings { pub auto_lock_timeout_ms: u64, pub require_password_before_edits: bool, pub reauth_grace_window_ms: u64, pub retention_window_ms: u64 }` (derives `Debug, Clone, Copy, PartialEq, Eq`; `impl Default`).
  - Constants (all `pub`): `SETTINGS_BLOCK_NAME: &str`, `SETTINGS_RECORD_TYPE: &str`, `SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS`, `SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS`, `SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS`, `SETTINGS_FIELD_RETENTION_WINDOW_MS` (all `&str`); `MS_PER_DAY`, `RETENTION_WINDOW_{DEFAULT,MIN,MAX}_MS`, `AUTO_LOCK_{DEFAULT,MIN,MAX}_MS`, `REAUTH_WINDOW_{DEFAULT,MIN,MAX}_MS` (all `u64`); `REQUIRE_PASSWORD_DEFAULT: bool`.
  - `pub fn deterministic_uuid_16(input: &str) -> [u8; 16]`.

- [ ] **Step 1: Create the module stub + wire it into lib.rs**

Create `ffi/secretary-ffi-bridge/src/settings/mod.rs`:

```rust
//! Vault-settings schema + parse/serialize + read/write orchestrators — the
//! single source of truth for the `secretary.settings.v1` record consumed by
//! desktop (directly) and mobile (via uniffi). Split: `schema` (value type +
//! constants + deterministic UUIDs), `parse` (pure string↔struct + bounds),
//! `orchestration` (vault I/O over `read_block` / `save_block`).

pub mod orchestration;
pub mod parse;
pub mod schema;

pub use orchestration::{read_settings, write_settings};
pub use parse::{
    parse_settings_fields, serialize_settings, validate_save_settings, SettingsBoundsError,
    SettingsParseError, SettingsWarning,
};
pub use schema::{
    deterministic_uuid_16, Settings, AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS,
    MS_PER_DAY, REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS,
    REQUIRE_PASSWORD_DEFAULT, RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MAX_MS,
    RETENTION_WINDOW_MIN_MS, SETTINGS_BLOCK_NAME, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
    SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS, SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
    SETTINGS_FIELD_RETENTION_WINDOW_MS, SETTINGS_RECORD_TYPE,
};
```

> The `pub use` lines reference `parse` / `orchestration` items created in Tasks 2–3. To let Task 1 compile alone, temporarily comment out the `orchestration` and `parse` lines (module + re-exports); uncomment them in their tasks. (Simplest: create empty `parse.rs` / `orchestration.rs` with `// filled in Task N` and only declare `pub mod schema;` + the schema re-export now, adding the others in Tasks 2–3.)

In `ffi/secretary-ffi-bridge/src/lib.rs`, add to the module list (alongside `pub mod save;` etc., keep alphabetical-ish with the neighbors):

```rust
pub mod settings;
```

- [ ] **Step 2: Write the failing test** (append to `schema.rs` after you create it in Step 3, but write it first mentally; concretely, create `schema.rs` with the test module and a `todo!()`-free skeleton). Put this test at the bottom of `schema.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_constants() {
        let d = Settings::default();
        assert_eq!(d.auto_lock_timeout_ms, AUTO_LOCK_DEFAULT_MS);
        assert_eq!(d.require_password_before_edits, REQUIRE_PASSWORD_DEFAULT);
        assert_eq!(d.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
        assert_eq!(d.retention_window_ms, RETENTION_WINDOW_DEFAULT_MS);
    }

    #[test]
    fn deterministic_uuid_is_sha256_prefix_and_stable() {
        let a = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
        let b = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
        assert_eq!(a, b, "same input → same uuid");
        let full = secretary_core::crypto::hash::sha256(SETTINGS_BLOCK_NAME.as_bytes());
        assert_eq!(a, full[0..16], "uuid is the 16-byte SHA-256 prefix");
        assert_ne!(
            deterministic_uuid_16(SETTINGS_BLOCK_NAME),
            deterministic_uuid_16(SETTINGS_RECORD_TYPE),
            "distinct inputs → distinct uuids"
        );
    }

    #[test]
    fn retention_default_equals_core_frozen_value() {
        assert_eq!(
            RETENTION_WINDOW_DEFAULT_MS,
            secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS
        );
    }

    // Compile-time bound ordering (mirrors desktop's const-asserts).
    const _: () = assert!(RETENTION_WINDOW_MIN_MS < RETENTION_WINDOW_DEFAULT_MS);
    const _: () = assert!(RETENTION_WINDOW_DEFAULT_MS < RETENTION_WINDOW_MAX_MS);
    const _: () = assert!(REAUTH_WINDOW_MIN_MS < REAUTH_WINDOW_DEFAULT_MS);
    const _: () = assert!(REAUTH_WINDOW_DEFAULT_MS < REAUTH_WINDOW_MAX_MS);
    const _: () = assert!(AUTO_LOCK_MIN_MS < AUTO_LOCK_DEFAULT_MS);
    const _: () = assert!(AUTO_LOCK_DEFAULT_MS < AUTO_LOCK_MAX_MS);
}
```

- [ ] **Step 3: Write the implementation** — the top of `schema.rs`:

```rust
//! The `Settings` value type, its bound constants, and the deterministic
//! block/record UUID derivation. Pure — no I/O, no vault handles. Lifted
//! from `desktop/src-tauri/src/{settings/parse.rs, constants.rs}` so all
//! platforms share one definition of the on-disk settings schema.

/// Block name of the app-settings block (frozen on-disk identifier).
pub const SETTINGS_BLOCK_NAME: &str = "__secretary_app_settings__";
/// Record type discriminator for the settings record (frozen).
pub const SETTINGS_RECORD_TYPE: &str = "secretary.settings.v1";

/// Field names inside the settings record (frozen wire strings).
pub const SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS: &str = "auto_lock_timeout_ms";
pub const SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS: &str = "require_password_before_edits";
pub const SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS: &str = "reauth_grace_window_ms";
pub const SETTINGS_FIELD_RETENTION_WINDOW_MS: &str = "retention_window_ms";

/// Milliseconds in one day.
pub const MS_PER_DAY: u64 = 86_400_000;

/// Trash retention window: default 90 d (== core's frozen value), floor 1 d,
/// ceiling 3650 d (10 y).
pub const RETENTION_WINDOW_DEFAULT_MS: u64 = secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS;
pub const RETENTION_WINDOW_MIN_MS: u64 = MS_PER_DAY;
pub const RETENTION_WINDOW_MAX_MS: u64 = 3650 * MS_PER_DAY;

/// Auto-lock timeout: default 10 min, floor 1 min, ceiling 24 h.
pub const AUTO_LOCK_DEFAULT_MS: u64 = 600_000;
pub const AUTO_LOCK_MIN_MS: u64 = 60_000;
pub const AUTO_LOCK_MAX_MS: u64 = 86_400_000;

/// Write re-auth grace window: default 2 min, floor 0, ceiling 1 h.
pub const REAUTH_WINDOW_DEFAULT_MS: u64 = 120_000;
pub const REAUTH_WINDOW_MIN_MS: u64 = 0;
pub const REAUTH_WINDOW_MAX_MS: u64 = 3_600_000;

/// Default for the require-password-before-edits flag.
pub const REQUIRE_PASSWORD_DEFAULT: bool = true;

/// Number of bytes taken from the front of a SHA-256 digest to form a
/// 128-bit UUID.
const UUID_BYTE_LEN: usize = 16;

/// Parsed app settings — pure value type, no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
    pub retention_window_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
            require_password_before_edits: REQUIRE_PASSWORD_DEFAULT,
            reauth_grace_window_ms: REAUTH_WINDOW_DEFAULT_MS,
            retention_window_ms: RETENTION_WINDOW_DEFAULT_MS,
        }
    }
}

/// Deterministic 16-byte UUID for a vault-internal name/record_type via
/// `SHA-256(input)[0..16]`. Two clients minting the same block independently
/// produce identical UUIDs, so the CRDT layer treats them as concurrent
/// updates of one block. Reuses core's `sha256` (no extra dependency).
pub fn deterministic_uuid_16(input: &str) -> [u8; UUID_BYTE_LEN] {
    let hash = secretary_core::crypto::hash::sha256(input.as_bytes());
    let mut out = [0u8; UUID_BYTE_LEN];
    out.copy_from_slice(&hash[0..UUID_BYTE_LEN]);
    out
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --release -p secretary-ffi-bridge settings::schema`
Expected: PASS (3 unit tests + the const-asserts compile).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/mobile-vault-settings
git add ffi/secretary-ffi-bridge/src/settings/ ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(ffi): bridge settings schema — Settings value type + constants + deterministic_uuid_16"
```

---

## Task 2: Bridge `settings/parse.rs` — pure parse / serialize / validate

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/settings/parse.rs`
- Modify: `ffi/secretary-ffi-bridge/src/settings/mod.rs` (uncomment the `parse` module + re-exports)

**Interfaces:**
- Consumes: `Settings`, all `SETTINGS_FIELD_*` names, all bound constants, from Task 1's `schema`.
- Produces:
  - `pub enum SettingsWarning { Clamped { original_ms: u64, clamped_ms: u64 }, Corrupt { detail: String } }` (derive `Debug, Clone, PartialEq, Eq`).
  - `pub enum SettingsParseError { UnknownVersion { version: String }, Corrupt { detail: String } }` (derive `Debug, Clone, PartialEq, Eq`).
  - `pub struct SettingsBoundsError { pub min: u64, pub max: u64 }` (derive `Debug, Clone, Copy, PartialEq, Eq`).
  - `pub fn parse_settings_fields(record_type: &str, fields: &[(String, String)]) -> Result<(Settings, Vec<SettingsWarning>), SettingsParseError>`
  - `pub fn serialize_settings(s: &Settings) -> Vec<(String, String, String)>` (triples: `(record_type, field_name, value_text)`).
  - `pub fn validate_save_settings(s: &Settings) -> Result<(), SettingsBoundsError>`.

- [ ] **Step 1: Write the failing test** — put this at the bottom of `parse.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::schema::*;

    #[test]
    fn serialize_round_trips_through_parse() {
        let original = Settings {
            auto_lock_timeout_ms: 900_000,
            require_password_before_edits: false,
            reauth_grace_window_ms: 30_000,
            retention_window_ms: 45 * MS_PER_DAY,
        };
        let triples = serialize_settings(&original);
        let record_type = &triples[0].0;
        let fields: Vec<(String, String)> =
            triples.iter().map(|(_, n, v)| (n.clone(), v.clone())).collect();
        let (parsed, warnings) = parse_settings_fields(record_type, &fields).expect("parse");
        assert_eq!(parsed, original);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_unknown_version_errors() {
        let err = parse_settings_fields("secretary.settings.v99", &[]).expect_err("must error");
        assert_eq!(err, SettingsParseError::UnknownVersion { version: "secretary.settings.v99".into() });
    }

    #[test]
    fn parse_below_min_clamps_with_warning() {
        let fields = vec![(SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(), "1000".to_string())];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.retention_window_ms, RETENTION_WINDOW_MIN_MS);
        assert_eq!(warnings, vec![SettingsWarning::Clamped { original_ms: 1000, clamped_ms: RETENTION_WINDOW_MIN_MS }]);
    }

    #[test]
    fn validate_rejects_out_of_range_retention() {
        let s = Settings { retention_window_ms: 999, ..Settings::default() };
        assert_eq!(
            validate_save_settings(&s),
            Err(SettingsBoundsError { min: RETENTION_WINDOW_MIN_MS, max: RETENTION_WINDOW_MAX_MS })
        );
    }

    #[test]
    fn parse_unknown_extra_field_warns_not_errors() {
        let fields = vec![("some_future_field".to_string(), "x".to_string())];
        let (_s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("must not hard-error");
        assert_eq!(warnings.len(), 1);
        assert!(matches!(warnings[0], SettingsWarning::Corrupt { .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge settings::parse`
Expected: FAIL (`parse_settings_fields` etc. not defined).

- [ ] **Step 3: Write the implementation** — the top of `parse.rs`:

```rust
//! Pure settings schema parse/serialize/validate. Every input is a `&str`,
//! every output is owned data — no filesystem, no vault handles. Lifted from
//! `desktop/src-tauri/src/settings/parse.rs`; the desktop-specific
//! `AppError`/`AppWarning` were replaced by the bridge-native types below.

use super::schema::{
    Settings, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS, REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS,
    RETENTION_WINDOW_MAX_MS, RETENTION_WINDOW_MIN_MS, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
    SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS, SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
    SETTINGS_FIELD_RETENTION_WINDOW_MS, SETTINGS_RECORD_TYPE,
};

/// A non-fatal condition surfaced while loading a settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsWarning {
    /// A numeric value out of bounds on load was clamped into range.
    Clamped { original_ms: u64, clamped_ms: u64 },
    /// A field was malformed / unknown / wrong-shaped and skipped.
    Corrupt { detail: String },
}

/// A fatal condition parsing a settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsParseError {
    /// `record_type` is not `secretary.settings.v1`.
    UnknownVersion { version: String },
    /// A known numeric field failed to parse as an integer.
    Corrupt { detail: String },
}

/// Bounds violation from `validate_save_settings` (the save path rejects
/// out-of-range rather than clamping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsBoundsError {
    pub min: u64,
    pub max: u64,
}
```

Then port the four functions from `desktop/src-tauri/src/settings/parse.rs` **lines 55–190** (`parse_settings_fields`, `clamp_ms_with_warning`, `validate_save_settings`, `serialize_settings`) verbatim, applying this substitution table:

| desktop source | bridge replacement |
|----|----|
| `AppError::SettingsUnknownVersion { version }` | `SettingsParseError::UnknownVersion { version }` |
| `AppError::SettingsCorrupt { detail }` | `SettingsParseError::Corrupt { detail }` |
| `AppWarning::SettingsClamped { original_ms, clamped_ms }` | `SettingsWarning::Clamped { original_ms, clamped_ms }` |
| `AppWarning::SettingsCorrupt { detail }` | `SettingsWarning::Corrupt { detail }` |
| return type `ParseResult` (`Result<(Settings, Vec<AppWarning>), AppError>`) | `Result<(Settings, Vec<SettingsWarning>), SettingsParseError>` |
| `-> Result<(), AppError>` (validate) | `-> Result<(), SettingsBoundsError>`; each `AppError::SettingsOutOfRange { min, max }` → `SettingsBoundsError { min, max }` |
| `use crate::constants::{…}` / `use crate::errors::{…}` | `use super::schema::{…}` (the `SETTINGS_FIELD_*`, bound constants) |

`clamp_ms_with_warning` returns `Vec<SettingsWarning>`; its body is unchanged except the warning constructor. `serialize_settings` is copied unchanged (it already returns `Vec<(String, String, String)>` and references `SETTINGS_RECORD_TYPE` + the field-name constants — now from `schema`).

- [ ] **Step 4: Uncomment the parse re-exports in `mod.rs`** (from Task 1's stub): the `pub mod parse;` line and the `pub use parse::{…}` line.

- [ ] **Step 5: Run the tests**

Run: `cargo test --release -p secretary-ffi-bridge settings::parse`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/settings/
git commit -m "feat(ffi): bridge settings parse/serialize/validate (lifted from desktop, bridge-native error types)"
```

---

## Task 3: Bridge `settings/orchestration.rs` — read_settings / write_settings

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/settings/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/settings/mod.rs` (uncomment `orchestration`)
- Create: `ffi/secretary-ffi-bridge/tests/settings.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (re-export `read_settings` / `write_settings` + selected settings items — see Step 5)

**Interfaces:**
- Consumes: `read_block`, `save_block`, `BlockInput`, `FieldInput`, `FieldInputValue`, `RecordInput` (`crate::…`), `UnlockedIdentity`, `OpenVaultManifest`, `FfiVaultError`; `Settings`, `deterministic_uuid_16`, `SETTINGS_BLOCK_NAME`, `SETTINGS_RECORD_TYPE`, `parse_settings_fields`, `serialize_settings`, `SettingsWarning` from `super`.
- Produces:
  - `pub fn read_settings(identity: &UnlockedIdentity, manifest: &OpenVaultManifest) -> Result<(Settings, Vec<SettingsWarning>), FfiVaultError>`
  - `pub fn write_settings(identity: &UnlockedIdentity, manifest: &OpenVaultManifest, settings: &Settings, device_uuid: [u8; 16], now_ms: u64) -> Result<(), FfiVaultError>`

- [ ] **Step 1: Write the failing integration test** — `ffi/secretary-ffi-bridge/tests/settings.rs`. Uses the same fixture harness as `tests/retention.rs` (`share_block_helpers::fresh_writable_vault` → `(_tmp, identity, manifest)`, plus `DEVICE_UUID`, `NOW_MS_BASE`):

```rust
//! Integration tests for the bridge settings orchestrators
//! (`read_settings` / `write_settings`) against a writable copy of
//! `golden_vault_001`. Proves: read of an absent settings block returns
//! defaults; write-then-read round-trips; and a partial update (touching
//! only retention) preserves every other field.

#[allow(dead_code)]
mod share_block_helpers;

use secretary_ffi_bridge::settings::{read_settings, write_settings, Settings};
use secretary_ffi_bridge::{MS_PER_DAY, REAUTH_WINDOW_DEFAULT_MS};

use share_block_helpers::{fresh_writable_vault, DEVICE_UUID, NOW_MS_BASE};

#[test]
fn read_absent_settings_block_returns_defaults() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let (settings, warnings) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(settings, Settings::default());
    assert!(warnings.is_empty());
}

#[test]
fn write_then_read_round_trips() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let want = Settings {
        auto_lock_timeout_ms: 900_000,
        require_password_before_edits: false,
        reauth_grace_window_ms: 30_000,
        retention_window_ms: 45 * MS_PER_DAY,
    };
    write_settings(&identity, &manifest, &want, DEVICE_UUID, NOW_MS_BASE).expect("write");
    let (got, warnings) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(got, want);
    assert!(warnings.is_empty());
}

#[test]
fn partial_update_preserves_other_fields() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    // Seed all 4 fields at non-default values (as desktop would).
    let seeded = Settings {
        auto_lock_timeout_ms: 900_000,
        require_password_before_edits: false,
        reauth_grace_window_ms: 42_000,
        retention_window_ms: 30 * MS_PER_DAY,
    };
    write_settings(&identity, &manifest, &seeded, DEVICE_UUID, NOW_MS_BASE).expect("seed");

    // Mobile-style read → mutate ONLY retention → write.
    let (mut s, _) = read_settings(&identity, &manifest).expect("read");
    s.retention_window_ms = 90 * MS_PER_DAY;
    write_settings(&identity, &manifest, &s, DEVICE_UUID, NOW_MS_BASE + 1).expect("write");

    let (got, _) = read_settings(&identity, &manifest).expect("read");
    assert_eq!(got.retention_window_ms, 90 * MS_PER_DAY, "retention updated");
    assert_eq!(got.auto_lock_timeout_ms, 900_000, "auto-lock preserved");
    assert!(!got.require_password_before_edits, "require-password preserved");
    assert_eq!(got.reauth_grace_window_ms, 42_000, "reauth grace preserved");
    // Sanity: the default is 120_000, so a preserved 42_000 proves it wasn't reset.
    assert_ne!(got.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge --test settings`
Expected: FAIL (`read_settings` / `write_settings` not found; also `secretary_ffi_bridge::settings` not re-exported yet — Step 5 fixes the re-export).

- [ ] **Step 3: Write the implementation** — `orchestration.rs`:

```rust
//! Vault I/O for the settings record: `read_settings` (find-block → read →
//! parse) and `write_settings` (find-or-create block → serialize → save).
//! Composed from the bridge's own `read_block` / `save_block`; no direct core
//! access. Warnings are returned to the (Rust) caller — desktop surfaces them;
//! the FFI wrappers drop them (mobile does not consume them).

use secretary_core::crypto::secret::SecretString;

use super::parse::{parse_settings_fields, serialize_settings, SettingsWarning};
use super::schema::{deterministic_uuid_16, Settings, SETTINGS_BLOCK_NAME, SETTINGS_RECORD_TYPE};
use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::save::{save_block, BlockInput, FieldInput, FieldInputValue, RecordInput};
use crate::vault::OpenVaultManifest;
use crate::{read_block, BlockReadOutput};

/// Look up the settings block UUID by name. Uses the on-disk `block_uuid`
/// (authoritative — a pre-spec vault that minted a random UUID keeps working).
fn find_settings_block_uuid(manifest: &OpenVaultManifest) -> Option<[u8; 16]> {
    manifest
        .block_summaries()
        .into_iter()
        .find(|bs| bs.block_name == SETTINGS_BLOCK_NAME)
        .map(|bs| bs.block_uuid)
}

/// Read the settings record from an unlocked vault. Returns
/// `(Settings::default(), [])` when no settings block exists (the happy path
/// for a vault whose owner never opened Settings). Lenient on record shape: a
/// non-text or payload-missing field is a warning, not a hard error.
pub fn read_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(Settings, Vec<SettingsWarning>), FfiVaultError> {
    let Some(block_uuid) = find_settings_block_uuid(manifest) else {
        return Ok((Settings::default(), Vec::new()));
    };

    let block: BlockReadOutput = read_block(identity, manifest, &block_uuid, false)?;

    if block.record_count() != 1 {
        return Ok((
            Settings::default(),
            vec![SettingsWarning::Corrupt {
                detail: format!("settings block has {} records (expected 1)", block.record_count()),
            }],
        ));
    }
    let record = block
        .record_at(0)
        .expect("record_count==1 ⇒ record_at(0) is Some");

    let mut field_pairs: Vec<(String, String)> = Vec::new();
    let mut shape_warnings: Vec<SettingsWarning> = Vec::new();
    for i in 0..record.field_count() {
        let field = record.field_at(i).expect("i < field_count ⇒ Some");
        if !field.is_text() {
            shape_warnings.push(SettingsWarning::Corrupt {
                detail: format!("settings field '{}' is not text-typed", field.name()),
            });
            continue;
        }
        let Some(text) = field.expose_text() else {
            shape_warnings.push(SettingsWarning::Corrupt {
                detail: "settings field text payload missing".to_string(),
            });
            continue;
        };
        field_pairs.push((field.name(), text));
    }

    // Empty record_type maps to v1 (records written before #141); any other
    // value flows to parse, which surfaces UnknownVersion for a future v2.
    let stored = record.record_type();
    let effective = if stored.is_empty() {
        SETTINGS_RECORD_TYPE.to_string()
    } else {
        stored
    };

    match parse_settings_fields(&effective, &field_pairs) {
        Ok((settings, mut parse_warnings)) => {
            let mut warnings = shape_warnings;
            warnings.append(&mut parse_warnings);
            Ok((settings, warnings))
        }
        // A malformed record must not block vault access: fall back to
        // defaults + a corruption warning (mirrors desktop's lenient load).
        Err(e) => Ok((
            Settings::default(),
            vec![SettingsWarning::Corrupt {
                detail: format!("settings record unparseable: {e:?}"),
            }],
        )),
    }
}

/// Persist the settings record. Creates the settings block on first write
/// (lazy creation; `deterministic_uuid_16(SETTINGS_BLOCK_NAME)` fallback),
/// replaces it in-place on subsequent writes (same `block_uuid`). Serializes
/// **all four** fields, so a partial update never drops a field.
///
/// Bounds are the CALLER's responsibility (uniffi/pyo3 wrappers and desktop
/// call `validate_save_settings` first); an out-of-range value here clamps on
/// next load and is not a security surface.
///
/// # Errors
/// Propagates `save_block`'s errors (`CorruptVault` on a wiped handle,
/// `FolderInvalid` on I/O, `SaveCryptoFailure` on crypto/encoding).
pub fn write_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    settings: &Settings,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let block_uuid =
        find_settings_block_uuid(manifest).unwrap_or_else(|| deterministic_uuid_16(SETTINGS_BLOCK_NAME));
    let record_uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);

    let triples = serialize_settings(settings);
    let record_type = triples[0].0.clone();
    let fields: Vec<FieldInput> = triples
        .into_iter()
        .map(|(_, name, value_text)| FieldInput {
            name,
            value: FieldInputValue::Text(SecretString::from(value_text)),
        })
        .collect();

    let input = BlockInput {
        block_uuid,
        block_name: SETTINGS_BLOCK_NAME.to_string(),
        records: vec![RecordInput {
            record_uuid,
            record_type,
            tags: Vec::new(),
            fields,
        }],
    };

    save_block(identity, manifest, input, device_uuid, now_ms)
}
```

> Verify the exact import paths compile — e.g. `read_block` / `BlockReadOutput` are re-exported at the crate root (`crate::{read_block, BlockReadOutput}`) per lib.rs; `save` items live at `crate::save::…` and are also re-exported at the root (`crate::{save_block, BlockInput, …}`). Prefer the crate-root re-exports if the submodule paths differ.

- [ ] **Step 4: Uncomment the orchestration re-exports in `mod.rs`.**

- [ ] **Step 5: Re-export from `lib.rs`.** Add after the existing `pub use save::{…};` block:

```rust
pub use settings::{
    deterministic_uuid_16, read_settings, write_settings, Settings, SettingsBoundsError,
    SettingsParseError, SettingsWarning, MS_PER_DAY, REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS,
    REAUTH_WINDOW_MIN_MS, RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MAX_MS,
    RETENTION_WINDOW_MIN_MS, SETTINGS_BLOCK_NAME, SETTINGS_RECORD_TYPE,
};
```

Also re-export `parse_settings_fields`, `serialize_settings`, `validate_save_settings`, and the remaining `SETTINGS_FIELD_*` / `AUTO_LOCK_*` / `REQUIRE_PASSWORD_DEFAULT` constants that desktop's migration (Task 6) will consume. (Keep the settings surface fully re-exported so desktop can `use secretary_ffi_bridge::…` for every item it previously defined locally.)

- [ ] **Step 6: Run the tests**

Run: `cargo test --release -p secretary-ffi-bridge --test settings`
Expected: PASS (3 integration tests).

Then the whole bridge crate:
Run: `cargo test --release -p secretary-ffi-bridge`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/settings/ ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/settings.rs
git commit -m "feat(ffi): bridge read_settings/write_settings orchestrators + field-preservation integration test"
```

---

## Task 4: uniffi projection — read_settings / write_settings + Settings dictionary

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/wrappers/settings.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`

**Interfaces:**
- Consumes: bridge `read_settings` / `write_settings` / `Settings` / `validate_save_settings` / `SettingsBoundsError`; the existing uniffi `VaultError`, `UnlockedIdentity`, `OpenVaultManifest`, `uuid_from_vec` helper.
- Produces (uniffi surface): `Settings read_settings(UnlockedIdentity, OpenVaultManifest)`; `void write_settings(UnlockedIdentity, OpenVaultManifest, Settings settings, bytes device_uuid, u64 now_ms)`; constant-reader fns `retention_window_default_ms()` / `_min_ms()` / `_max_ms()`, `reauth_window_default_ms()` / `_min_ms()` / `_max_ms()`.

- [ ] **Step 1: Add the uniffi value type** — `ffi/secretary-ffi-uniffi/src/wrappers/settings.rs`:

```rust
//! uniffi-side `Settings` value type mirroring the bridge `Settings`. Pure
//! data; the namespace fns convert to/from the bridge type. Field
//! names/shapes match `secretary.udl`'s `Settings` dictionary exactly.

/// App settings persisted in the vault (uniffi projection of the bridge
/// `Settings`). Passed by value both ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
    pub retention_window_ms: u64,
}

impl From<secretary_ffi_bridge::Settings> for Settings {
    fn from(s: secretary_ffi_bridge::Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
            retention_window_ms: s.retention_window_ms,
        }
    }
}

impl From<Settings> for secretary_ffi_bridge::Settings {
    fn from(s: Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
            retention_window_ms: s.retention_window_ms,
        }
    }
}
```

Add `pub mod settings;` to `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs`.

- [ ] **Step 2: Add the namespace fns** — in `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, near the retention fns (import `use crate::wrappers::settings::Settings;` at the top with the other wrapper imports):

```rust
/// Read the vault settings record. uniffi projection of
/// `secretary_ffi_bridge::read_settings`; load warnings are not surfaced on
/// the mobile boundary (desktop reads them from the bridge directly).
///
/// # Errors
/// - [`VaultError::CorruptVault`] — a wiped handle.
/// - [`VaultError::FolderInvalid`] / [`VaultError::SaveCryptoFailure`] — read failure.
pub fn read_settings(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
) -> Result<Settings, VaultError> {
    secretary_ffi_bridge::read_settings(&identity.0, &manifest.0)
        .map(|(s, _warnings)| Settings::from(s))
        .map_err(VaultError::from)
}

/// Persist the vault settings record. uniffi projection of
/// `secretary_ffi_bridge::write_settings`. Validates bounds and `device_uuid`
/// length at this wrapper (→ `InvalidArgument`), per the input-validation
/// convention; the bridge trusts its caller for bounds.
///
/// # Errors
/// - [`VaultError::InvalidArgument`] — out-of-range settings or wrong-length `device_uuid`.
/// - [`VaultError::CorruptVault`] / [`VaultError::FolderInvalid`] / [`VaultError::SaveCryptoFailure`].
pub fn write_settings(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    settings: Settings,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    let bridge_settings = secretary_ffi_bridge::Settings::from(settings);
    secretary_ffi_bridge::validate_save_settings(&bridge_settings)
        .map_err(|e| VaultError::InvalidArgument {
            detail: format!("settings out of range: [{}, {}]", e.min, e.max),
        })?;
    secretary_ffi_bridge::write_settings(&identity.0, &manifest.0, &bridge_settings, device_uuid, now_ms)
        .map_err(VaultError::from)
}

/// Retention-window bound constants (uniffi has no UDL `const`).
pub fn retention_window_default_ms() -> u64 { secretary_ffi_bridge::RETENTION_WINDOW_DEFAULT_MS }
pub fn retention_window_min_ms() -> u64 { secretary_ffi_bridge::RETENTION_WINDOW_MIN_MS }
pub fn retention_window_max_ms() -> u64 { secretary_ffi_bridge::RETENTION_WINDOW_MAX_MS }
/// Re-auth-grace-window bound constants.
pub fn reauth_window_default_ms() -> u64 { secretary_ffi_bridge::REAUTH_WINDOW_DEFAULT_MS }
pub fn reauth_window_min_ms() -> u64 { secretary_ffi_bridge::REAUTH_WINDOW_MIN_MS }
pub fn reauth_window_max_ms() -> u64 { secretary_ffi_bridge::REAUTH_WINDOW_MAX_MS }
```

> Confirm the exact spelling of the `VaultError::InvalidArgument` variant + its field (`detail`) and the `uuid_from_vec` helper name against the existing `namespace/mod.rs` (they are already used by `auto_purge_expired` / `move_record`); match them exactly.

- [ ] **Step 3: Add the UDL declarations** — in `ffi/secretary-ffi-uniffi/src/secretary.udl`:

Inside `namespace secretary { … }`, near `default_retention_window_ms`:

```
    /// Read the vault settings record (mobile does not consume load warnings).
    [Throws=VaultError]
    Settings read_settings(UnlockedIdentity identity, OpenVaultManifest manifest);

    /// Persist the vault settings record. `settings` fields must be in range
    /// and `device_uuid` exactly 16 bytes (otherwise [`VaultError::InvalidArgument`]).
    [Throws=VaultError]
    void write_settings(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        Settings settings,
        bytes device_uuid,
        u64 now_ms
    );

    u64 retention_window_default_ms();
    u64 retention_window_min_ms();
    u64 retention_window_max_ms();
    u64 reauth_window_default_ms();
    u64 reauth_window_min_ms();
    u64 reauth_window_max_ms();
```

Near the other dictionaries:

```
/// App settings persisted in the vault (block __secretary_app_settings__).
dictionary Settings {
    u64 auto_lock_timeout_ms;
    boolean require_password_before_edits;
    u64 reauth_grace_window_ms;
    u64 retention_window_ms;
};
```

- [ ] **Step 4: Build + generate bindings**

Run: `cargo build --release -p secretary-ffi-uniffi`
Expected: builds clean (UDL parses; namespace fns match the UDL signatures exactly — a mismatch is a build error).

- [ ] **Step 5: Lint + lean-binding guard**

Run:
```bash
cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
```
Expected: clean (no `notify`/`clap` leak; settings adds none).

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/
git commit -m "feat(ffi): project read_settings/write_settings + Settings + bound constants onto uniffi"
```

---

## Task 5: pyo3 projection + python round-trip test

**Files:**
- Create: `ffi/secretary-ffi-py/src/settings.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs`
- Create: `ffi/secretary-ffi-py/tests/test_settings.py`

**Interfaces:**
- Consumes: bridge `read_settings` / `write_settings` / `Settings` / `validate_save_settings`; pyo3 helpers `uuid_array_or_value_error`, `ffi_vault_error_to_pyerr` (`crate::errors`), `UnlockedIdentity`, `OpenVaultManifest`.
- Produces (python surface): `Settings` class (constructible + `get_all`/`set_all`), `read_settings(identity, manifest) -> Settings`, `write_settings(identity, manifest, settings, device_uuid, now_ms) -> None`.

- [ ] **Step 1: Add the pyo3 module** — `ffi/secretary-ffi-py/src/settings.rs`:

```rust
//! Settings entry points: `read_settings` (returns a `Settings`; load
//! warnings dropped — no python consumer needs them) + `write_settings`.
//! `Settings` is both input and output, so it carries a `#[new]` and
//! `set_all` (unlike the output-only retention DTOs).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// App settings persisted in the vault. Constructible from Python (for
/// `write_settings`) and returned by `read_settings`.
#[pyclass(get_all, set_all)]
#[derive(Clone)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
    pub retention_window_ms: u64,
}

#[pymethods]
impl Settings {
    #[new]
    fn new(
        auto_lock_timeout_ms: u64,
        require_password_before_edits: bool,
        reauth_grace_window_ms: u64,
        retention_window_ms: u64,
    ) -> Self {
        Self {
            auto_lock_timeout_ms,
            require_password_before_edits,
            reauth_grace_window_ms,
            retention_window_ms,
        }
    }
}

impl From<secretary_ffi_bridge::Settings> for Settings {
    fn from(s: secretary_ffi_bridge::Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
            retention_window_ms: s.retention_window_ms,
        }
    }
}

impl From<&Settings> for secretary_ffi_bridge::Settings {
    fn from(s: &Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
            retention_window_ms: s.retention_window_ms,
        }
    }
}

/// Read the vault settings record. Load warnings are not surfaced.
#[pyfunction]
pub(crate) fn read_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> PyResult<Settings> {
    secretary_ffi_bridge::read_settings(&identity.0, &manifest.0)
        .map(|(s, _warnings)| Settings::from(s))
        .map_err(ffi_vault_error_to_pyerr)
}

/// Persist the vault settings record. `device_uuid` must be 16 bytes; the
/// settings must be in range (else `ValueError`).
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn write_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    settings: &Settings,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    let bridge_settings = secretary_ffi_bridge::Settings::from(settings);
    secretary_ffi_bridge::validate_save_settings(&bridge_settings).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("settings out of range: [{}, {}]", e.min, e.max))
    })?;
    secretary_ffi_bridge::write_settings(&identity.0, &manifest.0, &bridge_settings, device_uuid, now_ms)
        .map_err(ffi_vault_error_to_pyerr)
}
```

- [ ] **Step 2: Register in `lib.rs`** — add `mod settings;`, a `use settings::{read_settings, write_settings, Settings};`, and in the module init:

```rust
    m.add_class::<Settings>()?;
    m.add_function(wrap_pyfunction!(read_settings, m)?)?;
    m.add_function(wrap_pyfunction!(write_settings, m)?)?;
```

- [ ] **Step 3: Write the python test** — `ffi/secretary-ffi-py/tests/test_settings.py`. Follow the harness of the sibling `tests/test_retention.py` (or `test_purge.py`) for opening a writable golden-vault copy + the device UUID; reuse its fixture helpers:

```python
"""Round-trip + field-preservation for the settings FFI surface."""
# (Fixture setup — writable golden-vault copy, opened identity+manifest,
#  DEVICE_UUID, NOW_MS — mirrors tests/test_retention.py; import/reuse its
#  helpers rather than duplicating.)
import secretary_ffi_py as s


def test_read_absent_returns_defaults(open_vault):
    identity, manifest = open_vault
    settings = s.read_settings(identity, manifest)
    assert settings.retention_window_ms == s.retention_window_default_ms() \
        if hasattr(s, "retention_window_default_ms") else settings.retention_window_ms > 0


def test_partial_update_preserves_other_fields(open_vault):
    identity, manifest = open_vault
    seeded = s.Settings(
        auto_lock_timeout_ms=900_000,
        require_password_before_edits=False,
        reauth_grace_window_ms=42_000,
        retention_window_ms=30 * 86_400_000,
    )
    s.write_settings(identity, manifest, seeded, DEVICE_UUID, NOW_MS)

    got = s.read_settings(identity, manifest)
    got.retention_window_ms = 90 * 86_400_000
    s.write_settings(identity, manifest, got, DEVICE_UUID, NOW_MS + 1)

    final = s.read_settings(identity, manifest)
    assert final.retention_window_ms == 90 * 86_400_000
    assert final.auto_lock_timeout_ms == 900_000
    assert final.require_password_before_edits is False
    assert final.reauth_grace_window_ms == 42_000
```

> The pyo3 crate exposes only `read_settings`/`write_settings`/`Settings` (no bound-constant fns unless you also add them to pyo3 — optional; the python test hard-codes `86_400_000`). Match the exact fixture-helper names in `tests/test_retention.py`; do not invent a fixture.

- [ ] **Step 4: Build + run the python test**

Build the extension + run (per repo convention — `uv`, never pip; and the maturin/uv cache caveat [[project_secretary_maturin_uv_cache]]):
```bash
cd ffi/secretary-ffi-py
maturin develop --release
uv run --with pytest pytest tests/test_settings.py -v
```
Expected: PASS (2 tests). If pytest sees a stale `.so`, nuke the venv + uv cache per [[project_secretary_maturin_uv_cache]].

- [ ] **Step 5: Lint**

Run: `cargo clippy --release -p secretary-ffi-py --tests -- -D warnings`
Expected: clean (watch the pyo3 0.28 `FromPyObject` deprecation — `Settings` is passed as `&Settings`, a pyclass ref, so no derive is needed; [[project_secretary_pyo3_028_fromtopyobject_deprecation]]).

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-py/
git commit -m "feat(ffi): project read_settings/write_settings + Settings onto pyo3 + python round-trip test"
```

---

## Task 6: Desktop migration — delegate to the shared bridge module

**Files:**
- Modify: `desktop/src-tauri/src/settings/parse.rs` (rewrite as adapter)
- Modify: `desktop/src-tauri/src/settings/io.rs` (`load_from_vault` / `save_to_vault` delegate)
- Modify: `desktop/src-tauri/src/constants.rs` (re-export from bridge; delete local `deterministic_uuid_16`)
- Modify: `desktop/src-tauri/Cargo.toml` (drop `sha2` if now unused)

**Interfaces:**
- Consumes: bridge `Settings`, `parse_settings_fields`, `serialize_settings`, `validate_save_settings`, `read_settings`, `write_settings`, `deterministic_uuid_16`, and all bound constants.
- Produces (unchanged desktop surface): `settings::{Settings, parse_settings_fields, serialize_settings, validate_save_settings, ParseResult, load_from_vault, save_to_vault, …}` — same names, same IPC behavior. `AppError`/`AppWarning` mapping preserved.

- [ ] **Step 1: Re-point `constants.rs`.** Replace the local `SETTINGS_*` / `RETENTION_WINDOW_*` / `REAUTH_WINDOW_*` / `AUTO_LOCK_*` / `REQUIRE_PASSWORD_DEFAULT` / `MS_PER_DAY` definitions and the `deterministic_uuid_16` fn (+ its `Sha256` import + `UUID_BYTE_LEN`) with re-exports:

```rust
pub use secretary_ffi_bridge::{
    deterministic_uuid_16, AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS, MS_PER_DAY,
    REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS, REQUIRE_PASSWORD_DEFAULT,
    RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MAX_MS, RETENTION_WINDOW_MIN_MS,
    SETTINGS_BLOCK_NAME, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS, SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS,
    SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS, SETTINGS_FIELD_RETENTION_WINDOW_MS,
    SETTINGS_RECORD_TYPE,
};
```

Keep any desktop-only constants (e.g. `AUTO_LOCK_TICK_MS`, `TWO_MINUTES_MS`, other `SETTINGS_FIELD_*` used by tests) that the bridge does not own. Preserve the const-assert tests that still reference desktop-local constants.

- [ ] **Step 2: Rewrite `settings/parse.rs` as an adapter.** Replace the `Settings` struct + `parse_settings_fields` + `serialize_settings` + `validate_save_settings` + `clamp_ms_with_warning` bodies with re-exports/wrappers over the bridge, keeping the desktop return types (`ParseResult` = `Result<(Settings, Vec<AppWarning>), AppError>`):

```rust
pub use secretary_ffi_bridge::{serialize_settings, Settings};
use secretary_ffi_bridge::{
    parse_settings_fields as bridge_parse, validate_save_settings as bridge_validate,
    SettingsBoundsError, SettingsParseError, SettingsWarning,
};
use crate::errors::{AppError, AppWarning};

pub type ParseResult = Result<(Settings, Vec<AppWarning>), AppError>;

/// Map a bridge load warning to the desktop IPC warning wire-type.
fn map_warning(w: SettingsWarning) -> AppWarning {
    match w {
        SettingsWarning::Clamped { original_ms, clamped_ms } => {
            AppWarning::SettingsClamped { original_ms, clamped_ms }
        }
        SettingsWarning::Corrupt { detail } => AppWarning::SettingsCorrupt { detail },
    }
}

/// Parse settings fields via the shared bridge, mapping bridge errors/warnings
/// to the desktop IPC wire-types.
pub fn parse_settings_fields(record_type: &str, fields: &[(String, String)]) -> ParseResult {
    match bridge_parse(record_type, fields) {
        Ok((settings, warnings)) => Ok((settings, warnings.into_iter().map(map_warning).collect())),
        Err(SettingsParseError::UnknownVersion { version }) => {
            Err(AppError::SettingsUnknownVersion { version })
        }
        Err(SettingsParseError::Corrupt { detail }) => Err(AppError::SettingsCorrupt { detail }),
    }
}

/// Validate settings for save via the shared bridge, mapping the bounds error.
pub fn validate_save_settings(s: &Settings) -> Result<(), AppError> {
    bridge_validate(s).map_err(|SettingsBoundsError { min, max }| AppError::SettingsOutOfRange { min, max })
}
```

Keep the existing `#[cfg(test)] mod tests` in desktop `parse.rs` — they now exercise the adapter (bridge logic + desktop mapping) end-to-end and are the migration's behavioral oracle. (Fix any test `use crate::constants::…` paths that moved.)

- [ ] **Step 3: Delegate `io.rs` facades.** In `load_from_vault`, replace the inline `read_block` + field-collection + `parse_settings_fields` body with a call to `secretary_ffi_bridge::read_settings(identity, manifest)` mapping the result:

```rust
pub fn load_from_vault(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(Settings, Vec<AppWarning>), AppError> {
    let (settings, warnings) =
        secretary_ffi_bridge::read_settings(identity, manifest).map_err(AppError::from)?;
    Ok((settings, warnings.into_iter().map(super::parse::map_warning_pub).collect()))
}
```

> `map_warning` is private in `parse.rs`; either expose a `pub(crate) fn map_warning_pub` or inline the 2-arm match here. Prefer a single shared `pub(crate)` mapper to keep it DRY.

In `save_to_vault`, replace the `find_settings_block_uuid` + `serialize_settings` + `BlockInput` construction + `save_block` body with `validate_save_settings` (desktop mapping) then `secretary_ffi_bridge::write_settings`:

```rust
pub fn save_to_vault(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    device_uuid: [u8; 16],
    new_settings: &Settings,
) -> Result<(), AppError> {
    validate_save_settings(new_settings)?; // desktop mapping → SettingsOutOfRange
    secretary_ffi_bridge::write_settings(identity, manifest, new_settings, device_uuid, now_ms())
        .map_err(AppError::from)
}
```

Delete the now-unused `find_settings_block_uuid` in `io.rs` and any imports (`BlockInput`, `FieldInput`, `FieldInputValue`, `RecordInput`, `read_block`, `save_block`, `SecretString`, `deterministic_uuid_16`, `SETTINGS_*`) that only that removed code used. Keep the device-UUID persistence half of `io.rs` untouched. Confirm `AppError: From<FfiVaultError>` exists (it is already used across desktop); if `read_settings`/`write_settings` surface an `FfiVaultError` variant not yet mapped, extend the existing `From` impl (no new variant is introduced — the set is identical to `read_block`/`save_block`).

- [ ] **Step 4: Drop the `sha2` desktop dependency if unused.** Search: `grep -rn "sha2\|Sha256" desktop/src-tauri/src`. If `deterministic_uuid_16` was its only user, remove `sha2 = "0.10"` from `desktop/src-tauri/Cargo.toml` and update the dependency comment. Leave `hex` (used elsewhere).

- [ ] **Step 5: Run the desktop Rust tests**

Run: `cargo test --release -p secretary-desktop` (or the desktop package name from its `Cargo.toml`; check with `grep '^name' desktop/src-tauri/Cargo.toml`).
Expected: PASS — the migrated `parse.rs` tests + `ipc_integration.rs` stay green (the migration preserved behavior).

- [ ] **Step 6: Run the full workspace + desktop frontend gates**

```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd desktop && pnpm test && pnpm run svelte-check
```
Expected: all green. `pnpm test` proves the IPC settings commands (`get_settings`/`set_settings`) still behave identically ([[project_secretary_desktop_generate_handler_writecommands_coverage]] — no new command added, so the #280 coverage test is unaffected).

- [ ] **Step 7: Commit**

```bash
git add desktop/src-tauri/
git commit -m "refactor(desktop): migrate settings to the shared secretary-ffi-bridge module (single source of truth)"
```

---

## Self-Review (completed by the plan author)

**1. Spec coverage (PR 1 scope only — Components A, B, and C of the spec):**
- Spec Component A (shared bridge module) → Tasks 1–3. ✓
- Spec Component B (FFI projection uniffi + pyo3) → Tasks 4–5. Refinement: `SettingsWarning` is **not** projected on the FFI (mobile does not consume warnings; desktop reads them from the bridge directly), so the FFI surfaces `read_settings → Settings`. This is a simplification of the spec's "project the Settings dictionary and SettingsWarning enum"; the spec's Component B is updated to match.
- Spec Component C (desktop migration) → Task 6. ✓
- Spec Components D/E (mobile adapters, Settings screen, gate retarget, Trash integration) → **not in this PR** (PRs 2 & 3). The retarget-after-save security ordering and field-preservation-at-VM tests belong there; the bridge field-preservation guarantee they rely on is proven here (Task 3).
- Acceptance criteria 1, 2, 5, 6, 7 (spec) are satisfied by this PR; criteria 3, 4 are mobile (PRs 2–3).

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N". The parse-lift (Task 2 Step 3) is a concrete verbatim copy of named line ranges + a full substitution table, not a placeholder. The python fixture (Task 5 Step 3) explicitly defers to the existing `tests/test_retention.py` helpers rather than inventing them — a real instruction, but the implementer must read that file for the exact fixture names.

**3. Type consistency:** `Settings` fields identical across bridge/uniffi/pyo3/desktop (`auto_lock_timeout_ms: u64`, `require_password_before_edits: bool`, `reauth_grace_window_ms: u64`, `retention_window_ms: u64`). `read_settings`/`write_settings` signatures consistent (bridge returns `(Settings, Vec<SettingsWarning>)`; FFI wrappers return `Settings` / `()`). `SettingsBoundsError { min, max }` used identically in all three validation call sites. `deterministic_uuid_16` signature identical bridge↔desktop.

## Open items to confirm during implementation
- The desktop crate package name for `cargo test -p <name>` (Task 6 Step 5) — read it from `desktop/src-tauri/Cargo.toml`.
- The exact `VaultError::InvalidArgument` field name + `uuid_from_vec` helper in uniffi (Task 4) — match the existing `auto_purge_expired`/`move_record` call sites.
- The exact `tests/test_retention.py` fixture helper names (Task 5) — reuse, don't reinvent.
- Whether `AppError: From<FfiVaultError>` already covers every variant `read_settings`/`write_settings` can surface (Task 6 Step 3) — it should, since they propagate only `read_block`/`save_block` errors.
