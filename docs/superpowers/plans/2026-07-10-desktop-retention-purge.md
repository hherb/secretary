# Desktop Retention + Per-Block Purge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire three destructive trash operations into the Tauri desktop client over the merged #406 retention FFI — retention preview, retention commit ("Run retention now"), and per-block purge ("Delete forever") — with a configurable retention-window vault setting.

**Architecture:** The desktop backend depends on `secretary-ffi-bridge` directly (in-process, no serialization boundary), so new Tauri commands call `expired_trash_entries` / `auto_purge_expired` / `purge_block` natively and project bridge types to camelCase wire DTOs. The retention window is read from vault settings. The frontend adds a two-step retention preview dialog and a per-row "Delete forever" confirm, both gated by the existing write re-auth.

**Tech Stack:** Rust (Tauri 2, `secretary-ffi-bridge`), Svelte 5 (runes) + TypeScript, Vitest, `cargo test`.

## Global Constraints

- **FFI-consuming UI slice only** — no `core/` / crypto / on-disk-format change; no new `FfiVaultError` variant expected; `#![forbid(unsafe_code)]` intact.
- **Desktop uses pnpm**, not npm (`cd desktop && pnpm test`). Type-check is `pnpm exec svelte-check`, not bare `tsc`.
- **No magic numbers** — every bound/default is a named constant in `desktop/src-tauri/src/constants.rs`, mirrored in `desktop/src/lib/constants.ts` in lockstep (the IPC does not carry constants).
- **Error mapping stays exhaustive** — no `_` catch-all in any `FfiVaultError → AppError` match (per the #40 convention).
- **Every registered `generate_handler!` command must be classified** in `writeCommands.ts` or the #280 `writeGateCoverage` test fails.
- **Writes go through `authorizeWrite(...)`** before the IPC call, catching `ReauthCancelled`, exactly like `confirmTrash`.
- **Retention window bounds:** min 1 day, max 3650 days (10 years), default 90 days (= bridge `DEFAULT_RETENTION_WINDOW_MS` = `7_776_000_000` ms).
- **Gates before PR (all green):** `cargo test --release --workspace` · `cargo clippy --release --workspace --tests -- -D warnings` · `cargo fmt --all -- --check` · `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` · `cd desktop && pnpm test && pnpm exec svelte-check`.
- **Worktree:** all work in `.worktrees/desktop-retention/` on branch `feature/desktop-retention`. Use absolute paths or chain `cd` in one Bash call (shell state does not persist).

## File Structure

**Backend (`desktop/src-tauri/src/`):**
- `constants.rs` — *modify*: add `MS_PER_DAY`, `RETENTION_WINDOW_{DEFAULT,MIN,MAX}_MS`, `SETTINGS_FIELD_RETENTION_WINDOW_MS`.
- `settings/parse.rs` — *modify*: `Settings.retention_window_ms` field + Default + parse arm + clamp + `validate_save_settings` bound + `serialize_settings` triple.
- `dtos/manifest.rs` — *modify*: `SettingsDto` / `SettingsInput` field + `From` impls.
- `dtos/retention.rs` — *create*: `ExpiredEntryDto`, `RetentionPreviewDto`, `RetentionReportDto`, `PurgeReportDto` + projections.
- `dtos/mod.rs` — *modify*: `pub mod retention;` + re-exports.
- `commands/retention.rs` — *create*: `preview_retention`, `run_retention`, `purge_block` (+ `*_impl`).
- `commands/mod.rs` — *modify*: `pub mod retention;`.
- `main.rs` — *modify*: three `generate_handler!` entries.

**Frontend (`desktop/src/`):**
- `lib/constants.ts` — *modify*: retention constants mirror.
- `lib/retention.ts` — *create*: pure helpers.
- `lib/ipc.ts` — *modify*: 3 wrappers + `SettingsDto.retentionWindowMs`.
- `lib/writeCommands.ts` — *modify*: classify the three commands.
- `components/delete/RetentionDialog.svelte` — *create*: two-step preview dialog.
- `components/delete/TrashView.svelte` — *modify*: "Run retention now" button + per-row purge wiring.
- `components/delete/TrashedBlockRow.svelte` — *modify*: `onPurge` prop + "Delete forever" button.
- `components/SettingsDialog.svelte` — *modify*: retention window (days) control.

---

### Task 1: Retention window setting — backend value layer

**Files:**
- Modify: `desktop/src-tauri/src/constants.rs`
- Modify: `desktop/src-tauri/src/settings/parse.rs`
- Test: `desktop/src-tauri/src/settings/parse.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::DEFAULT_RETENTION_WINDOW_MS` (const, `u64`, 90 days).
- Produces: `constants::{MS_PER_DAY, RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MIN_MS, RETENTION_WINDOW_MAX_MS, SETTINGS_FIELD_RETENTION_WINDOW_MS}`; `Settings.retention_window_ms: u64`.

- [ ] **Step 1: Add constants**

In `desktop/src-tauri/src/constants.rs`, after the write-reauth block, add:

```rust
// =============================================================================
// Retention window (auto-purge of trashed blocks past this age)
// =============================================================================

/// Milliseconds per day. Used to convert the user-visible retention window
/// (days) to/from the wire-format ms.
pub const MS_PER_DAY: u64 = 86_400_000;

/// Default retention window, in milliseconds. Re-exported from the bridge's
/// `DEFAULT_RETENTION_WINDOW_MS` (90 days) so the desktop default can never
/// drift from the FFI default.
pub const RETENTION_WINDOW_DEFAULT_MS: u64 = secretary_ffi_bridge::DEFAULT_RETENTION_WINDOW_MS;

/// Lower bound for `retention_window_ms`. One day — a 0-day window would purge
/// everything on the next run; the floor makes that a deliberate impossibility
/// through the settings surface.
pub const RETENTION_WINDOW_MIN_MS: u64 = MS_PER_DAY;

/// Upper bound for `retention_window_ms`. 3650 days (10 years) — a sanity
/// ceiling; beyond this the window is effectively "never purge".
pub const RETENTION_WINDOW_MAX_MS: u64 = 3650 * MS_PER_DAY;

/// Settings field name: the retention window in milliseconds.
pub const SETTINGS_FIELD_RETENTION_WINDOW_MS: &str = "retention_window_ms";
```

Add compile-time ordering guards alongside the existing ones (in the `#[cfg(test)] mod tests` const-assert block):

```rust
const _: () = assert!(RETENTION_WINDOW_MIN_MS < RETENTION_WINDOW_DEFAULT_MS);
const _: () = assert!(RETENTION_WINDOW_DEFAULT_MS < RETENTION_WINDOW_MAX_MS);
```

- [ ] **Step 2: Write the failing tests** in `settings/parse.rs` tests module:

```rust
#[test]
fn default_includes_retention_window() {
    assert_eq!(
        Settings::default().retention_window_ms,
        crate::constants::RETENTION_WINDOW_DEFAULT_MS
    );
}

#[test]
fn parse_retention_window_field() {
    let fields = vec![(
        SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(),
        (30 * crate::constants::MS_PER_DAY).to_string(),
    )];
    let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
    assert_eq!(s.retention_window_ms, 30 * crate::constants::MS_PER_DAY);
    assert!(warnings.is_empty());
}

#[test]
fn parse_retention_window_clamps_below_min() {
    let fields = vec![(SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(), "1000".to_string())];
    let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
    assert_eq!(s.retention_window_ms, RETENTION_WINDOW_MIN_MS);
    assert_eq!(warnings.len(), 1);
}

#[test]
fn validate_save_rejects_out_of_range_retention() {
    let s = Settings { retention_window_ms: 999, ..Settings::default() };
    assert!(matches!(
        validate_save_settings(&s),
        Err(AppError::SettingsOutOfRange { .. })
    ));
}

#[test]
fn serialize_round_trips_retention_window() {
    let s = Settings { retention_window_ms: 45 * crate::constants::MS_PER_DAY, ..Settings::default() };
    let triples = serialize_settings(&s);
    assert!(triples.iter().any(|(_, name, val)|
        name == SETTINGS_FIELD_RETENTION_WINDOW_MS
            && val == &(45 * crate::constants::MS_PER_DAY).to_string()));
}
```

Add the needed imports to the tests module `use` (`RETENTION_WINDOW_MIN_MS`, `SETTINGS_FIELD_RETENTION_WINDOW_MS`).

- [ ] **Step 3: Run tests — expect FAIL** (`retention_window_ms` field missing):

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention/desktop/src-tauri && cargo test --release settings::parse 2>&1 | tail -20
```
Expected: compile error / FAIL (no field `retention_window_ms`).

- [ ] **Step 4: Implement**

In `settings/parse.rs`: add the import `RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MIN_MS, RETENTION_WINDOW_MAX_MS, SETTINGS_FIELD_RETENTION_WINDOW_MS` to the top-of-file `use crate::constants::{...}`; add the field:

```rust
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
    pub retention_window_ms: u64,
}
```

Default:

```rust
retention_window_ms: RETENTION_WINDOW_DEFAULT_MS,
```

Parse arm (in `parse_settings_fields`, alongside the others):

```rust
SETTINGS_FIELD_RETENTION_WINDOW_MS => {
    let raw: u64 = value.parse().map_err(|e| AppError::SettingsCorrupt {
        detail: format!("retention_window_ms parse failure: {e}"),
    })?;
    let (v, mut w) =
        clamp_ms_with_warning(raw, RETENTION_WINDOW_MIN_MS, RETENTION_WINDOW_MAX_MS);
    settings.retention_window_ms = v;
    warnings.append(&mut w);
}
```

`validate_save_settings` bound:

```rust
if !(RETENTION_WINDOW_MIN_MS..=RETENTION_WINDOW_MAX_MS).contains(&s.retention_window_ms) {
    return Err(AppError::SettingsOutOfRange {
        min: RETENTION_WINDOW_MIN_MS,
        max: RETENTION_WINDOW_MAX_MS,
    });
}
```

`serialize_settings` triple (append to the `vec!`):

```rust
(
    SETTINGS_RECORD_TYPE.to_string(),
    SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(),
    s.retention_window_ms.to_string(),
),
```

Fix any other literal `Settings { ... }` constructions in the file's tests to include `retention_window_ms` (or use `..Settings::default()`).

- [ ] **Step 5: Run tests — expect PASS**

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention/desktop/src-tauri && cargo test --release settings::parse 2>&1 | tail -20
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-retention
git add desktop/src-tauri/src/constants.rs desktop/src-tauri/src/settings/parse.rs
git commit -m "feat(desktop): retention_window_ms vault setting + bounds"
```

---

### Task 2: Settings DTO field (wire projection)

**Files:**
- Modify: `desktop/src-tauri/src/dtos/manifest.rs`
- Test: `desktop/src-tauri/src/dtos/manifest.rs` (tests module)

**Interfaces:**
- Consumes: `Settings.retention_window_ms` (Task 1).
- Produces: `SettingsDto.retention_window_ms` / `SettingsInput.retention_window_ms` (camelCase `retentionWindowMs` on the wire).

- [ ] **Step 1: Write the failing test** in `dtos/manifest.rs` tests:

```rust
#[test]
fn settings_dto_includes_retention_window_camel_case() {
    let dto = SettingsDto::from(&Settings {
        retention_window_ms: 90 * crate::constants::MS_PER_DAY,
        ..Settings::default()
    });
    let v = to_json(&dto);
    assert_eq!(v["retentionWindowMs"], 90 * crate::constants::MS_PER_DAY);
    assert!(v.get("retention_window_ms").is_none());
}
```
(Use the file's existing `to_json` helper; if the existing `SettingsDto::from(&Settings { ... })` test constructs a literal `Settings`, add the new field there too.)

- [ ] **Step 2: Run — expect FAIL** (`cargo test --release dtos::manifest`).

- [ ] **Step 3: Implement** — add `pub retention_window_ms: u64,` to both `SettingsDto` and `SettingsInput`, and the field to both `From` impls:

```rust
// SettingsDto::from(&Settings)
retention_window_ms: s.retention_window_ms,
// Settings::from(&SettingsInput)
retention_window_ms: s.retention_window_ms,
```

- [ ] **Step 4: Run — expect PASS** (`cargo test --release dtos::manifest`).

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/dtos/manifest.rs
git commit -m "feat(desktop): project retention_window_ms through settings DTOs"
```

---

### Task 3: Retention wire DTOs

**Files:**
- Create: `desktop/src-tauri/src/dtos/retention.rs`
- Modify: `desktop/src-tauri/src/dtos/mod.rs`
- Test: `desktop/src-tauri/src/dtos/retention.rs` (tests module)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{ExpiredEntry, RetentionPurgeReport}` and `secretary_ffi_bridge::purge::PurgeReport` (verify the exact re-export path; it may be `secretary_ffi_bridge::PurgeReport`).
  - `ExpiredEntry { block_uuid: [u8;16], tombstoned_at_ms: u64, age_ms: u64 }`
  - `RetentionPurgeReport { purged_count, shared_count, owner_only_count, unknown_count, files_removed, files_failed: u32, window_ms: u64 }`
  - `PurgeReport { block_uuid: [u8;16], was_shared: Option<bool>, recipient_count: Option<u16>, files_removed: u32 }`
- Produces: `dtos::{ExpiredEntryDto, RetentionPreviewDto, RetentionReportDto, PurgeReportDto}` + `From` projections; `RetentionPreviewDto::from_entries(Vec<ExpiredEntry>, window_ms)`.

- [ ] **Step 1: Write the failing tests** in a new `dtos/retention.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SAMPLE_UUID_HEX: &str = "00112233445566778899aabbccddeeff";
    const SAMPLE_UUID_BYTES: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];

    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("serialize")).expect("parse")
    }

    #[test]
    fn expired_entry_dto_hex_and_camel_case() {
        let dto = ExpiredEntryDto::from(&secretary_ffi_bridge::ExpiredEntry {
            block_uuid: SAMPLE_UUID_BYTES,
            tombstoned_at_ms: 1_700_000_000_000,
            age_ms: 99,
        });
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["tombstonedAtMs"], 1_700_000_000_000_u64);
        assert_eq!(v["ageMs"], 99);
        assert!(v.get("block_uuid").is_none());
    }

    #[test]
    fn retention_preview_dto_carries_window_and_entries() {
        let preview = RetentionPreviewDto::from_entries(
            vec![secretary_ffi_bridge::ExpiredEntry {
                block_uuid: SAMPLE_UUID_BYTES, tombstoned_at_ms: 1, age_ms: 2,
            }],
            7_776_000_000,
        );
        let v = to_json(&preview);
        assert_eq!(v["windowMs"], 7_776_000_000_u64);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn retention_report_dto_camel_case() {
        let dto = RetentionReportDto::from(&secretary_ffi_bridge::RetentionPurgeReport {
            purged_count: 3, shared_count: 1, owner_only_count: 2,
            unknown_count: 0, files_removed: 3, files_failed: 0, window_ms: 7_776_000_000,
        });
        let v = to_json(&dto);
        assert_eq!(v["purgedCount"], 3);
        assert_eq!(v["filesFailed"], 0);
        assert_eq!(v["windowMs"], 7_776_000_000_u64);
    }

    #[test]
    fn purge_report_dto_camel_case() {
        let dto = PurgeReportDto::from(&secretary_ffi_bridge::PurgeReport {
            block_uuid: SAMPLE_UUID_BYTES, was_shared: Some(true),
            recipient_count: Some(2), files_removed: 1,
        });
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["wasShared"], true);
        assert_eq!(v["recipientCount"], 2);
        assert_eq!(v["filesRemoved"], 1);
    }
}
```

- [ ] **Step 2: Run — expect FAIL** (module does not exist):

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention/desktop/src-tauri && cargo test --release dtos::retention 2>&1 | tail -20
```

- [ ] **Step 3: Implement** the module body (above the tests):

```rust
//! Retention/purge read DTOs. Project the bridge's retention + purge report
//! types onto camelCase wire shapes: `block_uuid: [u8;16]` is hex-encoded
//! (parity with `TrashedBlockDto`); `u32` counts serialize as JSON numbers.
//! None of these fields is secret material.

use secretary_ffi_bridge::{ExpiredEntry, PurgeReport, RetentionPurgeReport};

/// One trashed block that is past the retention window (preview only).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiredEntryDto {
    pub block_uuid_hex: String,
    pub tombstoned_at_ms: u64,
    pub age_ms: u64,
}

impl From<&ExpiredEntry> for ExpiredEntryDto {
    fn from(e: &ExpiredEntry) -> Self {
        Self {
            block_uuid_hex: hex::encode(e.block_uuid),
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        }
    }
}

/// Preview payload: the expired entries plus the window they were computed
/// against (so the UI shows "> N days" consistently with the commit).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPreviewDto {
    pub entries: Vec<ExpiredEntryDto>,
    pub window_ms: u64,
}

impl RetentionPreviewDto {
    pub fn from_entries(entries: Vec<ExpiredEntry>, window_ms: u64) -> Self {
        Self {
            entries: entries.iter().map(ExpiredEntryDto::from).collect(),
            window_ms,
        }
    }
}

/// Report from a committed retention purge.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionReportDto {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
    pub window_ms: u64,
}

impl From<&RetentionPurgeReport> for RetentionReportDto {
    fn from(r: &RetentionPurgeReport) -> Self {
        Self {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
            window_ms: r.window_ms,
        }
    }
}

/// Report from a single per-block purge.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeReportDto {
    pub block_uuid_hex: String,
    pub was_shared: Option<bool>,
    pub recipient_count: Option<u16>,
    pub files_removed: u32,
}

impl From<&PurgeReport> for PurgeReportDto {
    fn from(r: &PurgeReport) -> Self {
        Self {
            block_uuid_hex: hex::encode(r.block_uuid),
            was_shared: r.was_shared,
            recipient_count: r.recipient_count,
            files_removed: r.files_removed,
        }
    }
}
```

In `dtos/mod.rs` add `pub mod retention;` and extend the `pub use` line, e.g.:

```rust
pub use retention::{ExpiredEntryDto, PurgeReportDto, RetentionPreviewDto, RetentionReportDto};
```

**Note:** verify the exact bridge import paths (`use secretary_ffi_bridge::{ExpiredEntry, PurgeReport, RetentionPurgeReport};`). If `PurgeReport` is only re-exported under a submodule (e.g. `secretary_ffi_bridge::purge::PurgeReport`), use that path. `hex` is already a dependency (used by `delete.rs`).

- [ ] **Step 4: Run — expect PASS** (`cargo test --release dtos::retention`).

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/dtos/retention.rs desktop/src-tauri/src/dtos/mod.rs
git commit -m "feat(desktop): retention + purge wire DTOs"
```

---

### Task 4: Retention commands + handler wiring

**Files:**
- Create: `desktop/src-tauri/src/commands/retention.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs`
- Modify: `desktop/src-tauri/src/main.rs`
- Test: `desktop/src-tauri/src/commands/retention.rs` (tests module)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{expired_trash_entries, auto_purge_expired, purge_block}`; `dtos::{RetentionPreviewDto, RetentionReportDto, PurgeReportDto}`; `commands::shared::{lock_session, parse_uuid_16}`; `auto_lock::now_ms`; `errors::{map_ffi_error, AppError}`; `session::VaultSession`.
- Produces: Tauri commands `preview_retention`, `run_retention`, `purge_block` (registered in `generate_handler!`).

- [ ] **Step 1: Verify `purge_block`'s error set maps cleanly.** Read `ffi/secretary-ffi-bridge/src/purge/orchestration.rs` `purge_block`; confirm every `FfiVaultError` it can return already has a non-`_` arm in `desktop/src-tauri/src/errors/mapping.rs::map_ffi_error`. Expected returns: `CorruptVault`, `FolderInvalid`, `SaveCryptoFailure` (and idempotent re-purge returns `Ok`). If a genuinely unmapped variant exists, STOP and surface it — a new `AppError` variant + `errors.ts` union entry would be a scoped addition (update the design's "no new variant" assumption and the frontend union). Do not add a `_` catch-all.

- [ ] **Step 2: Write the failing tests** in `commands/retention.rs`. Follow the harness in `commands/delete.rs` tests (they build a `Mutex<VaultSession>` over a temp golden-vault copy — reuse that exact setup helper; per [[feedback_smoke_test_temp_copy_golden_vault]] always operate on a `cp -R` copy, never the tracked fixture). Minimum cases:

```rust
#[test]
fn preview_retention_locked_session_errors() {
    let state = locked_session(); // mirror delete.rs's locked-session helper
    assert!(matches!(preview_retention_impl(&state), Err(AppError::NotUnlocked)));
}

#[test]
fn preview_retention_unlocked_returns_preview() {
    let state = unlocked_temp_vault(); // mirror delete.rs's unlocked helper
    let preview = preview_retention_impl(&state).expect("preview");
    // A freshly-minted vault has no expired trash; entries empty, window is the setting.
    assert!(preview.entries.is_empty());
    assert_eq!(preview.window_ms, crate::constants::RETENTION_WINDOW_DEFAULT_MS);
}

#[test]
fn run_retention_unlocked_ok() {
    let state = unlocked_temp_vault();
    let report = run_retention_impl(&state).expect("run");
    assert_eq!(report.purged_count, 0); // nothing expired in a fresh vault
    assert_eq!(report.window_ms, crate::constants::RETENTION_WINDOW_DEFAULT_MS);
}

#[test]
fn purge_block_bad_uuid_errors() {
    let state = unlocked_temp_vault();
    assert!(purge_block_impl(&state, "not-hex").is_err());
}
```

(For a non-empty retention/purge assertion, prefer to trash a block first via `bridge_trash_block` in the test setup, then assert `purge_block_impl` returns `files_removed`/report fields — mirror how `delete.rs` tests exercise trash→restore.)

- [ ] **Step 3: Run — expect FAIL** (module absent):

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention/desktop/src-tauri && cargo test --release commands::retention 2>&1 | tail -20
```

- [ ] **Step 4: Implement** `commands/retention.rs`:

```rust
//! `preview_retention` / `run_retention` / `purge_block` commands. Retention
//! reads its window from the vault settings (default 90 days); the commits
//! follow the `delete::trash_block` shape — snapshot under one lock, one
//! bridge call, typed error via `map_ffi_error`. No new `FfiVaultError`
//! variant: retention/purge surface only `CorruptVault` / `FolderInvalid` /
//! `SaveCryptoFailure`, all already mapped.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::{
    auto_purge_expired as bridge_auto_purge, expired_trash_entries as bridge_expired_entries,
    purge_block as bridge_purge_block,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::{lock_session, parse_uuid_16};
use crate::dtos::{PurgeReportDto, RetentionPreviewDto, RetentionReportDto};
use crate::errors::{map_ffi_error, AppError};
use crate::session::VaultSession;

#[tauri::command]
pub async fn preview_retention(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<RetentionPreviewDto, AppError> {
    preview_retention_impl(state.inner())
}

#[tauri::command]
pub async fn run_retention(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<RetentionReportDto, AppError> {
    run_retention_impl(state.inner())
}

#[tauri::command]
pub async fn purge_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<PurgeReportDto, AppError> {
    purge_block_impl(state.inner(), &block_uuid_hex)
}

/// Preview which trashed blocks are past the configured window. Read-only,
/// infallible at the bridge; the `Result` carries only the locked / poisoned
/// session paths.
pub fn preview_retention_impl(
    state: &Mutex<VaultSession>,
) -> Result<RetentionPreviewDto, AppError> {
    let session = lock_session(state)?;
    let window_ms = session.current_settings().retention_window_ms;
    session.with_unlocked(|u| {
        let entries = bridge_expired_entries(&u.manifest, window_ms, now_ms());
        Ok(RetentionPreviewDto::from_entries(entries, window_ms))
    })
}

/// Commit a retention purge: permanently delete every trashed block past the
/// configured window.
pub fn run_retention_impl(state: &Mutex<VaultSession>) -> Result<RetentionReportDto, AppError> {
    let session = lock_session(state)?;
    let window_ms = session.current_settings().retention_window_ms;
    session.with_unlocked(|u| {
        let report = bridge_auto_purge(
            &u.identity,
            &u.manifest,
            window_ms,
            now_ms(),
            u.device_uuid,
        )
        .map_err(map_ffi_error)?;
        Ok(RetentionReportDto::from(&report))
    })
}

/// Permanently delete one trashed block ("delete forever").
pub fn purge_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
) -> Result<PurgeReportDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let report = bridge_purge_block(
            &u.identity,
            &u.manifest,
            block_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_ffi_error)?;
        Ok(PurgeReportDto::from(&report))
    })
}
```

**Verify** against `delete.rs`: `with_unlocked` must return `Result<T, AppError>` and `preview_retention_impl` must produce `AppError::NotUnlocked` on a locked session (confirm whether `with_unlocked` already yields `NotUnlocked` when locked — `delete.rs` relies on that; if `preview` must reject on locked, `with_unlocked` is the right gate). Adjust the `window_ms` read to occur inside/outside `with_unlocked` per what `current_settings()` requires (it returns defaults while locked — reading it before `with_unlocked` is fine).

In `commands/mod.rs`: add `pub mod retention;`.

In `main.rs` `generate_handler!`: add `retention::preview_retention, retention::run_retention, retention::purge_block,` (append; keep the existing entries untouched to minimize diff).

- [ ] **Step 5: Run — expect PASS** (`cargo test --release commands::retention`), then the whole backend:

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention && cargo test --release --workspace 2>&1 | tail -15
```

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/commands/retention.rs desktop/src-tauri/src/commands/mod.rs desktop/src-tauri/src/main.rs
git commit -m "feat(desktop): preview_retention / run_retention / purge_block commands"
```

---

### Task 5: Frontend constants + pure helpers

**Files:**
- Modify: `desktop/src/lib/constants.ts`
- Create: `desktop/src/lib/retention.ts`
- Test: `desktop/tests/retention.test.ts`

**Interfaces:**
- Produces: `constants.{MS_PER_DAY, RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MIN_MS, RETENTION_WINDOW_MAX_MS}`; `retention.{msToDays, daysToMs, oldestAgeMs, retentionSummary, formatAgeDays}`.

- [ ] **Step 1: Add constants** to `desktop/src/lib/constants.ts` (mirror Task 1 values exactly — drift → confusing `settings_out_of_range`):

```ts
/** Milliseconds per day. Mirror of `constants.rs::MS_PER_DAY`. */
export const MS_PER_DAY = 86_400_000;

/** Default retention window (90 days). Mirror of
 *  `constants.rs::RETENTION_WINDOW_DEFAULT_MS` (= bridge default). */
export const RETENTION_WINDOW_DEFAULT_MS = 7_776_000_000;

/** Lower bound (1 day). Mirror of `constants.rs::RETENTION_WINDOW_MIN_MS`. */
export const RETENTION_WINDOW_MIN_MS = 86_400_000;

/** Upper bound (3650 days / 10 years). Mirror of
 *  `constants.rs::RETENTION_WINDOW_MAX_MS`. */
export const RETENTION_WINDOW_MAX_MS = 315_360_000_000;
```

- [ ] **Step 2: Write failing tests** `desktop/tests/retention.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { msToDays, daysToMs, oldestAgeMs, retentionSummary } from '../src/lib/retention';
import { MS_PER_DAY } from '../src/lib/constants';
import type { ExpiredEntryDto } from '../src/lib/ipc';

const entry = (ageMs: number): ExpiredEntryDto => ({
  blockUuidHex: 'aa', tombstonedAtMs: 0, ageMs
});

describe('retention helpers', () => {
  it('converts days <-> ms round trip', () => {
    expect(daysToMs(90)).toBe(90 * MS_PER_DAY);
    expect(msToDays(90 * MS_PER_DAY)).toBe(90);
  });

  it('oldestAgeMs returns the max age, 0 for empty', () => {
    expect(oldestAgeMs([])).toBe(0);
    expect(oldestAgeMs([entry(5), entry(99), entry(2)])).toBe(99);
  });

  it('summary reports count + window days', () => {
    const s = retentionSummary([entry(10 * MS_PER_DAY)], 90 * MS_PER_DAY);
    expect(s).toContain('1');
    expect(s).toContain('90');
  });

  it('summary handles the empty case', () => {
    expect(retentionSummary([], 90 * MS_PER_DAY).toLowerCase()).toContain('no');
  });
});
```

- [ ] **Step 3: Run — expect FAIL** (`cd desktop && pnpm test retention` — module missing).

- [ ] **Step 4: Implement** `desktop/src/lib/retention.ts`:

```ts
// Pure retention helpers — no IPC, no DOM. Convert between the user-visible
// window unit (days) and wire ms, and format the preview summary. Unit-tested
// in isolation (retention.test.ts).

import { MS_PER_DAY } from './constants';
import type { ExpiredEntryDto } from './ipc';

/** Whole days for a ms value, rounded to nearest (settings display). */
export function msToDays(ms: number): number {
  return Math.round(ms / MS_PER_DAY);
}

/** Days → ms (settings save). */
export function daysToMs(days: number): number {
  return days * MS_PER_DAY;
}

/** Largest `ageMs` among entries, or 0 when empty. */
export function oldestAgeMs(entries: ExpiredEntryDto[]): number {
  return entries.reduce((max, e) => (e.ageMs > max ? e.ageMs : max), 0);
}

/** Human summary line for the retention preview dialog. */
export function retentionSummary(entries: ExpiredEntryDto[], windowMs: number): string {
  const days = msToDays(windowMs);
  if (entries.length === 0) {
    return `No trashed items are older than ${days} days.`;
  }
  const n = entries.length;
  const noun = n === 1 ? 'item' : 'items';
  const oldestDays = msToDays(oldestAgeMs(entries));
  return `${n} ${noun} trashed more than ${days} days ago will be permanently ` +
    `deleted (oldest: ${oldestDays} days).`;
}
```

- [ ] **Step 5: Run — expect PASS** (`cd desktop && pnpm test retention`).

- [ ] **Step 6: Commit**

```bash
git add desktop/src/lib/constants.ts desktop/src/lib/retention.ts desktop/tests/retention.test.ts
git commit -m "feat(desktop): retention constants + pure helpers"
```

---

### Task 6: IPC wrappers + write classification + TS settings field

**Files:**
- Modify: `desktop/src/lib/ipc.ts`
- Modify: `desktop/src/lib/writeCommands.ts`
- Test: (coverage tests already present: `writeGateCoverage.test.ts`, `writeCommands.test.ts`)

**Interfaces:**
- Consumes: the three commands from Task 4.
- Produces: `ipc.{previewRetention, runRetention, purgeBlock}` and `ExpiredEntryDto` / `RetentionPreviewDto` / `RetentionReportDto` / `PurgeReportDto` TS interfaces; `SettingsDto.retentionWindowMs`.

- [ ] **Step 1: Add the TS types + wrappers** to `desktop/src/lib/ipc.ts`:

```ts
export interface ExpiredEntryDto {
  blockUuidHex: string;
  tombstonedAtMs: number;
  ageMs: number;
}

export interface RetentionPreviewDto {
  entries: ExpiredEntryDto[];
  windowMs: number;
}

export interface RetentionReportDto {
  purgedCount: number;
  sharedCount: number;
  ownerOnlyCount: number;
  unknownCount: number;
  filesRemoved: number;
  filesFailed: number;
  windowMs: number;
}

export interface PurgeReportDto {
  blockUuidHex: string;
  wasShared: boolean | null;
  recipientCount: number | null;
  filesRemoved: number;
}

export async function previewRetention(): Promise<RetentionPreviewDto> {
  return call<RetentionPreviewDto>('preview_retention', {});
}

export async function runRetention(): Promise<RetentionReportDto> {
  return call<RetentionReportDto>('run_retention', {});
}

export async function purgeBlock(blockUuidHex: string): Promise<PurgeReportDto> {
  return call<PurgeReportDto>('purge_block', { blockUuidHex });
}
```

Add `retentionWindowMs: number;` to the `SettingsDto` interface.

- [ ] **Step 2: Classify the commands** in `desktop/src/lib/writeCommands.ts` `COMMAND_CLASSIFICATION` (match the existing entry shape — inspect a gated write like `trash_block` and a read like `list_trashed_blocks` for the exact object literal):

```ts
preview_retention: { kind: 'read' },
run_retention: { kind: 'write', disposition: 'gated', wrapper: 'runRetention' },
purge_block: { kind: 'write', disposition: 'gated', wrapper: 'purgeBlock' },
```

(Use the exact field names the file already uses; the wrapper strings must equal the `ipc.ts` `export async function` names.)

- [ ] **Step 3: Run — expect PASS** (the coverage tests now see all three registered commands classified + wrappers bound):

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention/desktop && pnpm test writeGateCoverage writeCommands 2>&1 | tail -15
```
If FAIL with "unclassified"/"stale"/"wrapper not found", fix the classification/wrapper names to match `main.rs` + `ipc.ts` exactly.

- [ ] **Step 4: Type-check**

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention/desktop && pnpm exec svelte-check 2>&1 | tail -15
```
Expected: no new errors.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/ipc.ts desktop/src/lib/writeCommands.ts
git commit -m "feat(desktop): retention/purge IPC wrappers + write-gate classification"
```

---

### Task 7: RetentionDialog component

**Files:**
- Create: `desktop/src/components/delete/RetentionDialog.svelte`
- Test: `desktop/tests/RetentionDialog.test.ts`

**Interfaces:**
- Consumes: `ipc.{previewRetention, runRetention}`, `retention.retentionSummary`, `writeGuard.{authorizeWrite, ReauthCancelled}`, `stores.refreshManifest`, `errors.userMessageFor`.
- Produces: `RetentionDialog` with props `{ onClose: () => void }`. Mounts only while open (parent controls mount, like `ConfirmDialog`).

- [ ] **Step 1: Write the failing test** `desktop/tests/RetentionDialog.test.ts`. Mirror `ConfirmDialog.test.ts` / `TrashView.test.ts` (mock `../src/lib/ipc`, `../src/lib/stores`, `../src/lib/writeGuard`; render with `@testing-library/svelte`). Cases:
  - On mount, calls `previewRetention`; renders the summary text from the resolved preview.
  - Empty preview → renders the "No trashed items…" text; the confirm/purge button is absent or disabled.
  - Non-empty → clicking "Purge" calls `authorizeWrite` then `runRetention` then `refreshManifest` then `onClose`.
  - `authorizeWrite` rejecting with `ReauthCancelled` → no `runRetention`, dialog stays (no `onClose`).
  - `runRetention` rejecting with a typed error → renders `userMessageFor` text; no `onClose`.

  (Per [[project_secretary_vitest_mockrejectedvalue_quirk]] use `mockRejectedValueOnce` for the rejection cases.)

- [ ] **Step 2: Run — expect FAIL** (`cd desktop && pnpm test RetentionDialog`).

- [ ] **Step 3: Implement** `RetentionDialog.svelte` (model the `<dialog>` lifecycle on `ConfirmDialog`, the load/error state on `TrashView`):

```svelte
<script lang="ts">
  // Two-step retention dialog: preview which trashed blocks are past the
  // window, then commit an irreversible bulk purge. Preview via
  // previewRetention() on mount; commit gated by authorizeWrite like every
  // other mutating write. Mounts only while open (parent controls mount).

  import { previewRetention, runRetention, isAppError, type RetentionPreviewDto } from '../../lib/ipc';
  import { retentionSummary } from '../../lib/retention';
  import { authorizeWrite, ReauthCancelled } from '../../lib/writeGuard';
  import { refreshManifest } from '../../lib/stores';
  import { userMessageFor, type AppError } from '../../lib/errors';

  type Props = { onClose: () => void };
  let { onClose }: Props = $props();

  let preview = $state<RetentionPreviewDto | null>(null);
  let error = $state<AppError | null>(null);
  let submitting = $state(false);
  let dialogEl: HTMLDialogElement | undefined = $state();

  let loadSeq = 0;
  async function load() {
    const seq = ++loadSeq;
    error = null;
    try {
      const p = await previewRetention();
      if (seq === loadSeq) preview = p;
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) dialogEl.showModal();
  });
  $effect(() => { void load(); });

  function onNativeCancel(event: Event) {
    event.preventDefault();
    onClose();
  }

  let summary = $derived(preview ? retentionSummary(preview.entries, preview.windowMs) : '');
  let hasExpired = $derived((preview?.entries.length ?? 0) > 0);

  async function confirm() {
    error = null;
    try {
      await authorizeWrite('Confirm permanently deleting expired trash');
    } catch (err) {
      if (err === ReauthCancelled) return;
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    submitting = true;
    try {
      await runRetention();
      await refreshManifest();
      onClose();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    } finally {
      submitting = false;
    }
  }
</script>

<dialog
  bind:this={dialogEl}
  class="retention-dialog"
  aria-labelledby="retention-dialog-title"
  oncancel={onNativeCancel}
>
  <h2 id="retention-dialog-title" class="retention-dialog__title">Run retention now</h2>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="retention-dialog__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if preview === null}
    <p class="retention-dialog__loading">Checking trash…</p>
  {:else}
    <p class="retention-dialog__summary">{summary}</p>
  {/if}

  <div class="retention-dialog__actions">
    <button type="button" class="retention-dialog__button" onclick={onClose} disabled={submitting}>
      {hasExpired ? 'Cancel' : 'Close'}
    </button>
    {#if hasExpired}
      <button
        type="button"
        class="retention-dialog__button retention-dialog__button--danger"
        onclick={confirm}
        disabled={submitting}
      >
        {submitting ? 'Purging…' : `Purge ${preview?.entries.length} items`}
      </button>
    {/if}
  </div>
</dialog>
```

Add minimal styling to match the sibling dialogs' `theme.css` classes if needed (danger button reuses the shared `--danger` var — check `ConfirmDialog`/`SettingsDialog` styling).

- [ ] **Step 4: Run — expect PASS** (`cd desktop && pnpm test RetentionDialog`).

- [ ] **Step 5: Commit**

```bash
git add desktop/src/components/delete/RetentionDialog.svelte desktop/tests/RetentionDialog.test.ts
git commit -m "feat(desktop): RetentionDialog two-step preview + commit"
```

---

### Task 8: TrashView integration — "Run retention now" + per-block "Delete forever"

**Files:**
- Modify: `desktop/src/components/delete/TrashView.svelte`
- Modify: `desktop/src/components/delete/TrashedBlockRow.svelte`
- Test: `desktop/tests/TrashView.test.ts` (extend), `desktop/tests/TrashedBlockRow.test.ts` (if present)

**Interfaces:**
- Consumes: `RetentionDialog`, `ConfirmDialog`, `ipc.purgeBlock`, `writeGuard.{authorizeWrite, ReauthCancelled}`, `stores.refreshManifest`.
- Produces: TrashView renders a "Run retention now" button and each row a "Delete forever" action.

- [ ] **Step 1: Write the failing tests** (extend `TrashView.test.ts`):
  - A "Run retention now" button renders; clicking it mounts `RetentionDialog` (assert `previewRetention` gets called, or the dialog title appears).
  - Each `TrashedBlockRow` renders a "Delete forever" button; clicking it opens a `ConfirmDialog`; confirming calls `authorizeWrite` → `purgeBlock(hex)` → `refreshManifest` → reload.
  - `authorizeWrite` → `ReauthCancelled` path does not call `purgeBlock`.

- [ ] **Step 2: Run — expect FAIL** (`cd desktop && pnpm test TrashView`).

- [ ] **Step 3: Implement**

`TrashedBlockRow.svelte` — add an `onPurge` prop + button:

```svelte
  type Props = {
    entry: TrashedBlockDto;
    onRestore: (entry: TrashedBlockDto) => void;
    onPurge: (entry: TrashedBlockDto) => void;
  };
  let { entry, onRestore, onPurge }: Props = $props();
```
```svelte
  <button
    type="button"
    class="trashed-row__purge"
    aria-label={`Permanently delete block ${entry.blockName}`}
    onclick={() => onPurge(entry)}
  >
    Delete forever
  </button>
```

`TrashView.svelte`:
- Import `RetentionDialog`, `ConfirmDialog`, `purgeBlock`.
- Add `let showRetention = $state(false);` and `let pendingPurge = $state<TrashedBlockDto | null>(null);`.
- Add the "Run retention now" button in the header (near the back button). On success the dialog closes; call `load()` after retention (a `refreshManifest` happened in the dialog, but re-`load()` refreshes the trash list):

```svelte
  <button type="button" class="trash-view__retention" onclick={() => (showRetention = true)}>
    Run retention now
  </button>
```
```svelte
  {#if showRetention}
    <RetentionDialog onClose={() => { showRetention = false; void load(); }} />
  {/if}
```
- Wire per-row purge with a `ConfirmDialog` (block name in body):

```svelte
  {#each entries as entry (entry.blockUuidHex)}
    <TrashedBlockRow {entry} onRestore={restore} onPurge={(e) => (pendingPurge = e)} />
  {/each}

  {#if pendingPurge}
    <ConfirmDialog
      title="Delete forever?"
      body={`"${pendingPurge.blockName}" will be permanently deleted. This cannot be undone.`}
      confirmLabel="Delete forever"
      onConfirm={confirmPurge}
      onCancel={() => (pendingPurge = null)}
    />
  {/if}
```
- Add `confirmPurge` (mirror `restore`):

```svelte
  async function confirmPurge() {
    const target = pendingPurge;
    pendingPurge = null;
    if (!target) return;
    error = null;
    try {
      await authorizeWrite('Confirm permanently deleting this block');
    } catch (err) {
      if (err === ReauthCancelled) return;
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    try {
      await purgeBlock(target.blockUuidHex);
      await refreshManifest();
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
```

- [ ] **Step 4: Run — expect PASS** + type-check:

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention/desktop && pnpm test TrashView TrashedBlockRow && pnpm exec svelte-check 2>&1 | tail -15
```

- [ ] **Step 5: Commit**

```bash
git add desktop/src/components/delete/TrashView.svelte desktop/src/components/delete/TrashedBlockRow.svelte desktop/tests/TrashView.test.ts desktop/tests/TrashedBlockRow.test.ts
git commit -m "feat(desktop): TrashView retention button + per-block delete-forever"
```

---

### Task 9: SettingsDialog retention window control

**Files:**
- Modify: `desktop/src/components/SettingsDialog.svelte`
- Test: `desktop/tests/SettingsDialog.test.ts` (extend)

**Interfaces:**
- Consumes: `constants.{RETENTION_WINDOW_MIN_MS, RETENTION_WINDOW_MAX_MS, RETENTION_WINDOW_DEFAULT_MS, MS_PER_DAY}`, `retention.{msToDays, daysToMs}`, `SettingsDto.retentionWindowMs`.
- Produces: a "Retention window (days)" number input persisted via the existing save flow.

- [ ] **Step 1: Write the failing tests** (extend `SettingsDialog.test.ts`):
  - Dialog pre-populates the retention input from `currentSettings.retentionWindowMs` (as days).
  - Saving includes `retentionWindowMs` in the `setSettings` payload (= input days × MS_PER_DAY).
  - An out-of-range day value (e.g. 0) → `settings_out_of_range` error, no `setSettings` call.

- [ ] **Step 2: Run — expect FAIL** (`cd desktop && pnpm test SettingsDialog`).

- [ ] **Step 3: Implement** in `SettingsDialog.svelte`:
  - Import the retention constants + `msToDays`/`daysToMs` (or compute inline with `MS_PER_DAY`).
  - Add derived `currentRetentionMs` (from `$sessionState.settings.retentionWindowMs`, default `RETENTION_WINDOW_DEFAULT_MS` while locked), a `$state inputRetentionDays`, seed it in the re-seed `$effect` (`msToDays(currentRetentionMs)`), and reset it in `cancel()`.
  - Add a bound to `validateOrError()`:

```ts
const RETENTION_MIN_DAYS = RETENTION_WINDOW_MIN_MS / MS_PER_DAY;
const RETENTION_MAX_DAYS = RETENTION_WINDOW_MAX_MS / MS_PER_DAY;
// ...in validateOrError():
if (
  !Number.isInteger(inputRetentionDays) ||
  inputRetentionDays < RETENTION_MIN_DAYS ||
  inputRetentionDays > RETENTION_MAX_DAYS
) {
  return { code: 'settings_out_of_range', min: RETENTION_WINDOW_MIN_MS, max: RETENTION_WINDOW_MAX_MS };
}
```
  - Include the field in the `newSettings` payload: `retentionWindowMs: inputRetentionDays * MS_PER_DAY`.
  - Retention widening is not a security *reduction* (it only delays discarding ciphertext), so it does **not** need to be added to the `reducesProtection` gate — leave that logic unchanged.
  - Add the input markup (mirror the auto-lock field, suffix "days"):

```svelte
  <label class="settings-dialog__field">
    <span class="settings-dialog__label">Retention window</span>
    <div class="settings-dialog__input-row">
      <input
        type="number"
        class="settings-dialog__input"
        min={RETENTION_MIN_DAYS}
        max={RETENTION_MAX_DAYS}
        step="1"
        bind:value={inputRetentionDays}
        disabled={submitting}
      />
      <span class="settings-dialog__suffix">days</span>
    </div>
  </label>
```

- [ ] **Step 4: Run — expect PASS** + type-check (`cd desktop && pnpm test SettingsDialog && pnpm exec svelte-check`).

- [ ] **Step 5: Commit**

```bash
git add desktop/src/components/SettingsDialog.svelte desktop/tests/SettingsDialog.test.ts
git commit -m "feat(desktop): configurable retention window in Settings"
```

---

### Task 10: Full-suite gates + docs + handoff

**Files:**
- Modify: `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-07-10-desktop-retention-purge-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget symlink)

- [ ] **Step 1: Run every gate from the worktree root** and confirm green:

```
cd /Users/hherb/src/secretary/.worktrees/desktop-retention
cargo test --release --workspace 2>&1 | tail -8
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -8
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -5
cd desktop && pnpm test 2>&1 | tail -12 && pnpm exec svelte-check 2>&1 | tail -8
```
All must pass. Fix any failure before proceeding (do not defer).

- [ ] **Step 2: Update `README.md`** — in the desktop "Project status" area, note desktop now supports retention auto-purge + per-block permanent delete over the #406 FFI (brief dot-point per [[feedback_readme_style]] — no test-count walls).

- [ ] **Step 3: Update `ROADMAP.md`** — mark the desktop retention/purge UX slice shipped; note empty-trash + iOS/Android retention still deferred.

- [ ] **Step 4: Write the handoff** `docs/handoffs/2026-07-10-desktop-retention-purge-shipped.md` capturing: (1) what shipped + commit SHAs, (2) what's next with acceptance criteria (empty-trash slice; iOS/Android retention UX; the deferred manual GUI smoke), (3) open decisions/risks (retention window is caller-invoked, no scheduler; per-block purge idempotent re-purge behavior), (4) exact resume commands (cd, branch, test command), (5) the symlink model note.

- [ ] **Step 5: Retarget the symlink + commit both**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-retention
ln -snf docs/handoffs/2026-07-10-desktop-retention-purge-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
git add README.md ROADMAP.md docs/handoffs/2026-07-10-desktop-retention-purge-shipped.md NEXT_SESSION.md
git commit -m "docs: desktop retention/purge shipped — README + ROADMAP + handoff"
```

- [ ] **Step 6: Push + open PR** (per [[feedback_baton_push_and_open_pr_default]] — push and open, user still merges):

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-retention
git push -u origin feature/desktop-retention
gh pr create --base main --title "feat(desktop): retention auto-purge + per-block delete-forever UX" --body "<summary + test evidence + closes-note>"
```

---

## Self-Review

**Spec coverage:**
- Retention preview → Task 3 (DTO) + Task 4 (`preview_retention`) + Task 7 (dialog). ✓
- Retention commit → Task 4 (`run_retention`) + Task 7. ✓
- Per-block purge → Task 4 (`purge_block`) + Task 8. ✓
- Configurable window setting → Task 1 (backend) + Task 2 (DTO) + Task 6 (TS field) + Task 9 (UI). ✓
- Two-step preview UX (Approach A) → Task 7. ✓
- ConfirmDialog reuse for per-block → Task 8. ✓
- Write-gate on both commits → Tasks 7, 8. ✓
- Error mapping exhaustive, no new variant → Task 4 Step 1. ✓
- Non-goals (empty-trash, scheduler, iOS/Android) → not in any task. ✓
- Collision minimization (new modules) → Tasks 3, 4, 5, 7 create new files; shared edits narrow. ✓

**Placeholder scan:** No TBD/TODO; every code step shows code; the one deliberate STOP (Task 4 Step 1) is a verification gate with a defined fallback, not a placeholder.

**Type consistency:** `retention_window_ms` (Rust) ↔ `retentionWindowMs` (wire/TS) consistent across Tasks 1/2/6/9. DTO field names (`purgedCount`, `filesFailed`, `windowMs`, `wasShared`, `recipientCount`) consistent across Tasks 3/6. `previewRetention`/`runRetention`/`purgeBlock` wrapper names consistent across Tasks 4/6/7/8 and the `writeCommands.ts` `wrapper` strings. Command names (`preview_retention`/`run_retention`/`purge_block`) consistent across Tasks 4/6.
