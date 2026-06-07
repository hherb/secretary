# D.1.14 — Desktop Sync UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the shipped `secretary_ffi_bridge::sync_status` / `sync_vault` primitives into the desktop as a TopBar sync-status pill that re-prompts for the password in a centered modal and reports the outcome.

**Architecture:** Bridge-thick, pure D-phase slice. Two thin Tauri command delegates (`sync_status`, `sync_now`) + two desktop DTOs project the bridge surface; the TS layer adds typed errors, a pure outcome/label mapping, two IPC wrappers, and two Svelte components (a combined pill + a password modal). No `core`/`ffi`/`FfiVaultError`/UDL change, so no cross-language conformance run. Desktop tests are seam-only-hermetic (NotUnlocked path + DTO wire-format); end-to-end sync stays covered by D.1.13's bridge TempDir tests + a mandatory manual GUI smoke.

**Tech Stack:** Rust (Tauri 2 commands, serde), Svelte 5 (runes: `$props`/`$state`/`$effect`), TypeScript, Vitest + @testing-library/svelte, `cargo test`.

**Spec:** [docs/superpowers/specs/2026-06-06-d114-desktop-sync-ui-design.md](../specs/2026-06-06-d114-desktop-sync-ui-design.md)

---

## File Structure

**Rust (`desktop/src-tauri/`)**
- `src/session.rs` *(modify)* — add `vault_folder: PathBuf` to `UnlockedSession`, set in `unlock()`.
- `src/dtos/sync.rs` *(create)* — desktop `SyncStatusDto` + `SyncOutcomeDto` + `From<bridge::…>` + serde tests.
- `src/dtos/mod.rs` *(modify)* — declare + re-export the sync DTOs.
- `src/commands/sync.rs` *(create)* — `sync_status` / `sync_now` commands + `_impl`s + `vault_uuid_16` helper.
- `src/commands/mod.rs` *(modify)* — `pub mod sync;`.
- `src/main.rs` *(modify)* — register `sync::sync_status`, `sync::sync_now`.
- `tests/session_integration.rs` *(modify)* — assert `vault_folder` is retained on unlock.
- `tests/ipc_integration.rs` *(modify)* — NotUnlocked path for both commands.

**TS (`desktop/src/`)**
- `lib/errors.ts` *(modify)* — 5 sync codes + union arms + `userMessageFor` cases.
- `lib/format.ts` *(modify)* — pure `formatRelativeTime(pastMs, nowMs)`.
- `lib/sync.ts` *(create)* — types + `syncOutcomeMessage` + `syncChangedData` + `lastSyncedLabel`.
- `lib/ipc.ts` *(modify)* — `syncStatus()` + `syncNow(password)` wrappers.
- `components/SyncPasswordDialog.svelte` *(create)* — centered re-prompt modal.
- `components/SyncPill.svelte` *(create)* — the combined indicator + trigger.
- `components/TopBar.svelte` *(modify)* — mount `<SyncPill />`.

**Tests (`desktop/tests/`)** — `errorsSync.test.ts`, `format.test.ts` *(modify/create)*, `sync.test.ts`, `ipc.test.ts` *(modify)*, `SyncPasswordDialog.test.ts`, `SyncPill.test.ts`, `TopBar.test.ts` *(modify)* — all created/extended in their owning task.

**Naming note (refines spec terminology):** the spec calls the outcome→message mapping `syncOutcomeToast` / `SyncToast`. The codebase has **no generic toast** (the `Toast` component is bound to the auto-lock-notice union; surfaces render their own inline `role="alert"`/`role="status"`). This plan therefore names the pure mapping `syncOutcomeMessage` returning `SyncMessage`, rendered as an inline region in `SyncPill` — same data, codebase-consistent rendering.

---

## Task 1: Session retains the vault folder path

**Files:**
- Modify: `desktop/src-tauri/src/session.rs`
- Test: `desktop/src-tauri/tests/session_integration.rs`

- [ ] **Step 1: Write the failing test**

Append to `desktop/src-tauri/tests/session_integration.rs`:

```rust
#[test]
fn unlock_retains_vault_folder_on_the_unlocked_session() {
    let (mut session, _device_dir) = fresh_session();
    let folder = golden_vault_path();
    session
        .unlock(&folder, GOLDEN_VAULT_PASSWORD)
        .expect("unlock golden vault");

    let retained: PathBuf = session
        .with_unlocked(|u| Ok(u.vault_folder.clone()))
        .expect("session must be unlocked");

    assert_eq!(
        retained, folder,
        "unlock() must retain the vault folder on the UnlockedSession so \
         sync_now can pass it to the bridge sync_vault"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop/src-tauri && cargo test --test session_integration unlock_retains_vault_folder -- --exact`
Expected: FAIL — `no field 'vault_folder' on type '&UnlockedSession'` (compile error).

- [ ] **Step 3: Add the field and populate it**

In `desktop/src-tauri/src/session.rs`, add the field to `UnlockedSession` (after `pending_warnings`):

```rust
    pub pending_warnings: Vec<AppWarning>,
    /// Absolute path the vault was opened from. Needed by `sync_now` to call
    /// the bridge `sync_vault`, which takes a folder path (a different entry
    /// point than the manifest handle). Plain value, no secret material — the
    /// `Drop` order (manifest.wipe → identity.wipe) is unaffected.
    pub vault_folder: PathBuf,
```

In `VaultSession::unlock()`, add the field to the `UnlockedSession { … }` constructor (alongside `device_uuid`):

```rust
        self.inner = Some(UnlockedSession {
            identity: output.identity,
            manifest: output.manifest,
            settings: settings_val,
            device_uuid,
            pending_warnings,
            vault_folder: folder.to_path_buf(),
        });
```

(`PathBuf` is already imported via `use std::path::{Path, PathBuf};`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd desktop/src-tauri && cargo test --test session_integration unlock_retains_vault_folder -- --exact`
Expected: PASS.

- [ ] **Step 5: Run the full session suite + clippy to confirm no fallout**

Run: `cd desktop/src-tauri && cargo test --test session_integration && cargo clippy --tests -- -D warnings`
Expected: all pass, clippy clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/session.rs desktop/src-tauri/tests/session_integration.rs
git commit -m "D.1.14 Task 1 — UnlockedSession retains vault_folder for sync_now"
```

---

## Task 2: Desktop sync DTOs + wire-format tests

**Files:**
- Create: `desktop/src-tauri/src/dtos/sync.rs`
- Modify: `desktop/src-tauri/src/dtos/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `desktop/src-tauri/src/dtos/sync.rs` with ONLY the test module first (so it compiles to a failing reference):

```rust
//! Sync DTOs crossing the Tauri IPC boundary (D.1.14). Projections of the
//! bridge `SyncStatusDto` / `SyncOutcomeDto`:
//!
//! - `SyncStatusDto` drops `device_clocks` (not surfaced in v1 — a plain
//!   "last synced" time is enough; see spec §3 "Out of scope").
//! - `SyncOutcomeDto` is a serde-tagged union for the TS discriminated type.
//!   `rename_all_fields` is required so `ConflictsPending`'s `veto_count`
//!   field serializes as `vetoCount` (the enum-level `rename_all` renames
//!   *variants* only, not struct-variant *fields*).

use serde::Serialize;

use secretary_ffi_bridge::{
    SyncOutcomeDto as BridgeSyncOutcomeDto, SyncStatusDto as BridgeSyncStatusDto,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub has_state: bool,
    pub last_state_write_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SyncOutcomeDto {
    NothingToDo,
    AppliedAutomatically,
    SilentMerge,
    MergedClean,
    ConflictsPending { veto_count: u32 },
    RollbackRejected,
}

impl From<BridgeSyncStatusDto> for SyncStatusDto {
    fn from(b: BridgeSyncStatusDto) -> Self {
        // device_clocks intentionally dropped (not surfaced in v1).
        Self {
            has_state: b.has_state,
            last_state_write_ms: b.last_state_write_ms,
        }
    }
}

impl From<BridgeSyncOutcomeDto> for SyncOutcomeDto {
    fn from(b: BridgeSyncOutcomeDto) -> Self {
        match b {
            BridgeSyncOutcomeDto::NothingToDo => Self::NothingToDo,
            BridgeSyncOutcomeDto::AppliedAutomatically => Self::AppliedAutomatically,
            BridgeSyncOutcomeDto::SilentMerge => Self::SilentMerge,
            BridgeSyncOutcomeDto::MergedClean => Self::MergedClean,
            BridgeSyncOutcomeDto::ConflictsPending { veto_count } => {
                Self::ConflictsPending { veto_count }
            }
            BridgeSyncOutcomeDto::RollbackRejected => Self::RollbackRejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_dto_serializes_camelcase_without_device_clocks() {
        let dto = SyncStatusDto {
            has_state: true,
            last_state_write_ms: Some(1_700_000_000_000),
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(
            v,
            json!({ "hasState": true, "lastStateWriteMs": 1_700_000_000_000u64 })
        );
        assert!(v.get("deviceClocks").is_none(), "device_clocks must be dropped");
    }

    #[test]
    fn status_dto_null_write_ms_when_never_synced() {
        let dto = SyncStatusDto { has_state: false, last_state_write_ms: None };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(v, json!({ "hasState": false, "lastStateWriteMs": null }));
    }

    #[test]
    fn outcome_unit_variants_serialize_as_tagged_kind() {
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::NothingToDo).unwrap(),
            json!({ "kind": "nothingToDo" })
        );
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::AppliedAutomatically).unwrap(),
            json!({ "kind": "appliedAutomatically" })
        );
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::RollbackRejected).unwrap(),
            json!({ "kind": "rollbackRejected" })
        );
    }

    #[test]
    fn conflicts_pending_serializes_kind_and_camelcase_veto_count() {
        let v = serde_json::to_value(SyncOutcomeDto::ConflictsPending { veto_count: 3 }).unwrap();
        assert_eq!(v, json!({ "kind": "conflictsPending", "vetoCount": 3 }));
    }
}
```

- [ ] **Step 2: Wire the module so the test compiles**

In `desktop/src-tauri/src/dtos/mod.rs`, add `mod sync;` (alphabetically, after `recipient`) and a `pub use`:

```rust
mod recipient;
mod sync;
mod trash;
```
```rust
pub use recipient::{RecipientDto, RecipientKindDto};
pub use sync::{SyncOutcomeDto, SyncStatusDto};
pub use trash::TrashedBlockDto;
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cd desktop/src-tauri && cargo test --lib dtos::sync`
Expected: 4 tests PASS. (TDD note: the implementation and tests land together here because the serde wire-format *is* the unit under test — the assertions would be meaningless without the `#[derive]`/`#[serde]` attributes they pin; there is no behavior to red-first separately.)

- [ ] **Step 4: Clippy**

Run: `cd desktop/src-tauri && cargo clippy --lib --tests -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/dtos/sync.rs desktop/src-tauri/src/dtos/mod.rs
git commit -m "D.1.14 Task 2 — desktop sync DTOs (drops device_clocks; tagged outcome wire-format)"
```

---

## Task 3: Rust sync commands + registration

**Files:**
- Create: `desktop/src-tauri/src/commands/sync.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs`, `desktop/src-tauri/src/main.rs`
- Test: `desktop/src-tauri/tests/ipc_integration.rs`

- [ ] **Step 1: Write the failing test**

Append to `desktop/src-tauri/tests/ipc_integration.rs`:

```rust
// ---- D.1.14 sync commands: seam-only hermetic coverage (NotUnlocked). ----
// The end-to-end sync path is covered hermetically by the bridge's own
// TempDir tests (ffi/secretary-ffi-bridge/src/sync/*) and by the mandatory
// manual GUI smoke; the bridge's public sync_status/sync_vault use the
// default OS state dir, so driving them here would be non-hermetic.

#[test]
fn sync_status_on_locked_session_yields_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let err = sync::sync_status_impl(&state).expect_err("locked session must error");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}

#[test]
fn sync_now_on_locked_session_yields_not_unlocked() {
    let (state, _device_dir) = fresh_state();
    let pw = Password::from_bytes(b"unused while locked");
    let err = sync::sync_now_impl(&state, &pw, 0).expect_err("locked session must error");
    assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
}
```

Extend the imports at the top of `ipc_integration.rs`: add `sync` to the commands list and import `Password`:

```rust
use secretary_desktop::commands::{browse, create, delete, edit, lock, settings, sync, unlock, vault};
```
```rust
use secretary_desktop::secret_arg::Password;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop/src-tauri && cargo test --test ipc_integration sync_ -- --exact`
Expected: FAIL — `unresolved import ... sync` / `no function sync_status_impl` (compile error).

- [ ] **Step 3: Create the command module**

Create `desktop/src-tauri/src/commands/sync.rs`:

```rust
//! Sync IPC commands (D.1.14): `sync_status` (read) + `sync_now` (mutation).
//! Thin delegates to the bridge `sync_status` / `sync_vault` (D.1.13), in the
//! same `#[tauri::command]` + testable `*_impl` split as the other command
//! modules. `sync_now` re-opens a core identity from a fresh password (the
//! bridge surface takes a password, not the session identity) — the password
//! rides the zeroize-typed `Password` and is dropped at `_impl` end.

use std::sync::Mutex;

use tauri::State;

use secretary_core::crypto::secret::SecretBytes;
use secretary_ffi_bridge::{sync_status as bridge_sync_status, sync_vault as bridge_sync_vault};

use crate::auto_lock::now_ms;
use crate::commands::shared::lock_session;
use crate::dtos::{SyncOutcomeDto, SyncStatusDto};
use crate::errors::{map_ffi_error, AppError};
use crate::secret_arg::Password;
use crate::session::VaultSession;

/// Narrow a manifest's `vault_uuid()` (`Vec<u8>`) to the `[u8; 16]` the bridge
/// `sync_status` expects. Unreachable for an opened vault (the manifest uuid is
/// always 16 bytes); a typed `Internal` rather than a panic if it ever isn't.
fn vault_uuid_16(bytes: &[u8]) -> Result<[u8; 16], AppError> {
    bytes.try_into().map_err(|_| AppError::Internal)
}

#[tauri::command]
pub async fn sync_status(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<SyncStatusDto, AppError> {
    sync_status_impl(state.inner())
}

/// Testable core for `sync_status`. Read-only: projects the bridge status for
/// the unlocked vault's uuid. `NotUnlocked` when locked (via `with_unlocked`).
pub fn sync_status_impl(state: &Mutex<VaultSession>) -> Result<SyncStatusDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let vault_uuid = vault_uuid_16(&u.manifest.vault_uuid())?;
        let dto = bridge_sync_status(vault_uuid).map_err(map_ffi_error)?;
        Ok(SyncStatusDto::from(dto))
    })
}

#[tauri::command]
pub async fn sync_now(
    state: State<'_, Mutex<VaultSession>>,
    password: Password,
) -> Result<SyncOutcomeDto, AppError> {
    sync_now_impl(state.inner(), &password, now_ms())
}

/// Testable core for `sync_now`. Runs the bridge pause-on-conflict sync pass
/// over the session's retained vault folder, re-opening an identity from
/// `password`. `now_ms` is supplied by the command wrapper (deterministic in
/// tests); it only affects the merge timestamp on the concurrent-clean-merge
/// arm. Strict: every bridge error is mapped, nothing swallowed.
pub fn sync_now_impl(
    state: &Mutex<VaultSession>,
    password: &Password,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let outcome = bridge_sync_vault(&u.vault_folder, SecretBytes::from(password.expose()), now_ms)
            .map_err(map_ffi_error)?;
        Ok(SyncOutcomeDto::from(outcome))
    })
}
```

- [ ] **Step 4: Register the module + commands**

In `desktop/src-tauri/src/commands/mod.rs`, add (alphabetically, after `shared`):

```rust
pub(crate) mod shared;
pub mod sync;
pub mod unlock;
```

In `desktop/src-tauri/src/main.rs`, add to the `tauri::generate_handler![…]` list (after the `contacts::*` block):

```rust
            contacts::block_recipients,
            contacts::list_contact_blocks,
            sync::sync_status,
            sync::sync_now,
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd desktop/src-tauri && cargo test --test ipc_integration sync_ -- --exact`
Expected: 2 tests PASS.

- [ ] **Step 6: Full workspace build + clippy (the command wrappers must compile under the Tauri macro)**

Run: `cd desktop/src-tauri && cargo build && cargo clippy --tests -- -D warnings`
Expected: compiles, clippy clean.

- [ ] **Step 7: Commit**

```bash
git add desktop/src-tauri/src/commands/sync.rs desktop/src-tauri/src/commands/mod.rs desktop/src-tauri/src/main.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "D.1.14 Task 3 — sync_status + sync_now Tauri commands (NotUnlocked seam-tested)"
```

---

## Task 4: TS error variants for the 5 sync codes

**Files:**
- Modify: `desktop/src/lib/errors.ts`
- Test: `desktop/tests/errorsSync.test.ts` (create)

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/errorsSync.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { APP_ERROR_CODES, userMessageFor, type AppError } from '../src/lib/errors';

const SYNC_CODES = [
  'sync_in_progress',
  'sync_evidence_stale',
  'sync_state_vault_mismatch',
  'sync_state_corrupt',
  'sync_failed'
] as const;

describe('errors.ts — D.1.14 sync variants', () => {
  it('registers all five sync codes in APP_ERROR_CODES', () => {
    for (const code of SYNC_CODES) {
      expect(APP_ERROR_CODES).toContain(code);
    }
  });

  it('userMessageFor returns a non-empty title + actionHint for each sync code', () => {
    for (const code of SYNC_CODES) {
      const msg = userMessageFor({ code } as AppError);
      expect(msg.title.length).toBeGreaterThan(0);
      expect(msg.actionHint && msg.actionHint.length).toBeGreaterThan(0);
      // must not fall through to the unknown-code fallback
      expect(msg.title).not.toBe('Unknown error');
    }
  });

  it('sync_failed has the real user copy (not the terse Rust placeholder)', () => {
    const msg = userMessageFor({ code: 'sync_failed' } as AppError);
    expect(msg.title).toBe("Sync didn't complete");
    expect(msg.actionHint).toMatch(/try again/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop && pnpm vitest run tests/errorsSync.test.ts`
Expected: FAIL — codes not in `APP_ERROR_CODES`; `userMessageFor` returns "Unknown error".

- [ ] **Step 3: Add the codes, union arms, and messages**

In `desktop/src/lib/errors.ts`, add the five codes to `APP_ERROR_CODES` (before `'internal'`):

```ts
  'recipient_not_present',
  'cannot_revoke_owner',
  'sync_in_progress',
  'sync_evidence_stale',
  'sync_state_vault_mismatch',
  'sync_state_corrupt',
  'sync_failed',
  'internal'
```

Add the union arms (before `| { code: 'internal' }`):

```ts
  | { code: 'sync_in_progress' }
  | { code: 'sync_evidence_stale' }
  | { code: 'sync_state_vault_mismatch' }
  | { code: 'sync_state_corrupt' }
  | { code: 'sync_failed' }
  | { code: 'internal' };
```

Add the `userMessageFor` cases (before `case 'internal':`):

```ts
    case 'sync_in_progress':
      return {
        title: 'Another sync is in progress',
        actionHint: 'Wait for it to finish, then try again.'
      };
    case 'sync_evidence_stale':
      return {
        title: 'The vault changed during sync',
        actionHint: 'Something modified the vault while it was syncing. Try again.'
      };
    case 'sync_state_vault_mismatch':
      return {
        title: 'Sync state belongs to a different vault',
        actionHint: "The local sync cache doesn't match this vault."
      };
    case 'sync_state_corrupt':
      return {
        title: 'Sync state cache is unreadable',
        actionHint: 'The local sync cache is corrupt and will be rebuilt on the next sync.'
      };
    case 'sync_failed':
      return {
        title: "Sync didn't complete",
        actionHint: 'Something went wrong during sync. Try again.'
      };
```

- [ ] **Step 4: Run the test + the existing errors suite + typecheck**

Run: `cd desktop && pnpm vitest run tests/errorsSync.test.ts tests/errors.test.ts && pnpm typecheck`
Expected: PASS; `tsc` exhaustiveness on the `userMessageFor` switch is satisfied.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/errors.ts desktop/tests/errorsSync.test.ts
git commit -m "D.1.14 Task 4 — TS AppError sync variants + userMessageFor (real sync_failed copy)"
```

---

## Task 5: Pure sync helpers (`lib/sync.ts` + `formatRelativeTime`)

**Files:**
- Modify: `desktop/src/lib/format.ts`
- Create: `desktop/src/lib/sync.ts`
- Test: `desktop/tests/format.test.ts` (extend or create), `desktop/tests/sync.test.ts` (create)

- [ ] **Step 1: Write the failing test for `formatRelativeTime`**

Create/extend `desktop/tests/format.test.ts` with:

```ts
import { describe, it, expect } from 'vitest';
import { formatRelativeTime } from '../src/lib/format';

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe('formatRelativeTime', () => {
  const now = 1_700_000_000_000;

  it('shows "just now" under a minute', () => {
    expect(formatRelativeTime(now - 30 * SECOND, now)).toBe('just now');
  });
  it('shows whole minutes', () => {
    expect(formatRelativeTime(now - 2 * MINUTE, now)).toBe('2m ago');
  });
  it('shows whole hours', () => {
    expect(formatRelativeTime(now - 3 * HOUR, now)).toBe('3h ago');
  });
  it('shows whole days up to the cutoff', () => {
    expect(formatRelativeTime(now - 5 * DAY, now)).toBe('5d ago');
  });
  it('falls back to a short date beyond 7 days', () => {
    const past = now - 30 * DAY;
    // beyond the relative window → an absolute date (year present)
    expect(formatRelativeTime(past, now)).toMatch(/\d{4}/);
  });
  it('treats a future/equal timestamp as "just now" (clock skew safety)', () => {
    expect(formatRelativeTime(now + 5 * SECOND, now)).toBe('just now');
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm vitest run tests/format.test.ts`
Expected: FAIL — `formatRelativeTime` is not exported.

- [ ] **Step 3: Implement `formatRelativeTime`**

Append to `desktop/src/lib/format.ts`:

```ts
const MS_PER_SECOND = 1_000;
const MS_PER_MINUTE = 60 * MS_PER_SECOND;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;
/** Beyond this many days, show an absolute date instead of "Nd ago". */
const RELATIVE_DAYS_CUTOFF = 7;

/** Pure relative-time label: "just now" / "Nm ago" / "Nh ago" / "Nd ago",
 *  falling back to {@link formatShortDate} beyond {@link RELATIVE_DAYS_CUTOFF}
 *  days. A `pastMs` at or after `nowMs` (clock skew) reads as "just now". */
export function formatRelativeTime(pastMs: number, nowMs: number): string {
  const delta = nowMs - pastMs;
  if (delta < MS_PER_MINUTE) return 'just now';
  if (delta < MS_PER_HOUR) return `${Math.floor(delta / MS_PER_MINUTE)}m ago`;
  if (delta < MS_PER_DAY) return `${Math.floor(delta / MS_PER_HOUR)}h ago`;
  const days = Math.floor(delta / MS_PER_DAY);
  if (days <= RELATIVE_DAYS_CUTOFF) return `${days}d ago`;
  return formatShortDate(pastMs);
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm vitest run tests/format.test.ts`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `lib/sync.ts`**

Create `desktop/tests/sync.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  syncOutcomeMessage,
  syncChangedData,
  lastSyncedLabel,
  type SyncOutcome,
  type SyncStatusDto
} from '../src/lib/sync';

describe('syncOutcomeMessage', () => {
  it('maps nothingToDo to a success "already up to date"', () => {
    expect(syncOutcomeMessage({ kind: 'nothingToDo' })).toEqual({
      kind: 'success',
      text: 'Already up to date'
    });
  });

  it('collapses the three applied/merged arms to one success message', () => {
    const arms: SyncOutcome[] = [
      { kind: 'appliedAutomatically' },
      { kind: 'silentMerge' },
      { kind: 'mergedClean' }
    ];
    for (const o of arms) {
      expect(syncOutcomeMessage(o)).toEqual({
        kind: 'success',
        text: 'Synced — your vault is up to date'
      });
    }
  });

  it('maps conflictsPending to a warning with the veto count interpolated', () => {
    expect(syncOutcomeMessage({ kind: 'conflictsPending', vetoCount: 1 })).toEqual({
      kind: 'warning',
      text: '1 conflict needs resolution — coming soon'
    });
    expect(syncOutcomeMessage({ kind: 'conflictsPending', vetoCount: 3 })).toEqual({
      kind: 'warning',
      text: '3 conflicts need resolution — coming soon'
    });
  });

  it('maps rollbackRejected to an error message', () => {
    expect(syncOutcomeMessage({ kind: 'rollbackRejected' })).toEqual({
      kind: 'error',
      text: 'Sync rejected — a peer tried to roll back protected data'
    });
  });
});

describe('syncChangedData', () => {
  it('is true only for the three applied/merged arms', () => {
    expect(syncChangedData({ kind: 'appliedAutomatically' })).toBe(true);
    expect(syncChangedData({ kind: 'silentMerge' })).toBe(true);
    expect(syncChangedData({ kind: 'mergedClean' })).toBe(true);
  });
  it('is false for arms that write nothing', () => {
    expect(syncChangedData({ kind: 'nothingToDo' })).toBe(false);
    expect(syncChangedData({ kind: 'conflictsPending', vetoCount: 2 })).toBe(false);
    expect(syncChangedData({ kind: 'rollbackRejected' })).toBe(false);
  });
});

describe('lastSyncedLabel', () => {
  const now = 1_700_000_000_000;
  it('says "Never synced" when no state exists', () => {
    const s: SyncStatusDto = { hasState: false, lastStateWriteMs: null };
    expect(lastSyncedLabel(s, now)).toBe('Never synced');
  });
  it('says "Synced" with no time when state exists but mtime is unknown', () => {
    const s: SyncStatusDto = { hasState: true, lastStateWriteMs: null };
    expect(lastSyncedLabel(s, now)).toBe('Synced');
  });
  it('says "Synced {relative}" when a write time is known', () => {
    const s: SyncStatusDto = { hasState: true, lastStateWriteMs: now - 120_000 };
    expect(lastSyncedLabel(s, now)).toBe('Synced 2m ago');
  });
});
```

- [ ] **Step 6: Run to verify it fails**

Run: `cd desktop && pnpm vitest run tests/sync.test.ts`
Expected: FAIL — module `../src/lib/sync` not found.

- [ ] **Step 7: Implement `lib/sync.ts`**

Create `desktop/src/lib/sync.ts`:

```ts
// Pure sync-domain helpers shared by SyncPill + tests. No I/O, no Svelte.
// Outcome/label mapping kept here (not in components) so it is unit-tested
// in isolation and trivially re-split later if the collapsed success copy
// (spec §4.6) ever needs to differentiate the three applied/merged arms.

import { formatRelativeTime } from './format';

/** Read-only sync status from the `sync_status` command (mirrors the Rust
 *  `dtos::SyncStatusDto`; `device_clocks` is intentionally not surfaced). */
export type SyncStatusDto = { hasState: boolean; lastStateWriteMs: number | null };

/** Outcome of a sync pass (mirrors the tagged Rust `dtos::SyncOutcomeDto`). */
export type SyncOutcome =
  | { kind: 'nothingToDo' }
  | { kind: 'appliedAutomatically' }
  | { kind: 'silentMerge' }
  | { kind: 'mergedClean' }
  | { kind: 'conflictsPending'; vetoCount: number }
  | { kind: 'rollbackRejected' };

export type NoticeKind = 'success' | 'warning' | 'error';
export type SyncMessage = { kind: NoticeKind; text: string };

/** Map a sync outcome to its inline notice. The three "changes applied
 *  safely" arms collapse to one success message — the distinction isn't
 *  user-actionable (spec §4.6). */
export function syncOutcomeMessage(outcome: SyncOutcome): SyncMessage {
  switch (outcome.kind) {
    case 'nothingToDo':
      return { kind: 'success', text: 'Already up to date' };
    case 'appliedAutomatically':
    case 'silentMerge':
    case 'mergedClean':
      return { kind: 'success', text: 'Synced — your vault is up to date' };
    case 'conflictsPending': {
      const noun = outcome.vetoCount === 1 ? 'conflict needs' : 'conflicts need';
      return {
        kind: 'warning',
        text: `${outcome.vetoCount} ${noun} resolution — coming soon`
      };
    }
    case 'rollbackRejected':
      return {
        kind: 'error',
        text: 'Sync rejected — a peer tried to roll back protected data'
      };
  }
}

/** Whether an outcome changed vault data, so the records view must refresh. */
export function syncChangedData(outcome: SyncOutcome): boolean {
  return (
    outcome.kind === 'appliedAutomatically' ||
    outcome.kind === 'silentMerge' ||
    outcome.kind === 'mergedClean'
  );
}

/** Pill label: "Never synced" / "Synced" / "Synced {relative time}". */
export function lastSyncedLabel(status: SyncStatusDto, nowMs: number): string {
  if (!status.hasState) return 'Never synced';
  if (status.lastStateWriteMs === null) return 'Synced';
  return `Synced ${formatRelativeTime(status.lastStateWriteMs, nowMs)}`;
}
```

- [ ] **Step 8: Run both suites + typecheck**

Run: `cd desktop && pnpm vitest run tests/sync.test.ts tests/format.test.ts && pnpm typecheck`
Expected: all PASS (note: `syncOutcomeMessage`'s switch is exhaustive over the union, so `tsc` covers the no-default-arm).

- [ ] **Step 9: Commit**

```bash
git add desktop/src/lib/format.ts desktop/src/lib/sync.ts desktop/tests/format.test.ts desktop/tests/sync.test.ts
git commit -m "D.1.14 Task 5 — pure sync helpers (outcome message, changed-data, last-synced label)"
```

---

## Task 6: TS IPC wrappers

**Files:**
- Modify: `desktop/src/lib/ipc.ts`
- Test: `desktop/tests/ipc.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `desktop/tests/ipc.test.ts` (follow the file's existing `invoke`-mock pattern; the snippet below shows the self-contained shape — adapt the mock import to match the file's existing `vi.mock('@tauri-apps/api/core')` setup):

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { syncStatus, syncNow } from '../src/lib/ipc';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
const mockInvoke = vi.mocked(invoke);

describe('ipc.ts — sync wrappers', () => {
  beforeEach(() => mockInvoke.mockReset());

  it('syncStatus invokes the sync_status command', async () => {
    mockInvoke.mockResolvedValue({ hasState: true, lastStateWriteMs: 123 });
    const dto = await syncStatus();
    expect(mockInvoke).toHaveBeenCalledWith('sync_status', undefined);
    expect(dto).toEqual({ hasState: true, lastStateWriteMs: 123 });
  });

  it('syncNow invokes sync_now with the password arg', async () => {
    mockInvoke.mockResolvedValue({ kind: 'nothingToDo' });
    const outcome = await syncNow('hunter2');
    expect(mockInvoke).toHaveBeenCalledWith('sync_now', { password: 'hunter2' });
    expect(outcome).toEqual({ kind: 'nothingToDo' });
  });

  it('syncNow re-throws a typed AppError on rejection', async () => {
    mockInvoke.mockRejectedValue({ code: 'sync_in_progress' });
    await expect(syncNow('hunter2')).rejects.toEqual({ code: 'sync_in_progress' });
  });
});
```

> If `tests/ipc.test.ts` already mocks `@tauri-apps/api/core` at the top, do NOT re-declare the mock — append only the new `describe` block and reuse the existing `mockInvoke` handle.

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm vitest run tests/ipc.test.ts -t "sync wrappers"`
Expected: FAIL — `syncStatus` / `syncNow` not exported.

- [ ] **Step 3: Add the wrappers**

In `desktop/src/lib/ipc.ts`, add the type import near the other lib imports:

```ts
import type { SyncStatusDto, SyncOutcome } from './sync';
```

Append the two wrappers (next to the other `call<T>` wrappers, e.g. after `revokeBlockFrom`):

```ts
export async function syncStatus(): Promise<SyncStatusDto> {
  return call<SyncStatusDto>('sync_status');
}

export async function syncNow(password: string): Promise<SyncOutcome> {
  return call<SyncOutcome>('sync_now', { password });
}
```

- [ ] **Step 4: Run to verify it passes + typecheck**

Run: `cd desktop && pnpm vitest run tests/ipc.test.ts && pnpm typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/ipc.ts desktop/tests/ipc.test.ts
git commit -m "D.1.14 Task 6 — syncStatus / syncNow IPC wrappers"
```

---

## Task 7: SyncPasswordDialog.svelte (the re-prompt modal)

**Files:**
- Create: `desktop/src/components/SyncPasswordDialog.svelte`
- Test: `desktop/tests/SyncPasswordDialog.test.ts`

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/SyncPasswordDialog.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import SyncPasswordDialog from '../src/components/SyncPasswordDialog.svelte';
import * as ipc from '../src/lib/ipc';

vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof ipc>()),
  syncNow: vi.fn()
}));
const mockSyncNow = vi.mocked(ipc.syncNow);

function renderDialog(overrides: Record<string, unknown> = {}) {
  const onSynced = vi.fn();
  const onCancel = vi.fn();
  const utils = render(SyncPasswordDialog, { props: { onSynced, onCancel, ...overrides } });
  return { ...utils, onSynced, onCancel };
}

describe('SyncPasswordDialog.svelte', () => {
  beforeEach(() => mockSyncNow.mockReset());

  it('opens a modal with a password field and a Sync button', async () => {
    const { container, getByLabelText, getByRole } = renderDialog();
    await waitFor(() => {
      const dialog = container.querySelector('dialog') as HTMLDialogElement;
      expect(dialog.hasAttribute('open')).toBe(true);
    });
    expect(getByLabelText(/password/i)).toBeTruthy();
    expect(getByRole('button', { name: /sync/i })).toBeTruthy();
  });

  it('calls syncNow with the typed password and onSynced with the outcome', async () => {
    mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
    const { getByLabelText, getByRole, onSynced } = renderDialog();
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'hunter2' } });
    await fireEvent.click(getByRole('button', { name: /^sync$/i }));
    await waitFor(() => expect(mockSyncNow).toHaveBeenCalledWith('hunter2'));
    expect(onSynced).toHaveBeenCalledWith({ kind: 'nothingToDo' });
  });

  it('renders the typed error inline and stays open on failure', async () => {
    mockSyncNow.mockRejectedValue({ code: 'wrong_password' });
    const { getByLabelText, getByRole, findByRole, onSynced } = renderDialog();
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'bad' } });
    await fireEvent.click(getByRole('button', { name: /^sync$/i }));
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/wrong password/i);
    expect(onSynced).not.toHaveBeenCalled();
  });

  it('fires onCancel when Cancel is clicked, without syncing', async () => {
    const { getByRole, onCancel } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(mockSyncNow).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm vitest run tests/SyncPasswordDialog.test.ts`
Expected: FAIL — component file does not exist.

- [ ] **Step 3: Implement the component**

Create `desktop/src/components/SyncPasswordDialog.svelte`:

```svelte
<script lang="ts">
  // Centered password re-prompt for "Sync now" (D.1.14). Native <dialog>
  // mirroring ConfirmDialog: callback props, showModal() on mount via
  // $effect, Esc → preventDefault + onCancel so the parent's unmount is the
  // single close route. The mutation is strict: a failure renders the typed
  // AppError inline and keeps the dialog open so the user can retry a
  // mistyped password. The password lives only in this component's state and
  // is cleared on success.
  import { syncNow } from '../lib/ipc';
  import { isAppError } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';
  import type { SyncOutcome } from '../lib/sync';

  type Props = {
    onSynced: (outcome: SyncOutcome) => void;
    onCancel: () => void;
  };
  let { onSynced, onCancel }: Props = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let password = $state('');
  let busy = $state(false);
  let error = $state<AppError | null>(null);

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) {
      dialogEl.showModal();
    }
  });

  function onNativeCancel(event: Event) {
    event.preventDefault();
    onCancel();
  }

  async function submit(event: Event) {
    event.preventDefault();
    if (busy || password.length === 0) return;
    busy = true;
    error = null;
    try {
      const outcome = await syncNow(password);
      password = '';
      onSynced(outcome);
    } catch (err) {
      error = isAppError(err) ? err : { code: 'internal' };
    } finally {
      busy = false;
    }
  }
</script>

<dialog bind:this={dialogEl} class="sync-dialog" oncancel={onNativeCancel}>
  <form class="sync-dialog__form" onsubmit={submit}>
    <h2 class="sync-dialog__title">Confirm your password</h2>
    <p class="sync-dialog__subtitle">Needed to sync this vault.</p>

    <label class="sync-dialog__label" for="sync-password">Password</label>
    <!-- svelte-ignore a11y_autofocus -->
    <input
      id="sync-password"
      class="sync-dialog__input"
      type="password"
      autocomplete="current-password"
      autofocus
      bind:value={password}
      disabled={busy}
    />

    {#if error}
      {@const msg = userMessageFor(error)}
      <p class="sync-dialog__error" role="alert">
        {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
      </p>
    {/if}

    <div class="sync-dialog__actions">
      <button type="button" class="sync-dialog__button" onclick={onCancel} disabled={busy}>
        Cancel
      </button>
      <button
        type="submit"
        class="sync-dialog__button sync-dialog__button--primary"
        disabled={busy || password.length === 0}
      >
        {busy ? 'Syncing…' : 'Sync'}
      </button>
    </div>
  </form>
</dialog>
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm vitest run tests/SyncPasswordDialog.test.ts`
Expected: 4 tests PASS.

- [ ] **Step 5: typecheck + svelte-check**

Run: `cd desktop && pnpm typecheck && pnpm svelte-check`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src/components/SyncPasswordDialog.svelte desktop/tests/SyncPasswordDialog.test.ts
git commit -m "D.1.14 Task 7 — SyncPasswordDialog (centered re-prompt, strict inline error)"
```

---

## Task 8: SyncPill.svelte (the combined indicator + trigger)

**Files:**
- Create: `desktop/src/components/SyncPill.svelte`
- Test: `desktop/tests/SyncPill.test.ts`

> **Design note (refines spec §5.1):** the in-flight "Syncing…" indication lives on the dialog's Sync button (Task 7), not on the pill — while a sync runs the modal is open over the dimmed app, so a second pill spinner would be hidden anyway. The pill therefore has two states: a label, and the modal-open state. After a data-changing outcome it calls the **global** `refreshManifest()` directly (no parent threading — `refreshManifest` is exported from `lib/stores`).

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/SyncPill.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import SyncPill from '../src/components/SyncPill.svelte';
import * as ipc from '../src/lib/ipc';
import * as stores from '../src/lib/stores';

vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof ipc>()),
  syncStatus: vi.fn(),
  syncNow: vi.fn()
}));
vi.mock('../src/lib/stores', async (orig) => ({
  ...(await orig<typeof stores>()),
  refreshManifest: vi.fn()
}));
const mockStatus = vi.mocked(ipc.syncStatus);
const mockSyncNow = vi.mocked(ipc.syncNow);
const mockRefresh = vi.mocked(stores.refreshManifest);

describe('SyncPill.svelte', () => {
  beforeEach(() => {
    mockStatus.mockReset();
    mockSyncNow.mockReset();
    mockRefresh.mockReset();
  });

  it('reads status on mount and renders the last-synced label', async () => {
    mockStatus.mockResolvedValue({ hasState: false, lastStateWriteMs: null });
    const { findByRole } = render(SyncPill);
    const btn = await findByRole('button', { name: /sync/i });
    await waitFor(() => expect(btn.textContent).toMatch(/never synced/i));
    expect(mockStatus).toHaveBeenCalledTimes(1);
  });

  it('opens the password dialog on click', async () => {
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    const { findByRole, container } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await waitFor(() => expect(container.querySelector('dialog')).not.toBeNull());
  });

  it('after a data-changing sync: toasts success, refreshes status + manifest', async () => {
    mockStatus
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: null })   // mount
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: Date.now() }); // post-sync
    mockSyncNow.mockResolvedValue({ kind: 'appliedAutomatically' });
    const { findByRole, getByLabelText, findByText } = render(SyncPill);

    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'pw' } });
    await fireEvent.click(await findByRole('button', { name: /^sync$/i }));

    expect(await findByText(/your vault is up to date/i)).toBeTruthy();
    await waitFor(() => expect(mockRefresh).toHaveBeenCalledTimes(1));
    expect(mockStatus).toHaveBeenCalledTimes(2);
  });

  it('does NOT refresh the manifest when the outcome changed nothing', async () => {
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
    const { findByRole, getByLabelText, findByText } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'pw' } });
    await fireEvent.click(await findByRole('button', { name: /^sync$/i }));
    expect(await findByText(/already up to date/i)).toBeTruthy();
    expect(mockRefresh).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm vitest run tests/SyncPill.test.ts`
Expected: FAIL — component does not exist.

- [ ] **Step 3: Implement the component**

Create `desktop/src/components/SyncPill.svelte`:

```svelte
<script lang="ts">
  // Combined sync indicator + trigger in the TopBar (D.1.14). The pill shows
  // the last-synced label and IS the "Sync now" control; clicking it opens
  // SyncPasswordDialog. Self-contained: reads sync_status on mount and after
  // each sync; on a data-changing outcome it calls the global refreshManifest
  // (the in-memory manifest goes stale when sync applies peer changes).
  import { onMount } from 'svelte';
  import { syncStatus } from '../lib/ipc';
  import { refreshManifest } from '../lib/stores';
  import {
    lastSyncedLabel,
    syncOutcomeMessage,
    syncChangedData,
    type SyncStatusDto,
    type SyncOutcome,
    type SyncMessage
  } from '../lib/sync';
  import SyncPasswordDialog from './SyncPasswordDialog.svelte';

  let status = $state<SyncStatusDto | null>(null);
  let dialogOpen = $state(false);
  let notice = $state<SyncMessage | null>(null);

  const label = $derived(status ? lastSyncedLabel(status, Date.now()) : 'Sync…');

  async function loadStatus() {
    try {
      status = await syncStatus();
    } catch {
      // Status is informational; a read failure leaves the prior label.
    }
  }

  onMount(loadStatus);

  async function onSynced(outcome: SyncOutcome) {
    dialogOpen = false;
    notice = syncOutcomeMessage(outcome);
    await loadStatus();
    if (syncChangedData(outcome)) {
      await refreshManifest();
    }
  }
</script>

<div class="sync-pill">
  <button
    type="button"
    class="sync-pill__button"
    onclick={() => { notice = null; dialogOpen = true; }}
    aria-label={`Sync now — ${label.toLowerCase()}`}
    title="Sync now"
  >
    <span class="sync-pill__icon" aria-hidden="true">↻</span>
    {label}
  </button>

  {#if notice}
    <span
      class="sync-pill__notice sync-pill__notice--{notice.kind}"
      role={notice.kind === 'success' ? 'status' : 'alert'}
    >
      {notice.text}
    </span>
  {/if}
</div>

{#if dialogOpen}
  <SyncPasswordDialog {onSynced} onCancel={() => (dialogOpen = false)} />
{/if}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm vitest run tests/SyncPill.test.ts`
Expected: 4 tests PASS.

- [ ] **Step 5: typecheck + svelte-check**

Run: `cd desktop && pnpm typecheck && pnpm svelte-check`
Expected: clean. (If `refreshManifest`'s exported name differs, fix the import to match `lib/stores`; it is imported as `refreshManifest` in `routes/Vault.svelte`.)

- [ ] **Step 6: Commit**

```bash
git add desktop/src/components/SyncPill.svelte desktop/tests/SyncPill.test.ts
git commit -m "D.1.14 Task 8 — SyncPill (status label + Sync trigger + post-sync refresh)"
```

---

## Task 9: Mount SyncPill in the TopBar

**Files:**
- Modify: `desktop/src/components/TopBar.svelte`
- Test: `desktop/tests/TopBar.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `desktop/tests/TopBar.test.ts` a check that the pill is mounted. Because `SyncPill` calls `syncStatus` on mount, stub it so the TopBar test stays isolated:

```ts
// At the top of the file, alongside any existing mocks:
vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof import('../src/lib/ipc')>()),
  syncStatus: vi.fn().mockResolvedValue({ hasState: false, lastStateWriteMs: null })
}));

// New test inside the existing describe('TopBar.svelte', …):
it('mounts the sync pill with a Sync control', async () => {
  const { findByRole } = render(TopBar, {
    props: { vaultLabel: '— personal.vault', onOpenSettings: vi.fn() }
  });
  expect(await findByRole('button', { name: /sync now/i })).toBeTruthy();
});
```

> If `TopBar.test.ts` already mocks `../src/lib/ipc`, merge `syncStatus` into that mock factory rather than adding a second `vi.mock` for the same module (only one mock per module path is honored).

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm vitest run tests/TopBar.test.ts -t "sync pill"`
Expected: FAIL — no "Sync now" button in the TopBar.

- [ ] **Step 3: Mount the pill**

In `desktop/src/components/TopBar.svelte`, import and place `<SyncPill />` first in `top-bar__right`:

```svelte
<script lang="ts">
  import LockButton from './LockButton.svelte';
  import Settings from './icons/Settings.svelte';
  import SyncPill from './SyncPill.svelte';
  // …existing Props…
</script>
```
```svelte
  <div class="top-bar__right">
    <SyncPill />
    <button
      type="button"
      class="top-bar__settings"
      onclick={onOpenSettings}
      title="Settings"
      aria-label="Settings"
    >
      <Settings />Settings
    </button>
    <LockButton />
  </div>
```

- [ ] **Step 4: Run to verify it passes + the full TopBar suite**

Run: `cd desktop && pnpm vitest run tests/TopBar.test.ts`
Expected: PASS (existing TopBar tests still green).

- [ ] **Step 5: typecheck + svelte-check + lint**

Run: `cd desktop && pnpm typecheck && pnpm svelte-check && pnpm lint`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src/components/TopBar.svelte desktop/tests/TopBar.test.ts
git commit -m "D.1.14 Task 9 — mount SyncPill in the TopBar"
```

---

## Task 10: Full gauntlet, docs, and manual GUI smoke

**Files:**
- Modify: `README.md`, `ROADMAP.md` (if they track the D-phase slice list)

- [ ] **Step 1: Run the full desktop gauntlet (frontend + Rust)**

Run:
```bash
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint && cd ..
cd desktop/src-tauri && cargo fmt --all --check && cargo clippy --tests -- -D warnings && cargo test && cd ../..
```
Expected: all green. (No core-workspace conformance run — this slice touches no `core`/`ffi`/`FfiVaultError`/UDL.)

- [ ] **Step 2: Update README / ROADMAP**

Mark D.1.14 ✅ (desktop sync UI: status pill + Sync-now modal) and advance "next" per the established README/ROADMAP convention (brief dot points — see [[feedback_readme_style]]). If the docs only track coarser milestones, make the smallest accurate edit; if nothing references the slice, skip and note "no doc change needed" in the commit.

- [ ] **Step 3: Manual GUI smoke (mandatory — this slice mutates)**

Per [[feedback_smoke_test_temp_copy_golden_vault]], the app stores settings *inside* the vault, so **never open the tracked fixture**. Stage a throwaway copy:

```bash
SMOKE_DIR="$(mktemp -d)/golden_smoke"
cp -R core/tests/data/golden_vault_001 "$SMOKE_DIR"
echo "Smoke vault at: $SMOKE_DIR  (password: 'correct horse battery staple')"
cd desktop && pnpm tauri dev
```

Verify:
- TopBar shows the pill — "Never synced" (or "Synced …") for the freshly-copied vault.
- Click the pill → centered modal appears; the app dims; focus is in the password field.
- Wrong password → inline `role="alert"` error ("Wrong password — …"); the dialog stays open.
- Esc and Cancel both close the dialog without syncing.
- Correct password → the modal closes and the pill shows the outcome notice (a single-device copy with no remote → "Already up to date").
- The records view still renders correctly afterward.

Record the result in the PR description.

- [ ] **Step 4: Commit any doc changes**

```bash
git add README.md ROADMAP.md
git commit -m "D.1.14 Task 10 — README/ROADMAP: desktop sync UI shipped; manual smoke green"
```

---

## Self-Review (completed by plan author)

**Spec coverage:** §3 in-scope items each map to a task — session `vault_folder` (T1), DTOs (T2), commands+registration (T3), TS errors (T4), pure helpers (T5), IPC wrappers (T6), modal (T7), pill (T8), TopBar (T9), docs+smoke (T10). §4.4 `SyncFailed` real copy → T4. §5.3 stale-manifest refresh → T8 (global `refreshManifest`). §7 seam-only hermetic testing → T2 (DTO wire-format) + T3 (NotUnlocked); end-to-end deferred to bridge tests + T10 smoke, as decided.

**Type consistency:** desktop Rust `SyncStatusDto { has_state, last_state_write_ms }` / tagged `SyncOutcomeDto` (T2) ↔ TS `SyncStatusDto { hasState, lastStateWriteMs }` / `SyncOutcome` `{ kind, vetoCount }` (T5) ↔ IPC wrapper return types (T6) ↔ component usage (T7/T8). Error codes `sync_*` consistent across T3 (Rust, already shipped in D.1.13) and T4 (TS). `refreshManifest` / `syncStatus` / `syncNow` / `syncOutcomeMessage` / `syncChangedData` / `lastSyncedLabel` / `formatRelativeTime` names match across their defining and consuming tasks.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; test code is concrete. The only deferred-to-implementation detail is matching each test file's *existing* `vi.mock` setup (flagged inline in T6/T9), which is a mechanical merge, not missing content.
