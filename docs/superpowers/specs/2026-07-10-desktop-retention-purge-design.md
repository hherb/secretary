# Desktop retention + per-block purge — design

**Date:** 2026-07-10
**Slice:** Sub-project D (desktop / Tauri 2 client)
**Depends on:** #406 (retention FFI projection) merged to `main` @ `1b769706`; #399/#403 purge lifecycle in `secretary-ffi-bridge`.
**Branch/worktree:** `feature/desktop-retention` in `.worktrees/desktop-retention/`.

## Summary

Wire three destructive trash operations into the Tauri desktop client, all consuming
`secretary-ffi-bridge` directly (the desktop backend depends on the bridge crate, not the
pyo3/uniffi bindings):

1. **Retention preview** — how many trashed blocks are past the retention window, and the
   oldest age, shown *before* any deletion.
2. **Retention commit** — permanently delete every trashed block past the window ("Run
   retention now").
3. **Per-block purge** — permanently delete one selected trashed block ("Delete forever").

The retention window is a new **configurable vault setting** (default 90 days). This is an
FFI-consuming UI slice only: **no core / crypto / on-disk-format change, no new
`FfiVaultError` variant, `#![forbid(unsafe_code)]` intact.**

## Non-goals (YAGNI)

- **Empty-trash ("delete all now")** — a distinct `empty_trash` bridge call; deferred to a
  later slice. Retention (past-window) + per-block purge cover this session's scope.
- **Automatic / scheduled retention** — all retention stays caller-invoked. An open-time or
  timer-driven auto-purge is an ADR + threat-model decision, out of scope (carried from the
  #402 core slice: the platform owns the *when*).
- **iOS / Android retention UX** — separate native slices over uniffi.
- **Inline "expired" badges in the trash list** — considered (Approach C) and rejected to
  avoid coupling retention rendering into the existing trash-list model/tests.

## FFI boundary

Consumed from `secretary_ffi_bridge` (Rust, in-process — no serialization boundary below the
Tauri command):

```rust
// pure, infallible, manifest-only, read-only — [] on a wiped handle
fn expired_trash_entries(manifest: &OpenVaultManifest, window_ms: u64, now_ms: u64)
    -> Vec<ExpiredEntry>;
// ExpiredEntry { block_uuid: [u8;16], tombstoned_at_ms: u64, age_ms: u64 }

// commit — snapshots manifest+identity, single manifest write; Err leaves handle byte-identical
fn auto_purge_expired(identity: &UnlockedIdentity, manifest: &OpenVaultManifest,
    window_ms: u64, now_ms: u64, device_uuid: [u8;16])
    -> Result<RetentionPurgeReport, FfiVaultError>;
// RetentionPurgeReport { purged_count, shared_count, owner_only_count, unknown_count,
//                        files_removed, files_failed: u32, window_ms: u64 }

// per-block commit
fn purge_block(identity: &UnlockedIdentity, manifest: &OpenVaultManifest,
    block_uuid: [u8;16], device_uuid: [u8;16], now_ms: u64)
    -> Result<PurgeReport, FfiVaultError>;

const DEFAULT_RETENTION_WINDOW_MS: u64; // 90 days, re-exported from secretary-core
```

`now_ms` is supplied by the desktop backend via the existing `crate::auto_lock::now_ms()`.
`window_ms` is read from vault settings (below). Both `auto_purge_expired` and `purge_block`
surface only `CorruptVault` / `FolderInvalid` / `SaveCryptoFailure` on the error path — all of
which already have arms in `desktop/src-tauri/src/errors/mapping.rs::map_ffi_error`, so **no new
`AppError` variant is expected** (verified during Task 1; a variant is added only if the
implementation surfaces a genuinely unmapped `FfiVaultError`).

## Architecture

### Retention preview → confirm flow (Approach A, two-step)

"Run retention now" opens a dedicated dialog that first calls the preview, shows the real count
+ oldest age, and only then offers an irreversible danger confirm. Rationale: the count matters
most for a *bulk* irreversible act, and the `expired_trash_entries` API exists precisely to make
the commit previewable. Per-block "Delete forever" is a single-item act, so it reuses the
existing generic `ConfirmDialog` with the block name in the body.

```
TrashView
  ├── "Run retention now" ──▶ RetentionDialog
  │        (open) previewRetention() ─▶ RetentionPreviewDto { entries, windowMs }
  │        render: "N items trashed more than X days ago will be permanently
  │                 deleted (oldest: Y days)."   |  empty → "Nothing to purge."
  │        (danger confirm) authorizeWrite() ─▶ runRetention() ─▶ RetentionReportDto
  │                                          ─▶ refreshManifest()
  └── per-row "Delete forever" ──▶ ConfirmDialog(block name)
           (confirm) authorizeWrite() ─▶ purgeBlock(hex) ─▶ refreshManifest()
```

### Backend (Rust / Tauri)

New, isolated modules (minimize overlap with the in-flight `feature/desktop-block-crud-ui`
branch, which heavily edits `edit.rs` and the pre-split `errors.rs`):

- **`desktop/src-tauri/src/commands/retention.rs`** — three commands, each a thin
  `#[tauri::command]` shell delegating to a testable `*_impl`, following the `delete.rs`
  `trash_block` template (`parse_uuid_16` → `lock_session` → `session.with_unlocked(|u| …)` →
  bridge call → `.map_err(map_ffi_error)`):
  - `preview_retention(state) -> Result<RetentionPreviewDto, AppError>` — reads the window from
    `session.current_settings()`, calls `expired_trash_entries`. Read/no-gate. Returns an empty
    entry list (not an error) when nothing is expired.
  - `run_retention(state) -> Result<RetentionReportDto, AppError>` — reads the window from
    settings, calls `auto_purge_expired`. Write.
  - `purge_block(state, block_uuid_hex) -> Result<PurgeReportDto, AppError>` — calls
    `purge_block`. Write.
- **`desktop/src-tauri/src/dtos/retention.rs`** — camelCase wire DTOs projecting bridge types
  across IPC. `block_uuid: [u8;16]` is hex-encoded (mirroring `TrashedBlockDto`); `u32` counts
  serialize as numbers:
  - `ExpiredEntryDto { blockUuidHex, tombstonedAtMs, ageMs }`
  - `RetentionPreviewDto { entries: Vec<ExpiredEntryDto>, windowMs }`
  - `RetentionReportDto { purgedCount, sharedCount, ownerOnlyCount, unknownCount, filesRemoved, filesFailed, windowMs }`
  - `PurgeReportDto { … }` (projecting `PurgeReport`)

Narrow edits to shared files:

- **`desktop/src-tauri/src/settings/parse.rs`** — add `retention_window_ms: u64` to `Settings`
  (Default = `RETENTION_WINDOW_DEFAULT_MS`, a parse arm with clamp-on-load warning, and a
  save-path bound check). A missing field on an older-client record falls back to the default
  with no warning (existing forward-compat behavior).
- **`desktop/src-tauri/src/constants.rs`** — `RETENTION_WINDOW_DEFAULT_MS` (re-export of the
  bridge `DEFAULT_RETENTION_WINDOW_MS`, so there is **no drift** between the FFI default and the
  desktop default), `RETENTION_WINDOW_MIN_MS`, `RETENTION_WINDOW_MAX_MS`, plus the
  `const _: () = assert!(min < default < max)` compile-time guards used by the other settings.
  Bounds: **min 1 day, max 3650 days (10 years), default 90 days.**
- **`desktop/src-tauri/src/dtos/manifest.rs`** — add `retention_window_ms` to `SettingsDto` and
  `SettingsInput` (and the `From` impls).
- **`desktop/src-tauri/src/main.rs`** — three `generate_handler!` entries:
  `retention::preview_retention`, `retention::run_retention`, `retention::purge_block`.
- **`desktop/src-tauri/src/dtos/mod.rs`, `commands/mod.rs`** — module wiring.

Error mapping stays exhaustive with no `_` catch-all (per the #40 convention).

### Frontend (Svelte / TypeScript)

New files:

- **`desktop/src/lib/retention.ts`** — pure helpers, no IPC/DOM (unit-tested in isolation):
  `retentionSummary(entries, windowMs)` → the human line, `oldestAgeMs(entries)`,
  `daysToMs(days)` / `msToDays(ms)` for the settings control, plus a small age-formatter (or
  reuse `formatTrashedWhen` from `trash.ts` if it fits).
- **`desktop/src/components/delete/RetentionDialog.svelte`** — the two-step dialog. On mount
  calls `previewRetention()` (loading state), renders the summary or an empty state, and a danger
  "Purge N items" button that runs `authorizeWrite(…)` → `runRetention()` → `refreshManifest()`,
  closing on success. Load/error/empty states modeled on `TrashView.svelte`; a generation guard
  (`loadSeq`) like `TrashView` if the dialog can re-preview.

Narrow edits:

- **`desktop/src/lib/ipc.ts`** — `previewRetention()`, `runRetention()`, `purgeBlock(blockUuidHex)`
  wrappers over `call<…>('preview_retention' | 'run_retention' | 'purge_block', …)`.
- **`desktop/src/lib/writeCommands.ts`** — classify `preview_retention` as `read`;
  `run_retention` and `purge_block` as **gated `write`** (bound to their `ipc.ts` wrappers).
  Mandatory: the #280 `writeGateCoverage` test fails if a registered command is unclassified.
- **`desktop/src/lib/errors.ts`** — only if a new `AppError` variant is introduced (not
  expected).
- **`desktop/src/components/delete/TrashView.svelte`** — a "Run retention now" button (mounts
  `RetentionDialog`) and a per-row "Delete forever" action wired to a `ConfirmDialog` (block name
  in the body) → `authorizeWrite` → `purgeBlock` → `refreshManifest`.
- **Settings UI** — a "Retention window" number input in **days** (converted via
  `retention.ts`), default 90, bounded by min/max; out-of-range save → existing
  `AppError::SettingsOutOfRange`. Added wherever the current settings form lives.

Both writes go through `authorizeWrite(...)` before the IPC call, exactly like `confirmTrash`,
catching `ReauthCancelled`.

## Error handling

- `preview_retention` is infallible at the bridge; the command still returns `Result` for the
  `NotUnlocked` / lock-poison paths (`lock_session`).
- `run_retention` / `purge_block` map bridge errors through the existing `map_ffi_error`
  (`CorruptVault` → `Internal`/`CorruptVault`, `FolderInvalid` → …, `SaveCryptoFailure` → …).
  No new variant expected; add one only if a genuinely unmapped `FfiVaultError` surfaces.
- Frontend renders all typed errors via the existing `userMessageFor(err)`; unknown errors fall
  back to `{ code: 'internal' }` as elsewhere.
- Partial file-removal (`files_failed > 0` in the report) is surfaced to the user as an
  informational note (the manifest commit still succeeded — the block is logically purged even if
  a stray ciphertext file lingered), not as an error.

## Testing (TDD, red-first)

**Backend (`cargo test --release --workspace`):**
- `commands/retention.rs`: per-`*_impl` — locked session → `NotUnlocked`; `preview_retention`
  returns projected entries (and empty list when nothing expired); `run_retention` / `purge_block`
  happy path returns the projected report; a bridge error maps to the expected `AppError`.
- `settings/parse.rs`: new `retention_window_ms` field parse, clamp-on-load warning, save-path
  bound rejection, and a full round-trip; the `const _: () = assert!(min<default<max)` guards.
- `dtos/retention.rs`: hex encoding of `block_uuid`, camelCase serialization shape.

**Frontend (`cd desktop && pnpm test` + `pnpm exec svelte-check`):**
- `lib/retention.ts`: `retentionSummary` wording, `oldestAgeMs`, `daysToMs`/`msToDays`
  round-trip + boundary (min/max days), empty-entry behavior.
- `RetentionDialog` component test: preview → confirm → `refreshManifest`; empty state renders
  "Nothing to purge"; error state renders `userMessageFor`.
- `TrashView` test: the two new buttons appear and are wired.
- `writeGateCoverage` / `writeCommands` extended automatically by the new classifications.

**Gates before PR (all must be green):**
```
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd desktop && pnpm test && pnpm exec svelte-check
```

## Collision awareness

The parallel `feature/desktop-block-crud-ui` worktree heavily edits `commands/edit.rs` and the
pre-`errors/`-split `errors.rs`, and adds `generate_handler!` entries. This slice avoids that
surface by using **new** modules (`commands/retention.rs`, `dtos/retention.rs`,
`lib/retention.ts`, `RetentionDialog.svelte`). Unavoidable shared touchpoints — `main.rs`,
`ipc.ts`, `writeCommands.ts`, `errors.ts`, `TrashView.svelte`, settings files — are edited as
narrowly as possible (append-only where feasible) to keep any eventual merge trivial.

## Risks / open items

- **`purge_block` error set** — assumed to be a subset of `{CorruptVault, FolderInvalid,
  SaveCryptoFailure}`. Task 1 verifies against the bridge; if it surfaces `BlockNotInTrash` or
  `BlockPurged` for an already-purged block, those already map (`TrashEntryNotFound` /
  `BlockPurged`) — no new variant, but the frontend messaging is checked.
- **Settings schema growth** — adding a settings field is forward-compatible by the existing
  design (unknown fields warn, missing fields default); no manifest-version bump.
- **Retention window bounds** — min 1 day prevents a footgun (a 0-day window would purge
  everything on the next run); max 10 years is a sanity ceiling. Adjustable if review disagrees.
```
