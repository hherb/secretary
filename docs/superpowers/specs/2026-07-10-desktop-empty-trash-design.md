# Desktop empty-trash UX — design

**Date:** 2026-07-10
**Branch:** `feature/desktop-empty-trash` (off `main` @ `63a20ac4`, after #409 merged)
**Follows:** the #409 desktop retention/purge slice — this closes the one trash
destructive op that slice deferred (`empty_trash`, NEXT_SESSION §2.1).

## Summary

Wire the already-projected `secretary-ffi-bridge::empty_trash` orchestrator
into the Tauri desktop client's Trash view: an **"Empty trash"** button that
permanently deletes every currently-trashed block in one batch, behind the
existing password re-auth write gate.

This is an **FFI-consuming UI slice only**:
- No `core` / crypto / on-disk-format change.
- No new `FfiVaultError` / `AppError` variant — `empty_trash`'s bridge errors
  (`CorruptVault` / `FolderInvalid` / `SaveCryptoFailure`) all map through the
  existing `map_ffi_error` arms.
- `#![forbid(unsafe_code)]` intact.
- No `manifest_version` bump; no KEM / signature-site / equal-clock change.

## Why simpler than retention

The #409 retention flow is **two-step** (preview → commit) because it applies a
*window filter*: the user must see *which* blocks are past the configured
retention window before committing. Empty-trash has **no filter** — every
trashed block goes. The total count is already known from the loaded trash list
(`entries.length`), so a single `ConfirmDialog` showing the count is sufficient.
This mirrors the per-block "Delete forever" flow exactly.

**UX decision (confirmed with user):** single confirm, silent reload. After the
purge the trash list reloads and shows "Trash is empty." — the empty list is the
success signal. The returned `EmptyTrashReport` counts are **not** surfaced in a
result dialog (parity with `purgeBlock`, whose report is likewise ignored in the
UI).

## The bridge surface (already shipped, unchanged)

```rust
// ffi/secretary-ffi-bridge/src/purge/orchestration.rs
pub fn empty_trash(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<EmptyTrashReport, FfiVaultError>;

pub struct EmptyTrashReport {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
}
```

`empty_trash` performs a single manifest commit covering every target (the
normative sequence lives in `secretary_core::vault::empty_trash`). It takes no
`block_uuid` — it targets the entire trash in one call.

## Components

### Backend — `desktop/src-tauri/`

1. **DTO** — `EmptyTrashReportDto` in `src/dtos/retention.rs`
   - `From<&EmptyTrashReport>`, `#[serde(rename_all = "camelCase")]`.
   - Projects only counts: `purgedCount`, `sharedCount`, `ownerOnlyCount`,
     `unknownCount`, `filesRemoved`, `filesFailed`.
   - No UUID, no window, **no plaintext** — no secret widening.
   - Serde/camelCase unit test mirroring the existing `RetentionReportDto` test.

2. **Command** — `empty_trash` in `src/commands/retention.rs`
   ```rust
   #[tauri::command]
   pub async fn empty_trash(
       state: State<'_, Mutex<VaultSession>>,
   ) -> Result<EmptyTrashReportDto, AppError> {
       empty_trash_impl(state.inner())
   }

   pub fn empty_trash_impl(
       state: &Mutex<VaultSession>,
   ) -> Result<EmptyTrashReportDto, AppError> {
       let session = lock_session(state)?;
       session.with_unlocked(|u| {
           // NOTE arg order: `bridge_empty_trash(identity, manifest,
           // device_uuid, now_ms)` — device_uuid is [u8;16], now_ms is u64,
           // so the two are distinct types and cannot swap silently. Guard
           // comment kept for parity with the run_retention / purge_block
           // siblings, whose same-type args CAN swap.
           let report =
               bridge_empty_trash(&u.identity, &u.manifest, u.device_uuid, now_ms())
                   .map_err(map_ffi_error)?;
           Ok(EmptyTrashReportDto::from(&report))
       })
   }
   ```
   - Import `empty_trash as bridge_empty_trash` from `secretary_ffi_bridge`.

3. **Handler wiring** — add `empty_trash` to `generate_handler!` in the command
   registration site (same list the retention commands were added to).
   - Error mapping unchanged: `map_ffi_error` already covers every error
     `empty_trash` can surface. **No new variant.**

### Frontend — `desktop/src/`

4. **Pure helper** — `emptyTrashConfirmBody(count: number): string` in
   `src/lib/trash.ts`
   - Pluralized: `count === 1` → "The 1 item in trash will be permanently
     deleted. This cannot be undone."; else "All N items in trash will be
     permanently deleted. This cannot be undone."
   - No IPC / DOM. Unit-tested in `trash.test.ts` (n=0 guard not needed — the
     button only renders when the list is non-empty, but test n=1 and n=2 for
     the pluralization boundary).

5. **IPC** — `src/lib/ipc.ts`
   - `EmptyTrashReportDto` interface (camelCase, mirrors the Rust DTO).
   - `emptyTrash(): Promise<EmptyTrashReportDto>` → `call('empty_trash', {})`.

6. **Write-gate classification** — `src/lib/writeCommands.ts`
   - `empty_trash: { kind: 'write', gate: 'gated', wrapper: 'emptyTrash' }`.
   - Satisfies the #280 static write-gate coverage test (`writeGateCoverage`).

7. **UI** — `src/components/delete/TrashView.svelte`
   - An **"Empty trash"** button, rendered **only when `entries` is non-empty**
     (there is nothing to empty otherwise), placed alongside "Run retention now".
   - Click → `pendingEmpty = true`.
   - Reuse `ConfirmDialog`:
     - title `"Empty trash?"`
     - body from `emptyTrashConfirmBody(entries.length)`
     - confirmLabel `"Empty trash"`
   - `confirmEmpty()` mirrors `confirmPurge()`:
     ```
     authorizeWrite('Confirm permanently deleting all trashed blocks')
       — catch ReauthCancelled → return; other error → surface
     emptyTrash()            (report ignored)
     refreshManifest()
     load()                  (trash now empty → "Trash is empty.")
     ```

## Security properties (to verify in review)

- **Write-gated**: the irreversible `empty_trash` goes through `authorizeWrite`;
  `ReauthCancelled` aborts. Enforced by `writeGateCoverage` (green) via the
  `writeCommands.ts` classification.
- **Exhaustive error mapping / no new variant**: `empty_trash` surfaces only
  errors already mapped by `map_ffi_error`.
- **No secret widening**: `EmptyTrashReportDto` is counts only — no plaintext,
  no UUID.
- **Arg-order integrity**: `empty_trash`'s trailing args (`device_uuid: [u8;16]`,
  `now_ms: u64`) are distinct types → no silent swap hazard (unlike the
  same-type hazards the retention/purge commands carry). Guard comment kept for
  parity.

## Testing (TDD)

- **Rust**: `EmptyTrashReportDto` serde/camelCase test (asserts camelCase keys,
  no snake_case leak). Command impl follows the existing `commands/retention.rs`
  test shape if one exists; otherwise the DTO test + the workspace build/clippy
  gates cover the wiring.
- **TS**: `trash.test.ts` for `emptyTrashConfirmBody` (n=1 singular, n=2 plural).
  `writeCommands` coverage stays green. `svelte-check` 0/0. Full `pnpm test`.

## Acceptance (from the worktree root)

```bash
cargo fmt --all -- --check
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
cd desktop && pnpm test && pnpm exec svelte-check
```

## Out of scope

- iOS / Android empty-trash UX (native over uniffi) — separate per-platform
  slices (NEXT_SESSION §2.2).
- Surfacing the `EmptyTrashReport` counts in a result dialog — deliberately not
  done (empty list is the success signal; parity with per-block purge).
- Any automatic / scheduled empty-trash — all purge remains caller-invoked
  (a deferred ADR + threat-model decision).
