# Desktop block-CRUD UI — design

**Date:** 2026-06-20
**Branch:** `feature/desktop-block-crud-ui` (worktree `.worktrees/desktop-block-crud-ui`), off `main` @ `7076cc27`.
**Status:** approved design; implementation plan to follow.

## Problem

The three block-CRUD operations — `create_block` / `rename_block` / `move_record` —
exist as FFI primitives in `secretary-ffi-bridge` and already have UI affordances on
**Android** (PR #268) and **iOS** (PR #270). The **desktop** Tauri app has only the
create affordance wired end-to-end (`create_block` command + `ipc.ts` `createBlock`
wrapper + `NewBlock.svelte` dialog). **Rename block** and **move record** are not yet
reachable from the desktop UI. This slice completes the tier on the third platform.

This is a **desktop-UI-only slice** over already-shipped, already-reviewed bridge ops.
It does **not** touch `core/`, the crypto/vault spec, any `*.udl`, the uniffi/pyo3
projections, Android, or iOS.

## Key constraints discovered

- **Desktop calls the FFI _bridge_ directly** (`secretary-ffi-bridge`, already a path
  dependency in `desktop/src-tauri/Cargo.toml`), **not** the uniffi wrapper. The
  same-block-move guard and UUID-length checks that the uniffi _namespace_ layer
  enforces for Android/iOS are therefore **not** on the desktop path. The bridge has no
  `InvalidArgument` and trusts its caller. Desktop must enforce those guards itself.
- **No `invalid_argument` variant exists** in the desktop `AppError`. It is a
  discriminated union mirrored on both sides: Rust `desktop/src-tauri/src/errors.rs`
  (`enum AppError`) and TS `desktop/src/lib/errors.ts` (`type AppError` union +
  `APP_ERROR_CODES` array). A new typed variant must be added to both.
- **`list_blocks`** already exists (`ipc.ts` `listBlocks(): Promise<BlockSummaryDto[]>`)
  and is the source for the move-target picker (source block excluded).
- Desktop's existing convention is **component-local logic calling `ipc.ts` directly**
  (no separate VM/model layer like Android/iOS), with **vitest** component tests and
  Rust `*_impl` integration tests against the golden vault.
- **No e2e:** tauri-driver has no macOS WKWebView support, so there is no rendered
  end-to-end harness on this platform (carried known limitation).

## Design

### Layer 1 — Rust Tauri commands (`desktop/src-tauri/src/commands/edit.rs`)

Two new commands, each with a pure-ish testable `*_impl` helper (mirroring the existing
`create_block` / `create_block_impl` pattern), calling the already-available
`secretary-ffi-bridge` primitives:

- `rename_block(block_uuid_hex: String, new_name: String)`
- `move_record(source_block_uuid_hex: String, target_block_uuid_hex: String, source_record_uuid_hex: String)`

**Authoritative guards** (this is the authoritative half of the defense-in-depth):

- `rename_block`: blank/whitespace-only `new_name` → `AppError::InvalidArgument`.
- `move_record`: `source_block_uuid_hex == target_block_uuid_hex` → `AppError::InvalidArgument`.
- UUID-length / non-hex inputs are rejected when decoding hex into the bridge's
  `&[u8; N]` arguments (existing hex-decode error path; surfaced as the existing
  decode/`invalid`-style error already used by sibling commands).

Return shapes follow the sibling commands (e.g. `move_record` returns the new record
uuid hex like the uniffi/iOS surface does; `rename_block` returns the updated
`BlockSummaryDto` if the create sibling's return convention warrants it — pinned in the
plan against the actual `create_block` signature).

### Layer 2 — New typed error `AppError::InvalidArgument`

- Rust `desktop/src-tauri/src/errors.rs`: add `InvalidArgument { detail: String }` to
  `enum AppError` with the `#[serde(tag = "code", rename_all = "snake_case")]`
  projection → wire code `invalid_argument`. Map it in any exhaustive `match` over
  `AppError` (detail-stripping/conversion sites).
- TS `desktop/src/lib/errors.ts`: add `| { code: 'invalid_argument'; detail: string }`
  to the `AppError` union **and** `'invalid_argument'` to `APP_ERROR_CODES` (so
  `KNOWN_ERROR_CODES` recognises it and it is not coerced to `internal`).

**Scope:** desktop-only. This is **not** `FfiVaultError`; the cross-language
Swift/Kotlin conformance harnesses and pyo3/uniffi projections are untouched.

### Layer 3 — IPC wrappers (`desktop/src/lib/ipc.ts`)

- `renameBlock(blockUuidHex: string, newName: string): Promise<...>`
- `moveRecord(sourceBlockUuidHex: string, targetBlockUuidHex: string, sourceRecordUuidHex: string): Promise<...>`

Both via the existing `call<T>(...)` helper so the discriminated-union error mapping
(including the new `invalid_argument`) flows through unchanged.

### Layer 4 — Pure frontend validation (`desktop/src/lib/blockCrud.ts`, new)

Reusable pure functions used by the components for the **pre-check** half of
defense-in-depth (keeps the dialog/picker open with no IPC round-trip):

- `isBlankName(name: string): boolean` — true for empty/whitespace-only.
- `isSameBlock(sourceUuidHex: string, targetUuidHex: string): boolean`.

These are unit-tested in isolation. The frontend pre-check and the Rust authoritative
guard intentionally enforce the same rule (defense in depth) — duplication is deliberate
and documented.

### Layer 5 — UI (desktop idioms: buttons + modal dialogs)

- **Generalize `NewBlock.svelte` → `BlockNameDialog.svelte`** with a mode discriminant
  `{ kind: 'create' } | { kind: 'rename'; block: BlockSummaryDto }`. Rename mode
  pre-fills the current name; confirm calls `renameBlock` (or `createBlock` for create).
  Blank-name pre-check via `isBlankName` keeps the dialog open. Update existing call
  sites; **re-run the existing `NewBlock` vitest test** (migrated) to prove the create
  flow did not regress.
- **"Rename" button** per block on `BlockCard.svelte`, disabled while a write is in
  flight; opens `BlockNameDialog` in rename mode.
- **"Move" button** per **live** record in `RecordRow.svelte` (next to Delete), disabled
  while writing; opens the new `MoveTargetPicker.svelte`.
- **`MoveTargetPicker.svelte`** (new modal): lists candidate target blocks from
  `listBlocks()` with the **source block excluded**; selecting one calls `moveRecord`.
  Same-block selection is impossible by construction (excluded), with the Rust guard as
  backstop.
- **After a successful move:** re-read the **source** block so the moved record shows
  tombstoned (matches iOS); clear the picker.

### Validation rules (parity with Android/iOS)

1. Blank/whitespace name → `invalid_argument`, no write, dialog stays open.
2. Same-block move → `invalid_argument`, no write, picker stays open.
3. Write failure → dialog/picker stays open, error surfaced, retryable.
4. Success → reload affected block list/record view, clear dialog/picker.

## Testing

- **vitest** (`desktop/tests/*.test.ts`, mocking `@tauri-apps/api/core` `invoke` per the
  established hoisted-mock pattern):
  - `BlockNameDialog` — create path (migrated from `NewBlock.test.ts`), rename path with
    name pre-fill, blank-name pre-check (no `invoke` call, dialog stays open).
  - `MoveTargetPicker` — candidate list excludes the source block; selecting a target
    invokes `move_record` with the right args.
  - `RecordRow` — Move button present on live records, absent/disabled appropriately.
  - `blockCrud.ts` pure-fn unit tests (`isBlankName`, `isSameBlock`).
- **Rust integration** (`desktop/src-tauri/tests/ipc_integration.rs`): `rename_block` and
  `move_record` `*_impl` against a **temp copy** of `golden_vault_001` (copy via
  `cp -R` to a tempdir first — the tracked fixture is a frozen KAT and the app writes
  settings into the vault; never mutate it in place). Assert:
  - create→move→read-back: the moved record's field value is readable in the target
    block and the source record is tombstoned.
  - `rename_block` with a blank name → `AppError::InvalidArgument`.
  - `move_record` with `source == target` → `AppError::InvalidArgument`.
- **No e2e** (tauri-driver macOS limitation).

## Out of scope / non-goals

- No changes to `core/`, crypto/vault spec, `*.udl`, uniffi/pyo3 projections, Android, iOS.
- No new bridge variant (`secretary-ffi-bridge` trusts its caller; validation lives at
  the desktop binding/command + frontend, per the project's input-validation convention).
- No rendered end-to-end test (platform limitation).
- Block create affordance is already shipped; this slice reuses/generalizes it but does
  not re-spec it.

## Docs

- README row + ROADMAP entry matching the Android/iOS block-CRUD sibling rows.

## Deliberate decisions (so a future reader does not "fix" them)

- **Defense in depth on validation**: the Rust command is the authoritative guard
  returning `AppError::InvalidArgument`; the frontend pure-fn pre-check is a UX layer
  that avoids a round-trip and keeps the dialog open. Both enforce the same rule on
  purpose.
- **Blank-name rejection is a UI policy** — the FFI/spec permit empty block names; the
  desktop UI rejects them for usability + cross-platform parity (matches Android/iOS).
- **Generalize `NewBlock` rather than duplicate** — one `BlockNameDialog` for
  create+rename, DRY, guarded by re-running the create test.
- **New `AppError::InvalidArgument` is desktop-scoped** — not `FfiVaultError`; no
  conformance-harness impact.
- **Move semantics** (from the bridge): copy-to-target-under-a-fresh-uuid + tombstone in
  source. The read-back asserts the field _value_, not the uuid.
