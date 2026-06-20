# Android block-CRUD UI affordances — design

**Date:** 2026-06-20
**Branch:** `feature/android-block-crud-ui` (worktree `.worktrees/android-block-crud-ui`, from `main` @ `19a1ddc2`)
**Scope:** Android only. Wire the three already-shipped FFI block-CRUD ops into the Compose browse UI. **No `core/`, crypto/vault spec, UDL, pyo3, or iOS change.**

## Background

The three block-CRUD primitives — `create_block`, `rename_block`, `move_record` — are projected onto the uniffi binding (`uniffi.secretary.{createBlock, renameBlock, moveRecord}`, PR #266) and onto pyo3 (PR #267). They are **FFI-only**: no platform UI exposes them. This slice adds the Android UI affordance over the existing browse/edit stack. iOS is a deliberate follow-up (mirror slice, next session).

The existing Android browse stack is cleanly layered, and this design follows it exactly:

| Layer | File | Role |
|---|---|---|
| FFI seam (port) | `android/vault-access/.../browse/VaultOpenPort.kt` | `VaultSession` interface; `appendRecord` mints its UUID + resolves device-uuid/now-ms inside the impl |
| Real adapter | `android/kit/.../browse/UniffiVaultOpenPort.kt` | `UniffiVaultSession`; `write { dev, now -> … }` resolves device-uuid, stamps now-ms, serializes under `sessionLock`, maps errors |
| Pure model | `android/vault-access/.../browse/VaultBrowseModel.kt` | host-tested StateFlows; `commitThenReload` re-reads on success only |
| androidx VM | `android/browse-ui/.../ui/VaultBrowseViewModel.kt` | thin bridge; launches suspend funs on `viewModelScope` |
| Compose UI | `android/browse-ui/.../ui/BrowseScreen.kt` | two-state (block list ↔ record list) + edit-form overlay; every action has a `testTag` |
| Error type | `android/vault-access/.../browse/VaultBrowseError.kt` | sealed; already has `BlockNotFound` / `InvalidArgument` / `RecordNotFound` / `SaveCryptoFailure` / `CorruptVault` |

## FFI signatures consumed (unchanged)

From `ffi/secretary-ffi-uniffi/src/secretary.udl`:

```
[Throws=VaultError] void create_block(identity, manifest, bytes block_uuid /*16*/, string block_name, bytes device_uuid /*16*/, u64 now_ms);
[Throws=VaultError] void rename_block(identity, manifest, bytes block_uuid /*16*/, string new_block_name, bytes device_uuid /*16*/, u64 now_ms);
[Throws=VaultError] void move_record(identity, manifest, bytes source_block_uuid /*16*/, bytes target_block_uuid /*16*/, bytes source_record_uuid /*16*/, bytes new_record_uuid /*16*/, bytes device_uuid /*16*/, u64 now_ms);
```

Semantics (from the bridge): `create_block` is insert-or-update on uuid collision; `rename_block` throws `BlockNotFound` on an absent block; `move_record` is copy-to-target then tombstone-in-source, and throws `RecordNotFound` if the source record is absent/already tombstoned, `InvalidArgument` on a same-block move or wrong-length uuid.

## Design

### § 1 — `VaultSession` port (`:vault-access`)

Add three methods, mirroring `appendRecord`'s contract (UUID minted inside the impl so the pure model stays deterministic; device-uuid + now-ms resolved inside the impl):

```kotlin
/** Create an empty block named [blockName]; mints (SecureRandom) + returns its fresh 16-byte UUID.
 *  Device-uuid + now-ms resolved inside the impl. */
suspend fun createBlock(blockName: String): ByteArray

/** Rename the block identified by [blockUuid] to [newName]. `BlockNotFound` if absent.
 *  Device-uuid + now-ms resolved inside the impl. */
suspend fun renameBlock(blockUuid: ByteArray, newName: String)

/** Move the live record [sourceRecordUuid] from [sourceBlockUuid] into [targetBlockUuid], minting
 *  (SecureRandom) + returning the fresh target record UUID. Copy-to-target then tombstone-in-source.
 *  Caller guarantees source != target (the model + the picker enforce it). Device-uuid + now-ms
 *  resolved inside the impl. */
suspend fun moveRecord(sourceBlockUuid: ByteArray, targetBlockUuid: ByteArray, sourceRecordUuid: ByteArray): ByteArray
```

### § 2 — Real adapter `UniffiVaultSession` (`:kit`)

Implement via the existing `write { dev, now -> … }` helper and `SecureRandom`, plus three import aliases (`import uniffi.secretary.createBlock as ffiCreateBlock`, etc.):

```kotlin
override suspend fun createBlock(blockName: String): ByteArray =
    write { dev, now ->
        val blockUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
        ffiCreateBlock(identity, manifest, blockUuid, blockName, dev, now)
        blockUuid
    }

override suspend fun renameBlock(blockUuid: ByteArray, newName: String) =
    write { dev, now -> ffiRenameBlock(identity, manifest, blockUuid, newName, dev, now) }

override suspend fun moveRecord(
    sourceBlockUuid: ByteArray, targetBlockUuid: ByteArray, sourceRecordUuid: ByteArray,
): ByteArray =
    write { dev, now ->
        val newRecordUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
        ffiMoveRecord(identity, manifest, sourceBlockUuid, targetBlockUuid, sourceRecordUuid, newRecordUuid, dev, now)
        newRecordUuid
    }
```

`write {}` already throws `VaultBrowseError.Failed("write on a wiped session")` on the wipe race and surfaces a missing `DeviceUuidProvider` as a typed error. **Writes therefore require the device-uuid-provider factory** `uniffiVaultOpenPort(deviceUuids)` — the same precondition delete/restore/edit already have.

### § 3 — Pure model `VaultBrowseModel` (`:vault-access`, host-tested)

**New presentation state** (two StateFlows):

```kotlin
sealed interface BlockNameDialogState {
    data object CreateBlock : BlockNameDialogState
    data class RenameBlock(val blockUuid: ByteArray, val currentName: String) : BlockNameDialogState
}
val blockNameDialog: StateFlow<BlockNameDialogState?>   // null = closed
val movingRecord: StateFlow<RecordSummaryView?>         // non-null = move picker open; picker lists `blocks` minus the source block
```

**New actions:**

- `startCreateBlock()` → `blockNameDialog = CreateBlock`
- `startRenameBlock(block)` → `blockNameDialog = RenameBlock(block.uuid, block.name)`
- `cancelBlockNameDialog()` → `blockNameDialog = null`
- `suspend confirmBlockName(name)` — trims; **rejects blank** (`VaultBrowseError.InvalidArgument("block name is empty")`, no write, dialog stays open); else dispatches `createBlock` / `renameBlock` per the dialog state, closes the dialog, then `loadBlocks()` to refresh the manifest summaries.
- `startMoveRecord(record)` → `movingRecord = record`
- `cancelMove()` → `movingRecord = null`
- `suspend confirmMove(target)` — **defensive guard** `target.uuid != selectedBlock.uuid` (else `InvalidArgument`, no write — the picker already excludes the source, this is belt-and-suspenders mirroring `move_record`'s wrapper rule); else `session.moveRecord(sourceBlock.uuid, target.uuid, record.uuid)`, closes the picker, then re-reads the **source** block so the moved record shows tombstoned/withheld there.

**Refactor (in-scope):** extract the re-entrancy + error-preservation core of `commitThenReload` into:

```kotlin
private suspend fun guardedWrite(reload: suspend () -> Unit, op: suspend () -> Unit) {
    if (_writing.value) return
    _writing.value = true
    try {
        try { op() } catch (e: VaultBrowseError) { _error.value = e; return }
        reload()
    } finally { _writing.value = false }
}
```

`commitThenReload` becomes `guardedWrite(reload = { selectBlock(block) }) { op(block) }` (after the existing `selectedBlock == null` early-return), preserving identical behavior. Create/rename use `reload = { loadBlocks() }`; move uses `reload = { selectBlock(sourceBlock) }`. The `writing` flag thus disables all write buttons (block-list and record-list) during any in-flight block-CRUD write, exactly as for delete/restore.

`lock()` additionally resets `blockNameDialog` and `movingRecord` to null.

### § 4 — androidx VM + Compose UI (`:browse-ui`)

**`VaultBrowseViewModel`** — re-expose `blockNameDialog` and `movingRecord`; delegate the non-suspend actions directly and launch the suspend ones on `viewModelScope` (no logic; mirrors the existing class):

```kotlin
val blockNameDialog = model.blockNameDialog
val movingRecord = model.movingRecord
fun startCreateBlock() = model.startCreateBlock()
fun startRenameBlock(block: BlockSummaryView) = model.startRenameBlock(block)
fun cancelBlockNameDialog() = model.cancelBlockNameDialog()
fun confirmBlockName(name: String) { viewModelScope.launch { model.confirmBlockName(name) } }
fun startMoveRecord(record: RecordSummaryView) = model.startMoveRecord(record)
fun cancelMove() = model.cancelMove()
fun confirmMove(target: BlockSummaryView) { viewModelScope.launch { model.confirmMove(target) } }
```

**`BrowseScreen`** additions:

- Block-list state: a **"New block"** `TextButton` in the header (`testTag "new-block"`, disabled while `writing`). Each `BlockRow` gains a trailing **"Rename"** `TextButton` (`"rename-<uuidHex>"`); tapping the block name still selects it.
- Record-list state: each non-tombstoned `RecordRow` gains a **"Move"** `TextButton` (`"move-<uuidHex>"`, disabled while `writing`) alongside Edit/Delete.
- Render the dialogs from the collected state flows.

**New file `BlockCrudDialogs.kt`** (keeps `BrowseScreen` focused — one-concept-per-file; `BrowseScreen` is already ~237 lines):

- `BlockNameDialog(state, onConfirm, onCancel)` — `AlertDialog` with an `OutlinedTextField` seeded from `currentName` for rename / empty for create. Tags: `block-name-field`, `block-name-confirm`, `block-name-cancel`. Title reflects create vs rename.
- `MovePickerDialog(record, blocks, sourceBlockUuidHex, onPick, onCancel)` — `AlertDialog` listing `blocks` **excluding** the source; each a clickable row (`"move-target-<uuidHex>"`); Cancel button.

### § 5 — Error handling

No new `VaultBrowseError` variant — every FFI error these ops throw (`BlockNotFound` / `InvalidArgument` / `RecordNotFound` / `SaveCryptoFailure` / `CorruptVault`) already exists and is covered by the uniffi→domain mapper (`mapVaultBrowseError`). Client-side validation (blank name, same-block move) lives in the **model** and surfaces `InvalidArgument`, mirroring the project rule that input validation lives at the binding wrapper, not the bridge. A failed write surfaces via `error` and leaves the visible list intact (the `guardedWrite` reloads on success only).

### § 6 — Tests (TDD)

**Host (no emulator) — the bulk of the logic:**

- Extend the host fakes (`android/browse-ui/src/test/.../FakeVaultSession.kt` and `android/vault-access/src/test/.../FakeVaultBrowse.kt`) to mutate an in-memory block/record map for `createBlock` / `renameBlock` / `moveRecord`, and to be configurable to throw typed errors (`BlockNotFound`, etc.) for error paths.
- New `VaultBrowseModelBlockCrudTest`:
  - **create:** `startCreateBlock` → `confirmBlockName("Work")` → `blocks` now contains "Work"; blank/whitespace name → `InvalidArgument`, no write, dialog stays open.
  - **rename:** `startRenameBlock(block)` → `confirmBlockName("Renamed")` → name changed in `blocks`, records preserved; absent block → `BlockNotFound` surfaced via `error`.
  - **move:** select source, `startMoveRecord(record)`, `confirmMove(target)` → source re-read shows the record tombstoned/withheld, fake target holds the copy under a fresh uuid; same-block guard → no write + `InvalidArgument`.
  - **re-entrancy:** a second action while `writing` is a no-op.
  - **lock:** resets `blockNameDialog` + `movingRecord`.
- `VaultBrowseViewModelTest` additions: the new methods delegate / launch correctly.

**Instrumented (emulator) — acceptance gate:** one Compose UI round-trip in `:browse-ui` (or `:kit`) androidTest driving the real `UniffiVaultSession` (with a wired `DeviceUuidProvider`) over a **temp copy** of the golden vault (never the tracked fixture):

1. Tap `new-block`, type a name, confirm → the new block appears in the list.
2. Enter a source block, tap `move-<uuidHex>` on a record, pick the new block in the picker.
3. Navigate into the new block → assert the record is present and its value reads back.
4. Assert the source block (show-deleted on) shows the record tombstoned.

Uses absolute `adb`/emulator paths (not on bare PATH on this machine).

## Acceptance criteria

- `./gradlew :vault-access:test :browse-ui:test` green (host).
- New `VaultBrowseModelBlockCrudTest` + VM delegation tests pass.
- Instrumented Compose round-trip green on the emulator (create → move → read-back; source tombstoned).
- Guardrail empty: `git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|ios/'` → nothing.
- `cargo`/clippy untouched (no Rust change).
- README + ROADMAP gain a row for the Android block-CRUD UI affordance.

## Out of scope / deferred

- **iOS** mirror slice (next session).
- Inline-edit / multi-select / drag-and-drop UX (YAGNI — dialogs chosen).
- Decrypted-block residency on move (tracked in #251).
- Biometric re-auth before a write (ROADMAP C.3 remaining).

## Risks / decisions

- **Move re-read shows the source record tombstoned, not gone** — `move_record` is copy-then-tombstone, so with show-deleted off it simply disappears from the source list; the test asserts both the disappearance (live view) and the tombstone (show-deleted view).
- **`new_record_uuid` is minted fresh** — the moved record has a new uuid in the target block (per the FFI contract). Read-back asserts on the *value*, not the uuid.
- **Writes need a `DeviceUuidProvider`** — the instrumented test must use `uniffiVaultOpenPort(deviceUuids)`, like the existing write-path tests.
