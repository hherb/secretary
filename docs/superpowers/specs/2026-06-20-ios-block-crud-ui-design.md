# iOS block-CRUD UI affordance — design

**Date:** 2026-06-20
**Status:** approved (brainstorming) → ready for implementation plan
**Slice:** iOS-only. Mirror of merged PR #268 (Android block-CRUD UI) onto the iOS SwiftUI browse stack.

## Problem

The three block-CRUD operations — `create_block` / `rename_block` / `move_record` —
ship in the uniffi binding (Rust PR #266, exported from
`ffi/secretary-ffi-uniffi/src/namespace/block_crud.rs`) and now have an Android UI
affordance (PR #268). The iOS SwiftUI browse stack has **no** affordance for them:
a user can browse, reveal, add/edit/delete records, but cannot create a block,
rename a block, or move a record between blocks.

This slice wires the three ops into the iOS browse UI via native iOS idioms,
completing the tier on the second platform.

## Non-goals / guardrails

- **iOS-only.** No change to `core/`, the crypto/vault spec, any `*.udl`, the pyo3
  binding, or the Android code. The uniffi ops are already shipped and reviewed;
  this is a pure UI/adapter slice over them.
- **No new error variant.** `VaultAccessError.invalidArgument(String)` already
  exists and `VaultError.InvalidArgument` already maps to it
  (`VaultErrorMapping.swift:24`). Every error these ops surface is already mapped.
  The cross-language conformance / Swift+Kotlin harnesses are untouched.
- **No drag-drop, multi-select, or inline-edit.** Dialogs + a picker (YAGNI; matches
  the Android UI policy).
- **No XCUITest target this slice.** The real-FFI round-trip drives the VM, not the
  rendered UI. accessibilityIdentifiers are seeded so a future XCUITest can be added.

## Architecture note: iOS has one VM, not two layers

Android split a **pure** `VaultBrowseModel` from a thin androidx `VaultBrowseViewModel`.
iOS does not have that split: `VaultBrowseViewModel`
(`@MainActor public final class … : ObservableObject`) is itself the FFI-free,
host-testable unit, exercised directly via `FakeVaultSession`. This slice follows
the existing iOS structure — it does **not** introduce a separate pure model.

Writes are synchronous on `@MainActor`, serialized by the existing `isWriting`
flag. Block-CRUD does **not** run Argon2id (the identity is already unlocked), so —
unlike unlock/sync — no off-main-actor offload is needed; the existing record
mutations (delete/restore/edit) are already synchronous and this slice matches them.

## Layers

### 1. Port — `SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift`

Three new protocol methods, shaped like `appendRecord` (UUIDs minted **inside** the
impl, never passed by the caller):

```swift
/// Create a new, empty block; mints a fresh 16-byte block UUID and returns it.
@discardableResult
func createBlock(blockName: String) throws -> [UInt8]

/// Rename an existing block in place (records + unknown maps preserved).
/// Throws `.blockNotFound` if absent.
func renameBlock(blockUuid: [UInt8], newName: String) throws

/// Move a LIVE record to another block under a FRESH uuid (copy-before-delete:
/// the source is tombstoned only after the copy lands). Returns the new uuid.
/// Throws `.recordNotFound` / `.blockNotFound`.
@discardableResult
func moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8],
                sourceRecordUuid: [UInt8]) throws -> [UInt8]
```

### 2. Real adapter — `SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`

Implements the three via the existing `write { dev, now in … }` helper (device-uuid
resolved + cached per session, now-ms stamped, `VaultError`→`VaultAccessError`
mapped). `createBlock` and `moveRecord` mint a fresh 16-byte uuid via the existing
CSPRNG seam before the `write` call, exactly like `appendRecord`.

- `freshRecordUuid()` is generalized to `freshUuid()` (it is no longer record-only;
  it now also mints block uuids and move-target record uuids). The named constant
  `recordUuidByteLen = 16` becomes `uuidByteLen = 16` with a comment that block and
  record uuids share the byte length but are unrelated values.
- `createBlock`: mint `blockUuid`; `write { dev, now in try SecretaryKit.createBlock(
  identity:, manifest:, blockUuid: Data(blockUuid), blockName:, deviceUuid: Data(dev),
  nowMs: now) }`; return `blockUuid`.
- `renameBlock`: `write { dev, now in try SecretaryKit.renameBlock(…, newBlockName:
  newName, …) }`.
- `moveRecord`: mint `newRecordUuid`; `write { dev, now in try SecretaryKit.moveRecord(
  …, sourceBlockUuid:, targetBlockUuid:, sourceRecordUuid:, newRecordUuid:, …) }`;
  return `newRecordUuid`. (The uniffi layer also enforces `source != target` →
  `InvalidArgument`; the VM guards it first, so this is a backstop.)

### 3. Fake — `SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift`

In-memory implementations modelling the real state transitions:

- `blocks` changes from `let` to `var` so create/rename can mutate it.
- `createBlock(blockName:)`: mint a deterministic uuid (existing `mintUuid()`), append
  a `BlockSummary(uuid:, name: blockName, createdAtMs:, lastModMs:)` and an empty record
  list to `recordsByBlock`; return the uuid.
- `renameBlock(blockUuid:newName:)`: replace the matching `BlockSummary`'s name;
  `.blockNotFound` if absent.
- `moveRecord(source:target:sourceRecord:)`: require both blocks; find the LIVE source
  record (`.recordNotFound` otherwise); append a copy under a fresh minted uuid to the
  target; set the source record's tombstone true; return the new uuid. (Copy-before-
  delete observable end state: live copy in target, tombstone in source.)
- A **failure-injection seam**: an optional `failNextWrite: VaultAccessError?` (or a
  closure) so the VM's "write fails → dialog stays open" test can force a throw without
  a malformed vault. If a simpler existing mechanism is already present, reuse it.

### 4. VM — `SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`

New published state:

```swift
/// nil = no name dialog. `.create` = new block; `.rename` carries the target block.
public enum BlockNameDialog: Equatable { case create; case rename(block: BlockSummary) }
@Published public private(set) var blockNameDialog: BlockNameDialog?
/// The record currently being moved (drives the target-picker sheet). nil = none.
@Published public private(set) var movingRecord: RecordView?
```

Generalize the existing `commitThenReload(_:)` into a shared helper that lets a write
choose what to reload afterwards (the create/rename path reloads the **block list**;
move + the existing record mutations reload a **block**):

```swift
/// Run a write, then on SUCCESS run `reload`. A failed write surfaces `error`
/// and runs neither `reload` nor any dialog-clearing the caller deferred to its
/// own success branch — so the visible list / open dialog is preserved.
private func guardedWrite(reload: () -> Void, op: () throws -> Void)
```

`commitThenReload` becomes a thin wrapper that captures `selectedBlockUuid` and calls
`guardedWrite(reload: { self.reload(blockUuid:) }, op:)` — behavior-preserving for the
existing delete/restore callers (full `VaultBrowseViewModelTests` + `…DeletedTests`
re-run proves no regression).

Actions:

- `startCreateBlock()` → `blockNameDialog = .create`.
- `startRenameBlock(_ block: BlockSummary)` → `blockNameDialog = .rename(block:)`.
- `cancelBlockNameDialog()` → `blockNameDialog = nil`.
- `confirmBlockName(_ name: String)`:
  - **blank-name guard** (UI policy; see below): trimmed-empty → `error = .invalidArgument(…)`,
    **no write**, dialog stays open.
  - else `guardedWrite(reload: { self.loadBlocks() }) { create or rename per the case }`;
    on success **only**, `blockNameDialog = nil`. (On failure the dialog stays open and
    `error` shows.)
- `startMoveRecord(_ record: RecordView)` → `movingRecord = record`.
- `cancelMove()` → `movingRecord = nil`.
- `confirmMove(target: BlockSummary)`:
  - `guard let record = movingRecord else { return }`, `guard let source = selectedBlockUuid`.
  - **same-block guard**: `target.uuid == source` → `error = .invalidArgument(…)`, no write,
    picker stays open.
  - else `guardedWrite(reload: { self.refresh() }) { try session.moveRecord(source, target,
    record.uuid) }` — `refresh()` re-reads the **source** block so the tombstone is visible
    (with show-deleted on); on success **only**, `movingRecord = nil`.
- `lock()` additionally resets `blockNameDialog = nil` and `movingRecord = nil`.

**Blank-name is a UI policy, not a spec rule.** The spec/FFI explicitly *permit* empty
block names (`block_crud.rs`: "Empty block_name is allowed"). The UI rejects blank names
for usability and to match Android. Documented in the VM doc-comment so a future reader
does not "fix" it by deleting the guard.

### 5. UI — `SecretaryApp/Sources/VaultBrowseScreen.swift` (native iOS idioms)

- **New block**: a `ToolbarItem(placement: .primaryAction)` "New block" button
  (`Label("New block", systemImage: "folder.badge.plus")`), available regardless of
  selected block, `.disabled(viewModel.isWriting)`, `.accessibilityIdentifier("new-block")`.
  (Sits alongside the existing selected-block-gated "Add record" toolbar item.)
- **Rename block**: `.swipeActions(edge: .trailing)` "Rename" button
  (`pencil`, `.tint(.orange)`) on each block row in the Blocks section, disabled while
  writing, id `rename-<uuidHex>`.
- **Move record**: a "Move" button in the live record row's `.swipeActions(edge: .leading)`
  (beside Edit) — `arrow.right.square` / `folder`, disabled while writing, id `move-<uuidHex>`.
- **Block-name entry**: `.alert("New block" / "Rename block", isPresented:)` with a
  `TextField` bound to a `@State private var blockNameField` and Create/Rename + Cancel
  buttons. Confirm calls `viewModel.confirmBlockName(blockNameField)`; Cancel calls
  `viewModel.cancelBlockNameDialog()`. ids `block-name-field` / `block-name-confirm` /
  `block-name-cancel`. The alert is driven by a `Binding` derived from
  `viewModel.blockNameDialog != nil` (same pattern as the existing delete
  `confirmationDialog`). The `TextField` is reset when the dialog opens.
- **Move-target picker**: `.sheet(item: $movingRecordItem)` (an `Identifiable` wrapper over
  `viewModel.movingRecord`, like `EditSession`) presenting a list of target blocks
  **excluding the source** (`viewModel.blocks.filter { $0.uuid != selectedBlockUuid }`),
  title naming the moving record's type. Each row id `move-target-<uuidHex>` calls
  `viewModel.confirmMove(target:)`; a Cancel (`move-cancel`) calls `viewModel.cancelMove()`.
- The screen currently has **no** accessibilityIdentifiers; this slice adds them on the
  new controls only (existing rows can stay as-is — out of scope to retrofit).

### 6. Tests

**Host VM** — `SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift`
(`swift test`):
- create happy: `startCreateBlock` → `confirmBlockName("X")` → block list gains "X", dialog nil.
- rename happy: `startRenameBlock(block)` → `confirmBlockName("Y")` → summary renamed, dialog nil.
- move happy: select source → `startMoveRecord(rec)` → `confirmMove(target)` → source record
  tombstoned (visible with showDeleted), target gains a live copy; `movingRecord` nil.
- blank-name guard: `confirmBlockName("   ")` → `error == .invalidArgument`, **no** mutation,
  `blockNameDialog` still set.
- same-block guard: `confirmMove(target: sameAsSource)` → `error == .invalidArgument`, no write,
  `movingRecord` still set.
- write-failure-keeps-dialog-open: inject a failing fake → `confirmBlockName`/`confirmMove`
  leaves the dialog/picker set and surfaces `error`.
- `lock()` resets both `blockNameDialog` and `movingRecord`.

**Fake behavior** — extend `FakeVaultSessionTests` (or add) to cover createBlock/renameBlock/
moveRecord state transitions + the not-found throws.

**Real-FFI round-trip** — `SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift`:
drive the **real** `VaultBrowseViewModel` over a **real** `UniffiVaultSession` against a
**temp copy** of `golden_vault_001` (never the tracked fixture — per the smoke-test-temp-copy
discipline). Sequence: `loadBlocks` → `startCreateBlock` + `confirmBlockName("Moved")` →
select the source block ("Personal logins") → `startMoveRecord(firstLiveRecord)` →
`confirmMove(target: the new "Moved" block)` → re-open the target and assert a field value
equals the KAT (`owner@example.com`) → assert the source record is tombstoned. Reuses the
`RecordEditIntegrationTests` staging + `FixedDeviceUuid` provider pattern. Runs on the
simulator via `ios/scripts/run-ios-tests.sh`.

### 7. Docs

README row + ROADMAP entry mirroring the Android block-CRUD UI rows (neighbor style,
brief dot points per the README-style preference). Spec (this file) + the implementation
plan committed under `docs/superpowers/`.

## Deliberate design decisions (so a future reader doesn't "fix" them)

- **Single VM**, not a pure-model/VM split — follows existing iOS structure.
- **Native idioms** (toolbar + swipe + `.alert`-with-TextField + sheet picker), not the
  visible inline buttons Android used.
- **UUIDs minted in the impl** (CSPRNG in the real adapter, deterministic counter in the
  fake) so the VM stays deterministic — matches `appendRecord`.
- **Validation in the VM, not the bridge**: blank-name + same-block guards surface
  `.invalidArgument` *before* any FFI call. **No new error case** — all errors already map.
- **`guardedWrite` generalization** shares the re-entrancy + on-success-only-reload +
  error-preservation core between record writes and block-list writes; behavior-preserving
  (full existing browse suite re-run proves no regression).
- **Move semantics**: copy-to-target-under-a-fresh-uuid + tombstone-in-source. Read-back
  asserts the field *value*, not the uuid; the source shows the record tombstoned.
- **Round-trip drives the VM, not the rendered UI** — no XCUITest target this slice;
  accessibilityIdentifiers are seeded for a later one.

## Acceptance

```bash
# Host VM + fake (no simulator):
cd ios && swift test --package-path SecretaryVaultAccess     # all green incl. new BlockCrud tests

# Real-FFI round-trip + integration (simulator; rebuilds xcframework to expose the
# create/rename/move Swift bindings):
bash ios/scripts/run-ios-tests.sh                            # BlockCrudRoundTripIntegrationTests green

# Guardrails (must be EMPTY this slice):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|android/'   # empty
git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'                                                        # empty
```
