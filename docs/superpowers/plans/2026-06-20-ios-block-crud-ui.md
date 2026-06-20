# iOS block-CRUD UI affordance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the three already-shipped uniffi block-CRUD ops (`create_block` / `rename_block` / `move_record`) into the iOS SwiftUI browse stack via native idioms.

**Architecture:** A pure mirror of merged PR #268 (Android), adapted to iOS's single-VM structure. Port (`VaultSession` protocol) gains three methods that mint UUIDs internally; the real adapter (`UniffiVaultSession`) calls the regenerated uniffi free functions; the FFI-free `VaultBrowseViewModel` (the host-tested unit) gains dialog/picker state + guarded actions; `VaultBrowseScreen` adds a toolbar button, swipe actions, an `.alert` name prompt, and a target-picker sheet. Validation (blank-name, same-block) lives in the VM before any FFI call.

**Tech Stack:** Swift 5.9 / SwiftUI, XCTest, Swift Package Manager (three packages: `SecretaryVaultAccess` host-pure, `SecretaryKit` FFI, `SecretaryApp` UI), uniffi-generated Swift bindings.

## Global Constraints

- **iOS-only.** No change to `core/`, `docs/crypto-design.md`, `docs/vault-format.md`, any `*.udl`, `ffi/secretary-ffi-py`, or `android/`. Guardrail greps in §Acceptance MUST be empty.
- **No new error case.** `VaultAccessError.invalidArgument(String)` exists; `VaultError.InvalidArgument` already maps to it (`VaultErrorMapping.swift:24`). Do not add a variant — the cross-language conformance + Swift/Kotlin harnesses stay untouched.
- **UUIDs minted inside the impl** (CSPRNG in the real adapter, deterministic counter in the fake), never passed by the VM — matches `appendRecord`.
- **Validation in the VM, not the bridge** ([[project_secretary_input_validation_at_binding_wrapper]]): blank-name + same-block guards surface `.invalidArgument` before any FFI call.
- **Dialog/picker cleared only on write success** — a failed write keeps it open.
- **Blank-name rejection is a UI policy** — the spec/FFI permit empty block names; the UI rejects them for usability + Android parity. Document it; don't "fix" it away.
- **Tests use random crypto values, never hardcoded** ([[feedback_test_crypto_random_not_hardcoded]]) — N/A here (no key/nonce literals); golden-vault KAT values come from the staged fixture, never inline byte arrays.
- **Golden vault: temp copy only** ([[feedback_smoke_test_temp_copy_golden_vault]]) — the round-trip stages a `cp -R` temp copy; never open the tracked fixture.
- Host VM/fake/protocol changes are testable with `cd ios/SecretaryVaultAccess && swift test` (no FFI). The real adapter + round-trip need the regenerated bindings via `ios/scripts/build-xcframework.sh`.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift` | Port: +3 method signatures | 1 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift` | In-memory impl + failure-injection seam | 1 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultSessionBlockCrudTests.swift` | Fake behavior tests | 1 |
| `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` | `guardedWrite` refactor + dialog/picker state + actions | 2,3,4 |
| `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift` | Host VM tests | 2,3,4 |
| `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift` | Real adapter: +3 impls + `freshUuid()` | 5 |
| `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` | Toolbar + swipe + `.alert` + picker sheet + a11y ids | 6 |
| `ios/SecretaryApp/Sources/BlockCrudViews.swift` | New `MoveTargetPickerSheet` view (keeps the screen file focused) | 6 |
| `ios/SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift` | Real-FFI VM round-trip | 7 |
| `README.md`, `ROADMAP.md` | Status rows | 8 |

---

### Task 1: Port + Fake + fake behavior tests

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultSessionBlockCrudTests.swift` (create)

**Interfaces:**
- Produces (consumed by Tasks 2–5):
  - `VaultSession.createBlock(blockName: String) throws -> [UInt8]` (`@discardableResult`)
  - `VaultSession.renameBlock(blockUuid: [UInt8], newName: String) throws`
  - `VaultSession.moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8], sourceRecordUuid: [UInt8]) throws -> [UInt8]` (`@discardableResult`)
  - `FakeVaultSession.failNextWrite: VaultAccessError?` (test seam: next create/rename/move throws it once)

- [ ] **Step 1: Write the failing fake-behavior test**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultSessionBlockCrudTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeVaultSessionBlockCrudTests: XCTestCase {
    private func make() -> (FakeVaultSession, BlockSummary, RecordView) {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let rec = RecordView(uuid: Array(repeating: 2, count: 16),
                             type: "login", tags: [],
                             fields: [FieldView(name: "u", kind: .text) { .text("v") }])
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: [block], recordsByBlock: [[7]: [rec]])
        return (s, block, rec)
    }

    func testCreateBlockAddsEmptyBlock() throws {
        let (s, _, _) = make()
        let uuid = try s.createBlock(blockName: "New")
        XCTAssertTrue(s.blockSummaries().contains { $0.uuid == uuid && $0.name == "New" })
        XCTAssertEqual(try s.readBlock(blockUuid: uuid, includeDeleted: true).count, 0)
    }

    func testRenameBlockChangesName() throws {
        let (s, block, _) = make()
        try s.renameBlock(blockUuid: block.uuid, newName: "Renamed")
        XCTAssertEqual(s.blockSummaries().first { $0.uuid == block.uuid }?.name, "Renamed")
    }

    func testRenameUnknownBlockThrowsBlockNotFound() {
        let (s, _, _) = make()
        XCTAssertThrowsError(try s.renameBlock(blockUuid: [0xFF], newName: "x")) {
            guard case VaultAccessError.blockNotFound = $0 else { return XCTFail("got \($0)") }
        }
    }

    func testMoveRecordCopiesToTargetAndTombstonesSource() throws {
        let (s, src, rec) = make()
        let target = try s.createBlock(blockName: "Target")
        let newUuid = try s.moveRecord(sourceBlockUuid: src.uuid,
                                       targetBlockUuid: target, sourceRecordUuid: rec.uuid)
        // live copy in target under a fresh uuid:
        let inTarget = try s.readBlock(blockUuid: target, includeDeleted: false)
        XCTAssertEqual(inTarget.count, 1)
        XCTAssertEqual(inTarget.first?.uuid, newUuid)
        // source record tombstoned (withheld unless includeDeleted):
        XCTAssertEqual(try s.readBlock(blockUuid: src.uuid, includeDeleted: false).count, 0)
        XCTAssertEqual(try s.readBlock(blockUuid: src.uuid, includeDeleted: true).count, 1)
    }

    func testMoveUnknownRecordThrowsRecordNotFound() throws {
        let (s, src, _) = make()
        let target = try s.createBlock(blockName: "Target")
        XCTAssertThrowsError(try s.moveRecord(sourceBlockUuid: src.uuid,
                                              targetBlockUuid: target,
                                              sourceRecordUuid: [0xEE])) {
            guard case VaultAccessError.recordNotFound = $0 else { return XCTFail("got \($0)") }
        }
    }

    func testFailNextWriteInjectsOneError() {
        let (s, _, _) = make()
        s.failNextWrite = .other("boom")
        XCTAssertThrowsError(try s.createBlock(blockName: "x"))
        XCTAssertNoThrow(try s.createBlock(blockName: "y"), "injection is one-shot")
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakeVaultSessionBlockCrudTests`
Expected: FAIL — `value of type 'FakeVaultSession' has no member 'createBlock'` (protocol + impl not added yet).

- [ ] **Step 3: Add the three protocol methods**

In `VaultSession.swift`, before `func wipe()`:

```swift
    /// Create a new, empty block. The session mints a fresh 16-byte block UUID,
    /// stamps this device's UUID + now, and returns the new UUID. Empty names are
    /// permitted by the spec (the UI may impose its own policy).
    @discardableResult
    func createBlock(blockName: String) throws -> [UInt8]
    /// Rename a block in place (records + unknown maps preserved).
    /// Throws `.blockNotFound` if `blockUuid` is absent.
    func renameBlock(blockUuid: [UInt8], newName: String) throws
    /// Move a LIVE record to another block under a FRESH uuid (copy-before-delete:
    /// the source is tombstoned only after the copy lands). Returns the new uuid.
    /// Throws `.recordNotFound` (no live source record) / `.blockNotFound`.
    @discardableResult
    func moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8],
                    sourceRecordUuid: [UInt8]) throws -> [UInt8]
```

- [ ] **Step 4: Implement them in `FakeVaultSession`**

Change `private let blocks: [BlockSummary]` to `private var blocks: [BlockSummary]`. Add the seam field after `lastIncludeDeleted`:

```swift
    /// Test seam: when set, the NEXT create/rename/move throws this once, then clears.
    public var failNextWrite: VaultAccessError?
```

Add a one-shot check helper next to the other helpers:

```swift
    private func throwIfInjected() throws {
        if let e = failNextWrite { failNextWrite = nil; throw e }
    }
```

Add the three methods (place after `resurrectRecord`):

```swift
    @discardableResult
    public func createBlock(blockName: String) throws -> [UInt8] {
        try throwIfInjected()
        let uuid = mintUuid()
        blocks.append(BlockSummary(uuid: uuid, name: blockName, createdAtMs: 0, lastModMs: 0))
        recordsByBlock[uuid] = []
        return uuid
    }

    public func renameBlock(blockUuid: [UInt8], newName: String) throws {
        try throwIfInjected()
        guard let idx = blocks.firstIndex(where: { $0.uuid == blockUuid }) else {
            throw VaultAccessError.blockNotFound(hex(blockUuid))
        }
        let old = blocks[idx]
        blocks[idx] = BlockSummary(uuid: old.uuid, name: newName,
                                   createdAtMs: old.createdAtMs, lastModMs: old.lastModMs)
    }

    @discardableResult
    public func moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8],
                           sourceRecordUuid: [UInt8]) throws -> [UInt8] {
        try throwIfInjected()
        let idx = try liveIndex(sourceBlockUuid, sourceRecordUuid)
        try requireBlock(targetBlockUuid)
        guard let src = recordsByBlock[sourceBlockUuid]?[idx] else {
            throw VaultAccessError.recordNotFound(hex(sourceRecordUuid))
        }
        let newUuid = mintUuid()
        // copy-before-delete: land the copy in the target, THEN tombstone the source.
        recordsByBlock[targetBlockUuid]?.append(RecordView(
            uuid: newUuid, type: src.type, tags: src.tags, fields: src.fields, tombstone: false))
        setTombstone(sourceBlockUuid, idx, true)
        return newUuid
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakeVaultSessionBlockCrudTests`
Expected: PASS (6 tests). Then full package: `cd ios/SecretaryVaultAccess && swift test` — all green (no regression in existing fake consumers).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSession.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSession.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/FakeVaultSessionBlockCrudTests.swift
git commit -m "feat(ios): block-CRUD on VaultSession port + fake + behavior tests"
```

---

### Task 2: VM — `guardedWrite` refactor + create-block action

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift` (create)

**Interfaces:**
- Consumes: `VaultSession.createBlock` (Task 1), `FakeVaultSession.failNextWrite` (Task 1).
- Produces (consumed by Tasks 3,4,6):
  - `enum BlockNameDialog: Equatable { case create; case rename(block: BlockSummary) }`
  - `@Published private(set) var blockNameDialog: BlockNameDialog?`
  - `func startCreateBlock()`, `func cancelBlockNameDialog()`, `func confirmBlockName(_ name: String)`
  - `private func guardedWrite(onSuccess: () -> Void, op: () throws -> Void) -> Bool` (`@discardableResult`)

- [ ] **Step 1: Write the failing create-block tests**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultBrowseViewModelBlockCrudTests: XCTestCase {
    private func make() -> (FakeVaultSession, BlockSummary, RecordView) {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let rec = RecordView(uuid: Array(repeating: 2, count: 16),
                             type: "login", tags: [],
                             fields: [FieldView(name: "u", kind: .text) { .text("v") }])
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: [block], recordsByBlock: [[7]: [rec]])
        return (s, block, rec)
    }

    func testCreateBlockHappyPathAddsBlockAndClearsDialog() {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startCreateBlock()
        XCTAssertEqual(vm.blockNameDialog, .create)
        vm.confirmBlockName("Archive")
        XCTAssertNil(vm.blockNameDialog, "dialog cleared on success")
        XCTAssertTrue(vm.blocks.contains { $0.name == "Archive" })
        XCTAssertNil(vm.error)
    }

    func testConfirmBlankNameKeepsDialogOpenAndSurfacesInvalidArgument() {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        let before = vm.blocks.count
        vm.startCreateBlock()
        vm.confirmBlockName("   ")
        XCTAssertEqual(vm.blockNameDialog, .create, "blank name must not close the dialog")
        XCTAssertEqual(vm.blocks.count, before, "blank name must not write")
        guard case .invalidArgument = vm.error else { return XCTFail("expected invalidArgument, got \(String(describing: vm.error))") }
    }

    func testCreateBlockWriteFailureKeepsDialogOpen() {
        let (s, _, _) = make()
        s.failNextWrite = .other("disk full")
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startCreateBlock()
        vm.confirmBlockName("Archive")
        XCTAssertEqual(vm.blockNameDialog, .create, "failed write must keep the dialog open")
        XCTAssertNotNil(vm.error)
    }

    func testCancelBlockNameDialogClearsIt() {
        let (s, _, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.startCreateBlock()
        vm.cancelBlockNameDialog()
        XCTAssertNil(vm.blockNameDialog)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockCrudTests`
Expected: FAIL — `value of type 'VaultBrowseViewModel' has no member 'startCreateBlock'`.

- [ ] **Step 3: Refactor `commitThenReload` into `guardedWrite` + add create-block**

In `VaultBrowseViewModel.swift`, add published state after the `isWriting` property:

```swift
    /// Drives the block-name prompt. nil = closed. `.create` = new block;
    /// `.rename` carries the block being renamed.
    public enum BlockNameDialog: Equatable { case create; case rename(block: BlockSummary) }
    @Published public private(set) var blockNameDialog: BlockNameDialog?
```

Replace the existing `commitThenReload(_:)` (lines ~88-106) with the generalized helper plus a thin wrapper:

```swift
    /// Run `op`, then on SUCCESS run `onSuccess`. A failed write surfaces `error`
    /// and runs neither `onSuccess` nor any caller-deferred dialog clear — so the
    /// visible list / open dialog is preserved. Returns true iff the write
    /// succeeded. Re-entrancy guarded by `isWriting`.
    @discardableResult
    private func guardedWrite(onSuccess: () -> Void, op: () throws -> Void) -> Bool {
        guard !isWriting else { return false }
        isWriting = true
        defer { isWriting = false }
        do {
            try op()
        } catch let e as VaultAccessError {
            error = e
            return false
        } catch {
            self.error = .other(String(describing: error))
            return false
        }
        onSuccess()
        return true
    }

    /// Run a mutation against the selected block, then re-read it on success.
    /// Behavior-preserving wrapper over `guardedWrite` for the record mutations.
    private func commitThenReload(_ op: ([UInt8]) throws -> Void) {
        guard let blockUuid = selectedBlockUuid else { return }
        guardedWrite(onSuccess: { self.reload(blockUuid: blockUuid) }) { try op(blockUuid) }
    }
```

Add the create-block actions (place after `loadBlocks()` or near the bottom, before `makeEditViewModel`):

```swift
    /// Open the name prompt for a NEW block.
    public func startCreateBlock() { blockNameDialog = .create }
    /// Dismiss the block-name prompt without writing.
    public func cancelBlockNameDialog() { blockNameDialog = nil }

    /// Confirm the block-name prompt. Blank names are rejected as a UI policy
    /// (the spec/FFI permit empty block names; the UI requires a non-blank one) —
    /// this surfaces `.invalidArgument` WITHOUT writing and keeps the dialog open.
    /// On a successful write the block LIST is reloaded and the dialog cleared;
    /// on a failed write the dialog stays open with `error` set.
    public func confirmBlockName(_ name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            error = .invalidArgument("block name must not be blank")
            return
        }
        guard let dialog = blockNameDialog else { return }
        let ok = guardedWrite(onSuccess: { self.loadBlocks() }) {
            switch dialog {
            case .create:
                try self.session.createBlock(blockName: trimmed)
            case .rename(let block):
                try self.session.renameBlock(blockUuid: block.uuid, newName: trimmed)
            }
        }
        if ok { blockNameDialog = nil }
    }
```

(The `.rename` arm references `renameBlock` from Task 1; its VM-level test arrives in Task 3.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockCrudTests`
Expected: PASS (4 tests). Then `cd ios/SecretaryVaultAccess && swift test` — the existing `VaultBrowseViewModelTests` + `…DeletedTests` still pass (proves `guardedWrite` refactor is behavior-preserving).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift
git commit -m "feat(ios): VM create-block action + guardedWrite refactor"
```

---

### Task 3: VM — rename-block action

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift`

**Interfaces:**
- Consumes: `VaultSession.renameBlock` (Task 1), `confirmBlockName` / `BlockNameDialog` (Task 2).
- Produces: `func startRenameBlock(_ block: BlockSummary)`.

- [ ] **Step 1: Write the failing rename tests**

Append to `VaultBrowseViewModelBlockCrudTests.swift`:

```swift
    func testRenameBlockHappyPathRenamesAndClearsDialog() {
        let (s, block, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startRenameBlock(block)
        XCTAssertEqual(vm.blockNameDialog, .rename(block: block))
        vm.confirmBlockName("Renamed")
        XCTAssertNil(vm.blockNameDialog)
        XCTAssertTrue(vm.blocks.contains { $0.uuid == block.uuid && $0.name == "Renamed" })
        XCTAssertNil(vm.error)
    }

    func testRenameBlockWriteFailureKeepsDialogOpen() {
        let (s, block, _) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        vm.startRenameBlock(block)
        s.failNextWrite = .other("disk full")
        vm.confirmBlockName("Renamed")
        XCTAssertEqual(vm.blockNameDialog, .rename(block: block))
        XCTAssertNotNil(vm.error)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockCrudTests`
Expected: FAIL — `has no member 'startRenameBlock'`.

- [ ] **Step 3: Add the action**

In `VaultBrowseViewModel.swift`, beside `startCreateBlock`:

```swift
    /// Open the name prompt to RENAME `block` (pre-binds the current name in the UI).
    public func startRenameBlock(_ block: BlockSummary) { blockNameDialog = .rename(block: block) }
```

(The rename write itself is already handled by `confirmBlockName`'s `.rename` arm from Task 2.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockCrudTests`
Expected: PASS (6 tests total).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift
git commit -m "feat(ios): VM rename-block action"
```

---

### Task 4: VM — move-record action + lock reset

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift`

**Interfaces:**
- Consumes: `VaultSession.moveRecord` (Task 1).
- Produces (consumed by Task 6):
  - `@Published private(set) var movingRecord: RecordView?`
  - `func startMoveRecord(_ record: RecordView)`, `func cancelMove()`, `func confirmMove(target: BlockSummary)`

- [ ] **Step 1: Write the failing move tests**

Append to `VaultBrowseViewModelBlockCrudTests.swift`:

```swift
    func testMoveRecordHappyPathTombstonesSourceAndClearsPicker() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        let targetUuid = try! s.createBlock(blockName: "Target")  // pre-seed a target block
        vm.loadBlocks()
        let target = vm.blocks.first { $0.uuid == targetUuid }!
        vm.selectBlock(src)
        vm.startMoveRecord(rec)
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid)
        vm.confirmMove(target: target)
        XCTAssertNil(vm.movingRecord, "picker cleared on success")
        XCTAssertNil(vm.error)
        // source re-read shows the record tombstoned (withheld while showDeleted is off):
        XCTAssertEqual(vm.visibleRecords.count, 0)
        XCTAssertEqual(try! s.readBlock(blockUuid: target.uuid, includeDeleted: false).count, 1)
    }

    func testMoveToSameBlockKeepsPickerOpenAndSurfacesInvalidArgument() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks(); vm.selectBlock(src)
        vm.startMoveRecord(rec)
        vm.confirmMove(target: src)  // same block
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid, "same-block move must keep the picker open")
        guard case .invalidArgument = vm.error else { return XCTFail("expected invalidArgument, got \(String(describing: vm.error))") }
    }

    func testMoveWriteFailureKeepsPickerOpen() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks()
        let targetUuid = try! s.createBlock(blockName: "Target"); vm.loadBlocks()
        let target = vm.blocks.first { $0.uuid == targetUuid }!
        vm.selectBlock(src); vm.startMoveRecord(rec)
        s.failNextWrite = .other("disk full")
        vm.confirmMove(target: target)
        XCTAssertEqual(vm.movingRecord?.uuid, rec.uuid)
        XCTAssertNotNil(vm.error)
    }

    func testLockResetsDialogAndMovingRecord() {
        let (s, src, rec) = make()
        let vm = VaultBrowseViewModel(session: s)
        vm.loadBlocks(); vm.selectBlock(src)
        vm.startCreateBlock()
        vm.startMoveRecord(rec)
        vm.lock()
        XCTAssertNil(vm.blockNameDialog)
        XCTAssertNil(vm.movingRecord)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockCrudTests`
Expected: FAIL — `has no member 'startMoveRecord'`.

- [ ] **Step 3: Add move state + actions + lock reset**

In `VaultBrowseViewModel.swift`, add published state after `blockNameDialog`:

```swift
    /// The record currently being moved (drives the target-picker sheet). nil = none.
    @Published public private(set) var movingRecord: RecordView?
```

Add the actions beside the block-name ones:

```swift
    /// Begin moving `record` — opens the target-block picker.
    public func startMoveRecord(_ record: RecordView) { movingRecord = record }
    /// Dismiss the move picker without writing.
    public func cancelMove() { movingRecord = nil }

    /// Confirm a move into `target`. Rejects a same-block move as a UI guard
    /// (`.invalidArgument`, no write, picker stays open). On success the SOURCE
    /// block is re-read (so the tombstone shows with show-deleted on) and the
    /// picker cleared; on a failed write the picker stays open with `error` set.
    public func confirmMove(target: BlockSummary) {
        guard let record = movingRecord else { return }
        guard let source = selectedBlockUuid else { return }
        guard target.uuid != source else {
            error = .invalidArgument("source and target block must differ")
            return
        }
        let ok = guardedWrite(onSuccess: { self.refresh() }) {
            try self.session.moveRecord(sourceBlockUuid: source,
                                        targetBlockUuid: target.uuid,
                                        sourceRecordUuid: record.uuid)
        }
        if ok { movingRecord = nil }
    }
```

Update `lock()` to reset both (add the two lines before `session.wipe()`):

```swift
    public func lock() {
        revealed.removeAll()
        blockNameDialog = nil
        movingRecord = nil
        session.wipe()
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockCrudTests`
Expected: PASS (10 tests total). Then `cd ios/SecretaryVaultAccess && swift test` — whole package green.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockCrudTests.swift
git commit -m "feat(ios): VM move-record action + lock resets dialog/picker"
```

---

### Task 5: Real adapter — `UniffiVaultSession`

**Files:**
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`

**Interfaces:**
- Consumes: the regenerated uniffi free functions `SecretaryKit.createBlock(identity:manifest:blockUuid:blockName:deviceUuid:nowMs:)`, `SecretaryKit.renameBlock(identity:manifest:blockUuid:newBlockName:deviceUuid:nowMs:)`, `SecretaryKit.moveRecord(identity:manifest:sourceBlockUuid:targetBlockUuid:sourceRecordUuid:newRecordUuid:deviceUuid:nowMs:)`.
- Produces: `UniffiVaultSession` conforms to the three new `VaultSession` methods (so it compiles after Task 1's protocol change).

> **NOTE on binding names:** uniffi lower-camel-cases snake_case. The exact generated label for `rename_block`'s `new_block_name` arg is `newBlockName`. If the regenerated `secretary.swift` differs (e.g. `newName`), match what it emits — the generated file is the source of truth. Confirm by grepping it after Step 1.

- [ ] **Step 1: Regenerate the Swift bindings**

Run: `bash ios/scripts/build-xcframework.sh`
Expected: rebuilds the framework and writes `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift` containing `public func createBlock(`, `public func renameBlock(`, `public func moveRecord(`. Verify:

Run: `grep -nE 'public func (createBlock|renameBlock|moveRecord)\(' ios/SecretaryKit/Sources/SecretaryKit/secretary.swift`
Expected: three matches. Note the exact argument labels for Step 2.

- [ ] **Step 2: Generalize the uuid minter + implement the three methods**

In `UniffiVaultSession.swift`:

Rename the constant + minter (they are no longer record-only):

```swift
    /// 16 bytes — a UUID (block or record). Both kinds share the byte length but
    /// are unrelated values; named generically since this mints both.
    private static let uuidByteLen = 16

    private static func freshUuid() throws -> [UInt8] {
        var u = [UInt8](repeating: 0, count: uuidByteLen)
        let status = SecRandomCopyBytes(kSecRandomDefault, u.count, &u)
        guard status == errSecSuccess else {
            throw VaultAccessError.other("OS entropy unavailable for UUID (status \(status))")
        }
        return u
    }
```

Update `appendRecord` to call `Self.freshUuid()` instead of `Self.freshRecordUuid()`.

Add the three methods after `resurrectRecord` (use the labels confirmed in Step 1):

```swift
    @discardableResult
    public func createBlock(blockName: String) throws -> [UInt8] {
        let blockUuid = try Self.freshUuid()
        try write { dev, now in
            try SecretaryKit.createBlock(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), blockName: blockName,
                deviceUuid: Data(dev), nowMs: now)
        }
        return blockUuid
    }

    public func renameBlock(blockUuid: [UInt8], newName: String) throws {
        try write { dev, now in
            try SecretaryKit.renameBlock(
                identity: identity, manifest: manifest,
                blockUuid: Data(blockUuid), newBlockName: newName,
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    @discardableResult
    public func moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8],
                           sourceRecordUuid: [UInt8]) throws -> [UInt8] {
        let newRecordUuid = try Self.freshUuid()
        try write { dev, now in
            try SecretaryKit.moveRecord(
                identity: identity, manifest: manifest,
                sourceBlockUuid: Data(sourceBlockUuid), targetBlockUuid: Data(targetBlockUuid),
                sourceRecordUuid: Data(sourceRecordUuid), newRecordUuid: Data(newRecordUuid),
                deviceUuid: Data(dev), nowMs: now)
        }
        return newRecordUuid
    }
```

- [ ] **Step 3: Build SecretaryKit to verify it compiles**

Run: `cd ios/SecretaryKit && swift build`
Expected: BUILD SUCCEEDED (conformance to the 3 new protocol requirements satisfied; no other consumer breaks).

- [ ] **Step 4: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift \
        ios/SecretaryKit/Sources/SecretaryKit/secretary.swift
git commit -m "feat(ios): UniffiVaultSession block-CRUD impls + regenerated bindings"
```

> If `secretary.swift` is `.gitignore`d / build-generated in this repo, omit it from the `git add` (the round-trip's `build-xcframework.sh` regenerates it). Check `git status` before committing.

---

### Task 6: SwiftUI — toolbar + swipe + alert + picker

**Files:**
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`
- Create: `ios/SecretaryApp/Sources/BlockCrudViews.swift`

**Interfaces:**
- Consumes: `startCreateBlock` / `startRenameBlock` / `cancelBlockNameDialog` / `confirmBlockName` / `blockNameDialog` (Tasks 2,3); `startMoveRecord` / `cancelMove` / `confirmMove` / `movingRecord` (Task 4).
- Produces: UI only (no symbols consumed downstream).

> This task has no host unit test (SwiftUI view bodies aren't host-tested in this repo; the VM logic is covered by Tasks 2–4 and the rendered flow by Task 7's VM round-trip). Acceptance is "builds + manual smoke is possible"; accessibilityIdentifiers are seeded for a future XCUITest. Verify by building the app target.

- [ ] **Step 1: Add the move-target picker sheet view**

Create `ios/SecretaryApp/Sources/BlockCrudViews.swift`:

```swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Identifiable wrapper so `.sheet(item:)` can drive the move-target picker.
struct MovingRecordItem: Identifiable {
    let id = UUID()
    let record: RecordView
}

/// Lists the blocks a record can be moved INTO — every block except the source.
/// Tapping a row calls `confirmMove`; Cancel calls `cancelMove`.
struct MoveTargetPickerSheet: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    let record: RecordView
    let sourceBlockUuid: [UInt8]

    var body: some View {
        NavigationStack {
            List {
                ForEach(viewModel.blocks.filter { $0.uuid != sourceBlockUuid }, id: \.uuidHex) { block in
                    Button(block.name) { viewModel.confirmMove(target: block) }
                        .accessibilityIdentifier("move-target-\(block.uuidHex)")
                }
            }
            .navigationTitle("Move \(record.type.isEmpty ? "record" : record.type)")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { viewModel.cancelMove() }
                        .accessibilityIdentifier("move-cancel")
                }
            }
        }
    }
}
```

- [ ] **Step 2: Wire the toolbar button, swipe actions, alert, and sheet into `VaultBrowseScreen`**

In `VaultBrowseScreen.swift`:

Add screen state beside `recordPendingDelete`:

```swift
    // Block-name alert field (create/rename share the one prompt).
    @State private var blockNameField = ""
    // Identifiable wrapper bridging viewModel.movingRecord → .sheet(item:).
    @State private var movingItem: MovingRecordItem?
```

Add a "New block" toolbar item (after the existing `.primaryAction` Add-record item, NOT gated on `selectedBlock`):

```swift
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        blockNameField = ""
                        viewModel.startCreateBlock()
                    } label: {
                        Label("New block", systemImage: "folder.badge.plus")
                    }
                    .disabled(viewModel.isWriting)
                    .accessibilityIdentifier("new-block")
                }
```

Add a Rename swipe action to the block row. Change the Blocks `ForEach` body from the bare `Button(block.name)` to a button with a swipe action:

```swift
                    ForEach(viewModel.blocks, id: \.uuidHex) { block in
                        Button(block.name) {
                            selectedBlock = block
                            viewModel.selectBlock(block)
                        }
                        .swipeActions(edge: .trailing) {
                            Button {
                                blockNameField = block.name
                                viewModel.startRenameBlock(block)
                            } label: {
                                Label("Rename", systemImage: "pencil")
                            }
                            .tint(.orange)
                            .disabled(viewModel.isWriting)
                            .accessibilityIdentifier("rename-\(block.uuidHex)")
                        }
                    }
```

Add a Move button to the live-record leading swipe group (in `recordView`, inside the existing `.swipeActions(edge: .leading)` block, after the Edit button, still guarded by `!record.tombstone`):

```swift
                Button {
                    viewModel.startMoveRecord(record)
                } label: {
                    Label("Move", systemImage: "folder")
                }
                .tint(.indigo)
                .disabled(viewModel.isWriting)
                .accessibilityIdentifier("move-\(record.uuidHex)")
```

Add the block-name `.alert` and the move `.sheet` to the `NavigationStack` modifiers (next to the existing `.confirmationDialog`):

```swift
            .alert(
                blockNameAlertTitle,
                isPresented: Binding(
                    get: { viewModel.blockNameDialog != nil },
                    set: { if !$0 { viewModel.cancelBlockNameDialog() } }
                )
            ) {
                TextField("Block name", text: $blockNameField)
                    .accessibilityIdentifier("block-name-field")
                Button("Save") { viewModel.confirmBlockName(blockNameField) }
                    .accessibilityIdentifier("block-name-confirm")
                Button("Cancel", role: .cancel) { viewModel.cancelBlockNameDialog() }
                    .accessibilityIdentifier("block-name-cancel")
            }
            .sheet(item: $movingItem) { item in
                if let source = selectedBlock?.uuid {
                    MoveTargetPickerSheet(viewModel: viewModel, record: item.record, sourceBlockUuid: source)
                }
            }
            .onChange(of: viewModel.movingRecord?.uuidHex) { _, _ in
                // Bridge the VM's movingRecord → the Identifiable sheet item.
                movingItem = viewModel.movingRecord.map { MovingRecordItem(record: $0) }
            }
```

Add a computed title helper at the bottom of the struct:

```swift
    private var blockNameAlertTitle: String {
        switch viewModel.blockNameDialog {
        case .rename: return "Rename block"
        case .create, .none: return "New block"
        }
    }
```

- [ ] **Step 3: Build the app target to verify it compiles**

Run: `bash ios/scripts/build-xcframework.sh && cd ios && xcodebuild -scheme SecretaryApp -destination "generic/platform=iOS Simulator" build CODE_SIGNING_ALLOWED=NO 2>&1 | tail -5`
Expected: `** BUILD SUCCEEDED **` (or the project's equivalent app-build invocation — if the repo drives the app build via XcodeGen + a specific scheme, use that; the goal is a clean compile of `VaultBrowseScreen.swift` + `BlockCrudViews.swift`).

- [ ] **Step 4: Commit**

```bash
git add ios/SecretaryApp/Sources/VaultBrowseScreen.swift ios/SecretaryApp/Sources/BlockCrudViews.swift
git commit -m "feat(ios): block-CRUD UI — toolbar, swipe actions, name alert, move picker"
```

---

### Task 7: Real-FFI VM round-trip integration test

**Files:**
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift`

**Interfaces:**
- Consumes: real `UniffiVaultSession` (Task 5) + `VaultBrowseViewModel` actions (Tasks 2–4) + the `RecordEditIntegrationTests` staging helpers in `TestHelpers.swift`.

> **Read `ios/SecretaryKit/Tests/SecretaryKitTests/TestHelpers.swift` and `RecordEditIntegrationTests.swift` first** to reuse the exact golden-vault temp-staging API + `FixedDeviceUuid` provider + open call. The code below names the helpers as `RecordEditIntegrationTests` uses them; if a helper has a different name in `TestHelpers.swift`, match it.

- [ ] **Step 1: Write the round-trip test**

Create `ios/SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift`. Adapt the staging/open calls to the actual `TestHelpers` API discovered above:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessUI
@testable import SecretaryKit

/// Real-FFI round-trip: drive the REAL VaultBrowseViewModel over a REAL
/// UniffiVaultSession against a TEMP COPY of golden_vault_001 (never the tracked
/// fixture). create -> select source -> move -> read back the moved field value
/// from the KAT, and confirm the source record is tombstoned.
@MainActor
final class BlockCrudRoundTripIntegrationTests: XCTestCase {
    func testCreateThenMoveRoundTripThroughViewModel() throws {
        // 1. Stage a writable temp copy + open via the real adapter.
        //    (Reuse the staging + open helper that RecordEditIntegrationTests uses.)
        let output = try openStagedGoldenVault()  // <- match TestHelpers' actual name
        let session = UniffiVaultSession(output: output, deviceUuids: FixedDeviceUuid())
        let vm = VaultBrowseViewModel(session: session)
        vm.loadBlocks()

        // 2. Create a fresh target block.
        vm.startCreateBlock()
        vm.confirmBlockName("Moved")
        XCTAssertNil(vm.error)
        let target = try XCTUnwrap(vm.blocks.first { $0.name == "Moved" })

        // 3. Select the source block ("Personal logins") and grab its first live record.
        let source = try XCTUnwrap(vm.blocks.first { $0.name == "Personal logins" })
        vm.selectBlock(source)
        let record = try XCTUnwrap(vm.visibleRecords.first)

        // 4. Move it.
        vm.startMoveRecord(record)
        vm.confirmMove(target: target)
        XCTAssertNil(vm.error)
        XCTAssertNil(vm.movingRecord)

        // 5. Read back the TARGET: one live record whose KAT field value survived.
        vm.selectBlock(target)
        let moved = try XCTUnwrap(vm.visibleRecords.first)
        let field = try XCTUnwrap(moved.fields.first { $0.name == "username" })
        XCTAssertEqual(try field.reveal(), .text("owner@example.com"))

        // 6. Source now shows the record tombstoned (withheld unless showDeleted).
        vm.selectBlock(source)
        XCTAssertEqual(vm.visibleRecords.count, 0)
        vm.showDeleted = true
        XCTAssertEqual(vm.visibleRecords.count, 1)
        XCTAssertTrue(vm.visibleRecords.first?.tombstone ?? false)
    }
}
```

> The exact field name (`username`) and value (`owner@example.com`) come from `golden_vault_001`'s "Personal logins" block. Confirm against `core/tests/data/golden_vault_001_inputs.json` (or the iOS-staged `golden_vault_001_inputs.json`) and the existing `VaultAccessIntegrationTests` assertions; use whatever live field/value those tests already assert on.

- [ ] **Step 2: Run the full iOS gauntlet (builds bindings + simulator run)**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: pure host packages pass, framework builds, and the SecretaryKit XCTest suite — including `BlockCrudRoundTripIntegrationTests` — passes on the simulator. To target just this class while iterating: `cd ios/SecretaryKit && swift test --filter BlockCrudRoundTripIntegrationTests` after a prior `build-xcframework.sh`.

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryKit/Tests/SecretaryKitTests/BlockCrudRoundTripIntegrationTests.swift
git commit -m "test(ios): real-FFI create->move->read-back round-trip through the VM"
```

---

### Task 8: Docs — README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Find the Android block-CRUD UI rows to mirror**

Run: `grep -n "block-CRUD UI\|block-CRUD\|Android block" README.md ROADMAP.md`
Expected: the PR #268 Android row in each. Read the neighbours for exact style.

- [ ] **Step 2: Add the iOS row to README.md**

Add a sibling row/dot-point next to the Android block-CRUD UI entry, e.g. (match the surrounding table/list style exactly — brief, audience = curious contributors, no test-count walls per [[feedback_readme_style]]):

```
iOS block-CRUD UI affordance (create/rename block + move record over the SwiftUI browse stack)
```

- [ ] **Step 3: Add the iOS entry to ROADMAP.md**

Add the matching ROADMAP entry beside the Android block-CRUD UI one, in the same numbering/format the file uses.

- [ ] **Step 4: Verify guardrails are empty**

Run:
```bash
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|android/'   # expect EMPTY
git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'                                                        # expect EMPTY
```
Expected: both empty (the regenerated `secretary.swift` is Swift, not Rust; no `.rs`/`Cargo` touched).

- [ ] **Step 5: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: README + ROADMAP rows for iOS block-CRUD UI"
```

---

## Acceptance (whole branch)

```bash
cd /Users/hherb/src/secretary/.worktrees/ios-block-crud-ui

# Host VM + fake (fast, no simulator):
( cd ios/SecretaryVaultAccess && swift test )                 # all green incl. BlockCrud tests

# Full iOS gauntlet (regenerates bindings, builds framework, simulator XCTest):
bash ios/scripts/run-ios-tests.sh                             # BlockCrudRoundTripIntegrationTests green

# Guardrails (MUST be empty):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|android/'   # empty
git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'                                                        # empty
```

## Self-review notes

- **Spec coverage:** Port (T1), adapter (T5), fake (T1), VM create/rename/move + guards + lock (T2–T4), UI (T6), round-trip (T7), docs (T8) — every spec §Layers item maps to a task.
- **No new error case:** confirmed — `.invalidArgument` reused; no `VaultAccessError`/`VaultError` variant added.
- **Type consistency:** `BlockNameDialog` (.create / .rename(block:)), `blockNameDialog`, `movingRecord`, `confirmBlockName`, `confirmMove(target:)`, `guardedWrite(onSuccess:op:)`, `freshUuid()` used consistently across T2–T7.
- **Binding-label risk (T5):** flagged — generated labels are the source of truth; grep `secretary.swift` after regen and match.
- **Helper-name risk (T7):** flagged — read `TestHelpers.swift` and match the real staging/open + `FixedDeviceUuid` API.
```
