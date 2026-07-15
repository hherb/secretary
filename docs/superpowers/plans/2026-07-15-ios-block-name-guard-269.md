# iOS block-name warn-but-allow (#434, mirror of #269) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mirror PR #432's Android warn-but-allow duplicate block-name guard onto iOS: a colliding block name shows a live inline warning and relabels the confirm "Save" → "Save anyway"; a single tap still commits.

**Architecture:** Three layered units — a pure FFI-free `BlockNamePolicy.hasNameCollision` collision predicate (host-tested), a `VaultBrowseViewModel.blockNameCollides(_:)` wiring method that picks the create/rename exclude-uuid (host-tested), and a live-reactive `BlockNameSheet` that replaces the current UIKit-backed SwiftUI `.alert` (which cannot live-update its button/message). Only the SwiftUI render layer is untested — the accepted #417-class gap.

**Tech Stack:** Swift 6 / SwiftUI, XCTest, Swift Package Manager. iOS 17 target.

## Global Constraints

- iOS only. **No `core` / crypto / FFI / on-disk-format / error-variant change; no Rust touched.** Write path (`VaultBrowseViewModel.confirmBlockName`) is unchanged — duplicate block names remain writable (UUID-keyed, harmless).
- Decision is **fixed** (from #269 / PR #432): warn-but-allow, **case-insensitive**, **trimmed candidate**, **one-tap "Save anyway"**. Do not turn this into a hard reject.
- Case fold must be **locale-independent**: `caseInsensitiveCompare(_:)`, NOT `localizedCaseInsensitiveCompare` (Turkish-i-class bugs). Mirror of Android `equals(ignoreCase = true)`.
- Trim the candidate only; compare against `block.name` untrimmed (stored names are trimmed on write).
- Pure/host-testable logic goes in the `SecretaryVaultAccess` package (no xcframework dep → runs in `swift test` Step 1). SwiftUI views go in `ios/SecretaryApp/Sources/`.
- Keep files under 500 lines; one concept per test file.
- Preserve accessibility identifiers `block-name-field` / `block-name-confirm` / `block-name-cancel`.

**Test command (Tasks 1–2, fast, host, no simulator):**
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-block-name-guard-269/ios/SecretaryVaultAccess && swift test
```
Filter a single suite with `swift test --filter BlockNamePolicyTests` (or `VaultBrowseViewModelBlockNameWarnTests`).

**Compile proof (Task 3, app target, needs xcframework — multi-minute, watchdog-prone):**
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-block-name-guard-269 && bash ios/scripts/build-app.sh
```

---

### Task 1: Pure collision predicate `BlockNamePolicy.hasNameCollision`

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/BlockNamePolicy.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/BlockNamePolicyTests.swift`

**Interfaces:**
- Consumes: `BlockSummary` (`uuid: [UInt8]`, `name: String`) from `SecretaryVaultAccess`.
- Produces: `BlockNamePolicy.hasNameCollision(candidate: String, existing: [BlockSummary], excludeUuid: [UInt8]? = nil) -> Bool` — used by Task 2.

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/BlockNamePolicyTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess

/// Host tests for the pure block-name collision predicate. One-for-one mirror of
/// Android `BlockNamePolicyTest.kt` (PR #432). Runs in `swift test` Step 1 (no
/// xcframework), like `MovePolicyTests`.
final class BlockNamePolicyTests: XCTestCase {
    private func block(_ b: UInt8, _ name: String) -> BlockSummary {
        BlockSummary(uuid: Array(repeating: b, count: 16), name: name, createdAtMs: 0, lastModMs: 0)
    }
    private var work: BlockSummary { block(0x11, "Work") }
    private var personal: BlockSummary { block(0x22, "Personal") }
    private var existing: [BlockSummary] { [work, personal] }

    func testEmptyBlockListNeverCollides() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "Work", existing: []))
    }
    func testUniqueNameDoesNotCollide() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "Finance", existing: existing))
    }
    func testExactDuplicateCollides() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "Work", existing: existing))
    }
    func testSurroundingWhitespaceTrimmedBeforeComparison() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "  Work  ", existing: existing))
    }
    func testCaseOnlyDifferenceCollides() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "work", existing: existing))
    }
    func testBlankCandidateNeverCollides() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "   ", existing: existing))
    }
    func testRenameToOwnCurrentNameDoesNotCollide() {
        XCTAssertFalse(BlockNamePolicy.hasNameCollision(candidate: "Work", existing: existing, excludeUuid: work.uuid))
    }
    func testRenameToDifferentExistingNameCollides() {
        XCTAssertTrue(BlockNamePolicy.hasNameCollision(candidate: "Personal", existing: existing, excludeUuid: work.uuid))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter BlockNamePolicyTests`
Expected: FAIL — compile error, `BlockNamePolicy` is not defined.

- [ ] **Step 3: Write minimal implementation**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/BlockNamePolicy.swift`:

```swift
import Foundation

/// Whether a candidate block name collides with an existing block's display name.
/// Pure + FFI-free so it is host-testable without a simulator. Mirror of Android
/// `blockNameCollides` (PR #432), named after `MovePolicy`.
///
/// UX layer ONLY: the write path always allows duplicate block names (they are
/// UUID-keyed and harmless); this drives a warn-but-allow affordance, never a
/// hard reject.
public enum BlockNamePolicy {
    /// True when `candidate` (after trimming) matches the display name of some block in
    /// `existing` OTHER than `excludeUuid`, compared **case-insensitively**. The comparison
    /// is locale-independent via `caseInsensitiveCompare(_:)` — deliberately NOT
    /// `localizedCaseInsensitiveCompare` (Turkish-i-class locale bugs); this is the Swift
    /// analogue of Android's `equals(ignoreCase = true)`. `candidate` is trimmed; `block.name`
    /// is compared untrimmed (stored names are already trimmed on write, so this can only
    /// ever *under*-warn, never falsely warn). `excludeUuid` is the block being renamed
    /// (`nil` on create), so renaming a block without changing its name is never a collision.
    /// Blank candidate → `false` (the blank-name guard in `confirmBlockName` owns that case).
    public static func hasNameCollision(candidate: String,
                                        existing: [BlockSummary],
                                        excludeUuid: [UInt8]? = nil) -> Bool {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return false }
        return existing.contains { block in
            (excludeUuid == nil || block.uuid != excludeUuid!) &&
                trimmed.caseInsensitiveCompare(block.name) == .orderedSame
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter BlockNamePolicyTests`
Expected: PASS — 8 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/BlockNamePolicy.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/BlockNamePolicyTests.swift
git commit -m "feat(ios): pure BlockNamePolicy.hasNameCollision + 8-case host tests (#434)"
```

---

### Task 2: VM wiring `VaultBrowseViewModel.blockNameCollides(_:)`

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` (add one method after `confirmBlockName`, ~line 249)
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockNameWarnTests.swift` (new)

**Interfaces:**
- Consumes: `BlockNamePolicy.hasNameCollision(candidate:existing:excludeUuid:)` (Task 1); `self.blocks: [BlockSummary]`; `self.blockNameDialog: BlockNameDialog?` (`.create` / `.rename(block:)`).
- Produces: `VaultBrowseViewModel.blockNameCollides(_ candidate: String) -> Bool` — used by Task 3's `BlockNameSheet`.

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockNameWarnTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

/// Host tests for the VM's block-name warn wiring: it must pick the correct
/// create/rename exclude-uuid and delegate to the pure predicate, and the
/// write path must stay warn-but-allow (a colliding name still writes).
@MainActor
final class VaultBrowseViewModelBlockNameWarnTests: XCTestCase {
    private func block(_ b: UInt8, _ name: String) -> BlockSummary {
        BlockSummary(uuid: Array(repeating: b, count: 16), name: name, createdAtMs: 0, lastModMs: 0)
    }
    private func makeVM(blocks: [BlockSummary]) -> VaultBrowseViewModel {
        let s = FakeVaultSession(vaultUuidHex: "ab", blocks: blocks, recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: s, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        return vm
    }

    func testCreateModeCollisionWarns() {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        XCTAssertTrue(vm.blockNameCollides("Work"))
    }

    func testCreateModeUniqueDoesNotWarn() {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        XCTAssertFalse(vm.blockNameCollides("Finance"))
    }

    func testBlankNeverWarns() {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        XCTAssertFalse(vm.blockNameCollides("   "))
    }

    func testRenameToOwnNameDoesNotWarn() {
        let work = block(0x11, "Work")
        let vm = makeVM(blocks: [work, block(0x22, "Personal")])
        vm.startRenameBlock(work)
        XCTAssertFalse(vm.blockNameCollides("Work"), "renaming a block to its own name is not a collision")
    }

    func testRenameToOtherExistingNameWarns() {
        let work = block(0x11, "Work")
        let vm = makeVM(blocks: [work, block(0x22, "Personal")])
        vm.startRenameBlock(work)
        XCTAssertTrue(vm.blockNameCollides("Personal"))
    }

    func testCollidingCreateStillWritesTheDuplicate() async {
        let vm = makeVM(blocks: [block(0x11, "Work")])
        vm.startCreateBlock()
        await vm.confirmBlockName("Work")   // warn-but-allow: the write still happens
        XCTAssertNil(vm.blockNameDialog, "dialog clears on a successful (allowed) duplicate write")
        XCTAssertNil(vm.error)
        XCTAssertEqual(vm.blocks.filter { $0.name == "Work" }.count, 2, "the duplicate name is written")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockNameWarnTests`
Expected: FAIL — compile error, `blockNameCollides` is not a member of `VaultBrowseViewModel`.

- [ ] **Step 3: Write minimal implementation**

In `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`, add this method immediately after `confirmBlockName(_:)` (after the closing brace near line 249):

```swift
    /// True when `candidate` collides (case-insensitively, trimmed) with an existing
    /// block's name, EXCLUDING the block currently being renamed. Drives the block-name
    /// sheet's warn-but-allow affordance (`BlockNameSheet`); the write path
    /// (`confirmBlockName`) is unchanged — duplicate names remain writable. Reads the
    /// active dialog to pick the exclude-uuid: `.rename` excludes its own block (so a
    /// no-op rename never warns); `.create`/`.none` exclude nothing.
    public func blockNameCollides(_ candidate: String) -> Bool {
        let excludeUuid: [UInt8]?
        switch blockNameDialog {
        case .rename(let block): excludeUuid = block.uuid
        case .create, .none:     excludeUuid = nil
        }
        return BlockNamePolicy.hasNameCollision(candidate: candidate, existing: blocks, excludeUuid: excludeUuid)
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelBlockNameWarnTests`
Expected: PASS — 6 tests, 0 failures.

Then run the whole package to prove nothing regressed:
Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS — all suites green (including the existing `VaultBrowseViewModelBlockCrudTests` and `MovePolicyTests`).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelBlockNameWarnTests.swift
git commit -m "feat(ios): VaultBrowseViewModel.blockNameCollides warn wiring + host tests (#434)"
```

---

### Task 3: `BlockNameSheet` replaces the `.alert` (live warn affordance)

**Files:**
- Modify: `ios/SecretaryApp/Sources/BlockCrudViews.swift` (add `BlockNameSheet` struct)
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` (replace `.alert(...)` at lines 177-190 with a `.sheet`; rename the `blockNameAlertTitle` computed property to `blockNameSheetTitle` at lines 208-213 and its one call site)

**Interfaces:**
- Consumes: `VaultBrowseViewModel.blockNameCollides(_:)` (Task 2); `viewModel.confirmBlockName(_:)`, `viewModel.cancelBlockNameDialog()`, `viewModel.blockNameDialog`, `viewModel.error`, `viewModel.isWriting`; the parent's `@State private var blockNameField` binding.
- Produces: `struct BlockNameSheet` (app-internal SwiftUI view). No downstream consumers.

Note: this task's deliverable is a **compile-proof + manual simulator check**. The SwiftUI render layer is not host-tested (accepted #417-class gap); all logic it calls is already covered by Tasks 1–2.

- [ ] **Step 1: Add the `BlockNameSheet` view**

Append to `ios/SecretaryApp/Sources/BlockCrudViews.swift`:

```swift
/// Create/rename a block: one text field + Cancel/Save. Warns (but still allows —
/// #269/#434) when the entered name collides case-insensitively with an existing
/// block; the confirm button relabels "Save" → "Save anyway". Live-reactive by
/// design — a `.sheet` (unlike the UIKit-backed `.alert`) rebuilds as the user
/// types, so the warning and relabel update on every keystroke. The write path is
/// unchanged; a single "Save anyway" tap commits the duplicate.
struct BlockNameSheet: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    @Binding var name: String
    let title: String

    var body: some View {
        NavigationStack {
            Form {
                TextField("Block name", text: $name)
                    .accessibilityIdentifier("block-name-field")
                if viewModel.blockNameCollides(name) {
                    Text("A block named \"\(name.trimmingCharacters(in: .whitespacesAndNewlines))\" already exists.")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("block-name-warning")
                }
                if let error = viewModel.error {
                    // A full-screen sheet hides the parent list's error section, so
                    // surface a failed write here (the old .alert left it merely behind).
                    Text(String(describing: error))
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { viewModel.cancelBlockNameDialog() }
                        .accessibilityIdentifier("block-name-cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(viewModel.blockNameCollides(name) ? "Save anyway" : "Save") {
                        Task { await viewModel.confirmBlockName(name) }
                    }
                    .accessibilityIdentifier("block-name-confirm")
                    .disabled(viewModel.isWriting)
                }
            }
        }
    }
}
```

- [ ] **Step 2: Replace the `.alert` with a `.sheet` in `VaultBrowseScreen.swift`**

Replace the entire `.alert(...)` modifier (lines 177-190):

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
                Button("Save") { Task { await viewModel.confirmBlockName(blockNameField) } }
                    .accessibilityIdentifier("block-name-confirm")
                Button("Cancel", role: .cancel) { viewModel.cancelBlockNameDialog() }
                    .accessibilityIdentifier("block-name-cancel")
            }
```

with a `.sheet`:

```swift
            .sheet(isPresented: Binding(
                get: { viewModel.blockNameDialog != nil },
                set: { if !$0 { viewModel.cancelBlockNameDialog() } }
            )) {
                BlockNameSheet(viewModel: viewModel, name: $blockNameField, title: blockNameSheetTitle)
            }
```

- [ ] **Step 3: Rename the title helper to match the new container**

Replace the `blockNameAlertTitle` computed property (lines 208-213):

```swift
    private var blockNameAlertTitle: String {
        switch viewModel.blockNameDialog {
        case .rename: return "Rename block"
        case .create, .none: return "New block"
        }
    }
```

with:

```swift
    private var blockNameSheetTitle: String {
        switch viewModel.blockNameDialog {
        case .rename: return "Rename block"
        case .create, .none: return "New block"
        }
    }
```

(The only call site is the `.sheet` from Step 2, already updated to `blockNameSheetTitle`.)

- [ ] **Step 4: Compile-proof the app target**

Run: `cd /Users/hherb/src/secretary/.worktrees/ios-block-name-guard-269 && bash ios/scripts/build-app.sh`
Expected: BUILD SUCCEEDED. (Multi-minute; needs the xcframework. If run under a watchdog-limited agent, warm the xcframework build once and background the build, polling its log — see [[project_secretary_ios_xcframework_build_watchdog]].)

- [ ] **Step 5: Re-run the host suites (guard against an accidental package edit)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS — all suites green.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryApp/Sources/BlockCrudViews.swift ios/SecretaryApp/Sources/VaultBrowseScreen.swift
git commit -m "feat(ios): live block-name warn sheet replaces static .alert (#434)"
```

---

## Manual verification (on simulator, after Task 3)

Launch the app (`ios/scripts/build-app.sh` builds it; run in the simulator), open a vault, and:
1. Tap **New block**, type the name of an existing block → the warning appears **live** and the button reads **"Save anyway"**.
2. Change a character so the name is unique → the warning disappears and the button reverts to **"Save"**.
3. Tap **"Save anyway"** → the duplicate block is created (two blocks share the name); the sheet dismisses.
4. Swipe a block → **Rename**; leave the name unchanged → **no** warning (self excluded). Change it to another block's name → warning + "Save anyway".

## Self-review notes

- **Spec coverage:** Unit 1 → Task 1; Unit 2 → Task 2; Unit 3 → Task 3; 8-case pure suite → Task 1; VM wiring + warn-but-allow write-intact → Task 2; `.alert`→`.sheet` + inline error non-regression → Task 3. Manual on-sim check → the Manual verification section.
- **Type consistency:** `hasNameCollision(candidate:existing:excludeUuid:)` and `blockNameCollides(_:)` names are used identically in every task. `BlockSummary(uuid:name:createdAtMs:lastModMs:)` matches the real initializer. `blockNameDialog` arms are `.create` / `.rename(block:)` / `.none`.
- **No placeholders:** every code step shows complete code; every run step shows the command + expected result.
