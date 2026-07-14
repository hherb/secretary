# Mobile Move-Affordance Parity (#429) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hide the per-record Move affordance on Android and iOS when the vault has ≤ 1 live block (no candidate target), mirroring desktop #273.

**Architecture:** Each platform derives the live-block count from the `blocks` collection its browse view-model already holds and feeds it to a pure `hasMoveTargets(blockCount) -> Bool` guard that gates the Move affordance. No new FFI/IPC. The move-picker empty-state and the Rust `move_record_impl` same-block guard remain the authoritative safety layer — this is a UX layer only.

**Tech Stack:** Kotlin / Jetpack Compose (`android/browse-ui`), Swift / SwiftUI (`ios/`), JUnit5 (Android host), Compose UI test (Android instrumented, emulator), XCTest via `swift test` (iOS host).

## Global Constraints

- Named constant `MIN_BLOCKS_TO_MOVE` / `minBlocksToMove` **= 2** (record's own block + ≥ 1 distinct target); **no magic number**.
- `hasMoveTargets(blockCount) == blockCount >= 2`. Reimplemented per platform (no cross-platform code sharing).
- **No `core` / crypto / FFI-bridge / uniffi / pyo3 / on-disk-format change; no new error variant; no Rust touched.**
- The Move-picker empty-state and `move_record_impl` guard stay in place (do not remove).
- Android host unit tests live in `src/test` (JVM, no emulator); Compose render tests live in `src/androidTest` (emulator).
- iOS pure helper lives in the FFI-free `SecretaryVaultAccess` module; VM lives in `SecretaryVaultAccessUI`; both are host-testable via `swift test`. The SwiftUI screen (`ios/SecretaryApp/Sources/VaultBrowseScreen.swift`) has no literal render-assertion test (infra gap tracked as #417).
- Only the **Move** affordance is gated. Edit / Delete / Restore / Reveal are unchanged.

---

## File Structure

**Android**
- `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseRenderHelpers.kt` — add pure `hasMoveTargets`.
- `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt` — thread `canMove` into `RecordRow`, gate Move button.
- `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt` — host unit for `hasMoveTargets`.
- `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenMoveButtonTest.kt` — **new** instrumented render test.

**iOS**
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MovePolicy.swift` — **new** pure helper.
- `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift` — add `hasMoveTargets` computed property.
- `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` — gate the Move swipe button.
- `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MovePolicyTests.swift` — **new** host unit.
- `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift` — add VM-property host test.

---

## Task 1: Android pure `hasMoveTargets` guard (host)

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseRenderHelpers.kt`
- Test: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt`

**Interfaces:**
- Produces: `fun hasMoveTargets(blockCount: Int): Boolean` (package `org.secretary.browse.ui`).

- [ ] **Step 1: Write the failing test**

Append inside the `BrowseRenderHelpersTest` class body in `BrowseRenderHelpersTest.kt`:

```kotlin
    @Test
    fun `move is hidden when the vault has zero or one block`() {
        assertEquals(false, hasMoveTargets(0))
        assertEquals(false, hasMoveTargets(1))
    }

    @Test
    fun `move is shown once a second block exists`() {
        assertEquals(true, hasMoveTargets(2))
        assertEquals(true, hasMoveTargets(3))
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :browse-ui:testDebugUnitTest --tests "org.secretary.browse.ui.BrowseRenderHelpersTest"`
Expected: FAIL — `hasMoveTargets` unresolved reference.

- [ ] **Step 3: Write minimal implementation**

Append to `BrowseRenderHelpers.kt` (after `revealedText`):

```kotlin
/** Minimum live-block count for a record move to have a destination: the record's own block plus
 *  at least one distinct target block. */
private const val MIN_BLOCKS_TO_MOVE = 2

/** True when at least one block OTHER than the record's own exists, so a Move has a real
 *  destination. [blockCount] is the live-block count the browse VM already holds — the same
 *  collection the move picker enumerates — so below the threshold the Move affordance can only
 *  dead-end into the picker's empty state and is hidden. UX layer only: the picker empty-state and
 *  the Rust `move_record_impl` guard remain authoritative (parity with desktop #273 / mobile #429). */
fun hasMoveTargets(blockCount: Int): Boolean = blockCount >= MIN_BLOCKS_TO_MOVE
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :browse-ui:testDebugUnitTest --tests "org.secretary.browse.ui.BrowseRenderHelpersTest"`
Expected: PASS (all `BrowseRenderHelpersTest` cases green).

- [ ] **Step 5: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseRenderHelpers.kt \
        android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt
git commit -m "feat(android): pure hasMoveTargets guard for Move affordance (#429)"
```

---

## Task 2: Android — gate the Move button + instrumented render test (emulator)

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`
- Test: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenMoveButtonTest.kt` (new)

**Interfaces:**
- Consumes: `hasMoveTargets(blockCount: Int)` (Task 1); `VaultBrowseViewModel`, `BrowseScreen`, `FakeVaultSession(vaultUuidHex, blocks, recordsByBlock)`, `textField(name, value)`, `BlockSummaryView(ByteArray, String, ULong, ULong)`, `RecordSummaryView(uuidHex, type, tags, ULong, ULong, tombstone, fields)`.
- Produces: `RecordRow(..., canMove: Boolean, ...)` (private); Move `TextButton` rendered only when `canMove`.

- [ ] **Step 1: Write the failing test**

Create `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenMoveButtonTest.kt`:

```kotlin
package org.secretary.browse.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

/** #429: the per-record Move affordance is hidden when the open vault has no other block to move
 *  into, and shown once a second block exists. Only Move is gated — Edit/Delete stay. */
class BrowseScreenMoveButtonTest {
    @get:Rule val composeRule = createComposeRule()

    private val liveUuid = "33445566778899aabbccddeeff001122"
    private val logins = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val cards = BlockSummaryView(ByteArray(16) { 0x4d }, "Cards", 1u, 2u)
    private val live = RecordSummaryView(
        liveUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("username", "u")),
    )

    private fun open(blocks: List<BlockSummaryView>): VaultBrowseViewModel {
        val session = FakeVaultSession("abcd", blocks, mapOf(logins.uuidHex to listOf(live)))
        val vm = VaultBrowseViewModel(VaultBrowseModel(session))
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()
        composeRule.waitForIdle()
        return vm
    }

    @Test
    fun singleBlockVault_hidesMoveButton_butKeepsEditAndDelete() {
        open(listOf(logins))
        composeRule.onAllNodesWithTag("move-$liveUuid").assertCountEquals(0)
        composeRule.onNodeWithTag("edit-$liveUuid").assertIsDisplayed()
        composeRule.onNodeWithTag("delete-$liveUuid").assertIsDisplayed()
    }

    @Test
    fun multiBlockVault_showsMoveButton() {
        open(listOf(logins, cards))
        composeRule.onNodeWithTag("move-$liveUuid").assertIsDisplayed()
    }
}
```

(`onNodeWithTag` import is required for the `edit-`/`delete-`/`move-` single-node assertions — add `import androidx.compose.ui.test.onNodeWithTag`.)

- [ ] **Step 2: Run test to verify it fails**

Start the emulator if needed (paths per repo convention — adb/emulator are not on the bare PATH), then:

Run: `cd android && ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BrowseScreenMoveButtonTest`
Expected: FAIL — `singleBlockVault_hidesMoveButton_butKeepsEditAndDelete` finds 1 `move-<uuid>` node (button not yet gated).

- [ ] **Step 3: Add the `canMove` parameter to `RecordRow`**

In `BrowseScreen.kt`, add the parameter to the `RecordRow` signature (after `onMove`):

```kotlin
    onMove: (RecordSummaryView) -> Unit,
    canMove: Boolean,
) {
```

- [ ] **Step 4: Gate the Move `TextButton`**

In `RecordRow`, wrap the existing Move `TextButton` in an `if (canMove)`:

```kotlin
                    if (canMove) {
                        TextButton(
                            onClick = { onMove(record) },
                            enabled = !writing,
                            modifier = Modifier.testTag("move-${record.uuidHex}"),
                        ) { Text("Move") }
                    }
```

- [ ] **Step 5: Pass `canMove` from the record branch call site**

In `BrowseScreen`'s selected-block `LazyColumn`, update the `RecordRow(...)` call to pass `canMove` (computed from the already-collected `blocks`):

```kotlin
                    RecordRow(
                        record = r,
                        revealed = revealed,
                        autoHideMillis = autoHideMillis,
                        writing = writing,
                        onReveal = viewModel::reveal,
                        onHide = viewModel::hide,
                        onDelete = viewModel::delete,
                        onRestore = viewModel::restore,
                        onEdit = viewModel::startEdit,
                        onMove = viewModel::startMoveRecord,
                        canMove = hasMoveTargets(blocks.size),
                    )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd android && ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BrowseScreenMoveButtonTest`
Expected: PASS (both cases). Also re-run the existing suite that renders `RecordRow` to prove no regression:
Run: `cd android && ./gradlew :browse-ui:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BrowseScreenSoftDeleteTest`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt \
        android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenMoveButtonTest.kt
git commit -m "feat(android): hide per-record Move button when no other block (#429)"
```

---

## Task 3: iOS pure `MovePolicy.hasMoveTargets` (host)

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MovePolicy.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MovePolicyTests.swift` (new)

**Interfaces:**
- Produces: `enum MovePolicy { public static func hasMoveTargets(blockCount: Int) -> Bool }`.

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MovePolicyTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccess

final class MovePolicyTests: XCTestCase {
    func testHiddenWhenZeroOrOneBlock() {
        XCTAssertFalse(MovePolicy.hasMoveTargets(blockCount: 0))
        XCTAssertFalse(MovePolicy.hasMoveTargets(blockCount: 1))
    }

    func testShownOnceASecondBlockExists() {
        XCTAssertTrue(MovePolicy.hasMoveTargets(blockCount: 2))
        XCTAssertTrue(MovePolicy.hasMoveTargets(blockCount: 3))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter MovePolicyTests`
Expected: FAIL — cannot find `MovePolicy` in scope (compile error).

- [ ] **Step 3: Write minimal implementation**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MovePolicy.swift`:

```swift
import Foundation

/// Policy for whether the per-record Move affordance has anywhere to go. A move needs the record's
/// own block plus at least one distinct target block. The SwiftUI browse screen gates the Move
/// swipe action on the view model's `hasMoveTargets`, which delegates here. UX layer only: the move
/// picker's empty-state and the Rust `move_record_impl` guard remain authoritative (parity with
/// desktop #273 / mobile #429). The threshold is a named constant — never a magic number.
public enum MovePolicy {
    /// The record's own block + at least one distinct target block.
    static let minBlocksToMove = 2

    /// True when at least one block OTHER than the record's own exists, so a Move has a real
    /// destination. `blockCount` is the live-block count the browse VM already holds — the same
    /// collection the picker enumerates — so below the threshold Move can only dead-end.
    public static func hasMoveTargets(blockCount: Int) -> Bool { blockCount >= minBlocksToMove }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter MovePolicyTests`
Expected: PASS (both cases).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/MovePolicy.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/MovePolicyTests.swift
git commit -m "feat(ios): pure MovePolicy.hasMoveTargets guard (#429)"
```

---

## Task 4: iOS — VM `hasMoveTargets` property (host) + gate the SwiftUI Move swipe

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift`

**Interfaces:**
- Consumes: `MovePolicy.hasMoveTargets(blockCount:)` (Task 3); `VaultBrowseViewModel(session:gate:)`, `BlockSummary(uuid:name:createdAtMs:lastModMs:)`, `FakeVaultSession(vaultUuidHex:blocks:recordsByBlock:)`, `FakeWriteReauthGate()`.
- Produces: `VaultBrowseViewModel.hasMoveTargets: Bool` (public computed).

- [ ] **Step 1: Write the failing test**

Append inside the `VaultBrowseViewModelTests` class body:

```swift
    func testHasMoveTargetsFalseWithSingleBlock() {
        let block = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [block], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        XCTAssertFalse(vm.hasMoveTargets)
    }

    func testHasMoveTargetsTrueWithTwoBlocks() {
        let logins = BlockSummary(uuid: [7], name: "Logins", createdAtMs: 1, lastModMs: 2)
        let cards = BlockSummary(uuid: [8], name: "Cards", createdAtMs: 1, lastModMs: 2)
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [logins, cards], recordsByBlock: [:])
        let vm = VaultBrowseViewModel(session: session, gate: FakeWriteReauthGate())
        vm.loadBlocks()
        XCTAssertTrue(vm.hasMoveTargets)
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelTests`
Expected: FAIL — `value of type 'VaultBrowseViewModel' has no member 'hasMoveTargets'`.

- [ ] **Step 3: Add the VM computed property**

In `VaultBrowseViewModel.swift`, add a computed property near the other `@Published` block state (e.g. just after the `visibleRecords` computed property). Import is already `SecretaryVaultAccess` via the module dependency:

```swift
    /// True when the vault has a candidate target block for a record move (live block count ≥ 2).
    /// Delegates to the pure `MovePolicy`; the SwiftUI screen gates the Move swipe action on this.
    /// UX layer only — the move picker empty-state and the Rust `move_record_impl` guard remain
    /// authoritative (parity with desktop #273 / mobile #429).
    public var hasMoveTargets: Bool { MovePolicy.hasMoveTargets(blockCount: blocks.count) }
```

(`import SecretaryVaultAccess` is already present at the top of this file, so `MovePolicy` resolves with no new import.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelTests`
Expected: PASS (both new cases + the existing ones).

- [ ] **Step 5: Gate the SwiftUI Move swipe button**

In `VaultBrowseScreen.swift`'s `recordView`, wrap the Move `Button` (inside the `.swipeActions(edge: .leading)` `if !record.tombstone` branch, after the Edit button) in `if viewModel.hasMoveTargets`:

```swift
                if viewModel.hasMoveTargets {
                    Button {
                        viewModel.startMoveRecord(record)
                    } label: {
                        Label("Move", systemImage: "folder")
                    }
                    .tint(.indigo)
                    .disabled(viewModel.isWriting)
                    .accessibilityIdentifier("move-\(record.uuidHex)")
                }
```

- [ ] **Step 6: Verify the app target compiles**

Run the iOS app-target build so the SwiftUI edit is compiled (the render behavior has no host test — infra gap #417 — so a green build is the gate for this file):
Run: `bash ios/scripts/run-ios-tests.sh` (or a full `xcodebuild` of the `SecretaryApp` scheme).
Expected: build succeeds; the host test suites (Step 4) stay green.

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryApp/Sources/VaultBrowseScreen.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift
git commit -m "feat(ios): hide per-record Move swipe when no other block (#429)"
```

---

## Self-Review

**Spec coverage:**
- Android pure guard → Task 1. Android gate + instrumented render test (single-block hides, 2+ shows) → Task 2. ✅
- iOS pure guard → Task 3. iOS host-testable VM gating → Task 4 (Steps 1–4). iOS SwiftUI render pattern gated on VM prop → Task 4 (Step 5). ✅
- "Only Move gated; Edit/Delete stay" → asserted in Task 2 Step 1 (`edit-`/`delete-` still displayed). ✅
- "Picker empty-state + `move_record_impl` guard unchanged" → no task touches them; called out in every helper's doc comment. ✅
- Named constant, no magic number → Task 1 Step 3, Task 3 Step 3. ✅
- No core/FFI/Rust change → no task touches those trees. ✅

**Placeholder scan:** No TBD/TODO/"add error handling"/"similar to Task N". Every code step shows full code. ✅

**Type consistency:** `hasMoveTargets(blockCount: Int)` used identically in Tasks 1–2 (Kotlin) and 3–4 (Swift). `canMove: Boolean` param name matches between `RecordRow` definition (Task 2 Step 3) and call site (Task 2 Step 5). `MovePolicy.hasMoveTargets` name matches between definition (Task 3) and VM consumer (Task 4 Step 3). Fake/type constructors copied from existing tests. ✅

## Notes for the executor
- **Worktree:** all work is in `.worktrees/mobile-move-parity-429` on branch `feature/mobile-move-parity-429`. Use full worktree paths with Edit/Write (a bare main-repo path silently edits `main`).
- **Android emulator** is available but not on the bare PATH — use absolute `adb`/`emulator` paths; `connectedAndroidTest` rejects `--tests` (use `-Pandroid.testInstrumentationRunnerArguments.class=`).
- **iOS host tests** (`swift test`) run in `ios/SecretaryVaultAccess`; they are fast and FFI-free. The `run-ios-tests.sh` Rust xcframework build is multi-minute and silent — warm it once and prefer backgrounding with log-polling.
