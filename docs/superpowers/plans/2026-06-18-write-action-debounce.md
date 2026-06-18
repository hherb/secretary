# Write-action in-flight guard (#254) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** No write action (record Add/Edit `commit`, or list `delete`/`restore`) can execute twice from concurrent or rapid-repeat taps, on Android and iOS.

**Architecture:** A host-tested re-entrancy guard in each model (a boolean `StateFlow`/`@Published` flag, checked at the top of the write method, reset in `finally`/`defer`) is the correctness fix; the UI reads the flag to disable the button. Android's `commit()` guard checks `inFlight` (concurrent coroutine) **and** `committed` (post-success re-tap render gap); iOS's synchronous `commit()` guards on `committed` for the same render gap. No `core` / `ffi` / on-disk-format / UDL change.

**Tech Stack:** Kotlin + Compose + JUnit5 + kotlinx-coroutines-test (Android `:vault-access`, `:browse-ui`); Swift + SwiftUI + XCTest (`SecretaryVaultAccess`, `SecretaryApp`).

## Global Constraints

- No `core/` / `ffi/` / `crypto-design` / `vault-format` change. Guardrail: `git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'` must be empty.
- `ios/` IS intentionally in the diff this slice (unlike prior Android-only slices). The "no `ios/`" guardrail does NOT apply; the handoff says so explicitly.
- Everything lands under `android/`, `ios/`, `docs/`, `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`. Guardrail: `git diff main...HEAD --name-only | grep -vE '^(android/|ios/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'` empty.
- No new `VaultBrowseError` / `FfiVaultError` / `VaultAccessError` variant (so no workspace-wide exhaustive-match or Swift/Kotlin conformance-harness obligation is triggered).
- TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit. Keep files under 500 lines (all touched files stay well under).
- Working dir: `/Users/hherb/src/secretary/.worktrees/write-action-debounce` on branch `feature/write-action-debounce`. Verify with `pwd && git branch --show-current` before path-sensitive commands.

---

### Task 1: Android `RecordEditModel` in-flight + committed guard

**Files:**
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt` (add an optional write gate so the concurrent test is deterministic)
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt` (add `inFlight`, strengthen the `commit()` guard)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelTest.kt`

**Interfaces:**
- Consumes: existing `RecordEditModel(session, blockUuid, mode)`, `FakeVaultSession`, `committed`/`error`/`loadFailed` StateFlows.
- Produces: `RecordEditModel.inFlight: StateFlow<Boolean>`; `FakeVaultSession(..., writeGate: CompletableDeferred<Unit>? = null)` whose write methods `await` the gate before recording.

- [ ] **Step 1: Add the optional write gate to the host fake**

In `FakeVaultBrowse.kt`, add the import and constructor param, and `await` the gate at the top of every write method (before the audit-list record). This lets a test hold a write in flight while a second call hits the guard.

Add near the top:
```kotlin
import kotlinx.coroutines.CompletableDeferred
```
Add the constructor param (after `rawWriteThrowable`):
```kotlin
    /** When set, every write suspends on this gate before recording — lets a test hold a write
     *  in flight while a second call hits the model's re-entrancy guard (a faithful race, not a sleep). */
    private val writeGate: CompletableDeferred<Unit>? = null,
```
At the **first line** inside `tombstoneRecord`, `resurrectRecord`, `appendRecord`, and `editRecord` (before the existing `writeError?.let { throw it }`), insert:
```kotlin
        writeGate?.await()
```

- [ ] **Step 2: Write the failing tests**

Append to `RecordEditModelTest.kt` (add imports `kotlinx.coroutines.CompletableDeferred`, `kotlinx.coroutines.launch`, `kotlinx.coroutines.test.advanceUntilIdle`, `kotlinx.coroutines.test.runCurrent`):

```kotlin
    @Test
    fun `concurrent commit appends exactly once`() = runTest {
        val gate = CompletableDeferred<Unit>()
        val s = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to emptyList()), writeGate = gate)
        val m = addModel(s)
        m.setRecordType("note"); m.addField(); m.setFieldName(0, "body"); m.setFieldRawText(0, "x")
        launch { m.commit() }   // grabs inFlight, parks on the gate inside appendRecord
        launch { m.commit() }   // sees inFlight == true, returns without appending
        runCurrent()
        assertTrue(m.inFlight.value)
        assertEquals(0, s.appended.size)
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, s.appended.size)
        assertFalse(m.inFlight.value)
        assertTrue(m.committed.value)
    }

    @Test
    fun `second commit after success does not append again`() = runTest {
        val s = session()
        val m = addModel(s)
        m.setRecordType("note"); m.addField(); m.setFieldName(0, "body"); m.setFieldRawText(0, "x")
        m.commit()
        assertTrue(m.committed.value)
        m.commit()   // post-success re-tap (render gap before the form clears) — committed guard blocks it
        assertEquals(1, s.appended.size)
    }

    @Test
    fun `failed write resets inFlight`() = runTest {
        val s = session(writeError = VaultBrowseError.SaveCryptoFailure("boom"))
        val m = addModel(s)
        m.setRecordType("note"); m.addField(); m.setFieldName(0, "body"); m.setFieldRawText(0, "x")
        m.commit()
        assertFalse(m.inFlight.value)
        assertFalse(m.committed.value)
    }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecordEditModelTest'`
Expected: FAIL — `inFlight` is unresolved (and `concurrent commit` would append twice without the guard).

- [ ] **Step 4: Add `inFlight` and strengthen the guard in `RecordEditModel.kt`**

After the `_committed` block (around line 56), add:
```kotlin
    private val _inFlight = MutableStateFlow(false)
    /** True while a [commit] write is in flight. Blocks a concurrent second commit; the UI also
     *  disables Save while set. Reset in [commit]'s finally on success, typed error, and raw throwable. */
    val inFlight: StateFlow<Boolean> = _inFlight.asStateFlow()
```
Replace the `commit()` body's opening guard + wrap the work in try/finally:
```kotlin
    suspend fun commit() {
        if (_inFlight.value || _committed.value || _loadFailed.value) return
        _inFlight.value = true
        try {
            val content = buildContent() ?: return // sets _error on hex failure
            content.validate()?.let {
                _error.value = mapValidation(it)
                return
            }
            try {
                when (val m = mode) {
                    Mode.Add -> session.appendRecord(blockUuid, content)
                    is Mode.Edit -> session.editRecord(blockUuid, m.recordUuid, content)
                }
                _error.value = null
                _committed.value = true
            } catch (e: VaultBrowseError) {
                _error.value = e
            } catch (e: CancellationException) {
                throw e // never swallow coroutine cancellation (commit is suspend)
            } catch (e: Exception) {
                _error.value = VaultBrowseError.Failed(e.toString())
            }
        } finally {
            _inFlight.value = false
        }
    }
```
(The `return` on hex/validation failure now returns through the `finally`, correctly clearing `inFlight`.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.RecordEditModelTest'`
Expected: PASS (all existing + 3 new).

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git add android/vault-access/src/main/kotlin/org/secretary/browse/RecordEditModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/RecordEditModelTest.kt
git commit -m "feat(android): in-flight + committed guard on RecordEditModel.commit (#254)"
```

---

### Task 2: Android `VaultBrowseModel` writing guard (delete/restore)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt`

**Interfaces:**
- Consumes: existing `VaultBrowseModel(session)`, `delete`/`restore`/`commitThenReload`, `FakeVaultSession(writeGate = …)` from Task 1.
- Produces: `VaultBrowseModel.writing: StateFlow<Boolean>`.

- [ ] **Step 1: Write the failing tests**

Append to `VaultBrowseModelTest.kt` (add imports as in Task 1: `CompletableDeferred`, `launch`, `advanceUntilIdle`, `runCurrent`). Use the file's existing helpers to build a model with one selected block containing one live record `rec`; if the file lacks a ready selected-block helper, build inline mirroring the existing delete test. Skeleton:

```kotlin
    @Test
    fun `concurrent delete tombstones exactly once`() = runTest {
        val gate = CompletableDeferred<Unit>()
        val s = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec)), writeGate = gate)
        val m = VaultBrowseModel(s)
        m.loadBlocks()
        m.selectBlock(m.blocks.value.single())
        launch { m.delete(rec) }   // grabs writing, parks on the gate
        launch { m.delete(rec) }   // sees writing == true, returns
        runCurrent()
        assertTrue(m.writing.value)
        assertEquals(0, s.tombstoned.size)
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, s.tombstoned.size)
        assertFalse(m.writing.value)
    }

    @Test
    fun `failed delete resets writing and keeps the list`() = runTest {
        val s = session(/* writeError = SaveCryptoFailure, one selected block with rec */)
        val m = VaultBrowseModel(s)
        m.loadBlocks(); m.selectBlock(m.blocks.value.single())
        val before = m.selectedRecords.value
        m.delete(rec)
        assertFalse(m.writing.value)
        assertEquals(before, m.selectedRecords.value)   // rejected write leaves the list intact
    }
```
(Match `block`/`rec`/`session(...)` to this test file's existing fixtures; reuse the existing delete-test's setup verbatim for the block+record so only the gate and `writing` assertions are new.)

- [ ] **Step 2: Run to verify they fail**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: FAIL — `writing` unresolved.

- [ ] **Step 3: Add `writing` and guard `commitThenReload`**

In `VaultBrowseModel.kt`, after the `_editing` block (around line 45) add:
```kotlin
    private val _writing = MutableStateFlow(false)
    /** True while a delete/restore write is in flight. Disables ALL delete/restore buttons in the UI
     *  (global flag — writes serialize under the session lock, so no concurrent write is allowed). */
    val writing: StateFlow<Boolean> = _writing.asStateFlow()
```
Replace `commitThenReload`:
```kotlin
    private suspend fun commitThenReload(op: suspend (BlockSummaryView) -> Unit) {
        val block = _selectedBlock.value ?: return
        if (_writing.value) return
        _writing.value = true
        try {
            try {
                op(block)
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }
            selectBlock(block)
        } finally {
            _writing.value = false
        }
    }
```
In `lock()`, add `_writing.value = false` alongside the other resets (defense-in-depth — a wipe racing a write).

- [ ] **Step 4: Run to verify they pass**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: PASS.

- [ ] **Step 5: Run the whole vault-access suite (no regressions from the fake change)**

Run: `cd android && ./gradlew :vault-access:test`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt
git commit -m "feat(android): global writing guard on VaultBrowseModel delete/restore (#254)"
```

---

### Task 3: Android `:browse-ui` — expose flags, disable buttons, instrumented test

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt` (re-expose `writing`)
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/RecordEditForm.kt` (Save disabled while `inFlight`)
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt` (delete/restore/add disabled while `writing`)
- Modify: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt` (add `writeGate` param, mirroring Task 1)
- Test: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/RecordEditFormTest.kt` (Save-disabled) and the existing soft-delete instrumented test file for Delete-disabled

**Interfaces:**
- Consumes: `VaultBrowseModel.writing`, `RecordEditModel.inFlight` (Tasks 1–2).
- Produces: `VaultBrowseViewModel.writing: StateFlow<Boolean>`.

- [ ] **Step 1: Add the write gate to the androidTest fake**

Mirror Task 1 Step 1 in `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt`: `import kotlinx.coroutines.CompletableDeferred`, add `private val writeGate: CompletableDeferred<Unit>? = null` constructor param, and `writeGate?.await()` at the top of each write method. (If this androidTest fake's class shape differs from the host one, adapt the same idea: await the gate before recording the write.)

- [ ] **Step 2: Write the failing instrumented tests**

In `RecordEditFormTest.kt`, add (uses `composeTestRule`, a gated fake, and the existing harness that mounts the form):
```kotlin
    @Test
    fun saveDisabledWhileWriteInFlight() {
        val gate = CompletableDeferred<Unit>()
        // build the model/VM over a FakeVaultSession(writeGate = gate) with one selected block,
        // open the Add form, fill a valid field (mirror the existing add test's setup)
        // tap Save -> commit launches, parks on the gate
        composeTestRule.onNodeWithTag("save-record").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("save-record").assertIsNotEnabled()
        gate.complete(Unit)
    }
```
In the soft-delete instrumented test file (the slice-9 `BrowseScreenSoftDeleteTest`), add:
```kotlin
    @Test
    fun deleteDisabledWhileWriteInFlight() {
        val gate = CompletableDeferred<Unit>()
        // mount BrowseScreen over a gated fake with one live record in the selected block
        composeTestRule.onNodeWithTag("delete-$uuidHex").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("delete-$uuidHex").assertIsNotEnabled()
        gate.complete(Unit)
    }
```
(Reuse each file's existing setup verbatim; only the gate + `assertIsNotEnabled` lines are new. Import `androidx.compose.ui.test.assertIsNotEnabled` and `kotlinx.coroutines.CompletableDeferred`.)

- [ ] **Step 3: Run to verify they fail (emulator running)**

Run: `cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" ./gradlew :browse-ui:connectedDebugAndroidTest --tests '*RecordEditFormTest' --tests '*BrowseScreenSoftDeleteTest'`
Expected: FAIL — buttons are still enabled mid-write.

- [ ] **Step 4: Wire the flags into the UI**

`VaultBrowseViewModel.kt` — add after `val showDeleted` line:
```kotlin
    /** True while a delete/restore write is in flight (disables list write buttons). */
    val writing: StateFlow<Boolean> = model.writing
```
`RecordEditForm.kt` — collect `inFlight` and gate Save:
```kotlin
    val inFlight by model.inFlight.collectAsStateWithLifecycle()
```
and change the Save `TextButton`'s `enabled = !loadFailed` to:
```kotlin
                enabled = !loadFailed && !inFlight,
```
`BrowseScreen.kt` — collect `writing` (near the other `collectAsStateWithLifecycle` calls):
```kotlin
    val writing by viewModel.writing.collectAsStateWithLifecycle()
```
Thread it into `RecordRow` (add a `writing: Boolean` param) and set `enabled = !writing` on the Delete, Restore, and Add `TextButton`s. The Add button is in the block header `Row` (line ~85): `TextButton(onClick = { viewModel.startAdd() }, enabled = !writing, …)`.

- [ ] **Step 5: Run to verify they pass**

Run: `cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" ./gradlew :browse-ui:connectedDebugAndroidTest`
Expected: all `:browse-ui` connected tests PASS (existing + 2 new).

- [ ] **Step 6: Host build + commit**

```bash
cd android && ./gradlew :browse-ui:test   # host unit (no regression)
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/RecordEditForm.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt \
        android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt \
        android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/RecordEditFormTest.kt \
        android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenSoftDeleteTest.kt
git commit -m "feat(android): disable Save/delete/restore/add while a write is in flight (#254)"
```

---

### Task 4: iOS `RecordEditViewModel` committed + isWriting guard

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift`

**Interfaces:**
- Consumes: existing `RecordEditViewModel(session, blockUuid, mode)`, `committed`/`loadFailed`, `FakeVaultSession`.
- Produces: `RecordEditViewModel.isWriting: Bool` (published, private-set).

- [ ] **Step 1: Write the failing test**

Append to `RecordEditViewModelTests.swift`:
```swift
    func testSecondCommitAfterSuccessDoesNotAppendAgain() throws {
        let s = session()
        let vm = RecordEditViewModel(session: s, blockUuid: block, mode: .add)
        vm.recordType = "login"; vm.addField(); vm.fields[0].name = "user"; vm.fields[0].rawText = "alice"
        vm.commit()
        XCTAssertTrue(vm.committed)
        vm.commit()   // render-gap re-tap: committed guard must block a second append
        XCTAssertEqual(try s.readBlock(blockUuid: block, includeDeleted: false).count, 1)
        XCTAssertFalse(vm.isWriting)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter RecordEditViewModelTests/testSecondCommitAfterSuccessDoesNotAppendAgain`
Expected: FAIL — `isWriting` unknown member (and without the `committed` guard, count would be 2).

- [ ] **Step 3: Add `isWriting` and the guard**

In `RecordEditViewModel.swift`, after the `committed` published property (line ~34) add:
```swift
    @Published public private(set) var isWriting = false
```
Change `commit()`'s opening guard and wrap the write so the flag always resets:
```swift
    public func commit() {
        guard !committed, !isWriting, !loadFailed else { return }
        isWriting = true
        defer { isWriting = false }
        let content: RecordContentInput
        do {
            content = try buildContent()
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .other(String(describing: error))
            return
        }
        if let v = content.validate() {
            error = Self.mapValidation(v)
            return
        }
        do {
            switch mode {
            case .add:
                try session.appendRecord(blockUuid: blockUuid, content: content)
            case .edit(let recordUuid):
                try session.editRecord(blockUuid: blockUuid, recordUuid: recordUuid, content: content)
            }
            error = nil
            committed = true
        } catch let e as VaultAccessError {
            error = e
        } catch {
            self.error = .other(String(describing: error))
        }
    }
```
(The old standalone `guard !loadFailed else { return }` is folded into the new combined guard.)

- [ ] **Step 4: Run to verify it passes (+ full edit-VM suite)**

Run: `cd ios/SecretaryVaultAccess && swift test --filter RecordEditViewModelTests`
Expected: PASS (all existing + new).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/RecordEditViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/RecordEditViewModelTests.swift
git commit -m "feat(ios): committed+isWriting guard on RecordEditViewModel.commit (#254)"
```

---

### Task 5: iOS `VaultBrowseViewModel` isWriting + SwiftUI button disables

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift`
- Modify: `ios/SecretaryApp/Sources/RecordEditScreen.swift` (Save `.disabled`)
- Modify: `ios/SecretaryApp/Sources/VaultBrowseScreen.swift` (Delete/Restore/Add `.disabled`)
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift`

**Interfaces:**
- Consumes: existing `VaultBrowseViewModel.delete`/`restore`/`commitThenReload`.
- Produces: `VaultBrowseViewModel.isWriting: Bool` (published, private-set).

Note: `SecretaryApp` SwiftUI views are an XcodeGen target, NOT covered by `swift test`. The view `.disabled` one-liners are verified by compilation (the VM flag is the tested part). The iOS delete/restore path is synchronous on `@MainActor` so it cannot truly re-enter; the guard + `.disabled` are UX parity (disable the swipe/dialog button during the brief write). The real iOS double-write (Add) is fixed in Task 4.

- [ ] **Step 1: Write the failing test**

Append to `VaultBrowseViewModelTests.swift` (mirror the file's existing delete-test setup for `vm`/`record`):
```swift
    func testIsWritingFalseAtRestAndAfterDelete() throws {
        // build vm with one selected block containing a live record (reuse existing delete-test setup)
        XCTAssertFalse(vm.isWriting)
        vm.delete(record: record)          // synchronous; returns after the re-read
        XCTAssertFalse(vm.isWriting)       // defer reset ran
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelTests/testIsWritingFalseAtRestAndAfterDelete`
Expected: FAIL — `isWriting` unknown member.

- [ ] **Step 3: Add `isWriting` and guard `commitThenReload`**

In `VaultBrowseViewModel.swift`, add a published flag near the other `@Published` properties:
```swift
    @Published public private(set) var isWriting = false
```
Wrap `commitThenReload`:
```swift
    private func commitThenReload(_ op: ([UInt8]) throws -> Void) {
        guard let blockUuid = selectedBlockUuid else { return }
        guard !isWriting else { return }
        isWriting = true
        defer { isWriting = false }
        do {
            try op(blockUuid)
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .other(String(describing: error))
            return
        }
        reload(blockUuid: blockUuid)
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter VaultBrowseViewModelTests`
Expected: PASS.

- [ ] **Step 5: Disable the SwiftUI buttons**

`RecordEditScreen.swift` — change the Save button:
```swift
                    Button("Save") { viewModel.commit() }
                        .disabled(viewModel.loadFailed || viewModel.committed || viewModel.isWriting)
```
`VaultBrowseScreen.swift` — add `.disabled(viewModel.isWriting)` to: the confirmation-dialog Delete button (line ~120), the swipe-action Restore button (line ~155), the swipe-action Delete button (line ~162), and the Add-record button (line ~77). Example:
```swift
                    Button("Delete", role: .destructive) {
                        viewModel.delete(record: record)
                    }
                    .disabled(viewModel.isWriting)
```

- [ ] **Step 6: Verify the iOS package + app compile**

Run: `cd ios/SecretaryVaultAccess && swift build && swift test`
Expected: BUILD + tests green. (If an `xcodegen`/`xcodebuild` step for `SecretaryApp` is part of the repo's iOS verification — see `ios/` README — run it to confirm the view changes compile; otherwise the package build + targeted review of the one-line `.disabled` edits suffices, as in slice 10.)

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultBrowseViewModel.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultBrowseViewModelTests.swift \
        ios/SecretaryApp/Sources/RecordEditScreen.swift \
        ios/SecretaryApp/Sources/VaultBrowseScreen.swift
git commit -m "feat(ios): isWriting guard + disable write buttons in flight (#254)"
```

---

### Task 6: Docs + close #254

**Files:**
- Modify: `README.md`, `ROADMAP.md`

- [ ] **Step 1: Update README.md**

Add an entry under the Android C.3 progress (mirroring the slice rows' style, brief): a "write-action debounce" line noting the in-flight + committed guard on Add/Edit commit and delete/restore, Android + iOS, no core/ffi/format change, closing #254.

- [ ] **Step 2: Update ROADMAP.md**

Add a matching dot-point under the C.3 Android section noting #254 closed (write-action in-flight guard, cross-platform).

- [ ] **Step 3: Full gauntlet**

```bash
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce/ios/SecretaryVaultAccess && swift test
```
Expected: all green.

- [ ] **Step 4: Guardrail greps (both empty)**

```bash
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'
git diff main...HEAD --name-only | grep -vE '^(android/|ios/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
```

- [ ] **Step 5: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: write-action debounce shipped (Android + iOS), closes #254"
```

---

## Self-Review

**Spec coverage:**
- Android `RecordEditModel.inFlight` + `committed` guard → Task 1. ✅
- Android `VaultBrowseModel.writing` global guard → Task 2. ✅
- Android UI disable (Save/Delete/Restore/Add) + instrumented tests → Task 3. ✅
- iOS `RecordEditViewModel` `committed`/`isWriting` guard → Task 4. ✅
- iOS `VaultBrowseViewModel` `isWriting` + SwiftUI disables → Task 5. ✅
- Guardrails + docs + close #254 → Task 6. ✅
- Read-path actions left unguarded (non-goal) — no task touches `setShowDeleted`/`selectBlock`/`reveal`. ✅

**Placeholder scan:** Test bodies in Tasks 2, 3, 5 say "reuse existing setup" for fixtures (`block`/`rec`/`vm`/`record`/harness) rather than re-printing each file's boilerplate — the new assertions are shown in full. This is deliberate (the existing delete/add tests in those files are the canonical setup; copying them verbatim risks drift). Not a logic placeholder.

**Type consistency:** `inFlight`/`writing`/`isWriting` names are consistent across model → VM → UI in each platform. `writeGate: CompletableDeferred<Unit>?` is the same param name in both Android fakes. `committed` is the existing property reused on both platforms.
