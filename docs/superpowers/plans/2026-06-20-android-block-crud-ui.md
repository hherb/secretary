# Android block-CRUD UI affordances Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the already-shipped FFI ops `create_block` / `rename_block` / `move_record` into the Android Compose browse UI via dialogs.

**Architecture:** Follow the existing browse layering exactly — extend the `VaultSession` port (`:vault-access`), implement it in the real `UniffiVaultSession` adapter (`:kit`), add presentation state + actions to the host-tested pure `VaultBrowseModel` (`:vault-access`), re-expose through the thin androidx `VaultBrowseViewModel` (`:browse-ui`), and surface "New block" / "Rename" / "Move" buttons plus two dialogs in `BrowseScreen` (`:browse-ui`). The bulk of the logic is host-tested against in-memory fakes; one `:app` instrumented Compose test drives the real FFI over a staged golden vault as the acceptance gate.

**Tech Stack:** Kotlin, Coroutines + StateFlow, Jetpack Compose (Material3), JUnit5 (host, `org.junit.jupiter`), AndroidX Compose UI test + AndroidJUnit4 (instrumented), uniffi-generated `uniffi.secretary` bindings.

## Global Constraints

- **Android only.** No change to `core/`, `docs/crypto-design.md`, `docs/vault-format.md`, `*.udl`, `ffi/secretary-ffi-py`, or `ios/`. Guardrail (must be empty): `git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|ios/'`.
- **No new `VaultBrowseError` variant.** Reuse `BlockNotFound` / `InvalidArgument` / `RecordNotFound` / `SaveCryptoFailure` / `CorruptVault` / `Failed` (all in `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt`).
- **UUIDs minted inside the impl** (real adapter uses `java.security.SecureRandom`); the pure model never mints crypto bytes.
- **Input validation lives in the model/wrapper, not the bridge** — blank-name reject and same-block-move guard are client-side (`VaultBrowseError.InvalidArgument`), mirroring `move_record`'s wrapper rule.
- **Pure functions in reusable modules**; one concept per file; keep files well under 500 lines.
- **TDD**: failing test → run-red → minimal impl → run-green → commit. Each task is one commit (or two if a UI button + its dialog test split cleanly).
- **Host test command** (no emulator), from the worktree:
  `cd /Users/hherb/src/secretary/.worktrees/android-block-crud-ui/android && ./gradlew :vault-access:test :browse-ui:test`
  Single class: append `--tests "org.secretary.browse.VaultBrowseModelBlockCrudTest"`.
- **Instrumented test command** (emulator; `adb`/`emulator` are NOT on bare PATH on this machine — use absolute paths or a booted AVD):
  `cd .../android && ./gradlew :app:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.BlockCrudRoundTripUiTest`
- **Commit trailer** on every commit: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt` | Modify | Add 3 ops to `VaultSession` |
| `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt` | Modify | Real adapter impl of the 3 ops |
| `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt` | Modify | Host fake: in-memory create/rename/move |
| `android/browse-ui/src/test/kotlin/org/secretary/browse/FakeVaultSession.kt` | Modify | Host fake (browse-ui) |
| `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt` | Modify | Instrumented fake (browse-ui) |
| `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt` | Modify | Dialog state + create/rename/move actions + `guardedWrite` |
| `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt` | Create | Host tests for the new model logic |
| `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt` | Modify | Host tests for the new fake behavior |
| `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt` | Modify | Re-expose new flows + launch new actions |
| `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/VaultBrowseViewModelTest.kt` | Modify | Host tests for VM delegation |
| `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt` | Modify | New-block / Rename / Move buttons; render dialogs |
| `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BlockCrudDialogs.kt` | Create | `BlockNameDialog` + `MovePickerDialog` composables |
| `android/app/src/androidTest/kotlin/org/secretary/app/BlockCrudRoundTripUiTest.kt` | Create | Instrumented end-to-end acceptance over real FFI |
| `README.md`, `ROADMAP.md` | Modify | Add the Android block-CRUD UI row |

---

## Task 1: Extend the `VaultSession` port + all implementations (compile-green foundation)

Adds the three ops to the port and implements them in the real adapter and all fakes, so the whole tree compiles. The fake behavior is host-tested here; the real adapter is exercised by the Task 7 instrumented test.

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt`
- Modify: `android/browse-ui/src/test/kotlin/org/secretary/browse/FakeVaultSession.kt`
- Modify: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt`

**Interfaces:**
- Produces (on `VaultSession`):
  - `suspend fun createBlock(blockName: String): ByteArray`
  - `suspend fun renameBlock(blockUuid: ByteArray, newName: String)`
  - `suspend fun moveRecord(sourceBlockUuid: ByteArray, targetBlockUuid: ByteArray, sourceRecordUuid: ByteArray): ByteArray`
- Produces (on `:vault-access` `FakeVaultSession`, for later model tests): mutable `blocks` reflecting create/rename; `records` reflecting move (copy to target under a fresh uuid + tombstone in source); recorded call logs `created: MutableList<String>`, `renamed: MutableList<Pair<String,String>>` (blockHex→newName), `moved: MutableList<Triple<String,String,String>>` (srcHex, tgtHex, recHex).

- [ ] **Step 1: Write the failing fake-behavior test**

Add to `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt`:

```kotlin
@Test
fun `fake createBlock adds a block and returns its uuid`() = kotlinx.coroutines.test.runTest {
    val fake = FakeVaultSession("abcd", emptyList())
    val uuid = fake.createBlock("Work")
    assertEquals(16, uuid.size)
    assertEquals(listOf("Work"), fake.blockSummaries().map { it.name })
    assertEquals(listOf("Work"), fake.created)
}

@Test
fun `fake renameBlock changes the name and preserves records`() = kotlinx.coroutines.test.runTest {
    val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Old", 1u, 2u)
    val rec = RecordSummaryView("aa", "login", emptyList(), 1u, 2u, false, listOf(textField("u", "v")))
    val fake = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec)))
    fake.renameBlock(block.uuid, "New")
    assertEquals(listOf("New"), fake.blockSummaries().map { it.name })
    assertEquals(listOf(rec), fake.readBlock(block.uuid, includeDeleted = false))
}

@Test
fun `fake moveRecord copies to target under a fresh uuid and tombstones the source`() = kotlinx.coroutines.test.runTest {
    val src = BlockSummaryView(ByteArray(16) { 0x11 }, "Src", 1u, 2u)
    val tgt = BlockSummaryView(ByteArray(16) { 0x22 }, "Tgt", 1u, 2u)
    val rec = RecordSummaryView("aa", "login", listOf("t"), 1u, 2u, false, listOf(textField("u", "secret")))
    val fake = FakeVaultSession("abcd", listOf(src, tgt), mapOf(src.uuidHex to listOf(rec)))
    val newUuid = fake.moveRecord(src.uuid, tgt.uuid, ByteArray(16).also { /* recHex "aa..0" */ })
        .also { assertEquals(16, it.size) }
    // target holds a live copy whose field value reads back
    val tgtRecs = fake.readBlock(tgt.uuid, includeDeleted = false)
    assertEquals(1, tgtRecs.size)
    assertEquals("secret", (tgtRecs[0].fields[0].reveal() as RevealedValue.Text).value)
    // source: live view empty, show-deleted view shows the tombstone
    assertTrue(fake.readBlock(src.uuid, includeDeleted = false).isEmpty())
    assertEquals(1, fake.readBlock(src.uuid, includeDeleted = true).size)
    assertTrue(fake.readBlock(src.uuid, includeDeleted = true)[0].tombstone)
}
```

> Note: the move test passes the source record's raw uuid. Because `RecordSummaryView` stores `uuidHex` (not raw bytes), have the fake match the source record by `hexOfBytes(sourceRecordUuid)`. In the test, build the record with a known hex and pass the matching bytes — simplest is to set the record's `uuidHex` to all-zero-with-last-byte and pass `ByteArray(16)`. Adjust the literal so `hexOfBytes(passedBytes) == rec.uuidHex`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-block-crud-ui/android && ./gradlew :vault-access:test --tests "org.secretary.browse.FakeVaultBrowseTest"`
Expected: FAIL — `createBlock`/`renameBlock`/`moveRecord` unresolved (port has no such members).

- [ ] **Step 3: Add the three methods to the `VaultSession` port**

In `VaultOpenPort.kt`, inside `interface VaultSession`, after `editRecord(...)` and before `fun wipe()`:

```kotlin
    /**
     * Create a new (empty) block named [blockName]; mints (SecureRandom in the real adapter) and
     * returns its fresh 16-byte UUID. Device-uuid + now-ms are resolved inside the impl.
     */
    suspend fun createBlock(blockName: String): ByteArray

    /**
     * Rename the block identified by [blockUuid] to [newName]. `BlockNotFound` if no such block.
     * Device-uuid + now-ms are resolved inside the impl.
     */
    suspend fun renameBlock(blockUuid: ByteArray, newName: String)

    /**
     * Move the live record [sourceRecordUuid] from [sourceBlockUuid] into [targetBlockUuid], minting
     * (SecureRandom) and returning the fresh target record UUID. Copy-to-target then tombstone-in-
     * source. Caller guarantees source != target. Device-uuid + now-ms resolved inside the impl.
     */
    suspend fun moveRecord(
        sourceBlockUuid: ByteArray,
        targetBlockUuid: ByteArray,
        sourceRecordUuid: ByteArray,
    ): ByteArray
```

- [ ] **Step 4: Implement in the real adapter `UniffiVaultSession`**

In `UniffiVaultOpenPort.kt`, add imports near the other `as ffi*` aliases:

```kotlin
import uniffi.secretary.createBlock as ffiCreateBlock
import uniffi.secretary.renameBlock as ffiRenameBlock
import uniffi.secretary.moveRecord as ffiMoveRecord
```

In `class UniffiVaultSession`, after `editRecord(...)`:

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
        sourceBlockUuid: ByteArray,
        targetBlockUuid: ByteArray,
        sourceRecordUuid: ByteArray,
    ): ByteArray =
        write { dev, now ->
            val newRecordUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
            ffiMoveRecord(
                identity, manifest, sourceBlockUuid, targetBlockUuid,
                sourceRecordUuid, newRecordUuid, dev, now,
            )
            newRecordUuid
        }
```

- [ ] **Step 5: Implement in the `:vault-access` host fake (`FakeVaultBrowse.kt`)**

Change `private val blocks: List<BlockSummaryView>` to a mutable backing list and add call logs + the three methods. Replace the `blocks` field and `blockSummaries()`:

```kotlin
    private val mutableBlocks: MutableList<BlockSummaryView> = blocks.toMutableList()
    val created: MutableList<String> = mutableListOf()
    val renamed: MutableList<Pair<String, String>> = mutableListOf()      // blockHex -> newName
    val moved: MutableList<Triple<String, String, String>> = mutableListOf() // srcHex, tgtHex, recHex
    private var nextFakeBlockByte: Int = 0xB0

    override fun blockSummaries(): List<BlockSummaryView> {
        blocksError?.let { throw it }
        return mutableBlocks.toList()
    }
```

(Keep the constructor param named `blocks`; the `mutableBlocks` copy is the live store.) Add, after `editRecord`:

```kotlin
    override suspend fun createBlock(blockName: String): ByteArray {
        writeGate?.await()
        writeError?.let { throw it }
        val uuid = ByteArray(16).also { it[15] = (nextFakeBlockByte and 0xff).toByte() }
        nextFakeBlockByte += 1
        created += blockName
        mutableBlocks += BlockSummaryView(uuid, blockName, 0u, 0u)
        records.getOrPut(hexOfBytes(uuid)) { mutableListOf() }
        return uuid
    }

    override suspend fun renameBlock(blockUuid: ByteArray, newName: String) {
        writeGate?.await()
        writeError?.let { throw it }
        val hex = hexOfBytes(blockUuid)
        val i = mutableBlocks.indexOfFirst { it.uuidHex == hex }
        if (i < 0) throw VaultBrowseError.BlockNotFound(hex)
        renamed += hex to newName
        val b = mutableBlocks[i]
        mutableBlocks[i] = BlockSummaryView(b.uuid, newName, b.createdAtMs, b.lastModifiedMs)
    }

    override suspend fun moveRecord(
        sourceBlockUuid: ByteArray,
        targetBlockUuid: ByteArray,
        sourceRecordUuid: ByteArray,
    ): ByteArray {
        writeGate?.await()
        writeError?.let { throw it }
        val srcHex = hexOfBytes(sourceBlockUuid)
        val tgtHex = hexOfBytes(targetBlockUuid)
        val recHex = hexOfBytes(sourceRecordUuid)
        moved += Triple(srcHex, tgtHex, recHex)
        val srcList = records[srcHex] ?: throw VaultBrowseError.BlockNotFound(srcHex)
        val si = srcList.indexOfFirst { it.uuidHex == recHex && !it.tombstone }
        if (si < 0) throw VaultBrowseError.RecordNotFound(recHex)
        val moving = srcList[si]
        val newUuid = ByteArray(16).also { it[15] = (nextFakeUuidByte and 0xff).toByte() }
        nextFakeUuidByte += 1
        records.getOrPut(tgtHex) { mutableListOf() } += moving.copy(uuidHex = hexOfBytes(newUuid))
        srcList[si] = moving.copy(tombstone = true)
        return newUuid
    }
```

- [ ] **Step 6: Mirror the three methods in both `:browse-ui` fakes**

In `android/browse-ui/src/test/kotlin/org/secretary/browse/FakeVaultSession.kt` and `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt`, make `blocks` a mutable copy the same way and add the same three methods (you may drop the `writeGate`/call-log fields the browse-ui fakes don't have — keep it minimal: just mutate `blocks`/`records` and return a fresh uuid). The `:browse-ui` androidTest fake is what the Task 6 Compose test drives, so its create/rename/move must update the in-memory state so the UI reflects them.

- [ ] **Step 7: Run the fake tests to verify they pass**

Run: `cd .../android && ./gradlew :vault-access:test --tests "org.secretary.browse.FakeVaultBrowseTest"`
Expected: PASS. Then confirm the whole tree still compiles: `./gradlew :app:compileDebugKotlin :browse-ui:test` → PASS.

- [ ] **Step 8: Commit**

```bash
git add android/vault-access/src/main android/kit/src/main android/vault-access/src/test android/browse-ui/src/test android/browse-ui/src/androidTest
git commit -m "feat(android): add create/rename/move to VaultSession port + adapter + fakes

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Model — block-name dialog state + create + `guardedWrite` refactor

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt` (create)

**Interfaces:**
- Consumes: `VaultSession.createBlock` (Task 1).
- Produces:
  - `sealed interface BlockNameDialogState { data object CreateBlock; data class RenameBlock(val blockUuid: ByteArray, val currentName: String) }`
  - `val blockNameDialog: StateFlow<BlockNameDialogState?>`
  - `fun startCreateBlock()`, `fun cancelBlockNameDialog()`, `suspend fun confirmBlockName(name: String)`
  - `private suspend fun guardedWrite(reload: suspend () -> Unit, op: suspend () -> Unit)`

- [ ] **Step 1: Write the failing tests**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultBrowseModelBlockCrudTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private fun fake(
        writeError: VaultBrowseError? = null,
        writeGate: CompletableDeferred<Unit>? = null,
    ) = FakeVaultSession("abcd", listOf(block), writeError = writeError, writeGate = writeGate)

    @Test
    fun `startCreateBlock opens the create dialog`() = runTest {
        val model = VaultBrowseModel(fake())
        model.startCreateBlock()
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.CreateBlock)
    }

    @Test
    fun `confirmBlockName create adds the block and closes the dialog`() = runTest {
        val f = fake()
        val model = VaultBrowseModel(f)
        model.loadBlocks()
        model.startCreateBlock()
        model.confirmBlockName("Work")
        assertEquals(listOf("Work"), f.created)
        assertTrue(model.blocks.value.any { it.name == "Work" })
        assertNull(model.blockNameDialog.value)
        assertNull(model.error.value)
    }

    @Test
    fun `confirmBlockName rejects a blank name without writing and keeps the dialog open`() = runTest {
        val f = fake()
        val model = VaultBrowseModel(f)
        model.startCreateBlock()
        model.confirmBlockName("   ")
        assertTrue(model.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(f.created.isEmpty())
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.CreateBlock)
    }

    @Test
    fun `a second confirm while a write is in flight is a no-op`() = runTest {
        val gate = CompletableDeferred<Unit>()
        val f = fake(writeGate = gate)
        val model = VaultBrowseModel(f)
        model.startCreateBlock()
        val first = launch { model.confirmBlockName("A") }
        runCurrent()
        model.confirmBlockName("B")   // re-entrant; blocked by `writing`
        gate.complete(Unit)
        advanceUntilIdle()
        first.join()
        assertEquals(listOf("A"), f.created)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd .../android && ./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelBlockCrudTest"`
Expected: FAIL — `startCreateBlock`/`blockNameDialog`/`confirmBlockName` unresolved.

- [ ] **Step 3: Add the dialog state type, flow, the `guardedWrite` helper, and the create actions**

In `VaultBrowseModel.kt`, add at the top of the class body (after the existing flows):

```kotlin
    private val _blockNameDialog = MutableStateFlow<BlockNameDialogState?>(null)
    /** Non-null when the create/rename-block name dialog is open. Cleared on confirm-success / cancel / lock. */
    val blockNameDialog: StateFlow<BlockNameDialogState?> = _blockNameDialog.asStateFlow()
```

Add the sealed type at the bottom of the file (top-level, after the class), or just above the class:

```kotlin
/** Presentation state of the single block-name dialog (create OR rename). */
sealed interface BlockNameDialogState {
    /** The dialog is collecting a name for a brand-new block. */
    data object CreateBlock : BlockNameDialogState

    /** The dialog is renaming the block [blockUuid], pre-filled with [currentName]. */
    data class RenameBlock(val blockUuid: ByteArray, val currentName: String) : BlockNameDialogState {
        override fun equals(other: Any?): Boolean =
            other is RenameBlock && blockUuid.contentEquals(other.blockUuid) && currentName == other.currentName
        override fun hashCode(): Int = 31 * blockUuid.contentHashCode() + currentName.hashCode()
    }
}
```

Add the `guardedWrite` helper and refactor `commitThenReload` to use it:

```kotlin
    /**
     * Re-entrancy + error-preservation core shared by record writes (delete/restore/edit) and
     * block-list writes (create/rename/move). Runs [op]; on success runs [reload]; a typed failure
     * surfaces via [error] and skips [reload] (the visible list stays intact). No-op if a write is
     * already in flight.
     */
    private suspend fun guardedWrite(reload: suspend () -> Unit, op: suspend () -> Unit) {
        if (_writing.value) return
        _writing.value = true
        try {
            try {
                op()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }
            reload()
        } finally {
            _writing.value = false
        }
    }
```

Replace the body of `commitThenReload` with:

```kotlin
    private suspend fun commitThenReload(op: suspend (BlockSummaryView) -> Unit) {
        val block = _selectedBlock.value ?: return
        guardedWrite(reload = { selectBlock(block) }) { op(block) }
    }
```

Add the create actions:

```kotlin
    /** Open the create-block name dialog. */
    fun startCreateBlock() { _blockNameDialog.value = BlockNameDialogState.CreateBlock }

    /** Dismiss the block-name dialog without writing. */
    fun cancelBlockNameDialog() { _blockNameDialog.value = null }

    /**
     * Confirm the open block-name dialog. Rejects a blank name (InvalidArgument, no write, dialog
     * stays open). On success: create or rename per the dialog state, close the dialog, refresh the
     * block summaries. No-op if no dialog is open.
     */
    suspend fun confirmBlockName(name: String) {
        val dialog = _blockNameDialog.value ?: return
        val trimmed = name.trim()
        if (trimmed.isEmpty()) {
            _error.value = VaultBrowseError.InvalidArgument("block name is empty")
            return
        }
        guardedWrite(reload = { loadBlocks() }) {
            when (dialog) {
                BlockNameDialogState.CreateBlock -> session.createBlock(trimmed)
                is BlockNameDialogState.RenameBlock -> session.renameBlock(dialog.blockUuid, trimmed)
            }
            _blockNameDialog.value = null
        }
    }
```

> Place `_blockNameDialog.value = null` INSIDE the `op` lambda (before the reload) so a failed write leaves the dialog open with the error.

- [ ] **Step 4: Run to verify the create tests pass**

Run: `cd .../android && ./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelBlockCrudTest"`
Expected: PASS (4 tests). Also run the full `:vault-access:test` to confirm the `commitThenReload` refactor regressed nothing.

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt
git commit -m "feat(android): model create-block dialog + guardedWrite refactor

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Model — rename

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt`

**Interfaces:**
- Consumes: `VaultSession.renameBlock` (Task 1); `confirmBlockName` (Task 2).
- Produces: `fun startRenameBlock(block: BlockSummaryView)`.

- [ ] **Step 1: Write the failing tests**

Append to `VaultBrowseModelBlockCrudTest`:

```kotlin
    @Test
    fun `startRenameBlock opens the dialog pre-filled with the current name`() = runTest {
        val model = VaultBrowseModel(fake())
        model.startRenameBlock(block)
        val state = model.blockNameDialog.value
        assertTrue(state is BlockNameDialogState.RenameBlock)
        assertEquals("Logins", (state as BlockNameDialogState.RenameBlock).currentName)
    }

    @Test
    fun `confirmBlockName rename changes the name and closes the dialog`() = runTest {
        val f = fake()
        val model = VaultBrowseModel(f)
        model.loadBlocks()
        model.startRenameBlock(block)
        model.confirmBlockName("Passwords")
        assertEquals(listOf(block.uuidHex to "Passwords"), f.renamed)
        assertTrue(model.blocks.value.any { it.name == "Passwords" })
        assertNull(model.blockNameDialog.value)
    }

    @Test
    fun `rename of an absent block surfaces BlockNotFound and keeps the dialog open`() = runTest {
        val absent = BlockSummaryView(ByteArray(16) { 0x77 }, "Ghost", 1u, 2u)
        val f = fake()
        val model = VaultBrowseModel(f)
        model.loadBlocks()
        model.startRenameBlock(absent)
        model.confirmBlockName("X")
        assertTrue(model.error.value is VaultBrowseError.BlockNotFound)
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.RenameBlock)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd .../android && ./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelBlockCrudTest"`
Expected: FAIL — `startRenameBlock` unresolved.

- [ ] **Step 3: Add `startRenameBlock`**

In `VaultBrowseModel.kt`, after `startCreateBlock()`:

```kotlin
    /** Open the rename-block dialog for [block], pre-filled with its current name. */
    fun startRenameBlock(block: BlockSummaryView) {
        _blockNameDialog.value = BlockNameDialogState.RenameBlock(block.uuid, block.name)
    }
```

(The rename write path already exists in `confirmBlockName` from Task 2; the `BlockNotFound`-keeps-dialog-open behavior falls out of `guardedWrite` skipping the `_blockNameDialog = null` line on a thrown error.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd .../android && ./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelBlockCrudTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt
git commit -m "feat(android): model rename-block action

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Model — move record + lock reset

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt`

**Interfaces:**
- Consumes: `VaultSession.moveRecord` (Task 1).
- Produces:
  - `val movingRecord: StateFlow<RecordSummaryView?>`
  - `fun startMoveRecord(record: RecordSummaryView)`, `fun cancelMove()`, `suspend fun confirmMove(target: BlockSummaryView)`

- [ ] **Step 1: Write the failing tests**

Append to `VaultBrowseModelBlockCrudTest`:

```kotlin
    private val src = BlockSummaryView(ByteArray(16) { 0x11 }, "Src", 1u, 2u)
    private val tgt = BlockSummaryView(ByteArray(16) { 0x22 }, "Tgt", 1u, 2u)
    private val movableRec =
        RecordSummaryView(hexOfBytes(ByteArray(16) { 0x33 }), "login", listOf("t"), 1u, 2u, false,
            listOf(textField("u", "secret")))
    private fun moveFake() =
        FakeVaultSession("abcd", listOf(src, tgt), mapOf(src.uuidHex to listOf(movableRec)))

    @Test
    fun `startMoveRecord opens the picker`() = runTest {
        val model = VaultBrowseModel(moveFake())
        model.startMoveRecord(movableRec)
        assertEquals(movableRec, model.movingRecord.value)
    }

    @Test
    fun `confirmMove moves the record to the target and re-reads the source`() = runTest {
        val f = moveFake()
        val model = VaultBrowseModel(f)
        model.loadBlocks(); model.selectBlock(src)
        model.startMoveRecord(movableRec)
        model.confirmMove(tgt)
        assertEquals(1, f.moved.size)
        assertEquals(src.uuidHex, f.moved[0].first)
        assertEquals(tgt.uuidHex, f.moved[0].second)
        assertNull(model.movingRecord.value)
        // source re-read: live view no longer shows it
        assertTrue(model.selectedRecords.value!!.none { it.uuidHex == movableRec.uuidHex })
        // target holds the copy with the value
        assertEquals(1, f.readBlock(tgt.uuid, includeDeleted = false).size)
    }

    @Test
    fun `confirmMove to the same block is rejected without writing`() = runTest {
        val f = moveFake()
        val model = VaultBrowseModel(f)
        model.loadBlocks(); model.selectBlock(src)
        model.startMoveRecord(movableRec)
        model.confirmMove(src)   // same as selected source
        assertTrue(model.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(f.moved.isEmpty())
    }

    @Test
    fun `lock resets the dialogs`() = runTest {
        val model = VaultBrowseModel(moveFake())
        model.startMoveRecord(movableRec)
        model.startCreateBlock()
        model.lock()
        assertNull(model.movingRecord.value)
        assertNull(model.blockNameDialog.value)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd .../android && ./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelBlockCrudTest"`
Expected: FAIL — `movingRecord`/`startMoveRecord`/`confirmMove` unresolved.

- [ ] **Step 3: Add the move state + actions + lock reset**

In `VaultBrowseModel.kt`, add the flow (after `_blockNameDialog`):

```kotlin
    private val _movingRecord = MutableStateFlow<RecordSummaryView?>(null)
    /** Non-null when the move-record block-picker is open; the picker lists `blocks` minus the
     *  source (selected) block. Cleared on confirm-success / cancel / lock. */
    val movingRecord: StateFlow<RecordSummaryView?> = _movingRecord.asStateFlow()
```

Add the actions (after the rename action):

```kotlin
    /** Open the move-record block picker for [record]. No-op if no block is selected. */
    fun startMoveRecord(record: RecordSummaryView) {
        if (_selectedBlock.value == null) return
        _movingRecord.value = record
    }

    /** Dismiss the move picker without writing. */
    fun cancelMove() { _movingRecord.value = null }

    /**
     * Move the in-flight [movingRecord] from the selected (source) block into [target]. Defensive
     * same-block guard (the picker already excludes the source). On success: move, close the picker,
     * re-read the source so the moved record shows tombstoned/withheld. No-op if nothing is moving or
     * no block is selected.
     */
    suspend fun confirmMove(target: BlockSummaryView) {
        val record = _movingRecord.value ?: return
        val source = _selectedBlock.value ?: return
        if (target.uuid.contentEquals(source.uuid)) {
            _error.value = VaultBrowseError.InvalidArgument("cannot move a record into its own block")
            return
        }
        guardedWrite(reload = { selectBlock(source) }) {
            session.moveRecord(source.uuid, target.uuid, hexToBytes(record.uuidHex))
            _movingRecord.value = null
        }
    }
```

Update `lock()` to reset both dialogs — add inside the `lock()` body (with the other resets):

```kotlin
        _blockNameDialog.value = null
        _movingRecord.value = null
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd .../android && ./gradlew :vault-access:test --tests "org.secretary.browse.VaultBrowseModelBlockCrudTest"`
Expected: PASS. Run full `:vault-access:test` to confirm no regression.

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelBlockCrudTest.kt
git commit -m "feat(android): model move-record action + lock resets dialogs

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: androidx VM delegation

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt`
- Test: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/VaultBrowseViewModelTest.kt`

**Interfaces:**
- Consumes: model actions from Tasks 2–4.
- Produces (on `VaultBrowseViewModel`): `blockNameDialog`, `movingRecord` StateFlows; `startCreateBlock()`, `startRenameBlock(block)`, `cancelBlockNameDialog()`, `confirmBlockName(name)`, `startMoveRecord(record)`, `cancelMove()`, `confirmMove(target)`.

- [ ] **Step 1: Write the failing tests**

Append to `VaultBrowseViewModelTest` (mirror its existing style — it constructs a `VaultBrowseModel` over a fake and drives the VM; use the module's coroutine test rule / `runTest` exactly as the existing cases do):

```kotlin
    @Test
    fun `confirmBlockName create reaches the model`() = runTest {
        val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
        val fake = FakeVaultSession("abcd", listOf(block))
        val vm = VaultBrowseViewModel(VaultBrowseModel(fake))
        vm.startCreateBlock()
        vm.confirmBlockName("Work")
        advanceUntilIdle()
        assertEquals(listOf("Work"), fake.created)
    }

    @Test
    fun `confirmMove reaches the model`() = runTest {
        val src = BlockSummaryView(ByteArray(16) { 0x11 }, "Src", 1u, 2u)
        val tgt = BlockSummaryView(ByteArray(16) { 0x22 }, "Tgt", 1u, 2u)
        val rec = RecordSummaryView(hexOfBytes(ByteArray(16) { 0x33 }), "login", emptyList(), 1u, 2u, false,
            listOf(textField("u", "v")))
        val fake = FakeVaultSession("abcd", listOf(src, tgt), mapOf(src.uuidHex to listOf(rec)))
        val vm = VaultBrowseViewModel(VaultBrowseModel(fake))
        vm.selectBlock(src); advanceUntilIdle()
        vm.startMoveRecord(rec)
        vm.confirmMove(tgt); advanceUntilIdle()
        assertEquals(1, fake.moved.size)
    }
```

> The `:browse-ui` `FakeVaultSession` from Task 1 must expose `created`/`moved` for these assertions — add those call-log lists to the browse-ui fake in Task 1 Step 6 (keep parity with the `:vault-access` fake).

- [ ] **Step 2: Run to verify it fails**

Run: `cd .../android && ./gradlew :browse-ui:test --tests "org.secretary.browse.ui.VaultBrowseViewModelTest"`
Expected: FAIL — VM has no `startCreateBlock`/`confirmBlockName`/`confirmMove`.

- [ ] **Step 3: Add the delegations**

In `VaultBrowseViewModel.kt`, add (mirroring the existing thin style):

```kotlin
    val blockNameDialog: StateFlow<BlockNameDialogState?> = model.blockNameDialog
    val movingRecord: StateFlow<RecordSummaryView?> = model.movingRecord

    /** Open the create-block dialog. */
    fun startCreateBlock() = model.startCreateBlock()

    /** Open the rename-block dialog for [block]. */
    fun startRenameBlock(block: BlockSummaryView) = model.startRenameBlock(block)

    /** Dismiss the block-name dialog. */
    fun cancelBlockNameDialog() = model.cancelBlockNameDialog()

    /** Confirm the block-name dialog (suspend on the model → launched here). */
    fun confirmBlockName(name: String) {
        viewModelScope.launch { model.confirmBlockName(name) }
    }

    /** Open the move-record picker. */
    fun startMoveRecord(record: RecordSummaryView) = model.startMoveRecord(record)

    /** Dismiss the move picker. */
    fun cancelMove() = model.cancelMove()

    /** Confirm a move into [target] (suspend on the model → launched here). */
    fun confirmMove(target: BlockSummaryView) {
        viewModelScope.launch { model.confirmMove(target) }
    }
```

Add the `import org.secretary.browse.BlockNameDialogState` import.

- [ ] **Step 4: Run to verify it passes**

Run: `cd .../android && ./gradlew :browse-ui:test --tests "org.secretary.browse.ui.VaultBrowseViewModelTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt android/browse-ui/src/test/kotlin/org/secretary/browse/ui/VaultBrowseViewModelTest.kt
git commit -m "feat(android): VM delegation for block-CRUD actions

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Compose UI — buttons + dialogs

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`
- Create: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BlockCrudDialogs.kt`
- Test: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BlockCrudUiTest.kt` (instrumented, over the androidTest fake)

**Interfaces:**
- Consumes: VM members from Task 5; the androidTest `FakeVaultSession` (Task 1).
- Produces: testTags `new-block`, `rename-<uuidHex>`, `move-<uuidHex>`, `block-name-field`, `block-name-confirm`, `block-name-cancel`, `move-target-<uuidHex>`.

- [ ] **Step 1: Write the failing instrumented UI test**

Create `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BlockCrudUiTest.kt`. Model it on the existing `BrowseScreenSoftDeleteTest` (same `createComposeRule`, same `VaultBrowseViewModel(VaultBrowseModel(FakeVaultSession(...)))` wiring). Cover three interactions:

```kotlin
// 1. Tap "new-block" → dialog appears → type into "block-name-field" → "block-name-confirm"
//    → the new block name appears in the block list (fake mutated).
// 2. From a selected block, tap "move-<recordHex>" → picker shows "move-target-<otherBlockHex>"
//    → tap it → record leaves the source list.
// 3. Tap "rename-<blockHex>" → dialog pre-filled → change → confirm → new name in the list.
```

Use `composeRule.onNodeWithTag("new-block").performClick()`, `onNodeWithTag("block-name-field").performTextInput("Work")`, `onNodeWithTag("block-name-confirm").performClick()`, then `onNodeWithText("Work").assertIsDisplayed()`. Drive `viewModel.loadBlocks()` in `setContent` via the existing `LaunchedEffect`.

- [ ] **Step 2: Run to verify it fails**

Run (emulator booted): `cd .../android && ./gradlew :browse-ui:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockCrudUiTest`
Expected: FAIL — no `new-block` node.

- [ ] **Step 3: Create `BlockCrudDialogs.kt`**

```kotlin
package org.secretary.browse.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.secretary.browse.BlockNameDialogState
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView

/** Create/rename a block: one text field + confirm/cancel. Seeded from the current name on rename. */
@Composable
fun BlockNameDialog(
    state: BlockNameDialogState,
    onConfirm: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val initial = (state as? BlockNameDialogState.RenameBlock)?.currentName ?: ""
    var name by remember(state) { mutableStateOf(initial) }
    val title = if (state is BlockNameDialogState.RenameBlock) "Rename block" else "New block"
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("block-name-field"),
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(name) }, modifier = Modifier.testTag("block-name-confirm")) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel, modifier = Modifier.testTag("block-name-cancel")) { Text("Cancel") }
        },
    )
}

/** Move-record picker: lists every block except [sourceBlockUuidHex]; tap one to move. */
@Composable
fun MovePickerDialog(
    record: RecordSummaryView,
    blocks: List<BlockSummaryView>,
    sourceBlockUuidHex: String,
    onPick: (BlockSummaryView) -> Unit,
    onCancel: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Move to block") },
        text = {
            Column {
                blocks.filter { it.uuidHex != sourceBlockUuidHex }.forEach { b ->
                    Text(
                        text = b.name,
                        modifier = Modifier.fillMaxWidth()
                            .clickable { onPick(b) }
                            .padding(vertical = 12.dp)
                            .testTag("move-target-${b.uuidHex}"),
                    )
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onCancel, modifier = Modifier.testTag("move-cancel")) { Text("Cancel") }
        },
    )
}
```

- [ ] **Step 4: Wire buttons + dialogs into `BrowseScreen`**

In `BrowseScreen.kt`:

1. Collect the new flows after the existing `collectAsStateWithLifecycle` block:

```kotlin
    val blockNameDialog by viewModel.blockNameDialog.collectAsStateWithLifecycle()
    val movingRecord by viewModel.movingRecord.collectAsStateWithLifecycle()
```

2. In the block-list branch (`if (block == null)`), add a header row with a "New block" button above the `LazyColumn`:

```kotlin
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Blocks", style = MaterialTheme.typography.titleMedium)
                TextButton(
                    onClick = { viewModel.startCreateBlock() },
                    enabled = !writing,
                    modifier = Modifier.testTag("new-block"),
                ) { Text("New block") }
            }
```

(Remove the standalone `Text("Blocks", …)` it replaces.) Give `BlockRow` an `onRename` callback and a trailing Rename button:

```kotlin
@Composable
private fun BlockRow(block: BlockSummaryView, writing: Boolean, onClick: () -> Unit, onRename: () -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(
            text = blockLabel(block),
            modifier = Modifier.weight(1f).clickable(onClick = onClick).padding(vertical = 12.dp),
            style = MaterialTheme.typography.bodyLarge,
        )
        TextButton(onClick = onRename, enabled = !writing, modifier = Modifier.testTag("rename-${block.uuidHex}")) {
            Text("Rename")
        }
    }
}
```

Update the call site: `BlockRow(b, writing = writing, onClick = { viewModel.selectBlock(b) }, onRename = { viewModel.startRenameBlock(b) })`.

3. In `RecordRow`, add a "Move" button in the non-tombstoned action row (next to Edit/Delete) — add an `onMove: (RecordSummaryView) -> Unit` param and:

```kotlin
                    TextButton(
                        onClick = { onMove(record) },
                        enabled = !writing,
                        modifier = Modifier.testTag("move-${record.uuidHex}"),
                    ) { Text("Move") }
```

Thread `onMove = viewModel::startMoveRecord` from the `RecordRow(...)` call site.

4. Render the dialogs near the end of the outer `Column` (after the block/record branches, before the closing brace):

```kotlin
        blockNameDialog?.let { state ->
            BlockNameDialog(
                state = state,
                onConfirm = { viewModel.confirmBlockName(it) },
                onCancel = { viewModel.cancelBlockNameDialog() },
            )
        }
        movingRecord?.let { rec ->
            MovePickerDialog(
                record = rec,
                blocks = blocks,
                sourceBlockUuidHex = selectedBlock?.uuidHex ?: "",
                onPick = { viewModel.confirmMove(it) },
                onCancel = { viewModel.cancelMove() },
            )
        }
```

> The dialogs must render even when the record-list branch `return@Column`s early. Either remove that early-return pattern for the dialog block, or place the dialog rendering BEFORE the `if (editModel != null) … return@Column` and block/record branches so it always evaluates. Simplest: render the two `?.let` dialog blocks at the very top of the `Column` (after collecting state), so they overlay whatever branch is active.

- [ ] **Step 5: Run to verify the UI test passes**

Run (emulator): `cd .../android && ./gradlew :browse-ui:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.BlockCrudUiTest`
Expected: PASS. Also run the existing browse-ui instrumented tests to confirm no regression: `:browse-ui:connectedAndroidTest`.

- [ ] **Step 6: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/ android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BlockCrudUiTest.kt
git commit -m "feat(android): block-CRUD UI buttons + dialogs in BrowseScreen

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Instrumented end-to-end acceptance over the real FFI (`:app`)

The acceptance gate: drive the real composables over a real `UniffiVaultSession` on a staged golden vault — create a block, move a record into it through the UI, read it back, and confirm the source shows the tombstone. Models on `android/app/src/androidTest/kotlin/org/secretary/app/BrowseWithSyncScreenUiTest.kt` (which already stages the golden vault + wires `uniffiVaultOpenPort(deviceUuids)` + a `FileDeviceUuidStore`).

**Files:**
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/BlockCrudRoundTripUiTest.kt`

**Interfaces:**
- Consumes: everything above; `AppVaultProvisioning.stageGoldenVault(context)`, `uniffiVaultOpenPort(deviceUuids)`, `FileDeviceUuidStore`, the `BrowseScreen` testTags.

- [ ] **Step 1: Write the end-to-end test**

Create `BlockCrudRoundTripUiTest.kt`, copying the `@get:Rule createAndroidComposeRule`, `stageGoldenVault`, device-uuid-store, and `uniffiVaultOpenPort(deviceUuids)` setup from `BrowseWithSyncScreenUiTest`. Then:

```kotlin
// 1. Wait for the block list. Tap "new-block"; type a unique name (e.g. "Moved-${System.nanoTime()}");
//    tap "block-name-confirm". Assert the new name is displayed.
// 2. Tap an existing source block to enter it. Pick its first record; capture its title.
//    Tap "move-<recordHex>"; in the picker tap "move-target-<newBlockHex>".
// 3. Tap "Back"; enter the new block. Assert the moved record's title is displayed there
//    (read-back), and reveal a field to confirm the value materializes.
// 4. Re-enter the source block, toggle "toggle-show-deleted" on, assert a tombstoned row appears.
```

Resolve the new block's `uuidHex` by reading `viewModel.blocks.value` after the create completes (hold the VM in the test, as `BrowseWithSyncScreenUiTest` does), or assert by displayed name + `move-target` text node. Use `composeRule.waitUntil(timeoutMillis = 10_000L) { … }` for async reads, matching the existing test.

- [ ] **Step 2: Run to verify it fails (then passes after wiring)**

Run (emulator): `cd .../android && ./gradlew :app:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.BlockCrudRoundTripUiTest`
Expected: initially may fail on a selector mismatch; iterate selectors until PASS. The deliverable is a GREEN run.

- [ ] **Step 3: Commit**

```bash
git add android/app/src/androidTest/kotlin/org/secretary/app/BlockCrudRoundTripUiTest.kt
git commit -m "test(android): on-device create->move->read-back round-trip through the UI

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Docs — README + ROADMAP rows

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Add the README row**

In the FFI/clients status section (where the block-CRUD binding rows live — search `block CRUD`), add a brief dot-point or table row: Android UI affordance for create/rename block + move record (dialogs over the browse screen), 2026-06-20. Keep it terse per the README style (no test-count walls).

- [ ] **Step 2: Add the ROADMAP row**

In `ROADMAP.md`, add an `[x]` entry under the relevant D-phase (platform UI) section: "Android block-CRUD UI affordance (create/rename block + move record) — 2026-06-20".

- [ ] **Step 3: Verify the guardrail is still empty**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-block-crud-ui && git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|ios/'`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: README + ROADMAP rows for Android block-CRUD UI

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (before PR)

- [ ] Host suite green: `cd .../android && ./gradlew :vault-access:test :browse-ui:test`
- [ ] Instrumented green (emulator booted): `./gradlew :browse-ui:connectedAndroidTest :app:connectedAndroidTest` (or the two scoped class runs above)
- [ ] Guardrail empty (Task 8 Step 3).
- [ ] No Rust touched: `git diff main...HEAD --name-only | grep -E '\.rs$|Cargo'` → empty.
- [ ] Update the session handoff (NEXT_SESSION symlink + new `docs/handoffs/<date>-android-block-crud-ui-shipped.md`) on the branch before opening the PR.

## Self-review notes (author)

- **Spec coverage:** §1 port → T1; §2 adapter → T1; §3 model (state, create, rename, move, guardedWrite, lock) → T2–T4; §4 VM → T5, Compose UI + dialogs → T6; §5 errors → no new variant (T2–T4 use existing); §6 host tests → T1–T5, instrumented UI → T6, real-FFI round-trip → T7; acceptance docs → T8. All covered.
- **Type consistency:** `BlockNameDialogState` (sealed: `CreateBlock`/`RenameBlock`), `blockNameDialog`/`movingRecord` flows, and method names (`startCreateBlock`/`startRenameBlock`/`cancelBlockNameDialog`/`confirmBlockName`/`startMoveRecord`/`cancelMove`/`confirmMove`) are used identically across model (T2–T4), VM (T5), and UI (T6).
- **Known follow-the-pattern items for the implementer:** the exact JUnit5 coroutine-test imports and `runTest`/`advanceUntilIdle` idioms must match each module's existing tests; the `:browse-ui` fakes need the `created`/`moved` call-logs added in T1 to satisfy T5 assertions; the golden-vault block/record names in T7 should be read from the live `blocks` flow rather than hard-coded.
