# C.3 Android slice 9: soft-delete lifecycle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the soft-delete lifecycle to the Android Compose browse surface — a Show-deleted toggle plus per-row Delete (tombstone) / Restore (resurrect) — and the device-UUID + write infrastructure all future Android writes reuse.

**Architecture:** The first Android slice that writes to a vault. New pure `DeviceUuidProvider` + `FileDeviceUuidStore` in `:vault-access`; the `VaultSession` interface and `VaultBrowseModel` gain writers + a `showDeleted` flag; `:kit`'s `UniffiVaultSession` projects the existing uniffi `tombstoneRecord`/`resurrectRecord` under the established `sessionLock`/`wiped` guard; `:browse-ui` adds the toggle + buttons; `:app` injects a `FileDeviceUuidStore` rooted at `noBackupFilesDir`. Mirrors the iOS `VaultBrowseViewModel` delete/restore/showDeleted surface, minus the edit view-model (deferred to slice 10).

**Tech Stack:** Kotlin, Coroutines/StateFlow, Jetpack Compose + Material3, JUnit5 (host) + AndroidX Compose UI test (instrumented), uniffi-generated `uniffi.secretary` bindings over the Rust `.so`.

## Global Constraints

- **No `core` / `ffi` / `ios` / on-disk-format change.** The uniffi write surface and the `read_block` `includeDeleted` gate already exist and are exercised by iOS. Both guardrail greps MUST stay empty:
  - `git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'`
  - `git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'`
- **Device UUID is non-secret** (a public per-device CRDT fingerprint), NOT key material; but it must be 16 bytes and stable per `(install, vault)`.
- **No magic numbers** — the 16-byte UUID length is a named constant (`DEVICE_UUID_BYTE_LEN`).
- **Crypto values generated at runtime, never hardcoded** — the device UUID uses `java.security.SecureRandom` (per the repo's hardcoded-crypto-value rule).
- **`arm64-v8a` only** — matches the existing `:kit`; irrelevant on the arm64 emulator/devices used here.
- **Working dir:** all commands run from the worktree `.worktrees/c3-android-soft-delete`. Gradle commands run from its `android/` subdir. Connected tests need a running emulator and `PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH"`.
- **Module test tasks:** `:vault-access:test` (JUnit5), `:kit:testDebugUnitTest`, `:browse-ui:test`, `:app:test` (host); `:browse-ui:connectedDebugAndroidTest`, `:app:connectedDebugAndroidTest` (connected).

---

### Task 1: `DeviceUuidProvider` + `FileDeviceUuidStore` (`:vault-access`, pure)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUuid.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/FileDeviceUuidStoreTest.kt`

**Interfaces:**
- Consumes: nothing (leaf).
- Produces:
  - `interface DeviceUuidProvider { fun deviceUuid(vaultHex: String): ByteArray }` — returns exactly 16 bytes.
  - `class DeviceUuidException(message: String) : Exception(message)`
  - `class FileDeviceUuidStore(private val directory: java.io.File) : DeviceUuidProvider`
  - `const val DEVICE_UUID_BYTE_LEN = 16`

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class FileDeviceUuidStoreTest {
    @Test
    fun `fresh call creates a 16-byte uuid and persists it`(@TempDir dir: File) {
        val store = FileDeviceUuidStore(File(dir, "devices"))
        val uuid = store.deviceUuid("abcd1234")
        assertEquals(DEVICE_UUID_BYTE_LEN, uuid.size)
        assertEquals(true, File(File(dir, "devices"), "abcd1234.dev").exists())
    }

    @Test
    fun `second call returns the same persisted uuid`(@TempDir dir: File) {
        val store = FileDeviceUuidStore(File(dir, "devices"))
        val first = store.deviceUuid("abcd1234")
        val second = store.deviceUuid("abcd1234")
        assertArrayEquals(first, second)
    }

    @Test
    fun `distinct vaults get distinct uuids`(@TempDir dir: File) {
        val store = FileDeviceUuidStore(File(dir, "devices"))
        val a = store.deviceUuid("aaaa")
        val b = store.deviceUuid("bbbb")
        // Astronomically unlikely to collide; a failure here means the vaultHex was ignored.
        assertEquals(false, a.contentEquals(b))
    }

    @Test
    fun `a corrupt-length file is rejected with a typed error`(@TempDir dir: File) {
        val devices = File(dir, "devices").apply { mkdirs() }
        File(devices, "abcd1234.dev").writeBytes(ByteArray(7))   // wrong length
        val store = FileDeviceUuidStore(devices)
        assertThrows(DeviceUuidException::class.java) { store.deviceUuid("abcd1234") }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.FileDeviceUuidStoreTest'`
Expected: FAIL — `FileDeviceUuidStore` / `DeviceUuidProvider` unresolved.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.browse

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.SecureRandom

/** 16 bytes — a UUID. Named so the length is never a magic literal at call sites. */
const val DEVICE_UUID_BYTE_LEN = 16

/** Thrown when a persisted device-uuid file is unreadable or the wrong length. */
class DeviceUuidException(message: String) : Exception(message)

/**
 * Resolves the 16-byte CRDT modifier UUID for a vault on this device. The edit FFI stamps it onto
 * every field a write touches. Non-secret (a public per-device fingerprint), so NOT key material.
 * Pure seam — mirrors iOS `DeviceUuidProviding`; the real impl is [FileDeviceUuidStore].
 */
interface DeviceUuidProvider {
    /** [vaultHex]: lowercase, dash-less vault-UUID hex. Returns exactly [DEVICE_UUID_BYTE_LEN] bytes. */
    fun deviceUuid(vaultHex: String): ByteArray
}

/**
 * File-backed [DeviceUuidProvider] mirroring iOS `DeviceUuidStore` / desktop
 * `settings/io.rs::load_or_create_device_uuid_in`: random 16 bytes per (install, vault) via
 * [SecureRandom], persisted as `<vaultHex>.dev`, read back on later calls so one device == one CRDT
 * fingerprint. A `CREATE_NEW` write that loses a same-launch race reads the winner back (converge).
 * The [directory] is supplied by `:app` from `Context.noBackupFilesDir` so a restored backup does not
 * clone the fingerprint.
 */
class FileDeviceUuidStore(private val directory: File) : DeviceUuidProvider {
    override fun deviceUuid(vaultHex: String): ByteArray {
        directory.mkdirs()
        val file = File(directory, "$vaultHex.dev")
        if (file.exists()) return readUuid(file)
        val uuid = ByteArray(DEVICE_UUID_BYTE_LEN).also { SecureRandom().nextBytes(it) }
        return try {
            Files.write(file.toPath(), uuid, StandardOpenOption.CREATE_NEW)
            uuid
        } catch (e: java.nio.file.FileAlreadyExistsException) {
            readUuid(file)   // lost a same-launch race; converge on the winner
        }
    }

    private fun readUuid(file: File): ByteArray {
        val bytes = file.readBytes()
        if (bytes.size != DEVICE_UUID_BYTE_LEN) {
            throw DeviceUuidException("device-uuid file ${file.name} is ${bytes.size} bytes, expected $DEVICE_UUID_BYTE_LEN")
        }
        return bytes
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.FileDeviceUuidStoreTest'`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/DeviceUuid.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FileDeviceUuidStoreTest.kt
git commit -m "feat(android): file-backed DeviceUuidProvider for vault writes"
```

---

### Task 2: `VaultBrowseModel` show-deleted toggle (`:vault-access`)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt` (record `includeDeleted`)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt`

**Interfaces:**
- Consumes: existing `VaultSession.readBlock(blockUuid, includeDeleted)`, `VaultBrowseModel.selectBlock`.
- Produces: `VaultBrowseModel.showDeleted: StateFlow<Boolean>`; `VaultBrowseModel.setShowDeleted(value: Boolean)` (suspend).

- [ ] **Step 1: Make the unit-test fake record the `includeDeleted` it was last called with**

Edit `FakeVaultBrowse.kt` — add a recorded field to `FakeVaultSession`:

```kotlin
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    private val recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
    private val blocksError: VaultBrowseError? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set
    /** The `includeDeleted` arg of the most recent readBlock call (null until first read). */
    var lastIncludeDeleted: Boolean? = null
        private set

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> {
        blocksError?.let { throw it }
        return blocks
    }
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        lastIncludeDeleted = includeDeleted
        readError?.let { throw it }
        return recordsByBlockHex[hexOfBytes(blockUuid)] ?: emptyList()
    }
    override fun wipe() { wiped = true }
}
```

(Leave `FakeVaultOpenPort` unchanged.)

- [ ] **Step 2: Write the failing test**

Add to `VaultBrowseModelTest.kt`:

```kotlin
    @Test
    fun `selectBlock reads with includeDeleted false by default`() = runTest {
        val s = session()
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(block)
        assertEquals(false, s.lastIncludeDeleted)
    }

    @Test
    fun `setShowDeleted true re-reads the selected block with includeDeleted true`() = runTest {
        val s = session()
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(block)
        model.setShowDeleted(true)
        assertEquals(true, model.showDeleted.value)
        assertEquals(true, s.lastIncludeDeleted)
    }

    @Test
    fun `setShowDeleted with no block selected just records the flag`() = runTest {
        val s = session()
        val model = VaultBrowseModel(s)
        model.loadBlocks()
        model.setShowDeleted(true)
        assertEquals(true, model.showDeleted.value)
        assertNull(s.lastIncludeDeleted)   // no read happened
    }
```

(`assertEquals` is already imported; `assertNull` already imported.)

- [ ] **Step 3: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: FAIL — `setShowDeleted` / `showDeleted` unresolved.

- [ ] **Step 4: Write minimal implementation**

In `VaultBrowseModel.kt`, add the flow + setter and route `selectBlock` through it:

```kotlin
    private val _showDeleted = MutableStateFlow(false)
    /** When false (default) the list shows only live records; the Rust read_block gate withholds
     *  tombstoned records. Toggling RE-READS the selected block with the new flag — the client never
     *  holds withheld data and never filters tombstones itself. Mirror of iOS VaultBrowseViewModel.showDeleted. */
    val showDeleted: StateFlow<Boolean> = _showDeleted.asStateFlow()

    /** Set the show-deleted flag; on a real change, re-read the selected block (if any). */
    suspend fun setShowDeleted(value: Boolean) {
        if (value == _showDeleted.value) return
        _showDeleted.value = value
        _selectedBlock.value?.let { selectBlock(it) }
    }
```

Change the `selectBlock` read line from `includeDeleted = false` to:

```kotlin
            val records = session.readBlock(block.uuid, includeDeleted = _showDeleted.value)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: PASS (existing + 3 new).

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt
git commit -m "feat(android): show-deleted toggle re-reads block with includeDeleted"
```

---

### Task 3: typed write-error surface (`:vault-access` + `:kit`)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt`
- Modify: `android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTest.kt`

**Interfaces:**
- Consumes: `uniffi.secretary.VaultException.RecordNotFound { uuidHex }`, `uniffi.secretary.VaultException.SaveCryptoFailure { detail }` (confirmed in `ffi/secretary-ffi-uniffi/src/errors/vault.rs`; `RecipientNotPresent` is a real unmapped arm with no fields).
- Produces: `VaultBrowseError.RecordNotFound(val uuidHex: String)`, `VaultBrowseError.SaveCryptoFailure(val detail: String)`.

This task lands the typed write errors FIRST, so the writers task (Task 4) can reference `RecordNotFound` directly.

- [ ] **Step 1: Update the mapper tests (failing)**

The existing `BrowseMappingTest.kt` has a test (`folds any other arm into Failed …`) that uses `RecordNotFound` as its example of an *unmapped* arm — that example is about to become mapped. Replace that test's body to use a still-unmapped arm, and add a new test asserting the two newly-mapped arms:

```kotlin
    @Test
    fun `maps the write-relevant arms to their domain counterparts`() {
        assertEquals(VaultBrowseError.RecordNotFound("deadbeef"),
            mapVaultBrowseError(VaultException.RecordNotFound("deadbeef")))
        assertEquals(VaultBrowseError.SaveCryptoFailure("io"),
            mapVaultBrowseError(VaultException.SaveCryptoFailure("io")))
    }

    @Test
    fun `folds a still-unmapped arm into Failed carrying the variant name`() {
        val mapped = mapVaultBrowseError(VaultException.RecipientNotPresent())
        assertTrue(mapped is VaultBrowseError.Failed)
        assertTrue((mapped as VaultBrowseError.Failed).detail.contains("RecipientNotPresent"))
    }
```

(`RecipientNotPresent` is a real fieldless `VaultError` arm — confirmed in `ffi/secretary-ffi-uniffi/src/errors/vault.rs` — and is not handled by the browse mapper, so it exercises the `else`-fold.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd android && ./gradlew :kit:testDebugUnitTest --tests 'org.secretary.browse.BrowseMappingTest'`
Expected: FAIL — `VaultBrowseError.RecordNotFound` / `SaveCryptoFailure` unresolved.

- [ ] **Step 3: Add the two error variants**

In `VaultBrowseError.kt`, before the `Failed` arm:

```kotlin
    /** A write targeted a record that does not exist in the requested state (e.g. a peer already
     *  deleted it). Surfaced by tombstone/resurrect/edit. */
    data class RecordNotFound(val uuidHex: String) : VaultBrowseError(uuidHex)

    /** The save tail (atomic manifest + block rewrite) failed during a write. */
    data class SaveCryptoFailure(val detail: String) : VaultBrowseError(detail)
```

- [ ] **Step 4: Map them in `BrowseMapping.kt`**

Add explicit arms above the `else` (and update the MAINTAINER WARNING comment if it cites a specific arm count):

```kotlin
    is VaultException.RecordNotFound -> VaultBrowseError.RecordNotFound(e.uuidHex)
    is VaultException.SaveCryptoFailure -> VaultBrowseError.SaveCryptoFailure(e.detail)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd android && ./gradlew :kit:testDebugUnitTest`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt \
        android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt \
        android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTest.kt
git commit -m "feat(android): typed RecordNotFound/SaveCryptoFailure write errors"
```

---

### Task 4: `VaultSession` writers + model delete/restore (`:vault-access`)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt` (add 2 writers to `VaultSession`)
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt` (delete/restore)
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt` (add `hexToBytes`)
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt` (implement writers)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt`

**Interfaces:**
- Consumes: `VaultBrowseModel.selectedBlock`, `RecordSummaryView.uuidHex`, `hexOfBytes` (existing, in `HexFormat.kt`); `VaultBrowseError.RecordNotFound` (Task 3).
- Produces:
  - On `VaultSession`: `suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray)`, `suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray)`.
  - On `VaultBrowseModel`: `suspend fun delete(record: RecordSummaryView)`, `suspend fun restore(record: RecordSummaryView)`.
  - In `HexFormat.kt`: `internal fun hexToBytes(hex: String): ByteArray`.
- NOTE: adding the two interface methods also requires the **`:browse-ui` androidTest** `FakeVaultSession` to implement them — that update is folded into **Task 7** (the connected-test task that compiles androidTest). The host gates for Tasks 4–6 do not compile androidTest, so they stay green.

- [ ] **Step 1: Add the two writers to the `VaultSession` interface**

In `VaultOpenPort.kt`, inside `interface VaultSession`, after `readBlock`:

```kotlin
    /** Soft-delete one live record (tombstone). Device-uuid + now-ms are resolved inside the impl. */
    suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray)

    /** Restore one tombstoned record (resurrect). Device-uuid + now-ms are resolved inside the impl. */
    suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray)
```

- [ ] **Step 2: Make the unit-test fake implement the writers (record calls + simulate)**

In `FakeVaultBrowse.kt`, extend `FakeVaultSession`. Add a mutable working copy keyed by block-hex so a tombstone/resurrect is observable on the next read, plus a scriptable write error:

```kotlin
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
    private val blocksError: VaultBrowseError? = null,
    private val writeError: VaultBrowseError? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set
    var lastIncludeDeleted: Boolean? = null
        private set
    /** (blockHex, recordUuidHex) of each tombstone/resurrect call, in order. */
    val tombstoned: MutableList<Pair<String, String>> = mutableListOf()
    val resurrected: MutableList<Pair<String, String>> = mutableListOf()

    private val records: MutableMap<String, MutableList<RecordSummaryView>> =
        recordsByBlockHex.mapValues { it.value.toMutableList() }.toMutableMap()

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> {
        blocksError?.let { throw it }
        return blocks
    }
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        lastIncludeDeleted = includeDeleted
        readError?.let { throw it }
        val all = records[hexOfBytes(blockUuid)] ?: return emptyList()
        return if (includeDeleted) all.toList() else all.filter { !it.tombstone }
    }
    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeError?.let { throw it }
        tombstoned += hexOfBytes(blockUuid) to hexOfBytes(recordUuid)
        flipTombstone(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = true)
    }
    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeError?.let { throw it }
        resurrected += hexOfBytes(blockUuid) to hexOfBytes(recordUuid)
        flipTombstone(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = false)
    }
    override fun wipe() { wiped = true }

    private fun flipTombstone(blockHex: String, recordHex: String, tombstone: Boolean) {
        val list = records[blockHex] ?: return
        val i = list.indexOfFirst { it.uuidHex == recordHex }
        if (i >= 0) list[i] = list[i].copy(tombstone = tombstone)
    }
}
```

(`RecordSummaryView` is a `data class`, so `.copy(tombstone = …)` is available. The existing `session()` / `revealModel()` constructors keep compiling — `recordsByBlockHex` is still a defaulted param and the new `writeError` is defaulted. NOTE: `recordsByBlockHex` is no longer a stored `val` — it is consumed into the `records` map — so if any existing test referenced the constructor by that property name it must use the new `records`-backed behavior; none do.)

- [ ] **Step 3: Write the failing test**

Add to `VaultBrowseModelTest.kt`. Use a block whose records include a live record:

```kotlin
    private fun writableSession(writeError: VaultBrowseError? = null): FakeVaultSession {
        val live = RecordSummaryView("ab", "login", emptyList(), 1u, 2u, false, listOf(textField("u", "x")))
        return FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(live)), writeError = writeError)
    }

    @Test
    fun `delete tombstones the record then re-reads so it leaves the live view`() = runTest {
        val s = writableSession()
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(block)
        val rec = model.selectedRecords.value!!.first()
        model.delete(rec)
        assertEquals(listOf(block.uuidHex to rec.uuidHex), s.tombstoned)
        assertTrue(model.selectedRecords.value!!.none { it.uuidHex == rec.uuidHex })  // gone from live view
    }

    @Test
    fun `restore resurrects the record then re-reads`() = runTest {
        val s = writableSession()
        val model = VaultBrowseModel(s)
        model.loadBlocks()
        model.setShowDeleted(true)
        model.selectBlock(block)
        val rec = model.selectedRecords.value!!.first()
        model.delete(rec)                       // tombstone it (still visible: showDeleted = true)
        model.restore(rec)
        assertEquals(listOf(block.uuidHex to rec.uuidHex), s.resurrected)
        assertTrue(model.selectedRecords.value!!.any { it.uuidHex == rec.uuidHex && !it.tombstone })
    }

    @Test
    fun `a failed delete surfaces a typed error and leaves the visible list intact`() = runTest {
        val s = writableSession(writeError = VaultBrowseError.RecordNotFound("ab"))
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(block)
        val before = model.selectedRecords.value
        model.delete(before!!.first())
        assertTrue(model.error.value is VaultBrowseError.RecordNotFound)
        assertEquals(before, model.selectedRecords.value)   // NOT blanked
    }
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: FAIL — `delete` / `restore` unresolved.

- [ ] **Step 5: Write minimal implementation**

First add `hexToBytes` to `HexFormat.kt` (confirmed absent — `HexFormat.kt` has only `hexOfBytes`):

```kotlin
/** Parse a 32-char lowercase hex string to its raw bytes. Inverse of [hexOfBytes]. */
internal fun hexToBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
```

Then in `VaultBrowseModel.kt`, add the two writers + a private commit-then-reload helper:

```kotlin
    /** Soft-delete [record], then re-read the selected block so the list reflects it. */
    suspend fun delete(record: RecordSummaryView) =
        commitThenReload { block -> session.tombstoneRecord(block.uuid, hexToBytes(record.uuidHex)) }

    /** Restore [record], then re-read. */
    suspend fun restore(record: RecordSummaryView) =
        commitThenReload { block -> session.resurrectRecord(block.uuid, hexToBytes(record.uuidHex)) }

    /**
     * Run a mutation against the selected block, then re-read on SUCCESS only. A failed mutation
     * surfaces [error] but deliberately leaves [selectedRecords] (and any reveal) intact — a rejected
     * delete must not blank the visible list. No-op if no block is selected. Mirror of iOS commitThenReload.
     */
    private suspend fun commitThenReload(op: suspend (BlockSummaryView) -> Unit) {
        val block = _selectedBlock.value ?: return
        try {
            op(block)
        } catch (e: VaultBrowseError) {
            _error.value = e
            return
        }
        selectBlock(block)
    }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test`
Expected: PASS (whole `:vault-access` host suite).

- [ ] **Step 7: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt
git commit -m "feat(android): VaultBrowseModel delete/restore via session write seam"
```

---

### Task 5: real write impl + device-uuid injection (`:kit`)

**Files:**
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`

**Interfaces:**
- Consumes: `DeviceUuidProvider`, `DeviceUuidException` (Task 1); `VaultSession.tombstoneRecord`/`resurrectRecord` (Task 4); `uniffi.secretary.tombstoneRecord` / `uniffi.secretary.resurrectRecord` (generated: `(identity: UnlockedIdentity, manifest: OpenVaultManifest, blockUuid: ByteArray, recordUuid: ByteArray, deviceUuid: ByteArray, nowMs: ULong)`, throws `VaultException`).
- Produces: `fun uniffiVaultOpenPort(deviceUuids: DeviceUuidProvider): VaultOpenPort` (new production factory); the existing no-arg `uniffiVaultOpenPort()` stays for read-only callers.

**Testing note:** `UniffiVaultSession` holds real FFI handles and cannot be host-instantiated, so its write behavior is proven on-device in **Task 8**, exactly as slice 8 proved its reveal logic on-device. This task's gate is: `:kit` compiles and the existing `:kit` host suite stays green (the pure mappers are unaffected).

- [ ] **Step 1: Add the provider to the port + session and implement the writers**

In `UniffiVaultOpenPort.kt`:

Add imports:
```kotlin
import uniffi.secretary.resurrectRecord as ffiResurrectRecord
import uniffi.secretary.tombstoneRecord as ffiTombstoneRecord
```

Give `UniffiVaultOpenPort` an optional provider and pass it down:
```kotlin
class UniffiVaultOpenPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val deviceUuids: DeviceUuidProvider? = null,
    private val openFn: (ByteArray, ByteArray) -> OpenVaultOutput = ::openVaultWithPassword,
) : VaultOpenPort {
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors { openFn(vaultFolder.toByteArray(Charsets.UTF_8), password) }
            UniffiVaultSession(output, ioDispatcher, deviceUuids)
        }
}
```

Give `UniffiVaultSession` the provider + cache + writers. Add the constructor param:
```kotlin
class UniffiVaultSession(
    output: OpenVaultOutput,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val deviceUuids: DeviceUuidProvider? = null,
) : VaultSession {
```

Add the cache field near `wiped`:
```kotlin
    /** Resolved once per session (first write) so every write stamps the same device UUID. */
    private var cachedDeviceUuid: ByteArray? = null
```

Implement the writers + a private `write` helper (mirrors iOS), placed after `readBlock`:
```kotlin
    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        write { dev, now -> ffiTombstoneRecord(identity, manifest, blockUuid, recordUuid, dev, now) }

    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        write { dev, now -> ffiResurrectRecord(identity, manifest, blockUuid, recordUuid, dev, now) }

    /**
     * Resolve (device-uuid, now-ms), run the FFI write under [sessionLock] + the [wiped] guard, and
     * map errors. A write that loses the race to a concurrent wipe() must not touch zeroized handles.
     */
    private suspend fun write(body: (deviceUuid: ByteArray, nowMs: ULong) -> Unit) =
        withContext(ioDispatcher) {
            mapErrors {
                synchronized(sessionLock) {
                    if (wiped) throw VaultBrowseError.Failed("write on a wiped session")
                    val dev = deviceUuid()
                    body(dev, System.currentTimeMillis().toULong())
                }
            }
        }

    /** Resolve + cache the per-vault device UUID; surface a store failure as a typed error. */
    private fun deviceUuid(): ByteArray {
        cachedDeviceUuid?.let { return it }
        val provider = deviceUuids
            ?: throw VaultBrowseError.Failed("read-only session: no device-uuid provider configured")
        val d = try {
            provider.deviceUuid(vaultUuidHex())
        } catch (e: DeviceUuidException) {
            throw VaultBrowseError.Failed("device-uuid resolve failed: ${e.message}")
        }
        cachedDeviceUuid = d
        return d
    }
```

Add the production factory overload near the existing `uniffiVaultOpenPort()`:
```kotlin
/** Production factory that supports writes (delete/restore/edit): inject a device-uuid provider. */
fun uniffiVaultOpenPort(deviceUuids: DeviceUuidProvider): VaultOpenPort =
    UniffiVaultOpenPort(deviceUuids = deviceUuids)
```

(`vaultUuidHex()` already exists on the session; `identity`, `manifest`, `sessionLock`, `wiped`, `mapErrors` are existing members. `DeviceUuidProvider` / `DeviceUuidException` need imports from `org.secretary.browse` — same package, so no import needed.)

- [ ] **Step 2: Verify the generated uniffi write signature matches the call**

Run: `cd android && ./gradlew :kit:compileDebugKotlin`
Expected: SUCCESS. If it fails on `nowMs`/`deviceUuid` types, inspect the generated `uniffi.secretary` signature (the build extracts it into `:kit`'s build dir) and adjust — `u64` → `ULong`, `Vec<u8>` → `ByteArray`. Fix the call to match; do not change the FFI.

- [ ] **Step 3: Run the kit + vault-access host suites (no regression)**

Run: `cd android && ./gradlew :kit:testDebugUnitTest :vault-access:test`
Expected: PASS (pure mappers + model unaffected).

- [ ] **Step 4: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt
git commit -m "feat(android): UniffiVaultSession tombstone/resurrect + device-uuid injection"
```

---

### Task 6: VM forwarding + BrowseScreen UI (`:browse-ui`)

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt`
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`

**Interfaces:**
- Consumes: `VaultBrowseModel.showDeleted`/`setShowDeleted` (Task 2), `delete`/`restore` (Task 4).
- Produces (on `VaultBrowseViewModel`): `val showDeleted: StateFlow<Boolean>`; `fun setShowDeleted(value: Boolean)`; `fun delete(record: RecordSummaryView)`; `fun restore(record: RecordSummaryView)`.

**Testing note:** `VaultBrowseViewModel` extends `androidx.lifecycle.ViewModel` and `BrowseScreen` is Compose — neither is host-unit-tested (mirroring slices 6–8, where the screen was proven by the instrumented test). This task's gate is `:browse-ui` assembling + the existing host suite staying green; behavior is asserted in **Task 7**.

- [ ] **Step 1: Forward the new model API on the VM**

In `VaultBrowseViewModel.kt`, add the import `import org.secretary.browse.RecordSummaryView` (if not present — it is, via reveal) and:
```kotlin
    val showDeleted: StateFlow<Boolean> = model.showDeleted

    /** Toggle show-deleted (suspend on the model → launched on viewModelScope). */
    fun setShowDeleted(value: Boolean) {
        viewModelScope.launch { model.setShowDeleted(value) }
    }

    /** Soft-delete a record (re-reads on success inside the model). */
    fun delete(record: RecordSummaryView) {
        viewModelScope.launch { model.delete(record) }
    }

    /** Restore a tombstoned record. */
    fun restore(record: RecordSummaryView) {
        viewModelScope.launch { model.restore(record) }
    }
```

- [ ] **Step 2: Add the toggle + per-row buttons to `BrowseScreen`**

In `BrowseScreen.kt`:

Add imports:
```kotlin
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Switch
```

Collect the flow in `BrowseScreen`:
```kotlin
    val showDeleted by viewModel.showDeleted.collectAsStateWithLifecycle()
```

In the selected-block branch, add a toggle row under the title `Row` (before the `LazyColumn`):
```kotlin
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Show deleted", style = MaterialTheme.typography.bodyMedium)
                Switch(
                    checked = showDeleted,
                    onCheckedChange = { viewModel.setShowDeleted(it) },
                    modifier = Modifier.testTag("toggle-show-deleted"),
                )
            }
```

Thread `onDelete` / `onRestore` into `RecordRow`:
```kotlin
                    RecordRow(
                        record = r,
                        revealed = revealed,
                        autoHideMillis = autoHideMillis,
                        onReveal = viewModel::reveal,
                        onHide = viewModel::hide,
                        onDelete = viewModel::delete,
                        onRestore = viewModel::restore,
                    )
```

Update `RecordRow` to render the action button beside the title — Delete for a live record, Restore for a tombstoned one:
```kotlin
@Composable
private fun RecordRow(
    record: RecordSummaryView,
    revealed: Map<String, RevealedValue>,
    autoHideMillis: Long,
    onReveal: (RecordSummaryView, RevealableField) -> Unit,
    onHide: (String, String) -> Unit,
    onDelete: (RecordSummaryView) -> Unit,
    onRestore: (RecordSummaryView) -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(recordTitle(record), style = MaterialTheme.typography.bodyLarge)
            if (record.tombstone) {
                TextButton(
                    onClick = { onRestore(record) },
                    modifier = Modifier.testTag("restore-${record.uuidHex}"),
                ) { Text("Restore") }
            } else {
                TextButton(
                    onClick = { onDelete(record) },
                    modifier = Modifier.testTag("delete-${record.uuidHex}"),
                ) { Text("Delete") }
            }
        }
        record.fields.forEach { field ->
            val key = "${record.uuidHex}/${field.name}"
            FieldRow(
                record = record,
                field = field,
                value = revealed[key],
                autoHideMillis = autoHideMillis,
                onReveal = onReveal,
                onHide = onHide,
            )
        }
    }
}
```

- [ ] **Step 3: Assemble `:browse-ui` + run its host suite**

Run: `cd android && ./gradlew :browse-ui:assembleDebug :browse-ui:test`
Expected: SUCCESS / PASS.

- [ ] **Step 4: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt
git commit -m "feat(android): BrowseScreen show-deleted toggle + delete/restore buttons"
```

---

### Task 7: instrumented `BrowseScreenSoftDeleteTest` (`:browse-ui`, connected)

**Files:**
- Modify: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt` (implement the new writers — required for androidTest to compile)
- Create: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenSoftDeleteTest.kt`

**Interfaces:**
- Consumes: `BrowseScreen`, `VaultBrowseViewModel`, `VaultBrowseModel`, the androidTest `FakeVaultSession`.

- [ ] **Step 1: Make the androidTest fake implement the writers + record/simulate**

Replace the androidTest `FakeVaultSession.kt` body so it implements the two new `VaultSession` methods and makes tombstone/resurrect observable on the next read (mirrors the unit-test fake):

```kotlin
package org.secretary.browse

/** Instrumented-source VaultSession double (androidTest can't see the unit-test fake). */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
) : VaultSession {
    var wiped: Boolean = false
        private set

    private val records: MutableMap<String, MutableList<RecordSummaryView>> =
        recordsByBlockHex.mapValues { it.value.toMutableList() }.toMutableMap()

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> = blocks
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        val all = records[hexOfBytes(blockUuid)] ?: return emptyList()
        return if (includeDeleted) all.toList() else all.filter { !it.tombstone }
    }
    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        flip(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = true)
    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        flip(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = false)
    override fun wipe() { wiped = true }

    private fun flip(blockHex: String, recordHex: String, tombstone: Boolean) {
        val list = records[blockHex] ?: return
        val i = list.indexOfFirst { it.uuidHex == recordHex }
        if (i >= 0) list[i] = list[i].copy(tombstone = tombstone)
    }
}

fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }
```

- [ ] **Step 2: Write the failing instrumented test**

```kotlin
package org.secretary.browse.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

class BrowseScreenSoftDeleteTest {
    @get:Rule val composeRule = createComposeRule()

    private val liveUuid = "33445566778899aabbccddeeff001122"
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val live = RecordSummaryView(
        liveUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("username", "u")),
    )

    private fun vm(): VaultBrowseViewModel {
        val session = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(live)))
        return VaultBrowseViewModel(VaultBrowseModel(session))
    }

    private fun openBlock(vm: VaultBrowseViewModel) {
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()
        composeRule.waitForIdle()
    }

    @Test
    fun delete_removesRecordFromLiveView() {
        val vm = vm()
        openBlock(vm)
        composeRule.onNodeWithTag("delete-$liveUuid").assertIsDisplayed().performClick()
        composeRule.waitForIdle()
        composeRule.onAllNodesWithTag("delete-$liveUuid").assertCountEquals(0)   // gone from live view
    }

    @Test
    fun showDeleted_revealsDeletedRecord_andRestoreBringsItBack() {
        val vm = vm()
        openBlock(vm)
        composeRule.onNodeWithTag("delete-$liveUuid").performClick()             // tombstone
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("toggle-show-deleted").performClick()          // show deleted
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("restore-$liveUuid").assertIsDisplayed().performClick()
        composeRule.waitForIdle()
        // After restore, with show-deleted still on, the row is live again → Delete button returns.
        composeRule.onNodeWithTag("delete-$liveUuid").assertIsDisplayed()
    }
}
```

- [ ] **Step 3: Run the instrumented test (emulator running)**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest
```
Expected: PASS — `BrowseScreenSoftDeleteTest` 2/2 + `BrowseScreenRevealTest` 2/2.

- [ ] **Step 4: Commit**

```bash
git add android/browse-ui/src/androidTest/kotlin/org/secretary/browse/FakeVaultSession.kt \
        android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/BrowseScreenSoftDeleteTest.kt
git commit -m "test(android): instrumented soft-delete toggle + delete/restore UI"
```

---

### Task 8: `:app` wiring + on-device round-trip smoke (`:app`, connected)

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`
- Modify: `android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt`

**Interfaces:**
- Consumes: `FileDeviceUuidStore` (Task 1), `uniffiVaultOpenPort(deviceUuids)` (Task 5), `VaultBrowseModel.setShowDeleted` (Task 2), `VaultBrowseModel.delete`/`restore` (Task 4).

- [ ] **Step 1: Inject a `FileDeviceUuidStore` rooted at `noBackupFilesDir` in AppRoot**

In `AppRoot.kt`, add imports:
```kotlin
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File
```
(replace the existing `import org.secretary.browse.uniffiVaultOpenPort` rather than duplicating it.)

In `unlockAndOpen`, change the open line to inject the provider:
```kotlin
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val session = uniffiVaultOpenPort(deviceUuids).openWithPassword(folder.path, password)
```

- [ ] **Step 2: Write the failing on-device round-trip smoke**

Add a test to `OpenBrowseSmokeTest.kt` (it already stages a fresh golden-vault copy per test and cleans up in `@After`). Add the needed imports (`assertFalse`) at the top:

```kotlin
    @Test
    fun softDelete_roundTrip_tombstoneThenResurrect() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = org.secretary.browse.FileDeviceUuidStore(
            File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val session = org.secretary.browse.uniffiVaultOpenPort(deviceUuids)
            .openWithPassword(folder.path, goldenPassword.toByteArray())
        val model = VaultBrowseModel(session)
        model.loadBlocks()
        model.selectBlock(model.blocks.value.first())

        val target = model.selectedRecords.value!!.first { it.type == "login" }

        // Tombstone → gone from the default (live-only) view.
        model.delete(target)
        assertTrue("tombstoned record left the live view",
            model.selectedRecords.value!!.none { it.uuidHex == target.uuidHex })

        // Show-deleted → present again, marked tombstoned.
        model.setShowDeleted(true)
        val deleted = model.selectedRecords.value!!.first { it.uuidHex == target.uuidHex }
        assertTrue("record is tombstoned under show-deleted", deleted.tombstone)

        // Resurrect → live again.
        model.restore(target)
        val restored = model.selectedRecords.value!!.first { it.uuidHex == target.uuidHex }
        assertFalse("resurrected record is live", restored.tombstone)

        model.lock()
    }
```

(Uses fully-qualified `org.secretary.browse.FileDeviceUuidStore` / `uniffiVaultOpenPort(deviceUuids)` to avoid touching the file's existing no-arg import used by the other tests. The device-uuid dir is per-run under `noBackupFilesDir` so it never collides across test runs.)

- [ ] **Step 3: Run the on-device smoke (emulator running)**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
```
Expected: PASS — `OpenBrowseSmokeTest` 4/4 (3 existing + the new round-trip) + `MakeVaultSyncSmokeTest` 2/2. The new test exercises the real `tombstoneRecord`/`resurrectRecord` save-tail against the staged golden-vault copy.

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt
git commit -m "feat(android): wire FileDeviceUuidStore + on-device soft-delete round-trip smoke"
```

---

## Final verification (after all tasks)

- [ ] **Full host gauntlet**

```bash
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test
```
Expected: BUILD SUCCESSFUL.

- [ ] **Connected gauntlet (emulator running)**

```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest
```
Expected: `BrowseScreenSoftDeleteTest` 2/2 + `BrowseScreenRevealTest` 2/2; `OpenBrowseSmokeTest` 4/4 + `MakeVaultSyncSmokeTest` 2/2.

- [ ] **Guardrails (both empty)**

```bash
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

- [ ] **Docs:** update `README.md` + `ROADMAP.md` (Android C.3 slice 9 ✅ soft-delete) and write the handoff per `/nextsession`.
