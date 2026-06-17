# C.3 Android slice 7 — vault open/browse port + metadata-only browse screen — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first Android open-a-vault path: unlock → `open_vault_with_password` → a Compose `BrowseScreen` that lists blocks and a selected block's record titles/types/tags (metadata only, no secret values), proven on-device against the staged `golden_vault_001`.

**Architecture:** Mirror the established Android layering and the iOS open/browse seam. Pure port + coordinator + view types in `:vault-access` (host-tested with fakes); the real uniffi adapter in `:kit`; a new FFI-free `:browse-ui` Compose module; route wiring in `:app` with an on-device smoke. **No `core/`/`ffi/`/`ios/` change** — the open/read uniffi surface already exists and `:kit` already generates its Kotlin bindings.

**Tech Stack:** Kotlin, Gradle, Jetbrains Compose, kotlinx-coroutines, JUnit5 (host) + JUnit4/AndroidJUnitRunner (instrumented), uniffi-generated `uniffi.secretary.*` bindings.

## Global Constraints

- **No edits under `core/`, `ffi/`, `ios/`, or the on-disk format.** Guardrail: `git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'` must be empty.
- **Metadata only:** never call `FieldHandle.exposeText()` / `exposeBytes()` anywhere in this slice. `RecordSummaryView` has no value field by construction.
- **Package convention:** `org.secretary.browse` (pure + adapter), `org.secretary.browse.ui` (UI) — mirrors `org.secretary.sync` / `org.secretary.sync.ui`.
- **coroutines pinned** `strictly("1.8.0")`; JUnit via `junit-bom:5.10.2`; Compose via `compose-bom:2025.05.00`; same Espresso/coroutines `force()` block as `:sync-ui`/`:app` on any module with instrumented tests.
- **JVM 21** toolchain; `compileSdk = 36`, `minSdk = 26`.
- **Secret hygiene:** the unlock password `ByteArray` is forwarded to the port and zeroized by the `:app` caller in a `finally`; ports/VMs never retain it. The `VaultSession` is wiped on background.
- **TDD, frequent commits, files < 500 lines, one concept per file.**
- **uniffi Kotlin names** (verified against `ffi/secretary-ffi-uniffi/tests/kotlin/`): top-level `openVaultWithPassword(folderPath: ByteArray, password: ByteArray): OpenVaultOutput`; `readBlock(identity, manifest, blockUuid: ByteArray, includeDeleted: Boolean): BlockReadOutput`. `OpenVaultOutput.identity: UnlockedIdentity`, `.manifest: OpenVaultManifest`. `OpenVaultManifest.blockSummaries(): List<BlockSummary>`, `.vaultUuid(): ByteArray`. `BlockSummary` (data class): `blockUuid: ByteArray`, `blockName: String`, `createdAtMs: ULong`, `lastModifiedMs: ULong`, `recipientUuids: List<ByteArray>`. `BlockReadOutput.recordCount(): ULong`, `.recordAt(idx: ULong): Record?`; AutoCloseable (`.use {}`). `Record.recordUuid(): ByteArray`, `.recordType(): String`, `.tags(): List<String>`, `.createdAtMs(): ULong`, `.lastModMs(): ULong`, `.tombstone(): Boolean`, `.fieldNames(): List<String>`. Errors: `uniffi.secretary.VaultException` (sealed) with arms incl. `WrongPasswordOrCorrupt()`, `VaultMismatch()`, `CorruptVault(detail)`, `FolderInvalid(detail)`, `BlockNotFound(uuidHex)`, `InvalidArgument(detail)`. The opaque handles expose idempotent `.wipe()` (zeroize-now) plus AutoCloseable `.close()`.

---

### Task 1: Browse view types, hex helper, and typed error (`:vault-access`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/HexFormat.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/BrowseModels.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/BrowseModelsTest.kt`

**Interfaces:**
- Produces: `fun hexOfBytes(bytes: ByteArray): String`; `class BlockSummaryView(uuid: ByteArray, name: String, createdAtMs: ULong, lastModifiedMs: ULong)` with `val uuidHex: String`; `data class RecordSummaryView(uuidHex, type, tags, createdAtMs, lastModMs, tombstone, fieldNames)`; `sealed class VaultBrowseError : Exception`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BrowseModelsTest {
    @Test
    fun `hexOfBytes lowercases and zero-pads each byte`() {
        assertEquals("000102ff", hexOfBytes(byteArrayOf(0, 1, 2, 0xff.toByte())))
        assertEquals("", hexOfBytes(ByteArray(0)))
    }

    @Test
    fun `block summary derives a 32-char lowercase hex from its uuid`() {
        val uuid = ByteArray(16) { it.toByte() }
        val block = BlockSummaryView(uuid = uuid, name = "Logins", createdAtMs = 1u, lastModifiedMs = 2u)
        assertEquals("000102030405060708090a0b0c0d0e0f", block.uuidHex)
        assertEquals("Logins", block.name)
    }

    @Test
    fun `record summary carries metadata and no secret value`() {
        val rec = RecordSummaryView(
            uuidHex = "deadbeef",
            type = "login",
            tags = listOf("personal"),
            createdAtMs = 10u,
            lastModMs = 20u,
            tombstone = false,
            fieldNames = listOf("username", "password"),
        )
        assertEquals("login", rec.type)
        assertEquals(listOf("username", "password"), rec.fieldNames)
        assertTrue(rec.tags.contains("personal"))
    }

    @Test
    fun `VaultBrowseError is throwable and arms carry detail`() {
        val e: VaultBrowseError = VaultBrowseError.BlockNotFound("00")
        assertTrue(e is Exception)
        assertEquals("00", (e as VaultBrowseError.BlockNotFound).uuidHex)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.BrowseModelsTest'`
Expected: FAIL — `hexOfBytes` / `BlockSummaryView` / `RecordSummaryView` / `VaultBrowseError` unresolved.

- [ ] **Step 3: Write minimal implementation**

`HexFormat.kt`:
```kotlin
package org.secretary.browse

private const val HEX_DIGITS = "0123456789abcdef"

/**
 * Lowercase hex encoding of [bytes] (two chars per byte, zero-padded). Pure; used to derive the
 * stable string identity of a block/record UUID for UI keys and equality (raw [ByteArray] has
 * referential equals/hashCode, so hex is the safe identity).
 */
fun hexOfBytes(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xff
        sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0f])
    }
    return sb.toString()
}
```

`BrowseModels.kt`:
```kotlin
package org.secretary.browse

/**
 * Metadata for one vault block (no records decrypted). Holds the raw 16-byte [uuid] because the
 * session needs it to call `read_block`; [uuidHex] is the string identity for UI keys.
 *
 * NOT a data class: a data class over a [ByteArray] gives referential equals/hashCode. Treat
 * [uuidHex] as identity. Mirror of iOS `BlockSummary`.
 */
class BlockSummaryView(
    val uuid: ByteArray,
    val name: String,
    val createdAtMs: ULong,
    val lastModifiedMs: ULong,
) {
    val uuidHex: String get() = hexOfBytes(uuid)
}

/**
 * Metadata-only view of one record. Deliberately carries NO secret value — only the field *names*
 * (metadata). Reveal-on-tap (`expose_text`/`expose_bytes`) is a deferred slice; this type having no
 * value field is the structural guarantee that no secret is materialized while browsing.
 * Mirror of iOS `RecordView` minus the reveal closures.
 */
data class RecordSummaryView(
    val uuidHex: String,
    val type: String,
    val tags: List<String>,
    val createdAtMs: ULong,
    val lastModMs: ULong,
    val tombstone: Boolean,
    val fieldNames: List<String>,
)
```

`VaultBrowseError.kt`:
```kotlin
package org.secretary.browse

/**
 * Errors raised by the vault open/browse surface. Throwable (mirrors [org.secretary.sync.VaultSyncError])
 * so the coordinator can `catch (e: VaultBrowseError)`. Deliberately SEPARATE from `VaultSyncError`:
 * the open/read FFI returns a different `VaultException` arm set; folding them would misattribute errors.
 *
 * [WrongPasswordOrCorrupt] is intentionally conflated (wrong password vs. corruption) per the threat
 * model's anti-oracle rule (§13). Do NOT split it.
 */
sealed class VaultBrowseError(message: String? = null) : Exception(message) {
    /** Open failed: wrong password OR corrupt vault. Conflated on purpose (§13). */
    data object WrongPasswordOrCorrupt : VaultBrowseError()

    /** The opened folder is a different vault than expected. */
    data object VaultMismatch : VaultBrowseError()

    /** The vault on disk is structurally corrupt. */
    data class CorruptVault(val detail: String) : VaultBrowseError(detail)

    /** The supplied folder path is not a readable vault folder. */
    data class FolderInvalid(val detail: String) : VaultBrowseError(detail)

    /** No block with the requested UUID exists in the manifest. */
    data class BlockNotFound(val uuidHex: String) : VaultBrowseError(uuidHex)

    /** A caller argument was malformed (e.g. wrong-length UUID). */
    data class InvalidArgument(val detail: String) : VaultBrowseError(detail)

    /** Any other open/read failure (the mapper's else-fold). */
    data class Failed(val detail: String) : VaultBrowseError(detail)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.BrowseModelsTest'`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse android/vault-access/src/test/kotlin/org/secretary/browse
git commit -m "feat(android): browse view types + hex helper + VaultBrowseError (:vault-access)"
```

---

### Task 2: `VaultOpenPort` / `VaultSession` seam + test fakes (`:vault-access`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt`

**Interfaces:**
- Consumes: `BlockSummaryView`, `RecordSummaryView`, `VaultBrowseError` (Task 1).
- Produces: `interface VaultOpenPort { suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession }`; `interface VaultSession { fun vaultUuidHex(): String; fun blockSummaries(): List<BlockSummaryView>; suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView>; fun wipe() }`; test doubles `FakeVaultOpenPort`, `FakeVaultSession`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FakeVaultBrowseTest {
    private fun block(name: String) =
        BlockSummaryView(uuid = ByteArray(16) { name.first().code.toByte() }, name = name, createdAtMs = 1u, lastModifiedMs = 2u)

    @Test
    fun `fake port opens to a seeded session`() = runTest {
        val session = FakeVaultSession(vaultUuidHex = "abcd", blocks = listOf(block("Logins")))
        val port = FakeVaultOpenPort(session = session)
        val opened = port.openWithPassword("/vault", "pw".toByteArray())
        assertEquals(session, opened)
        assertEquals(listOf("/vault"), port.openedFolders)
    }

    @Test
    fun `fake port throws the seeded open error`() = runTest {
        val port = FakeVaultOpenPort(openError = VaultBrowseError.WrongPasswordOrCorrupt)
        assertThrows(VaultBrowseError.WrongPasswordOrCorrupt::class.java) {
            kotlinx.coroutines.runBlocking { port.openWithPassword("/vault", "pw".toByteArray()) }
        }
    }

    @Test
    fun `fake session returns seeded records and records wipe`() = runTest {
        val recs = listOf(
            RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf("username")),
        )
        val session = FakeVaultSession(vaultUuidHex = "abcd", blocks = listOf(block("Logins")), recordsByBlockHex = mapOf("4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c" to recs))
        // "Logins" → first char 'L' = 0x4c repeated 16x
        val out = session.readBlock(session.blockSummaries().first().uuid, includeDeleted = false)
        assertEquals(recs, out)
        assertTrue(!session.wiped)
        session.wipe()
        assertTrue(session.wiped)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.FakeVaultBrowseTest'`
Expected: FAIL — `VaultOpenPort` / `VaultSession` / fakes unresolved.

- [ ] **Step 3: Write minimal implementation**

`VaultOpenPort.kt`:
```kotlin
package org.secretary.browse

/**
 * Opens a vault folder, producing a [VaultSession]. The pure seam mirrors iOS `VaultOpenPort`; the
 * real implementation (`:kit` `UniffiVaultOpenPort`) runs Argon2id off the main thread. The
 * [password] is forwarded per call and never retained by the port.
 */
interface VaultOpenPort {
    suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession
}

/**
 * An opened vault. The single owner of the decrypted manifest + identity handles. [blockSummaries]
 * is in-memory manifest metadata (no decryption); [readBlock] decrypts ONE block and returns
 * metadata-only [RecordSummaryView]s (it never exposes a secret value). [wipe] zeroizes/releases the
 * underlying handles and is idempotent. Mirror of iOS `VaultSession`.
 */
interface VaultSession {
    fun vaultUuidHex(): String
    fun blockSummaries(): List<BlockSummaryView>
    suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView>
    fun wipe()
}
```

`FakeVaultBrowse.kt` (test source):
```kotlin
package org.secretary.browse

/** In-memory [VaultSession] for host tests. Records whether it was wiped; keyed by block uuidHex. */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    private val recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> = blocks
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        readError?.let { throw it }
        return recordsByBlockHex[hexOfBytes(blockUuid)] ?: emptyList()
    }
    override fun wipe() { wiped = true }
}

/** Scriptable [VaultOpenPort]: returns [session] or throws [openError]; records opened folders. */
class FakeVaultOpenPort(
    private val session: VaultSession = FakeVaultSession("00", emptyList()),
    private val openError: VaultBrowseError? = null,
) : VaultOpenPort {
    val openedFolders: MutableList<String> = mutableListOf()
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession {
        openedFolders += vaultFolder
        openError?.let { throw it }
        return session
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.FakeVaultBrowseTest'`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultOpenPort.kt android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowse.kt android/vault-access/src/test/kotlin/org/secretary/browse/FakeVaultBrowseTest.kt
git commit -m "feat(android): VaultOpenPort/VaultSession seam + host fakes (:vault-access)"
```

---

### Task 3: `VaultBrowseModel` coordinator (`:vault-access`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt`

**Interfaces:**
- Consumes: `VaultSession`, `BlockSummaryView`, `RecordSummaryView`, `VaultBrowseError`, fakes (Tasks 1–2).
- Produces: `class VaultBrowseModel(session: VaultSession)` with `val blocks: StateFlow<List<BlockSummaryView>>`, `val selectedBlock: StateFlow<BlockSummaryView?>`, `val selectedRecords: StateFlow<List<RecordSummaryView>?>`, `val error: StateFlow<VaultBrowseError?>`; `fun loadBlocks()`, `suspend fun selectBlock(block: BlockSummaryView)`, `fun clearSelection()`, `fun lock()`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultBrowseModelTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val recs = listOf(RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf("username")))
    private fun session(readError: VaultBrowseError? = null) =
        FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to recs), readError)

    @Test
    fun `loadBlocks publishes the manifest summaries`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks()
        assertEquals(listOf(block), model.blocks.value)
        assertNull(model.error.value)
    }

    @Test
    fun `selectBlock publishes the block's records`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks()
        model.selectBlock(block)
        assertEquals(block, model.selectedBlock.value)
        assertEquals(recs, model.selectedRecords.value)
    }

    @Test
    fun `a read failure is captured as a typed error and leaves selection cleared`() = runTest {
        val model = VaultBrowseModel(session(readError = VaultBrowseError.BlockNotFound("4c")))
        model.loadBlocks()
        model.selectBlock(block)
        assertTrue(model.error.value is VaultBrowseError.BlockNotFound)
        assertNull(model.selectedRecords.value)
    }

    @Test
    fun `clearSelection returns to the block list`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks(); model.selectBlock(block)
        model.clearSelection()
        assertNull(model.selectedBlock.value)
        assertNull(model.selectedRecords.value)
    }

    @Test
    fun `lock wipes the session and resets every flow`() = runTest {
        val s = session()
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(block)
        model.lock()
        assertTrue(s.wiped)
        assertTrue(model.blocks.value.isEmpty())
        assertNull(model.selectedBlock.value)
        assertNull(model.selectedRecords.value)
        assertNull(model.error.value)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: FAIL — `VaultBrowseModel` unresolved.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The host-tested heart of the Android browse UI — Kotlin mirror of the iOS VaultBrowseViewModel's
 * coordinator role (metadata-only: it never reveals a field value). It owns the [VaultSession] and
 * turns "open → list blocks → select a block → list records" into observable [StateFlow]s.
 *
 * Concurrency: main-thread-confined like the iOS @MainActor model. [selectBlock] is `suspend`
 * because the real session offloads `read_block` (AEAD) to IO; callers invoke it from the UI scope.
 *
 * Secret hygiene: no record field value is ever materialized here — [readBlock] returns metadata-only
 * [RecordSummaryView]s. [lock] wipes the session (called on background) and resets all state.
 */
class VaultBrowseModel(private val session: VaultSession) {
    private val _blocks = MutableStateFlow<List<BlockSummaryView>>(emptyList())
    val blocks: StateFlow<List<BlockSummaryView>> = _blocks.asStateFlow()

    private val _selectedBlock = MutableStateFlow<BlockSummaryView?>(null)
    val selectedBlock: StateFlow<BlockSummaryView?> = _selectedBlock.asStateFlow()

    private val _selectedRecords = MutableStateFlow<List<RecordSummaryView>?>(null)
    val selectedRecords: StateFlow<List<RecordSummaryView>?> = _selectedRecords.asStateFlow()

    private val _error = MutableStateFlow<VaultBrowseError?>(null)
    val error: StateFlow<VaultBrowseError?> = _error.asStateFlow()

    /** Publish the manifest's block summaries (in-memory metadata; no decryption). */
    fun loadBlocks() {
        _error.value = null
        _blocks.value = session.blockSummaries()
    }

    /** Decrypt the selected block and publish its records (metadata only). Errors are captured. */
    suspend fun selectBlock(block: BlockSummaryView) {
        _error.value = null
        try {
            val records = session.readBlock(block.uuid, includeDeleted = false)
            _selectedBlock.value = block
            _selectedRecords.value = records
        } catch (e: VaultBrowseError) {
            _error.value = e
            _selectedBlock.value = null
            _selectedRecords.value = null
        }
    }

    /** Return to the block list. */
    fun clearSelection() {
        _selectedBlock.value = null
        _selectedRecords.value = null
    }

    /** Wipe the session (zeroize handles) and reset every flow. Called on background / lock. */
    fun lock() {
        session.wipe()
        _blocks.value = emptyList()
        _selectedBlock.value = null
        _selectedRecords.value = null
        _error.value = null
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.VaultBrowseModelTest'`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the whole module to confirm no regression, then commit**

```bash
cd android && ./gradlew :vault-access:test
git add android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt
git commit -m "feat(android): VaultBrowseModel coordinator + host tests (:vault-access)"
```

---

### Task 4: Browse error/summary mappers (`:kit`)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTest.kt`

**Interfaces:**
- Consumes: `VaultBrowseError`, `BlockSummaryView` (`:vault-access`); `uniffi.secretary.{VaultException, BlockSummary}`.
- Produces: `internal fun mapVaultBrowseError(e: VaultException): VaultBrowseError`; `internal fun mapBlockSummary(s: BlockSummary): BlockSummaryView`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.BlockSummary
import uniffi.secretary.VaultException

class BrowseMappingTest {
    @Test
    fun `maps open-relevant arms to their domain counterparts`() {
        assertEquals(VaultBrowseError.WrongPasswordOrCorrupt, mapVaultBrowseError(VaultException.WrongPasswordOrCorrupt()))
        assertEquals(VaultBrowseError.VaultMismatch, mapVaultBrowseError(VaultException.VaultMismatch()))
        assertEquals(VaultBrowseError.CorruptVault("c"), mapVaultBrowseError(VaultException.CorruptVault("c")))
        assertEquals(VaultBrowseError.FolderInvalid("f"), mapVaultBrowseError(VaultException.FolderInvalid("f")))
        assertEquals(VaultBrowseError.BlockNotFound("ab"), mapVaultBrowseError(VaultException.BlockNotFound("ab")))
        assertEquals(VaultBrowseError.InvalidArgument("a"), mapVaultBrowseError(VaultException.InvalidArgument("a")))
    }

    @Test
    fun `folds any other arm into Failed carrying the variant name`() {
        val mapped = mapVaultBrowseError(VaultException.RecordNotFound("deadbeef"))
        assertTrue(mapped is VaultBrowseError.Failed)
        assertTrue((mapped as VaultBrowseError.Failed).detail.contains("RecordNotFound"))
    }

    @Test
    fun `block summary maps every metadata field`() {
        val uuid = ByteArray(16) { it.toByte() }
        val view = mapBlockSummary(
            BlockSummary(blockUuid = uuid, blockName = "Logins", createdAtMs = 5u, lastModifiedMs = 6u, recipientUuids = emptyList()),
        )
        assertEquals("000102030405060708090a0b0c0d0e0f", view.uuidHex)
        assertEquals("Logins", view.name)
        assertEquals(5uL, view.createdAtMs)
        assertEquals(6uL, view.lastModifiedMs)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :kit:testDebugUnitTest --tests 'org.secretary.browse.BrowseMappingTest'`
Expected: FAIL — `mapVaultBrowseError` / `mapBlockSummary` unresolved.

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.browse

import uniffi.secretary.BlockSummary
import uniffi.secretary.VaultException

/**
 * Pure `VaultException` → [VaultBrowseError] mapper for the open/read path. Maps only the
 * open-relevant arms; every other arm folds into [VaultBrowseError.Failed] carrying the variant
 * name (mirrors `:kit`'s `mapVaultSyncError` else-fold).
 *
 * [VaultException.WrongPasswordOrCorrupt] stays conflated per the threat model (§13) — do NOT split.
 *
 * MAINTAINER WARNING: the `else` fold silently swallows any FUTURE open-relevant arm into
 * [VaultBrowseError.Failed] (the `when` is non-exhaustive by design over a ~30-arm sealed type). If
 * the open/read FFI surface gains a new arm, add an explicit branch above `else` and a matching
 * [VaultBrowseError] case. The Kotlin compiler will not flag it.
 */
internal fun mapVaultBrowseError(e: VaultException): VaultBrowseError = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> VaultBrowseError.WrongPasswordOrCorrupt
    is VaultException.VaultMismatch -> VaultBrowseError.VaultMismatch
    is VaultException.CorruptVault -> VaultBrowseError.CorruptVault(e.detail)
    is VaultException.FolderInvalid -> VaultBrowseError.FolderInvalid(e.detail)
    is VaultException.BlockNotFound -> VaultBrowseError.BlockNotFound(e.uuidHex)
    is VaultException.InvalidArgument -> VaultBrowseError.InvalidArgument(e.detail)
    else -> VaultBrowseError.Failed(e.toString())
}

/** Pure uniffi `BlockSummary` → [BlockSummaryView] (metadata only; recipient list dropped). */
internal fun mapBlockSummary(s: BlockSummary): BlockSummaryView =
    BlockSummaryView(
        uuid = s.blockUuid,
        name = s.blockName,
        createdAtMs = s.createdAtMs,
        lastModifiedMs = s.lastModifiedMs,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :kit:testDebugUnitTest --tests 'org.secretary.browse.BrowseMappingTest'`
Expected: PASS (3 tests). If `BlockSummary`'s generated constructor uses different arg defaults, keep all five named args as shown.

- [ ] **Step 5: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse android/kit/src/test/kotlin/org/secretary/browse
git commit -m "feat(android): browse error + block-summary mappers + host tests (:kit)"
```

---

### Task 5: Real uniffi adapter — `UniffiVaultOpenPort` + `UniffiVaultSession` + factory (`:kit`)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt`

**Interfaces:**
- Consumes: `VaultOpenPort`, `VaultSession`, `RecordSummaryView`, `BlockSummaryView`, `hexOfBytes` (`:vault-access`); `mapVaultBrowseError`, `mapBlockSummary` (Task 4); `uniffi.secretary.{openVaultWithPassword, readBlock, OpenVaultOutput, OpenVaultManifest, UnlockedIdentity, Record, VaultException}`.
- Produces: `class UniffiVaultOpenPort(...) : VaultOpenPort`; `class UniffiVaultSession(output: OpenVaultOutput) : VaultSession`; `fun uniffiVaultOpenPort(): VaultOpenPort`.

> No host unit test: this is the only browse code that invokes the native bindings; it is proven on-device by Task 8's `OpenBrowseSmokeTest`. (Mirrors `:kit`'s `UniffiVaultSyncPort`, whose real FFI calls are proven by `SyncRoundTripInstrumentedTest`.)

- [ ] **Step 1: Write the implementation**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.OpenVaultManifest
import uniffi.secretary.OpenVaultOutput
import uniffi.secretary.Record
import uniffi.secretary.UnlockedIdentity
import uniffi.secretary.VaultException
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.readBlock

/**
 * The real [VaultOpenPort] over the generated `uniffi.secretary` open call. The only browse code
 * (with [UniffiVaultSession]) that invokes the bindings. Kotlin mirror of iOS `UniffiVaultOpenPort`.
 *
 * [openWithPassword] re-derives the vault key with Argon2id, so it runs on [ioDispatcher]
 * (default [Dispatchers.IO]) to keep the caller responsive. The password [ByteArray] is forwarded
 * per call (UTF-8 path + raw password bytes) and never retained. The open function is an injectable
 * seam defaulting to the real binding.
 */
class UniffiVaultOpenPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val openFn: (ByteArray, ByteArray) -> OpenVaultOutput = ::openVaultWithPassword,
) : VaultOpenPort {
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors { openFn(vaultFolder.toByteArray(Charsets.UTF_8), password) }
            UniffiVaultSession(output, ioDispatcher)
        }
}

/**
 * The real [VaultSession]: owns the decrypted [OpenVaultManifest] + [UnlockedIdentity] handles.
 * [blockSummaries] reads in-memory manifest metadata. [readBlock] decrypts ONE block on
 * [ioDispatcher], maps each [Record]'s metadata + field NAMES to a [RecordSummaryView], and closes
 * the block output immediately — it NEVER calls `exposeText`/`exposeBytes`, so no secret value is
 * materialized while browsing. [wipe] zeroizes the manifest + identity (idempotent).
 */
class UniffiVaultSession(
    output: OpenVaultOutput,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : VaultSession {
    private val identity: UnlockedIdentity = output.identity
    private val manifest: OpenVaultManifest = output.manifest

    override fun vaultUuidHex(): String = hexOfBytes(manifest.vaultUuid())

    override fun blockSummaries(): List<BlockSummaryView> =
        manifest.blockSummaries().map(::mapBlockSummary)

    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> =
        withContext(ioDispatcher) {
            mapErrors {
                // `.use` closes (and zeroizes) the decrypted block output as soon as we have copied
                // the metadata out — no decrypted record handle outlives this call.
                readBlock(identity, manifest, blockUuid, includeDeleted).use { block ->
                    val count = block.recordCount().toInt()
                    (0 until count).mapNotNull { i ->
                        block.recordAt(i.toULong())?.use(::toRecordSummaryView)
                    }
                }
            }
        }

    override fun wipe() {
        // Idempotent zeroize-now of both long-lived handles (mirrors iOS UniffiVaultSession.wipe).
        manifest.wipe()
        identity.wipe()
    }
}

/** Map one decrypted [Record] handle to a metadata-only view. NEVER reads a field value. */
private fun toRecordSummaryView(record: Record): RecordSummaryView =
    RecordSummaryView(
        uuidHex = hexOfBytes(record.recordUuid()),
        type = record.recordType(),
        tags = record.tags(),
        createdAtMs = record.createdAtMs(),
        lastModMs = record.lastModMs(),
        tombstone = record.tombstone(),
        fieldNames = record.fieldNames(),
    )

/** Run an FFI call, translating any [VaultException] into the domain [VaultBrowseError]. */
private inline fun <T> mapErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultBrowseError(e)
    }

/** Production factory for the real open port (defaults to the live bindings + IO dispatcher). */
fun uniffiVaultOpenPort(): VaultOpenPort = UniffiVaultOpenPort()
```

- [ ] **Step 2: Compile the module (no native load on the host compile path)**

Run: `cd android && ./gradlew :kit:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. If `Record`/`OpenVaultManifest` method names differ from the binding, fix to match the generated `uniffi.secretary` symbols (see Global Constraints).

- [ ] **Step 3: Run `:kit` host tests (mapping tests still green; adapter is compile-only here)**

Run: `cd android && ./gradlew :kit:testDebugUnitTest`
Expected: PASS (existing + Task 4).

- [ ] **Step 4: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt
git commit -m "feat(android): UniffiVaultOpenPort + UniffiVaultSession + factory (:kit)"
```

---

### Task 6: `:browse-ui` module scaffold + ViewModel + render helpers

**Files:**
- Create: `android/browse-ui/build.gradle.kts`
- Create: `android/browse-ui/src/main/AndroidManifest.xml` (empty `<manifest/>` — library; or omit if AGP infers namespace-only)
- Modify: `android/settings.gradle.kts` (add `include(":browse-ui")`)
- Create: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/VaultBrowseViewModel.kt`
- Create: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseRenderHelpers.kt`
- Test: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/VaultBrowseViewModelTest.kt`
- Test: `android/browse-ui/src/test/kotlin/org/secretary/browse/ui/BrowseRenderHelpersTest.kt`

**Interfaces:**
- Consumes: `VaultBrowseModel`, `BlockSummaryView`, `RecordSummaryView`, `VaultBrowseError`, fakes (Tasks 1–3).
- Produces: `class VaultBrowseViewModel(model: VaultBrowseModel) : ViewModel()` (`blocks`, `selectedBlock`, `selectedRecords`, `error` flows; `loadBlocks()`, `selectBlock(block)`, `back()`, `lock()`); `fun recordTitle(r: RecordSummaryView): String`; `fun blockLabel(b: BlockSummaryView): String`.

- [ ] **Step 1: Create the module build file** (mirror `:sync-ui/build.gradle.kts` exactly, with `namespace = "org.secretary.browse.ui"`)

`android/browse-ui/build.gradle.kts`:
```kotlin
plugins {
    id("com.android.library")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.secretary.browse.ui"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
    }

    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
}

kotlin {
    jvmToolchain(21)
}

// Test-tooling version forces — identical rationale to :sync-ui (API-36 Espresso + the workspace
// coroutines 1.8.0 production pin must win over espresso's transitive coroutines-bom constraint).
configurations.configureEach {
    resolutionStrategy {
        force("androidx.test.espresso:espresso-core:3.7.0")
        force("androidx.test.espresso:espresso-idling-resource:3.7.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")
    }
}

dependencies {
    // FFI-free: the UI layer depends only on the pure model module, never on :kit.
    api(project(":vault-access"))

    val composeBom = platform("androidx.compose:compose-bom:2025.05.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.activity:activity-compose")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }

    // --- Host JUnit5 unit tests (helpers + ViewModel forwarding) ---
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
    testImplementation("androidx.lifecycle:lifecycle-viewmodel:2.8.6")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // --- Instrumented Compose UI tests (none authored this slice; deps kept for parity/future) ---
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
```

Add to `android/settings.gradle.kts` after `include(":sync-ui")`:
```kotlin
include(":browse-ui")
```

- [ ] **Step 2: Write the failing tests**

`BrowseRenderHelpersTest.kt`:
```kotlin
package org.secretary.browse.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView

class BrowseRenderHelpersTest {
    private fun rec(type: String, tags: List<String>, tombstone: Boolean = false) =
        RecordSummaryView("aa", type, tags, 1u, 2u, tombstone, listOf("username"))

    @Test
    fun `record title shows type and first tag`() {
        assertEquals("login · personal", recordTitle(rec("login", listOf("personal", "work"))))
    }

    @Test
    fun `record title without tags is just the type`() {
        assertEquals("login", recordTitle(rec("login", emptyList())))
    }

    @Test
    fun `untyped record falls back to a placeholder`() {
        assertEquals("Untitled record", recordTitle(rec("", emptyList())))
    }

    @Test
    fun `deleted record title is prefixed`() {
        assertEquals("(deleted) login", recordTitle(rec("login", emptyList(), tombstone = true)))
    }

    @Test
    fun `block label uses the name and falls back when blank`() {
        assertEquals("Logins", blockLabel(BlockSummaryView(ByteArray(16), "Logins", 1u, 2u)))
        assertEquals("Untitled block", blockLabel(BlockSummaryView(ByteArray(16), "", 1u, 2u)))
    }
}
```

`VaultBrowseViewModelTest.kt`:
```kotlin
package org.secretary.browse.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel

class VaultBrowseViewModelTest {
    private val dispatcher = StandardTestDispatcher()
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val recs = listOf(RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf("username")))

    @BeforeEach fun setUp() = Dispatchers.setMain(dispatcher)
    @AfterEach fun tearDown() = Dispatchers.resetMain()

    private fun model() = VaultBrowseModel(FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to recs)))

    @Test
    fun `loadBlocks forwards to the model`() = runTest {
        val vm = VaultBrowseViewModel(model())
        vm.loadBlocks()
        assertEquals(listOf(block), vm.blocks.value)
    }

    @Test
    fun `selectBlock launches the suspend read and publishes records`() = runTest {
        val vm = VaultBrowseViewModel(model())
        vm.loadBlocks()
        vm.selectBlock(block)
        dispatcher.scheduler.advanceUntilIdle()
        assertEquals(recs, vm.selectedRecords.value)
        assertEquals(block, vm.selectedBlock.value)
    }

    @Test
    fun `back clears the selection`() = runTest {
        val vm = VaultBrowseViewModel(model())
        vm.loadBlocks(); vm.selectBlock(block); dispatcher.scheduler.advanceUntilIdle()
        vm.back()
        assertNull(vm.selectedBlock.value)
        assertNull(vm.selectedRecords.value)
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd android && ./gradlew :browse-ui:test`
Expected: FAIL — module/`VaultBrowseViewModel`/helpers unresolved (after the module resolves).

- [ ] **Step 4: Write minimal implementation**

`BrowseRenderHelpers.kt`:
```kotlin
package org.secretary.browse.ui

import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView

private const val UNTITLED_RECORD = "Untitled record"
private const val UNTITLED_BLOCK = "Untitled block"
private const val DELETED_PREFIX = "(deleted) "
private const val TAG_SEPARATOR = " · "

/**
 * Pure human label for a record row: `type` optionally suffixed with its first tag, prefixed with a
 * deleted marker for tombstones. Never reads a field value (metadata only). Empty type → placeholder.
 */
fun recordTitle(record: RecordSummaryView): String {
    val base = record.type.ifBlank { UNTITLED_RECORD }
    val withTag = if (record.tags.isEmpty()) base else "$base$TAG_SEPARATOR${record.tags.first()}"
    return if (record.tombstone) "$DELETED_PREFIX$withTag" else withTag
}

/** Pure label for a block row: its name, or a placeholder when blank. */
fun blockLabel(block: BlockSummaryView): String = block.name.ifBlank { UNTITLED_BLOCK }
```

`VaultBrowseViewModel.kt`:
```kotlin
package org.secretary.browse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultBrowseModel

/**
 * Thin Compose bridge over the host-tested [VaultBrowseModel]. Holds NO browse logic — it
 * re-exposes the model's StateFlows for `collectAsStateWithLifecycle` and launches the model's
 * suspend [selectBlock] on [viewModelScope]. The injected [model] wraps `:kit`'s real session in
 * production and a fake in tests; this class never touches the FFI.
 */
class VaultBrowseViewModel(private val model: VaultBrowseModel) : ViewModel() {
    val blocks: StateFlow<List<BlockSummaryView>> = model.blocks
    val selectedBlock: StateFlow<BlockSummaryView?> = model.selectedBlock
    val selectedRecords: StateFlow<List<RecordSummaryView>?> = model.selectedRecords
    val error: StateFlow<VaultBrowseError?> = model.error

    /** Publish the manifest block summaries (synchronous in-memory read). */
    fun loadBlocks() = model.loadBlocks()

    /** Decrypt + list the selected block's records (metadata only). */
    fun selectBlock(block: BlockSummaryView) {
        viewModelScope.launch { model.selectBlock(block) }
    }

    /** Return to the block list. */
    fun back() = model.clearSelection()

    /** Wipe the session (called on background); the screen returns to Unlock. */
    fun lock() = model.lock()
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd android && ./gradlew :browse-ui:test`
Expected: PASS (8 tests).

- [ ] **Step 6: Commit**

```bash
git add android/settings.gradle.kts android/browse-ui
git commit -m "feat(android): :browse-ui module + VaultBrowseViewModel + render helpers"
```

---

### Task 7: `BrowseScreen` Compose UI (`:browse-ui`)

**Files:**
- Create: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt`

**Interfaces:**
- Consumes: `VaultBrowseViewModel` (Task 6), `recordTitle`, `blockLabel`, `BlockSummaryView`, `RecordSummaryView`, `VaultBrowseError`.
- Produces: `@Composable fun BrowseScreen(viewModel: VaultBrowseViewModel)`.

> No host unit test: per the spec, the Compose glue is not UI-unit-tested this slice (the genuinely-novel runtime behavior — real FFI open/read — is proven by Task 8's on-device smoke; the pure VM + helpers are already host-tested in Task 6). Mirrors slice-6's untested `AppRoot`/`SyncScreen` glue. The deliverable is that `:browse-ui` compiles and `:browse-ui:test` stays green.

- [ ] **Step 1: Write the implementation**

```kotlin
package org.secretary.browse.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseError

/**
 * Metadata-only browse surface: a block list, and (when a block is selected) that block's record
 * titles with a back affordance. No secret value is ever rendered — only types/tags/field-names.
 * Loads blocks once on first composition.
 */
@Composable
fun BrowseScreen(viewModel: VaultBrowseViewModel) {
    val blocks by viewModel.blocks.collectAsStateWithLifecycle()
    val selectedBlock by viewModel.selectedBlock.collectAsStateWithLifecycle()
    val records by viewModel.selectedRecords.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { viewModel.loadBlocks() }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        error?.let { ErrorBanner(it) }
        val block = selectedBlock
        if (block == null) {
            Text("Blocks", style = MaterialTheme.typography.titleMedium)
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(blocks, key = { it.uuidHex }) { b ->
                    BlockRow(b, onClick = { viewModel.selectBlock(b) })
                    Divider()
                }
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(blockLabel(block), style = MaterialTheme.typography.titleMedium)
                TextButton(onClick = { viewModel.back() }) { Text("Back") }
            }
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(records.orEmpty(), key = { it.uuidHex }) { r ->
                    RecordRow(r)
                    Divider()
                }
            }
        }
    }
}

@Composable
private fun BlockRow(block: BlockSummaryView, onClick: () -> Unit) {
    Text(
        text = blockLabel(block),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp),
        style = MaterialTheme.typography.bodyLarge,
    )
}

@Composable
private fun RecordRow(record: RecordSummaryView) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
        Text(recordTitle(record), style = MaterialTheme.typography.bodyLarge)
        if (record.fieldNames.isNotEmpty()) {
            Text(
                text = record.fieldNames.joinToString(", "),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun ErrorBanner(error: VaultBrowseError) {
    Text(
        text = "Couldn't read the vault: ${error::class.simpleName}",
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(bottom = 8.dp),
    )
}
```

- [ ] **Step 2: Compile + run module tests (still green)**

Run: `cd android && ./gradlew :browse-ui:compileDebugKotlin :browse-ui:test`
Expected: BUILD SUCCESSFUL; Task 6 tests still PASS. If `Divider` is flagged deprecated under `-Xlint`, switch to `HorizontalDivider` (Compose BOM 2025.05 has it).

- [ ] **Step 3: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/BrowseScreen.kt
git commit -m "feat(android): BrowseScreen metadata-only Compose UI (:browse-ui)"
```

---

### Task 8: App wiring (route → Browse) + on-device open/browse smoke (`:app`)

**Files:**
- Modify: `android/app/build.gradle.kts` (add `implementation(project(":browse-ui"))`)
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` (route Unlock → Browse; lock on background)
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt`

**Interfaces:**
- Consumes: `uniffiVaultOpenPort()` (Task 5), `VaultBrowseModel` (Task 3), `VaultBrowseViewModel` + `BrowseScreen` (Tasks 6–7), `AppVaultProvisioning.stageGoldenVault` (existing), `VaultBrowseError` (Task 1).
- Produces: the runnable app's browse route; the on-device proof.

- [ ] **Step 1: Add the `:browse-ui` dependency**

In `android/app/build.gradle.kts`, in the `dependencies { }` block alongside the existing project deps:
```kotlin
    implementation(project(":browse-ui"))
```

- [ ] **Step 2: Write the failing instrumented test** (the test bar for the real-FFI wiring)

`OpenBrowseSmokeTest.kt`:
```kotlin
package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * First on-device exercise of the open/browse stack: production provisioning → uniffiVaultOpenPort
 * (real `openVaultWithPassword`, Argon2id) → VaultBrowseModel over the REAL native
 * libsecretary_ffi_uniffi.so. Host tests (fakes) cannot touch the .so. Metadata-only: asserts on
 * block/record metadata; never exposes a field value.
 */
@RunWith(AndroidJUnit4::class)
class OpenBrowseSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    // The published golden-vault KAT password — not a real secret.
    private val goldenPassword = "correct horse battery staple"

    @After fun cleanup() {
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun open_correctPassword_listsBlocksAndRecordMetadata() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val session = uniffiVaultOpenPort().openWithPassword(folder.path, goldenPassword.toByteArray())
        val model = VaultBrowseModel(session)

        model.loadBlocks()
        val blocks = model.blocks.value
        assertTrue("golden vault has at least one block", blocks.isNotEmpty())
        assertTrue("block uuidHex is 32 hex chars", blocks.first().uuidHex.length == 32)

        model.selectBlock(blocks.first())
        val records = model.selectedRecords.value
        assertNotNull("a block read yields a (possibly empty) record list", records)
        // golden_vault_001's first block is non-empty; assert real metadata came back.
        assertTrue("first block has records", records!!.isNotEmpty())
        val first = records.first()
        assertTrue("record type is non-empty", first.type.isNotBlank())
        assertTrue("record uuidHex is 32 hex chars", first.uuidHex.length == 32)

        model.lock()
        assertTrue("lock clears blocks", model.blocks.value.isEmpty())
    }

    @Test
    fun open_wrongPassword_throwsTypedError() {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        assertThrows(VaultBrowseError.WrongPasswordOrCorrupt::class.java) {
            runBlocking {
                uniffiVaultOpenPort().openWithPassword(folder.path, "definitely-wrong".toByteArray())
            }
        }
    }
}
```

- [ ] **Step 3: Rewrite `AppRoot.kt` to route Unlock → Browse with lock-on-background**

Replace the whole file with:
```kotlin
package org.secretary.app

import android.content.Context
import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.launch
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.uniffiVaultOpenPort
import org.secretary.browse.ui.BrowseScreen
import org.secretary.browse.ui.VaultBrowseViewModel

private const val TAG = "AppRoot"

/** The app's two screens; Browse carries the live view-model for the unlocked session. */
private sealed interface Route {
    data object Unlock : Route
    data class Browse(val viewModel: VaultBrowseViewModel) : Route
}

/**
 * Top-level routing for the walking skeleton: Unlock → Browse. On unlock it opens the REAL vault
 * (open_vault_with_password, Argon2id offloaded to IO inside the port), builds a VaultBrowseModel,
 * lists blocks, and routes to the metadata-only BrowseScreen. On background (ON_STOP) the app routes
 * back to Unlock; leaving Browse disposes its composition, whose DisposableEffect calls
 * viewModel.lock() — the session is wiped, so returning requires the password again (lock-on-background,
 * mirroring iOS). FLAG_SECURE (set on the Activity) blocks screenshot/recents capture.
 */
@Composable
fun AppRoot() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var route by remember { mutableStateOf<Route>(Route.Unlock) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) route = Route.Unlock
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    when (val r = route) {
        is Route.Unlock -> UnlockScreen(onUnlock = { password ->
            scope.launch { route = unlockAndOpen(context, password) }
        })
        is Route.Browse -> {
            // Wipe the session when we leave Browse (background → Unlock, or teardown): the decrypted
            // manifest/identity never outlives the on-screen session. Re-entry re-opens from password.
            DisposableEffect(r.viewModel) {
                onDispose { r.viewModel.lock() }
            }
            BrowseScreen(viewModel = r.viewModel)
        }
    }
}

/**
 * Opens the vault (main-dispatched coroutine; Argon2id hops to IO inside the port), lists blocks,
 * and returns the Browse route. Unlike the sync slice, this open is session-producing and CAN refuse:
 * a wrong password / corrupt or provisioning failure is logged and returns the user to Unlock.
 *
 * Secret hygiene: the password buffer is zeroized in a `finally` wrapping the whole body — overwritten
 * on every exit (success, open failure, early provisioning throw). Because openWithPassword is awaited,
 * the zeroize cannot race the async Argon2id that consumes the buffer.
 *
 * Known accepted minor race (mirrors slice 6): if backgrounded (ON_STOP → route = Unlock) while this
 * suspends, the coroutine may still set route = Browse afterwards; the next ON_STOP disposes Browse and
 * wipes the session, and the password is already zeroized — self-heals.
 */
private suspend fun unlockAndOpen(context: Context, password: ByteArray): Route {
    try {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val session = uniffiVaultOpenPort().openWithPassword(folder.path, password)
        val model = VaultBrowseModel(session)
        model.loadBlocks()
        return Route.Browse(VaultBrowseViewModel(model))
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        return Route.Unlock
    } finally {
        password.fill(0) // zeroize on every exit — success, open failure, or early throw
    }
}
```

- [ ] **Step 4: Verify host suites + the whole-workspace host build**

Run: `cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test`
Expected: BUILD SUCCESSFUL (no emulator). The `:app` host tests (`AppSyncStateDirTest`, `VaultUuidParsingTest`) still pass — `AppSyncStateDir`/`VaultUuidParsing` remain in the module (the latter is still used by `AppVaultProvisioning`).

- [ ] **Step 5: Run the on-device smoke (emulator must be running)**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
```
Expected: BUILD SUCCESSFUL — `OpenBrowseSmokeTest` (2 cases) + the existing `MakeVaultSyncSmokeTest` (2 cases) green on the arm64 emulator (real `.so`).

- [ ] **Step 6: Confirm the guardrails, then commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format' || echo "GUARDRAIL CLEAN"
git add android/app/build.gradle.kts android/app/src/main/kotlin/org/secretary/app/AppRoot.kt android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseSmokeTest.kt
git commit -m "feat(android): route :app unlock → BrowseScreen + on-device open/browse smoke"
```

---

### Task 9: Docs (README + ROADMAP) + handoff

**Files:**
- Modify: `README.md` (Android status: add slice 7 ✅ open/browse)
- Modify: `ROADMAP.md` (mark C.3 Android open/browse slice ✅)
- Create: `docs/handoffs/2026-06-17-c3-android-open-browse-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget symlink)

- [ ] **Step 1: Update README + ROADMAP**

In `README.md`, locate the Android C.3 status (the slice-6 `:app` line) and add a brief dot point: the app now opens a vault and browses block/record metadata (`:browse-ui`, metadata-only; reveal-on-tap deferred). Keep it brief per the README style (dot points, no test-count walls). In `ROADMAP.md`, add/flip the Android open/browse slice to ✅ with a one-line summary; note reveal-on-tap + sync-badge re-integration as the next slices.

- [ ] **Step 2: Verify the doc references are accurate** (grep for any stale "sync-only" / "no open port" Android claim and update it)

Run: `grep -rn "no .* open port\|sync-only" README.md ROADMAP.md`
Expected: either no hits, or hits that you update to reflect the new open/browse capability.

- [ ] **Step 3: Author the handoff and retarget the symlink** (see the `/nextsession` baton requirements: shipped SHAs, what's next w/ acceptance, risks, resume commands)

```bash
# author docs/handoffs/2026-06-17-c3-android-open-browse-shipped.md, then:
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse
ln -snf docs/handoffs/2026-06-17-c3-android-open-browse-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md docs/handoffs/2026-06-17-c3-android-open-browse-shipped.md NEXT_SESSION.md
git commit -m "docs: README + ROADMAP for Android open/browse slice 7 + handoff"
```

---

## Final acceptance (run before opening the PR)

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse/android
./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test          # host green
PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest                                              # on-device green
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   # → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'                # → empty
```

The user reviews/merges the PR; this session does NOT merge.

## Self-Review (completed by the author)

- **Spec coverage:** §Section 1 → Tasks 1–3; §Section 2 → Tasks 4–5; §Section 3 → Tasks 6–7; §Section 4 → Task 8; §Testing → Tasks 1–8; §Acceptance → Final acceptance; §Deferred → carried in the handoff (Task 9). No spec requirement is unmapped.
- **Placeholder scan:** every code/test step carries complete code; no TBD/“similar to”/“add error handling”.
- **Type consistency:** `VaultOpenPort.openWithPassword(String, ByteArray)`, `VaultSession.{vaultUuidHex, blockSummaries, readBlock(ByteArray, Boolean) suspend, wipe}`, `VaultBrowseModel.{loadBlocks, selectBlock(BlockSummaryView) suspend, clearSelection, lock}`, `VaultBrowseViewModel.{loadBlocks, selectBlock, back, lock}`, `mapVaultBrowseError`, `mapBlockSummary`, `uniffiVaultOpenPort()` are referenced identically across tasks. `RecordSummaryView` has no value field (metadata-only invariant). `VaultBrowseError` is a throwable sealed class.
- **Known follow-ups (named in the spec/handoff, not this plan):** reveal-on-tap; sync-badge re-integration onto BrowseScreen; recovery/device open paths; `AppSyncStateDir` is retained but unused by the app route until sync re-integrates.
```
