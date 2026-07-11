# Android Trash Browser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the native Android (Jetpack Compose) Trash browser — list trashed blocks, restore, delete-forever, empty-trash, and run-retention-now against the fixed 90-day default — mirroring the shipped iOS slice (#412).

**Architecture:** Bottom-up over the existing Android browse layering. Pure host-tested logic (value types, formatting, `TrashBrowseModel`) lives in `:vault-access`; the real FFI adapter conforms `UniffiVaultSession` to a new `TrashPort` in `:kit`; a thin Compose `TrashBrowseViewModel` bridge + `TrashScreen` live in `:browse-ui`; `:app` wires the entry point. No new FFI (all trash/retention fns already on the Kotlin uniffi surface).

**Tech Stack:** Kotlin, Jetpack Compose (material3), kotlinx-coroutines (`StateFlow`), JUnit 5 (`org.junit.jupiter`) + `kotlinx-coroutines-test`, uniffi-generated `uniffi.secretary.*` bindings.

## Global Constraints

- **NO new FFI.** All trash/retention functions are already on the Kotlin uniffi surface: `listTrashedBlocks`, `expiredTrashEntries`, `defaultRetentionWindowMs`, `restoreBlock`, `purgeBlock`, `emptyTrash`, `autoPurgeExpired`.
- **NO `core`/crypto/on-disk-format change; NO `manifest_version` bump; `#![forbid(unsafe_code)]` intact.** This slice touches only `android/`.
- **NO new `VaultBrowseError` variant.** `BlockNotInTrash`/`BlockPurged` map to the existing `VaultBrowseError.BlockNotFound`.
- **NO record plaintext crosses the FFI boundary for trash ops** — only block names + counts. The adapter never calls a decrypt/read-record FFI function.
- **Every destructive write is gated** via the existing `WriteReauthGate`; `previewRetention`/`listTrashedBlocks` are ungated reads.
- **Reports are discarded** (parity with iOS/desktop). The `TrashPort` returns report DTOs (plumbed for #411) but `TrashBrowseModel` discards them; success = the reloaded list.
- **`:kit` conformance is in-class, no visibility widening** — Kotlin cannot conform to an interface via an extension file, so the `TrashPort` overrides live in the `UniffiVaultSession` class body and keep `identity`/`manifest`/`write`/`sessionLock`/`wiped` `private`.
- **uniffi numeric mapping:** Rust `u64`/`u32`/`u16` → Kotlin `ULong`/`UInt`/`UShort`. Pure value types use signed `Long`/`Int`; the `:kit` adapter narrows (`.toLong()`/`.toInt()`) at the boundary (mirrors existing `BlockSummaryView`).
- **Package:** `:vault-access` code is `org.secretary.browse`; `:browse-ui` code is `org.secretary.browse.ui`.
- **Build discipline:** build `:app` in the same task as any `:kit`/`:browse-ui` change (a consumer can compile in isolation while `:app` breaks — a uniffi return-shape or cross-module `when` regression only surfaces at `:app`).
- **Working dir:** worktree `.worktrees/android-trash-browser`, branch `feature/android-trash-browser`. All gradle runs from `android/`.

---

### Task 1: Pure value types + formatting helpers (`:vault-access`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/TrashModels.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/TrashFormatting.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/TrashFormattingTest.kt`

**Interfaces:**
- Produces:
  - `data class TrashedBlockInfo(blockUuid: ByteArray, blockName: String, tombstonedAtMs: Long, tombstonedBy: ByteArray)` with `val uuidHex: String`.
  - `data class ExpiredEntryInfo(blockUuid: ByteArray, tombstonedAtMs: Long, ageMs: Long)`.
  - `data class PurgeResultInfo(blockUuid: ByteArray, wasShared: Boolean?, recipientCount: Int?, filesRemoved: Int)`.
  - `data class EmptyTrashReportInfo(purgedCount: Int, sharedCount: Int, ownerOnlyCount: Int, unknownCount: Int, filesRemoved: Int, filesFailed: Int)`.
  - `data class RetentionReportInfo(purgedCount: Int, sharedCount: Int, ownerOnlyCount: Int, unknownCount: Int, filesRemoved: Int, filesFailed: Int, windowMs: Long)`.
  - `interface TrashPort` (7 methods — see code).
  - Free funcs: `msToDays(Long): Long`, `sortTrashed(List<TrashedBlockInfo>): List<TrashedBlockInfo>`, `formatTrashedWhen(Long): String`, `emptyTrashConfirmBody(Int): String`, `retentionSummary(List<ExpiredEntryInfo>, Long): String`. Const `MS_PER_DAY: Long`.

- [ ] **Step 1: Write `TrashModels.kt`** (value types + port; no logic to unit-test directly — exercised via later tasks)

```kotlin
package org.secretary.browse

/**
 * Read-only metadata for one trashed block. No secret material — the block name is plaintext in the
 * manifest; record content never leaves the core. Kotlin mirror of iOS `TrashedBlockInfo`.
 */
data class TrashedBlockInfo(
    val blockUuid: ByteArray,
    val blockName: String,
    val tombstonedAtMs: Long,
    val tombstonedBy: ByteArray,
) {
    /** Lowercase hex, no dashes — stable Compose list `key`. */
    val uuidHex: String get() = hexOfBytes(blockUuid)

    override fun equals(other: Any?): Boolean =
        other is TrashedBlockInfo &&
            blockUuid.contentEquals(other.blockUuid) &&
            blockName == other.blockName &&
            tombstonedAtMs == other.tombstonedAtMs &&
            tombstonedBy.contentEquals(other.tombstonedBy)

    override fun hashCode(): Int {
        var h = blockUuid.contentHashCode()
        h = 31 * h + blockName.hashCode()
        h = 31 * h + tombstonedAtMs.hashCode()
        h = 31 * h + tombstonedBy.contentHashCode()
        return h
    }
}

/** One trash entry eligible for retention auto-purge (preview only). Mirror of iOS `ExpiredEntryInfo`. */
data class ExpiredEntryInfo(
    val blockUuid: ByteArray,
    val tombstonedAtMs: Long,
    val ageMs: Long,
) {
    override fun equals(other: Any?): Boolean =
        other is ExpiredEntryInfo &&
            blockUuid.contentEquals(other.blockUuid) &&
            tombstonedAtMs == other.tombstonedAtMs &&
            ageMs == other.ageMs

    override fun hashCode(): Int {
        var h = blockUuid.contentHashCode()
        h = 31 * h + tombstonedAtMs.hashCode()
        h = 31 * h + ageMs.hashCode()
        return h
    }
}

/** Outcome of a single-block purge. Counts/classification only. Mirror of iOS `PurgeResultInfo`. */
data class PurgeResultInfo(
    val blockUuid: ByteArray,
    val wasShared: Boolean?,
    val recipientCount: Int?,
    val filesRemoved: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is PurgeResultInfo &&
            blockUuid.contentEquals(other.blockUuid) &&
            wasShared == other.wasShared &&
            recipientCount == other.recipientCount &&
            filesRemoved == other.filesRemoved

    override fun hashCode(): Int {
        var h = blockUuid.contentHashCode()
        h = 31 * h + (wasShared?.hashCode() ?: 0)
        h = 31 * h + (recipientCount ?: 0)
        h = 31 * h + filesRemoved
        return h
    }
}

/** Aggregate outcome of an empty-trash batch. Counts only. Mirror of iOS `EmptyTrashReportInfo`. */
data class EmptyTrashReportInfo(
    val purgedCount: Int,
    val sharedCount: Int,
    val ownerOnlyCount: Int,
    val unknownCount: Int,
    val filesRemoved: Int,
    val filesFailed: Int,
)

/** Aggregate outcome of a retention auto-purge commit. Counts + echoed window. Mirror of iOS `RetentionReportInfo`. */
data class RetentionReportInfo(
    val purgedCount: Int,
    val sharedCount: Int,
    val ownerOnlyCount: Int,
    val unknownCount: Int,
    val filesRemoved: Int,
    val filesFailed: Int,
    val windowMs: Long,
)

/**
 * The vault-trash operations a Trash browser needs. Conformed by the `:kit` adapter
 * ([org.secretary.browse.UniffiVaultSession]) and by `FakeTrashPort` in tests. Kotlin mirror of the
 * iOS `TrashPort` protocol. Reports are returned (plumbed for #411) but the VM discards them.
 *
 * Reads ([listTrashedBlocks]/[expiredTrashEntries]/[defaultRetentionWindowMs]) are synchronous
 * in-memory manifest reads (no decryption). Writes are `suspend` — the real adapter offloads the
 * FFI write to the IO dispatcher, like [VaultSession.tombstoneRecord].
 */
interface TrashPort {
    /** All not-yet-purged trashed blocks, projected by name. */
    fun listTrashedBlocks(): List<TrashedBlockInfo>

    /** Retention preview for [windowMs] (adapter supplies `now`). Non-throwing (empty on wiped). */
    fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo>

    /** The frozen default retention window (90 days, in ms). */
    fun defaultRetentionWindowMs(): Long

    /** Restore the newest trashed copy of a block. */
    suspend fun restoreBlock(uuid: ByteArray)

    /** Permanently purge one trashed block. */
    suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo

    /** Permanently purge every currently-trashed block. */
    suspend fun emptyTrash(): EmptyTrashReportInfo

    /** Permanently purge every trashed block older than [windowMs]. */
    suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo
}
```

- [ ] **Step 2: Write the failing test** `TrashFormattingTest.kt`

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class TrashFormattingTest {
    private fun block(name: String, ms: Long) =
        TrashedBlockInfo(ByteArray(16), name, ms, ByteArray(16))

    @Test
    fun `msToDays rounds half up`() {
        assertEquals(0L, msToDays(0L))
        assertEquals(1L, msToDays(MS_PER_DAY))
        // 90 days exactly
        assertEquals(90L, msToDays(90L * MS_PER_DAY))
        // 1.5 days rounds to 2 (half-up)
        assertEquals(2L, msToDays(MS_PER_DAY + MS_PER_DAY / 2))
        // just under half a day rounds to 0
        assertEquals(0L, msToDays(MS_PER_DAY / 2 - 1))
    }

    @Test
    fun `sortTrashed orders newest first`() {
        val a = block("a", 100L)
        val b = block("b", 300L)
        val c = block("c", 200L)
        assertEquals(listOf("b", "c", "a"), sortTrashed(listOf(a, b, c)).map { it.blockName })
    }

    @Test
    fun `formatTrashedWhen renders UTC yyyy-MM-dd`() {
        // 2021-01-01T00:00:00Z = 1_609_459_200_000 ms
        assertEquals("2021-01-01", formatTrashedWhen(1_609_459_200_000L))
        // 2026-07-11T12:00:00Z
        assertEquals("2026-07-11", formatTrashedWhen(1_784_030_400_000L))
    }

    @Test
    fun `emptyTrashConfirmBody singular vs plural`() {
        assertEquals(
            "The 1 item in trash will be permanently deleted. This cannot be undone.",
            emptyTrashConfirmBody(1),
        )
        assertEquals(
            "All 3 items in trash will be permanently deleted. This cannot be undone.",
            emptyTrashConfirmBody(3),
        )
    }

    @Test
    fun `retentionSummary empty and populated`() {
        val window = 90L * MS_PER_DAY
        assertEquals(
            "No trashed items are older than 90 days.",
            retentionSummary(emptyList(), window),
        )
        val entries = listOf(
            ExpiredEntryInfo(ByteArray(16), 0L, 100L * MS_PER_DAY),
            ExpiredEntryInfo(ByteArray(16), 0L, 95L * MS_PER_DAY),
        )
        assertEquals(
            "2 items trashed more than 90 days ago will be permanently deleted (oldest: 100 days).",
            retentionSummary(entries, window),
        )
        val one = listOf(ExpiredEntryInfo(ByteArray(16), 0L, 91L * MS_PER_DAY))
        assertEquals(
            "1 item trashed more than 90 days ago will be permanently deleted (oldest: 91 days).",
            retentionSummary(one, window),
        )
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.TrashFormattingTest'`
Expected: FAIL — unresolved references `msToDays`, `sortTrashed`, `formatTrashedWhen`, `emptyTrashConfirmBody`, `retentionSummary`, `MS_PER_DAY`.

- [ ] **Step 4: Write `TrashFormatting.kt`**

```kotlin
package org.secretary.browse

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** Milliseconds per day — the days↔ms conversion base. */
const val MS_PER_DAY: Long = 86_400_000L

/**
 * Whole days in [ms], rounded to nearest — parity with desktop `Math.round(ms / MS_PER_DAY)` and iOS
 * `msToDays`. Integer round-half-up; cannot overflow for realistic ms values.
 */
fun msToDays(ms: Long): Long = (ms + MS_PER_DAY / 2) / MS_PER_DAY

/** Trashed blocks newest-first by tombstone time (parity: desktop/iOS `sortTrashed`). */
fun sortTrashed(entries: List<TrashedBlockInfo>): List<TrashedBlockInfo> =
    entries.sortedByDescending { it.tombstonedAtMs }

/** Fixed UTC `yyyy-MM-dd` formatter (thread-safe; immutable). */
private val TRASHED_WHEN_FORMAT: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC)

/**
 * Absolute `yyyy-MM-dd` (UTC) of a tombstone timestamp. Deliberately deterministic (fixed pattern +
 * UTC) rather than desktop's locale-aware short-date, so this pure helper is host-testable without a
 * fixed clock/zone. Trade-off: the displayed calendar day is UTC, so a block trashed within a few
 * hours of local midnight can render the adjacent day. Locale-aware parity with desktop is tracked
 * in #413. Mirror of iOS `formatTrashedWhen`.
 */
fun formatTrashedWhen(ms: Long): String = TRASHED_WHEN_FORMAT.format(Instant.ofEpochMilli(ms))

/** Empty-trash confirm body (parity: desktop/iOS `emptyTrashConfirmBody`). */
fun emptyTrashConfirmBody(count: Int): String {
    val lead = if (count == 1) "The 1 item" else "All $count items"
    return "$lead in trash will be permanently deleted. This cannot be undone."
}

/** Retention summary (parity: desktop/iOS `retentionSummary`). */
fun retentionSummary(entries: List<ExpiredEntryInfo>, windowMs: Long): String {
    val days = msToDays(windowMs)
    if (entries.isEmpty()) return "No trashed items are older than $days days."
    val n = entries.size
    val oldestDays = msToDays(entries.maxOf { it.ageMs })
    val noun = if (n == 1) "item" else "items"
    return "$n $noun trashed more than $days days ago will be permanently deleted (oldest: $oldestDays days)."
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.TrashFormattingTest'`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/TrashModels.kt \
        android/vault-access/src/main/kotlin/org/secretary/browse/TrashFormatting.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/TrashFormattingTest.kt
git commit -m "feat(android): trash value types + TrashPort + formatting helpers (host-tested)"
```

---

### Task 2: `TrashBrowseModel` + `FakeTrashPort` (`:vault-access`)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/TrashBrowseModel.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeTrashPort.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/TrashBrowseModelTest.kt`

**Interfaces:**
- Consumes: `TrashPort`, `TrashedBlockInfo`, `ExpiredEntryInfo`, report DTOs (Task 1); `WriteReauthGate`/`NoopReauthGate`/`DeviceUnlockError`/`reauthFailedMessage` (existing); `VaultBrowseError` (existing); `sortTrashed` (Task 1).
- Produces: `class TrashBrowseModel(port: TrashPort, gate: WriteReauthGate = NoopReauthGate)` exposing `StateFlow`s `entries`/`error`/`writing`/`preview`, `val retentionWindowMs: Long`, `fun load()`, `fun previewRetention()`, `fun clearPreview()`, and `suspend` `restore(ByteArray)`/`purge(ByteArray)`/`emptyTrash()`/`runRetention()`. Reuses the existing test double idiom `RecordingReauthGate` (defined in `VaultBrowseModelReauthTest.kt`) — but Task 2's tests define their own `FakeTrashPort`; use a local `RecordingReauthGate` copy if the existing one is not visible across test files (it is same-package `:vault-access/src/test`, so it is visible).

- [ ] **Step 1: Write the failing test** `TrashBrowseModelTest.kt`

```kotlin
package org.secretary.browse

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class TrashBrowseModelTest {
    private fun tb(name: String, ms: Long, uuid: Byte) =
        TrashedBlockInfo(ByteArray(16) { uuid }, name, ms, ByteArray(16))

    @Test
    fun `load sorts entries newest-first`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 100L, 1), tb("b", 300L, 2), tb("c", 200L, 3)))
        val model = TrashBrowseModel(port)
        model.load()
        assertEquals(listOf("b", "c", "a"), model.entries.value.map { it.blockName })
        assertNull(model.error.value)
    }

    @Test
    fun `load surfaces a typed error and leaves entries empty`() = runTest {
        val port = FakeTrashPort(listError = VaultBrowseError.CorruptVault("boom"))
        val model = TrashBrowseModel(port)
        model.load()
        assertEquals(VaultBrowseError.CorruptVault("boom"), model.error.value)
        assertTrue(model.entries.value.isEmpty())
    }

    @Test
    fun `restore authorizes with the restore reason then reloads`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 1L, 1)))
        val gate = RecordingReauthGate()
        val model = TrashBrowseModel(port, gate)
        model.load()
        // After the write the fake returns an empty list (block gone).
        port.list = emptyList()
        model.restore(ByteArray(16) { 1 })
        assertEquals(listOf("Confirm restoring this block"), gate.reasons)
        assertEquals(1, port.restored.size)
        assertTrue(model.entries.value.isEmpty())   // reloaded
        assertFalse(model.writing.value)
    }

    @Test
    fun `purge on user-cancel is silent - no write, no error, list intact`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 1L, 1)))
        val gate = RecordingReauthGate(error = DeviceUnlockError.UserCancelled)
        val model = TrashBrowseModel(port, gate)
        model.load()
        model.purge(ByteArray(16) { 1 })
        assertEquals(0, port.purged.size)
        assertNull(model.error.value)                 // silent
        assertEquals(1, model.entries.value.size)     // list untouched
    }

    @Test
    fun `purge on reauth failure surfaces ReauthFailed and skips the write`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 1L, 1)))
        val gate = RecordingReauthGate(error = DeviceUnlockError.AuthenticationFailed)
        val model = TrashBrowseModel(port, gate)
        model.load()
        model.purge(ByteArray(16) { 1 })
        assertEquals(0, port.purged.size)
        assertTrue(model.error.value is VaultBrowseError.ReauthFailed)
        assertEquals(1, model.entries.value.size)
    }

    @Test
    fun `emptyTrash reloads to an empty list on success`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 1L, 1), tb("b", 2L, 2)))
        val model = TrashBrowseModel(port)
        model.load()
        port.list = emptyList()
        model.emptyTrash()
        assertEquals(1, port.emptied)
        assertTrue(model.entries.value.isEmpty())
    }

    @Test
    fun `previewRetention is ungated and clearPreview resets it`() = runTest {
        val port = FakeTrashPort(
            expired = listOf(ExpiredEntryInfo(ByteArray(16), 0L, 100L * MS_PER_DAY)),
        )
        val gate = RecordingReauthGate()
        val model = TrashBrowseModel(port, gate)
        model.previewRetention()
        assertEquals(1, model.preview.value?.size)
        assertTrue(gate.reasons.isEmpty())            // ungated read
        model.clearPreview()
        assertNull(model.preview.value)
    }

    @Test
    fun `runRetention authorizes with the retention reason and reloads`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 1L, 1)))
        val gate = RecordingReauthGate()
        val model = TrashBrowseModel(port, gate)
        model.load()
        port.list = emptyList()
        model.runRetention()
        assertEquals(listOf("Confirm permanently deleting expired trash"), gate.reasons)
        assertEquals(1, port.autoPurged.size)
        assertTrue(model.entries.value.isEmpty())
    }
}
```

- [ ] **Step 2: Write `FakeTrashPort.kt`** (test source)

```kotlin
package org.secretary.browse

/**
 * In-memory [TrashPort] test double. Seed [list]/[expired]/reports; prime [listError] to make
 * [listTrashedBlocks] throw. Records each write for assertions. Mirror of iOS `FakeTrashPort`.
 */
class FakeTrashPort(
    var list: List<TrashedBlockInfo> = emptyList(),
    var expired: List<ExpiredEntryInfo> = emptyList(),
    private val listError: VaultBrowseError? = null,
    private val windowMs: Long = 90L * MS_PER_DAY,
) : TrashPort {
    val restored = mutableListOf<ByteArray>()
    val purged = mutableListOf<ByteArray>()
    var emptied = 0
    val autoPurged = mutableListOf<Long>()

    override fun listTrashedBlocks(): List<TrashedBlockInfo> {
        listError?.let { throw it }
        return list
    }

    override fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo> = expired

    override fun defaultRetentionWindowMs(): Long = windowMs

    override suspend fun restoreBlock(uuid: ByteArray) { restored += uuid }

    override suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo {
        purged += uuid
        return PurgeResultInfo(uuid, wasShared = false, recipientCount = 0, filesRemoved = 1)
    }

    override suspend fun emptyTrash(): EmptyTrashReportInfo {
        emptied += 1
        return EmptyTrashReportInfo(list.size, 0, list.size, 0, list.size, 0)
    }

    override suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo {
        autoPurged += windowMs
        return RetentionReportInfo(expired.size, 0, expired.size, 0, expired.size, 0, windowMs)
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.TrashBrowseModelTest'`
Expected: FAIL — unresolved reference `TrashBrowseModel`.

- [ ] **Step 4: Write `TrashBrowseModel.kt`**

```kotlin
package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Host-tested Trash browser model — Kotlin mirror of iOS `TrashViewModel`, following the
 * [VaultBrowseModel.guardedWrite] discipline: [_writing] is set BEFORE the gate await; a
 * `UserCancelled` re-auth aborts silently (no write, no error, list intact); a typed op failure
 * surfaces via [error] and skips the reload. Destructive-op reports are DISCARDED — the reloaded
 * list is the success signal (parity with iOS/desktop; #411 surfaces counts later).
 *
 * Main-thread-confined like [VaultBrowseModel] (the injected [WriteReauthGate] is not thread-safe).
 * Writes are `suspend` because the real [TrashPort] offloads the FFI write to IO.
 */
class TrashBrowseModel(
    private val port: TrashPort,
    private val gate: WriteReauthGate = NoopReauthGate,
) {
    private val _entries = MutableStateFlow<List<TrashedBlockInfo>>(emptyList())
    val entries: StateFlow<List<TrashedBlockInfo>> = _entries.asStateFlow()

    private val _error = MutableStateFlow<VaultBrowseError?>(null)
    val error: StateFlow<VaultBrowseError?> = _error.asStateFlow()

    private val _writing = MutableStateFlow(false)
    /** True while a destructive write is in flight — disables all trash write buttons. */
    val writing: StateFlow<Boolean> = _writing.asStateFlow()

    private val _preview = MutableStateFlow<List<ExpiredEntryInfo>?>(null)
    /** Populated by [previewRetention]; drives the retention sheet summary. Null = not yet previewed. */
    val preview: StateFlow<List<ExpiredEntryInfo>?> = _preview.asStateFlow()

    /** The frozen 90-day default retention window (no per-vault setting yet). */
    val retentionWindowMs: Long get() = port.defaultRetentionWindowMs()

    /** List trashed blocks (newest-first). A typed failure surfaces via [error]; entries cleared. */
    fun load() {
        _error.value = null
        try {
            _entries.value = sortTrashed(port.listTrashedBlocks())
        } catch (e: VaultBrowseError) {
            _error.value = e
            _entries.value = emptyList()
        }
    }

    /** Ungated retention preview against the fixed default window. */
    fun previewRetention() {
        _preview.value = port.expiredTrashEntries(port.defaultRetentionWindowMs())
    }

    /** Drop the cached preview so a reopened retention sheet shows its loading state (no stale flash). */
    fun clearPreview() {
        _preview.value = null
    }

    suspend fun restore(uuid: ByteArray) =
        guardedWrite("Confirm restoring this block") { port.restoreBlock(uuid) }

    suspend fun purge(uuid: ByteArray) =
        guardedWrite("Confirm permanently deleting this block") { port.purgeBlock(uuid) }

    suspend fun emptyTrash() =
        guardedWrite("Confirm permanently deleting all trashed blocks") { port.emptyTrash() }

    suspend fun runRetention() {
        val window = port.defaultRetentionWindowMs()
        guardedWrite("Confirm permanently deleting expired trash") { port.autoPurgeExpired(window) }
    }

    /**
     * Re-auth, run a guarded destructive op, then reload on success. [_writing] set before the gate
     * await so a second action during the prompt is rejected. Mirror of [VaultBrowseModel.guardedWrite]:
     * `UserCancelled` → silent; other `DeviceUnlockError` → [error]; op failure → [error], no reload.
     * The op's return value (report DTO) is discarded.
     */
    private suspend fun guardedWrite(reason: String, op: suspend () -> Unit) {
        if (_writing.value) return
        _writing.value = true
        try {
            // CancellationException is NOT caught here — it propagates past these DeviceUnlockError
            // catches so coroutine cancellation is never swallowed. Do NOT widen to catch (Exception).
            try {
                gate.authorizeWrite(reason)
            } catch (e: DeviceUnlockError.UserCancelled) {
                return // silent: no write, no error
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(reauthFailedMessage(e))
                return
            }
            try {
                op()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }
            load()
        } finally {
            _writing.value = false
        }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.TrashBrowseModelTest'`
Expected: PASS (8 tests).

- [ ] **Step 6: Run the whole `:vault-access` suite (no regressions)**

Run: `cd android && ./gradlew :vault-access:test`
Expected: BUILD SUCCESSFUL, all tests pass.

- [ ] **Step 7: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/TrashBrowseModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/FakeTrashPort.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/TrashBrowseModelTest.kt
git commit -m "feat(android): TrashBrowseModel with gate parity + report-discard (host-tested)"
```

---

### Task 3: `:kit` — real `TrashPort` adapter + error mapping

**Files:**
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt` (add `TrashPort` to `UniffiVaultSession`; add trash imports)
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt:42` (two arms above `else`)
- Test: `android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTrashTest.kt` (new)

**Interfaces:**
- Consumes: `TrashPort` + value types (Task 1); the session's existing `private` `identity`/`manifest`/`sessionLock`/`wiped`/`write`/`mapErrors`; generated `uniffi.secretary.{listTrashedBlocks,expiredTrashEntries,defaultRetentionWindowMs,restoreBlock,purgeBlock,emptyTrash,autoPurgeExpired}` and DTOs `TrashedBlock`/`ExpiredEntry`/`PurgeReport`/`EmptyTrashReport`/`RetentionPurgeReport`; `VaultException.{BlockNotInTrash,BlockPurged}`.
- Produces: `UniffiVaultSession : VaultSession, TrashPort` (the production adapter). `mapVaultBrowseError` now maps the two trash-gone variants to `BlockNotFound`.

> **Generated-name check (do FIRST):** confirm the exact camelCased binding names + DTO field names before writing the overrides:
> `grep -rn 'fun listTrashedBlocks\|fun expiredTrashEntries\|fun purgeBlock\|fun emptyTrash\|fun autoPurgeExpired\|fun restoreBlock\|fun defaultRetentionWindowMs\|data class TrashedBlock\|data class ExpiredEntry\|data class PurgeReport\|data class EmptyTrashReport\|data class RetentionPurgeReport' android/kit/build ffi/secretary-ffi-uniffi 2>/dev/null | head -40`
> Expected (per the UDL): fns as named above; `TrashedBlock(blockUuid, blockName, tombstonedAtMs: ULong, tombstonedBy)`, `ExpiredEntry(blockUuid, tombstonedAtMs: ULong, ageMs: ULong)`, `PurgeReport(blockUuid, wasShared: Boolean?, recipientCount: UShort?, filesRemoved: UInt)`, `EmptyTrashReport(purgedCount, sharedCount, ownerOnlyCount, unknownCount, filesRemoved, filesFailed: UInt)`, `RetentionPurgeReport(...same six... , windowMs: ULong)`. If any field name differs, adjust the mapping accordingly.

- [ ] **Step 1: Write the failing test** `BrowseMappingTrashTest.kt` (the mapping arms are pure and JVM-testable — `VaultException` is on the test classpath)

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.VaultException

class BrowseMappingTrashTest {
    @Test
    fun `BlockNotInTrash maps to BlockNotFound`() {
        val mapped = mapVaultBrowseError(VaultException.BlockNotInTrash("no entry"))
        assertTrue(mapped is VaultBrowseError.BlockNotFound)
    }

    @Test
    fun `BlockPurged maps to BlockNotFound`() {
        val mapped = mapVaultBrowseError(VaultException.BlockPurged("already purged"))
        assertTrue(mapped is VaultBrowseError.BlockNotFound)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :kit:testDebugUnitTest --tests 'org.secretary.browse.BrowseMappingTrashTest'`
Expected: FAIL — both map to `VaultBrowseError.Failed` (the current `else` fold), not `BlockNotFound`.

> If the test instead fails to compile with "unresolved reference: BlockNotInTrash", the generated bindings jar is stale — rebuild it first: `./gradlew :kit:compileDebugKotlin` (or the module's binding-generation task). The UDL has both variants (lines 467-468), so they exist on the surface.

- [ ] **Step 3: Add the two mapping arms** to `BrowseMapping.kt`, immediately above `else -> VaultBrowseError.Failed(e.toString())`:

```kotlin
    // Trash ops: no live/trashed block for this UUID (already restored, purged, or never trashed).
    // Fold both to the existing BlockNotFound surface — no new VaultBrowseError variant (parity with
    // iOS mapping BlockNotInTrash/BlockPurged -> .blockNotFound). e.detail is a free-text identifier.
    is VaultException.BlockNotInTrash -> VaultBrowseError.BlockNotFound(e.detail)
    is VaultException.BlockPurged -> VaultBrowseError.BlockNotFound(e.detail)
```

- [ ] **Step 4: Run the mapping test to verify it passes**

Run: `cd android && ./gradlew :kit:testDebugUnitTest --tests 'org.secretary.browse.BrowseMappingTrashTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Add the trash imports** to `UniffiVaultOpenPort.kt` (with the other `uniffi.secretary.*` imports near the top):

```kotlin
import uniffi.secretary.listTrashedBlocks as ffiListTrashedBlocks
import uniffi.secretary.expiredTrashEntries as ffiExpiredTrashEntries
import uniffi.secretary.defaultRetentionWindowMs as ffiDefaultRetentionWindowMs
import uniffi.secretary.restoreBlock as ffiRestoreBlock
import uniffi.secretary.purgeBlock as ffiPurgeBlock
import uniffi.secretary.emptyTrash as ffiEmptyTrash
import uniffi.secretary.autoPurgeExpired as ffiAutoPurgeExpired
```

- [ ] **Step 6: Conform `UniffiVaultSession` to `TrashPort`.** Change the class declaration:

```kotlin
class UniffiVaultSession(
    output: OpenVaultOutput,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val deviceUuids: DeviceUuidProvider? = null,
) : VaultSession, TrashPort {
```

Then add the 7 overrides inside the class body, just before `override fun wipe()`. They reuse the
existing `private` machinery (`sessionLock`, `wiped`, `write`, `mapErrors`, `identity`, `manifest`) —
**no member is widened to `internal`** (Kotlin needs interface overrides in the class body; that is
exactly where these live). Every trash op reuses the existing `write`/read-guard, adding no new
handle-access pattern (the lock-discipline invariant holds verbatim):

```kotlin
    // ---- TrashPort (no record plaintext crosses here — only names + counts; never a decrypt call) ----
    // These reuse the same sessionLock + `wiped` guard and `write` device-uuid/now resolution as every
    // other session op, so they add no new handle-access pattern. Reports are returned for #411 but
    // the pure TrashBrowseModel discards them.

    override fun listTrashedBlocks(): List<TrashedBlockInfo> =
        synchronized(sessionLock) {
            if (wiped) emptyList()
            else mapErrors {
                ffiListTrashedBlocks(identity, manifest).map { b ->
                    TrashedBlockInfo(
                        blockUuid = b.blockUuid,
                        blockName = b.blockName,
                        tombstonedAtMs = b.tombstonedAtMs.toLong(),
                        tombstonedBy = b.tombstonedBy,
                    )
                }
            }
        }

    override fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo> =
        synchronized(sessionLock) {
            if (wiped) emptyList()
            else mapErrors {
                ffiExpiredTrashEntries(manifest, windowMs.toULong(), System.currentTimeMillis().toULong())
                    .map { e ->
                        ExpiredEntryInfo(
                            blockUuid = e.blockUuid,
                            tombstonedAtMs = e.tombstonedAtMs.toLong(),
                            ageMs = e.ageMs.toLong(),
                        )
                    }
            }
        }

    override fun defaultRetentionWindowMs(): Long = ffiDefaultRetentionWindowMs().toLong()

    override suspend fun restoreBlock(uuid: ByteArray) =
        write { dev, now -> ffiRestoreBlock(identity, manifest, uuid, dev, now) }

    override suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo =
        write { dev, now ->
            val r = ffiPurgeBlock(identity, manifest, uuid, dev, now)
            PurgeResultInfo(
                blockUuid = r.blockUuid,
                wasShared = r.wasShared,
                recipientCount = r.recipientCount?.toInt(),
                filesRemoved = r.filesRemoved.toInt(),
            )
        }

    override suspend fun emptyTrash(): EmptyTrashReportInfo =
        write { dev, now ->
            val r = ffiEmptyTrash(identity, manifest, dev, now)
            EmptyTrashReportInfo(
                purgedCount = r.purgedCount.toInt(),
                sharedCount = r.sharedCount.toInt(),
                ownerOnlyCount = r.ownerOnlyCount.toInt(),
                unknownCount = r.unknownCount.toInt(),
                filesRemoved = r.filesRemoved.toInt(),
                filesFailed = r.filesFailed.toInt(),
            )
        }

    override suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo =
        write { dev, now ->
            val r = ffiAutoPurgeExpired(identity, manifest, windowMs.toULong(), now, dev)
            RetentionReportInfo(
                purgedCount = r.purgedCount.toInt(),
                sharedCount = r.sharedCount.toInt(),
                ownerOnlyCount = r.ownerOnlyCount.toInt(),
                unknownCount = r.unknownCount.toInt(),
                filesRemoved = r.filesRemoved.toInt(),
                filesFailed = r.filesFailed.toInt(),
                windowMs = r.windowMs.toLong(),
            )
        }
```

> **Note on `write`'s signature:** `private suspend fun <T> write(body: (deviceUuid: ByteArray, nowMs: ULong) -> T): T`. The `now` it hands the body is already a `ULong` — so `ffiRestoreBlock(..., dev, now)` passes `now: ULong` directly (matches the generated `nowMs: ULong` param). `autoPurgeExpired`'s generated param order is `(identity, manifest, windowMs, nowMs, deviceUuid)` — device UUID LAST (verify against the generated signature; the UDL confirms it).

- [ ] **Step 7: Compile `:kit` and run its unit tests**

Run: `cd android && ./gradlew :kit:testDebugUnitTest`
Expected: BUILD SUCCESSFUL — `:kit` compiles with the new conformance; `BrowseMappingTrashTest` + all existing tests pass.

- [ ] **Step 8: Commit**

```bash
git add android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt \
        android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt \
        android/kit/src/test/kotlin/org/secretary/browse/BrowseMappingTrashTest.kt
git commit -m "feat(android): real TrashPort adapter on UniffiVaultSession + trash-gone error mapping"
```

---

### Task 4: `:browse-ui` — Compose `TrashBrowseViewModel` bridge + `TrashScreen`

**Files:**
- Create: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashBrowseViewModel.kt`
- Create: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashScreen.kt`

**Interfaces:**
- Consumes: `TrashBrowseModel` + value types + formatting helpers (Tasks 1-2); Compose material3.
- Produces:
  - `class TrashBrowseViewModel(model: TrashBrowseModel) : ViewModel` exposing `entries`/`error`/`writing`/`preview` `StateFlow`s + `val retentionWindowMs: Long`, `fun load()`, `fun previewRetention()`, `fun clearPreview()`, and `fun restore(ByteArray)`/`purge(ByteArray)`/`emptyTrash()`/`runRetention()` (each `launch`ed on `viewModelScope`).
  - `@Composable fun TrashScreen(viewModel: TrashBrowseViewModel, onBack: () -> Unit)`.

> This task has no host unit test (Compose UI + a `ViewModel` bridge that only re-exposes flows and
> launches coroutines — matching the untested `VaultBrowseViewModel` bridge). Its gate is
> compilation. An optional `:browse-ui` instrumented test over a `FakeTrashPort`-backed model is a
> nice-to-have, deferred (the load-bearing coverage is Task 2's host tests).

- [ ] **Step 1: Write `TrashBrowseViewModel.kt`**

```kotlin
package org.secretary.browse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.secretary.browse.ExpiredEntryInfo
import org.secretary.browse.TrashBrowseModel
import org.secretary.browse.TrashedBlockInfo
import org.secretary.browse.VaultBrowseError

/**
 * Thin Compose bridge over the host-tested [TrashBrowseModel]. Holds NO trash logic — it re-exposes
 * the model's StateFlows for `collectAsStateWithLifecycle` and launches the model's suspend writes on
 * [viewModelScope]. Mirror of [VaultBrowseViewModel]; the injected [model] wraps `:kit`'s real
 * session in production and a fake in tests; this class never touches the FFI.
 */
class TrashBrowseViewModel(private val model: TrashBrowseModel) : ViewModel() {
    val entries: StateFlow<List<TrashedBlockInfo>> = model.entries
    val error: StateFlow<VaultBrowseError?> = model.error
    val writing: StateFlow<Boolean> = model.writing
    val preview: StateFlow<List<ExpiredEntryInfo>?> = model.preview

    val retentionWindowMs: Long get() = model.retentionWindowMs

    /** Load the trashed-block list (synchronous in-memory read). */
    fun load() = model.load()

    /** Ungated retention preview. */
    fun previewRetention() = model.previewRetention()

    /** Drop the cached preview (on sheet dismiss). */
    fun clearPreview() = model.clearPreview()

    fun restore(uuid: ByteArray) { viewModelScope.launch { model.restore(uuid) } }
    fun purge(uuid: ByteArray) { viewModelScope.launch { model.purge(uuid) } }
    fun emptyTrash() { viewModelScope.launch { model.emptyTrash() } }
    fun runRetention() { viewModelScope.launch { model.runRetention() } }
}
```

- [ ] **Step 2: Write `TrashScreen.kt`** (material3; icon buttons per row, `AlertDialog` confirms, `ModalBottomSheet` retention preview)

```kotlin
package org.secretary.browse.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.browse.TrashedBlockInfo
import org.secretary.browse.emptyTrashConfirmBody
import org.secretary.browse.formatTrashedWhen
import org.secretary.browse.retentionSummary

/**
 * The Android Trash browser — mirror of iOS `TrashScreen`. Lists trashed blocks newest-first; each
 * row has Restore + Delete-forever icon buttons (delete confirmed via [AlertDialog]). The top bar
 * carries Empty-trash (only when non-empty) and Run-retention-now (a [ModalBottomSheet] previewing
 * the expired set against the fixed 90-day default). All destructive ops route through the model's
 * write-reauth gate; the retention preview is an ungated read.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrashScreen(viewModel: TrashBrowseViewModel, onBack: () -> Unit) {
    val entries by viewModel.entries.collectAsStateWithLifecycle()
    val writing by viewModel.writing.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val preview by viewModel.preview.collectAsStateWithLifecycle()

    var confirmDelete by remember { mutableStateOf<TrashedBlockInfo?>(null) }
    var confirmEmpty by remember { mutableStateOf(false) }
    var showRetention by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { viewModel.load() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Trash") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { showRetention = true },
                        enabled = !writing,
                        modifier = Modifier.testTag("run-retention"),
                    ) { Icon(Icons.Filled.Refresh, contentDescription = "Run retention now") }
                    if (entries.isNotEmpty()) {
                        TextButton(
                            onClick = { confirmEmpty = true },
                            enabled = !writing,
                            modifier = Modifier.testTag("empty-trash"),
                        ) { Text("Empty") }
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            error?.let {
                Text(
                    it.toString(),
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(16.dp).testTag("trash-error"),
                )
            }
            if (entries.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Trash is empty", style = MaterialTheme.typography.bodyLarge)
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(entries, key = { it.uuidHex }) { block ->
                        TrashRow(
                            block = block,
                            enabled = !writing,
                            onRestore = { viewModel.restore(block.blockUuid) },
                            onDelete = { confirmDelete = block },
                        )
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    confirmDelete?.let { block ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Delete forever?") },
            text = { Text("\"${block.blockName}\" will be permanently deleted. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.purge(block.blockUuid); confirmDelete = null
                }) { Text("Delete forever") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel") } },
        )
    }

    if (confirmEmpty) {
        AlertDialog(
            onDismissRequest = { confirmEmpty = false },
            title = { Text("Empty trash?") },
            text = { Text(emptyTrashConfirmBody(entries.size)) },
            confirmButton = {
                TextButton(onClick = { viewModel.emptyTrash(); confirmEmpty = false }) { Text("Empty trash") }
            },
            dismissButton = { TextButton(onClick = { confirmEmpty = false }) { Text("Cancel") } },
        )
    }

    if (showRetention) {
        ModalBottomSheet(
            onDismissRequest = { showRetention = false; viewModel.clearPreview() },
        ) {
            LaunchedEffect(Unit) { viewModel.previewRetention() }
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text("Run retention now", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (preview == null) "Checking…"
                    else retentionSummary(preview!!, viewModel.retentionWindowMs),
                    modifier = Modifier.padding(vertical = 12.dp).testTag("retention-summary"),
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { showRetention = false; viewModel.clearPreview() }) { Text("Cancel") }
                    TextButton(
                        onClick = { viewModel.runRetention(); showRetention = false; viewModel.clearPreview() },
                        enabled = !writing && preview?.isNotEmpty() == true,
                    ) { Text("Purge expired") }
                }
            }
        }
    }
}

@Composable
private fun TrashRow(
    block: TrashedBlockInfo,
    enabled: Boolean,
    onRestore: () -> Unit,
    onDelete: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(block.blockName, style = MaterialTheme.typography.bodyLarge)
            Text(
                "trashed ${formatTrashedWhen(block.tombstonedAtMs)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(onClick = onRestore, enabled = enabled) {
            Icon(Icons.Filled.Refresh, contentDescription = "Restore ${block.blockName}")
        }
        IconButton(onClick = onDelete, enabled = enabled) {
            Icon(Icons.Filled.Delete, contentDescription = "Delete ${block.blockName} forever")
        }
    }
}
```

> **Icon note:** if `Icons.AutoMirrored.Filled.ArrowBack` is unavailable in the pinned Compose
> material-icons version, fall back to `Icons.Filled.ArrowBack` (check how `BrowseScreen.kt` /
> existing screens import their back icon and match that). Restore reuses `Icons.Filled.Refresh`;
> if a dedicated restore glyph is already used elsewhere in the app, match it.

- [ ] **Step 3: Compile `:browse-ui`**

Run: `cd android && ./gradlew :browse-ui:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashBrowseViewModel.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashScreen.kt
git commit -m "feat(android): Compose TrashScreen + TrashBrowseViewModel bridge"
```

---

### Task 5: `:app` — wire the Trash entry point

**Files:**
- Modify: the browse composition that assembles the browse top bar + navigation — `android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt` and/or `android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt` (inspect both to find where the browse `Scaffold`/`TopAppBar` and the open `UniffiVaultSession` + `GraceWindowReauthGate` are in scope).

**Interfaces:**
- Consumes: the open `UniffiVaultSession` (now a `TrashPort`), the browse `WriteReauthGate`, `TrashBrowseModel` (Task 2), `TrashBrowseViewModel` + `TrashScreen` (Task 4).
- Produces: a Trash affordance on the browse block-list surface that navigates to `TrashScreen`, backed by a `TrashBrowseViewModel(TrashBrowseModel(session, gate))`.

> **Investigate first** (the browse-with-sync composition wiring is app-specific): read
> `BrowseWithSyncScreen.kt` + `BrowseSession.kt` to learn (a) how the open session + gate are held,
> (b) how the app currently switches surfaces (nav state / a `when` over a screen enum / a boolean).
> Mirror that existing navigation idiom — do NOT introduce a nav library if the app hand-rolls screen
> state. The iOS reference builds the trash VM lazily at the navigation boundary
> (`makeTrashViewModel()`); do the same (construct `TrashBrowseModel` from the already-open session +
> gate — NO second FFI open).

- [ ] **Step 1: Add a Trash action to the browse top bar** (block-list surface only). Concrete shape depends on the existing composition; the addition is an `IconButton`/`TextButton` in the browse `TopAppBar` `actions` that flips a `showTrash` state, plus a branch that renders `TrashScreen` when `showTrash` is set:

```kotlin
// where the open session + gate are in scope (e.g. in BrowseWithSyncScreen):
var showTrash by rememberSaveable { mutableStateOf(false) }

if (showTrash) {
    // Build the trash VM from the already-open session (which now conforms to TrashPort) + the
    // same write-reauth gate the browse write path uses. No second FFI open.
    val trashVm = remember(session) { TrashBrowseViewModel(TrashBrowseModel(session, reauthGate)) }
    TrashScreen(viewModel = trashVm, onBack = { showTrash = false })
} else {
    // existing browse surface; add to its TopAppBar actions:
    //   IconButton(onClick = { showTrash = true }) {
    //       Icon(Icons.Filled.Delete, contentDescription = "Trash")
    //   }
}
```

> `session` here must be the concrete `UniffiVaultSession` (or the `VaultSession` reference the app
> holds, cast/known to also be a `TrashPort` in production). If the app holds it only as
> `VaultSession`, either (a) expose the `TrashPort` alongside it from the same open, or (b) smart-cast
> `(session as? TrashPort)` and guard. Prefer (a): thread the `TrashPort` from wherever the
> `UniffiVaultSession` is constructed (the open port), so no cast is needed. Match the app's existing
> dependency-passing style.

- [ ] **Step 2: Assemble the whole app (compiles + links every module)**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL. This is the load-bearing cross-module gate — it fails if the `:kit`
conformance, the `:browse-ui` screen, or the `:app` wiring disagree on any signature.

- [ ] **Step 3: Run the app's host unit tests (no regressions)**

Run: `cd android && ./gradlew :app:testDebugUnitTest :browse-ui:testDebugUnitTest`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/
git commit -m "feat(android): reach the Trash browser from the browse top bar"
```

---

### Task 6: Docs — README + ROADMAP

**Files:**
- Modify: `README.md` (Android status row — note the Trash browser shipped; retention-window setting still deferred)
- Modify: `ROADMAP.md` (mark the Android trash-browser slice done; keep the iOS retention-window-setting + Android settings screen as the deferred follow-up)

**Interfaces:** none (docs only).

- [ ] **Step 1: Read the current Android status** in `README.md` and `ROADMAP.md`

Run: `grep -n -i 'trash\|retention\|android' README.md ROADMAP.md | head -40`

- [ ] **Step 2: Update `README.md`** — in the Android section/status, add the Trash browser (list / restore / delete-forever / empty-trash / run-retention @ 90-day default, behind the biometric write gate), mirroring how the iOS Trash browser was noted for #412. Keep it brief (dot-point; no test-count walls — [[feedback_readme_style]]). Note the retention-window *setting* is still deferred (needs settings FFI + an Android Settings screen).

- [ ] **Step 3: Update `ROADMAP.md`** — mark the Android trash-browser slice shipped; record the deferred follow-ups (retention-window setting on both mobile platforms; #411 purge-count surfacing; #413 locale-aware date).

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: Android Trash browser shipped (retention-window setting deferred)"
```

---

## Self-Review

**Spec coverage:**
- List/restore/delete-forever/empty-trash/run-retention → Tasks 1 (types/format), 2 (model), 3 (adapter), 4 (screen). ✓
- No new FFI → Task 3 consumes existing bindings only. ✓
- No new `VaultBrowseError` → Task 3 maps to existing `BlockNotFound`. ✓
- Report discard → Task 2 `guardedWrite` discards the op return; DTOs still plumbed. ✓
- Gated writes / ungated preview → Task 2 (`guardedWrite` vs `previewRetention`), Task 4 (sheet). ✓
- No visibility widening (Kotlin in-class conformance) → Task 3 Step 6. ✓
- Entry from browse top bar → Task 5. ✓
- `:app` built same task → Task 5 Step 2. ✓
- Docs → Task 6. ✓

**Type consistency:** `TrashPort` signatures (Task 1) match `FakeTrashPort` (Task 2), the real adapter (Task 3), and `TrashBrowseViewModel` (Task 4). `TrashBrowseModel` public surface (`entries`/`error`/`writing`/`preview`/`retentionWindowMs`/`load`/`previewRetention`/`clearPreview`/`restore`/`purge`/`emptyTrash`/`runRetention`) is identical in Task 2 definition and Task 4 consumption. Report DTO field names (`purgedCount`/`sharedCount`/`ownerOnlyCount`/`unknownCount`/`filesRemoved`/`filesFailed`/`windowMs`) consistent across Tasks 1-3.

**Placeholder scan:** no TBD/TODO; every code step shows full code; the two investigate-first notes (Task 3 generated-name check, Task 5 wiring) are explicit verification steps, not deferred work.

## Out of scope (tracked, do not implement here)

- Retention-window **setting** (per-vault, replacing the 90-day default) — needs `retention_window_ms` on uniffi + an Android Settings screen; own slice ([[project_secretary_ios_settings_ffi_gap]]).
- Purge-count surfacing ("Purged N items") → #411 (DTOs plumbed).
- Locale-aware trashed-date (vs UTC `yyyy-MM-dd`) → #413.
- Manual GUI smoke on emulator/device against a **temp copy** of a staged vault with old trash — human-only ([[feedback_smoke_test_temp_copy_golden_vault]]).
