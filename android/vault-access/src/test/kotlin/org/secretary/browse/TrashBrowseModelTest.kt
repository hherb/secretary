package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class TrashBrowseModelTest {
    private fun tb(name: String, ms: Long, uuid: Byte) =
        TrashedBlockInfo(ByteArray(16) { uuid }, name, ms, ByteArray(16))

    /**
     * Reauth gate whose failure can be re-scripted mid-test. [RecordingReauthGate]'s error is fixed
     * at construction, which can't express "first call succeeds, a later call fails" — needed by
     * `refused reauth clears a prior notice` below.
     */
    private class ScriptedReauthGate : WriteReauthGate {
        var failNext: DeviceUnlockError? = null
        override suspend fun authorizeWrite(reason: String) {
            failNext?.let { throw it }
        }
    }

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
    fun `a second write while one is in flight is a no-op`() = runTest {
        val gate = CompletableDeferred<Unit>()
        val port = FakeTrashPort(list = listOf(tb("a", 1L, 1)), writeGate = gate)
        val model = TrashBrowseModel(port)
        model.load()
        val first = launch { model.purge(ByteArray(16) { 1 }) }
        runCurrent()
        model.purge(ByteArray(16) { 1 })   // re-entrant; blocked by `writing`
        gate.complete(Unit)
        advanceUntilIdle()
        first.join()
        assertEquals(1, port.purged.size)  // only the first write reached the port
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

    @Test
    fun `runRetention sets a purged notice`() = runTest {
        val port = FakeTrashPort(
            expired = listOf(
                ExpiredEntryInfo(ByteArray(16), 0L, 100L * MS_PER_DAY),
                ExpiredEntryInfo(ByteArray(16), 0L, 100L * MS_PER_DAY),
            ),
        )
        val model = TrashBrowseModel(port)
        model.load()
        model.runRetention()
        assertEquals(PurgeNotice("Purged 2 items", PurgeSeverity.SUCCESS), model.notice.value)
    }

    @Test
    fun `runRetention warns when files failed`() = runTest {
        val port = FakeTrashPort(
            expired = listOf(ExpiredEntryInfo(ByteArray(16), 0L, 100L * MS_PER_DAY)),
            retentionFilesFailed = 1,
        )
        val model = TrashBrowseModel(port)
        model.load()
        model.runRetention()
        assertEquals(
            PurgeNotice("Purged 1 item · 1 file could not be removed", PurgeSeverity.WARNING),
            model.notice.value,
        )
    }

    @Test
    fun `emptyTrash sets a purged notice`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 100L, 1), tb("b", 200L, 2)))
        val model = TrashBrowseModel(port)
        model.load()
        model.emptyTrash()
        assertEquals(PurgeNotice("Purged 2 items", PurgeSeverity.SUCCESS), model.notice.value)
    }

    @Test
    fun `emptyTrash warns when files failed`() = runTest {
        val port = FakeTrashPort(
            list = listOf(tb("a", 100L, 1), tb("b", 200L, 2)),
            emptyTrashFilesFailed = 1,
        )
        val model = TrashBrowseModel(port)
        model.load()
        model.emptyTrash()
        assertEquals(
            PurgeNotice("Purged 2 items · 1 file could not be removed", PurgeSeverity.WARNING),
            model.notice.value,
        )
    }

    @Test
    fun `purge sets a deleted-forever notice`() = runTest {
        val port = FakeTrashPort(list = listOf(tb("a", 100L, 1)))
        val model = TrashBrowseModel(port)
        model.load()
        model.purge(ByteArray(16) { 1 })
        assertEquals(PurgeNotice("Deleted forever", PurgeSeverity.SUCCESS), model.notice.value)
    }

    @Test
    fun `refused reauth clears a prior notice`() = runTest {
        val gate = ScriptedReauthGate()
        val port = FakeTrashPort(list = listOf(tb("a", 100L, 1), tb("b", 200L, 2)))
        val model = TrashBrowseModel(port, gate)
        model.load()
        model.emptyTrash()
        assertNotNull(model.notice.value)
        gate.failNext = DeviceUnlockError.UserCancelled
        model.purge(ByteArray(16) { 2 })
        assertNull(model.notice.value)
    }
}
