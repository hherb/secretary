package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultBrowseModelTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val recs = listOf(
        RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf(textField("username", "u"))),
    )
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
    fun `loadBlocks captures a summary failure as a typed error and leaves blocks empty`() = runTest {
        val failing = FakeVaultSession("abcd", listOf(block), blocksError = VaultBrowseError.CorruptVault("bad"))
        val model = VaultBrowseModel(failing)
        model.loadBlocks()
        assertTrue(model.error.value is VaultBrowseError.CorruptVault)
        assertTrue(model.blocks.value.isEmpty())
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
    fun `clearSelection clears a lingering read error`() = runTest {
        val model = VaultBrowseModel(session(readError = VaultBrowseError.BlockNotFound("4c")))
        model.loadBlocks()
        model.selectBlock(block)
        assertTrue(model.error.value is VaultBrowseError.BlockNotFound)
        model.clearSelection()
        assertNull(model.error.value)
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

    private val pwField = textField("password", "hunter2")
    private val revealRecs = listOf(
        RecordSummaryView("33445566778899aabbccddeeff001122", "login", emptyList(), 1u, 2u, false, listOf(pwField)),
    )
    private fun revealModel(): VaultBrowseModel {
        val s = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to revealRecs))
        return VaultBrowseModel(s)
    }

    @Test
    fun `reveal materializes a field value into the revealed map`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        model.reveal(rec, pwField)
        assertEquals(
            RevealedValue.Text("hunter2"),
            model.revealed.value["${rec.uuidHex}/password"],
        )
    }

    @Test
    fun `hide removes exactly one revealed field`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        model.reveal(rec, pwField)
        model.hide(rec.uuidHex, "password")
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `hideAll clears every revealed field`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        val second = RevealableField("username", FieldKind.Text) { RevealedValue.Text("owner") }
        model.reveal(rec, pwField)
        model.reveal(rec, second)
        assertEquals(2, model.revealed.value.size)
        model.hideAll()
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `selectBlock clears any previously revealed value`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        model.reveal(rec, pwField)
        model.selectBlock(block)
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `lock clears revealed values as well as wiping`() = runTest {
        val model = revealModel()
        model.reveal(revealRecs.first(), pwField)
        model.lock()
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `a reveal lambda that throws routes to error and leaves revealed empty`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        val boom = RevealableField("password", FieldKind.Text) {
            throw VaultBrowseError.CorruptVault("expose failed")
        }
        model.reveal(rec, boom)
        assertTrue(model.error.value is VaultBrowseError.CorruptVault)
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `a reveal lambda throwing a non-VaultBrowseError folds to Failed and leaves revealed empty`() = runTest {
        val model = revealModel()
        val rec = revealRecs.first()
        val boom = RevealableField("password", FieldKind.Text) {
            throw IllegalStateException("unexpected")
        }
        model.reveal(rec, boom)
        assertTrue(model.error.value is VaultBrowseError.Failed)
        assertTrue(model.revealed.value.isEmpty())
    }

    @Test
    fun `clearSelection clears any revealed value`() = runTest {
        val model = revealModel()
        model.reveal(revealRecs.first(), pwField)
        model.clearSelection()
        assertTrue(model.revealed.value.isEmpty())
    }

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

    @Test
    fun `startAdd publishes an Add edit model on the selected block`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks()
        model.selectBlock(block)
        model.startAdd()
        val editing = model.editing.value
        assertEquals(RecordEditModel.Mode.Add, editing?.mode)
    }

    @Test
    fun `startEdit publishes an Edit model prefilled from the record`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks()
        model.selectBlock(block)
        val rec = model.selectedRecords.value!!.first()
        model.startEdit(rec)
        val editing = model.editing.value!!
        assertTrue(editing.mode is RecordEditModel.Mode.Edit)
        assertEquals(rec.type, editing.recordType.value)
    }

    @Test
    fun `cancelEdit clears the editing model`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks(); model.selectBlock(block); model.startAdd()
        model.cancelEdit()
        assertNull(model.editing.value)
    }

    @Test
    fun `onEditCommitted clears editing and re-reads the block`() = runTest {
        val s = session()
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(block); model.startAdd()
        // Simulate a committed append directly on the session, then signal commit.
        s.appendRecord(block.uuid, RecordContentInput("note", emptyList(), emptyList()))
        model.onEditCommitted()
        assertNull(model.editing.value)
        assertTrue(model.selectedRecords.value!!.any { it.type == "note" })
    }

    @Test
    fun `lock clears editing`() = runTest {
        val model = VaultBrowseModel(session())
        model.loadBlocks(); model.selectBlock(block); model.startAdd()
        model.lock()
        assertNull(model.editing.value)
    }

    private fun writableSessionGated(gate: CompletableDeferred<Unit>): FakeVaultSession {
        val live = RecordSummaryView("ab", "login", emptyList(), 1u, 2u, false, listOf(textField("u", "x")))
        return FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(live)), writeGate = gate)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `concurrent delete tombstones exactly once`() = runTest {
        val gate = CompletableDeferred<Unit>()
        val s = writableSessionGated(gate)
        val model = VaultBrowseModel(s)
        model.loadBlocks()
        model.selectBlock(model.blocks.value.single())
        val rec = model.selectedRecords.value!!.first()
        launch { model.delete(rec) }   // grabs writing, parks on the gate
        launch { model.delete(rec) }   // sees writing == true, returns
        runCurrent()
        assertTrue(model.writing.value)
        assertEquals(0, s.tombstoned.size)
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, s.tombstoned.size)
        assertFalse(model.writing.value)
    }

    @Test
    fun `failed delete resets writing and keeps the list`() = runTest {
        val s = writableSession(writeError = VaultBrowseError.RecordNotFound("ab"))
        val model = VaultBrowseModel(s)
        model.loadBlocks(); model.selectBlock(model.blocks.value.single())
        val before = model.selectedRecords.value
        val rec = before!!.first()
        model.delete(rec)
        assertFalse(model.writing.value)
        assertEquals(before, model.selectedRecords.value)   // rejected write leaves the list intact
    }

    @Test
    fun `onCommit fires after a successful write not after a read`() = runTest {
        var commits = 0
        val s = writableSession()
        val model = VaultBrowseModel(s, onCommit = { commits++ })
        model.loadBlocks()
        model.selectBlock(model.blocks.value.first())
        assertEquals(0, commits)    // reads must not trigger a flush
        model.delete(model.selectedRecords.value!!.first()) // a successful mutating commit
        assertEquals(1, commits)    // one commit → one flush hook
    }

    @Test
    fun `onCommit does not fire after a failed write`() = runTest {
        var commits = 0
        val s = writableSession(writeError = VaultBrowseError.RecordNotFound("ab"))
        val model = VaultBrowseModel(s, onCommit = { commits++ })
        model.loadBlocks(); model.selectBlock(model.blocks.value.single())
        model.delete(model.selectedRecords.value!!.first())
        assertEquals(0, commits)    // failed write must not trigger a flush
    }
}
