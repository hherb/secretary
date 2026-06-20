package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
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

    @Test
    fun `confirmBlockName leaves the create dialog open when the write fails`() = runTest {
        val f = fake(writeError = VaultBrowseError.SaveCryptoFailure("boom"))
        val model = VaultBrowseModel(f)
        model.startCreateBlock()
        model.confirmBlockName("Work")
        assertTrue(model.error.value is VaultBrowseError.SaveCryptoFailure)
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.CreateBlock)
    }

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
}
