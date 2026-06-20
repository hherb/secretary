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
