package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
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
}
