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
}
