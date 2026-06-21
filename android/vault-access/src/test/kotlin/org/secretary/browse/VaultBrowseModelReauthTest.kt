package org.secretary.browse

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Records each authorizeWrite reason; optionally throws the scripted error. */
class RecordingReauthGate(private val error: DeviceUnlockError? = null) : WriteReauthGate {
    val reasons = mutableListOf<String>()
    override suspend fun authorizeWrite(reason: String) {
        reasons += reason
        error?.let { throw it }
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class VaultBrowseModelReauthTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val rec = RecordSummaryView(
        hexOfBytes(ByteArray(16) { 0x33 }), "login", listOf("t"), 1u, 2u, false,
        listOf(textField("u", "secret")),
    )
    private fun fake() = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec)))

    @Test
    fun `delete authorizes with the delete reason before writing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.selectBlock(block)
        model.delete(rec)
        assertEquals(listOf("Confirm deleting this entry"), gate.reasons)
        assertEquals(1, f.tombstoned.size)
    }

    @Test
    fun `confirmBlockName create authorizes with the create reason`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertEquals(listOf("Confirm creating this block"), gate.reasons)
        assertEquals(listOf("Work"), f.created)
    }

    @Test
    fun `confirmBlockName rename authorizes with the rename reason`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startRenameBlock(block)
        model.confirmBlockName("Passwords")
        assertEquals(listOf("Confirm renaming this block"), gate.reasons)
        assertEquals(listOf(block.uuidHex to "Passwords"), f.renamed)
    }

    @Test
    fun `a cancelled reauth writes nothing and keeps the dialog open with no error`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.UserCancelled)
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertTrue(f.created.isEmpty())                                   // no write
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.CreateBlock) // dialog stays open
        assertNull(model.error.value)                                    // cancel is silent
    }

    @Test
    fun `a failed reauth surfaces ReauthFailed and writes nothing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.BiometryLockout)
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertTrue(f.created.isEmpty())
        assertTrue(model.error.value is VaultBrowseError.ReauthFailed)
        assertTrue(model.blockNameDialog.value is BlockNameDialogState.CreateBlock)
    }

    @Test
    fun `confirmMove cancelled keeps the picker open and writes nothing`() = runTest {
        val src = BlockSummaryView(ByteArray(16) { 0x11 }, "Src", 1u, 2u)
        val tgt = BlockSummaryView(ByteArray(16) { 0x22 }, "Tgt", 1u, 2u)
        val mv = RecordSummaryView(hexOfBytes(ByteArray(16) { 0x33 }), "login", listOf("t"), 1u, 2u, false,
            listOf(textField("u", "secret")))
        val f = FakeVaultSession("abcd", listOf(src, tgt), mapOf(src.uuidHex to listOf(mv)))
        val gate = RecordingReauthGate(error = DeviceUnlockError.UserCancelled)
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks(); model.selectBlock(src); model.startMoveRecord(mv)
        model.confirmMove(tgt)
        assertTrue(f.moved.isEmpty())
        assertEquals(mv, model.movingRecord.value)   // picker still open
    }

    @Test
    fun `lock resets the gate so the next write prompts again`() = runTest {
        // A GraceWindowReauthGate seeded open would normally be silent; lock() must reset it.
        var now = 1_000L
        val auth = object : BiometricAuthorizer {
            override val isEnrolled = true
            val reasons = mutableListOf<String>()
            override suspend fun authorize(reason: String) { reasons += reason }
        }
        val gate = GraceWindowReauthGate(auth, { now }, windowMs = 30_000L)
        gate.seed(now)
        val f = fake()
        val model = VaultBrowseModel(f, gate)
        model.loadBlocks()
        model.lock()                                  // must call gate.reset()
        model.loadBlocks(); model.startCreateBlock()
        model.confirmBlockName("Work")
        assertEquals(listOf("Confirm creating this block"), auth.reasons) // prompted (window was reset)
    }
}
