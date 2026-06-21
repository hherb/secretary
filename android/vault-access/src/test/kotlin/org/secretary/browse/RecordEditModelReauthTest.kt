package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RecordEditModelReauthTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private fun fake() = FakeVaultSession("abcd", listOf(block))

    private fun addModel(gate: WriteReauthGate, f: FakeVaultSession) =
        RecordEditModel(f, block.uuid, RecordEditModel.Mode.Add, gate).apply {
            setRecordType("login"); addField(); setFieldName(0, "user"); setFieldRawText(0, "alice")
        }

    @Test
    fun `commit authorizes with the save reason before writing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        val model = addModel(gate, f)
        model.commit()
        assertEquals(listOf("Confirm saving this entry"), gate.reasons)
        assertEquals(1, f.appended.size)
        assertTrue(model.committed.value)
    }

    @Test
    fun `a cancelled reauth writes nothing, sets no error, and does not commit`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.UserCancelled)
        val model = addModel(gate, f)
        model.commit()
        assertTrue(f.appended.isEmpty())
        assertFalse(model.committed.value)   // form stays open
        assertNull(model.error.value)        // cancel is silent
    }

    @Test
    fun `a failed reauth surfaces ReauthFailed and writes nothing`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate(error = DeviceUnlockError.BiometryUnavailable)
        val model = addModel(gate, f)
        model.commit()
        assertTrue(f.appended.isEmpty())
        assertFalse(model.committed.value)
        assertTrue(model.error.value is VaultBrowseError.ReauthFailed)
    }

    @Test
    fun `the gate is consulted only AFTER validation (invalid input never prompts)`() = runTest {
        val f = fake()
        val gate = RecordingReauthGate()
        // duplicate field names → validation error before any gate call
        val model = RecordEditModel(f, block.uuid, RecordEditModel.Mode.Add, gate).apply {
            setRecordType("login")
            addField(); setFieldName(0, "dup"); setFieldRawText(0, "a")
            addField(); setFieldName(1, "dup"); setFieldRawText(1, "b")
        }
        model.commit()
        assertTrue(gate.reasons.isEmpty())                          // never prompted
        assertTrue(model.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(f.appended.isEmpty())
    }
}
