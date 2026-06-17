package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RecordEditModelTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)

    private fun session(writeError: VaultBrowseError? = null, records: List<RecordSummaryView> = emptyList()) =
        FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to records), writeError = writeError)

    private fun addModel(s: FakeVaultSession) =
        RecordEditModel(s, block.uuid, RecordEditModel.Mode.Add)

    @Test
    fun `add commit appends content and sets committed`() = runTest {
        val s = session()
        val m = addModel(s)
        m.setRecordType("note")
        m.addField()
        m.setFieldName(0, "body")
        m.setFieldRawText(0, "hello")
        m.commit()
        assertTrue(m.committed.value)
        assertNull(m.error.value)
        assertEquals("note", s.appended.single().second.recordType)
        assertEquals("body", s.appended.single().second.fields.single().name)
    }

    @Test
    fun `bytes field parses hex on commit`() = runTest {
        val s = session()
        val m = addModel(s)
        m.setRecordType("key")
        m.addField()
        m.setFieldName(0, "raw")
        m.setFieldKind(0, FieldKind.Bytes)
        m.setFieldRawText(0, "ab cd")
        m.commit()
        assertTrue(m.committed.value)
        val v = s.appended.single().second.fields.single().value as FieldContentValue.Bytes
        assertEquals(listOf<Byte>(0xAB.toByte(), 0xCD.toByte()), v.value.toList())
    }

    @Test
    fun `invalid hex blocks the write with a typed error`() = runTest {
        val s = session()
        val m = addModel(s)
        m.addField()
        m.setFieldName(0, "raw")
        m.setFieldKind(0, FieldKind.Bytes)
        m.setFieldRawText(0, "zz")
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(m.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(s.appended.isEmpty())
    }

    @Test
    fun `duplicate field name blocks the write`() = runTest {
        val s = session()
        val m = addModel(s)
        m.addField(); m.setFieldName(0, "user")
        m.addField(); m.setFieldName(1, "user")
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(m.error.value is VaultBrowseError.InvalidArgument)
        assertTrue(s.appended.isEmpty())
    }

    @Test
    fun `load reveals fields into the form`() {
        val rec = RecordSummaryView(
            "bb".repeat(16), "login", listOf("personal"), 1u, 2u, false,
            listOf(
                RevealableField("user", FieldKind.Text) { RevealedValue.Text("alice") },
                RevealableField("salt", FieldKind.Bytes) { RevealedValue.Bytes(byteArrayOf(0xAB.toByte())) },
            ),
        )
        val s = session(records = listOf(rec))
        val m = RecordEditModel(s, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(rec.uuidHex)))
        m.load(rec)
        assertFalse(m.loadFailed.value)
        assertEquals("login", m.recordType.value)
        assertEquals(listOf("personal"), m.tags.value)
        assertEquals("alice", m.fields.value[0].rawText)
        assertEquals("ab", m.fields.value[1].rawText) // bytes → lowercase hex
        assertEquals(FieldKind.Bytes, m.fields.value[1].kind)
    }

    @Test
    fun `edit commit edits the right record`() = runTest {
        val rec = RecordSummaryView(
            "bb".repeat(16), "login", emptyList(), 1u, 2u, false,
            listOf(RevealableField("user", FieldKind.Text) { RevealedValue.Text("alice") }),
        )
        val s = session(records = listOf(rec))
        val m = RecordEditModel(s, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(rec.uuidHex)))
        m.load(rec)
        m.setFieldRawText(0, "bob")
        m.commit()
        assertTrue(m.committed.value)
        assertEquals(rec.uuidHex, s.edited.single().second)
        assertEquals("bob", (s.edited.single().third.fields.single().value as FieldContentValue.Text).value)
    }

    @Test
    fun `load failure sets loadFailed and commit is a no-op`() = runTest {
        val rec = RecordSummaryView(
            "cc".repeat(16), "login", emptyList(), 1u, 2u, false,
            listOf(RevealableField("user", FieldKind.Text) {
                throw VaultBrowseError.CorruptVault("cannot expose")
            }),
        )
        val s = session(records = listOf(rec))
        val m = RecordEditModel(s, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(rec.uuidHex)))
        m.load(rec)
        assertTrue(m.loadFailed.value)
        assertTrue(m.error.value is VaultBrowseError.CorruptVault)
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(s.edited.isEmpty())
    }

    @Test
    fun `ffi failure surfaces error and does not set committed`() = runTest {
        val s = session(writeError = VaultBrowseError.SaveCryptoFailure("boom"))
        val m = addModel(s)
        m.setRecordType("note")
        m.commit()
        assertFalse(m.committed.value)
        assertTrue(m.error.value is VaultBrowseError.SaveCryptoFailure)
    }

    @Test
    fun `removeField and tag mutators work`() {
        val s = session()
        val m = addModel(s)
        m.addField(); m.setFieldName(0, "a")
        m.addField(); m.setFieldName(1, "b")
        m.removeField(0)
        assertEquals(listOf("b"), m.fields.value.map { it.name })
        m.addTag(); m.setTag(0, "x")
        assertEquals(listOf("x"), m.tags.value)
        m.removeTag(0)
        assertTrue(m.tags.value.isEmpty())
    }
}
