package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

class FakeVaultSessionWriteTest {
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val existing = RecordSummaryView(
        "aa".repeat(16), "login", emptyList(), 1u, 2u, false, listOf(textField("user", "u")),
    )

    private fun session() =
        FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(existing)))

    @Test
    fun `appendRecord records content and re-read shows the new record`() = runTest {
        val s = session()
        val content = RecordContentInput("note", listOf("t"), listOf(
            FieldContentInput("body", FieldContentValue.Text("hello"))))
        val uuid = s.appendRecord(block.uuid, content)
        assertEquals(16, uuid.size)
        assertEquals(1, s.appended.size)
        val records = s.readBlock(block.uuid, includeDeleted = false)
        assertTrue(records.any { it.type == "note" })
    }

    @Test
    fun `editRecord records the edit for the right uuid`() = runTest {
        val s = session()
        val content = RecordContentInput("login", emptyList(), listOf(
            FieldContentInput("user", FieldContentValue.Text("changed"))))
        s.editRecord(block.uuid, hexToBytes(existing.uuidHex), content)
        assertEquals(1, s.edited.size)
        assertEquals(existing.uuidHex, s.edited.first().second)
    }

    @Test
    fun `editRecord mutates the in-memory record so readBlock reflects the change`() = runTest {
        val s = session()
        val content = RecordContentInput("login", emptyList(), listOf(
            FieldContentInput("user", FieldContentValue.Text("new-value"))))
        s.editRecord(block.uuid, hexToBytes(existing.uuidHex), content)
        val records = s.readBlock(block.uuid, includeDeleted = false)
        val updated = records.first { it.uuidHex == existing.uuidHex }
        val revealed = updated.fields.first { it.name == "user" }.reveal()
        assertEquals(RevealedValue.Text("new-value"), revealed)
    }

    @Test
    fun `editRecord throws RecordNotFound for absent record uuid`() = runTest {
        val s = session()
        val content = RecordContentInput("login", emptyList(), emptyList())
        try {
            s.editRecord(block.uuid, ByteArray(16) { 0x00 }, content)
            fail("expected RecordNotFound")
        } catch (e: VaultBrowseError.RecordNotFound) { /* expected */ }
    }

    @Test
    fun `editRecord throws RecordNotFound when block uuid is unknown`() = runTest {
        val s = session()
        val content = RecordContentInput("login", emptyList(), emptyList())
        val unknownBlock = ByteArray(16) { 0x7f }
        try {
            s.editRecord(unknownBlock, hexToBytes(existing.uuidHex), content)
            fail("expected RecordNotFound")
        } catch (e: VaultBrowseError.RecordNotFound) { /* expected */ }
    }
}

class FakeVaultBrowseTest {
    private fun block(name: String) =
        BlockSummaryView(uuid = ByteArray(16) { name.first().code.toByte() }, name = name, createdAtMs = 1u, lastModifiedMs = 2u)

    @Test
    fun `fake createBlock adds a block and returns its uuid`() = kotlinx.coroutines.test.runTest {
        val fake = FakeVaultSession("abcd", emptyList())
        val uuid = fake.createBlock("Work")
        assertEquals(16, uuid.size)
        assertEquals(listOf("Work"), fake.blockSummaries().map { it.name })
        assertEquals(listOf("Work"), fake.created)
    }

    @Test
    fun `fake renameBlock changes the name and preserves records`() = kotlinx.coroutines.test.runTest {
        val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Old", 1u, 2u)
        val rec = RecordSummaryView("aa", "login", emptyList(), 1u, 2u, false, listOf(textField("u", "v")))
        val fake = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec)))
        fake.renameBlock(block.uuid, "New")
        assertEquals(listOf("New"), fake.blockSummaries().map { it.name })
        assertEquals(listOf(rec), fake.readBlock(block.uuid, includeDeleted = false))
    }

    @Test
    fun `fake moveRecord copies to target under a fresh uuid and tombstones the source`() = kotlinx.coroutines.test.runTest {
        val src = BlockSummaryView(ByteArray(16) { 0x11 }, "Src", 1u, 2u)
        val tgt = BlockSummaryView(ByteArray(16) { 0x22 }, "Tgt", 1u, 2u)
        val rec = RecordSummaryView(hexOfBytes(ByteArray(16) { 0x33 }), "login", listOf("t"), 1u, 2u, false, listOf(textField("u", "secret")))
        val fake = FakeVaultSession("abcd", listOf(src, tgt), mapOf(src.uuidHex to listOf(rec)))
        val newUuid = fake.moveRecord(src.uuid, tgt.uuid, ByteArray(16) { 0x33 })
            .also { assertEquals(16, it.size) }
        // target holds a live copy whose field value reads back
        val tgtRecs = fake.readBlock(tgt.uuid, includeDeleted = false)
        assertEquals(1, tgtRecs.size)
        assertEquals("secret", (tgtRecs[0].fields[0].reveal() as RevealedValue.Text).value)
        // source: live view empty, show-deleted view shows the tombstone
        assertTrue(fake.readBlock(src.uuid, includeDeleted = false).isEmpty())
        assertEquals(1, fake.readBlock(src.uuid, includeDeleted = true).size)
        assertTrue(fake.readBlock(src.uuid, includeDeleted = true)[0].tombstone)
    }

    @Test
    fun `fake port opens to a seeded session`() = runTest {
        val session = FakeVaultSession(vaultUuidHex = "abcd", blocks = listOf(block("Logins")))
        val port = FakeVaultOpenPort(session = session)
        val opened = port.openWithPassword("/vault", "pw".toByteArray())
        assertEquals(session, opened)
        assertEquals(listOf("/vault"), port.openedFolders)
    }

    @Test
    fun `fake port throws the seeded open error`() = runTest {
        val port = FakeVaultOpenPort(openError = VaultBrowseError.WrongPasswordOrCorrupt)
        assertThrows(VaultBrowseError.WrongPasswordOrCorrupt::class.java) {
            kotlinx.coroutines.runBlocking { port.openWithPassword("/vault", "pw".toByteArray()) }
        }
    }

    @Test
    fun `fake session returns seeded records and records wipe`() = runTest {
        val recs = listOf(
            RecordSummaryView("aa", "login", listOf("p"), 1u, 2u, false, listOf(textField("username", "u"))),
        )
        val session = FakeVaultSession(vaultUuidHex = "abcd", blocks = listOf(block("Logins")), recordsByBlockHex = mapOf("4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c" to recs))
        // "Logins" → first char 'L' = 0x4c repeated 16x
        val out = session.readBlock(session.blockSummaries().first().uuid, includeDeleted = false)
        assertEquals(recs, out)
        assertTrue(!session.wiped)
        session.wipe()
        assertTrue(session.wiped)
    }
}
