package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FakeVaultBrowseTest {
    private fun block(name: String) =
        BlockSummaryView(uuid = ByteArray(16) { name.first().code.toByte() }, name = name, createdAtMs = 1u, lastModifiedMs = 2u)

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
