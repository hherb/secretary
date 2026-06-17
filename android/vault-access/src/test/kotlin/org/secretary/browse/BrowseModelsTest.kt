package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BrowseModelsTest {
    @Test
    fun `hexOfBytes lowercases and zero-pads each byte`() {
        assertEquals("000102ff", hexOfBytes(byteArrayOf(0, 1, 2, 0xff.toByte())))
        assertEquals("", hexOfBytes(ByteArray(0)))
    }

    @Test
    fun `block summary derives a 32-char lowercase hex from its uuid`() {
        val uuid = ByteArray(16) { it.toByte() }
        val block = BlockSummaryView(uuid = uuid, name = "Logins", createdAtMs = 1u, lastModifiedMs = 2u)
        assertEquals("000102030405060708090a0b0c0d0e0f", block.uuidHex)
        assertEquals("Logins", block.name)
    }

    @Test
    fun `record summary carries metadata and derives field names from fields`() {
        val rec = RecordSummaryView(
            uuidHex = "deadbeef",
            type = "login",
            tags = listOf("personal"),
            createdAtMs = 10u,
            lastModMs = 20u,
            tombstone = false,
            fields = listOf(
                RevealableField("username", FieldKind.Text) { RevealedValue.Text("u") },
                RevealableField("password", FieldKind.Text) { RevealedValue.Text("p") },
            ),
        )
        assertEquals("login", rec.type)
        assertEquals(listOf("username", "password"), rec.fieldNames)   // computed
        assertTrue(rec.tags.contains("personal"))
    }

    @Test
    fun `VaultBrowseError is throwable and arms carry detail`() {
        val e: VaultBrowseError = VaultBrowseError.BlockNotFound("00")
        assertTrue(e is Exception)
        assertEquals("00", (e as VaultBrowseError.BlockNotFound).uuidHex)
    }
}
