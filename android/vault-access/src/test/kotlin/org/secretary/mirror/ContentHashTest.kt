package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ContentHashTest {
    @Test
    fun `is deterministic for the same input`() {
        val data = "block-ciphertext".toByteArray()
        assertEquals(sha256Hex(data), sha256Hex(data.copyOf()))
    }

    @Test
    fun `differs for different input`() {
        assertNotEquals(sha256Hex(byteArrayOf(1, 2, 3)), sha256Hex(byteArrayOf(1, 2, 4)))
    }

    @Test
    fun `is 64 lowercase hex characters`() {
        val hex = sha256Hex(ByteArray(0))
        assertEquals(64, hex.length)
        assertTrue(hex.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `same-length different-content inputs hash differently (the re-encryption case)`() {
        val a = ByteArray(100) { 0 }
        val b = ByteArray(100) { i -> if (i == 50) 1 else 0 }
        assertNotEquals(sha256Hex(a), sha256Hex(b))
    }
}
