package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class FakeCloudFolderPortTest {
    @Test
    fun `write then read round-trips the bytes`() {
        val port = FakeCloudFolderPort()
        port.write("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), port.read("blocks/a.cbor.enc"))
    }

    @Test
    fun `list reflects writes and deletes`() {
        val port = FakeCloudFolderPort(mapOf("a" to byteArrayOf(0)))
        port.write("b", byteArrayOf(0))
        port.delete("a")
        assertEquals(listOf("b"), port.list())
    }

    @Test
    fun `reading a missing file throws CloudFolderException`() {
        assertThrows(CloudFolderException::class.java) { FakeCloudFolderPort().read("nope") }
    }

    @Test
    fun `deleting a missing file is a no-op`() {
        val port = FakeCloudFolderPort()
        port.delete("nope")
        assertFalse(port.snapshot().containsKey("nope"))
    }

    @Test
    fun `failWith makes every operation throw`() {
        val port = FakeCloudFolderPort()
        port.failWith = "revoked"
        assertThrows(CloudFolderException::class.java) { port.list() }
    }

    @Test
    fun `writeOrder records mutating calls in order`() {
        val port = FakeCloudFolderPort(mapOf("old" to byteArrayOf(0)))
        port.write("blocks/a.cbor.enc", byteArrayOf(1))
        port.delete("old")
        assertEquals(listOf("write:blocks/a.cbor.enc", "delete:old"), port.writeOrder)
    }
}
