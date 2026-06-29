package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
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

    @Test
    fun `failNextN throws for the next N ops then succeeds`() {
        val fake = FakeCloudFolderPort()
        fake.failNextN = 2
        assertThrows(CloudFolderException::class.java) { fake.list() }
        assertThrows(CloudFolderException::class.java) { fake.list() }
        assertEquals(emptyList<String>(), fake.list()) // 3rd op succeeds
        assertEquals(listOf("list", "list", "list"), fake.callLog) // failed ops are still logged
    }

    @Test
    fun `readMissNextN reports a present file as missing for N reads then returns it`() {
        val fake = FakeCloudFolderPort(mapOf("blocks/a.cbor.enc" to byteArrayOf(7)))
        fake.readMissNextN = 1
        assertThrows(CloudFolderException::class.java) { fake.read("blocks/a.cbor.enc") }
        assertEquals(7, fake.read("blocks/a.cbor.enc")[0]) // 2nd read sees it
    }

    @Test
    fun `callLog records every op in order`() {
        val fake = FakeCloudFolderPort()
        fake.write("blocks/a.cbor.enc", byteArrayOf(1))
        fake.read("blocks/a.cbor.enc")
        fake.delete("blocks/a.cbor.enc")
        fake.list()
        assertTrue(
            fake.callLog == listOf("write:blocks/a.cbor.enc", "read:blocks/a.cbor.enc", "delete:blocks/a.cbor.enc", "list"),
            "callLog was ${fake.callLog}",
        )
    }
}
