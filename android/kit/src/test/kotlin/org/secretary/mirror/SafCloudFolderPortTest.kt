package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class SafCloudFolderPortTest {
    /** In-memory seams recording interactions, mirroring SafVaultLocationStoreTest.Fakes. */
    private class Fakes {
        val files = linkedMapOf<String, ByteArray>("blocks/a.cbor.enc" to byteArrayOf(1, 2))
        val events = mutableListOf<String>()
        var failNext: Boolean = false

        fun port(): SafCloudFolderPort = SafCloudFolderPort(
            listFiles = { maybeFail(); events.add("list"); files.keys.toList() },
            readFile = { path -> maybeFail(); events.add("read:$path"); files.getValue(path) },
            writeFile = { path, bytes -> maybeFail(); events.add("write:$path"); files[path] = bytes },
            deleteFile = { path -> maybeFail(); events.add("delete:$path"); files.remove(path); Unit },
        )

        private fun maybeFail() {
            if (failNext) throw IllegalStateException("provider boom")
        }
    }

    @Test
    fun `list forwards to the seam`() {
        val f = Fakes()
        assertEquals(listOf("blocks/a.cbor.enc"), f.port().list())
        assertEquals(listOf("list"), f.events)
    }

    @Test
    fun `read forwards the path and returns the bytes`() {
        val f = Fakes()
        assertArrayEquals(byteArrayOf(1, 2), f.port().read("blocks/a.cbor.enc"))
        assertEquals(listOf("read:blocks/a.cbor.enc"), f.events)
    }

    @Test
    fun `write forwards the path and bytes`() {
        val f = Fakes()
        f.port().write("manifest.cbor.enc", byteArrayOf(9))
        assertEquals(listOf("write:manifest.cbor.enc"), f.events)
        assertArrayEquals(byteArrayOf(9), f.files.getValue("manifest.cbor.enc"))
    }

    @Test
    fun `delete forwards the path`() {
        val f = Fakes()
        f.port().delete("blocks/a.cbor.enc")
        assertEquals(listOf("delete:blocks/a.cbor.enc"), f.events)
    }

    @Test
    fun `a seam failure is folded into CloudFolderException`() {
        val f = Fakes().apply { failNext = true }
        val e = assertThrows(CloudFolderException::class.java) { f.port().list() }
        assertEquals(true, e.message!!.contains("SAF list failed"))
    }

    @Test
    fun `a seam-thrown CloudFolderException passes through unwrapped`() {
        val port = SafCloudFolderPort(
            listFiles = { throw CloudFolderException("already typed") },
            readFile = { throw CloudFolderException("x") },
            writeFile = { _, _ -> },
            deleteFile = { },
        )
        val e = assertThrows(CloudFolderException::class.java) { port.list() }
        assertEquals("already typed", e.message)
    }
}
