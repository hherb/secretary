package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.api.Test
import java.io.File

class VaultMirrorTest {
    @TempDir
    lateinit var workingDir: File

    private fun writeWorking(relativePath: String, bytes: ByteArray) {
        val f = File(workingDir, relativePath)
        f.parentFile?.mkdirs()
        f.writeBytes(bytes)
    }

    @Test
    fun `flush copies a new working file to the cloud`() {
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        val cloud = FakeCloudFolderPort()
        val report = VaultMirror(cloud).flush(workingDir)
        assertEquals(listOf("blocks/a.cbor.enc"), report.copied)
        assertArrayEquals(byteArrayOf(1, 2, 3), cloud.snapshot().getValue("blocks/a.cbor.enc"))
    }

    @Test
    fun `flush writes blocks before the manifest (block-first)`() {
        writeWorking(MANIFEST_FILENAME, byteArrayOf(9))
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1))
        writeWorking("blocks/b.cbor.enc", byteArrayOf(2))
        val cloud = FakeCloudFolderPort()
        VaultMirror(cloud).flush(workingDir)
        assertEquals(
            listOf("write:blocks/a.cbor.enc", "write:blocks/b.cbor.enc", "write:$MANIFEST_FILENAME"),
            cloud.writeOrder,
        )
    }

    @Test
    fun `flush deletes a cloud orphan after copying, and only after`() {
        writeWorking(MANIFEST_FILENAME, byteArrayOf(9))
        val cloud = FakeCloudFolderPort(mapOf("blocks/old.cbor.enc" to byteArrayOf(7)))
        val report = VaultMirror(cloud).flush(workingDir)
        assertEquals(listOf("blocks/old.cbor.enc"), report.deleted)
        assertFalse(cloud.snapshot().containsKey("blocks/old.cbor.enc"))
        val lastWrite = cloud.writeOrder.indexOfLast { it.startsWith("write:") }
        val theDelete = cloud.writeOrder.indexOf("delete:blocks/old.cbor.enc")
        assertTrue(lastWrite < theDelete, "delete must follow all writes: ${cloud.writeOrder}")
    }

    @Test
    fun `flush is a no-op when both sides already agree`() {
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1))
        val cloud = FakeCloudFolderPort()
        VaultMirror(cloud).flush(workingDir)   // first flush populates the cloud
        cloud.writeOrder.clear()
        val report = VaultMirror(cloud).flush(workingDir)
        assertEquals(emptyList<String>(), report.copied)
        assertEquals(emptyList<String>(), report.deleted)
        assertTrue(cloud.writeOrder.isEmpty())
    }

    @Test
    fun `materialize pulls cloud files into the working dir, subdirs included`() {
        val cloud = FakeCloudFolderPort(
            mapOf(
                MANIFEST_FILENAME to byteArrayOf(9),
                "blocks/a.cbor.enc" to byteArrayOf(1, 2),
            ),
        )
        val report = VaultMirror(cloud).materialize(workingDir)
        assertTrue(report.copied.containsAll(listOf(MANIFEST_FILENAME, "blocks/a.cbor.enc")))
        assertArrayEquals(byteArrayOf(1, 2), File(workingDir, "blocks/a.cbor.enc").readBytes())
        assertArrayEquals(byteArrayOf(9), File(workingDir, MANIFEST_FILENAME).readBytes())
    }

    @Test
    fun `materialize deletes a working file absent from the cloud`() {
        writeWorking("blocks/stale.cbor.enc", byteArrayOf(5))
        val cloud = FakeCloudFolderPort(mapOf(MANIFEST_FILENAME to byteArrayOf(9)))
        VaultMirror(cloud).materialize(workingDir)
        assertFalse(File(workingDir, "blocks/stale.cbor.enc").exists())
    }

    @Test
    fun `flush then materialize into a fresh working copy converges byte-for-byte`() {
        writeWorking(MANIFEST_FILENAME, byteArrayOf(9))
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        writeWorking("contacts/c.cbor.enc", byteArrayOf(4))
        val cloud = FakeCloudFolderPort()
        VaultMirror(cloud).flush(workingDir)

        val fresh = File(workingDir.parentFile, "fresh").also { it.mkdirs() }
        VaultMirror(cloud).materialize(fresh)
        assertArrayEquals(byteArrayOf(9), File(fresh, MANIFEST_FILENAME).readBytes())
        assertArrayEquals(byteArrayOf(1, 2, 3), File(fresh, "blocks/a.cbor.enc").readBytes())
        assertArrayEquals(byteArrayOf(4), File(fresh, "contacts/c.cbor.enc").readBytes())
    }

    @Test
    fun `a cloud failure during flush surfaces as VaultMirrorException`() {
        writeWorking("blocks/a.cbor.enc", byteArrayOf(1))
        val cloud = FakeCloudFolderPort().apply { failWith = "revoked" }
        val e = assertThrows(VaultMirrorException::class.java) { VaultMirror(cloud).flush(workingDir) }
        assertTrue(e.message!!.contains("flush failed"))
    }

    @Test
    fun `materialize over a missing working dir creates it from the cloud`() {
        val missing = File(workingDir, "not-yet")
        val cloud = FakeCloudFolderPort(mapOf("blocks/a.cbor.enc" to byteArrayOf(1)))
        VaultMirror(cloud).materialize(missing)
        assertArrayEquals(byteArrayOf(1), File(missing, "blocks/a.cbor.enc").readBytes())
    }

    @Test
    fun `materialize writes blocks before the manifest (block-first) on the working side`() {
        val cloud = FakeCloudFolderPort(
            mapOf(
                MANIFEST_FILENAME to byteArrayOf(9),
                "blocks/a.cbor.enc" to byteArrayOf(1),
                "blocks/b.cbor.enc" to byteArrayOf(2),
            ),
        )
        val report = VaultMirror(cloud).materialize(workingDir)
        // report.copied preserves plan/execution order, so the working-side write order is
        // observable here: every block lands before the manifest.
        assertEquals(
            listOf("blocks/a.cbor.enc", "blocks/b.cbor.enc", MANIFEST_FILENAME),
            report.copied,
        )
    }

    @Test
    fun `a working-copy IO failure during materialize surfaces as VaultMirrorException`() {
        // Pre-create a regular file where a directory must go: writing "blocks/a.cbor.enc"
        // then fails because its parent "blocks" cannot be created (it is a file). A
        // deterministic IOException, independent of filesystem permissions / the test user.
        File(workingDir, "blocks").writeBytes(byteArrayOf(0))
        val cloud = FakeCloudFolderPort(mapOf("blocks/a.cbor.enc" to byteArrayOf(1)))
        val e = assertThrows(VaultMirrorException::class.java) { VaultMirror(cloud).materialize(workingDir) }
        assertTrue(e.message!!.contains("materialize failed"))
    }
}
