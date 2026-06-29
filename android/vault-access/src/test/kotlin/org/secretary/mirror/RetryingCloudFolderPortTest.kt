package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class RetryingCloudFolderPortTest {
    // Fast, deterministic policy: 3 attempts, 10ms base, 40ms cap — no real waiting (sleep is faked).
    private val fastPolicy = RetryPolicy(maxAttempts = 3, baseDelayMs = 10, maxDelayMs = 40)

    private class Recorder {
        val sleeps = mutableListOf<Long>()
        val retries = mutableListOf<String>()
    }

    private fun port(inner: CloudFolderPort, rec: Recorder, policy: RetryPolicy = fastPolicy) =
        RetryingCloudFolderPort(inner, policy, sleep = { rec.sleeps.add(it) }, onRetry = { rec.retries.add(it) })

    @Test
    fun `write succeeds after transient throws, sleeping the backoff schedule`() {
        val fake = FakeCloudFolderPort()
        fake.failNextN = 2 // first two write attempts throw, third succeeds
        val rec = Recorder()
        port(fake, rec).write("blocks/a.cbor.enc", byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), fake.snapshot().getValue("blocks/a.cbor.enc"))
        assertEquals(listOf(10L, 20L), rec.sleeps) // backoff after attempt 1 and 2
        assertEquals(2, rec.retries.size)
    }

    @Test
    fun `write retries when the read-back is not yet visible`() {
        val fake = FakeCloudFolderPort()
        fake.readMissNextN = 1 // write lands, but first read-back reports missing
        val rec = Recorder()
        port(fake, rec).write("blocks/a.cbor.enc", byteArrayOf(9))
        assertArrayEquals(byteArrayOf(9), fake.snapshot().getValue("blocks/a.cbor.enc"))
        assertEquals(listOf(10L), rec.sleeps) // one backoff before the visible read-back
        assertEquals(1, rec.retries.size)
    }

    @Test
    fun `write that never verifies throws after maxAttempts with bounded sleeps`() {
        val fake = FakeCloudFolderPort()
        fake.failWith = "provider down" // every op throws, forever
        val rec = Recorder()
        assertThrows(CloudFolderException::class.java) {
            port(fake, rec).write("blocks/a.cbor.enc", byteArrayOf(1))
        }
        assertEquals(listOf(10L, 20L), rec.sleeps) // 3 attempts → 2 backoffs, then rethrow
    }

    @Test
    fun `a non-CloudFolderException propagates immediately without retry`() {
        val throwing = object : CloudFolderPort {
            override fun list() = emptyList<String>()
            override fun read(relativePath: String) = ByteArray(0)
            override fun write(relativePath: String, bytes: ByteArray) { throw IllegalStateException("boom") }
            override fun delete(relativePath: String) {}
        }
        val rec = Recorder()
        assertThrows(IllegalStateException::class.java) { port(throwing, rec).write("x", byteArrayOf(1)) }
        assertTrue(rec.sleeps.isEmpty(), "no backoff sleep for a non-CloudFolderException")
        assertTrue(rec.retries.isEmpty(), "no onRetry for a non-CloudFolderException")
    }

    @Test
    fun `read retries transient failures then returns the bytes`() {
        val fake = FakeCloudFolderPort(mapOf("manifest.cbor.enc" to byteArrayOf(5)))
        fake.failNextN = 2
        val rec = Recorder()
        assertArrayEquals(byteArrayOf(5), port(fake, rec).read("manifest.cbor.enc"))
        assertEquals(listOf(10L, 20L), rec.sleeps)
    }

    @Test
    fun `list retries transient failures then returns the listing`() {
        val fake = FakeCloudFolderPort(mapOf("manifest.cbor.enc" to byteArrayOf(5)))
        fake.failNextN = 1
        val rec = Recorder()
        assertEquals(listOf("manifest.cbor.enc"), port(fake, rec).list())
        assertEquals(listOf(10L), rec.sleeps)
    }

    @Test
    fun `read rethrows after exhausting attempts on a permanent failure`() {
        val fake = FakeCloudFolderPort()
        fake.failWith = "revoked"
        val rec = Recorder()
        assertThrows(CloudFolderException::class.java) { port(fake, rec).read("x") }
        assertEquals(listOf(10L, 20L), rec.sleeps)
    }

    @Test
    fun `list rethrows after exhausting attempts on a permanent failure`() {
        val fake = FakeCloudFolderPort()
        fake.failWith = "revoked"
        val rec = Recorder()
        assertThrows(CloudFolderException::class.java) { port(fake, rec).list() }
        assertEquals(listOf(10L, 20L), rec.sleeps)
    }

    @Test
    fun `delete retries on exception but issues no read-back`() {
        val fake = FakeCloudFolderPort(mapOf("blocks/old.cbor.enc" to byteArrayOf(7)))
        fake.failNextN = 1
        val rec = Recorder()
        port(fake, rec).delete("blocks/old.cbor.enc")
        assertEquals(listOf(10L), rec.sleeps)
        assertEquals(0, fake.callLog.count { it.startsWith("read:") }, "delete must not read-back: ${fake.callLog}")
        assertFalse(fake.snapshot().containsKey("blocks/old.cbor.enc"), "retried delete must deliver the delete")
    }

    @Test
    fun `VaultMirror flush over a flaky retrying port pushes every file`(@TempDir workingDir: File) {
        File(workingDir, "manifest.cbor.enc").writeBytes(byteArrayOf(9))
        File(workingDir, "blocks").mkdirs()
        File(workingDir, "blocks/a.cbor.enc").writeBytes(byteArrayOf(1, 2))
        val fake = FakeCloudFolderPort()
        fake.failNextN = 1 // one transient hiccup on the cloud list; retry absorbs it, both writes then succeed
        val rec = Recorder()
        val mirror = VaultMirror(port(fake, rec))
        val report = mirror.flush(workingDir)
        assertTrue(rec.sleeps.isNotEmpty(), "at least one retry backoff sleep must have fired")
        assertEquals(2, report.copied.size, "both files pushed")
        assertArrayEquals(byteArrayOf(9), fake.snapshot().getValue("manifest.cbor.enc"))
        assertArrayEquals(byteArrayOf(1, 2), fake.snapshot().getValue("blocks/a.cbor.enc"))
    }
}
