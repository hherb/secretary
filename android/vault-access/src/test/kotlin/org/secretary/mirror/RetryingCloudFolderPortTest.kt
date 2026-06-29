package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

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
}
