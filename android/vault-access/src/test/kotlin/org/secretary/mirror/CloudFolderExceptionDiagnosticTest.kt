package org.secretary.mirror

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import org.secretary.diagnostics.diagnosticDetail
import java.io.File

/**
 * #475 regression: the wrapper exception types this package OWNS must be declared
 * `SecretFreeThrowable`.
 *
 * The bug these pin was a diagnostic regression, not a leak. Every wrapper in the cloud path
 * renders its cause through `diagnosticDetail`, which default-denies — so leaving
 * [CloudFolderException] / [VaultMirrorException] unconformed made each nested wrap discard the
 * message it had just been built to carry, and the whole chain collapsed to a type name. The
 * pre-existing tests here assert on exception TYPE, never on message content, which is exactly
 * why it shipped unnoticed; these assert on content.
 *
 * Each test is mutation-proven: dropping `, SecretFreeThrowable` from the declaration under test
 * makes it fail.
 */
class CloudFolderExceptionDiagnosticTest {
    @Test
    fun `a CloudFolderException renders its own message, not an undisclosed marker`() {
        val rendered = diagnosticDetail(CloudFolderException("SAF list failed: quota exceeded"))
        assertFalse(rendered.contains("<undisclosed"), rendered)
        assertEquals("org.secretary.mirror.CloudFolderException: SAF list failed: quota exceeded", rendered)
    }

    @Test
    fun `the retry wrapper preserves the underlying reason across the nested wrap`() {
        // The production shape: SafCloudFolderPort throws a gated CloudFolderException, and
        // RetryingCloudFolderPort wraps it once more. Both frames must survive.
        val fake = FakeCloudFolderPort().apply { failWith = "quota exceeded on drive" }
        val retries = mutableListOf<String>()
        val port = RetryingCloudFolderPort(
            fake,
            RetryPolicy(maxAttempts = 2, baseDelayMs = 0, maxDelayMs = 0),
            sleep = {},
            onRetry = { retries.add(it) },
        )

        val e = assertThrows<CloudFolderException> { port.list() }
        assertTrue(e.message!!.contains("quota exceeded on drive"), e.message!!)
        assertTrue(e.message!!.contains("failed after 2 attempts"), e.message!!)
        // The retry breadcrumb goes to SecretaryLog.info — it must say more than a class name.
        assertEquals(1, retries.size, "one retry before the budget ran out")
        assertTrue(retries[0].contains("quota exceeded on drive"), retries[0])
    }

    @Test
    fun `VaultMirror preserves the cloud reason when it folds to VaultMirrorException`(
        @TempDir workingDir: File,
    ) {
        val fake = FakeCloudFolderPort().apply { failWith = "permission revoked by provider" }
        val e = assertThrows<VaultMirrorException> { VaultMirror(fake).flush(workingDir) }
        assertFalse(e.message!!.contains("<undisclosed"), e.message!!)
        assertTrue(e.message!!.contains("permission revoked by provider"), e.message!!)

        // ...and the fold's OWN type must survive one more render. `openCloudTarget` catches this
        // and hands it to `SecretaryLog.warn`, which calls diagnosticDetail — so VaultMirrorException's
        // conformance, not CloudFolderException's, is what decides whether that log line says
        // anything. Asserting only on `message` above would pass with VaultMirrorException
        // unconformed, because the message was already assembled from the conformed inner type;
        // that vacuity is exactly what the mutation run caught.
        val rendered = diagnosticDetail(e)
        assertFalse(rendered.contains("<undisclosed"), rendered)
        assertTrue(rendered.contains("permission revoked by provider"), rendered)
    }
}
