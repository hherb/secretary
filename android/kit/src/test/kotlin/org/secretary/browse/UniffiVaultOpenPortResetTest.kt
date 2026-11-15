package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.VaultException
import java.io.File

/** The real port's rollback reset (#746): what it forwards to the binding, and when it refuses. */
class UniffiVaultOpenPortResetTest {
    @Test
    fun `forwards the configured state dir, the utf8 folder and the password to the binding`() = runTest {
        var seenStateDir: String? = null
        var seenFolder: ByteArray? = null
        var seenPassword: ByteArray? = null
        val port = UniffiVaultOpenPort(
            syncStateDir = File("/data/files/sync-state"),
            resetFn = { stateDir, folder, pw ->
                seenStateDir = stateDir
                seenFolder = folder
                seenPassword = ByteArray(pw.remaining()).also { pw.duplicate().get(it) }
                // No session can be built off-device; a typed error ends the call after capture.
                throw VaultException.WrongPasswordOrCorrupt()
            },
        )
        val thrown = runCatching { port.resetSyncStateAndOpenWithPassword("/vault", byteArrayOf(4, 5, 6)) }
            .exceptionOrNull()
        assertEquals("/data/files/sync-state", seenStateDir)
        assertArrayEquals("/vault".toByteArray(Charsets.UTF_8), seenFolder)
        assertArrayEquals(byteArrayOf(4, 5, 6), seenPassword)
        // A wrong password on the reset surfaces through the same mapping as a normal open.
        assertEquals(VaultBrowseError.WrongPasswordOrCorrupt, thrown)
    }

    @Test
    fun `a port without a sync state dir refuses the reset without calling the binding`() = runTest {
        var called = false
        val port = UniffiVaultOpenPort(resetFn = { _, _, _ -> called = true; error("must not run") })
        val thrown = runCatching { port.resetSyncStateAndOpenWithPassword("/vault", byteArrayOf(1)) }
            .exceptionOrNull()
        assertTrue(thrown is VaultBrowseError.Failed, "got $thrown")
        assertTrue(!called, "the binding must not run without a state dir")
    }
}
