package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.secretary.browse.VaultLocation
import org.secretary.mirror.PendingFlushNotPersisted
import org.secretary.mirror.VaultMirrorException
import java.io.File

class CloudCreateErrorRoutingTest {
    private fun target() = CloudVaultTarget(
        VaultLocation("V", "content://tree/x", ""), File("/tmp/wc"), isCreate = true,
    )

    @Test
    fun `pendingFlushNotPersisted is flagged as unsynced create`() {
        val r = cloudOpenFailureRoute(PendingFlushNotPersisted("deadbeef", RuntimeException("io")), target())
        assertTrue(r.createdButNotSynced, "must surface the un-synced-create warning")
        assertTrue(r.target.isCreate, "must stay on the create target (no materialize on reopen)")
    }

    @Test
    fun `ordinary failure is a plain retry`() {
        val r = cloudOpenFailureRoute(VaultMirrorException("offline"), target())
        assertEquals(false, r.createdButNotSynced)
        assertTrue(r.target.isCreate)
    }
}
