package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultSyncErrorTest {
    @Test
    fun detailArmsCarryDetailAsMessage() {
        assertEquals("boom", VaultSyncError.Failed("boom").message)
        assertEquals("bad-state", VaultSyncError.StateCorrupt("bad-state").message)
        assertEquals("arg", VaultSyncError.InvalidArgument("arg").message)
    }

    @Test
    fun objectArmsAreSingletonThrowables() {
        assertSame(VaultSyncError.WrongPasswordOrCorrupt, VaultSyncError.WrongPasswordOrCorrupt)
        // Static type widened to Any so the runtime `is` check is genuine (no always-true warning).
        val stale: Any = VaultSyncError.EvidenceStale
        val noConflict: Any = VaultSyncError.NoPendingConflict
        assertTrue(stale is VaultSyncError)
        assertTrue(noConflict is Throwable)
        assertNull(VaultSyncError.InProgress.message)
    }
}
