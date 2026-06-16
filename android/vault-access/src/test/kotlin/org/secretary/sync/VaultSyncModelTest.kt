package org.secretary.sync

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultSyncModelTest {
    private val pw = byteArrayOf(9, 9, 9)

    private fun veto(uuid: String = "r1") =
        SyncVeto(uuid, "login", emptyList(), listOf("password"), 100uL, 200uL, "devhex")

    private class Fixture(statusWriteMs: ULong? = null) {
        val port = FakeVaultSyncPort().apply {
            statusResult = Result.success(
                SyncStatus(hasState = statusWriteMs != null, deviceClocks = emptyList(), lastStateWriteMs = statusWriteMs),
            )
        }
        val coordinator = SyncCoordinator(port, stateDir = "/state", vaultFolder = "/vault")
        val clock = FakeWallClock(currentMs = 1_000uL)
        val hook = FakeSyncMonitorHook()
        fun model(vaultUuid: ByteArray? = ByteArray(16) { 1 }) =
            VaultSyncModel(coordinator, clock, hook, vaultUuid)
    }

    @Test
    fun initialBadgeIsNeverSynced() {
        val f = Fixture()
        assertEquals(SyncBadgeState.NeverSynced, f.model().badge.value)
    }

    @Test
    fun pendingChangesRaisedFlipsBadgeToChangesDetected() {
        val f = Fixture()
        val m = f.model()
        m.pendingChangesRaised()
        assertEquals(SyncBadgeState.ChangesDetected, m.badge.value)
    }

    @Test
    fun syncAtUnlockCleanArmAcknowledgesAndStaysSilent() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(SyncOutcome.MergedClean)
        val m = f.model()
        m.pendingChangesRaised() // simulate a prior detected change
        m.syncAtUnlock(pw)
        assertEquals(1, f.hook.muteCount)        // muted before the pass
        assertEquals(1, f.hook.acknowledgeCount) // acknowledged on the clean arm
        assertFalse(m.reviewNeeded.value)
        assertNull(m.pendingConflict.value)
        // pendingChanges consumed → badge falls back (no status write → NeverSynced)
        assertEquals(SyncBadgeState.NeverSynced, m.badge.value)
        assertEquals(1_000uL, f.port.syncCalls.single().nowMs) // nowMs from the wall clock
    }

    @Test
    fun syncAtUnlockConflictRaisesReviewWithoutSurfacingConflict() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        val m = f.model()
        m.syncAtUnlock(pw)
        assertTrue(m.reviewNeeded.value)
        assertNull(m.pendingConflict.value)      // password dropped → no interactive conflict surfaced
        assertEquals(0, f.hook.acknowledgeCount) // not acknowledged (unresolved)
        assertEquals(SyncBadgeState.ReviewNeeded, m.badge.value)
    }

    @Test
    fun interactivePassConflictSurfacesPendingConflict() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        val m = f.model()
        m.runInteractivePass(pw)
        assertEquals(PendingConflict(listOf(veto()), emptyList()), m.pendingConflict.value)
        assertTrue(m.reviewNeeded.value)
        assertEquals(SyncBadgeState.ReviewNeeded, m.badge.value)
    }

    @Test
    fun interactivePassCleanArmClearsAndAcknowledges() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(SyncOutcome.AppliedAutomatically)
        val m = f.model()
        m.runInteractivePass(pw)
        assertNull(m.pendingConflict.value)
        assertFalse(m.reviewNeeded.value)
        assertEquals(1, f.hook.acknowledgeCount)
    }

    @Test
    fun resolveCleanArmClearsConflictAndAcknowledges() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        f.port.commitResults += Result.success(SyncOutcome.MergedClean)
        val m = f.model()
        m.runInteractivePass(pw)
        m.resolve(listOf(SyncVetoDecision("r1", true)), pw)
        assertNull(m.pendingConflict.value)
        assertFalse(m.reviewNeeded.value)
        assertNull(m.lastError.value)
    }

    @Test
    fun resolveEvidenceStaleKeepsConflictAndSurfacesError() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        f.port.commitResults += Result.failure(VaultSyncError.EvidenceStale)
        val m = f.model()
        m.runInteractivePass(pw)
        m.resolve(listOf(SyncVetoDecision("r1", true)), pw)
        assertEquals(PendingConflict(listOf(veto()), emptyList()), m.pendingConflict.value) // kept for retry
        assertEquals(VaultSyncError.EvidenceStale, m.lastError.value)
    }

    @Test
    fun wrongPasswordOnUnlockSurfacesErrorAndDoesNotAcknowledge() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.failure(VaultSyncError.WrongPasswordOrCorrupt)
        val m = f.model()
        m.syncAtUnlock(pw)
        assertEquals(VaultSyncError.WrongPasswordOrCorrupt, m.lastError.value)
        assertEquals(0, f.hook.acknowledgeCount)
    }

    @Test
    fun cancelConflictClosesSheetButKeepsReviewBadge() = runTest {
        val f = Fixture()
        f.port.syncResults += Result.success(
            SyncOutcome.ConflictsPending(listOf(veto()), emptyList(), byteArrayOf(7)),
        )
        val m = f.model()
        m.runInteractivePass(pw)
        m.cancelConflict()
        assertNull(m.pendingConflict.value)               // sheet closed
        assertTrue(m.reviewNeeded.value)                  // still nagging
        assertEquals(SyncBadgeState.ReviewNeeded, m.badge.value)
    }

    @Test
    fun refreshStatusUpdatesSyncedLabel() = runTest {
        val f = Fixture(statusWriteMs = 555uL)
        val m = f.model()
        m.refreshStatus()
        assertEquals(SyncBadgeState.Synced(555uL), m.badge.value)
        assertTrue(f.port.statusCalls.isNotEmpty())
    }

    @Test
    fun refreshStatusNoopsWhenVaultUuidNull() = runTest {
        val f = Fixture(statusWriteMs = 555uL)
        val m = f.model(vaultUuid = null)
        m.refreshStatus()
        assertTrue(f.port.statusCalls.isEmpty())
        assertEquals(SyncBadgeState.NeverSynced, m.badge.value)
    }
}
