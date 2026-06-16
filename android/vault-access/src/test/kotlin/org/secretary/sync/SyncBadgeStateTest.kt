package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SyncBadgeStateTest {
    private fun status(lastWriteMs: ULong?) =
        SyncStatus(hasState = lastWriteMs != null, deviceClocks = emptyList(), lastStateWriteMs = lastWriteMs)

    @Test
    fun inProgressWinsOverEverything() {
        val badge = syncBadgeState(
            inProgress = true, pendingChanges = true, reviewNeeded = true, status = status(42uL),
        )
        assertEquals(SyncBadgeState.Syncing, badge)
    }

    @Test
    fun reviewNeededWinsOverChangesAndSynced() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = true, reviewNeeded = true, status = status(42uL),
        )
        assertEquals(SyncBadgeState.ReviewNeeded, badge)
    }

    @Test
    fun changesDetectedWinsOverSynced() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = true, reviewNeeded = false, status = status(42uL),
        )
        assertEquals(SyncBadgeState.ChangesDetected, badge)
    }

    @Test
    fun syncedCarriesLastStateWriteMs() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = false, reviewNeeded = false, status = status(42uL),
        )
        assertEquals(SyncBadgeState.Synced(42uL), badge)
    }

    @Test
    fun neverSyncedWhenNoStateWrite() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = false, reviewNeeded = false, status = status(null),
        )
        assertEquals(SyncBadgeState.NeverSynced, badge)
    }

    @Test
    fun neverSyncedWhenStatusNull() {
        val badge = syncBadgeState(
            inProgress = false, pendingChanges = false, reviewNeeded = false, status = null,
        )
        assertEquals(SyncBadgeState.NeverSynced, badge)
    }
}
