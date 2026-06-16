package org.secretary.sync.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.VaultSyncError

class SyncRenderHelpersTest {
    private val now = 1_750_000_000_000uL // realistic epoch millis (~2025-06-15); every now - offset in this file is a genuine past timestamp

    @Test
    fun relativeLabel_underAMinute_isJustNow() {
        assertEquals("just now", relativeSyncedLabel(sinceMs = now - 30_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_minutes() {
        assertEquals("3m ago", relativeSyncedLabel(sinceMs = now - 180_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_hours() {
        assertEquals("2h ago", relativeSyncedLabel(sinceMs = now - 7_200_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_days() {
        assertEquals("3d ago", relativeSyncedLabel(sinceMs = now - 259_200_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_futureClampsToJustNow() {
        // Clock skew: a sinceMs ahead of now must not underflow ULong subtraction.
        assertEquals("just now", relativeSyncedLabel(sinceMs = now + 5_000uL, nowMs = now))
    }

    @Test
    fun badgeLabel_coversEveryState() {
        assertEquals("Never synced", badgeLabel(SyncBadgeState.NeverSynced, now))
        assertEquals("Synced 3m ago", badgeLabel(SyncBadgeState.Synced(now - 180_000uL), now))
        assertEquals("Changes detected", badgeLabel(SyncBadgeState.ChangesDetected, now))
        assertEquals("Review needed", badgeLabel(SyncBadgeState.ReviewNeeded, now))
        assertEquals("Syncing…", badgeLabel(SyncBadgeState.Syncing, now))
    }

    @Test
    fun relativeLabel_exactlyOneMinute_isMinutes() {
        // 60_000 ms is NOT < JUST_NOW_CUTOFF_MS, so it falls into the minutes bucket as "1m ago".
        assertEquals("1m ago", relativeSyncedLabel(sinceMs = now - 60_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_exactlyOneHour_isHours() {
        assertEquals("1h ago", relativeSyncedLabel(sinceMs = now - 3_600_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_exactlyOneDay_isDays() {
        assertEquals("1d ago", relativeSyncedLabel(sinceMs = now - 86_400_000uL, nowMs = now))
    }

    @Test
    fun syncErrorLabel_coversEveryArm() {
        val cases = listOf(
            VaultSyncError.WrongPasswordOrCorrupt to "Wrong password, or the vault is corrupt.",
            VaultSyncError.EvidenceStale to "The vault changed while resolving — please try again.",
            VaultSyncError.DecisionsIncomplete to "Choose an option for every record.",
            VaultSyncError.InProgress to "A sync is already running.",
            VaultSyncError.StateVaultMismatch to "Sync state belongs to a different vault.",
            VaultSyncError.StateCorrupt("x") to "Sync state is corrupt.",
            VaultSyncError.NoPendingConflict to "Nothing to resolve.",
            VaultSyncError.InvalidArgument("x") to "Invalid sync request.",
            VaultSyncError.Failed("x") to "Sync failed.",
        )
        cases.forEach { (error, expected) -> assertEquals(expected, syncErrorLabel(error)) }
    }
}
