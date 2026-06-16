package org.secretary.sync.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.sync.SyncBadgeState

class SyncRenderHelpersTest {
    private val now = 10_000_000uL // arbitrary fixed "now" in epoch millis

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
}
