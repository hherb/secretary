package org.secretary.sync.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.ui.graphics.vector.ImageVector
import org.secretary.sync.SyncBadgeState

// ---------------------------------------------------------------------------
// Named time-bucket constants — no magic numbers in logic below.
// ---------------------------------------------------------------------------

private const val MINUTE_MS = 60_000L
private const val HOUR_MS = 60 * MINUTE_MS
private const val DAY_MS = 24 * HOUR_MS

/** Under this threshold the elapsed time reads as "just now". */
private const val JUST_NOW_CUTOFF_MS = MINUTE_MS

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

/**
 * Returns a human-readable relative-time string for a sync that completed at [sinceMs]
 * epoch millis, evaluated at [nowMs] epoch millis.
 *
 * This function is **pure** — it never reads the real clock. The caller is responsible for
 * supplying `nowMs` (e.g. `System.currentTimeMillis().toULong()`) at render time, which
 * makes the output trivially testable on the JVM host without an emulator.
 *
 * A [sinceMs] ahead of [nowMs] (clock skew) clamps to "just now".
 */
fun relativeSyncedLabel(sinceMs: ULong, nowMs: ULong): String {
    if (nowMs < sinceMs) return "just now" // clock skew: sinceMs is in the future
    val deltaMs: Long = (nowMs - sinceMs).toLong()
    return when {
        deltaMs < JUST_NOW_CUTOFF_MS -> "just now"
        deltaMs < HOUR_MS -> "${deltaMs / MINUTE_MS}m ago"
        deltaMs < DAY_MS -> "${deltaMs / HOUR_MS}h ago"
        else -> "${deltaMs / DAY_MS}d ago"
    }
}

/**
 * Returns the display label for a [SyncBadgeState], evaluated at [nowMs] epoch millis.
 *
 * This function is **pure** — it never reads the real clock. Supply
 * `System.currentTimeMillis().toULong()` at the call site.
 */
fun badgeLabel(state: SyncBadgeState, nowMs: ULong): String = when (state) {
    SyncBadgeState.NeverSynced -> "Never synced"
    is SyncBadgeState.Synced -> "Synced ${relativeSyncedLabel(state.sinceMs, nowMs)}"
    SyncBadgeState.ChangesDetected -> "Changes detected"
    SyncBadgeState.ReviewNeeded -> "Review needed"
    SyncBadgeState.Syncing -> "Syncing…"
}

// ---------------------------------------------------------------------------
// Icon helper
// ---------------------------------------------------------------------------

/**
 * Returns the [ImageVector] icon for a [SyncBadgeState].
 *
 * All icons are sourced from `material-icons-core` (the default bundled set) to avoid
 * pulling in the ~10 MB `material-icons-extended` artifact for a handful of icons.
 *
 * **Note on the [SyncBadgeState.Syncing] arm:** its icon is never displayed in practice —
 * the badge composable renders an indeterminate spinner for the syncing state instead.
 * It is mapped to [Icons.Default.Refresh] as a reasonable placeholder so that this `when`
 * remains exhaustive and any future refactor that drops the spinner falls back gracefully.
 */
fun badgeIcon(state: SyncBadgeState): ImageVector = when (state) {
    SyncBadgeState.NeverSynced -> Icons.Default.Info
    is SyncBadgeState.Synced -> Icons.Default.CheckCircle
    SyncBadgeState.ChangesDetected -> Icons.Default.Refresh // intentionally the same icon as Syncing below; do not deduplicate
    SyncBadgeState.ReviewNeeded -> Icons.Default.Warning
    SyncBadgeState.Syncing -> Icons.Default.Refresh
}
