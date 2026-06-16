package org.secretary.sync

/**
 * The advisory sync state shown on the badge. Mirror of the iOS SyncBadgeState
 * (docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md). Rendering — including the
 * relative "synced N min ago" label derived from [Synced.sinceMs] — is a slice-5 UI concern;
 * this type only carries the discrete state.
 */
sealed interface SyncBadgeState {
    /** No sync state has ever been written for this vault. */
    data object NeverSynced : SyncBadgeState

    /** Last successful state write at [sinceMs] (epoch millis), for a relative-time label. */
    data class Synced(val sinceMs: ULong) : SyncBadgeState

    /** The change monitor raised a debounced "remote changes detected" signal. */
    data object ChangesDetected : SyncBadgeState

    /** A prior pass surfaced a tombstone dispute awaiting the user's decision. */
    data object ReviewNeeded : SyncBadgeState

    /** A pass is currently running. */
    data object Syncing : SyncBadgeState
}

/**
 * Pure derivation of the badge from the model's flags + the latest status snapshot.
 * Precedence (highest first): syncing → review → changes → synced → never. The single
 * [reviewNeeded] input collapses the two ways a review can be pending (the model supplies
 * `reviewNeededFlag || pendingConflict != null`): the sync-at-unlock path raises the flag
 * with no stashed conflict (password dropped), while the interactive path stashes one.
 */
fun syncBadgeState(
    inProgress: Boolean,
    pendingChanges: Boolean,
    reviewNeeded: Boolean,
    status: SyncStatus?,
): SyncBadgeState {
    val sinceMs = status?.lastStateWriteMs
    return when {
        inProgress -> SyncBadgeState.Syncing
        reviewNeeded -> SyncBadgeState.ReviewNeeded
        pendingChanges -> SyncBadgeState.ChangesDetected
        sinceMs != null -> SyncBadgeState.Synced(sinceMs)
        else -> SyncBadgeState.NeverSynced
    }
}
