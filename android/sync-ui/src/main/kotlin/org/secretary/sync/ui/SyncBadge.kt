package org.secretary.sync.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.secretary.sync.SyncBadgeState

/** Semantic tag applied to the badge row — used by Compose UI tests to drive clicks. */
const val SYNC_BADGE_TAG = "sync-badge"

/** Semantic tag applied to the indeterminate spinner shown while [SyncBadgeState.Syncing]. */
const val SYNC_BADGE_SPINNER_TAG = "sync-badge-spinner"

private val BADGE_ICON_SIZE = 18.dp
private val BADGE_PADDING = 6.dp        // outer padding around the badge
private val BADGE_ICON_LABEL_GAP = 6.dp // gap between icon/spinner and the label

/**
 * The sync-status badge. Renders all five [SyncBadgeState]s as icon (or spinner for Syncing) +
 * a short label produced by [badgeLabel]. Tapping invokes [onTap], except while
 * [SyncBadgeState.Syncing] — a second sync pass cannot start mid-flight, so the tap is silently
 * ignored by disabling the [clickable] modifier.
 *
 * This composable is **stateless/hoisted**: it holds no [androidx.compose.runtime.remember]
 * of durable state and carries no [androidx.lifecycle.ViewModel] reference. All state flows in
 * from the caller, making it trivially driveable by instrumented Compose UI tests with literal
 * [SyncBadgeState] values.
 *
 * @param state  Current sync status to render.
 * @param nowMs  Current epoch milliseconds, evaluated by the caller at render time via
 *               `System.currentTimeMillis().toULong()`. Feeds the relative "synced N ago" label
 *               through [badgeLabel].
 * @param onTap  Invoked when the user taps the badge. Ignored while [SyncBadgeState.Syncing].
 * @param modifier Modifier chain forwarded to the outer [Row].
 */
@Composable
fun SyncBadge(
    state: SyncBadgeState,
    nowMs: ULong,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isSyncing = state is SyncBadgeState.Syncing
    Row(
        modifier = modifier
            .testTag(SYNC_BADGE_TAG)
            // Merge icon/spinner + label into one semantics node so TalkBack reads them together.
            .semantics(mergeDescendants = true) {}
            .clickable(enabled = !isSyncing, onClick = onTap)
            .padding(BADGE_PADDING),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(BADGE_ICON_LABEL_GAP),
    ) {
        if (isSyncing) {
            CircularProgressIndicator(
                modifier = Modifier
                    .size(BADGE_ICON_SIZE)
                    .testTag(SYNC_BADGE_SPINNER_TAG),
            )
        } else {
            Icon(
                imageVector = badgeIcon(state),
                contentDescription = null,
                modifier = Modifier.size(BADGE_ICON_SIZE),
            )
        }
        Text(text = badgeLabel(state, nowMs))
    }
}
