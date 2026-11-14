package org.secretary.sync.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.sync.SyncVetoDecision

/** Test tag for the inline error shown after a failed "Sync now" (no conflict sheet open). */
const val SYNC_ERROR_TAG = "sync-error"

/**
 * Wires a [VaultSyncViewModel]'s collected state into its surfaces: the always-visible badge
 * (a tap runs "Sync now" behind the write re-auth gate), an inline error line after a failed
 * pass, and the conflict sheet (gated on [VaultSyncViewModel.pendingConflict] != null), which
 * shows its own errors. The composables stay stateless; the VM owns the
 * durable state. No password is entered here: every pass runs through the open session (#733).
 *
 * @param viewModel  The [VaultSyncViewModel] provided by the host (:kit or a test double).
 */
@Composable
fun SyncScreen(viewModel: VaultSyncViewModel) {
    val badge by viewModel.badge.collectAsStateWithLifecycle()
    val pendingConflict by viewModel.pendingConflict.collectAsStateWithLifecycle()
    val lastError by viewModel.lastError.collectAsStateWithLifecycle()

    SyncBadge(
        state = badge,
        nowMs = System.currentTimeMillis().toULong(),
        onTap = { viewModel.beginInteractiveSync() },
    )

    val error = lastError
    if (error != null && pendingConflict == null) {
        Text(
            text = syncErrorLabel(error),
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.testTag(SYNC_ERROR_TAG),
        )
    }

    pendingConflict?.let { conflict ->
        ConflictResolutionSheet(
            conflict = conflict,
            error = lastError,
            onResolve = { decisions: List<SyncVetoDecision> -> viewModel.resolve(decisions) },
            onCancel = { viewModel.cancelConflict() },
        )
    }
}
