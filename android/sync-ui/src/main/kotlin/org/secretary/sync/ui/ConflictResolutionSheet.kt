package org.secretary.sync.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncVeto
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncError
import org.secretary.sync.collectDecisions

const val CONFLICT_APPLY_TAG = "conflict-apply"
const val CONFLICT_ERROR_TAG = "conflict-error"

private val CONFLICT_PADDING = 16.dp
private val CONFLICT_GAP = 12.dp
// Show only a device-id prefix, never the full hex. This is acceptable because the device UUID is
// non-secret metadata — it is already surfaced in the badge's vector-clock / SyncStatus.deviceClocks
// display; the prefix is enough to distinguish devices without exposing the full identifier.
private const val PEER_DEVICE_PREFIX_LEN = 8

/** Bottom-sheet wrapper; testable body is [ConflictSheetContent]. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConflictResolutionSheet(
    conflict: PendingConflict,
    error: VaultSyncError?,
    onResolve: (List<SyncVetoDecision>) -> Unit,
    onCancel: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onCancel) {
        ConflictSheetContent(conflict = conflict, error = error, onResolve = onResolve, onCancel = onCancel)
    }
}

/**
 * Metadata-only conflict resolution, mirroring desktop D.1.15 (the metadata-only conflict sheet).
 * One card per [SyncVeto] with a per-record Keep-mine / Accept-delete choice (default Keep mine).
 * A read-only summary lists the auto-merged field collisions. NO secret field VALUE is shown —
 * `fieldNames` only (anti-oracle). Tags are user-controlled labels classified as non-secret
 * metadata (same as the browse path) and are rendered verbatim; only field NAMES (never values)
 * and a device-id prefix are shown — anti-oracle.
 * Decisions are assembled via the shared [collectDecisions] (default `keepLocal = true`). The sheet
 * stays open on error; the caller keeps it presented until a clean resolve clears `pendingConflict`.
 */
@Composable
fun ConflictSheetContent(
    conflict: PendingConflict,
    error: VaultSyncError?,
    onResolve: (List<SyncVetoDecision>) -> Unit,
    onCancel: () -> Unit,
) {
    // recordUuidHex -> keepLocal override; absent means "Keep mine" (default via collectDecisions).
    val overrides = remember { mutableStateMapOf<String, Boolean>() }
    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(CONFLICT_PADDING),
        verticalArrangement = Arrangement.spacedBy(CONFLICT_GAP),
    ) {
        // TODO(i18n): extract user-facing strings to string resources when i18n infra is added.
        Text(text = "Resolve sync conflicts")
        conflict.vetoes.forEach { veto -> VetoCard(veto, overrides) }

        val mergedFieldCount = conflict.collisions.sumOf { it.fieldNames.size }
        if (mergedFieldCount > 0) {
            Text(text = "$mergedFieldCount field(s) auto-merged — no action needed")
        }
        if (error != null) {
            Text(text = syncErrorLabel(error), modifier = Modifier.testTag(CONFLICT_ERROR_TAG))
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = onCancel) { Text("Cancel") }
            // Apply is always enabled: untouched records default to Keep mine (no data loss);
            // decisionsComplete gating is deliberately deferred.
            Button(
                onClick = { onResolve(collectDecisions(conflict.vetoes, overrides.toMap())) },
                modifier = Modifier.testTag(CONFLICT_APPLY_TAG),
            ) { Text("Apply") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VetoCard(veto: SyncVeto, overrides: MutableMap<String, Boolean>) {
    val keepLocal = overrides[veto.recordUuidHex] ?: true
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(CONFLICT_PADDING),
            verticalArrangement = Arrangement.spacedBy(CONFLICT_GAP),
        ) {
            Text(text = veto.recordType)
            if (veto.tags.isNotEmpty()) Text(text = veto.tags.joinToString(" · "))
            if (veto.fieldNames.isNotEmpty()) Text(text = veto.fieldNames.joinToString(", "))
            Text(text = "deleted on device ${veto.peerDeviceHex.take(PEER_DEVICE_PREFIX_LEN)}")
            Row(horizontalArrangement = Arrangement.spacedBy(CONFLICT_GAP)) {
                FilterChip(
                    selected = keepLocal,
                    onClick = { overrides[veto.recordUuidHex] = true },
                    label = { Text("Keep mine") },
                )
                FilterChip(
                    selected = !keepLocal,
                    onClick = { overrides[veto.recordUuidHex] = false },
                    label = { Text("Accept delete") },
                )
            }
        }
    }
}
