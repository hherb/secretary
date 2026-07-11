package org.secretary.browse.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.browse.PurgeNotice
import org.secretary.browse.PurgeSeverity
import org.secretary.browse.TrashedBlockInfo
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.emptyTrashConfirmBody
import org.secretary.browse.formatTrashedWhen
import org.secretary.browse.retentionSummary
import java.time.ZoneId
import java.util.Locale

/**
 * The Android Trash browser — mirror of iOS `TrashScreen`. Lists trashed blocks newest-first; each
 * row has Restore + Delete-forever icon buttons (delete confirmed via [AlertDialog]). The top bar
 * carries Empty-trash (only when non-empty) and Run-retention-now (a [ModalBottomSheet] previewing
 * the expired set against the fixed 90-day default). All destructive ops route through the model's
 * write-reauth gate; the retention preview is an ungated read.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrashScreen(viewModel: TrashBrowseViewModel, onBack: () -> Unit) {
    val entries by viewModel.entries.collectAsStateWithLifecycle()
    val writing by viewModel.writing.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val preview by viewModel.preview.collectAsStateWithLifecycle()
    val notice by viewModel.notice.collectAsStateWithLifecycle()

    var confirmDelete by remember { mutableStateOf<TrashedBlockInfo?>(null) }
    var confirmEmpty by remember { mutableStateOf(false) }
    var showRetention by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { viewModel.load() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Trash") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    // A labelled text action (not an icon): the bundled `material-icons-core` set has
                    // no distinct "run retention / cleanup" glyph, and adding `material-icons-extended`
                    // (~10 MB) for one icon is against the project's icon policy (see sync-ui). Text also
                    // keeps `Refresh` unique to the per-row Restore, so the two actions never look alike.
                    TextButton(
                        onClick = { showRetention = true },
                        enabled = !writing,
                        modifier = Modifier.testTag("run-retention"),
                    ) { Text("Retention") }
                    if (entries.isNotEmpty()) {
                        TextButton(
                            onClick = { confirmEmpty = true },
                            enabled = !writing,
                            modifier = Modifier.testTag("empty-trash"),
                        ) { Text("Empty") }
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            error?.let { TrashErrorBanner(it) }
            notice?.let { TrashNoticeBanner(it) }
            if (entries.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Trash is empty", style = MaterialTheme.typography.bodyLarge)
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(entries, key = { it.uuidHex }) { block ->
                        TrashRow(
                            block = block,
                            enabled = !writing,
                            onRestore = { viewModel.restore(block.blockUuid) },
                            onDelete = { confirmDelete = block },
                        )
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    confirmDelete?.let { block ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Delete forever?") },
            text = { Text("\"${block.blockName}\" will be permanently deleted. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.purge(block.blockUuid); confirmDelete = null
                }) { Text("Delete forever") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel") } },
        )
    }

    if (confirmEmpty) {
        AlertDialog(
            onDismissRequest = { confirmEmpty = false },
            title = { Text("Empty trash?") },
            text = { Text(emptyTrashConfirmBody(entries.size)) },
            confirmButton = {
                TextButton(onClick = { viewModel.emptyTrash(); confirmEmpty = false }) { Text("Empty trash") }
            },
            dismissButton = { TextButton(onClick = { confirmEmpty = false }) { Text("Cancel") } },
        )
    }

    if (showRetention) {
        ModalBottomSheet(
            onDismissRequest = { showRetention = false; viewModel.clearPreview() },
        ) {
            LaunchedEffect(Unit) { viewModel.previewRetention() }
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text("Run retention now", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (preview == null) "Checking…"
                    else retentionSummary(preview!!, viewModel.retentionWindowMs),
                    modifier = Modifier.padding(vertical = 12.dp).testTag("retention-summary"),
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { showRetention = false; viewModel.clearPreview() }) { Text("Cancel") }
                    TextButton(
                        onClick = { viewModel.runRetention(); showRetention = false; viewModel.clearPreview() },
                        enabled = !writing && preview?.isNotEmpty() == true,
                    ) { Text("Purge expired") }
                }
            }
        }
    }
}

@Composable
private fun TrashErrorBanner(error: VaultBrowseError) {
    val text = when (error) {
        is VaultBrowseError.ReauthFailed -> "Couldn't authorize the change: ${error.detail}"
        else -> "Trash operation failed: ${error::class.simpleName}"
    }
    Text(
        text = text,
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(16.dp).testTag("trash-error"),
    )
}

@Composable
private fun TrashNoticeBanner(notice: PurgeNotice) {
    Text(
        text = notice.text,
        color = if (notice.severity == PurgeSeverity.WARNING) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(16.dp).testTag("trash-notice"),
    )
}

@Composable
private fun TrashRow(
    block: TrashedBlockInfo,
    enabled: Boolean,
    onRestore: () -> Unit,
    onDelete: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(block.blockName, style = MaterialTheme.typography.bodyLarge)
            Text(
                "trashed ${formatTrashedWhen(block.tombstonedAtMs, ZoneId.systemDefault(), Locale.getDefault())}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(onClick = onRestore, enabled = enabled) {
            Icon(Icons.Filled.Refresh, contentDescription = "Restore ${block.blockName}")
        }
        IconButton(onClick = onDelete, enabled = enabled) {
            Icon(Icons.Filled.Delete, contentDescription = "Delete ${block.blockName} forever")
        }
    }
}
