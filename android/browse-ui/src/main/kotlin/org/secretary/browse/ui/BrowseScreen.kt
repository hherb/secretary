package org.secretary.browse.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import org.secretary.browse.BlockNameDialogState
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.RevealPolicy
import org.secretary.browse.RevealableField
import org.secretary.browse.RevealedValue
import org.secretary.browse.VaultBrowseError

/** Milliseconds per second — auto-hide policy is expressed in seconds; Compose delay takes millis. */
private const val MILLIS_PER_SECOND: Long = 1000L

/**
 * Metadata-only browse surface: a block list, and (when a block is selected) that block's record
 * titles with a back affordance. Revealed field values are shown per-field and auto-hidden after
 * [autoHideMillis] milliseconds.
 * Loads blocks once on first composition.
 */
@Composable
fun BrowseScreen(
    viewModel: VaultBrowseViewModel,
    autoHideMillis: Long = RevealPolicy.autoHideSeconds * MILLIS_PER_SECOND,
) {
    val blocks by viewModel.blocks.collectAsStateWithLifecycle()
    val selectedBlock by viewModel.selectedBlock.collectAsStateWithLifecycle()
    val records by viewModel.selectedRecords.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val revealed by viewModel.revealed.collectAsStateWithLifecycle()
    val showDeleted by viewModel.showDeleted.collectAsStateWithLifecycle()
    val editing by viewModel.editing.collectAsStateWithLifecycle()
    val writing by viewModel.writing.collectAsStateWithLifecycle()
    val blockNameDialog by viewModel.blockNameDialog.collectAsStateWithLifecycle()
    val movingRecord by viewModel.movingRecord.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { viewModel.loadBlocks() }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        // Dialogs rendered first so they overlay whichever branch is active and are not
        // skipped by any early return@Column inside the block/record branches.
        blockNameDialog?.let { state ->
            BlockNameDialog(
                state = state,
                onConfirm = { viewModel.confirmBlockName(it) },
                onCancel = { viewModel.cancelBlockNameDialog() },
            )
        }
        movingRecord?.let { rec ->
            MovePickerDialog(
                record = rec,
                blocks = blocks,
                sourceBlockUuidHex = selectedBlock?.uuidHex ?: "",
                onPick = { viewModel.confirmMove(it) },
                onCancel = { viewModel.cancelMove() },
            )
        }
        val editModel = editing
        if (editModel != null) {
            val committed by editModel.committed.collectAsStateWithLifecycle()
            LaunchedEffect(committed) { if (committed) viewModel.onEditCommitted() }
            RecordEditForm(
                model = editModel,
                onCommit = viewModel::commitEdit,
                onCancel = viewModel::cancelEdit,
            )
            return@Column
        }
        error?.let { ErrorBanner(it) }
        val block = selectedBlock
        if (block == null) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Blocks", style = MaterialTheme.typography.titleMedium)
                TextButton(
                    onClick = { viewModel.startCreateBlock() },
                    enabled = !writing,
                    modifier = Modifier.testTag("new-block"),
                ) { Text("New block") }
            }
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(blocks, key = { it.uuidHex }) { b ->
                    BlockRow(b, writing = writing, onClick = { viewModel.selectBlock(b) }, onRename = { viewModel.startRenameBlock(b) })
                    HorizontalDivider()
                }
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(blockLabel(block), style = MaterialTheme.typography.titleMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(
                        onClick = { viewModel.startAdd() },
                        enabled = !writing,
                        modifier = Modifier.testTag("add-record"),
                    ) { Text("Add") }
                    TextButton(
                        onClick = { viewModel.back() },
                        modifier = Modifier.testTag("back-to-blocks"),
                    ) { Text("Back") }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("Show deleted", style = MaterialTheme.typography.bodyMedium)
                Switch(
                    checked = showDeleted,
                    onCheckedChange = { viewModel.setShowDeleted(it) },
                    modifier = Modifier.testTag("toggle-show-deleted"),
                )
            }
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(records.orEmpty(), key = { it.uuidHex }) { r ->
                    RecordRow(
                        record = r,
                        revealed = revealed,
                        autoHideMillis = autoHideMillis,
                        writing = writing,
                        onReveal = viewModel::reveal,
                        onHide = viewModel::hide,
                        onDelete = viewModel::delete,
                        onRestore = viewModel::restore,
                        onEdit = viewModel::startEdit,
                        onMove = viewModel::startMoveRecord,
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun BlockRow(block: BlockSummaryView, writing: Boolean, onClick: () -> Unit, onRename: () -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(
            text = blockLabel(block),
            modifier = Modifier.weight(1f).clickable(onClick = onClick).padding(vertical = 12.dp),
            style = MaterialTheme.typography.bodyLarge,
        )
        TextButton(onClick = onRename, enabled = !writing, modifier = Modifier.testTag("rename-${block.uuidHex}")) {
            Text("Rename")
        }
    }
}

@Composable
private fun RecordRow(
    record: RecordSummaryView,
    revealed: Map<String, RevealedValue>,
    autoHideMillis: Long,
    writing: Boolean,
    onReveal: (RecordSummaryView, RevealableField) -> Unit,
    onHide: (String, String) -> Unit,
    onDelete: (RecordSummaryView) -> Unit,
    onRestore: (RecordSummaryView) -> Unit,
    onEdit: (RecordSummaryView) -> Unit,
    onMove: (RecordSummaryView) -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(recordTitle(record), style = MaterialTheme.typography.bodyLarge)
            if (record.tombstone) {
                TextButton(
                    onClick = { onRestore(record) },
                    enabled = !writing,
                    modifier = Modifier.testTag("restore-${record.uuidHex}"),
                ) { Text("Restore") }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(
                        onClick = { onEdit(record) },
                        modifier = Modifier.testTag("edit-${record.uuidHex}"),
                    ) { Text("Edit") }
                    TextButton(
                        onClick = { onMove(record) },
                        enabled = !writing,
                        modifier = Modifier.testTag("move-${record.uuidHex}"),
                    ) { Text("Move") }
                    TextButton(
                        onClick = { onDelete(record) },
                        enabled = !writing,
                        modifier = Modifier.testTag("delete-${record.uuidHex}"),
                    ) { Text("Delete") }
                }
            }
        }
        record.fields.forEach { field ->
            val key = "${record.uuidHex}/${field.name}"
            val value = revealed[key]
            FieldRow(
                record = record,
                field = field,
                value = value,
                autoHideMillis = autoHideMillis,
                onReveal = onReveal,
                onHide = onHide,
            )
        }
    }
}

@Composable
private fun FieldRow(
    record: RecordSummaryView,
    field: RevealableField,
    value: RevealedValue?,
    autoHideMillis: Long,
    onReveal: (RecordSummaryView, RevealableField) -> Unit,
    onHide: (String, String) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(field.name, style = MaterialTheme.typography.bodySmall)
            if (value != null) {
                Text(
                    text = revealedText(value),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag("value-${record.uuidHex}-${field.name}"),
                )
            }
        }
        TextButton(
            onClick = {
                if (value == null) onReveal(record, field) else onHide(record.uuidHex, field.name)
            },
            modifier = Modifier.testTag("reveal-${record.uuidHex}-${field.name}"),
        ) {
            Text(if (value == null) "Reveal" else "Hide")
        }
    }
    // Auto-hide: keyed on the revealed value's presence so re-revealing restarts the timer.
    if (value != null) {
        LaunchedEffect(record.uuidHex, field.name, value) {
            delay(autoHideMillis)
            onHide(record.uuidHex, field.name)
        }
    }
}

@Composable
private fun ErrorBanner(error: VaultBrowseError) {
    Text(
        text = "Couldn't read the vault: ${error::class.simpleName}",
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(bottom = 8.dp),
    )
}
