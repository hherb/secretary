package org.secretary.browse.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.secretary.browse.BlockNameDialogState
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView

/** Create/rename a block: one text field + confirm/cancel. Seeded from the current name on rename. */
@Composable
fun BlockNameDialog(
    state: BlockNameDialogState,
    onConfirm: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val initial = (state as? BlockNameDialogState.RenameBlock)?.currentName ?: ""
    var name by remember(state) { mutableStateOf(initial) }
    val title = if (state is BlockNameDialogState.RenameBlock) "Rename block" else "New block"
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("block-name-field"),
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(name) }, modifier = Modifier.testTag("block-name-confirm")) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel, modifier = Modifier.testTag("block-name-cancel")) { Text("Cancel") }
        },
    )
}

/** Move-record picker: lists every block except [sourceBlockUuidHex]; tap one to move. */
@Composable
fun MovePickerDialog(
    record: RecordSummaryView,
    blocks: List<BlockSummaryView>,
    sourceBlockUuidHex: String,
    onPick: (BlockSummaryView) -> Unit,
    onCancel: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Move \"${record.type}\" to block") },
        text = {
            Column {
                blocks.filter { it.uuidHex != sourceBlockUuidHex }.forEach { b ->
                    Text(
                        text = b.name,
                        modifier = Modifier.fillMaxWidth()
                            .clickable { onPick(b) }
                            .padding(vertical = 12.dp)
                            .testTag("move-target-${b.uuidHex}"),
                    )
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onCancel, modifier = Modifier.testTag("move-cancel")) { Text("Cancel") }
        },
    )
}
