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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseError

/**
 * Metadata-only browse surface: a block list, and (when a block is selected) that block's record
 * titles with a back affordance. No secret value is ever rendered — only types/tags/field-names.
 * Loads blocks once on first composition.
 */
@Composable
fun BrowseScreen(viewModel: VaultBrowseViewModel) {
    val blocks by viewModel.blocks.collectAsStateWithLifecycle()
    val selectedBlock by viewModel.selectedBlock.collectAsStateWithLifecycle()
    val records by viewModel.selectedRecords.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { viewModel.loadBlocks() }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        error?.let { ErrorBanner(it) }
        val block = selectedBlock
        if (block == null) {
            Text("Blocks", style = MaterialTheme.typography.titleMedium)
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(blocks, key = { it.uuidHex }) { b ->
                    BlockRow(b, onClick = { viewModel.selectBlock(b) })
                    HorizontalDivider()
                }
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(blockLabel(block), style = MaterialTheme.typography.titleMedium)
                TextButton(onClick = { viewModel.back() }) { Text("Back") }
            }
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(records.orEmpty(), key = { it.uuidHex }) { r ->
                    RecordRow(r)
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun BlockRow(block: BlockSummaryView, onClick: () -> Unit) {
    Text(
        text = blockLabel(block),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp),
        style = MaterialTheme.typography.bodyLarge,
    )
}

@Composable
private fun RecordRow(record: RecordSummaryView) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
        Text(recordTitle(record), style = MaterialTheme.typography.bodyLarge)
        if (record.fieldNames.isNotEmpty()) {
            Text(
                text = record.fieldNames.joinToString(", "),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
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
