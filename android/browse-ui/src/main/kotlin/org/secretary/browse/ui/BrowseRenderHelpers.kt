package org.secretary.browse.ui

import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView

private const val UNTITLED_RECORD = "Untitled record"
private const val UNTITLED_BLOCK = "Untitled block"
private const val DELETED_PREFIX = "(deleted) "
private const val TAG_SEPARATOR = " · "

/**
 * Pure human label for a record row: `type` optionally suffixed with its first tag, prefixed with a
 * deleted marker for tombstones. Never reads a field value (metadata only). Empty type → placeholder.
 */
fun recordTitle(record: RecordSummaryView): String {
    val base = record.type.ifBlank { UNTITLED_RECORD }
    val withTag = if (record.tags.isEmpty()) base else "$base$TAG_SEPARATOR${record.tags.first()}"
    return if (record.tombstone) "$DELETED_PREFIX$withTag" else withTag
}

/** Pure label for a block row: its name, or a placeholder when blank. */
fun blockLabel(block: BlockSummaryView): String = block.name.ifBlank { UNTITLED_BLOCK }
