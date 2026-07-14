package org.secretary.browse.ui

import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.RevealedValue
import org.secretary.browse.hexOfBytes

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

/** Human-readable form of a revealed value: text as-is, bytes as lowercase hex. */
fun revealedText(value: RevealedValue): String = when (value) {
    is RevealedValue.Text -> value.value
    is RevealedValue.Bytes -> hexOfBytes(value.value)
}

/** Minimum live-block count for a record move to have a destination: the record's own block plus
 *  at least one distinct target block. */
private const val MIN_BLOCKS_TO_MOVE = 2

/** True when at least one block OTHER than the record's own exists, so a Move has a real
 *  destination. [blockCount] is the live-block count the browse VM already holds — the same
 *  collection the move picker enumerates — so below the threshold the Move affordance can only
 *  dead-end into the picker's empty state and is hidden. UX layer only: the picker empty-state and
 *  the Rust `move_record_impl` guard remain authoritative (parity with desktop #273 / mobile #429). */
fun hasMoveTargets(blockCount: Int): Boolean = blockCount >= MIN_BLOCKS_TO_MOVE
