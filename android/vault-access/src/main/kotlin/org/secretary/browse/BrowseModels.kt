package org.secretary.browse

/**
 * Metadata for one vault block (no records decrypted). Holds the raw 16-byte [uuid] because the
 * session needs it to call `read_block`; [uuidHex] is the string identity for UI keys.
 *
 * NOT a data class: a data class over a [ByteArray] gives referential equals/hashCode. Treat
 * [uuidHex] as identity. Mirror of iOS `BlockSummary`.
 */
class BlockSummaryView(
    val uuid: ByteArray,
    val name: String,
    val createdAtMs: ULong,
    val lastModifiedMs: ULong,
) {
    val uuidHex: String get() = hexOfBytes(uuid)
}

/**
 * Metadata-only view of one record. Deliberately carries NO secret value — only the field *names*
 * (metadata). Reveal-on-tap (`expose_text`/`expose_bytes`) is a deferred slice; this type having no
 * value field is the structural guarantee that no secret is materialized while browsing.
 * Mirror of iOS `RecordView` minus the reveal closures.
 */
data class RecordSummaryView(
    val uuidHex: String,
    val type: String,
    val tags: List<String>,
    val createdAtMs: ULong,
    val lastModMs: ULong,
    val tombstone: Boolean,
    val fieldNames: List<String>,
)
