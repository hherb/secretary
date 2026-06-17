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
 * View of one record. Metadata (type/tags/timestamps/tombstone) is non-secret. Each [RevealableField]
 * carries the field NAME (metadata) plus an on-demand `reveal` lambda — plaintext is materialized
 * only when the user taps (slice 8). [fieldNames] is a computed convenience over [fields] so render
 * helpers stay unchanged. Mirror of iOS `RecordView` (whose `fields` carry the reveal closures).
 *
 * Stays a data class: a reload returns the SAME RevealableField instances from the fake, so
 * structural equality over [fields] (referential on each closure-bearing field) still holds in tests.
 */
data class RecordSummaryView(
    val uuidHex: String,
    val type: String,
    val tags: List<String>,
    val createdAtMs: ULong,
    val lastModMs: ULong,
    val tombstone: Boolean,
    val fields: List<RevealableField>,
) {
    /** Field names in iteration order — metadata only (derived from [fields]). */
    val fieldNames: List<String> get() = fields.map { it.name }
}
