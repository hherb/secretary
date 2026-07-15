package org.secretary.browse

/**
 * True when [candidate] (after trimming) matches the display name of some existing block OTHER than
 * [excludeUuid], compared **case-insensitively** (a name differing only in case reads as an
 * accidental near-duplicate). The comparison is locale-independent via
 * `String.equals(other, ignoreCase = true)` — deliberately NOT `lowercase(Locale.getDefault())`,
 * which would be locale-sensitive (Turkish-i class bugs). Trimmed to match how names are stored +
 * displayed (`session.createBlock`/`renameBlock` write trimmed names). [excludeUuid] is the block
 * being renamed (null on create), so renaming a block without changing its name is never a collision.
 * Blank -> false (the blank-name guard in VaultBrowseModel.confirmBlockName owns that case).
 *
 * Pure + FFI-free so it is host-testable without an emulator. UX-only: the write path always allows
 * duplicate names (they are UUID-keyed and harmless); this only drives a warn-but-allow affordance.
 */
fun blockNameCollides(
    candidate: String,
    existing: List<BlockSummaryView>,
    excludeUuid: ByteArray? = null,
): Boolean {
    val trimmed = candidate.trim()
    if (trimmed.isEmpty()) return false
    return existing.any { block ->
        (excludeUuid == null || !block.uuid.contentEquals(excludeUuid)) &&
            trimmed.equals(block.name, ignoreCase = true)
    }
}
