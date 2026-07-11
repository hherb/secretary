package org.secretary.browse

/**
 * Read-only metadata for one trashed block. No secret material — the block name is plaintext in the
 * manifest; record content never leaves the core. Kotlin mirror of iOS `TrashedBlockInfo`.
 */
data class TrashedBlockInfo(
    val blockUuid: ByteArray,
    val blockName: String,
    val tombstonedAtMs: Long,
    val tombstonedBy: ByteArray,
) {
    /** Lowercase hex, no dashes — stable Compose list `key`. */
    val uuidHex: String get() = hexOfBytes(blockUuid)

    override fun equals(other: Any?): Boolean =
        other is TrashedBlockInfo &&
            blockUuid.contentEquals(other.blockUuid) &&
            blockName == other.blockName &&
            tombstonedAtMs == other.tombstonedAtMs &&
            tombstonedBy.contentEquals(other.tombstonedBy)

    override fun hashCode(): Int {
        var h = blockUuid.contentHashCode()
        h = 31 * h + blockName.hashCode()
        h = 31 * h + tombstonedAtMs.hashCode()
        h = 31 * h + tombstonedBy.contentHashCode()
        return h
    }
}

/** One trash entry eligible for retention auto-purge (preview only). Mirror of iOS `ExpiredEntryInfo`. */
data class ExpiredEntryInfo(
    val blockUuid: ByteArray,
    val tombstonedAtMs: Long,
    val ageMs: Long,
) {
    override fun equals(other: Any?): Boolean =
        other is ExpiredEntryInfo &&
            blockUuid.contentEquals(other.blockUuid) &&
            tombstonedAtMs == other.tombstonedAtMs &&
            ageMs == other.ageMs

    override fun hashCode(): Int {
        var h = blockUuid.contentHashCode()
        h = 31 * h + tombstonedAtMs.hashCode()
        h = 31 * h + ageMs.hashCode()
        return h
    }
}

/** Outcome of a single-block purge. Counts/classification only. Mirror of iOS `PurgeResultInfo`. */
data class PurgeResultInfo(
    val blockUuid: ByteArray,
    val wasShared: Boolean?,
    val recipientCount: Int?,
    val filesRemoved: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is PurgeResultInfo &&
            blockUuid.contentEquals(other.blockUuid) &&
            wasShared == other.wasShared &&
            recipientCount == other.recipientCount &&
            filesRemoved == other.filesRemoved

    override fun hashCode(): Int {
        var h = blockUuid.contentHashCode()
        h = 31 * h + (wasShared?.hashCode() ?: 0)
        h = 31 * h + (recipientCount ?: 0)
        h = 31 * h + filesRemoved
        return h
    }
}

/** Aggregate outcome of an empty-trash batch. Counts only. Mirror of iOS `EmptyTrashReportInfo`. */
data class EmptyTrashReportInfo(
    val purgedCount: Int,
    val sharedCount: Int,
    val ownerOnlyCount: Int,
    val unknownCount: Int,
    val filesRemoved: Int,
    val filesFailed: Int,
)

/** Aggregate outcome of a retention auto-purge commit. Counts + echoed window. Mirror of iOS `RetentionReportInfo`. */
data class RetentionReportInfo(
    val purgedCount: Int,
    val sharedCount: Int,
    val ownerOnlyCount: Int,
    val unknownCount: Int,
    val filesRemoved: Int,
    val filesFailed: Int,
    val windowMs: Long,
)

/**
 * The vault-trash operations a Trash browser needs. Conformed by the `:kit` adapter
 * ([org.secretary.browse.UniffiVaultSession]) and by `FakeTrashPort` in tests. Kotlin mirror of the
 * iOS `TrashPort` protocol. Reports are returned (plumbed for #411) but the VM discards them.
 *
 * Reads ([listTrashedBlocks]/[expiredTrashEntries]/[defaultRetentionWindowMs]) are synchronous
 * in-memory manifest reads (no decryption). Writes are `suspend` — the real adapter offloads the
 * FFI write to the IO dispatcher, like [VaultSession.tombstoneRecord].
 */
interface TrashPort {
    /** All not-yet-purged trashed blocks, projected by name. */
    fun listTrashedBlocks(): List<TrashedBlockInfo>

    /** Retention preview for [windowMs] (adapter supplies `now`). Non-throwing (empty on wiped). */
    fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo>

    /** The frozen default retention window (90 days, in ms). */
    fun defaultRetentionWindowMs(): Long

    /** Restore the newest trashed copy of a block. */
    suspend fun restoreBlock(uuid: ByteArray)

    /** Permanently purge one trashed block. */
    suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo

    /** Permanently purge every currently-trashed block. */
    suspend fun emptyTrash(): EmptyTrashReportInfo

    /** Permanently purge every trashed block older than [windowMs]. */
    suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo
}
