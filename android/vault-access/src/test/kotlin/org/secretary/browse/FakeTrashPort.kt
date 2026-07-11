package org.secretary.browse

/**
 * In-memory [TrashPort] test double. Seed [list]/[expired]/reports; prime [listError] to make
 * [listTrashedBlocks] throw. Records each write for assertions. Mirror of iOS `FakeTrashPort`.
 */
class FakeTrashPort(
    var list: List<TrashedBlockInfo> = emptyList(),
    var expired: List<ExpiredEntryInfo> = emptyList(),
    private val listError: VaultBrowseError? = null,
    private val windowMs: Long = 90L * MS_PER_DAY,
) : TrashPort {
    val restored = mutableListOf<ByteArray>()
    val purged = mutableListOf<ByteArray>()
    var emptied = 0
    val autoPurged = mutableListOf<Long>()

    override fun listTrashedBlocks(): List<TrashedBlockInfo> {
        listError?.let { throw it }
        return list
    }

    override fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo> = expired

    override fun defaultRetentionWindowMs(): Long = windowMs

    override suspend fun restoreBlock(uuid: ByteArray) { restored += uuid }

    override suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo {
        purged += uuid
        return PurgeResultInfo(uuid, wasShared = false, recipientCount = 0, filesRemoved = 1)
    }

    override suspend fun emptyTrash(): EmptyTrashReportInfo {
        emptied += 1
        return EmptyTrashReportInfo(list.size, 0, list.size, 0, list.size, 0)
    }

    override suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo {
        autoPurged += windowMs
        return RetentionReportInfo(expired.size, 0, expired.size, 0, expired.size, 0, windowMs)
    }
}
