package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred

/**
 * In-memory [TrashPort] test double. Seed [list]/[expired]/reports; prime [listError] to make
 * [listTrashedBlocks] throw. Records each write for assertions. Mirror of iOS `FakeTrashPort`.
 *
 * When [writeGate] is set, every suspend write awaits it before recording the call — lets a
 * test hold a write in flight while a second call hits the model's re-entrancy guard (a
 * faithful race, not a sleep).
 */
class FakeTrashPort(
    var list: List<TrashedBlockInfo> = emptyList(),
    var expired: List<ExpiredEntryInfo> = emptyList(),
    private val listError: VaultBrowseError? = null,
    private val windowMs: Long = 90L * MS_PER_DAY,
    private val writeGate: CompletableDeferred<Unit>? = null,
    var emptyTrashFilesFailed: Int = 0,
    var retentionFilesFailed: Int = 0,
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

    override suspend fun restoreBlock(uuid: ByteArray) {
        writeGate?.await()
        restored += uuid
    }

    override suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo {
        writeGate?.await()
        purged += uuid
        return PurgeResultInfo(uuid, wasShared = false, recipientCount = 0, filesRemoved = 1)
    }

    override suspend fun emptyTrash(): EmptyTrashReportInfo {
        writeGate?.await()
        emptied += 1
        return EmptyTrashReportInfo(list.size, 0, list.size, 0, list.size, emptyTrashFilesFailed)
    }

    override suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo {
        writeGate?.await()
        autoPurged += windowMs
        return RetentionReportInfo(expired.size, 0, expired.size, 0, expired.size, retentionFilesFailed, windowMs)
    }
}
