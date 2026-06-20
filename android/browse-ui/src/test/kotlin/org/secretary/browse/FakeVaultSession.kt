package org.secretary.browse

/** Build a text field whose reveal returns a canned value (host tests only). */
fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }

/**
 * Local test-only [VaultSession] double for :browse-ui host tests. Mirrors the `:vault-access`
 * `FakeVaultSession` (which lives in that module's test source set and is not exported). Keyed by
 * block uuidHex; returns [readError] on readBlock if set.
 */
class FakeVaultSession(
    private val vaultUuidHex: String,
    blocks: List<BlockSummaryView>,
    recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set

    val appended: MutableList<Pair<String, RecordContentInput>> = mutableListOf()
    val edited: MutableList<Triple<String, String, RecordContentInput>> = mutableListOf()
    val created: MutableList<String> = mutableListOf()
    val renamed: MutableList<Pair<String, String>> = mutableListOf()         // blockHex -> newName
    val moved: MutableList<Triple<String, String, String>> = mutableListOf() // srcHex, tgtHex, recHex
    private var nextFakeUuidByte: Int = 0xA0
    private var nextFakeBlockByte: Int = 0xB0

    private val mutableBlocks: MutableList<BlockSummaryView> = blocks.toMutableList()
    private val records: MutableMap<String, MutableList<RecordSummaryView>> =
        recordsByBlockHex.mapValues { it.value.toMutableList() }.toMutableMap()

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> = mutableBlocks.toList()
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        readError?.let { throw it }
        val all = records[hexOfBytes(blockUuid)] ?: return emptyList()
        return if (includeDeleted) all.toList() else all.filter { !it.tombstone }
    }
    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        flip(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = true)
    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        flip(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = false)

    override suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray {
        val blockHex = hexOfBytes(blockUuid)
        appended += blockHex to content
        val uuid = ByteArray(16).also { it[15] = (nextFakeUuidByte and 0xff).toByte() }
        nextFakeUuidByte += 1
        val list = records.getOrPut(blockHex) { mutableListOf() }
        list += RecordSummaryView(
            uuidHex = hexOfBytes(uuid),
            type = content.recordType,
            tags = content.tags,
            createdAtMs = 0u,
            lastModMs = 0u,
            tombstone = false,
            fields = content.fields.map { it.toRevealableField() },
        )
        return uuid
    }

    override suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput) {
        val blockHex = hexOfBytes(blockUuid)
        val recordHex = hexOfBytes(recordUuid)
        edited += Triple(blockHex, recordHex, content)
        val list = records[blockHex]
        val i = list?.indexOfFirst { it.uuidHex == recordHex } ?: -1
        if (i < 0) throw VaultBrowseError.RecordNotFound(recordHex)
        list!![i] = list[i].copy(
            type = content.recordType,
            tags = content.tags,
            fields = content.fields.map { it.toRevealableField() },
        )
    }

    override suspend fun createBlock(blockName: String): ByteArray {
        val uuid = ByteArray(16).also { it[15] = (nextFakeBlockByte and 0xff).toByte() }
        nextFakeBlockByte += 1
        created += blockName
        mutableBlocks += BlockSummaryView(uuid, blockName, 0u, 0u)
        records.getOrPut(hexOfBytes(uuid)) { mutableListOf() }
        return uuid
    }

    override suspend fun renameBlock(blockUuid: ByteArray, newName: String) {
        val hex = hexOfBytes(blockUuid)
        val i = mutableBlocks.indexOfFirst { it.uuidHex == hex }
        if (i < 0) throw VaultBrowseError.BlockNotFound(hex)
        renamed += hex to newName
        val b = mutableBlocks[i]
        mutableBlocks[i] = BlockSummaryView(b.uuid, newName, b.createdAtMs, b.lastModifiedMs)
    }

    override suspend fun moveRecord(
        sourceBlockUuid: ByteArray,
        targetBlockUuid: ByteArray,
        sourceRecordUuid: ByteArray,
    ): ByteArray {
        val srcHex = hexOfBytes(sourceBlockUuid)
        val tgtHex = hexOfBytes(targetBlockUuid)
        val recHex = hexOfBytes(sourceRecordUuid)
        moved += Triple(srcHex, tgtHex, recHex)
        val srcList = records[srcHex] ?: throw VaultBrowseError.BlockNotFound(srcHex)
        val si = srcList.indexOfFirst { it.uuidHex == recHex && !it.tombstone }
        if (si < 0) throw VaultBrowseError.RecordNotFound(recHex)
        val moving = srcList[si]
        val newUuid = ByteArray(16).also { it[15] = (nextFakeUuidByte and 0xff).toByte() }
        nextFakeUuidByte += 1
        records.getOrPut(tgtHex) { mutableListOf() } += moving.copy(uuidHex = hexOfBytes(newUuid))
        srcList[si] = moving.copy(tombstone = true)
        return newUuid
    }

    override fun wipe() { wiped = true }

    private fun flip(blockHex: String, recordHex: String, tombstone: Boolean) {
        val list = records[blockHex] ?: return
        val i = list.indexOfFirst { it.uuidHex == recordHex }
        if (i >= 0) list[i] = list[i].copy(tombstone = tombstone)
    }
}

private fun FieldContentInput.toRevealableField(): RevealableField = when (val v = value) {
    is FieldContentValue.Text -> RevealableField(name, FieldKind.Text) { RevealedValue.Text(v.value) }
    is FieldContentValue.Bytes -> RevealableField(name, FieldKind.Bytes) { RevealedValue.Bytes(v.value) }
}
