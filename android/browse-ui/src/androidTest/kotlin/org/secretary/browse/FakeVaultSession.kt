package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred

/**
 * Instrumented-source VaultSession double (androidTest can't see the unit-test fake).
 *
 * Deliberately minimal subset of the host `:vault-access` `FakeVaultSession`: covers the
 * write gate and happy-path recording only. It does NOT include the `writeError` /
 * `rawWriteThrowable` error-injection fields — those are exercised in the host unit tests
 * where coroutine-test utilities are available. Do not add error-injection here; keep
 * this double focused on gate-based concurrency and happy-path instrumented scenarios.
 */
class FakeVaultSession(
    private val vaultUuidHex: String,
    blocks: List<BlockSummaryView>,
    recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val writeGate: CompletableDeferred<Unit>? = null,
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
        val all = records[hexOfBytes(blockUuid)] ?: return emptyList()
        return if (includeDeleted) all.toList() else all.filter { !it.tombstone }
    }
    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeGate?.await()
        flip(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = true)
    }
    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeGate?.await()
        flip(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = false)
    }
    override fun wipe() { wiped = true }

    override suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray {
        writeGate?.await()
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
        writeGate?.await()
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
        writeGate?.await()
        val uuid = ByteArray(16).also { it[15] = (nextFakeBlockByte and 0xff).toByte() }
        nextFakeBlockByte += 1
        created += blockName
        mutableBlocks += BlockSummaryView(uuid, blockName, 0u, 0u)
        records.getOrPut(hexOfBytes(uuid)) { mutableListOf() }
        return uuid
    }

    override suspend fun renameBlock(blockUuid: ByteArray, newName: String) {
        writeGate?.await()
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
        writeGate?.await()
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

    private fun flip(blockHex: String, recordHex: String, tombstone: Boolean) {
        val list = records[blockHex] ?: return
        val i = list.indexOfFirst { it.uuidHex == recordHex }
        if (i >= 0) list[i] = list[i].copy(tombstone = tombstone)
    }
}

fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }

private fun FieldContentInput.toRevealableField(): RevealableField = when (val v = value) {
    is FieldContentValue.Text -> RevealableField(name, FieldKind.Text) { RevealedValue.Text(v.value) }
    is FieldContentValue.Bytes -> RevealableField(name, FieldKind.Bytes) { RevealedValue.Bytes(v.value) }
}
