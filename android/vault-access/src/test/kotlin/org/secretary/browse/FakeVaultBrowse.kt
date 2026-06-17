package org.secretary.browse

/** Build a text field whose reveal returns a canned value (host tests only). */
fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }

/** In-memory [VaultSession] for host tests. Records whether it was wiped; keyed by block uuidHex. */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
    private val blocksError: VaultBrowseError? = null,
    private val writeError: VaultBrowseError? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set
    /** The `includeDeleted` arg of the most recent readBlock call (null until first read). */
    var lastIncludeDeleted: Boolean? = null
        private set
    /** (blockHex, recordUuidHex) of each tombstone/resurrect call, in order. */
    val tombstoned: MutableList<Pair<String, String>> = mutableListOf()
    val resurrected: MutableList<Pair<String, String>> = mutableListOf()

    private val records: MutableMap<String, MutableList<RecordSummaryView>> =
        recordsByBlockHex.mapValues { it.value.toMutableList() }.toMutableMap()

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> {
        blocksError?.let { throw it }
        return blocks
    }
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        lastIncludeDeleted = includeDeleted
        readError?.let { throw it }
        val all = records[hexOfBytes(blockUuid)] ?: return emptyList()
        return if (includeDeleted) all.toList() else all.filter { !it.tombstone }
    }
    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeError?.let { throw it }
        tombstoned += hexOfBytes(blockUuid) to hexOfBytes(recordUuid)
        flipTombstone(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = true)
    }
    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeError?.let { throw it }
        resurrected += hexOfBytes(blockUuid) to hexOfBytes(recordUuid)
        flipTombstone(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = false)
    }
    override fun wipe() { wiped = true }

    private fun flipTombstone(blockHex: String, recordHex: String, tombstone: Boolean) {
        val list = records[blockHex] ?: return
        val i = list.indexOfFirst { it.uuidHex == recordHex }
        if (i >= 0) list[i] = list[i].copy(tombstone = tombstone)
    }
}

/** Scriptable [VaultOpenPort]: returns [session] or throws [openError]; records opened folders. */
class FakeVaultOpenPort(
    private val session: VaultSession = FakeVaultSession("00", emptyList()),
    private val openError: VaultBrowseError? = null,
) : VaultOpenPort {
    val openedFolders: MutableList<String> = mutableListOf()
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession {
        openedFolders += vaultFolder
        openError?.let { throw it }
        return session
    }
}
