package org.secretary.browse

/** In-memory [VaultSession] for host tests. Records whether it was wiped; keyed by block uuidHex. */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    private val recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> = blocks
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        readError?.let { throw it }
        return recordsByBlockHex[hexOfBytes(blockUuid)] ?: emptyList()
    }
    override fun wipe() { wiped = true }
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
