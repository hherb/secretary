package org.secretary.browse

/** Build a text field whose reveal returns a canned value (host tests only). */
fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }

/** In-memory [VaultSession] for host tests. Records whether it was wiped; keyed by block uuidHex. */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    private val recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
    private val blocksError: VaultBrowseError? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set
    /** The `includeDeleted` arg of the most recent readBlock call (null until first read). */
    var lastIncludeDeleted: Boolean? = null
        private set

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> {
        blocksError?.let { throw it }
        return blocks
    }
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        lastIncludeDeleted = includeDeleted
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
