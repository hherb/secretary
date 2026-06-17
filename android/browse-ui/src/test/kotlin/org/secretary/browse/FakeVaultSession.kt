package org.secretary.browse

/**
 * Local test-only [VaultSession] double for :browse-ui host tests. Mirrors the `:vault-access`
 * `FakeVaultSession` (which lives in that module's test source set and is not exported). Keyed by
 * block uuidHex; returns [readError] on readBlock if set.
 */
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
