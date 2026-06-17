package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The host-tested heart of the Android browse UI — Kotlin mirror of the iOS VaultBrowseViewModel's
 * coordinator role (metadata-only: it never reveals a field value). It owns the [VaultSession] and
 * turns "open → list blocks → select a block → list records" into observable [StateFlow]s.
 *
 * Concurrency: main-thread-confined like the iOS @MainActor model. [selectBlock] is `suspend`
 * because the real session offloads `read_block` (AEAD) to IO; callers invoke it from the UI scope.
 *
 * Secret hygiene: no record field value is ever materialized here — [readBlock] returns metadata-only
 * [RecordSummaryView]s. [lock] wipes the session (called on background) and resets all state.
 */
class VaultBrowseModel(private val session: VaultSession) {
    private val _blocks = MutableStateFlow<List<BlockSummaryView>>(emptyList())
    val blocks: StateFlow<List<BlockSummaryView>> = _blocks.asStateFlow()

    private val _selectedBlock = MutableStateFlow<BlockSummaryView?>(null)
    val selectedBlock: StateFlow<BlockSummaryView?> = _selectedBlock.asStateFlow()

    private val _selectedRecords = MutableStateFlow<List<RecordSummaryView>?>(null)
    val selectedRecords: StateFlow<List<RecordSummaryView>?> = _selectedRecords.asStateFlow()

    private val _error = MutableStateFlow<VaultBrowseError?>(null)
    val error: StateFlow<VaultBrowseError?> = _error.asStateFlow()

    /** Publish the manifest's block summaries (in-memory metadata; no decryption). */
    fun loadBlocks() {
        _error.value = null
        _blocks.value = session.blockSummaries()
    }

    /** Decrypt the selected block and publish its records (metadata only). Errors are captured. */
    suspend fun selectBlock(block: BlockSummaryView) {
        _error.value = null
        try {
            val records = session.readBlock(block.uuid, includeDeleted = false)
            _selectedBlock.value = block
            _selectedRecords.value = records
        } catch (e: VaultBrowseError) {
            _error.value = e
            _selectedBlock.value = null
            _selectedRecords.value = null
        }
    }

    /** Return to the block list. */
    fun clearSelection() {
        _selectedBlock.value = null
        _selectedRecords.value = null
    }

    /** Wipe the session (zeroize handles) and reset every flow. Called on background / lock. */
    fun lock() {
        session.wipe()
        _blocks.value = emptyList()
        _selectedBlock.value = null
        _selectedRecords.value = null
        _error.value = null
    }
}
