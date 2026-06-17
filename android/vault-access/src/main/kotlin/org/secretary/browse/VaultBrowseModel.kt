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

    private val _revealed = MutableStateFlow<Map<String, RevealedValue>>(emptyMap())
    /** Currently-revealed plaintext, keyed "<recordUuidHex>/<fieldName>". Cleared on
     *  selectBlock / clearSelection / lock. Mirror of iOS VaultBrowseViewModel.revealed. */
    val revealed: StateFlow<Map<String, RevealedValue>> = _revealed.asStateFlow()

    private val _showDeleted = MutableStateFlow(false)
    /** When false (default) the list shows only live records; the Rust read_block gate withholds
     *  tombstoned records. Toggling RE-READS the selected block with the new flag — the client never
     *  holds withheld data and never filters tombstones itself. Mirror of iOS VaultBrowseViewModel.showDeleted. */
    val showDeleted: StateFlow<Boolean> = _showDeleted.asStateFlow()

    private val _editing = MutableStateFlow<RecordEditModel?>(null)
    /** Non-null when an add/edit form is open — the third UI state (alongside block-list /
     *  record-list). Cleared on cancelEdit / commit / lock. Mirror of iOS's edit-sheet presentation. */
    val editing: StateFlow<RecordEditModel?> = _editing.asStateFlow()

    /** Set the show-deleted flag; on a real change, re-read the selected block (if any). */
    suspend fun setShowDeleted(value: Boolean) {
        if (value == _showDeleted.value) return
        _showDeleted.value = value
        _selectedBlock.value?.let { selectBlock(it) }
    }

    /** Publish the manifest's block summaries (in-memory metadata; no decryption). */
    fun loadBlocks() {
        _error.value = null
        try {
            _blocks.value = session.blockSummaries()
        } catch (e: VaultBrowseError) {
            _error.value = e
            _blocks.value = emptyList()
        }
    }

    /**
     * Composite reveal-map key. Collision-safe: [recordUuidHex] is always exactly 32 lowercase hex
     * chars (charset [0-9a-f]), so it can never contain the "/" separator nor alias another
     * (record, field) pair even though field names are arbitrary vault-supplied strings.
     */
    private fun revealKey(recordUuidHex: String, fieldName: String): String = "$recordUuidHex/$fieldName"

    /** Materialize one field's plaintext on explicit user action (invokes [RevealableField.reveal]). */
    fun reveal(record: RecordSummaryView, field: RevealableField) {
        try {
            _revealed.value = _revealed.value + (revealKey(record.uuidHex, field.name) to field.reveal())
        } catch (e: VaultBrowseError) {
            _error.value = e
        } catch (e: Exception) {
            // Mirror iOS: an unexpected throwable from a field lambda must not escape reveal()
            // (would crash the UI). Fold to the generic Failed arm rather than propagate.
            _error.value = VaultBrowseError.Failed(e.toString())
        }
    }

    /** Drop one revealed field. */
    fun hide(recordUuidHex: String, fieldName: String) {
        _revealed.value = _revealed.value - revealKey(recordUuidHex, fieldName)
    }

    /** Drop all revealed plaintext (e.g. on backgrounding) without locking. */
    fun hideAll() {
        _revealed.value = emptyMap()
    }

    /** Decrypt the selected block and publish its records (metadata only). Errors are captured. */
    suspend fun selectBlock(block: BlockSummaryView) {
        _revealed.value = emptyMap()
        _error.value = null
        try {
            val records = session.readBlock(block.uuid, includeDeleted = _showDeleted.value)
            _selectedBlock.value = block
            _selectedRecords.value = records
        } catch (e: VaultBrowseError) {
            _error.value = e
            _selectedBlock.value = null
            _selectedRecords.value = null
        }
    }

    /** Soft-delete [record], then re-read the selected block so the list reflects it. */
    suspend fun delete(record: RecordSummaryView) =
        commitThenReload { block -> session.tombstoneRecord(block.uuid, hexToBytes(record.uuidHex)) }

    /** Restore [record], then re-read. */
    suspend fun restore(record: RecordSummaryView) =
        commitThenReload { block -> session.resurrectRecord(block.uuid, hexToBytes(record.uuidHex)) }

    /** Open a blank add form for the selected block. No-op if no block is selected. */
    fun startAdd() {
        val block = _selectedBlock.value ?: return
        _editing.value = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Add)
    }

    /** Open an edit form prefilled from [record] (reveals its fields into the form). No-op if no
     *  block is selected. */
    fun startEdit(record: RecordSummaryView) {
        val block = _selectedBlock.value ?: return
        val model = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(record.uuidHex)))
        model.load(record)
        _editing.value = model
    }

    /** Dismiss the edit form without writing (drops its in-memory plaintext). */
    fun cancelEdit() { _editing.value = null }

    /** Called after a successful commit: drop the form and re-read the selected block so the list
     *  reflects the new/edited record (re-read on success only, like commitThenReload). */
    suspend fun onEditCommitted() {
        _editing.value = null
        _selectedBlock.value?.let { selectBlock(it) }
    }

    /**
     * Run a mutation against the selected block, then re-read on SUCCESS only. A failed mutation
     * surfaces [error] but deliberately leaves [selectedRecords] (and any reveal) intact — a rejected
     * delete must not blank the visible list. No-op if no block is selected. Mirror of iOS commitThenReload.
     */
    private suspend fun commitThenReload(op: suspend (BlockSummaryView) -> Unit) {
        val block = _selectedBlock.value ?: return
        try {
            op(block)
        } catch (e: VaultBrowseError) {
            _error.value = e
            return
        }
        selectBlock(block)
    }

    /** Return to the block list, clearing any read error left from a failed selection. */
    fun clearSelection() {
        _revealed.value = emptyMap()
        _selectedBlock.value = null
        _selectedRecords.value = null
        _error.value = null
    }

    /** Wipe the session (zeroize handles) and reset every flow. Called on background / lock. */
    fun lock() {
        _revealed.value = emptyMap()
        _editing.value = null
        session.wipe()
        _blocks.value = emptyList()
        _selectedBlock.value = null
        _selectedRecords.value = null
        _error.value = null
    }
}
