package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Presentation state of the single block-name dialog (create OR rename). */
sealed interface BlockNameDialogState {
    /** The dialog is collecting a name for a brand-new block. */
    data object CreateBlock : BlockNameDialogState

    /** The dialog is renaming the block [blockUuid], pre-filled with [currentName]. */
    data class RenameBlock(val blockUuid: ByteArray, val currentName: String) : BlockNameDialogState {
        override fun equals(other: Any?): Boolean =
            other is RenameBlock && blockUuid.contentEquals(other.blockUuid) && currentName == other.currentName
        override fun hashCode(): Int = 31 * blockUuid.contentHashCode() + currentName.hashCode()
    }
}

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
class VaultBrowseModel(
    private val session: VaultSession,
    private val gate: WriteReauthGate = NoopReauthGate,
) {
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

    private val _writing = MutableStateFlow(false)
    /** True while a delete/restore write is in flight. Disables ALL delete/restore buttons in the UI
     *  (global flag — writes serialize under the session lock, so no concurrent write is allowed). */
    val writing: StateFlow<Boolean> = _writing.asStateFlow()

    private val _blockNameDialog = MutableStateFlow<BlockNameDialogState?>(null)
    /** Non-null when the create/rename-block name dialog is open. Cleared on confirm-success / cancel / lock. */
    val blockNameDialog: StateFlow<BlockNameDialogState?> = _blockNameDialog.asStateFlow()

    private val _movingRecord = MutableStateFlow<RecordSummaryView?>(null)
    /** Non-null when the move-record block-picker is open; the picker lists `blocks` minus the
     *  source (selected) block. Cleared on confirm-success / cancel / lock. */
    val movingRecord: StateFlow<RecordSummaryView?> = _movingRecord.asStateFlow()

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

    /** Soft-delete [record] (after a presence proof), then re-read the selected block. */
    suspend fun delete(record: RecordSummaryView) =
        commitThenReload("Confirm deleting this entry") { block ->
            session.tombstoneRecord(block.uuid, hexToBytes(record.uuidHex))
        }

    /** Restore [record] (after a presence proof), then re-read. */
    suspend fun restore(record: RecordSummaryView) =
        commitThenReload("Confirm restoring this entry") { block ->
            session.resurrectRecord(block.uuid, hexToBytes(record.uuidHex))
        }

    /** Open a blank add form for the selected block. No-op if no block is selected. */
    fun startAdd() {
        val block = _selectedBlock.value ?: return
        _editing.value = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Add, gate)
    }

    /** Open an edit form prefilled from [record] (reveals its fields into the form). No-op if no
     *  block is selected. */
    fun startEdit(record: RecordSummaryView) {
        val block = _selectedBlock.value ?: return
        val model = RecordEditModel(session, block.uuid, RecordEditModel.Mode.Edit(hexToBytes(record.uuidHex)), gate)
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
     * Re-entrancy + error-preservation core shared by record writes (delete/restore/edit) and
     * block-list writes (create/rename/move). Runs [op]; on success runs [reload]; a typed failure
     * surfaces via [error] and skips [reload] (the visible list stays intact). No-op if a write is
     * already in flight.
     */
    private suspend fun guardedWrite(
        reason: String,
        reload: suspend () -> Unit,
        op: suspend () -> Unit,
    ) {
        if (_writing.value) return
        _writing.value = true
        try {
            // Note: CancellationException is NOT caught here — it propagates past these
            // DeviceUnlockError catches so coroutine cancellation is never swallowed.
            // Do NOT widen these catches to catch (e: Exception).
            try {
                gate.authorizeWrite(reason)
            } catch (e: DeviceUnlockError.UserCancelled) {
                return // silent: no write, no error; the originating dialog stays open (op never ran)
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(reauthFailedMessage(e))
                return
            }
            try {
                op()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }
            reload()
        } finally {
            _writing.value = false
        }
    }

    /**
     * Run a mutation against the selected block, then re-read on SUCCESS only. A failed mutation
     * surfaces [error] but deliberately leaves [selectedRecords] (and any reveal) intact — a rejected
     * delete must not blank the visible list. No-op if no block is selected or a write is already
     * in flight (global re-entrancy guard — writes serialize under the session lock). Mirror of iOS commitThenReload.
     */
    private suspend fun commitThenReload(reason: String, op: suspend (BlockSummaryView) -> Unit) {
        val block = _selectedBlock.value ?: return
        guardedWrite(reason, reload = { selectBlock(block) }) { op(block) }
    }

    /** Open the create-block name dialog. */
    fun startCreateBlock() { _blockNameDialog.value = BlockNameDialogState.CreateBlock }

    /** Open the rename-block dialog for [block], pre-filled with its current name. */
    fun startRenameBlock(block: BlockSummaryView) {
        _blockNameDialog.value = BlockNameDialogState.RenameBlock(block.uuid, block.name)
    }

    /** Dismiss the block-name dialog without writing. */
    fun cancelBlockNameDialog() { _blockNameDialog.value = null }

    /** Open the move-record block picker for [record]. */
    fun startMoveRecord(record: RecordSummaryView) {
        _movingRecord.value = record
    }

    /** Dismiss the move picker without writing. */
    fun cancelMove() { _movingRecord.value = null }

    /**
     * Move the in-flight [movingRecord] from the selected (source) block into [target]. Defensive
     * same-block guard (the picker already excludes the source). On success: move, close the picker,
     * re-read the source so the moved record shows tombstoned/withheld. No-op if nothing is moving or
     * no block is selected.
     */
    suspend fun confirmMove(target: BlockSummaryView) {
        val record = _movingRecord.value ?: return
        val source = _selectedBlock.value ?: return
        if (target.uuid.contentEquals(source.uuid)) {
            _error.value = VaultBrowseError.InvalidArgument("cannot move a record into its own block")
            return
        }
        guardedWrite("Confirm moving this entry", reload = { selectBlock(source) }) {
            session.moveRecord(source.uuid, target.uuid, hexToBytes(record.uuidHex))
            _movingRecord.value = null
        }
    }

    /**
     * Confirm the open block-name dialog. Rejects a blank name (InvalidArgument, no write, dialog
     * stays open). On success: create or rename per the dialog state, close the dialog, refresh the
     * block summaries. No-op if no dialog is open.
     */
    suspend fun confirmBlockName(name: String) {
        val dialog = _blockNameDialog.value ?: return
        val trimmed = name.trim()
        if (trimmed.isEmpty()) {
            _error.value = VaultBrowseError.InvalidArgument("block name is empty")
            return
        }
        val reason = when (dialog) {
            BlockNameDialogState.CreateBlock -> "Confirm creating this block"
            is BlockNameDialogState.RenameBlock -> "Confirm renaming this block"
        }
        guardedWrite(reason, reload = { loadBlocks() }) {
            when (dialog) {
                BlockNameDialogState.CreateBlock -> session.createBlock(trimmed)
                is BlockNameDialogState.RenameBlock -> session.renameBlock(dialog.blockUuid, trimmed)
            }
            _blockNameDialog.value = null
        }
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
        gate.reset()
        _revealed.value = emptyMap()
        _editing.value = null
        _blockNameDialog.value = null
        _movingRecord.value = null
        _writing.value = false
        session.wipe()
        _blocks.value = emptyList()
        _selectedBlock.value = null
        _selectedRecords.value = null
        _error.value = null
    }
}
