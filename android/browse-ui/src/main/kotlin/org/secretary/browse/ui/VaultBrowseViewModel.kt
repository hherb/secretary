package org.secretary.browse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordEditModel
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.RevealableField
import org.secretary.browse.RevealedValue
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultBrowseModel

/**
 * Thin Compose bridge over the host-tested [VaultBrowseModel]. Holds NO browse logic — it
 * re-exposes the model's StateFlows for `collectAsStateWithLifecycle` and launches the model's
 * suspend [selectBlock] on [viewModelScope]. The injected [model] wraps `:kit`'s real session in
 * production and a fake in tests; this class never touches the FFI.
 */
class VaultBrowseViewModel(private val model: VaultBrowseModel) : ViewModel() {
    val blocks: StateFlow<List<BlockSummaryView>> = model.blocks
    val selectedBlock: StateFlow<BlockSummaryView?> = model.selectedBlock
    val selectedRecords: StateFlow<List<RecordSummaryView>?> = model.selectedRecords
    val error: StateFlow<VaultBrowseError?> = model.error
    val revealed: StateFlow<Map<String, RevealedValue>> = model.revealed

    /** Publish the manifest block summaries (synchronous in-memory read). */
    fun loadBlocks() = model.loadBlocks()

    /** Decrypt + list the selected block's records (metadata only). */
    fun selectBlock(block: BlockSummaryView) {
        viewModelScope.launch { model.selectBlock(block) }
    }

    /** Return to the block list. */
    fun back() = model.clearSelection()

    /** Wipe the session (called on background); the screen returns to Unlock. */
    fun lock() = model.lock()

    /** Materialize one field's plaintext (user tap). */
    fun reveal(record: RecordSummaryView, field: RevealableField) = model.reveal(record, field)

    /** Hide one revealed field (user tap or auto-hide). */
    fun hide(recordUuidHex: String, fieldName: String) = model.hide(recordUuidHex, fieldName)

    /** Hide all revealed fields. */
    fun hideAll() = model.hideAll()

    val showDeleted: StateFlow<Boolean> = model.showDeleted

    /** True while a delete/restore write is in flight (disables list write buttons). */
    val writing: StateFlow<Boolean> = model.writing

    /** Toggle show-deleted (suspend on the model → launched on viewModelScope). */
    fun setShowDeleted(value: Boolean) {
        viewModelScope.launch { model.setShowDeleted(value) }
    }

    /** Soft-delete a record (re-reads on success inside the model). */
    fun delete(record: RecordSummaryView) {
        viewModelScope.launch { model.delete(record) }
    }

    /** Restore a tombstoned record. */
    fun restore(record: RecordSummaryView) {
        viewModelScope.launch { model.restore(record) }
    }

    val editing: StateFlow<RecordEditModel?> = model.editing

    /** Open a blank add form for the selected block. */
    fun startAdd() = model.startAdd()

    /** Open an edit form prefilled from [record]. */
    fun startEdit(record: RecordSummaryView) = model.startEdit(record)

    /** Dismiss the edit form without writing. */
    fun cancelEdit() = model.cancelEdit()

    /** Run the open form's commit (suspend) on the view-model scope. */
    fun commitEdit() {
        viewModelScope.launch { model.editing.value?.commit() }
    }

    /** After a successful commit: drop the form + re-read the block. */
    fun onEditCommitted() {
        viewModelScope.launch { model.onEditCommitted() }
    }
}
