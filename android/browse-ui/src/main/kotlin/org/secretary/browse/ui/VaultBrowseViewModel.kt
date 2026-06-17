package org.secretary.browse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView
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
}
