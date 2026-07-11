package org.secretary.browse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.secretary.browse.ExpiredEntryInfo
import org.secretary.browse.TrashBrowseModel
import org.secretary.browse.TrashedBlockInfo
import org.secretary.browse.VaultBrowseError

/**
 * Thin Compose bridge over the host-tested [TrashBrowseModel]. Holds NO trash logic — it re-exposes
 * the model's StateFlows for `collectAsStateWithLifecycle` and launches the model's suspend writes on
 * [viewModelScope]. Mirror of [VaultBrowseViewModel]; the injected [model] wraps `:kit`'s real
 * session in production and a fake in tests; this class never touches the FFI.
 */
class TrashBrowseViewModel(private val model: TrashBrowseModel) : ViewModel() {
    val entries: StateFlow<List<TrashedBlockInfo>> = model.entries
    val error: StateFlow<VaultBrowseError?> = model.error
    val writing: StateFlow<Boolean> = model.writing
    val preview: StateFlow<List<ExpiredEntryInfo>?> = model.preview

    val retentionWindowMs: Long get() = model.retentionWindowMs

    /** Load the trashed-block list (synchronous in-memory read). */
    fun load() = model.load()

    /** Ungated retention preview. */
    fun previewRetention() = model.previewRetention()

    /** Drop the cached preview (on sheet dismiss). */
    fun clearPreview() = model.clearPreview()

    fun restore(uuid: ByteArray) { viewModelScope.launch { model.restore(uuid) } }
    fun purge(uuid: ByteArray) { viewModelScope.launch { model.purge(uuid) } }
    fun emptyTrash() { viewModelScope.launch { model.emptyTrash() } }
    fun runRetention() { viewModelScope.launch { model.runRetention() } }
}
