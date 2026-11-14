package org.secretary.sync.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncError
import org.secretary.sync.VaultSyncModel

/**
 * Thin Compose bridge over the host-tested [VaultSyncModel]. Holds NO badge/conflict logic — it
 * re-exposes the model's StateFlows for `collectAsStateWithLifecycle` and launches the model's
 * suspend methods on [viewModelScope]. The injected [model] is built by `:kit`'s `makeVaultSync`
 * in production and over a fake port in tests; this class never touches the FFI. No secret
 * crosses it: every pass runs through the open session (#733).
 */
class VaultSyncViewModel(private val model: VaultSyncModel) : ViewModel() {
    val badge: StateFlow<SyncBadgeState> = model.badge
    val isSyncing: StateFlow<Boolean> = model.isSyncing
    val reviewNeeded: StateFlow<Boolean> = model.reviewNeeded
    val pendingConflict: StateFlow<PendingConflict?> = model.pendingConflict
    val lastError: StateFlow<VaultSyncError?> = model.lastError

    /** Badge tap / "Sync now": one interactive pass behind the write re-auth gate. A conflict
     *  surfaces [pendingConflict] for the resolution sheet; an error lands in [lastError]. */
    fun beginInteractiveSync() {
        viewModelScope.launch { model.runInteractivePass() }
    }

    /** Commit the user's veto decisions for the paused conflict (gated like a write). The
     *  conflict sheet is driven by [pendingConflict]; a clean resolve clears it. */
    fun resolve(decisions: List<SyncVetoDecision>) {
        viewModelScope.launch { model.resolve(decisions) }
    }

    /** Close the conflict sheet without writing; the review badge keeps nagging. */
    fun cancelConflict() = model.cancelConflict()

    /** Best-effort "synced N ago" label refresh (read before/after a pass, never during). */
    fun refreshStatus() {
        viewModelScope.launch { model.refreshStatus() }
    }

    /** Silent sync right after any unlock (trigger-1). Suspends until the pass settles. A
     *  conflict only raises the review badge (no sheet). */
    suspend fun syncAtUnlock() {
        model.syncAtUnlock()
    }
}
