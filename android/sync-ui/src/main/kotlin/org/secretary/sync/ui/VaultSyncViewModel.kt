package org.secretary.sync.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncError
import org.secretary.sync.VaultSyncModel

/**
 * Thin Compose bridge over the host-tested [VaultSyncModel]. Holds NO badge/conflict logic — it
 * re-exposes the model's StateFlows for `collectAsStateWithLifecycle`, owns the password-sheet
 * presentation flag (the one piece of UI state the model deliberately omits), and launches the
 * model's suspend methods on [viewModelScope]. The injected [model] is built by `:kit`'s
 * `makeVaultSync` in production and over a fake port in tests; this class never touches the FFI.
 */
class VaultSyncViewModel(private val model: VaultSyncModel) : ViewModel() {
    val badge: StateFlow<SyncBadgeState> = model.badge
    val isSyncing: StateFlow<Boolean> = model.isSyncing
    val reviewNeeded: StateFlow<Boolean> = model.reviewNeeded
    val pendingConflict: StateFlow<PendingConflict?> = model.pendingConflict
    val lastError: StateFlow<VaultSyncError?> = model.lastError

    private val _passwordSheetVisible = MutableStateFlow(false)
    val passwordSheetVisible: StateFlow<Boolean> = _passwordSheetVisible.asStateFlow()

    /** Trigger-2 entry: present the password sheet (badge tap / "Sync now"). */
    fun beginInteractiveSync() {
        _passwordSheetVisible.value = true
    }

    /**
     * Run one interactive pass with the re-entered password. On success — or when the pass
     * surfaces a conflict (handed off to the conflict sheet via [pendingConflict]) — the password
     * sheet closes. On a [VaultSyncError] (e.g. wrong password) the model captures it in
     * [lastError] without throwing, and the sheet STAYS OPEN so the user can retry inline.
     *
     * Secret hygiene: [password] is forwarded straight to the model and never stored on this VM.
     * The VM deliberately does NOT zeroize the buffer: the owning caller (the screen) may reuse
     * the same ByteArray across this interactive pass and a subsequent conflict [resolve] call.
     * Zeroizing here would corrupt that reuse. The owning caller is responsible for zeroizing the
     * ByteArray on its terminal paths (success, conflict-cancel, dismiss).
     */
    fun submitPassword(password: ByteArray) {
        viewModelScope.launch {
            model.runInteractivePass(password)
            if (model.lastError.value == null) _passwordSheetVisible.value = false
        }
    }

    /**
     * Commit the user's veto decisions for the paused conflict. The conflict sheet is driven by
     * [pendingConflict]; a clean resolve clears it (no separate visibility flag here).
     *
     * Secret hygiene: [password] is forwarded straight to the model and never stored on this VM.
     * The VM deliberately does NOT zeroize the buffer: the owning caller (the screen) reuses the
     * same ByteArray that was passed to [submitPassword] for the preceding interactive pass.
     * Zeroizing here would corrupt that reuse. The owning caller is responsible for zeroizing the
     * ByteArray on its terminal paths (success, conflict-cancel, dismiss).
     */
    fun resolve(decisions: List<SyncVetoDecision>, password: ByteArray) {
        viewModelScope.launch { model.resolve(decisions, password) }
    }

    /** Close the conflict sheet without writing; the review badge keeps nagging. */
    fun cancelConflict() = model.cancelConflict()

    /** Dismiss the password sheet without running a pass. */
    fun dismissPasswordSheet() {
        _passwordSheetVisible.value = false
    }

    /** Best-effort "synced N ago" label refresh (read before/after a pass, never during). */
    fun refreshStatus() {
        viewModelScope.launch { model.refreshStatus() }
    }

    /**
     * Silent sync immediately after a password unlock (trigger-1). Suspends until the pass
     * settles so the caller (the :app unlock orchestration) can zeroize the password buffer
     * only AFTER the async Argon2id re-open has consumed it — avoiding a use-after-zero race.
     * A conflict only raises the review badge (the password is dropped, no sheet).
     *
     * Secret hygiene: [password] is forwarded straight to the model and never stored on this VM.
     * The VM deliberately does NOT zeroize the buffer; the owning caller zeroizes after this
     * suspend call returns (it is never reused for a conflict resolve on the silent path).
     */
    suspend fun syncAtUnlock(password: ByteArray) {
        model.syncAtUnlock(password)
    }
}
