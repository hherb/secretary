package org.secretary.sync

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The host-tested heart of the Android sync UI — the Kotlin mirror of the iOS VaultSyncViewModel
 * (docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md), minus rendering. It turns the
 * change-monitor signal + a SyncStatus snapshot + the result of a [SyncCoordinator] pass into a
 * [SyncBadgeState], and drives the two sync triggers that converge on one resolution path.
 *
 * Two triggers, one resolution path:
 *  - [syncAtUnlock]: a silent pass with the in-hand unlock password; auto-applying arms update the
 *    badge silently, a conflict only raises [reviewNeeded] (the password is dropped, never held
 *    across a modal at unlock).
 *  - [runInteractivePass] -> [resolve]: the user re-enters a password; a conflict surfaces a
 *    [pendingConflict] for slice 5's sheet, which calls [resolve] with the collected decisions.
 *
 * Concurrency: main-thread-confined like the iOS @MainActor view model — callers invoke these
 * methods from the UI dispatcher. The underlying [SyncCoordinator] is Mutex-serialized across its
 * suspending port calls, so the model never drives concurrent passes. Do not drive [refreshStatus]
 * while a pass is in flight (it parks behind the coordinator mutex) — read status before/after.
 *
 * Badge labelling: a clean pass does not auto-refresh the "synced N ago" label — the [SyncBadgeState.Synced]
 * label updates only when slice 5 drives [refreshStatus] (read status before/after a pass, never during).
 * This deliberately differs from iOS, which refreshes inside the pass; on Android the refresh is a UI-layer
 * concern to avoid re-parking behind the just-released coordinator mutex.
 *
 * Secret hygiene: the password is a per-call argument, forwarded straight to the coordinator and
 * never stored on the model.
 */
class VaultSyncModel(
    private val coordinator: SyncCoordinator,
    private val wallClock: WallClock,
    private val monitorHook: SyncMonitorHook,
    private val vaultUuid: ByteArray?,
) {
    private val _badge = MutableStateFlow<SyncBadgeState>(SyncBadgeState.NeverSynced)
    val badge: StateFlow<SyncBadgeState> = _badge.asStateFlow()

    private val _isSyncing = MutableStateFlow(false)
    val isSyncing: StateFlow<Boolean> = _isSyncing.asStateFlow()

    private val _reviewNeeded = MutableStateFlow(false)
    val reviewNeeded: StateFlow<Boolean> = _reviewNeeded.asStateFlow()

    private val _pendingConflict = MutableStateFlow<PendingConflict?>(null)
    val pendingConflict: StateFlow<PendingConflict?> = _pendingConflict.asStateFlow()

    private val _lastError = MutableStateFlow<VaultSyncError?>(null)
    val lastError: StateFlow<VaultSyncError?> = _lastError.asStateFlow()

    private var pendingChanges: Boolean = false
    private var lastStatus: SyncStatus? = null

    /** The change monitor's onChange seam: a debounced remote change was detected. */
    fun pendingChangesRaised() {
        pendingChanges = true
        recomputeBadge()
    }

    /** Silent pass with the in-hand unlock password. A conflict only raises the review badge. */
    suspend fun syncAtUnlock(password: ByteArray) {
        runPass(password) { _reviewNeeded.value = true }
    }

    /** Interactive pass: a conflict surfaces a [pendingConflict] for the resolution sheet. */
    suspend fun runInteractivePass(password: ByteArray) {
        runPass(password) { outcome -> surfaceConflict(outcome) }
    }

    /** Commit the user's veto decisions for the paused conflict. */
    suspend fun resolve(decisions: List<SyncVetoDecision>, password: ByteArray) {
        guardedPass {
            when (val outcome = coordinator.resolve(decisions, password, wallClock.nowMs())) {
                is SyncOutcome.ConflictsPending -> surfaceConflict(outcome) // re-stashed; keep sheet open
                else -> onCleanArm()
            }
        }
    }

    /** Close the resolution sheet without writing; the review badge keeps nagging. */
    fun cancelConflict() {
        _pendingConflict.value = null
        _lastError.value = null
        recomputeBadge()
    }

    /** Best-effort status refresh for the "synced N ago" label; failures keep the prior state. */
    suspend fun refreshStatus() {
        val uuid = vaultUuid ?: return
        try {
            lastStatus = coordinator.status(uuid)
            recomputeBadge()
        } catch (_: VaultSyncError) {
            // best-effort read; keep prior label
        }
    }

    /** Shared pass body: mute -> run -> dispatch the ConflictsPending arm to [onConflict], else clean. */
    private suspend fun runPass(password: ByteArray, onConflict: (SyncOutcome.ConflictsPending) -> Unit) {
        guardedPass {
            when (val outcome = coordinator.runPass(password, wallClock.nowMs())) {
                is SyncOutcome.ConflictsPending -> onConflict(outcome)
                else -> onCleanArm()
            }
        }
    }

    /** Wraps a pass with the syncing flag, the self-write mute, and typed-error capture. */
    private suspend fun guardedPass(body: suspend () -> Unit) {
        _lastError.value = null
        _isSyncing.value = true
        recomputeBadge()
        monitorHook.muteSelfWrite()
        try {
            body()
        } catch (e: VaultSyncError) {
            _lastError.value = e // surfaced; conflict context (if any) is preserved for retry
        } finally {
            _isSyncing.value = false
            recomputeBadge()
        }
    }

    private fun surfaceConflict(outcome: SyncOutcome.ConflictsPending) {
        _reviewNeeded.value = true
        _pendingConflict.value = PendingConflict(outcome.vetoes, outcome.collisions)
    }

    private fun onCleanArm() {
        monitorHook.acknowledge()
        pendingChanges = false
        _pendingConflict.value = null
        _reviewNeeded.value = false
    }

    private fun recomputeBadge() {
        _badge.value = syncBadgeState(
            inProgress = _isSyncing.value,
            pendingChanges = pendingChanges,
            reviewNeeded = _reviewNeeded.value || _pendingConflict.value != null,
            status = lastStatus,
        )
    }
}
