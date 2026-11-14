package org.secretary.sync

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.secretary.browse.DeviceUnlockError
import org.secretary.browse.WriteReauthGate
import org.secretary.browse.reauthFailedMessage

/**
 * The host-tested heart of the Android sync UI — the Kotlin mirror of the iOS VaultSyncViewModel
 * (docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md), minus rendering. It turns the
 * change-monitor signal + a SyncStatus snapshot + the result of a [SyncCoordinator] pass into a
 * [SyncBadgeState], and drives the two sync triggers that converge on one resolution path.
 *
 * Two triggers, one resolution path:
 *  - [syncAtUnlock]: a silent pass right after any unlock (password, biometric or recovery);
 *    auto-applying arms update the badge silently, a conflict only raises [reviewNeeded]. Ungated:
 *    the user has just proven presence by unlocking.
 *  - [runInteractivePass] -> [resolve]: "Sync now" and conflict Apply, each behind the write
 *    re-auth [gate] (as on iOS, #733); a conflict surfaces a [pendingConflict] for the sheet,
 *    which calls [resolve] with the collected decisions.
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
 * Secret hygiene: no secret crosses the model; every pass runs through the open session.
 */
class VaultSyncModel(
    private val coordinator: SyncCoordinator,
    private val wallClock: WallClock,
    private val monitorHook: SyncMonitorHook,
    private val vaultUuid: ByteArray?,
    // No default: a forgotten gate would let "Sync now" and Apply through unprompted (#733).
    private val gate: WriteReauthGate,
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
    private var interactiveBusy: Boolean = false

    /** The change monitor's onChange seam: a debounced remote change was detected. */
    fun pendingChangesRaised() {
        pendingChanges = true
        recomputeBadge()
    }

    /** Silent pass right after unlock. A conflict only raises the review badge. */
    suspend fun syncAtUnlock() {
        runPass { _reviewNeeded.value = true }
    }

    /** Interactive pass ("Sync now"), gated: a conflict surfaces a [pendingConflict] for the sheet. */
    suspend fun runInteractivePass() = exclusive {
        if (!authorized("Confirm syncing this vault")) return@exclusive
        runPass { outcome -> surfaceConflict(outcome) }
    }

    /** Commit the user's veto decisions for the paused conflict, gated like a write. */
    suspend fun resolve(decisions: List<SyncVetoDecision>) = exclusive {
        if (!authorized("Confirm applying your sync choices")) return@exclusive
        guardedPass {
            when (val outcome = coordinator.resolve(decisions, wallClock.nowMs())) {
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

    /**
     * Prove presence before an interactive pass. A cancel returns false silently (nothing runs, a
     * conflict sheet stays open); any other proof failure is surfaced as [VaultSyncError.ReauthFailed].
     * CancellationException is not caught, so coroutine cancellation still propagates.
     */
    private suspend fun authorized(reason: String): Boolean {
        try {
            gate.authorizeWrite(reason)
        } catch (e: DeviceUnlockError.UserCancelled) {
            _lastError.value = null // the user retried and backed out; an older error is stale
            return false
        } catch (e: DeviceUnlockError) {
            _lastError.value = VaultSyncError.ReauthFailed(reauthFailedMessage(e))
            return false
        }
        return true
    }

    /**
     * Run one gated action at a time. The re-auth prompt suspends before [isSyncing] goes true, so
     * without this a second tap on "Sync now" or Apply while the prompt is up would queue a second
     * pass (or a second resolve against an already-emptied stash). Main-thread confined, so a plain
     * flag suffices; a tap that arrives while busy is dropped.
     */
    private suspend fun exclusive(action: suspend () -> Unit) {
        if (interactiveBusy) return
        interactiveBusy = true
        try {
            action()
        } finally {
            interactiveBusy = false
        }
    }

    /** Shared pass body: mute -> run -> dispatch the ConflictsPending arm to [onConflict], else clean. */
    private suspend fun runPass(onConflict: (SyncOutcome.ConflictsPending) -> Unit) {
        guardedPass {
            when (val outcome = coordinator.runPass(wallClock.nowMs())) {
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

    /**
     * Clear all conflict/review state after a clean pass. Deliberately does NOT
     * call [recomputeBadge] itself — it is only ever reached from inside
     * [guardedPass], whose `finally` recomputes the badge after the flags settle.
     * A future caller invoking this outside `guardedPass` must recompute the
     * badge afterwards (or this should grow its own `recomputeBadge()` call).
     */
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
