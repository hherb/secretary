package org.secretary.sync

import kotlin.time.Duration

/**
 * Coordinates a [FolderChangeDetector] with a [FolderWatchPort] (OS pulses) and a
 * [FlushScheduler] (debounce timer), exposing an advisory [pendingChanges] flag and an
 * [onChange] callback for a future UI slice. Main-thread-confined: the real conformers
 * deliver their callbacks on the main thread, so all detector mutation is serialized
 * there with no extra locking (mirror of the iOS @MainActor ChangeDetectionMonitor).
 *
 * Detect-only: a raised signal never triggers a sync pass (no password in hand after
 * unlock). Acting on it (re-prompt / sync-at-unlock) is slice 4.
 */
class ChangeDetectionMonitor(
    private val detector: FolderChangeDetector,
    private val watch: FolderWatchPort,
    private val scheduler: FlushScheduler,
    private val onChange: () -> Unit,
) {
    /** True once a debounced change is awaiting the user; cleared by [acknowledge]/[stop]. */
    var pendingChanges: Boolean = false
        private set

    /**
     * Start watching + gate active. Ignored if already started. Re-throws (and rolls
     * back the active gate) if the watch port can't start, so a retry after a failure
     * starts from a clean state.
     */
    fun start() {
        if (detector.isActive) return // already started — ignore double-start
        detector.setActive(true)
        try {
            watch.start(::handlePulse)
        } catch (e: Throwable) {
            detector.setActive(false) // roll back so a retry starts clean
            throw e
        }
    }

    /** Stop watching, cancel any armed flush, gate inactive, clear the signal. */
    fun stop() {
        scheduler.cancel()
        watch.stop()
        detector.setActive(false) // clears the detector's pending signal (clean-slate reset)
        pendingChanges = false
    }

    /**
     * Consume the signal. If a pulse arrived while the signal was pending, the detector
     * preserved it (its deadline may already have elapsed), so re-arm a flush — the
     * scheduler supplies the real fire instant, keeping this layer clock-free. With no
     * preserved pulse this is a no-op.
     */
    fun acknowledge() {
        detector.acknowledge()
        pendingChanges = detector.pendingChanges
        if (detector.nextFlushDeadline != null) {
            scheduler.schedule(Duration.ZERO, ::handleFlush)
        }
    }

    /** Suppress watcher pulses stamped before [instant] (self-write window). */
    fun muteUntil(instant: MonotonicInstant) {
        detector.muteUntil(instant)
    }

    private fun handlePulse(instant: MonotonicInstant) {
        detector.recordPulse(instant)
        rearm(now = instant)
    }

    private fun rearm(now: MonotonicInstant) {
        val deadline = detector.nextFlushDeadline
        if (deadline == null) {
            scheduler.cancel()
            return
        }
        // Clamp: a real scheduler firing slightly past the deadline must not pass a
        // negative Duration to schedule (the contract is undefined for it).
        val delay = maxOf(Duration.ZERO, now.durationTo(deadline))
        scheduler.schedule(delay, ::handleFlush)
    }

    private fun handleFlush(now: MonotonicInstant) {
        if (detector.flush(now)) {
            pendingChanges = true
            onChange()
        } else {
            rearm(now) // a later pulse moved the deadline
        }
    }
}
