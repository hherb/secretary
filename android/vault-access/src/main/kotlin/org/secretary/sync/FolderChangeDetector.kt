package org.secretary.sync

import kotlin.time.Duration

/**
 * Pure, deterministic reducer that turns a noisy stream of folder-change pulses into
 * a single debounced, foreground-gated "pending changes" signal. No real clock or
 * timer: callers supply instants and drive [flush]. Trailing debounce — the signal is
 * raised once the folder has been quiet for [debounceWindow] after the last pulse.
 *
 * Advisory + metadata-only: it sees timestamps, never record contents, and a
 * missed/spurious pulse never corrupts anything (sync reconciles truth). Mirror of the
 * iOS FolderChangeDetector; a Kotlin class with mutable private state stands in for the
 * Swift mutating struct.
 */
class FolderChangeDetector(
    val debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow,
) {
    var isActive: Boolean = false
        private set
    var pendingChanges: Boolean = false
        private set
    private var lastPulseAt: MonotonicInstant? = null
    private var muteBefore: MonotonicInstant? = null

    /**
     * Instant the monitor should next attempt a [flush], or null if nothing is armed
     * (inactive, already pending, or no pulse seen).
     */
    val nextFlushDeadline: MonotonicInstant?
        get() {
            if (!isActive || pendingChanges) return null
            val last = lastPulseAt ?: return null
            return last.advancedBy(debounceWindow)
        }

    /**
     * Foreground/unlocked gate (ADR-0003 foreground-only). Going inactive resets
     * detection state for a clean slate on next foreground.
     */
    fun setActive(active: Boolean) {
        if (active == isActive) return
        isActive = active
        if (!active) {
            lastPulseAt = null
            muteBefore = null
            pendingChanges = false
        }
    }

    /**
     * Record a watcher pulse. Dropped while inactive or muted. Keeping the max keeps
     * the armed deadline correct even if near-simultaneous pulses arrive out of order.
     * Deliberately does NOT guard on [pendingChanges]: a pulse arriving while pending is
     * preserved so [acknowledge] can re-arm it.
     */
    fun recordPulse(at: MonotonicInstant) {
        if (!isActive) return
        val mute = muteBefore
        if (mute != null && at < mute) return
        lastPulseAt = maxOf(lastPulseAt ?: at, at)
    }

    /** Suppress pulses stamped strictly before [instant] (self-write window). */
    fun muteUntil(instant: MonotonicInstant) {
        muteBefore = instant
    }

    /**
     * Attempt to raise the signal. Returns true iff this call flipped [pendingChanges]
     * false→true, so the monitor fires onChange exactly once.
     */
    fun flush(now: MonotonicInstant): Boolean {
        if (!isActive || pendingChanges) return false
        val last = lastPulseAt ?: return false
        if (now < last.advancedBy(debounceWindow)) return false
        pendingChanges = true
        lastPulseAt = null // consumed; further pulses re-arm post-acknowledge
        return true
    }

    /** Caller consumed the signal. A post-acknowledge pulse, or one preserved before
     *  the flush, re-arms. */
    fun acknowledge() {
        pendingChanges = false
    }
}
