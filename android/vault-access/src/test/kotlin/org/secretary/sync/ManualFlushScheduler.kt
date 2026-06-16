package org.secretary.sync

import kotlin.time.Duration

/**
 * In-memory [FlushScheduler] for host tests: the test controls when the pending work
 * fires and with which instant via [fire]. Models a one-shot timer — [fire] clears the
 * pending work before invoking it, so work that re-schedules (the monitor's re-arm) sets
 * a fresh pending entry.
 */
class ManualFlushScheduler : FlushScheduler {
    var scheduledDelay: Duration? = null
        private set
    var cancelCount: Int = 0
        private set
    private var pending: ((MonotonicInstant) -> Unit)? = null

    val hasPending: Boolean get() = pending != null

    override fun schedule(after: Duration, work: (MonotonicInstant) -> Unit) {
        scheduledDelay = after
        pending = work
    }

    override fun cancel() {
        pending = null
        cancelCount++
    }

    /** Fire the pending work at [at]. */
    fun fire(at: MonotonicInstant) {
        val work = pending ?: error("fire called with nothing scheduled")
        pending = null
        work(at)
    }
}
