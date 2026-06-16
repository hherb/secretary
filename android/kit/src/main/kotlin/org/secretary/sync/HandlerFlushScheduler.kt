package org.secretary.sync

import android.os.Handler
import android.os.Looper
import kotlin.time.Duration

/**
 * [FlushScheduler] over a main-Looper Handler. A new [schedule] cancels the prior one
 * (single outstanding flush — trailing debounce); the work fires on the main thread with
 * the actual fire instant from [now]. Mirror of the iOS DispatchFlushScheduler.
 *
 * [handler] and [now] are injectable so an instrumented test can supply a known Looper
 * and a deterministic clock; production uses the main Looper and SystemClock.
 */
class HandlerFlushScheduler(
    private val handler: Handler = Handler(Looper.getMainLooper()),
    private val now: () -> MonotonicInstant = ::monotonicNow,
) : FlushScheduler {
    private var pending: Runnable? = null

    override fun schedule(after: Duration, work: (MonotonicInstant) -> Unit) {
        cancel()
        val runnable = Runnable {
            pending = null // cleared before invocation: a re-entrant cancel() sees null (safe no-op)
            work(now())
        }
        pending = runnable
        handler.postDelayed(runnable, after.inWholeMilliseconds)
    }

    override fun cancel() {
        pending?.let { handler.removeCallbacks(it) }
        pending = null
    }
}
