package org.secretary.sync

import kotlin.time.Duration

/**
 * Seam over a single debounce timer. A new [schedule] replaces any outstanding one
 * (single outstanding flush — trailing debounce). The work receives the actual fire
 * instant, keeping the monitor clock-free. Conformers fire on the main thread.
 */
interface FlushScheduler {
    /** Schedule [work] to fire once after [after]; replaces any outstanding schedule. */
    fun schedule(after: Duration, work: (MonotonicInstant) -> Unit)

    /** Drop any pending work without firing it. Idempotent. */
    fun cancel()
}
