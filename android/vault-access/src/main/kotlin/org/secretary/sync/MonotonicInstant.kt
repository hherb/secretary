package org.secretary.sync

import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * A point on a monotonic clock, in nanoseconds. Only ordering and differences are
 * meaningful — never interpreted as wall-clock time. Keeps the detection core
 * clock-free: host tests supply instants directly; the real conformer sources them
 * from SystemClock.elapsedRealtimeNanos() (see :kit MonotonicClock).
 */
@JvmInline
value class MonotonicInstant(val nanos: Long) : Comparable<MonotonicInstant> {
    override fun compareTo(other: MonotonicInstant): Int = nanos.compareTo(other.nanos)

    /** This instant moved forward by [duration]. */
    fun advancedBy(duration: Duration): MonotonicInstant =
        MonotonicInstant(nanos + duration.inWholeNanoseconds)

    /** The (signed) duration from this instant to [later]. */
    fun durationTo(later: MonotonicInstant): Duration = (later.nanos - nanos).nanoseconds
}
