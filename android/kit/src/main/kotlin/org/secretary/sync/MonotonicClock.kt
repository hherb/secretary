package org.secretary.sync

import android.os.SystemClock

/**
 * Android monotonic time source for [MonotonicInstant]. Uses elapsedRealtimeNanos
 * (monotonic, counts during deep sleep, never wall-clock), so only ordering and
 * differences are meaningful — exactly the [MonotonicInstant] contract.
 */
fun monotonicNow(): MonotonicInstant = MonotonicInstant(SystemClock.elapsedRealtimeNanos())
