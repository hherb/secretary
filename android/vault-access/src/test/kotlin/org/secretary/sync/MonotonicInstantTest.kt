package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

class MonotonicInstantTest {
    @Test
    fun ordersByNanos() {
        assertTrue(MonotonicInstant(1) < MonotonicInstant(2))
        assertTrue(MonotonicInstant(5) > MonotonicInstant(2))
        assertEquals(MonotonicInstant(3), MonotonicInstant(3))
    }

    @Test
    fun advancedByAddsDuration() {
        val base = MonotonicInstant(1_000_000) // 1 ms
        assertEquals(MonotonicInstant(3_000_000), base.advancedBy(2.milliseconds))
    }

    @Test
    fun durationToIsSignedDifference() {
        val a = MonotonicInstant(1_000_000)
        val b = MonotonicInstant(4_000_000)
        assertEquals(3.milliseconds, a.durationTo(b))
        assertEquals((-3_000_000).nanoseconds, b.durationTo(a))
    }

    @Test
    fun tuningConstantsAreNamed() {
        assertEquals(2_000.milliseconds, ChangeDetectionTuning.defaultDebounceWindow)
        assertEquals(10_000.milliseconds, ChangeDetectionTuning.defaultSelfWriteMuteWindow)
    }
}
