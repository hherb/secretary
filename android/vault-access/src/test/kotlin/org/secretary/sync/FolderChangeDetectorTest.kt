package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds

class FolderChangeDetectorTest {
    private val window = 100.milliseconds
    private fun at(ms: Long) = MonotonicInstant(ms * 1_000_000)
    private fun active() = FolderChangeDetector(window).apply { setActive(true) }

    @Test
    fun singlePulseBecomesPendingAfterWindow() {
        val d = active()
        d.recordPulse(at(0))
        assertFalse(d.flush(at(99)))           // not quiet long enough
        assertFalse(d.pendingChanges)
        assertTrue(d.flush(at(100)))           // exactly the window → transition
        assertTrue(d.pendingChanges)
    }

    @Test
    fun flushReturnsTrueOnlyOnTransition() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))
        assertFalse(d.flush(at(200)))          // already pending → no second transition
    }

    @Test
    fun burstWithinWindowCoalescesToOneSignal() {
        val d = active()
        d.recordPulse(at(0))
        d.recordPulse(at(50))                  // resets the quiet window to 50
        assertFalse(d.flush(at(100)))          // 100 < 50 + 100
        assertTrue(d.flush(at(150)))           // quiet since the last pulse
    }

    @Test
    fun outOfOrderPulsesKeepLatestDeadline() {
        val d = active()
        d.recordPulse(at(50))
        d.recordPulse(at(10))                  // earlier instant must not move the deadline back
        assertFalse(d.flush(at(120)))          // deadline is 50 + 100 = 150
        assertTrue(d.flush(at(150)))
    }

    @Test
    fun inactiveDropsPulses() {
        val d = FolderChangeDetector(window)   // never activated
        d.recordPulse(at(0))
        assertNull(d.nextFlushDeadline)
        assertFalse(d.flush(at(1000)))
    }

    @Test
    fun goingInactiveResetsState() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))
        d.setActive(false)
        assertFalse(d.pendingChanges)
        assertNull(d.nextFlushDeadline)
        d.setActive(true)
        assertNull(d.nextFlushDeadline)        // no leftover pulse
    }

    @Test
    fun muteSuppressesEarlierPulses() {
        val d = active()
        d.muteUntil(at(100))
        d.recordPulse(at(50))                  // before the mute instant → ignored
        assertNull(d.nextFlushDeadline)
        d.recordPulse(at(100))                 // at/after the mute instant → counts
        assertEquals(at(100).advancedBy(window), d.nextFlushDeadline) // armed to 100 + window
        assertTrue(d.flush(at(200)))
    }

    @Test
    fun goingInactiveClearsMuteWindow() {
        val d = active()
        d.muteUntil(at(100))
        d.setActive(false)
        d.setActive(true)
        d.recordPulse(at(50))                  // mute was cleared, so this earlier pulse now counts
        assertEquals(at(50).advancedBy(window), d.nextFlushDeadline)
    }

    @Test
    fun acknowledgeClearsPending() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))
        d.acknowledge()
        assertFalse(d.pendingChanges)
    }

    @Test
    fun acknowledgeReArmsPulsePreservedDuringPending() {
        val d = active()
        d.recordPulse(at(0))
        assertTrue(d.flush(at(100)))           // pending = true, pulse consumed
        d.recordPulse(at(120))                 // arrives while still pending → preserved
        assertNull(d.nextFlushDeadline)        // not armed while pending
        d.acknowledge()
        assertTrue(d.nextFlushDeadline == at(120).advancedBy(window))
        assertTrue(d.flush(at(220)))           // signals again from the preserved pulse
    }
}
