package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Records seed/reset/authorize calls so the wrapper's forwarding is observable host-side. */
private class RecordingGate : WriteReauthGate {
    val seeds = mutableListOf<Long>()
    val authorizeReasons = mutableListOf<String>()
    var resets = 0
    override suspend fun authorizeWrite(reason: String) { authorizeReasons += reason }
    override fun seed(nowMs: Long) { seeds += nowMs }
    override fun reset() { resets++ }
}

class RetargetableReauthGateTest {
    @Test
    fun `default delegate authorizes (no crash, no real gate needed)`() = runTest {
        RetargetableReauthGate().authorizeWrite("w") // NoopReauthGate delegate → completes silently
    }

    @Test
    fun `seed then retarget seeds the new delegate with the recorded instant`() {
        val gate = RetargetableReauthGate()
        gate.seed(1_000L)
        val g = RecordingGate()
        gate.retarget(g)
        assertEquals(listOf(1_000L), g.seeds)
    }

    @Test
    fun `retarget then seed also seeds the new delegate (ordering independent)`() {
        val gate = RetargetableReauthGate()
        val g = RecordingGate()
        gate.retarget(g)          // not seeded yet → g not seeded here
        gate.seed(1_000L)         // forwards to current delegate g
        assertEquals(listOf(1_000L), g.seeds)
    }

    @Test
    fun `authorizeWrite forwards to the current delegate`() = runTest {
        val gate = RetargetableReauthGate()
        val g = RecordingGate()
        gate.retarget(g)
        gate.authorizeWrite("confirm delete")
        assertEquals(listOf("confirm delete"), g.authorizeReasons)
    }

    @Test
    fun `reset forwards and clears the recorded seed so a later retarget does not re-seed`() {
        val gate = RetargetableReauthGate()
        val g = RecordingGate()
        gate.retarget(g)
        gate.seed(1_000L)
        gate.reset()
        assertEquals(1, g.resets)                 // reset forwarded to current delegate
        val g2 = RecordingGate()
        gate.retarget(g2)
        assertTrue(g2.seeds.isEmpty())            // recorded instant cleared by reset
    }

    @Test
    fun `retargetWindow seeds the new delegate at the given instant, not the stored open instant`() = runTest {
        val gate = RetargetableReauthGate()
        gate.seed(1_000L)                         // original open instant
        val g = RecordingGate()
        gate.retargetWindow(g, 5_000L)            // seed-at-now (5_000), NOT the stored 1_000
        assertEquals(listOf(5_000L), g.seeds)
        gate.authorizeWrite("w")
        assertEquals(listOf("w"), g.authorizeReasons)
    }

    @Test
    fun `retargetWindow advances the recorded instant so a later plain retarget re-seeds at now`() {
        val gate = RetargetableReauthGate()
        gate.seed(1_000L)
        gate.retargetWindow(RecordingGate(), 5_000L)
        val g2 = RecordingGate()
        gate.retarget(g2)                         // uses the recorded instant, now advanced to 5_000
        assertEquals(listOf(5_000L), g2.seeds)
    }
}
