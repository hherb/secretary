package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

class ChangeDetectionMonitorTest {
    private fun at(ms: Long) = MonotonicInstant(ms * 1_000_000)

    private class Fixture {
        val watch = FakeFolderWatch()
        val scheduler = ManualFlushScheduler()
        var changes = 0
        val monitor = ChangeDetectionMonitor(
            detector = FolderChangeDetector(100.milliseconds),
            watch = watch,
            scheduler = scheduler,
            onChange = { changes++ },
        )
    }

    @Test
    fun pulseThenQuietFiresOnChangeOnce() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        assertEquals(100.milliseconds, f.scheduler.scheduledDelay) // armed to deadline
        f.scheduler.fire(at(100))
        assertEquals(1, f.changes)
        assertTrue(f.monitor.pendingChanges)
    }

    @Test
    fun burstFiresOnChangeOnce() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        f.watch.emit(at(40))
        f.watch.emit(at(80))
        // A flush that fires too early re-arms instead of signalling.
        f.scheduler.fire(at(100))     // 100 < 80 + 100 → re-arm
        assertEquals(0, f.changes)
        f.scheduler.fire(at(180))     // quiet since the last pulse
        assertEquals(1, f.changes)
    }

    @Test
    fun stopCancelsSchedulerAndStopsWatch() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        f.monitor.stop()
        assertEquals(1, f.scheduler.cancelCount)
        assertEquals(1, f.watch.stopCount)
        assertFalse(f.monitor.pendingChanges)
    }

    @Test
    fun acknowledgeClearsAndReArmsPreservedPulse() {
        val f = Fixture()
        f.monitor.start()
        f.watch.emit(at(0))
        f.scheduler.fire(at(100))               // pending raised, changes == 1
        f.watch.emit(at(120))                   // arrives while pending → preserved
        f.monitor.acknowledge()
        assertFalse(f.monitor.pendingChanges)
        assertTrue(f.scheduler.hasPending)      // re-armed at zero delay
        assertEquals(Duration.ZERO, f.scheduler.scheduledDelay)
        f.scheduler.fire(at(300))               // fires the preserved pulse
        assertEquals(2, f.changes)
    }

    @Test
    fun startErrorRollsBackActiveGateAndRetrySucceeds() {
        val f = Fixture()
        f.watch.startError = IllegalStateException("denied")
        assertThrows(IllegalStateException::class.java) { f.monitor.start() }
        assertEquals(0, f.watch.startCount)
        // Clear the error and retry — must start cleanly (active gate was rolled back).
        f.watch.startError = null
        f.monitor.start()
        assertEquals(1, f.watch.startCount)
    }

    @Test
    fun doubleStartIsIdempotent() {
        val f = Fixture()
        f.monitor.start()
        f.monitor.start()
        assertEquals(1, f.watch.startCount)
    }
}
