package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.milliseconds

class PortDoublesTest {
    @Test
    fun fakeWatchEmitsToRegisteredCallback() {
        val watch = FakeFolderWatch()
        var seen: MonotonicInstant? = null
        watch.start { seen = it }
        assertTrue(watch.started)
        assertEquals(1, watch.startCount)
        watch.emit(MonotonicInstant(42))
        assertEquals(MonotonicInstant(42), seen)
        watch.stop()
        assertFalse(watch.started)
        assertEquals(1, watch.stopCount)
    }

    @Test
    fun fakeWatchInjectedStartErrorLeavesItUnstarted() {
        val watch = FakeFolderWatch()
        val boom = IllegalStateException("no scope")
        watch.startError = boom
        val thrown = assertThrows(IllegalStateException::class.java) { watch.start {} }
        assertEquals("no scope", thrown.message)
        assertFalse(watch.started)
        assertEquals(0, watch.startCount)
    }

    @Test
    fun manualSchedulerFiresPendingWorkOnce() {
        val scheduler = ManualFlushScheduler()
        var fired: MonotonicInstant? = null
        scheduler.schedule(100.milliseconds) { fired = it }
        assertEquals(100.milliseconds, scheduler.scheduledDelay)
        assertTrue(scheduler.hasPending)
        scheduler.fire(MonotonicInstant(7))
        assertEquals(MonotonicInstant(7), fired)
        assertFalse(scheduler.hasPending)               // one-shot
    }

    @Test
    fun manualSchedulerCancelDropsPendingWork() {
        val scheduler = ManualFlushScheduler()
        scheduler.schedule(100.milliseconds) { error("should not fire") }
        scheduler.cancel()
        assertEquals(1, scheduler.cancelCount)
        assertFalse(scheduler.hasPending)
    }

    @Test
    fun fakeWatchStopBeforeStartIsHarmless() {
        val watch = FakeFolderWatch()
        watch.stop() // idempotent: stopping an unstarted watch must not throw
        assertFalse(watch.started)
        assertEquals(1, watch.stopCount)
    }

    @Test
    fun fakeWatchEmitAfterStopThrows() {
        val watch = FakeFolderWatch()
        watch.start {}
        watch.stop()
        assertThrows(IllegalStateException::class.java) { watch.emit(MonotonicInstant(1)) }
    }
}
