package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class MonitorSyncHookTest {
    private fun at(ms: Long) = MonotonicInstant(ms * 1_000_000)

    // :kit test sources can't see :vault-access test fakes, so use minimal inline stubs over the
    // public FolderWatchPort / FlushScheduler interfaces.
    private class StubWatch : FolderWatchPort {
        var onPulse: ((MonotonicInstant) -> Unit)? = null
        override fun start(onPulse: (MonotonicInstant) -> Unit) { this.onPulse = onPulse }
        override fun stop() { onPulse = null }
    }

    private class StubScheduler : FlushScheduler {
        private var pending: ((MonotonicInstant) -> Unit)? = null
        override fun schedule(after: Duration, work: (MonotonicInstant) -> Unit) { pending = work }
        override fun cancel() { pending = null }
        fun fire(at: MonotonicInstant) { val w = pending; pending = null; w?.invoke(at) }
    }

    private class Rig {
        val watch = StubWatch()
        val scheduler = StubScheduler()
        var changes = 0
        val monitor = ChangeDetectionMonitor(
            detector = FolderChangeDetector(100.milliseconds),
            watch = watch,
            scheduler = scheduler,
            onChange = { changes++ },
        ).also { it.start() }
    }

    @Test
    fun muteSelfWriteSuppressesPulsesWithinWindow() {
        val rig = Rig()
        // mute pulses stamped before at(0) + 10s = at(10_000)
        val hook = MonitorSyncHook(rig.monitor, muteWindow = 10.seconds, now = { at(0) })
        hook.muteSelfWrite()
        rig.watch.onPulse!!(at(5_000)) // within the mute window → dropped by the detector
        rig.scheduler.fire(at(5_100))  // nothing armed → no-op
        assertEquals(0, rig.changes)
        assertFalse(rig.monitor.pendingChanges)
    }

    @Test
    fun acknowledgeForwardsAndClearsRaisedSignal() {
        val rig = Rig()
        rig.watch.onPulse!!(at(0))
        rig.scheduler.fire(at(100)) // quiet window elapsed → signal raised
        assertTrue(rig.monitor.pendingChanges)
        val hook = MonitorSyncHook(rig.monitor, now = { at(1_000) })
        hook.acknowledge()
        assertFalse(rig.monitor.pendingChanges)
    }
}
