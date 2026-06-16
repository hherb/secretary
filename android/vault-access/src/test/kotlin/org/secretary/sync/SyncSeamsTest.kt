package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SyncSeamsTest {
    @Test
    fun fakeWallClockReturnsSeededValue() {
        val clock = FakeWallClock(currentMs = 1_234uL)
        assertEquals(1_234uL, clock.nowMs())
        clock.currentMs = 5_678uL
        assertEquals(5_678uL, clock.nowMs())
    }

    @Test
    fun fakeSyncMonitorHookCountsCalls() {
        val hook = FakeSyncMonitorHook()
        hook.muteSelfWrite()
        hook.muteSelfWrite()
        hook.acknowledge()
        assertEquals(2, hook.muteCount)
        assertEquals(1, hook.acknowledgeCount)
    }
}
