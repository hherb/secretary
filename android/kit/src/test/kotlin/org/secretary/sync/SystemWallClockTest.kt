package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SystemWallClockTest {
    @Test
    fun nowMsTracksSystemClock() {
        val before = System.currentTimeMillis().toULong()
        val t = SystemWallClock().nowMs()
        val after = System.currentTimeMillis().toULong()
        assertTrue(t in before..after) { "nowMs $t not in [$before, $after]" }
    }
}
