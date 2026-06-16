package org.secretary.sync

/** Host-test [WallClock] returning a settable epoch-millis value. */
class FakeWallClock(var currentMs: ULong = 0uL) : WallClock {
    override fun nowMs(): ULong = currentMs
}
