package org.secretary.sync

/**
 * Real [WallClock] over `System.currentTimeMillis()` (epoch millis). Used to stamp `nowMs` on
 * sync passes; the merge layer interprets it as wall-clock time.
 */
class SystemWallClock : WallClock {
    override fun nowMs(): ULong = System.currentTimeMillis().toULong()
}
