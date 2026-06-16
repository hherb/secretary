package org.secretary.sync

/**
 * Wall-clock seam: milliseconds since the Unix epoch. Injected so the model can be host-tested
 * deterministically (a [SyncCoordinator] pass needs a `nowMs` for merge timestamps). The real
 * conformer is `:kit`'s SystemWallClock.
 */
interface WallClock {
    fun nowMs(): ULong
}
