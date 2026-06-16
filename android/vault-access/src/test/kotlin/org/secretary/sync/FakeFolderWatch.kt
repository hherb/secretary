package org.secretary.sync

/**
 * In-memory [FolderWatchPort] for host tests. The test drives raw pulses via [emit].
 * [startError], if set, is thrown by [start] (before any state changes) to exercise the
 * monitor's start-failure roll-back path.
 */
class FakeFolderWatch : FolderWatchPort {
    var startCount: Int = 0
        private set
    var stopCount: Int = 0
        private set
    var startError: Throwable? = null
    private var onPulse: ((MonotonicInstant) -> Unit)? = null

    val started: Boolean get() = onPulse != null

    override fun start(onPulse: (MonotonicInstant) -> Unit) {
        startError?.let { throw it }
        this.onPulse = onPulse
        startCount++
    }

    override fun stop() {
        onPulse = null
        stopCount++
    }

    /** Deliver a pulse through the registered callback (simulates an OS event). */
    fun emit(at: MonotonicInstant) {
        val cb = onPulse ?: error("emit called while watch not started")
        cb(at)
    }
}
