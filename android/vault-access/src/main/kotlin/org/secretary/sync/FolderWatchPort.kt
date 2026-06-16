package org.secretary.sync

/**
 * Seam over the OS folder watcher. A real conformer (see :kit FileObserverFolderWatch)
 * observes the vault folder and delivers a pulse per change; the fake drives pulses
 * directly. Conformers MUST deliver [onPulse] on the main thread so the monitor needs
 * no locking (mirrors the iOS @MainActor contract).
 */
interface FolderWatchPort {
    /** Begin watching; [onPulse] is invoked (on the main thread) per detected change.
     *  May throw if the folder can't be watched — the monitor surfaces it, no silent swallow. */
    fun start(onPulse: (MonotonicInstant) -> Unit)

    /** Stop watching. Idempotent. */
    fun stop()
}
