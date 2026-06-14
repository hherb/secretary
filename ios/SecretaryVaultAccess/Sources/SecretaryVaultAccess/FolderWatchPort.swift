import Foundation

/// Watches a folder and delivers a pulse (with the instant it was observed) on
/// each detected change. Callbacks are delivered on the main actor — real
/// conformers marshal OS callbacks onto it, so consumers need no extra hop.
public protocol FolderWatchPort: AnyObject {
    /// Begin watching. Throws if watching can't start (folder unreadable / scope lost).
    func start(onPulse: @escaping @MainActor (MonotonicInstant) -> Void) throws
    /// Stop watching and release the watch. Safe to call if not started.
    func stop()
}

/// Schedules a single debounce flush. `schedule` replaces any pending-but-unfired
/// work (one outstanding timer). The fire instant is passed to `work`. Callbacks
/// are delivered on the main actor.
public protocol FlushScheduler: AnyObject {
    func schedule(after delay: Duration, _ work: @escaping @MainActor (MonotonicInstant) -> Void)
    func cancel()
}
