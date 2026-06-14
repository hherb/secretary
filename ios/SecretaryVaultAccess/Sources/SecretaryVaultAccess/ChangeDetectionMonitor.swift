import Foundation

/// Coordinates a `FolderChangeDetector` with a `FolderWatchPort` (OS pulses) and
/// a `FlushScheduler` (debounce timer), exposing an advisory `pendingChanges`
/// flag and an `onChange` callback for a future UI slice. `@MainActor`-isolated:
/// real conformers deliver their callbacks on the main actor, so all detector
/// mutation is serialized there with no extra locking.
///
/// Detect-only: a raised signal never triggers a sync pass (no password in hand
/// after unlock). Acting on it (re-prompt / sync-at-unlock) is slice 3.
@MainActor
public final class ChangeDetectionMonitor {
    private var detector: FolderChangeDetector
    private let watch: FolderWatchPort
    private let scheduler: FlushScheduler
    private let onChange: () -> Void

    /// True once a debounced change is awaiting the user; cleared by `acknowledge`.
    public private(set) var pendingChanges = false

    public init(detector: FolderChangeDetector, watch: FolderWatchPort,
                scheduler: FlushScheduler, onChange: @escaping () -> Void) {
        self.detector = detector
        self.watch = watch
        self.scheduler = scheduler
        self.onChange = onChange
    }

    /// Start watching + gate active. Throws if the watch port can't start.
    public func start() throws {
        detector.setActive(true)
        try watch.start(onPulse: { [weak self] instant in
            self?.handlePulse(at: instant)
        })
    }

    /// Stop watching, cancel any armed flush, gate inactive, clear the signal.
    public func stop() {
        scheduler.cancel()
        watch.stop()
        detector.setActive(false)
        pendingChanges = detector.pendingChanges
    }

    /// Consume the signal (a later change re-arms).
    public func acknowledge() {
        detector.acknowledge()
        pendingChanges = detector.pendingChanges
    }

    /// Suppress watcher pulses stamped before `instant` (self-write window).
    public func muteUntil(_ instant: MonotonicInstant) {
        detector.muteUntil(instant)
    }

    private func handlePulse(at instant: MonotonicInstant) {
        detector.recordPulse(at: instant)
        rearm(now: instant)
    }

    private func rearm(now: MonotonicInstant) {
        guard let deadline = detector.nextFlushDeadline else { scheduler.cancel(); return }
        scheduler.schedule(after: now.duration(to: deadline)) { [weak self] fireInstant in
            self?.handleFlush(now: fireInstant)
        }
    }

    private func handleFlush(now: MonotonicInstant) {
        if detector.flush(now: now) {
            pendingChanges = true
            onChange()
        } else {
            rearm(now: now)        // a later pulse moved the deadline
        }
    }
}
