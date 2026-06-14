import Foundation

/// Pure, deterministic reducer that turns a noisy stream of folder-change pulses
/// into a single debounced, foreground-gated "pending changes" signal. No real
/// clock or timer: callers supply instants and drive `flush`. Trailing debounce
/// — the signal is raised once the folder has been quiet for `debounceWindow`
/// after the last pulse.
///
/// Advisory + metadata-only: it sees timestamps, never record contents, and a
/// missed/spurious pulse never corrupts anything (sync reconciles truth).
public struct FolderChangeDetector: Sendable {
    public let debounceWindow: Duration
    public private(set) var isActive: Bool
    public private(set) var pendingChanges: Bool
    private var lastPulseAt: MonotonicInstant?
    private var muteBefore: MonotonicInstant?

    public init(debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow) {
        self.debounceWindow = debounceWindow
        self.isActive = false
        self.pendingChanges = false
    }

    /// Instant the monitor should next attempt a `flush`, or nil if nothing is
    /// armed (inactive, already pending, or no pulse seen).
    public var nextFlushDeadline: MonotonicInstant? {
        guard isActive, !pendingChanges, let last = lastPulseAt else { return nil }
        return last.advanced(by: debounceWindow)
    }

    /// Foreground/unlocked gate (ADR-0003 foreground-only). Going inactive resets
    /// detection state for a clean slate on next foreground.
    public mutating func setActive(_ active: Bool) {
        guard active != isActive else { return }
        isActive = active
        if !active {
            lastPulseAt = nil
            muteBefore = nil
            pendingChanges = false
        }
    }

    /// Record a watcher pulse. Dropped while inactive or muted. `max` keeps the
    /// armed deadline correct even if near-simultaneous pulses arrive out of order.
    public mutating func recordPulse(at instant: MonotonicInstant) {
        guard isActive else { return }
        if let mute = muteBefore, instant < mute { return }
        lastPulseAt = Swift.max(lastPulseAt ?? instant, instant)
    }

    /// Suppress pulses stamped strictly before `instant` (self-write window).
    public mutating func muteUntil(_ instant: MonotonicInstant) {
        muteBefore = instant
    }

    /// Attempt to raise the signal. Returns true iff this call flipped
    /// `pendingChanges` false→true, so the monitor fires `onChange` exactly once.
    @discardableResult
    public mutating func flush(now: MonotonicInstant) -> Bool {
        guard isActive, !pendingChanges, let last = lastPulseAt else { return false }
        guard now >= last.advanced(by: debounceWindow) else { return false }
        pendingChanges = true
        lastPulseAt = nil          // consumed; further pulses re-arm post-acknowledge
        return true
    }

    /// Caller consumed the signal. A later pulse re-arms.
    public mutating func acknowledge() {
        pendingChanges = false
    }
}
