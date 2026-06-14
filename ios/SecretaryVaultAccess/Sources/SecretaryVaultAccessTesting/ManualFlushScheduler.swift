import Foundation
import SecretaryVaultAccess

/// In-memory `FlushScheduler`. Tests inspect `scheduledDelay` and call `fire`.
public final class ManualFlushScheduler: FlushScheduler {
    public private(set) var scheduledDelay: Duration?
    public private(set) var cancelCount = 0
    private var pending: (@MainActor (MonotonicInstant) -> Void)?

    public init() {}

    public func schedule(after delay: Duration,
                         _ work: @escaping @MainActor (MonotonicInstant) -> Void) {
        scheduledDelay = delay
        pending = work
    }

    public func cancel() {
        cancelCount += 1
        scheduledDelay = nil
        pending = nil
    }

    /// Test hook: fire the pending work with a chosen instant (no-op if cancelled).
    @MainActor public func fire(at instant: MonotonicInstant) {
        let work = pending
        pending = nil
        scheduledDelay = nil
        work?(instant)
    }
}
