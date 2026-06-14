import Foundation
import SecretaryVaultAccess

/// Real `FlushScheduler` over a one-shot `DispatchSourceTimer` on the main queue.
/// `schedule` replaces any pending timer (single outstanding flush).
public final class DispatchFlushScheduler: FlushScheduler {
    private var timer: DispatchSourceTimer?

    public init() {}

    public func schedule(after delay: Duration,
                         _ work: @escaping @MainActor (MonotonicInstant) -> Void) {
        cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + delay.asDispatchTimeInterval)
        timer.setEventHandler {
            let instant = MonotonicInstant.now()
            // Fired on the main queue (main thread) → safe to assume main-actor
            // isolation for the callback.
            MainActor.assumeIsolated { work(instant) }
        }
        self.timer = timer
        timer.resume()
    }

    public func cancel() {
        timer?.cancel()
        timer = nil
    }
}

private extension Duration {
    /// Non-negative `DispatchTimeInterval` in whole nanoseconds for timer scheduling.
    var asDispatchTimeInterval: DispatchTimeInterval {
        .nanoseconds(Int(Swift.max(0, wholeNanoseconds)))
    }
}
