import Foundation

/// Wall-clock millisecond source for sync merge timestamps. Injected so the pure
/// layer never calls a real clock directly (mirrors `MonotonicInstant`'s split).
public protocol WallClock {
    /// Milliseconds since the Unix epoch.
    func nowMs() -> UInt64
}
