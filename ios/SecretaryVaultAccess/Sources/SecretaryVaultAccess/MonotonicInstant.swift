import Foundation

/// A point on a monotonic timeline, in nanoseconds since an arbitrary fixed
/// origin. Only ordering and differences are meaningful — never interpret as
/// wall-clock time. Keeps the detection core free of any real clock (real
/// instants are stamped by `SecretaryKit`'s `MonotonicInstant.now()`).
public struct MonotonicInstant: Comparable, Equatable, Sendable {
    public let nanoseconds: Int64
    public init(nanoseconds: Int64) { self.nanoseconds = nanoseconds }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.nanoseconds < rhs.nanoseconds }

    /// This instant moved forward by `duration`.
    public func advanced(by duration: Duration) -> MonotonicInstant {
        MonotonicInstant(nanoseconds: nanoseconds + duration.wholeNanoseconds)
    }

    /// Gap from this instant to a (presumed later) one. Negative if `later` precedes self.
    public func duration(to later: MonotonicInstant) -> Duration {
        .nanoseconds(later.nanoseconds - nanoseconds)
    }
}

extension Duration {
    /// Whole nanoseconds (drops sub-nanosecond attoseconds). Used by
    /// `MonotonicInstant` arithmetic and by `SecretaryKit`'s
    /// `DispatchFlushScheduler` to convert a `Duration` into a
    /// `DispatchTimeInterval`.
    public var wholeNanoseconds: Int64 {
        let (seconds, attoseconds) = components
        return seconds * 1_000_000_000 + attoseconds / 1_000_000_000
    }
}

/// Tunable constants for change detection. Injectable into `FolderChangeDetector`
/// so tests can use a tiny window; production uses the default.
public enum ChangeDetectionTuning {
    /// Trailing-debounce quiet period after the last folder pulse before the
    /// "remote changes detected" signal is raised.
    public static let defaultDebounceWindow: Duration = .milliseconds(2_000)
}
