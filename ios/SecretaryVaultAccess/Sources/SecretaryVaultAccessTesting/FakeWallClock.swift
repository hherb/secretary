import Foundation
import SecretaryVaultAccess

/// Deterministic `WallClock` for tests. `currentMs` is freely settable so a test
/// can advance time between calls.
public final class FakeWallClock: WallClock {
    /// The value returned by `nowMs()`. Set freely between calls to advance time.
    public var currentMs: UInt64
    public init(nowMs: UInt64 = 0) { self.currentMs = nowMs }
    public func nowMs() -> UInt64 { currentMs }
}
