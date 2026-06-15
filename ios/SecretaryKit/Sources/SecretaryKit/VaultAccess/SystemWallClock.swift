import Foundation
import SecretaryVaultAccess

/// Production `WallClock` reading the system clock in epoch milliseconds.
public struct SystemWallClock: WallClock {
    public init() {}
    public func nowMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1_000)
    }
}
