import Foundation
import SecretaryVaultAccess

extension MonotonicInstant {
    /// Current monotonic instant from `DispatchTime` (uptime nanoseconds). Lives
    /// in SecretaryKit so the pure `SecretaryVaultAccess` package stays free of
    /// any real clock dependency. `public` so the app's composition root can inject
    /// it as the write-reauth gate's clock (issue #282) — the same monotonic source
    /// the folder-change detector already uses.
    public static func now() -> MonotonicInstant {
        // `uptimeNanoseconds` is a `UInt64` since boot; reinterpreting its bit
        // pattern as `Int64` is exact (and stays positive) for ~292 years of
        // uptime, far beyond any device's lifetime — no truncation or sign flip.
        MonotonicInstant(nanoseconds: Int64(bitPattern: DispatchTime.now().uptimeNanoseconds))
    }
}
