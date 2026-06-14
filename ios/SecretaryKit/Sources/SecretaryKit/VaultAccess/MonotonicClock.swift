import Foundation
import SecretaryVaultAccess

extension MonotonicInstant {
    /// Current monotonic instant from `DispatchTime` (uptime nanoseconds). Lives
    /// in SecretaryKit so the pure `SecretaryVaultAccess` package stays free of
    /// any real clock dependency.
    static func now() -> MonotonicInstant {
        MonotonicInstant(nanoseconds: Int64(bitPattern: DispatchTime.now().uptimeNanoseconds))
    }
}
