import Foundation
import SecretaryVaultAccess

extension MonotonicInstant {
    /// Current monotonic instant from `DispatchTime` (uptime nanoseconds). Lives
    /// in SecretaryKit so the pure `SecretaryVaultAccess` package stays free of
    /// any real clock dependency. `public` so the app's composition root can inject
    /// it as the write-reauth gate's clock (issue #282) — the same monotonic source
    /// the folder-change detector already uses.
    public static func now() -> MonotonicInstant {
        // Use `mach_continuous_time` (continuous clock) rather than
        // `DispatchTime.uptimeNanoseconds` (= `mach_absolute_time`), which PAUSES
        // while the device is asleep (#365). The write-reauth grace window must
        // measure real elapsed time, not awake-time, so a vault backgrounded-then-
        // slept cannot silently extend its 30s window; the folder-change detector
        // that shares this source is equally correct counting sleep.
        //
        // Convert mach ticks → nanoseconds via the timebase (numer/denom is 1/1 on
        // most hardware but not guaranteed). The `UInt64` count since boot fits
        // `Int64` for ~292 years — no truncation or sign flip.
        var timebase = mach_timebase_info()
        mach_timebase_info(&timebase)
        let ticks = mach_continuous_time()
        let nanos = ticks &* UInt64(timebase.numer) / UInt64(timebase.denom)
        return MonotonicInstant(nanoseconds: Int64(bitPattern: nanos))
    }
}
