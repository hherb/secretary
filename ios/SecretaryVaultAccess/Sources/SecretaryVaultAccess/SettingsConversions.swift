import Foundation

/// Milliseconds per minute — the minutes↔ms conversion base for the re-auth
/// grace control. (`msPerDay`, the retention base, lives in `TrashFormatting`.)
public let msPerMinute: UInt64 = 60_000

// MARK: - Retention (days) ↔ ms

/// Whole days in `ms`, rounded to nearest, as an `Int` for the SwiftUI stepper.
/// Reuses `msToDays` (parity with desktop `Math.round(ms / MS_PER_DAY)`).
public func retentionDaysFromMs(_ ms: UInt64) -> Int { Int(msToDays(ms)) }

/// Days → ms (parity with desktop `days * MS_PER_DAY`). A negative input clamps
/// to 0 (the stepper never produces one; belt-and-suspenders for `Int`→`UInt64`).
public func msFromRetentionDays(_ days: Int) -> UInt64 { UInt64(max(0, days)) * msPerDay }

// MARK: - Re-auth grace (minutes) ↔ ms

/// Whole minutes in `ms`, rounded to nearest, as an `Int` for the stepper
/// (parity with desktop `Math.round(ms / MS_PER_MINUTE)`).
public func graceMinutesFromMs(_ ms: UInt64) -> Int { Int((ms + msPerMinute / 2) / msPerMinute) }

/// Minutes → ms (parity with desktop `minutes * MS_PER_MINUTE`). Negative → 0.
public func msFromGraceMinutes(_ minutes: Int) -> UInt64 { UInt64(max(0, minutes)) * msPerMinute }

// MARK: - Client-side clamps (validate against the projected FFI bounds)

/// Clamp a retention-days input to the bounds' day range (inclusive). The bounds
/// come from the port (`settingsBounds()`), so the UI validates against the same
/// constants the server enforces.
public func clampRetentionDays(_ days: Int, bounds: SettingsBounds) -> Int {
    let lo = retentionDaysFromMs(bounds.retentionMinMs)
    let hi = retentionDaysFromMs(bounds.retentionMaxMs)
    return min(max(days, lo), hi)
}

/// Clamp a grace-minutes input to the bounds' minute range (inclusive).
public func clampGraceMinutes(_ minutes: Int, bounds: SettingsBounds) -> Int {
    let lo = graceMinutesFromMs(bounds.reauthGraceMinMs)
    let hi = graceMinutesFromMs(bounds.reauthGraceMaxMs)
    return min(max(minutes, lo), hi)
}

// MARK: - Saved-confirmation banner

/// Inline saved-confirmation banner for the Settings screen (mirrors the Trash
/// `PurgeNotice` idiom). A settings save has no partial-failure state, so the
/// banner is always a benign confirmation; failures surface separately via the
/// view model's `error`.
public struct SettingsBanner: Equatable, Sendable {
    public let text: String
    public init(text: String) { self.text = text }
}

/// The banner shown after a successful settings save.
public func settingsSavedBanner() -> SettingsBanner { SettingsBanner(text: "Settings saved") }
