import Foundation

/// Milliseconds per day — the days↔ms conversion base.
public let msPerDay: UInt64 = 86_400_000

/// Whole days in `ms`, rounded to nearest — parity with desktop `msToDays`
/// (`Math.round(ms / MS_PER_DAY)`). Integer round-half-up; cannot overflow
/// for realistic ms values.
public func msToDays(_ ms: UInt64) -> UInt64 { (ms + msPerDay / 2) / msPerDay }

/// Trashed blocks newest-first by tombstone time (parity: desktop `sortTrashed`).
public func sortTrashed(_ entries: [TrashedBlockInfo]) -> [TrashedBlockInfo] {
    entries.sorted { $0.tombstonedAtMs > $1.tombstonedAtMs }
}

/// Locale-aware medium-style date (e.g. "Jun 15, 2024") of a tombstone timestamp,
/// matching desktop's short-month `formatShortDate`. The `timeZone` and `locale` are
/// injected rather than read from ambient state, so the helper stays pure and
/// host-testable: production passes `.current` (the user's zone/locale, resolving the
/// prior UTC-vs-local parity gap with desktop, #413), while tests pin a fixed zone and
/// locale for deterministic assertions.
public func formatTrashedWhen(_ ms: UInt64, timeZone: TimeZone, locale: Locale) -> String {
    let f = DateFormatter()
    f.locale = locale
    f.timeZone = timeZone
    f.dateStyle = .medium
    f.timeStyle = .none
    return f.string(from: Date(timeIntervalSince1970: Double(ms) / 1000.0))
}

/// Empty-trash confirm body (parity: desktop `emptyTrashConfirmBody`).
public func emptyTrashConfirmBody(count: Int) -> String {
    let lead = count == 1 ? "The 1 item" : "All \(count) items"
    return "\(lead) in trash will be permanently deleted. This cannot be undone."
}

/// Retention summary (parity: desktop `retentionSummary`).
public func retentionSummary(entries: [ExpiredEntryInfo], windowMs: UInt64) -> String {
    let days = msToDays(windowMs)
    if entries.isEmpty {
        return "No trashed items are older than \(days) days."
    }
    let n = entries.count
    let oldestDays = msToDays(entries.map { $0.ageMs }.max() ?? 0)
    let noun = n == 1 ? "item" : "items"
    return "\(n) \(noun) trashed more than \(days) days ago will be permanently deleted (oldest: \(oldestDays) days)."
}
