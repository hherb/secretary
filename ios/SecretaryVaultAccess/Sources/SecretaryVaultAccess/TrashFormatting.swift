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

/// Absolute yyyy-MM-dd (POSIX, UTC) of a tombstone timestamp. Deliberately
/// deterministic (fixed locale + UTC) rather than desktop's locale-aware
/// short-date, so this pure helper is host-testable without a fixed clock/zone.
/// Trade-off: the displayed calendar day is UTC, so a block trashed within a
/// few hours of local midnight can render the adjacent day.
public func formatTrashedWhen(_ ms: UInt64) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "UTC")
    f.dateFormat = "yyyy-MM-dd"
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
