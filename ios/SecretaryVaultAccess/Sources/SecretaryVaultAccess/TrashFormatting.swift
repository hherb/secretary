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

/// Severity of a post-op purge notice (#411): a plain confirmation or a
/// warning that some on-disk files could not be removed.
public enum PurgeSeverity: Equatable {
    case success
    case warning
}

/// A formatted post-op notice for the Trash browser banner.
public struct PurgeNotice: Equatable {
    public let text: String
    public let severity: PurgeSeverity
    public init(text: String, severity: PurgeSeverity) {
        self.text = text
        self.severity = severity
    }
}

/// Normalized outcome the view-model builds from whichever report an op
/// returned. `singlePurge` (delete-forever) carries no count — its DTO
/// (`PurgeResultInfo`) has none. Logic mirrors desktop `formatPurgeNotice`
/// and Android's `formatPurgeNotice`.
public enum PurgeOutcome: Equatable {
    case emptyTrash(purgedCount: UInt32, filesFailed: UInt32)
    case retention(purgedCount: UInt32, filesFailed: UInt32)
    case singlePurge
}

private func pluralCount(_ n: UInt32, _ singular: String) -> String {
    n == 1 ? "1 \(singular)" : "\(n) \(singular)s"
}

/// Map a destructive-trash outcome to a banner string + severity (#411).
public func formatPurgeNotice(_ outcome: PurgeOutcome) -> PurgeNotice {
    switch outcome {
    case .singlePurge:
        return PurgeNotice(text: "Deleted forever", severity: .success)
    case let .emptyTrash(purgedCount, filesFailed):
        return countNotice(purgedCount, filesFailed, zeroText: "Trash was already empty")
    case let .retention(purgedCount, filesFailed):
        return countNotice(purgedCount, filesFailed, zeroText: "No items were past the retention window")
    }
}

private func countNotice(_ purgedCount: UInt32, _ filesFailed: UInt32, zeroText: String) -> PurgeNotice {
    // purgedCount == 0 is checked before filesFailed by design: the Rust report
    // source guarantees `filesFailed > 0 ⇒ purgedCount > 0`, so {0, >0} — which
    // would show the no-op message and hide the failure — is unreachable. If that
    // source invariant changes, reorder (mirror in desktop/Android formatters).
    if purgedCount == 0 {
        return PurgeNotice(text: zeroText, severity: .success)
    }
    let base = "Purged \(pluralCount(purgedCount, "item"))"
    if filesFailed > 0 {
        return PurgeNotice(text: "\(base) · \(pluralCount(filesFailed, "file")) could not be removed", severity: .warning)
    }
    return PurgeNotice(text: base, severity: .success)
}
