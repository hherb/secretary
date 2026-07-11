package org.secretary.browse

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** Milliseconds per day — the days↔ms conversion base. */
const val MS_PER_DAY: Long = 86_400_000L

/**
 * Whole days in [ms], rounded to nearest — parity with desktop `Math.round(ms / MS_PER_DAY)` and iOS
 * `msToDays`. Integer round-half-up; cannot overflow for realistic ms values.
 */
fun msToDays(ms: Long): Long = (ms + MS_PER_DAY / 2) / MS_PER_DAY

/** Trashed blocks newest-first by tombstone time (parity: desktop/iOS `sortTrashed`). */
fun sortTrashed(entries: List<TrashedBlockInfo>): List<TrashedBlockInfo> =
    entries.sortedByDescending { it.tombstonedAtMs }

/** Fixed UTC `yyyy-MM-dd` formatter (thread-safe; immutable). */
private val TRASHED_WHEN_FORMAT: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC)

/**
 * Absolute `yyyy-MM-dd` (UTC) of a tombstone timestamp. Deliberately deterministic (fixed pattern +
 * UTC) rather than desktop's locale-aware short-date, so this pure helper is host-testable without a
 * fixed clock/zone. Trade-off: the displayed calendar day is UTC, so a block trashed within a few
 * hours of local midnight can render the adjacent day. Locale-aware parity with desktop is tracked
 * in #413. Mirror of iOS `formatTrashedWhen`.
 */
fun formatTrashedWhen(ms: Long): String = TRASHED_WHEN_FORMAT.format(Instant.ofEpochMilli(ms))

/** Empty-trash confirm body (parity: desktop/iOS `emptyTrashConfirmBody`). */
fun emptyTrashConfirmBody(count: Int): String {
    val lead = if (count == 1) "The 1 item" else "All $count items"
    return "$lead in trash will be permanently deleted. This cannot be undone."
}

/** Retention summary (parity: desktop/iOS `retentionSummary`). */
fun retentionSummary(entries: List<ExpiredEntryInfo>, windowMs: Long): String {
    val days = msToDays(windowMs)
    if (entries.isEmpty()) return "No trashed items are older than $days days."
    val n = entries.size
    val oldestDays = msToDays(entries.maxOf { it.ageMs })
    val noun = if (n == 1) "item" else "items"
    return "$n $noun trashed more than $days days ago will be permanently deleted (oldest: $oldestDays days)."
}
