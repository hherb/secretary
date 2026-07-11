package org.secretary.browse

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

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

/**
 * Locale-aware medium-style date (e.g. "Jun 15, 2024") of a tombstone timestamp, matching desktop's
 * short-month date and iOS `formatTrashedWhen`. The [zone] and [locale] are injected rather than
 * read from ambient state, so this helper stays pure and host-testable: production passes
 * `ZoneId.systemDefault()` / `Locale.getDefault()` (resolving the prior UTC-vs-local parity gap with
 * desktop, #413), while tests pin a fixed zone and locale for deterministic assertions.
 */
fun formatTrashedWhen(ms: Long, zone: ZoneId, locale: Locale): String =
    DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)
        .withLocale(locale)
        .withZone(zone)
        .format(Instant.ofEpochMilli(ms))

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

/** Severity of a post-op purge notice (#411): a plain confirmation or a warning that some
 * on-disk files could not be removed. Mirror of desktop/iOS `PurgeSeverity`. */
enum class PurgeSeverity { SUCCESS, WARNING }

/** A formatted post-op notice for the Trash browser banner. */
data class PurgeNotice(val text: String, val severity: PurgeSeverity)

/**
 * Normalized outcome the model builds from whichever report an op returned. [SinglePurge]
 * (delete-forever) carries no count — its DTO ([PurgeResultInfo]) has none. Logic mirrors desktop
 * and iOS `formatPurgeNotice`.
 */
sealed interface PurgeOutcome {
    data class EmptyTrash(val purgedCount: Int, val filesFailed: Int) : PurgeOutcome
    data class Retention(val purgedCount: Int, val filesFailed: Int) : PurgeOutcome
    data object SinglePurge : PurgeOutcome
}

/** "1 item" / "4 items" — English count noun. */
private fun pluralCount(n: Int, singular: String): String =
    if (n == 1) "1 $singular" else "$n ${singular}s"

/** Map a destructive-trash outcome to a banner string + severity (#411). */
fun formatPurgeNotice(outcome: PurgeOutcome): PurgeNotice = when (outcome) {
    is PurgeOutcome.SinglePurge -> PurgeNotice("Deleted forever", PurgeSeverity.SUCCESS)
    is PurgeOutcome.EmptyTrash -> countNotice(outcome.purgedCount, outcome.filesFailed, "Trash was already empty")
    is PurgeOutcome.Retention -> countNotice(outcome.purgedCount, outcome.filesFailed, "No items were past the retention window")
}

private fun countNotice(purgedCount: Int, filesFailed: Int, zeroText: String): PurgeNotice {
    // purgedCount == 0 is checked before filesFailed by design: the Rust report
    // source guarantees `filesFailed > 0 ⇒ purgedCount > 0`, so {0, >0} — which would
    // show the no-op message and hide the failure — is unreachable. If that source
    // invariant changes, reorder (mirror in desktop/iOS formatters).
    if (purgedCount == 0) return PurgeNotice(zeroText, PurgeSeverity.SUCCESS)
    val base = "Purged ${pluralCount(purgedCount, "item")}"
    return if (filesFailed > 0) {
        PurgeNotice("$base · ${pluralCount(filesFailed, "file")} could not be removed", PurgeSeverity.WARNING)
    } else {
        PurgeNotice(base, PurgeSeverity.SUCCESS)
    }
}
