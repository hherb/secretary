package org.secretary.browse

/**
 * Milliseconds per minute — the minutes↔ms conversion base for the re-auth grace control.
 * ([MS_PER_DAY], the retention base, lives in `TrashFormatting`.)
 */
const val MS_PER_MINUTE: Long = 60_000L

// ---- Retention (days) ↔ ms — reuse msToDays (parity with desktop round(ms / MS_PER_DAY) + iOS) ----

/** Whole days in [ms], rounded to nearest, as an `Int` for the stepper (reuses [msToDays]). */
fun retentionDaysFromMs(ms: Long): Int = msToDays(ms).toInt()

/** Days → ms (parity with desktop `days * MS_PER_DAY`). A negative input clamps to 0 (the stepper
 *  never produces one; belt-and-suspenders for `Int`→`Long`). */
fun msFromRetentionDays(days: Int): Long = maxOf(0, days).toLong() * MS_PER_DAY

// ---- Re-auth grace (minutes) ↔ ms (parity with desktop round(ms / MS_PER_MINUTE) + iOS) ----

/** Whole minutes in [ms], rounded to nearest, as an `Int` for the stepper. */
fun graceMinutesFromMs(ms: Long): Int = ((ms + MS_PER_MINUTE / 2) / MS_PER_MINUTE).toInt()

/** Minutes → ms (parity with desktop `minutes * MS_PER_MINUTE`). Negative → 0. */
fun msFromGraceMinutes(minutes: Int): Long = maxOf(0, minutes).toLong() * MS_PER_MINUTE

// ---- Client-side clamps — validate against the projected FFI bounds (same constants the server enforces) ----

/** Clamp a retention-days input to the bounds' day range (inclusive). The bounds come from the port
 *  ([SettingsPort.settingsBounds]), so the UI validates against the same constants the server enforces. */
fun clampRetentionDays(days: Int, bounds: SettingsBounds): Int {
    val lo = retentionDaysFromMs(bounds.retentionMinMs)
    val hi = retentionDaysFromMs(bounds.retentionMaxMs)
    return minOf(maxOf(days, lo), hi)
}

/** Clamp a grace-minutes input to the bounds' minute range (inclusive). */
fun clampGraceMinutes(minutes: Int, bounds: SettingsBounds): Int {
    val lo = graceMinutesFromMs(bounds.reauthGraceMinMs)
    val hi = graceMinutesFromMs(bounds.reauthGraceMaxMs)
    return minOf(maxOf(minutes, lo), hi)
}

/** The banner shown after a successful settings save (mirror iOS `settingsSavedBanner`). */
fun settingsSavedBanner(): SettingsBanner = SettingsBanner("Settings saved")
