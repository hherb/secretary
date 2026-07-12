package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** Pure retention-days / grace-minutes ↔ ms conversions + client-side clamps (parity with desktop
 *  `SettingsDialog` and iOS `SettingsConversions`). */
class SettingsConversionsTest {
    private val bounds = SettingsBounds(
        retentionDefaultMs = 90L * MS_PER_DAY,
        retentionMinMs = MS_PER_DAY,
        retentionMaxMs = 3650L * MS_PER_DAY,
        reauthGraceDefaultMs = 120_000L,
        reauthGraceMinMs = 0L,
        reauthGraceMaxMs = 3_600_000L,
    )

    @Test
    fun `retention days round-trips`() {
        assertEquals(90, retentionDaysFromMs(90L * MS_PER_DAY))
        assertEquals(90L * MS_PER_DAY, msFromRetentionDays(90))
    }

    @Test
    fun `retention days rounds half-up`() {
        assertEquals(2, retentionDaysFromMs(MS_PER_DAY + MS_PER_DAY / 2)) // 1.5 d → 2
    }

    @Test
    fun `grace minutes round-trips`() {
        assertEquals(2, graceMinutesFromMs(120_000L))
        assertEquals(120_000L, msFromGraceMinutes(2))
    }

    @Test
    fun `grace minutes rounds half-up`() {
        assertEquals(2, graceMinutesFromMs(MS_PER_MINUTE + MS_PER_MINUTE / 2)) // 1.5 min → 2
    }

    @Test
    fun `msFromRetentionDays clamps a negative to zero`() {
        assertEquals(0L, msFromRetentionDays(-3))
    }

    @Test
    fun `msFromGraceMinutes clamps a negative to zero`() {
        assertEquals(0L, msFromGraceMinutes(-3))
    }

    @Test
    fun `clampRetentionDays clamps to the bounds' day range`() {
        assertEquals(1, clampRetentionDays(0, bounds))       // below min → 1
        assertEquals(3650, clampRetentionDays(9999, bounds)) // above max → 3650
        assertEquals(90, clampRetentionDays(90, bounds))     // in range unchanged
    }

    @Test
    fun `clampGraceMinutes clamps to the bounds' minute range`() {
        assertEquals(0, clampGraceMinutes(-5, bounds))   // below min → 0
        assertEquals(60, clampGraceMinutes(999, bounds)) // above max → 60
        assertEquals(2, clampGraceMinutes(2, bounds))    // in range unchanged
    }

    @Test
    fun `settingsSavedBanner has the expected text`() {
        assertEquals(SettingsBanner("Settings saved"), settingsSavedBanner())
    }
}
