package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Locale

class TrashFormattingTest {
    private fun block(name: String, ms: Long) =
        TrashedBlockInfo(ByteArray(16), name, ms, ByteArray(16))

    @Test
    fun `msToDays rounds half up`() {
        assertEquals(0L, msToDays(0L))
        assertEquals(1L, msToDays(MS_PER_DAY))
        // 90 days exactly
        assertEquals(90L, msToDays(90L * MS_PER_DAY))
        // 1.5 days rounds to 2 (half-up)
        assertEquals(2L, msToDays(MS_PER_DAY + MS_PER_DAY / 2))
        // just under half a day rounds to 0
        assertEquals(0L, msToDays(MS_PER_DAY / 2 - 1))
    }

    @Test
    fun `sortTrashed orders newest first`() {
        val a = block("a", 100L)
        val b = block("b", 300L)
        val c = block("c", 200L)
        assertEquals(listOf("b", "c", "a"), sortTrashed(listOf(a, b, c)).map { it.blockName })
    }

    @Test
    fun `formatTrashedWhen is locale-aware medium style`() {
        // 2021-01-01T00:00:00Z. Medium style is CLDR-version dependent, so assert the
        // calendar parts (short month + year) rather than an exact string.
        val s = formatTrashedWhen(1_609_459_200_000L, ZoneOffset.UTC, Locale.US)
        assertTrue(s.contains("2021"), s)
        assertTrue(s.contains("Jan"), s)
    }

    @Test
    fun `formatTrashedWhen honors the injected time zone across midnight`() {
        // 2021-01-01T02:00:00Z renders Jan 1 2021 in UTC but Dec 31 2020 in
        // America/Los_Angeles (UTC-8) — proving the zone parameter is honored.
        val ms = 1_609_459_200_000L + 2 * 3_600_000L
        val utcDay = formatTrashedWhen(ms, ZoneOffset.UTC, Locale.US)
        val laDay = formatTrashedWhen(ms, ZoneId.of("America/Los_Angeles"), Locale.US)
        assertTrue(utcDay.contains("2021"), utcDay)
        assertTrue(laDay.contains("2020"), laDay)
        assertNotEquals(utcDay, laDay)
    }

    @Test
    fun `emptyTrashConfirmBody singular vs plural`() {
        assertEquals(
            "The 1 item in trash will be permanently deleted. This cannot be undone.",
            emptyTrashConfirmBody(1),
        )
        assertEquals(
            "All 3 items in trash will be permanently deleted. This cannot be undone.",
            emptyTrashConfirmBody(3),
        )
    }

    @Test
    fun `retentionSummary empty and populated`() {
        val window = 90L * MS_PER_DAY
        assertEquals(
            "No trashed items are older than 90 days.",
            retentionSummary(emptyList(), window),
        )
        val entries = listOf(
            ExpiredEntryInfo(ByteArray(16), 0L, 100L * MS_PER_DAY),
            ExpiredEntryInfo(ByteArray(16), 0L, 95L * MS_PER_DAY),
        )
        assertEquals(
            "2 items trashed more than 90 days ago will be permanently deleted (oldest: 100 days).",
            retentionSummary(entries, window),
        )
        val one = listOf(ExpiredEntryInfo(ByteArray(16), 0L, 91L * MS_PER_DAY))
        assertEquals(
            "1 item trashed more than 90 days ago will be permanently deleted (oldest: 91 days).",
            retentionSummary(one, window),
        )
    }
}
