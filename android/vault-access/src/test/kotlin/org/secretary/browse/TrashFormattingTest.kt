package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

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
    fun `formatTrashedWhen renders UTC yyyy-MM-dd`() {
        // 2021-01-01T00:00:00Z = 1_609_459_200_000 ms
        assertEquals("2021-01-01", formatTrashedWhen(1_609_459_200_000L))
        // 2026-07-11T12:00:00Z = 1_783_771_200_000 ms
        assertEquals("2026-07-11", formatTrashedWhen(1_783_771_200_000L))
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
