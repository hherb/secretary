package org.secretary.browse.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.RecordSummaryView

class BrowseRenderHelpersTest {
    private fun rec(type: String, tags: List<String>, tombstone: Boolean = false) =
        RecordSummaryView("aa", type, tags, 1u, 2u, tombstone, listOf("username"))

    @Test
    fun `record title shows type and first tag`() {
        assertEquals("login · personal", recordTitle(rec("login", listOf("personal", "work"))))
    }

    @Test
    fun `record title without tags is just the type`() {
        assertEquals("login", recordTitle(rec("login", emptyList())))
    }

    @Test
    fun `untyped record falls back to a placeholder`() {
        assertEquals("Untitled record", recordTitle(rec("", emptyList())))
    }

    @Test
    fun `deleted record title is prefixed`() {
        assertEquals("(deleted) login", recordTitle(rec("login", emptyList(), tombstone = true)))
    }

    @Test
    fun `block label uses the name and falls back when blank`() {
        assertEquals("Logins", blockLabel(BlockSummaryView(ByteArray(16), "Logins", 1u, 2u)))
        assertEquals("Untitled block", blockLabel(BlockSummaryView(ByteArray(16), "", 1u, 2u)))
    }
}
