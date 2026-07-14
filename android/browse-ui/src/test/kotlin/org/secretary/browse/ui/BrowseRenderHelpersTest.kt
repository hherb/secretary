package org.secretary.browse.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FieldKind
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.RevealableField
import org.secretary.browse.RevealedValue

private fun textField(name: String, value: String) =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }

class BrowseRenderHelpersTest {
    private fun rec(type: String, tags: List<String>, tombstone: Boolean = false) =
        RecordSummaryView("aa", type, tags, 1u, 2u, tombstone, listOf(textField("username", "u")))

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

    @Test
    fun `revealed text value is shown as-is`() {
        assertEquals("hunter2", revealedText(RevealedValue.Text("hunter2")))
    }

    @Test
    fun `revealed bytes value is shown as lowercase hex`() {
        assertEquals("00ff10", revealedText(RevealedValue.Bytes(byteArrayOf(0, 0xff.toByte(), 0x10))))
    }

    @Test
    fun `move is hidden when the vault has zero or one block`() {
        assertEquals(false, hasMoveTargets(0))
        assertEquals(false, hasMoveTargets(1))
    }

    @Test
    fun `move is shown once a second block exists`() {
        assertEquals(true, hasMoveTargets(2))
        assertEquals(true, hasMoveTargets(3))
    }
}
