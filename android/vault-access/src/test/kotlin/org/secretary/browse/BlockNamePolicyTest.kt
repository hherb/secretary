package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BlockNamePolicyTest {
    private fun block(uuidByte: Int, name: String) =
        BlockSummaryView(ByteArray(16) { uuidByte.toByte() }, name, 0u, 0u)

    private val work = block(0x11, "Work")
    private val personal = block(0x22, "Personal")
    private val existing = listOf(work, personal)

    @Test
    fun `empty block list never collides`() {
        assertFalse(blockNameCollides("Work", emptyList()))
    }

    @Test
    fun `unique name does not collide`() {
        assertFalse(blockNameCollides("Finance", existing))
    }

    @Test
    fun `exact duplicate collides`() {
        assertTrue(blockNameCollides("Work", existing))
    }

    @Test
    fun `surrounding whitespace is trimmed before comparison`() {
        assertTrue(blockNameCollides("  Work  ", existing))
    }

    @Test
    fun `case-only difference collides (case-insensitive)`() {
        assertTrue(blockNameCollides("work", existing))
    }

    @Test
    fun `blank candidate never collides`() {
        assertFalse(blockNameCollides("   ", existing))
    }

    @Test
    fun `rename to own current name does not collide (self excluded)`() {
        assertFalse(blockNameCollides("Work", existing, excludeUuid = work.uuid))
    }

    @Test
    fun `rename to a different existing name collides`() {
        assertTrue(blockNameCollides("Personal", existing, excludeUuid = work.uuid))
    }
}
