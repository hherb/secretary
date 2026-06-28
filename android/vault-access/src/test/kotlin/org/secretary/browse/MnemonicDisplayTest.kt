package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MnemonicDisplayTest {
    @Test
    fun `numbers words from one and splits on whitespace`() {
        val rows = groupMnemonic("alpha bravo  charlie".toByteArray(Charsets.UTF_8))
        assertEquals(
            listOf(MnemonicWord(1, "alpha"), MnemonicWord(2, "bravo"), MnemonicWord(3, "charlie")),
            rows,
        )
    }

    @Test
    fun `does not mutate the input phrase`() {
        val phrase = "alpha bravo".toByteArray(Charsets.UTF_8)
        val copy = phrase.copyOf()
        groupMnemonic(phrase)
        assertTrue(phrase.contentEquals(copy))
    }

    @Test
    fun `handles a full 24-word phrase`() {
        val words = (1..24).joinToString(" ") { "w$it" }
        val rows = groupMnemonic(words.toByteArray(Charsets.UTF_8))
        assertEquals(24, rows.size)
        assertEquals(MnemonicWord(24, "w24"), rows.last())
    }
}
