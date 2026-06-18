package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RecoveryPhraseTest {
    @Test
    fun `collapses internal whitespace runs to single spaces`() {
        assertEquals("alpha bravo charlie", RecoveryPhrase.normalize("alpha   bravo\tcharlie"))
    }

    @Test
    fun `trims leading and trailing whitespace`() {
        assertEquals("alpha bravo", RecoveryPhrase.normalize("  alpha bravo  "))
    }

    @Test
    fun `lowercases mixed-case input`() {
        assertEquals("alpha bravo", RecoveryPhrase.normalize("Alpha BRAVO"))
    }

    @Test
    fun `collapses newlines and tabs as whitespace`() {
        assertEquals("one two three", RecoveryPhrase.normalize("one\ntwo\t\nthree"))
    }

    @Test
    fun `leaves an already-clean phrase unchanged`() {
        val clean = "wall annual clay zebra"
        assertEquals(clean, RecoveryPhrase.normalize(clean))
    }

    @Test
    fun `an all-whitespace string normalizes to empty`() {
        assertEquals("", RecoveryPhrase.normalize("   \t\n "))
    }
}
