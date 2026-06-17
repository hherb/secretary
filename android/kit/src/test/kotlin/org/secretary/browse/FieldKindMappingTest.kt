package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class FieldKindMappingTest {
    @Test
    fun `isText true maps to Text kind`() {
        assertEquals(FieldKind.Text, fieldKindOf(isText = true))
    }

    @Test
    fun `isText false maps to Bytes kind`() {
        assertEquals(FieldKind.Bytes, fieldKindOf(isText = false))
    }
}
