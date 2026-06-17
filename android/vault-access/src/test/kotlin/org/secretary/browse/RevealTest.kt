package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RevealTest {
    @Test
    fun `RevealPolicy auto-hide is a named 30 second constant`() {
        assertEquals(30L, RevealPolicy.autoHideSeconds)
    }

    @Test
    fun `RevealedValue Text uses value equality`() {
        assertEquals(RevealedValue.Text("hunter2"), RevealedValue.Text("hunter2"))
        assertNotEquals(RevealedValue.Text("hunter2"), RevealedValue.Text("other"))
    }

    @Test
    fun `RevealedValue Bytes compares by content not reference`() {
        val a = RevealedValue.Bytes(byteArrayOf(1, 2, 3))
        val b = RevealedValue.Bytes(byteArrayOf(1, 2, 3))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, RevealedValue.Bytes(byteArrayOf(1, 2, 4)))
    }

    @Test
    fun `RevealableField calls its reveal lambda on demand only`() {
        var calls = 0
        val field = RevealableField("password", FieldKind.Text) {
            calls++
            RevealedValue.Text("hunter2")
        }
        assertEquals(0, calls)                       // not eager
        assertEquals(RevealedValue.Text("hunter2"), field.reveal())
        assertEquals(1, calls)
        assertEquals(FieldKind.Text, field.kind)
        assertTrue(field.name == "password")
    }
}
