package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.FieldInputValue

class RecordContentMappingTest {
    @Test
    fun `maps record type, tags and text-or-bytes fields`() {
        val input = RecordContentInput(
            recordType = "login",
            tags = listOf("personal"),
            fields = listOf(
                FieldContentInput("user", FieldContentValue.Text("alice")),
                FieldContentInput("salt", FieldContentValue.Bytes(byteArrayOf(0xAB.toByte(), 0xCD.toByte()))),
            ),
        )
        val ffi = toFfi(input)
        assertEquals("login", ffi.recordType)
        assertEquals(listOf("personal"), ffi.tags)
        assertEquals("user", ffi.fields[0].name)
        assertEquals(FieldInputValue.Text("alice"), ffi.fields[0].value)
        val bytesValue = ffi.fields[1].value as FieldInputValue.Bytes
        assertTrue(byteArrayOf(0xAB.toByte(), 0xCD.toByte()).contentEquals(bytesValue.data))
    }
}
