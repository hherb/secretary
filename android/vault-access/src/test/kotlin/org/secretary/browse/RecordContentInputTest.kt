package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class RecordContentInputTest {
    private fun text(name: String) = FieldContentInput(name, FieldContentValue.Text("v"))

    @Test
    fun `valid content returns null`() {
        val c = RecordContentInput("login", listOf("personal"), listOf(text("user"), text("pass")))
        assertNull(c.validate())
    }

    @Test
    fun `empty fields is allowed`() {
        assertNull(RecordContentInput("note", emptyList(), emptyList()).validate())
    }

    @Test
    fun `blank field name is rejected`() {
        val c = RecordContentInput("login", emptyList(), listOf(text("   ")))
        assertEquals(RecordContentInputError.EmptyFieldName, c.validate())
    }

    @Test
    fun `duplicate field name is rejected`() {
        val c = RecordContentInput("login", emptyList(), listOf(text("user"), text("user")))
        assertEquals(RecordContentInputError.DuplicateFieldName("user"), c.validate())
    }
}
