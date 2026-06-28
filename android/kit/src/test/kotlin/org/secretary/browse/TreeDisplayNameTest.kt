package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class TreeDisplayNameTest {
    @Test
    fun `uses the provider name when present`() {
        assertEquals("Vaults", treeDisplayNameOrFallback("Vaults"))
    }

    @Test
    fun `falls back when the name is null`() {
        assertEquals("Cloud folder", treeDisplayNameOrFallback(null))
    }

    @Test
    fun `falls back when the name is blank`() {
        assertEquals("Cloud folder", treeDisplayNameOrFallback("   "))
    }
}
