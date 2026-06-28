package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultNameTest {
    private fun invalidArm(raw: String): VaultNameError {
        val v = validateVaultName(raw)
        assertTrue(v is VaultNameValidation.Invalid, "expected invalid for <$raw>")
        return (v as VaultNameValidation.Invalid).error
    }

    @Test
    fun `trims and accepts a normal name`() {
        assertEquals(VaultNameValidation.Valid("My Vault"), validateVaultName("  My Vault  "))
    }

    @Test
    fun `blank rejected`() {
        assertTrue(invalidArm("   ") is VaultNameError.Blank)
    }

    @Test
    fun `over-length rejected`() {
        assertTrue(invalidArm("x".repeat(MAX_VAULT_NAME_LENGTH + 1)) is VaultNameError.TooLong)
    }

    @Test
    fun `path separators rejected`() {
        assertTrue(invalidArm("a/b") is VaultNameError.IllegalCharacters)
        assertTrue(invalidArm("a\\b") is VaultNameError.IllegalCharacters)
    }

    @Test
    fun `dot names rejected`() {
        assertTrue(invalidArm(".") is VaultNameError.IllegalCharacters)
        assertTrue(invalidArm("..") is VaultNameError.IllegalCharacters)
    }

    @Test
    fun `control and nul chars rejected`() {
        assertTrue(invalidArm("a\u0000b") is VaultNameError.IllegalCharacters)
        assertTrue(invalidArm("a\nb") is VaultNameError.IllegalCharacters)
        assertTrue(invalidArm("a\u007Fb") is VaultNameError.IllegalCharacters)
    }
}
