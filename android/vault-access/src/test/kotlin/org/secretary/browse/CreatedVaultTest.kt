package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CreatedVaultTest {
    @Test
    fun `CreatedVault exposes the phrase bytes verbatim`() {
        val phrase = "ripple ozone".toByteArray(Charsets.UTF_8)
        val uuid = ByteArray(16)
        val created = CreatedVault(phrase = phrase, vaultUuid = uuid)
        assertTrue(phrase.contentEquals(created.phrase))
        assertSame(phrase, created.phrase)
    }

    @Test
    fun `provisioning error arms are distinct and carry detail`() {
        val notEmpty: VaultProvisioningError = VaultProvisioningError.FolderNotEmpty
        val failed: VaultProvisioningError = VaultProvisioningError.CreateFailed("boom")
        assertEquals("boom", (failed as VaultProvisioningError.CreateFailed).detail)
        assertTrue(notEmpty is VaultProvisioningError.FolderNotEmpty)
        assertTrue(notEmpty !== failed)
    }
}
