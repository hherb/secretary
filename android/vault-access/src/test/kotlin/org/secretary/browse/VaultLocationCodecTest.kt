package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class VaultLocationCodecTest {
    private val tree = "content://com.android.externalstorage.documents/tree/primary%3AVault"

    @Test
    fun `round-trips a typical location`() {
        val loc = VaultLocation("My Vault", tree)
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test
    fun `round-trips a display name containing the colon delimiter`() {
        val loc = VaultLocation("a:b:c", tree)
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test
    fun `round-trips an empty display name`() {
        val loc = VaultLocation("", tree)
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test
    fun `decodes null for a wrong version tag`() {
        assertNull(decodeVaultLocation("v2:3:abc$tree"))
    }

    @Test
    fun `decodes null for a missing length delimiter`() {
        assertNull(decodeVaultLocation("v1:abc"))
    }

    @Test
    fun `decodes null for a non-numeric length`() {
        assertNull(decodeVaultLocation("v1:x:abc"))
    }

    @Test
    fun `decodes null when payload is shorter than the declared name length`() {
        assertNull(decodeVaultLocation("v1:99:short"))
    }

    @Test
    fun `decodes null for an empty string`() {
        assertNull(decodeVaultLocation(""))
    }

    @Test
    fun `decodes null when tree URI is empty (name exhausts payload)`() {
        assertNull(decodeVaultLocation("v1:3:abc"))
    }

    @Test
    fun `VaultLocation is value-equal (deliberate data class, unlike CreatedVault)`() {
        assertEquals(VaultLocation("n", "u"), VaultLocation("n", "u"))
        assertNotEquals(VaultLocation("n", "u"), VaultLocation("n", "v"))
    }

    @Test fun v2_roundtrips_vault_uuid_hex() {
        val loc = VaultLocation("My Vault", "content://tree/abc", "0102030405060708090a0b0c0d0e0f10")
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test fun v2_roundtrips_empty_uuid() {
        val loc = VaultLocation("My Vault", "content://tree/abc") // vaultUuidHex defaults ""
        assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
    }

    @Test fun v1_blob_decodes_with_empty_uuid() {
        // A pre-Slice-5 v1 blob has no uuid segment; it must decode (tolerant), not return null.
        val v1 = "v1:8:My Vaultcontent://tree/abc"
        assertEquals(VaultLocation("My Vault", "content://tree/abc", ""), decodeVaultLocation(v1))
    }
}
