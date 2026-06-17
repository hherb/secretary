package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.BlockSummary
import uniffi.secretary.VaultException

class BrowseMappingTest {
    @Test
    fun `maps open-relevant arms to their domain counterparts`() {
        assertEquals(VaultBrowseError.WrongPasswordOrCorrupt, mapVaultBrowseError(VaultException.WrongPasswordOrCorrupt()))
        assertEquals(VaultBrowseError.VaultMismatch, mapVaultBrowseError(VaultException.VaultMismatch()))
        assertEquals(VaultBrowseError.CorruptVault("c"), mapVaultBrowseError(VaultException.CorruptVault("c")))
        assertEquals(VaultBrowseError.FolderInvalid("f"), mapVaultBrowseError(VaultException.FolderInvalid("f")))
        assertEquals(VaultBrowseError.BlockNotFound("ab"), mapVaultBrowseError(VaultException.BlockNotFound("ab")))
        assertEquals(VaultBrowseError.InvalidArgument("a"), mapVaultBrowseError(VaultException.InvalidArgument("a")))
    }

    @Test
    fun `folds any other arm into Failed carrying the variant name`() {
        val mapped = mapVaultBrowseError(VaultException.RecordNotFound("deadbeef"))
        assertTrue(mapped is VaultBrowseError.Failed)
        assertTrue((mapped as VaultBrowseError.Failed).detail.contains("RecordNotFound"))
    }

    @Test
    fun `block summary maps every metadata field`() {
        val uuid = ByteArray(16) { it.toByte() }
        val view = mapBlockSummary(
            BlockSummary(blockUuid = uuid, blockName = "Logins", createdAtMs = 5u, lastModifiedMs = 6u, recipientUuids = emptyList()),
        )
        assertEquals("000102030405060708090a0b0c0d0e0f", view.uuidHex)
        assertEquals("Logins", view.name)
        assertEquals(5uL, view.createdAtMs)
        assertEquals(6uL, view.lastModifiedMs)
    }
}
