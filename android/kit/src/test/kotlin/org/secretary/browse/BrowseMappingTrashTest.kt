package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.VaultException

class BrowseMappingTrashTest {
    @Test
    fun `BlockNotInTrash maps to BlockNotFound`() {
        val mapped = mapVaultBrowseError(VaultException.BlockNotInTrash("no entry"))
        assertTrue(mapped is VaultBrowseError.BlockNotFound)
    }

    @Test
    fun `BlockPurged maps to BlockNotFound`() {
        val mapped = mapVaultBrowseError(VaultException.BlockPurged("already purged"))
        assertTrue(mapped is VaultBrowseError.BlockNotFound)
    }
}
