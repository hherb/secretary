package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.VaultException

class VaultSyncErrorMappingTest {
    @Test
    fun `maps each sync-specific arm to its domain counterpart`() {
        assertEquals(VaultSyncError.InProgress, mapVaultSyncError(VaultException.SyncInProgress()))
        assertEquals(VaultSyncError.StateVaultMismatch, mapVaultSyncError(VaultException.SyncStateVaultMismatch()))
        assertEquals(VaultSyncError.EvidenceStale, mapVaultSyncError(VaultException.SyncEvidenceStale()))
        assertEquals(VaultSyncError.DecisionsIncomplete, mapVaultSyncError(VaultException.SyncDecisionsIncomplete()))
    }

    @Test
    fun `maps detail-carrying arms preserving the detail string`() {
        assertEquals(VaultSyncError.StateCorrupt("boom"), mapVaultSyncError(VaultException.SyncStateCorrupt("boom")))
        assertEquals(VaultSyncError.Failed("nope"), mapVaultSyncError(VaultException.SyncFailed("nope")))
        assertEquals(VaultSyncError.InvalidArgument("bad uuid"), mapVaultSyncError(VaultException.InvalidArgument("bad uuid")))
    }

    @Test
    fun `keeps wrong-password-or-corrupt conflated per threat model`() {
        assertEquals(VaultSyncError.WrongPasswordOrCorrupt, mapVaultSyncError(VaultException.WrongPasswordOrCorrupt()))
    }

    @Test
    fun `folds any non-sync arm into Failed with a descriptive detail`() {
        // RecordNotFound carries a `uuidHex` arg in the generated binding (not a no-field arm),
        // so it is constructed with a value; the fold still surfaces the variant name via toString().
        val mapped = mapVaultSyncError(VaultException.RecordNotFound("deadbeef"))
        assertTrue(mapped is VaultSyncError.Failed)
        mapped as VaultSyncError.Failed
        assertTrue(mapped.detail.contains("RecordNotFound"))

        // A structurally different non-sync arm (no-field) also folds — proving the fold is
        // general, not incidentally matching RecordNotFound's shape.
        val mappedNoField = mapVaultSyncError(VaultException.CannotRevokeOwner())
        assertTrue(mappedNoField is VaultSyncError.Failed)
        mappedNoField as VaultSyncError.Failed
        assertTrue(mappedNoField.detail.contains("CannotRevokeOwner"))
    }
}
