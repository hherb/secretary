package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
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
        // The `SyncFailed` line below pins a RAW, UNGATED pass-through of Rust-authored text, and
        // that is deliberate — see VaultSyncError's payload-origin audit, which traces every Rust
        // construction site to a fixed literal, an io::Error, or an argument-shape description,
        // never a fold of an arbitrary VaultError. It is the one arm in either sealed type whose
        // safety rests on traced CONTENT rather than on construction, so it is the one that a Rust
        // edit could invalidate with no Kotlin diff (tracked as the #475 follow-up). Do NOT "fix"
        // it by routing through diagnosticDetail: VaultException is unconformed, so that renders
        // `<undisclosed …>` and destroys sync diagnostics without closing the drift class — the
        // same trade #475 had to undo for CloudFolderException.
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

    @Test
    fun `#472 regression - the else-fold never launders an unmapped arm's raw content`() {
        // CorruptVault is a real VaultException arm this mapper never names (it is browse-
        // relevant, not sync-relevant) and is exactly the arm whose Rust-side Display can carry a
        // decrypted CBOR field name (see BrowseMapping's own audit). Proof the sync else-fold is
        // gated regardless of which unmapped arm reaches it. Mutation-proved: reverting
        // VaultSyncErrorMapping.kt's else-fold to `e.toString()` makes this fail because
        // `VaultException.CorruptVault.toString()` embeds the raw detail via its generated
        // `message` override, while `diagnosticDetail` default-denies the unconformed uniffi type.
        val sentinel = "s3cr3t-sentinel-472"
        val mapped = mapVaultSyncError(VaultException.CorruptVault(sentinel))
        assertTrue(mapped is VaultSyncError.Failed)
        val detail = (mapped as VaultSyncError.Failed).detail
        assertFalse(detail.contains(sentinel), detail)
        assertTrue(detail.contains("<undisclosed "), detail)
    }
}
