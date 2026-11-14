package org.secretary.sync

/**
 * The seam over the FFI sync surface. `UniffiVaultSyncPort` (`:kit`) is the ONLY type that
 * imports the generated `uniffi.secretary` bindings; everything above this interface is pure and
 * host-tested with a fake.
 *
 * Every pass runs through the OPEN session (#733, as iOS since #101): no password and no folder
 * cross this boundary, so a biometric or recovery session syncs exactly like a password one. After
 * a pass the real adapter has already refreshed the session's manifest handle from disk (never on
 * [SyncOutcome.RollbackRejected] or [SyncOutcome.ConflictsPending]), so the next write sees the
 * merged state. If the pass succeeded but the refresh failed (typically a cloud drive still
 * delivering block files) the call throws and the handle is unchanged; retrying is safe.
 *
 * All methods are `suspend` for uniformity; the real adapter runs [sync] / [commitDecisions] on a
 * background dispatcher (disk I/O and crypto). Implementations signal failure by throwing
 * [VaultSyncError].
 */
interface VaultSyncPort {
    suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus

    suspend fun sync(stateDir: String, nowMs: ULong): SyncOutcome

    suspend fun commitDecisions(
        stateDir: String,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome
}
