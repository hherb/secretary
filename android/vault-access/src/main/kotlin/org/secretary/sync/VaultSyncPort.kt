package org.secretary.sync

/**
 * The seam over the FFI sync surface. The future `UniffiVaultSyncPort` is the ONLY type
 * that imports the generated `uniffi.secretary` bindings; everything above this interface
 * is pure and host-tested with a fake.
 *
 * All methods are `suspend` for uniformity. The real adapter runs [sync] / [commitDecisions]
 * on a background dispatcher (they re-open the vault and run Argon2id); [status] is a cheap
 * disk read. [password] is passed per call and MUST NOT be retained by any implementation.
 *
 * Implementations signal failure by throwing [VaultSyncError].
 */
interface VaultSyncPort {
    suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus

    suspend fun sync(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome

    suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome
}
