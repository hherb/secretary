package org.secretary.sync

/**
 * Errors raised by the sync surface. Deliberately SEPARATE from any future
 * `VaultAccessError`: the sync FFI returns a different `FfiVaultError`/`VaultException`
 * variant set, and folding the two would misattribute errors.
 *
 * [WrongPasswordOrCorrupt] is intentionally conflated (wrong password vs. vault corruption)
 * per the threat model's anti-oracle rule (§13). Do NOT split it.
 */
sealed class VaultSyncError(message: String? = null) : Exception(message) {
    /** Re-open failed: wrong password OR corrupt vault. Conflated on purpose (§13). */
    data object WrongPasswordOrCorrupt : VaultSyncError()

    /** Another sync is already running for this vault (per-vault FFI lockfile held). */
    data object InProgress : VaultSyncError()

    /** The sync-state cache belongs to a different vault. */
    data object StateVaultMismatch : VaultSyncError()

    /** The sync-state cache is corrupt. */
    data class StateCorrupt(val detail: String) : VaultSyncError(detail)

    /** The vault changed on disk mid-pass; the TOCTOU freshness gate tripped. Retry. */
    data object EvidenceStale : VaultSyncError()

    /** The supplied decisions did not cover the pending conflicts. */
    data object DecisionsIncomplete : VaultSyncError()

    /** A caller argument was malformed (e.g. wrong-length UUID/hash). */
    data class InvalidArgument(val detail: String) : VaultSyncError(detail)

    /** Any other sync failure. */
    data class Failed(val detail: String) : VaultSyncError(detail)

    /** Coordinator guard: `resolve` was called with no paused conflict stashed. */
    data object NoPendingConflict : VaultSyncError()
}
