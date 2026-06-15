package org.secretary.sync

import uniffi.secretary.VaultException

/**
 * Pure `VaultException`->`VaultSyncError` mapper. Deliberately maps only the sync-relevant
 * `VaultException` arms; every other arm folds into [VaultSyncError.Failed] carrying the
 * variant name (matching iOS `mapVaultSyncError`'s `default` branch).
 *
 * [VaultException.WrongPasswordOrCorrupt] stays conflated (wrong password vs. corruption)
 * per the threat model's anti-oracle rule (§13) — do NOT split it. [VaultSyncError.NoPendingConflict]
 * has no FFI origin (it is a coordinator-only guard) and is intentionally absent here.
 *
 * MAINTAINER WARNING: the `else` fold will SILENTLY swallow any FUTURE *sync-relevant*
 * `VaultException` arm into [VaultSyncError.Failed] — the Kotlin compiler will NOT flag it
 * (the `when` is non-exhaustive by design over a ~30-arm sealed type). If the sync FFI surface
 * gains a new arm, add an explicit branch above `else` and a matching [VaultSyncError] case.
 * The Swift/Kotlin conformance harnesses (not the compiler) are the cross-language guard.
 */
internal fun mapVaultSyncError(e: VaultException): VaultSyncError = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> VaultSyncError.WrongPasswordOrCorrupt
    is VaultException.SyncInProgress -> VaultSyncError.InProgress
    is VaultException.SyncStateVaultMismatch -> VaultSyncError.StateVaultMismatch
    is VaultException.SyncStateCorrupt -> VaultSyncError.StateCorrupt(e.detail)
    is VaultException.SyncEvidenceStale -> VaultSyncError.EvidenceStale
    is VaultException.SyncDecisionsIncomplete -> VaultSyncError.DecisionsIncomplete
    is VaultException.InvalidArgument -> VaultSyncError.InvalidArgument(e.detail)
    is VaultException.SyncFailed -> VaultSyncError.Failed(e.detail)
    else -> VaultSyncError.Failed(e.toString())
}
