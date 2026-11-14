import Foundation

/// Typed failures from a sync pass. A dedicated enum (like `VaultSelectionError`),
/// NOT a reuse of `VaultAccessError`: the sync FFI surfaces a structurally
/// different `VaultError` variant set, and folding it through the vault-access
/// cases would misattribute errors.
///
/// `wrongPasswordOrCorrupt` is the core's deliberately-conflated anti-oracle
/// variant (wrong password is indistinguishable from a tampered vault). Do NOT
/// split it into a "wrong credential" case — that reintroduces the oracle.
public enum VaultSyncError: Error, Equatable {
    /// Identity re-open failed: wrong password OR corruption. Kept for the
    /// password sync calls the CLI still uses; the session path never needs it.
    case wrongPasswordOrCorrupt
    /// Another sync pass already holds the per-vault lock.
    case inProgress
    /// The persisted sync state belongs to a different vault.
    case stateVaultMismatch
    /// The persisted sync state could not be decoded.
    case stateCorrupt(String)
    /// The freshness token no longer matches on-disk state (TOCTOU gate tripped).
    case evidenceStale
    /// The supplied decisions did not exactly cover the recomputed veto set.
    case decisionsIncomplete
    /// FFI input-shape error (e.g. wrong-length vault UUID / manifest hash).
    case invalidArgument(String)
    /// Any other sync failure carried as a string (never a raw panic).
    case failed(String)
    /// `resolve` was called without a prior `conflictsPending` pass. Raised
    /// entirely Swift-side; no FFI call is made.
    case noPendingConflict
    /// "Sync now" / Apply was refused by the write re-auth gate (cancelled or
    /// failed biometric / password confirmation). No pass ran. Carries a
    /// diagnostic label only. Raised entirely Swift-side.
    case reauthFailed(String)
}
