import SecretaryVaultAccess

/// Map the uniffi `VaultError` onto the pure `VaultSyncError`. `internal`, and
/// deliberately SEPARATE from `mapVaultAccessError` — the sync surface returns a
/// different `VaultError` variant set (the `Sync*` cases), and routing it through
/// the vault-access mapping would misattribute errors (see that function's doc).
///
/// `WrongPasswordOrCorrupt` is the core's anti-oracle conflation and maps 1:1;
/// do NOT split it.
internal func mapVaultSyncError(_ e: VaultError) -> VaultSyncError {
    switch e {
    case .WrongPasswordOrCorrupt:           return .wrongPasswordOrCorrupt
    case .SyncInProgress:                   return .inProgress
    case .SyncStateVaultMismatch:           return .stateVaultMismatch
    case .SyncStateCorrupt(let detail):     return .stateCorrupt(detail)
    case .SyncEvidenceStale:                return .evidenceStale
    case .SyncDecisionsIncomplete:          return .decisionsIncomplete
    case .InvalidArgument(let detail):      return .invalidArgument(detail)
    case .SyncFailed(let detail):           return .failed(detail)
    default:                                return .failed(String(describing: e))
    }
}
