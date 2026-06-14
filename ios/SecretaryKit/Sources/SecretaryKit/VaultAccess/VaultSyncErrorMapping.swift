import SecretaryVaultAccess

/// Map the uniffi `VaultError` onto the pure `VaultSyncError`. `internal`, and
/// deliberately SEPARATE from `mapVaultAccessError` — the sync surface returns a
/// different `VaultError` variant set (the `Sync*` cases), and routing it through
/// the vault-access mapping would misattribute errors (see that function's doc).
///
/// `WrongPasswordOrCorrupt` is the core's anti-oracle conflation and maps 1:1;
/// do NOT split it.
///
/// The `default` arm is deliberate, NOT exhaustive-match laziness: `VaultError`
/// is the union of the whole FFI surface (every vault-access + sync variant), so
/// an exhaustive `switch` here would force handling the vault-access cases that
/// the sync surface never returns. The cost is that the compiler will NOT flag a
/// newly-added *sync* `FfiVaultError` variant — it would silently fold into
/// `.failed(...)`. If you add a sync variant, add an explicit arm above this
/// comment and a matching `VaultSyncError` case; the Swift/Kotlin conformance
/// harnesses (not `cargo`/`clippy`) are the cross-language guard for that change.
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
    // Any non-sync VaultError variant (vault-access cases) — never expected off
    // the sync surface; carried as a string rather than misattributed. See the
    // doc comment: a new SYNC variant must get its own arm above, not land here.
    default:                                return .failed(String(describing: e))
    }
}
