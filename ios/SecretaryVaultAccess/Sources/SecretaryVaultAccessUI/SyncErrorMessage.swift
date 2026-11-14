import SecretaryVaultAccess

/// Short user-facing message for a sync error. Pure + host-tested, like
/// `settingsErrorMessage`. Exhaustive on purpose: a new `VaultSyncError` case must
/// choose its copy rather than fall back to a debug description of the enum.
///
/// Same anti-oracle discipline as `settingsErrorMessage`: a carried diagnostic
/// string is never interpolated, and `wrongPasswordOrCorrupt` keeps the damage
/// possibility visible.
public func syncErrorMessage(_ e: VaultSyncError) -> String {
    switch e {
    case .wrongPasswordOrCorrupt:
        return "Couldn’t sync: the password was wrong, or the vault may be damaged."
    case .inProgress:
        return "Another sync is already running. Try again in a moment."
    case .stateVaultMismatch:
        return "This device’s sync record belongs to a different vault."
    case .stateCorrupt:
        return "This device’s sync record couldn’t be read."
    case .evidenceStale:
        return "The vault changed while you were resolving conflicts. Sync again."
    case .decisionsIncomplete:
        return "Every conflict needs a decision before you apply."
    case .invalidArgument:
        return "Sync couldn’t start because of an invalid request."
    case .failed:
        return "Sync failed. Please try again."
    case .noPendingConflict:
        return "There are no conflicts to apply."
    case .reauthFailed:
        return "Sync wasn’t authorized."
    }
}
