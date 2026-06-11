import SecretaryVaultAccess

/// The single observable state of the unlock screen. Not `Equatable` — the
/// `.unlocked` case carries a live `VaultSession` (a reference). Tests pattern-
/// match the case.
public enum UnlockState {
    case idle
    case busy
    /// Opened — carries the live session handed to the browse screen.
    case unlocked(VaultSession)
    case failed(VaultAccessError)
}
