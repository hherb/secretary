import SecretaryVaultAccess

/// The single observable state of the unlock screen. Deliberately NOT
/// `Equatable`: the `.unlocked` case carries a live `VaultSession` (a reference)
/// that is passed out of band to the browse screen, not compared for equality
/// in production code — so we keep the live handle here rather than reducing it
/// to a comparable token the way `DeviceUnlockState` does. Tests pattern-match
/// the case.
public enum UnlockState {
    case idle
    /// One async operation only (the open) — no Activity payload needed, unlike
    /// `DeviceUnlockState.busy(Activity)` which multiplexes enroll/unlock/disenroll.
    case busy
    /// Opened — carries the live session handed to the browse screen.
    case unlocked(VaultSession)
    case failed(VaultAccessError)
}
