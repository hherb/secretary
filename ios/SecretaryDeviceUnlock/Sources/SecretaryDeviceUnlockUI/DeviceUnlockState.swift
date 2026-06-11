import SecretaryDeviceUnlock

/// What the ViewModel is currently doing — drives the spinner + disables buttons.
public enum Activity: Equatable {
    case enrolling, unlocking, disenrolling
}

/// The single observable state of the device-unlock screen. Pure value type so
/// the ViewModel is fully host-testable.
public enum DeviceUnlockState: Equatable {
    /// Before the first status refresh.
    case idle
    case notEnrolled
    /// Enrolled, not yet unlocked this session.
    case enrolled
    case busy(Activity)
    /// Happy path — the opened vault's uuid as lowercase hex.
    case unlocked(vaultUuidHex: String)
    /// Typed failure + the raw domain+code detail (nil when not applicable).
    case failed(DeviceUnlockError, detail: String?)
}
