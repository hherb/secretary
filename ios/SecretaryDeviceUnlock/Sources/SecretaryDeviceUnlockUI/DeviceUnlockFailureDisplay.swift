import SecretaryDeviceUnlock

/// How a failed biometric unlock should be presented on the Unlock screen.
public enum DeviceUnlockFailureDisplay: Equatable {
    /// User cancelled / dismissed the biometric prompt — return to Unlock quietly.
    case silent
    /// A real failure — surface this short, user-facing message (#341: a
    /// non-cancel failure must never silently return to Unlock).
    case message(String)
}

/// Classify a `DeviceUnlockError` for the Unlock screen. ONLY `.userCancelled`
/// is silent; every other case surfaces a typed message. (#341)
public func deviceUnlockFailureDisplay(_ error: DeviceUnlockError) -> DeviceUnlockFailureDisplay {
    switch error {
    case .userCancelled:
        return .silent
    case .biometryUnavailable:
        return .message("Biometric unlock is unavailable on this device.")
    case .biometryNotEnrolled:
        return .message("No biometrics are enrolled on this device.")
    case .biometryLockout:
        return .message("Biometrics are locked out. Use your passcode, then try again.")
    case .authenticationFailed:
        return .message("Biometric authentication failed. Try again or use your password.")
    case .notEnrolled:
        return .message("This device isn't set up for biometric unlock of this vault.")
    case .vaultSlotMismatch:
        return .message("This device's biometric enrollment is for a different vault.")
    case .wrappedSecretCorrupt, .wrongDeviceSecretOrCorrupt:
        return .message("The device key couldn't be used. Unlock with your password.")
    case .vault(let e):
        return .message("Couldn't open the vault (\(e)). Unlock with your password.")
    case .enclave(let detail):
        return .message("Secure Enclave error. Unlock with your password. (\(detail))")
    }
}
