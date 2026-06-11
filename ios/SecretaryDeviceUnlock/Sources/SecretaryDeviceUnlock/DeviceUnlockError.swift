/// Typed failures surfaced by `DeviceUnlockCoordinator`. The enclave conformer
/// produces the biometric/enclave cases; the coordinator produces the
/// orchestration cases from `VaultSlotError` and metadata state.
public enum DeviceUnlockError: Error, Equatable {
    case biometryUnavailable
    case biometryNotEnrolled
    case biometryLockout
    case userCancelled
    case authenticationFailed
    case notEnrolled
    case vaultSlotMismatch
    case wrappedSecretCorrupt
    case wrongDeviceSecretOrCorrupt
    case vault(VaultSlotError)
    /// Unexpected Security.framework / OSStatus error, carried as its string.
    case enclave(String)
}
