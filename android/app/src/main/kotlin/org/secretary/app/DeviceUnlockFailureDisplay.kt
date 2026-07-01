package org.secretary.app

import org.secretary.browse.DeviceUnlockError

/**
 * How a failed biometric unlock should be presented on the Unlock screen. Mirror of the iOS
 * `DeviceUnlockFailureDisplay`.
 */
sealed interface DeviceUnlockFailureDisplay {
    /** User cancelled / dismissed the biometric prompt — return to Unlock quietly. */
    data object Silent : DeviceUnlockFailureDisplay

    /** A real failure — surface this short, user-facing message. */
    data class Message(val text: String) : DeviceUnlockFailureDisplay
}

/**
 * Classify a [DeviceUnlockError] for the Unlock screen (#341). ONLY [DeviceUnlockError.UserCancelled]
 * is silent (a deliberate cancel must not nag); every other arm surfaces a typed message so a
 * non-cancel failure never silently returns to Unlock. Pure and exhaustive — host-tested over the
 * full taxonomy. Sibling of [mapBiometricError]. Mirror of the iOS `deviceUnlockFailureDisplay`.
 *
 * (Open-time failures — wrong secret / corrupt / slot-gone — surface as `VaultBrowseError` from the
 * shared open pipeline, not here; see [DeviceUnlockError].)
 */
fun deviceUnlockFailureDisplay(error: DeviceUnlockError): DeviceUnlockFailureDisplay = when (error) {
    DeviceUnlockError.UserCancelled ->
        DeviceUnlockFailureDisplay.Silent
    DeviceUnlockError.BiometryUnavailable ->
        DeviceUnlockFailureDisplay.Message("Biometric unlock is unavailable on this device.")
    DeviceUnlockError.BiometryNotEnrolled ->
        DeviceUnlockFailureDisplay.Message("No biometrics are enrolled on this device.")
    DeviceUnlockError.BiometryLockout ->
        DeviceUnlockFailureDisplay.Message("Biometrics are locked out. Use your PIN/password, then try again.")
    DeviceUnlockError.AuthenticationFailed ->
        DeviceUnlockFailureDisplay.Message("Biometric authentication failed. Try again or use your password.")
    DeviceUnlockError.NotEnrolled ->
        DeviceUnlockFailureDisplay.Message("This device isn't set up for biometric unlock of this vault.")
    DeviceUnlockError.VaultSlotMismatch ->
        DeviceUnlockFailureDisplay.Message("This device's biometric enrollment is for a different vault.")
    DeviceUnlockError.WrappedSecretCorrupt ->
        DeviceUnlockFailureDisplay.Message("The device key couldn't be used. Unlock with your password.")
    is DeviceUnlockError.Enclave ->
        DeviceUnlockFailureDisplay.Message("Secure hardware error. Unlock with your password. (${error.detail})")
}
