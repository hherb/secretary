package org.secretary.app

import androidx.biometric.BiometricPrompt
import org.secretary.browse.DeviceUnlockError

/**
 * Pure mapping from an [androidx.biometric.BiometricPrompt] error code to the slice-1
 * [DeviceUnlockError] taxonomy. Host-tested. Cancel/negative → [DeviceUnlockError.UserCancelled];
 * lockout → [DeviceUnlockError.BiometryLockout]; no-biometric → [DeviceUnlockError.BiometryNotEnrolled];
 * hardware → [DeviceUnlockError.BiometryUnavailable]; anything else → [DeviceUnlockError.AuthenticationFailed].
 */
fun mapBiometricError(errorCode: Int): DeviceUnlockError = when (errorCode) {
    BiometricPrompt.ERROR_USER_CANCELED,
    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
    BiometricPrompt.ERROR_CANCELED -> DeviceUnlockError.UserCancelled
    BiometricPrompt.ERROR_LOCKOUT,
    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> DeviceUnlockError.BiometryLockout
    BiometricPrompt.ERROR_NO_BIOMETRICS -> DeviceUnlockError.BiometryNotEnrolled
    BiometricPrompt.ERROR_HW_UNAVAILABLE,
    BiometricPrompt.ERROR_HW_NOT_PRESENT -> DeviceUnlockError.BiometryUnavailable
    else -> DeviceUnlockError.AuthenticationFailed
}
