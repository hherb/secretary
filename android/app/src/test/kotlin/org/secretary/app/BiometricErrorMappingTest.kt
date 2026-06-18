package org.secretary.app

import androidx.biometric.BiometricPrompt
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.browse.DeviceUnlockError

class BiometricErrorMappingTest {
    @Test fun userCanceled_mapsToUserCancelled() {
        assertEquals(DeviceUnlockError.UserCancelled, mapBiometricError(BiometricPrompt.ERROR_USER_CANCELED))
    }
    @Test fun negativeButton_mapsToUserCancelled() {
        assertEquals(DeviceUnlockError.UserCancelled, mapBiometricError(BiometricPrompt.ERROR_NEGATIVE_BUTTON))
    }
    @Test fun lockout_mapsToBiometryLockout() {
        assertEquals(DeviceUnlockError.BiometryLockout, mapBiometricError(BiometricPrompt.ERROR_LOCKOUT))
        assertEquals(DeviceUnlockError.BiometryLockout, mapBiometricError(BiometricPrompt.ERROR_LOCKOUT_PERMANENT))
    }
    @Test fun noBiometricEnrolled_mapsToBiometryNotEnrolled() {
        assertEquals(DeviceUnlockError.BiometryNotEnrolled, mapBiometricError(BiometricPrompt.ERROR_NO_BIOMETRICS))
    }
    @Test fun hardwareUnavailable_mapsToBiometryUnavailable() {
        assertEquals(DeviceUnlockError.BiometryUnavailable, mapBiometricError(BiometricPrompt.ERROR_HW_UNAVAILABLE))
        assertEquals(DeviceUnlockError.BiometryUnavailable, mapBiometricError(BiometricPrompt.ERROR_HW_NOT_PRESENT))
    }
    @Test fun unknownCode_mapsToAuthenticationFailed() {
        assertEquals(DeviceUnlockError.AuthenticationFailed, mapBiometricError(Int.MAX_VALUE))
    }
}
