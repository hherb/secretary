package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.secretary.browse.DeviceUnlockError

/**
 * Matrix over the full [DeviceUnlockError] taxonomy: ONLY [DeviceUnlockError.UserCancelled] is
 * silent; every other arm surfaces a non-blank [DeviceUnlockFailureDisplay.Message] (#341). Mirror
 * of the iOS `DeviceUnlockFailureDisplayTests`.
 */
class DeviceUnlockFailureDisplayTest {
    @Test fun userCancelled_isSilent() {
        assertEquals(
            DeviceUnlockFailureDisplay.Silent,
            deviceUnlockFailureDisplay(DeviceUnlockError.UserCancelled),
        )
    }

    @Test fun everyNonCancelError_surfacesANonBlankMessage() {
        val nonCancel = listOf(
            DeviceUnlockError.NotEnrolled,
            DeviceUnlockError.VaultSlotMismatch,
            DeviceUnlockError.BiometryUnavailable,
            DeviceUnlockError.BiometryNotEnrolled,
            DeviceUnlockError.BiometryLockout,
            DeviceUnlockError.AuthenticationFailed,
            DeviceUnlockError.WrappedSecretCorrupt,
            DeviceUnlockError.Enclave("keystore blew up"),
        )
        for (error in nonCancel) {
            val display = deviceUnlockFailureDisplay(error)
            assertTrue(
                display is DeviceUnlockFailureDisplay.Message && display.text.isNotBlank(),
                "expected a non-blank Message for $error, got $display",
            )
        }
    }

    @Test fun enclaveDetail_isIncludedInTheMessage() {
        val display = deviceUnlockFailureDisplay(DeviceUnlockError.Enclave("KEY_PERMANENTLY_INVALIDATED"))
        assertTrue(
            display is DeviceUnlockFailureDisplay.Message &&
                display.text.contains("KEY_PERMANENTLY_INVALIDATED"),
            "enclave detail should be surfaced for diagnosis, got $display",
        )
    }
}
