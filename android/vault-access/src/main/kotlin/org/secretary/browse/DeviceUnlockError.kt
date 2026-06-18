package org.secretary.browse

/**
 * Errors from the device-unlock coordinator + enclave. Throwable so callers can `catch`. The
 * coordinator itself raises [NotEnrolled] / [VaultSlotMismatch]; the remaining arms are raised by a
 * real [DeviceSecretEnclave] (slice 2) and propagated unchanged. Mirror of iOS `DeviceUnlockError`.
 *
 * (Open-time failures — wrong secret / corrupt / slot-gone — surface as [VaultBrowseError] from the
 * shared `openWithCredential` pipeline, NOT here, because the coordinator returns a credential
 * instead of opening.)
 */
sealed class DeviceUnlockError(message: String? = null) : Exception(message) {
    /** No enrollment metadata — the device was never enrolled (or was disenrolled). */
    data object NotEnrolled : DeviceUnlockError()

    /** The stored enrollment is for a different vault than the one requested. */
    data object VaultSlotMismatch : DeviceUnlockError()

    /** Biometry hardware/feature unavailable on this device. */
    data object BiometryUnavailable : DeviceUnlockError()

    /** No biometric is enrolled on the device. */
    data object BiometryNotEnrolled : DeviceUnlockError()

    /** Too many failed attempts — biometry is temporarily locked out. */
    data object BiometryLockout : DeviceUnlockError()

    /** The user cancelled the biometric prompt. */
    data object UserCancelled : DeviceUnlockError()

    /** The biometric attempt failed (not a match). */
    data object AuthenticationFailed : DeviceUnlockError()

    /** The wrapped secret could not be decrypted — actual ciphertext corruption (never an auth failure). */
    data object WrappedSecretCorrupt : DeviceUnlockError()

    /** Any other Keystore/enclave error. */
    data class Enclave(val detail: String) : DeviceUnlockError(detail)
}
