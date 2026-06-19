package org.secretary.browse

/**
 * Stores the raw 32-byte device secret and releases it on demand. In slice 1 this is faked
 * in-memory; in slice 2 the real impl is an Android Keystore/StrongBox key whose [release] is gated
 * by `BiometricPrompt` (hence [release] is `suspend`). Mirror of iOS `DeviceSecretEnclave`.
 *
 * Implementations throw [DeviceUnlockError] (e.g. [DeviceUnlockError.UserCancelled] from a cancelled
 * biometric prompt, [DeviceUnlockError.WrappedSecretCorrupt] from real ciphertext corruption).
 */
interface DeviceSecretEnclave {
    /** True iff a secret is stored. A cheap, non-prompting check (no biometric). */
    val isEnrolled: Boolean

    /** Store [secret], consuming it synchronously (encrypts, persists only ciphertext); the caller
     *  may zeroize its array after this returns. */
    suspend fun store(secret: ByteArray)

    /** Release the stored secret (slice 2: behind a biometric prompt explained by [reason]). The
     *  returned array is caller-owned; the caller zeroizes it after use. */
    suspend fun release(reason: String): ByteArray

    /** Drop the stored secret. Idempotent. */
    suspend fun clear()
}
