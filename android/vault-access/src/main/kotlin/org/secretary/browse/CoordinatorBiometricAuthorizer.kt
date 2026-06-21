package org.secretary.browse

/**
 * Real [BiometricAuthorizer] for write re-auth: proves presence by releasing the enrolled device
 * secret through the shipped [DeviceUnlockCoordinator] (which runs its NotEnrolled / VaultSlotMismatch
 * guards BEFORE the biometric prompt), then immediately zeroizes and discards the released bytes — we
 * need the *act* of releasing (proves biometry + Keystore-key integrity), not the secret itself.
 *
 * No new crypto: this is the exact path used to unlock the vault, reused as a presence proof.
 */
class CoordinatorBiometricAuthorizer(
    private val coordinator: DeviceUnlockCoordinator,
    private val vaultId: String,
) : BiometricAuthorizer {
    override val isEnrolled: Boolean get() = coordinator.isEnrolled

    override suspend fun authorize(reason: String) {
        val credential = coordinator.unlock(vaultId, reason) // throws DeviceUnlockError on cancel/fail
        credential.secret.fill(0)                            // zeroize + discard — proof was the release
    }
}
