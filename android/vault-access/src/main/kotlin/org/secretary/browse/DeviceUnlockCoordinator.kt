package org.secretary.browse

/**
 * Pure orchestration of device enrollment / unlock / disenroll over three injected ports. No I/O of
 * its own. Mirror of iOS `DeviceUnlockCoordinator`, with ONE deliberate divergence: [unlock] returns
 * an [UnlockCredential.DeviceSecret] (the caller opens via `openWithCredential`) rather than opening
 * directly — so open-time errors surface as [VaultBrowseError] from the shared pipeline, consistent
 * with the password/recovery paths.
 */
class DeviceUnlockCoordinator(
    private val slotPort: VaultDeviceSlotPort,
    private val enclave: DeviceSecretEnclave,
    private val metadata: DeviceEnrollmentMetadataStore,
) {
    /** True iff BOTH the enclave holds a secret AND enrollment metadata is present. */
    val isEnrolled: Boolean
        get() = enclave.isEnrolled && runCatching { metadata.load() }.getOrNull() != null

    /**
     * Mint a device slot, store its secret in the enclave, and record the enrollment — transactionally.
     * On enclave-store failure the slot is removed; on metadata-save failure both the enclave and the
     * slot are rolled back and the ORIGINAL save error is rethrown. The slot's secret copy is zeroized
     * on every exit. [password] is owned by the caller (forwarded to `addDeviceSlot`, not zeroized here).
     */
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray) {
        val slot = slotPort.addDeviceSlot(folder, password)
        try {
            try {
                enclave.store(slot.secret)
            } catch (e: Throwable) {
                runCatching { slotPort.removeDeviceSlot(folder, slot.deviceUuid) }
                throw e
            }
            try {
                metadata.save(DeviceEnrollment(vaultId, slot.deviceUuid))
            } catch (e: Throwable) {
                runCatching { enclave.clear() }
                // A process crash between enclave.clear() and removeDeviceSlot() below can leave an
                // orphan devices/<uuid>.wrap with no enclave secret and no metadata — benign (effectively
                // dead; idempotent disenroll cleans it).
                runCatching { slotPort.removeDeviceSlot(folder, slot.deviceUuid) }
                throw e
            }
        } finally {
            slot.secret.fill(0)
        }
    }

    /**
     * Release the device secret (slice 2: behind a biometric prompt) and wrap it into an
     * [UnlockCredential.DeviceSecret]. Guards run BEFORE [DeviceSecretEnclave.release] so a stale /
     * wrong-vault enrollment never triggers a biometric prompt: [DeviceUnlockError.NotEnrolled] if no
     * metadata, [DeviceUnlockError.VaultSlotMismatch] if the enrolled vaultId differs. The returned
     * credential owns the secret; the CALLER opens via `openWithCredential` and zeroizes it.
     */
    suspend fun unlock(vaultId: String, reason: String): UnlockCredential.DeviceSecret {
        val enrollment = metadata.load() ?: throw DeviceUnlockError.NotEnrolled
        if (enrollment.vaultId != vaultId) throw DeviceUnlockError.VaultSlotMismatch
        val secret = enclave.release(reason)
        return UnlockCredential.DeviceSecret(enrollment.deviceUuid, secret)
    }

    /**
     * Revoke this device's enrollment, idempotently. Removes the slot (a
     * [VaultBrowseError.DeviceSlotNotFound] is swallowed — already-gone is success; any other
     * [VaultBrowseError] propagates), then best-effort clears the enclave + metadata. Safe when not
     * enrolled (nothing to remove). No orphan survives.
     */
    suspend fun disenroll(folder: String) {
        val enrollment = metadata.load()
        if (enrollment != null) {
            try {
                slotPort.removeDeviceSlot(folder, enrollment.deviceUuid)
            } catch (e: VaultBrowseError.DeviceSlotNotFound) {
                // already gone — fine
            }
        }
        runCatching { enclave.clear() }
        runCatching { metadata.clear() }
    }
}
