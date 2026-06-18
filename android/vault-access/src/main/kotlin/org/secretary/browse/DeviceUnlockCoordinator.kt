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
                runCatching { slotPort.removeDeviceSlot(folder, slot.deviceUuid) }
                throw e
            }
        } finally {
            slot.secret.fill(0)
        }
    }
}
