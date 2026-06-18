package org.secretary.browse

/**
 * The FFI seam for device-slot management (mint / revoke). Separate from [VaultOpenPort] because the
 * device *open* is a credential open (it lives on [VaultOpenPort.openWithDeviceSecret]); this port is
 * slot lifecycle only. The real impl (`:kit` `UniffiVaultDeviceSlotPort`) wraps `add_device_slot` /
 * `remove_device_slot`. Mirror of the mint/remove half of iOS `VaultDeviceSlotPort`.
 *
 * Implementations throw [VaultBrowseError] (e.g. [VaultBrowseError.DeviceSlotNotFound] from
 * [removeDeviceSlot] when the slot is already gone).
 */
interface VaultDeviceSlotPort {
    /** Password-open the vault and mint a fresh device slot, writing `devices/<uuid>.wrap`. Returns
     *  the new 16-byte UUID + the raw 32-byte secret. The caller owns zeroizing [EnrolledSlot.secret]. */
    suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot

    /** Revoke a device slot (delete `devices/<uuid>.wrap`). Throws [VaultBrowseError.DeviceSlotNotFound]
     *  if the slot does not exist. */
    suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray)
}

/** A freshly-minted device slot: its 16-byte [deviceUuid] (non-secret) and raw 32-byte [secret]. */
class EnrolledSlot(val deviceUuid: ByteArray, val secret: ByteArray)
