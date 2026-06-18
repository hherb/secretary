package org.secretary.browse

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.DeviceEnrollOutput
import uniffi.secretary.addDeviceSlot as ffiAddDeviceSlot
import uniffi.secretary.removeDeviceSlot as ffiRemoveDeviceSlot

/**
 * The real [VaultDeviceSlotPort] over the generated `add_device_slot` / `remove_device_slot`. Runs on
 * [ioDispatcher] (add_device_slot password-opens the vault → Argon2id). The one-shot
 * `DeviceSecretOutput` is `takeSecret()`-ed once then `wipe()`-d in a `finally` so the bridge retains
 * nothing (mirror of iOS's `defer { out.deviceSecret.wipe() }`). The FFI fns are injectable seams
 * defaulting to the real bindings.
 */
class UniffiVaultDeviceSlotPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val addFn: (ByteArray, ByteArray) -> DeviceEnrollOutput = ::ffiAddDeviceSlot,
    private val removeFn: (ByteArray, ByteArray) -> Unit = ::ffiRemoveDeviceSlot,
) : VaultDeviceSlotPort {
    override suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot =
        withContext(ioDispatcher) {
            mapErrors {
                val out = addFn(vaultFolder.toByteArray(Charsets.UTF_8), password)
                try {
                    val taken = out.deviceSecret.takeSecret()
                        ?: throw VaultBrowseError.Failed("device secret handle was empty (already taken?)")
                    // take_secret() is declared `sequence<u8>?` → a boxed list; convert to ByteArray.
                    // (`it.toByte()` is valid whether the element type is UByte or Byte.)
                    val secret = taken.map { it.toByte() }.toByteArray()
                    EnrolledSlot(out.deviceUuid, secret)
                } finally {
                    out.deviceSecret.wipe()
                }
            }
        }

    override suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray) =
        withContext(ioDispatcher) {
            mapErrors { removeFn(vaultFolder.toByteArray(Charsets.UTF_8), deviceUuid) }
        }
}
