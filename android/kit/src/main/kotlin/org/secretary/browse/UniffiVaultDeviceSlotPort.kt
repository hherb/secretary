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
                    // takeSecret() is `bytes?` in the UDL, so uniffi hands back a zeroizable ByteArray? directly —
                    // no intermediate boxed List<UByte> left un-overwritable in the heap (#261). The FFI handle is
                    // wiped in the finally; the coordinator zeroizes this caller-owned ByteArray after enclave.store
                    // (see DeviceUnlockCoordinator.enroll).
                    val secret = out.deviceSecret.takeSecret()
                        ?: throw VaultBrowseError.Failed("device secret handle was empty (already taken?)")
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
