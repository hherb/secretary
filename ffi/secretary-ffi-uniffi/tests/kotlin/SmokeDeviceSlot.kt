// B.2 device-slot add / open / remove assertions for the Kotlin smoke runner.
//
// The Swift/Kotlin conformance runners (tests/kotlin/Conformance.kt) already
// exercise the addDeviceSlot → takeSecret → openWithDeviceSecret enrol
// round-trip. What they do NOT cover — and what this smoke block adds — is the
// revocation half of the contract:
//
//   - removeDeviceSlot deletes devices/<uuid>.wrap and succeeds.
//   - openWithDeviceSecret AFTER a remove → VaultException.DeviceSlotNotFound
//     (the wrap file is gone, so there's no slot to decap).
//   - a second removeDeviceSlot on the same UUID → VaultException.DeviceSlotNotFound
//     (the idempotent-removal contract: removing an absent slot is an error,
//     not a silent no-op).
//
//   - Assert 39: full add → open → remove → (open|remove) DeviceSlotNotFound flow.
//
// CRITICAL: every assertion runs against a per-test temp copy of
// golden_vault_001. removeDeviceSlot DELETES a file; running against the
// tracked fixture would delete a devices/*.wrap from a frozen KAT vault.
// `freshDeviceSlotVault` stages the copy; the caller removes it on exit.

import uniffi.secretary.VaultException
import uniffi.secretary.addDeviceSlot
import uniffi.secretary.openWithDeviceSecret
import uniffi.secretary.removeDeviceSlot

// Stage a fresh writable copy of golden_vault_001 in a unique tempdir and
// return its folder-path bytes + the tempdir Path the caller must clean up.
// Distinct from `freshWritableVault` because the device-slot flow operates
// folder-in (path bytes), not on opened identity/manifest handles.
fun freshDeviceSlotVault(env: SmokeEnv): Pair<ByteArray, java.nio.file.Path> {
    val tmp = java.nio.file.Files.createTempDirectory("secretary_smoke_kotlin_devslot_")
    recursiveCopy(env.vault001Path, tmp)
    return Pair(tmp.toString().toByteArray(Charsets.UTF_8), tmp)
}

fun runDeviceSlotAsserts(env: SmokeEnv) {
    var devTmp: java.nio.file.Path? = null

    // Assert 39: full add → open → remove → (open|remove) DeviceSlotNotFound flow.
    try {
        val (folderPath, tmp) = freshDeviceSlotVault(env)
        devTmp = tmp

        // addDeviceSlot → 16-byte device_uuid + one-shot secret handle.
        val enroll = addDeviceSlot(folderPath, env.password001.direct())
        check(
            enroll.deviceUuid.size == 16,
            "addDeviceSlot: device_uuid is 16 bytes (got ${enroll.deviceUuid.size})",
        )
        val secret = enroll.deviceSecret.use { it.takeSecret() }
        check(
            secret?.size == 32,
            "addDeviceSlot: device_secret is 32 bytes (got ${secret?.size ?: -1})",
        )
        if (secret == null) {
            check(false, "addDeviceSlot: takeSecret() returned null; cannot continue device-slot smoke")
            return
        }
        // takeSecret() is `bytes?` → a ByteArray? directly (#261); no boxed-list conversion.
        // openWithDeviceSecret → opens to the same owner (display_name "Owner").
        openWithDeviceSecret(folderPath, enroll.deviceUuid, secret.direct()).let { out ->
            out.identity.use { id ->
                out.manifest.use {
                    check(
                        id.displayName() == EXPECTED_DISPLAY_NAME,
                        "openWithDeviceSecret: display_name=\"${id.displayName()}\"",
                    )
                }
            }
        }

        // removeDeviceSlot → succeeds (deletes devices/<uuid>.wrap).
        try {
            removeDeviceSlot(folderPath, enroll.deviceUuid)
            check(true, "removeDeviceSlot: succeeded")
        } catch (e: Throwable) {
            check(false, "removeDeviceSlot threw $e, expected to succeed")
        }

        // openWithDeviceSecret AGAIN → VaultException.DeviceSlotNotFound (wrap deleted).
        try {
            openWithDeviceSecret(folderPath, enroll.deviceUuid, secret.direct())
            check(false, "open after remove should have thrown VaultException.DeviceSlotNotFound")
        } catch (e: VaultException.DeviceSlotNotFound) {
            check(true, "openWithDeviceSecret after remove → VaultException.DeviceSlotNotFound")
        }

        // removeDeviceSlot AGAIN → VaultException.DeviceSlotNotFound (idempotent-removal contract).
        try {
            removeDeviceSlot(folderPath, enroll.deviceUuid)
            check(false, "second remove should have thrown VaultException.DeviceSlotNotFound")
        } catch (e: VaultException.DeviceSlotNotFound) {
            check(true, "removeDeviceSlot second call → VaultException.DeviceSlotNotFound")
        }
    } catch (e: Throwable) {
        check(false, "device-slot smoke setup threw $e")
    } finally {
        devTmp?.let { cleanupTempVault(it) }
    }
}
