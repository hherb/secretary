// B.2 device-slot add / open / remove assertions for the Swift smoke runner.
//
// The Swift/Kotlin conformance runners (tests/swift/conformance.swift) already
// exercise the add_device_slot → take_secret → open_with_device_secret enrol
// round-trip. What they do NOT cover — and what this smoke block adds — is the
// revocation half of the contract:
//
//   - remove_device_slot deletes devices/<uuid>.wrap and succeeds.
//   - open_with_device_secret AFTER a remove → VaultError.DeviceSlotNotFound
//     (the wrap file is gone, so there's no slot to decap).
//   - a second remove_device_slot on the same UUID → VaultError.DeviceSlotNotFound
//     (the idempotent-removal contract: removing an absent slot is an error,
//     not a silent no-op).
//
// CRITICAL: every assertion runs against a per-test temp copy of
// golden_vault_001. remove_device_slot DELETES a file; running against the
// tracked fixture would delete a devices/*.wrap from a frozen KAT vault.
// `_freshDeviceSlotVault` stages the copy; the caller removes it on exit.

import Foundation

// Stage a fresh writable copy of golden_vault_001 in a unique tempdir and
// return its folder-path bytes + the tempdir URL the caller must remove.
// Distinct from `_freshWritableVault` because the device-slot flow operates
// folder-in (path bytes), not on opened identity/manifest handles.
func _freshDeviceSlotVault(env: SmokeEnv) throws -> (Data, URL) {
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("secretary_smoke_swift_devslot_\(UUID().uuidString)")
    try _recursiveCopy(env.vault001Url, tmp)
    return (Data(tmp.path.utf8), tmp)
}

func runDeviceSlotAsserts(env: SmokeEnv) {
    // Assert 38: full add → open → remove → (open|remove) DeviceSlotNotFound flow.
    do {
        let (folderPath, tmp) = try _freshDeviceSlotVault(env: env)
        defer { try? FileManager.default.removeItem(at: tmp) }

        // add_device_slot → 16-byte device_uuid + one-shot secret handle.
        let enroll = try addDeviceSlot(folderPath: folderPath, password: env.password001)
        check(
            enroll.deviceUuid.count == 16,
            "add_device_slot: device_uuid is 16 bytes (got \(enroll.deviceUuid.count))"
        )
        let secret = enroll.deviceSecret.takeSecret()
        defer { enroll.deviceSecret.wipe() }
        check(
            secret?.count == 32,
            "add_device_slot: device_secret is 32 bytes (got \(secret?.count ?? -1))"
        )
        guard let secret = secret else {
            check(false, "add_device_slot: take_secret() returned nil; cannot continue device-slot smoke")
            return
        }
        // takeSecret() is `bytes?` → a Data? directly (#261); pass it straight through.
        // open_with_device_secret → opens to the same owner (display_name "Owner").
        do {
            let out = try openWithDeviceSecret(
                folderPath: folderPath, deviceUuid: enroll.deviceUuid, deviceSecret: secret
            )
            defer { out.identity.wipe() }
            defer { out.manifest.wipe() }
            check(
                out.identity.displayName() == expectedDisplayName,
                "open_with_device_secret: display_name=\"\(out.identity.displayName())\""
            )
        }

        // remove_device_slot → succeeds (deletes devices/<uuid>.wrap).
        do {
            try removeDeviceSlot(folderPath: folderPath, deviceUuid: enroll.deviceUuid)
            check(true, "remove_device_slot: succeeded")
        } catch {
            check(false, "remove_device_slot threw \(error), expected to succeed")
        }

        // open_with_device_secret AGAIN → VaultError.DeviceSlotNotFound (wrap deleted).
        do {
            _ = try openWithDeviceSecret(
                folderPath: folderPath, deviceUuid: enroll.deviceUuid, deviceSecret: secret
            )
            check(false, "open after remove should have thrown VaultError.DeviceSlotNotFound")
        } catch VaultError.DeviceSlotNotFound {
            check(true, "open_with_device_secret after remove → VaultError.DeviceSlotNotFound")
        } catch {
            check(false, "open after remove threw \(error), expected VaultError.DeviceSlotNotFound")
        }

        // remove_device_slot AGAIN → VaultError.DeviceSlotNotFound (idempotent-removal contract).
        do {
            try removeDeviceSlot(folderPath: folderPath, deviceUuid: enroll.deviceUuid)
            check(false, "second remove should have thrown VaultError.DeviceSlotNotFound")
        } catch VaultError.DeviceSlotNotFound {
            check(true, "remove_device_slot second call → VaultError.DeviceSlotNotFound")
        } catch {
            check(false, "second remove threw \(error), expected VaultError.DeviceSlotNotFound")
        }
    } catch {
        check(false, "device-slot smoke setup threw \(error)")
    }
}
