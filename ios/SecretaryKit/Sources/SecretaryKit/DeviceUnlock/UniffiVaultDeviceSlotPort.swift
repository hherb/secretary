import Foundation
import SecretaryDeviceUnlock

/// Real `VaultDeviceSlotPort` over the B.2 uniffi functions. This is the ONLY
/// place that touches the one-shot `DeviceSecretOutput`.
public struct UniffiVaultDeviceSlotPort: VaultDeviceSlotPort {
    public init() {}

    public func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot {
        do {
            // Scrub the adapter-owned password Data copy on the way out (#364);
            // this runs on the production "Remember this device" enroll path, so
            // a master-password copy must not linger in the heap. Parity with
            // UniffiVaultOpenPort.
            let out = try withZeroizingData(password) { pw in
                try SecretaryKit.addDeviceSlot(folderPath: vaultPath, password: pw)
            }
            // Wipe the one-shot handle on EVERY exit (success, throw, or any
            // future fallible code inserted below), so the secret is never left
            // recoverable in the bridge handle.
            defer { out.deviceSecret.wipe() }
            // takeSecret() is `bytes?` in the UDL → a zeroizable `Data?` (not a boxed list, #261).
            guard var secret = out.deviceSecret.takeSecret() else {
                throw VaultSlotError.other("device secret handle was empty")
            }
            // Zero the transient Data once the port's `[UInt8]` copy is built; the coordinator
            // zeroizes that EnrolledSlot copy after enclave.store.
            defer { secret.resetBytes(in: 0..<secret.count) }
            return EnrolledSlot(deviceUuid: [UInt8](out.deviceUuid), deviceSecret: [UInt8](secret))
        } catch let e as VaultError {
            throw mapVaultError(e)
        }
    }

    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault {
        do {
            // Scrub the adapter-owned device-secret Data copy on the way out
            // (#364). deviceUuid is not secret. Parity with UniffiVaultOpenPort.
            return try withZeroizingData(deviceSecret) { secretData in
                try SecretaryKit.openWithDeviceSecret(
                    folderPath: vaultPath,
                    deviceUuid: Data(deviceUuid),
                    deviceSecret: secretData)
            }
        } catch let e as VaultError {
            throw mapVaultError(e)
        }
    }

    public func removeDeviceSlot(vaultPath: Data, deviceUuid: [UInt8]) throws {
        do {
            try SecretaryKit.removeDeviceSlot(folderPath: vaultPath, deviceUuid: Data(deviceUuid))
        } catch let e as VaultError {
            throw mapVaultError(e)
        }
    }
}

/// Map the uniffi `VaultError` onto the pure `VaultSlotError` mirror.
/// File-private: the device-slot error translation must not be reused to map a
/// `VaultError` from a non-device-slot path through these typed cases.
private func mapVaultError(_ e: VaultError) -> VaultSlotError {
    switch e {
    case .DeviceSlotNotFound:                       return .deviceSlotNotFound
    case .WrongDeviceSecretOrCorrupt:               return .wrongDeviceSecretOrCorrupt
    case .DeviceUuidMismatch(let detail):           return .deviceUuidMismatch(detail)
    case .InvalidArgument(let detail):              return .invalidArgument(detail)
    default:                                        return .other(String(describing: e))
    }
}
