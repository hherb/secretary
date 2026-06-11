import Foundation
import SecretaryDeviceUnlock

/// Real `VaultDeviceSlotPort` over the B.2 uniffi functions. This is the ONLY
/// place that touches the one-shot `DeviceSecretOutput`.
public struct UniffiVaultDeviceSlotPort: VaultDeviceSlotPort {
    public init() {}

    public func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot {
        do {
            let out = try SecretaryKit.addDeviceSlot(folderPath: vaultPath, password: Data(password))
            // Wipe the one-shot handle on EVERY exit (success, throw, or any
            // future fallible code inserted below), so the secret is never left
            // recoverable in the bridge handle.
            defer { out.deviceSecret.wipe() }
            guard let secret = out.deviceSecret.takeSecret() else {
                throw VaultSlotError.other("device secret handle was empty")
            }
            return EnrolledSlot(deviceUuid: [UInt8](out.deviceUuid), deviceSecret: secret)
        } catch let e as VaultError {
            throw mapVaultError(e)
        }
    }

    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault {
        do {
            return try SecretaryKit.openWithDeviceSecret(
                folderPath: vaultPath,
                deviceUuid: Data(deviceUuid),
                deviceSecret: Data(deviceSecret))
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
