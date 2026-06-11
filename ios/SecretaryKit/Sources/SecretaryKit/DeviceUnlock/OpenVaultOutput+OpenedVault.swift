import Foundation
import SecretaryDeviceUnlock

/// Bridge the uniffi `OpenVaultOutput` to the pure `OpenedVault` boundary type.
extension OpenVaultOutput: OpenedVault {
    public var vaultUuid: [UInt8] { [UInt8](manifest.vaultUuid()) }
    public func wipe() { manifest.wipe(); identity.wipe() }
}
