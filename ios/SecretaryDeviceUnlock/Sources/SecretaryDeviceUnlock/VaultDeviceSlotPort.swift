import Foundation

/// The 32-byte device secret + 16-byte device uuid returned by enrollment.
/// `deviceSecret` is a `var` so the coordinator can `zeroize` its canonical copy.
public struct EnrolledSlot {
    public let deviceUuid: [UInt8]
    public var deviceSecret: [UInt8]
    public init(deviceUuid: [UInt8], deviceSecret: [UInt8]) {
        self.deviceUuid = deviceUuid
        self.deviceSecret = deviceSecret
    }
}

/// Thin port over the three B.2 device-slot uniffi functions. Throws `VaultSlotError`.
public protocol VaultDeviceSlotPort {
    func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot
    func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault
    func removeDeviceSlot(vaultPath: Data, deviceUuid: [UInt8]) throws
}
