import SecretaryDeviceUnlock

public final class FakeOpenedVault: OpenedVault {
    public let vaultUuid: [UInt8]
    public private(set) var wipeCount = 0
    public init(vaultUuid: [UInt8]) { self.vaultUuid = vaultUuid }
    public func wipe() { wipeCount += 1 }
}
