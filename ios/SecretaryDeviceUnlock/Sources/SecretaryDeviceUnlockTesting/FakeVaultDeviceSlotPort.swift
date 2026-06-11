import Foundation
import SecretaryDeviceUnlock

/// In-memory `VaultDeviceSlotPort`. Records calls and supports error injection
/// so the coordinator's every branch is reachable without the real FFI.
public final class FakeVaultDeviceSlotPort: VaultDeviceSlotPort {
    // Canned outputs / injected errors.
    public var addResult: Result<EnrolledSlot, VaultSlotError>
    public var openResult: Result<OpenedVault, VaultSlotError>
    public var removeError: VaultSlotError?

    // Call recorders.
    public private(set) var addCalls = 0
    public private(set) var addCalledWith: (vaultPath: Data, password: [UInt8])?
    public private(set) var openedWith: (deviceUuid: [UInt8], deviceSecret: [UInt8])?
    public private(set) var removedUuids: [[UInt8]] = []

    public init(
        addResult: Result<EnrolledSlot, VaultSlotError> =
            .success(EnrolledSlot(deviceUuid: Array(repeating: 0xAB, count: 16),
                                  deviceSecret: Array(repeating: 0xCD, count: 32))),
        openResult: Result<OpenedVault, VaultSlotError> =
            .success(FakeOpenedVault(vaultUuid: Array(repeating: 0xEF, count: 16))),
        removeError: VaultSlotError? = nil
    ) {
        self.addResult = addResult
        self.openResult = openResult
        self.removeError = removeError
    }

    public func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot {
        addCalls += 1
        addCalledWith = (vaultPath, password)
        return try addResult.get()
    }

    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault {
        openedWith = (deviceUuid, deviceSecret)
        return try openResult.get()
    }

    public func removeDeviceSlot(vaultPath: Data, deviceUuid: [UInt8]) throws {
        removedUuids.append(deviceUuid)
        if let removeError { throw removeError }
    }
}
