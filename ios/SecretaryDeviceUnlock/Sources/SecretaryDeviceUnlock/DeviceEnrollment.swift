/// Non-secret enrollment metadata. `vaultId` is a caller-supplied opaque token
/// identifying the vault, used to detect a stale enrollment.
public struct DeviceEnrollment: Equatable {
    public let vaultId: String
    public let deviceUuid: [UInt8]
    public init(vaultId: String, deviceUuid: [UInt8]) {
        self.vaultId = vaultId
        self.deviceUuid = deviceUuid
    }
}

public protocol DeviceEnrollmentMetadataStore {
    func load() throws -> DeviceEnrollment?
    func save(_ enrollment: DeviceEnrollment) throws
    func clear() throws
}
