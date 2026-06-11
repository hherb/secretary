import SecretaryDeviceUnlock

public final class InMemoryEnrollmentMetadataStore: DeviceEnrollmentMetadataStore {
    private var enrollment: DeviceEnrollment?
    /// Deliberately the untyped `Error?` (not a specific enum): unlike the
    /// enclave (`DeviceUnlockError`) and the slot port (`VaultSlotError`), the
    /// metadata store's `save` throws *untyped* errors — the real Keychain
    /// conformer surfaces `NSError`/`OSStatus`, and the coordinator propagates
    /// those unchanged (spec §"planning refinements" #5). Tests inject an
    /// arbitrary `Error` to exercise that propagation.
    public var saveError: Error?
    public private(set) var clearCount = 0

    public init(enrollment: DeviceEnrollment? = nil) { self.enrollment = enrollment }

    public func load() throws -> DeviceEnrollment? { enrollment }

    public func save(_ enrollment: DeviceEnrollment) throws {
        if let saveError { throw saveError }
        self.enrollment = enrollment
    }

    public func clear() throws {
        clearCount += 1
        enrollment = nil
    }
}
