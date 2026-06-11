import SecretaryDeviceUnlock

public final class InMemoryEnrollmentMetadataStore: DeviceEnrollmentMetadataStore {
    private var enrollment: DeviceEnrollment?
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
