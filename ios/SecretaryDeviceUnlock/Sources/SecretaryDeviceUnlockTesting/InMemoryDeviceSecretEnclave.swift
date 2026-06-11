import SecretaryDeviceUnlock

/// In-memory `DeviceSecretEnclave`. Holds the bytes (no real crypto); supports
/// injecting a `DeviceUnlockError` from `store`/`release` to simulate biometric
/// failures. Reusable by the SecretaryKit Tier-2 integration test.
public final class InMemoryDeviceSecretEnclave: DeviceSecretEnclave {
    private var secret: [UInt8]?
    public var storeError: DeviceUnlockError?
    public var releaseError: DeviceUnlockError?
    public private(set) var clearCount = 0

    public init() {}

    public var isEnrolled: Bool { secret != nil }

    public func store(secret: [UInt8]) throws {
        if let storeError { throw storeError }
        self.secret = secret
    }

    public func release(reason: String) async throws -> [UInt8] {
        if let releaseError { throw releaseError }
        guard let secret else { throw DeviceUnlockError.notEnrolled }
        return secret
    }

    public func clear() throws {
        clearCount += 1
        secret = nil
    }
}
