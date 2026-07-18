import SecretaryVaultAccess

/// In-memory `DeviceSlotPort` double with a spy + failure injection, modeled on
/// `FakeSettingsPort`. `forgetError` throws once then clears, so a test can prove
/// a retry succeeds. `@unchecked Sendable` for the same single-thread reason as
/// `FakeSettingsPort` / `FakeWriteReauthGate`.
public final class FakeDeviceSlotPort: DeviceSlotPort, @unchecked Sendable {
    public var isEnrolled: Bool
    public var forgetError: VaultAccessError?
    public private(set) var forgetCallCount = 0

    public init(isEnrolled: Bool = true) {
        self.isEnrolled = isEnrolled
    }

    public func forgetThisDevice() throws {
        // Throw BEFORE recording: a throwing call performed no revocation, and
        // `forgetCallCount` is asserted as "revocations that happened".
        if let e = forgetError { forgetError = nil; throw e }
        forgetCallCount += 1
    }
}
