/// The biometric-released device secret + the slot it opens, plus the vault the
/// enrollment is bound to. Returned by `DeviceUnlockCoordinator.releaseCredential`
/// so a session-producing open port (outside this FFI-free package) can open the
/// vault — this package never names `VaultSession`.
///
/// `secret` is a `var` so the consumer can zeroize its canonical copy after the
/// open. Deliberately NOT `Sendable`: it carries raw secret bytes and is created
/// and consumed on the same actor within a single open; it is never stored or
/// sent across an actor boundary.
public struct DeviceSecretCredential {
    public let deviceUuid: [UInt8]
    public var secret: [UInt8]
    public let enrolledVaultId: String

    public init(deviceUuid: [UInt8], secret: [UInt8], enrolledVaultId: String) {
        self.deviceUuid = deviceUuid
        self.secret = secret
        self.enrolledVaultId = enrolledVaultId
    }
}
