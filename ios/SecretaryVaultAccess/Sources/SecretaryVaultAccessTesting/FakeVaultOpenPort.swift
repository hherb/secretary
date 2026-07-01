import Foundation
import SecretaryVaultAccess

/// In-memory `VaultOpenPort` returning pre-seeded results.
///
/// `@unchecked Sendable`: mutable spy state satisfying the (now `Sendable`) port
/// protocol. Safe because XCTest drives it serially through `await`; the
/// assumption is stated, not hidden (#231).
public final class FakeVaultOpenPort: VaultOpenPort, @unchecked Sendable {
    private let passwordResult: Result<VaultSession, VaultAccessError>
    private let recoveryResult: Result<VaultSession, VaultAccessError>
    private let deviceSecretResult: Result<VaultSession, VaultAccessError>
    /// Spies asserted by the UnlockViewModel tests (which credential bytes the
    /// VM forwarded for each mode).
    public private(set) var lastPassword: [UInt8]?
    public private(set) var lastPhrase: [UInt8]?
    public private(set) var lastDeviceOpen: (deviceUuid: [UInt8], secret: [UInt8])?
    /// Optional rendezvous so a responsiveness test can hold the call mid-flight.
    public var gate: SuspensionGate?

    public init(passwordResult: Result<VaultSession, VaultAccessError>,
                recoveryResult: Result<VaultSession, VaultAccessError>,
                deviceSecretResult: Result<VaultSession, VaultAccessError> = .failure(.other("device-secret open not stubbed"))) {
        self.passwordResult = passwordResult
        self.recoveryResult = recoveryResult
        self.deviceSecretResult = deviceSecretResult
    }

    public func openWithPassword(vaultPath: Data, password: [UInt8]) async throws -> VaultSession {
        lastPassword = password
        await gate?.enterAndWait()
        return try passwordResult.get()
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) async throws -> VaultSession {
        lastPhrase = phrase
        await gate?.enterAndWait()
        return try recoveryResult.get()
    }

    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                                     deviceSecret: [UInt8]) async throws -> VaultSession {
        lastDeviceOpen = (deviceUuid, deviceSecret)
        await gate?.enterAndWait()
        return try deviceSecretResult.get()
    }
}
