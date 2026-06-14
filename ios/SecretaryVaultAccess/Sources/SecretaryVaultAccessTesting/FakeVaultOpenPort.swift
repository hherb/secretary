import Foundation
import SecretaryVaultAccess

/// In-memory `VaultOpenPort` returning pre-seeded results.
public final class FakeVaultOpenPort: VaultOpenPort {
    private let passwordResult: Result<VaultSession, VaultAccessError>
    private let recoveryResult: Result<VaultSession, VaultAccessError>
    /// Spies asserted by the UnlockViewModel tests (which credential bytes the
    /// VM forwarded for each mode).
    public private(set) var lastPassword: [UInt8]?
    public private(set) var lastPhrase: [UInt8]?
    /// Optional rendezvous so a responsiveness test can hold the call mid-flight.
    public var gate: SuspensionGate?

    public init(passwordResult: Result<VaultSession, VaultAccessError>,
                recoveryResult: Result<VaultSession, VaultAccessError>) {
        self.passwordResult = passwordResult
        self.recoveryResult = recoveryResult
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
}
