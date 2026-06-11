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

    public init(passwordResult: Result<VaultSession, VaultAccessError>,
                recoveryResult: Result<VaultSession, VaultAccessError>) {
        self.passwordResult = passwordResult
        self.recoveryResult = recoveryResult
    }

    public func openWithPassword(vaultPath: Data, password: [UInt8]) throws -> VaultSession {
        lastPassword = password
        return try passwordResult.get()
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) throws -> VaultSession {
        lastPhrase = phrase
        return try recoveryResult.get()
    }
}
