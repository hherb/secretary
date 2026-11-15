import Foundation

/// Opens a vault folder by password or recovery phrase, producing a
/// `VaultSession`. Implementations throw `VaultAccessError`.
///
/// `async` because the real open runs Argon2id (CPU-heavy); implementations
/// offload it off the calling actor so a `@MainActor` caller's UI stays
/// responsive (see `SecretaryKit.runOffMainActor`).
///
/// `Sendable` because a `@MainActor` view model sends its conformer off-actor to
/// `await openWith…` (#231).
public protocol VaultOpenPort: Sendable {
    func openWithPassword(vaultPath: Data, password: [UInt8]) async throws -> VaultSession
    func openWithRecovery(vaultPath: Data, phrase: [UInt8]) async throws -> VaultSession

    /// Open the vault with the master password WITHOUT the rollback check, then
    /// replace this device's sync baseline for it with the clock just verified,
    /// accepting the copy on disk (#746). A wrong password changes nothing. Offered only after a password
    /// open threw `.rollbackDetected` and the user confirmed; never automatic.
    /// Runs Argon2id, so conformers offload like `openWithPassword`.
    func resetSyncStateAndOpen(vaultPath: Data, password: [UInt8]) async throws -> VaultSession

    /// Open a vault with a biometric-released device secret (B.2 device slot),
    /// producing the SAME `VaultSession` type as the password/recovery arms.
    /// `async` for contract uniformity; conformers offload for consistency.
    func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                              deviceSecret: [UInt8]) async throws -> VaultSession
}
