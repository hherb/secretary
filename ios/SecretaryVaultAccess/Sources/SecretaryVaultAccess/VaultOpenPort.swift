import Foundation

/// Opens a vault folder by password or recovery phrase, producing a
/// `VaultSession`. Implementations throw `VaultAccessError`.
///
/// `async` because the real open runs Argon2id (CPU-heavy); implementations
/// offload it off the calling actor so a `@MainActor` caller's UI stays
/// responsive (see `SecretaryKit.runOffMainActor`).
public protocol VaultOpenPort {
    func openWithPassword(vaultPath: Data, password: [UInt8]) async throws -> VaultSession
    func openWithRecovery(vaultPath: Data, phrase: [UInt8]) async throws -> VaultSession
}
