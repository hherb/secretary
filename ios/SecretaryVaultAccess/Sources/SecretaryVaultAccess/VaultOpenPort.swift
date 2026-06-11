import Foundation

/// Opens a vault folder by password or recovery phrase, producing a
/// `VaultSession`. Implementations throw `VaultAccessError`.
public protocol VaultOpenPort {
    func openWithPassword(vaultPath: Data, password: [UInt8]) throws -> VaultSession
    func openWithRecovery(vaultPath: Data, phrase: [UInt8]) throws -> VaultSession
}
