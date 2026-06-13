import Foundation
import SecretaryVaultAccess

/// Real `VaultOpenPort` over the uniffi folder-in open functions.
public struct UniffiVaultOpenPort: VaultOpenPort {
    public init() {}

    public func openWithPassword(vaultPath: Data, password: [UInt8]) throws -> VaultSession {
        do {
            let out = try SecretaryKit.openVaultWithPassword(
                folderPath: vaultPath, password: Data(password))
            return try UniffiVaultSession(output: out)
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) throws -> VaultSession {
        do {
            let out = try SecretaryKit.openVaultWithRecovery(
                folderPath: vaultPath, mnemonic: Data(phrase))
            return try UniffiVaultSession(output: out)
        } catch let e as VaultError {
            throw mapVaultAccessError(e)
        }
    }
}
