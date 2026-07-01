import Foundation
import SecretaryVaultAccess

/// Real `VaultOpenPort` over the uniffi folder-in open functions. The CPU-heavy
/// Argon2id open runs off the calling actor via `runOffMainActor`, so a
/// `@MainActor` view-model's UI is not blocked during the KDF.
public struct UniffiVaultOpenPort: VaultOpenPort {
    public init() {}

    public func openWithPassword(vaultPath: Data, password: [UInt8]) async throws -> VaultSession {
        try await runOffMainActor {
            do {
                let out = try withZeroizingData(password) { pw in
                    try SecretaryKit.openVaultWithPassword(
                        folderPath: vaultPath, password: pw)
                }
                return UniffiVaultSession(output: out)
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }

    public func openWithRecovery(vaultPath: Data, phrase: [UInt8]) async throws -> VaultSession {
        try await runOffMainActor {
            do {
                let out = try withZeroizingData(phrase) { ph in
                    try SecretaryKit.openVaultWithRecovery(
                        folderPath: vaultPath, mnemonic: ph)
                }
                return UniffiVaultSession(output: out)
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }

    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                                     deviceSecret: [UInt8]) async throws -> VaultSession {
        try await runOffMainActor {
            do {
                let out = try SecretaryKit.openWithDeviceSecret(
                    folderPath: vaultPath,
                    deviceUuid: Data(deviceUuid),
                    deviceSecret: Data(deviceSecret))
                return UniffiVaultSession(output: out)
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }
}
