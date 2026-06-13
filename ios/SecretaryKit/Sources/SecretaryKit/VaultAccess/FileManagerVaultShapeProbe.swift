import Foundation
import SecretaryVaultAccess

/// Real `VaultShapeProbe`: a folder looks like a vault iff it directly contains a
/// `vault.toml`. Crypto-free shape detection only — corrupt contents still surface
/// at unlock time via the FFI's typed errors.
public struct FileManagerVaultShapeProbe: VaultShapeProbe {
    public init() {}

    public func looksLikeVault(_ folder: URL) throws -> Bool {
        let marker = folder.appendingPathComponent("vault.toml", isDirectory: false)
        return FileManager.default.fileExists(atPath: marker.path)
    }
}
