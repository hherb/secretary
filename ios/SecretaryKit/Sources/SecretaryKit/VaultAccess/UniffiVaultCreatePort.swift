import Foundation
import SecretaryVaultAccess

/// Real `VaultCreatePort` over the uniffi `createVaultInFolder` surface. Owns the
/// iOS filesystem dance: hold the parent's security scope, mkdir a fresh subfolder
/// (guaranteed empty), create the vault, build a persistable bookmark, and return
/// the location + one-shot recovery phrase.
public struct UniffiVaultCreatePort: VaultCreatePort {
    public init() {}

    public func create(parent: URL,
                       vaultName: String,
                       password: [UInt8],
                       displayName: String) throws -> CreatedVault {
        // Hold the parent's security scope for the whole create + bookmark window.
        let granted = parent.startAccessingSecurityScopedResource()
        defer { if granted { parent.stopAccessingSecurityScopedResource() } }

        let folder = parent.appendingPathComponent(vaultName, isDirectory: true)

        // mkdir the fresh subfolder. `withIntermediateDirectories: false` so that
        // an existing dir surfaces as a typed error rather than silently reusing it.
        do {
            try FileManager.default.createDirectory(
                at: folder, withIntermediateDirectories: false)
        } catch let err as NSError
            where err.domain == NSCocoaErrorDomain && err.code == NSFileWriteFileExistsError {
            throw VaultProvisioningError.folderNotEmpty
        } catch {
            throw VaultProvisioningError.folderInvalid(String(describing: error))
        }

        let mnem: MnemonicOutput
        do {
            mnem = try SecretaryKit.createVaultInFolder(
                folderPath: Data(folder.path.utf8),
                password: Data(password),
                displayName: displayName,
                createdAtMs: UInt64(Date().timeIntervalSince1970 * 1000))
        } catch let e as VaultError {
            throw mapProvisioningError(e)
        }
        defer { mnem.wipe() }

        guard let phrase = mnem.takePhrase() else {
            throw VaultProvisioningError.createFailed("recovery phrase unavailable")
        }

        // Bookmark the NEW subfolder while still inside the parent's scope (the
        // standard pattern for bookmarking a child URL). iOS uses `[]` options.
        //
        // Degraded path: if bookmarking fails here the vault files are already
        // written, so we leave a complete-but-unreferenced vault folder on disk and
        // surface a typed error (never a silent no-op). The orphan is harmless — the
        // user can re-import the folder via "Import existing vault" to recover it.
        // We don't auto-delete it: destroying just-written user data on a transient
        // bookmark failure would be the worse outcome.
        let bookmark: Data
        do {
            bookmark = try folder.bookmarkData()
        } catch {
            throw VaultProvisioningError.folderInvalid(
                "vault created but bookmark failed: \(String(describing: error))")
        }

        return CreatedVault(
            location: VaultLocation(displayName: vaultName, bookmark: bookmark),
            phrase: phrase)
    }
}
