import Foundation

/// macOS `VaultLocationStore`: persists the one remembered vault as a PLAIN folder
/// path (no security-scoped bookmark) in `UserDefaults`, and brokers access with a
/// no-op scope. macOS pre-sandbox has direct filesystem access, so no bookmark is
/// required; the App-Sandbox slice will swap in a bookmark-backed store with no
/// change to `VaultSelectionViewModel`.
///
/// Reuses `VaultLocation.bookmark` to carry the UTF-8 path bytes — that field is
/// documented as a non-secret "path-style token", and a plain path is exactly that,
/// so no protocol or model change is needed. No password or key material ever flows
/// through this type (paths only).
///
/// Single-vault by design (mirrors `BookmarkVaultLocationStore`): `persist` replaces
/// any prior location.
public final class FileVaultLocationStore: VaultLocationStore {
    private let defaults: UserDefaults
    private let pathKey: String
    private let nameKey: String

    public init(defaults: UserDefaults = .standard,
                pathKey: String = "secretary.mac.vault.path",
                nameKey: String = "secretary.mac.vault.displayName") {
        self.defaults = defaults
        self.pathKey = pathKey
        self.nameKey = nameKey
    }

    public func load() -> VaultLocation? {
        guard let path = defaults.string(forKey: pathKey),
              let name = defaults.string(forKey: nameKey) else { return nil }
        return VaultLocation(displayName: name, bookmark: Data(path.utf8))
    }

    public func persist(_ location: VaultLocation) {
        defaults.set(String(decoding: location.bookmark, as: UTF8.self), forKey: pathKey)
        defaults.set(location.displayName, forKey: nameKey)
    }

    public func clear() {
        defaults.removeObject(forKey: pathKey)
        defaults.removeObject(forKey: nameKey)
    }

    /// macOS pre-sandbox: the stored path bytes are directly usable; there is no
    /// security scope to hold, so `onEnd` is a no-op. A folder that has since moved
    /// or been deleted is NOT hard-failed here (mirroring the iOS store's philosophy):
    /// it surfaces loudly downstream as the FFI's typed open error at unlock time.
    public func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath {
        ScopedVaultPath(pathData: location.bookmark, onEnd: {})
    }
}
