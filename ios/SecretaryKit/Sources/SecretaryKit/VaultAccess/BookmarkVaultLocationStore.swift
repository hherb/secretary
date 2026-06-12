import Foundation
import os
import SecretaryVaultAccess

/// Real `VaultLocationStore`: persists the remembered vault as a security-scoped
/// bookmark in `UserDefaults` and brokers scoped access via Foundation.
///
/// iOS bookmark note: unlike macOS, iOS does NOT use the `.withSecurityScope`
/// create/resolve options — a bookmark created from a document-picker URL is
/// implicitly security-scoped on iOS. We therefore use `[]` options throughout.
public final class BookmarkVaultLocationStore: VaultLocationStore {
    private static let log = Logger(subsystem: "com.secretary.app", category: "vault-location")
    private let defaults: UserDefaults
    private let bookmarkKey: String
    private let nameKey: String

    public init(defaults: UserDefaults = .standard,
                bookmarkKey: String = "secretary.vault.bookmark",
                nameKey: String = "secretary.vault.displayName") {
        self.defaults = defaults
        self.bookmarkKey = bookmarkKey
        self.nameKey = nameKey
    }

    public func load() -> VaultLocation? {
        guard let bookmark = defaults.data(forKey: bookmarkKey),
              let name = defaults.string(forKey: nameKey) else { return nil }
        return VaultLocation(displayName: name, bookmark: bookmark)
    }

    public func persist(_ location: VaultLocation) {
        defaults.set(location.bookmark, forKey: bookmarkKey)
        defaults.set(location.displayName, forKey: nameKey)
    }

    public func clear() {
        defaults.removeObject(forKey: bookmarkKey)
        defaults.removeObject(forKey: nameKey)
    }

    public func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath {
        var isStale = false
        let url: URL
        do {
            url = try URL(resolvingBookmarkData: location.bookmark,
                          options: [], relativeTo: nil, bookmarkDataIsStale: &isStale)
        } catch {
            throw VaultSelectionError.locationUnavailable(String(describing: error))
        }

        // `false` here is NOT treated as fatal: it is benign for in-sandbox paths,
        // and a genuine lack of access surfaces downstream as the FFI's typed open
        // error. We only `stop` if we actually `start`ed (`granted == true`).
        let granted = url.startAccessingSecurityScopedResource()

        // Refresh a stale bookmark WHILE access is held (re-persist). Best-effort:
        // a failed refresh does not abort the open — the already-resolved URL is
        // still valid — but it is LOGGED, never silent, so a recurring refresh
        // failure is diagnosable.
        if isStale {
            do {
                let fresh = try url.bookmarkData()
                persist(VaultLocation(displayName: location.displayName, bookmark: fresh))
                Self.log.notice("Refreshed stale vault bookmark for \(location.displayName, privacy: .public)")
            } catch {
                Self.log.error("Stale vault bookmark refresh failed (using resolved URL): \(String(describing: error), privacy: .public)")
            }
        }

        return ScopedVaultPath(pathData: Data(url.path.utf8),
                               onEnd: { if granted { url.stopAccessingSecurityScopedResource() } })
    }
}
