import Foundation
import SecretaryVaultAccess

/// In-memory `VaultLocationStore` for host tests. Counts scope starts/stops so
/// tests can assert the begin/end balance (no leaked scopes) that the real
/// adapter must also honour.
public final class FakeVaultLocationStore: VaultLocationStore {
    public private(set) var stored: VaultLocation?
    public private(set) var started = 0
    public private(set) var stopped = 0
    /// When set, `beginAccess` throws this instead of returning a handle.
    public var beginAccessError: VaultSelectionError?
    /// `pathData` returned by a successful `beginAccess`.
    public var pathDataToReturn: Data

    public init(stored: VaultLocation? = nil,
                pathDataToReturn: Data = Data("/fake/vault".utf8)) {
        self.stored = stored
        self.pathDataToReturn = pathDataToReturn
    }

    public func load() -> VaultLocation? { stored }
    public func persist(_ location: VaultLocation) { stored = location }
    public func clear() { stored = nil }

    public func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath {
        if let beginAccessError { throw beginAccessError }
        started += 1
        return ScopedVaultPath(pathData: pathDataToReturn,
                               onEnd: { [weak self] in self?.stopped += 1 })
    }

    /// Scopes acquired but not yet released. Must be 0 after balanced use.
    public var liveScopes: Int { started - stopped }
}
