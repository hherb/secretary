import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the vault-selection screen over a `VaultLocationStore` port. Holds only
/// the injected store, so it is fully host-testable. `@MainActor` because it
/// publishes UI state.
@MainActor
public final class VaultSelectionViewModel: ObservableObject {
    @Published public private(set) var state: VaultSelectionState = .empty

    private let store: VaultLocationStore

    public init(store: VaultLocationStore) {
        self.store = store
    }

    /// Refresh state from the persisted store (call on appear / on returning to
    /// the selection screen after a lock).
    public func loadPersisted() {
        if let loc = store.load() {
            state = .located(displayName: loc.displayName)
        } else {
            state = .empty
        }
    }

    /// Record a freshly picked vault (bookmark + name), persist it, and locate it.
    public func recordSelection(bookmark: Data, displayName: String) {
        store.persist(VaultLocation(displayName: displayName, bookmark: bookmark))
        state = .located(displayName: displayName)
    }

    /// Forget the remembered vault and return to the empty state.
    public func chooseDifferent() {
        store.clear()
        state = .empty
    }

    /// Acquire a scope for the remembered vault. The returned `ScopedVaultPath`
    /// must be held for the whole session and `end()`-ed on lock/background.
    /// Throws `.noVaultSelected` if nothing is remembered; on an unresolvable
    /// bookmark, transitions to `.unavailable` (the location is RETAINED, not
    /// cleared — losing the user's selection silently would be wrong) and rethrows.
    public func beginAccess() throws -> ScopedVaultPath {
        guard let loc = store.load() else { throw VaultSelectionError.noVaultSelected }
        do {
            return try store.beginAccess(loc)
        } catch {
            // ANY failure to acquire the scope means the remembered vault cannot be
            // opened right now. Reflect that in state so it never lies (a caller
            // observing only state must not see a stale `.located`). The location is
            // RETAINED, not cleared — losing the user's selection silently would be
            // wrong. Rethrow the ORIGINAL error unchanged (no reconstruction).
            if case VaultSelectionError.locationUnavailable(let reason) = error {
                state = .unavailable(reason: reason)
            } else {
                state = .unavailable(reason: String(describing: error))
            }
            throw error
        }
    }
}
