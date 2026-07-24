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
    private let probe: VaultShapeProbe

    public init(store: VaultLocationStore, probe: VaultShapeProbe) {
        self.store = store
        self.probe = probe
    }

    /// Refresh state from the persisted store (call on appear / on returning to
    /// the selection screen after a lock).
    ///
    /// A surfaced `.unavailable` is preserved, NOT silently downgraded back to
    /// `.located`: a failed open's reason must survive a screen re-appear so the
    /// user is not handed an "Open" button that will just fail again with no
    /// explanation. The user clears `.unavailable` explicitly — `chooseDifferent()`
    /// (→ `.empty`) or a fresh `recordSelection(...)` (→ `.located`) both override it.
    public func loadPersisted() {
        if case .unavailable = state { return }
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

    /// Consider a folder the user picked via "Import existing vault". Runs the
    /// crypto-free shape probe FIRST: only a folder that contains a vault is
    /// persisted + located. A non-vault folder is rejected without persisting (so
    /// the user is not handed an "Open" button that will just fail at unlock); an
    /// unreadable folder surfaces as `.unavailable`. The caller must hold the
    /// folder's security scope across this call (the probe reads `vault.toml`).
    public func considerImport(url: URL, bookmark: Data, displayName: String) -> ImportOutcome {
        do {
            guard try probe.looksLikeVault(url) else { return .notAVault }
            recordSelection(bookmark: bookmark, displayName: displayName)
            return .opened
        } catch {
            logFoldedError(error)
            return .unavailable(String(describing: error))
        }
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
                logFoldedError(error)
                state = .unavailable(reason: String(describing: error))
            }
            throw error
        }
    }
}
