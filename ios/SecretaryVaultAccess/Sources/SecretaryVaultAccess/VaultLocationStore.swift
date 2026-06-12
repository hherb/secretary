import Foundation

/// Persists ONE remembered vault location and brokers scoped access to it. The
/// port keeps the platform bookmark / security-scope machinery (and its known
/// pitfalls: stale bookmarks, the begin/end balance) behind a boundary so the
/// `VaultSelectionViewModel` state machine is host-testable against a fake.
///
/// Single-vault by design (this slice): `persist` replaces any prior location.
public protocol VaultLocationStore {
    /// The remembered location, or `nil` if none has been selected.
    func load() -> VaultLocation?
    /// Remember `location`, replacing any prior one.
    func persist(_ location: VaultLocation)
    /// Forget the remembered location.
    func clear()
    /// Resolve `location` and acquire a scope held until the returned handle's
    /// `end()`. Throws `VaultSelectionError.locationUnavailable` if the underlying
    /// bookmark cannot be resolved. The caller is responsible for ensuring a
    /// location exists before calling this (the no-vault-selected precondition is
    /// enforced one level up, in `VaultSelectionViewModel.beginAccess`), so this
    /// method does not throw `.noVaultSelected`.
    func beginAccess(_ location: VaultLocation) throws -> ScopedVaultPath
}
