/// Observable state of the vault-selection screen. Unlike `UnlockState`, this is
/// `Equatable`: it carries no live reference (the scoped handle is returned out of
/// band from `beginAccess`, not stored here), so tests compare it directly.
public enum VaultSelectionState: Equatable {
    /// No vault remembered — show "Select a vault…" / "Try the demo vault".
    case empty
    /// A vault is remembered — show "Open <name>" / "Choose a different vault".
    case located(displayName: String)
    /// The remembered vault could not be opened (bookmark unresolvable) — offer re-pick.
    case unavailable(reason: String)
}
