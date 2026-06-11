import Foundation

/// Policy constants for revealing secret field values. Auto-hide is driven by
/// the SwiftUI layer: `VaultBrowseScreen.fieldRow` attaches a `.task` that
/// `Task.sleep`s over this interval and then calls the view model's `hide`
/// (the unit-tested seam; `hide`/`hideAll` are asserted in
/// `VaultBrowseViewModelTests`). The interval is a named constant — never a
/// magic number sprinkled in the view.
public enum RevealPolicy {
    /// How long a revealed value stays visible before the UI auto-hides it.
    public static let autoHideSeconds: TimeInterval = 30
}
