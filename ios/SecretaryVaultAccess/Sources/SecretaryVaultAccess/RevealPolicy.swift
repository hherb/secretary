import Foundation

/// Policy constants for revealing secret field values. Auto-hide is driven by
/// the SwiftUI layer (a `Task.sleep` over this interval); the view models
/// expose `hide`/`hideAll`, which are the unit-tested seam. The interval is a
/// named constant — never a magic number sprinkled in the view.
public enum RevealPolicy {
    /// How long a revealed value stays visible before the UI auto-hides it.
    public static let autoHideSeconds: TimeInterval = 30
}
