import Foundation

/// The two numeric Settings inputs, parsed but **not** clamped to the vault's
/// projected bounds. Clamping belongs to `SettingsViewModel.setRetentionDays` /
/// `setGraceMinutes`, so this type carries no bounds dependency and stays trivially
/// testable.
public struct SettingsEdits: Equatable, Sendable {
    public let retentionDays: Int
    public let graceMinutes: Int

    public init(retentionDays: Int, graceMinutes: Int) {
        self.retentionDays = retentionDays
        self.graceMinutes = graceMinutes
    }
}

/// Raw text for the two numeric Settings inputs, held as view `@State` and
/// committed explicitly at Save.
///
/// **Why a text buffer instead of `TextField(value:format:)`.** That form commits
/// its binding only on Return or focus loss, and neither platform's Save button
/// reliably moves first responder first: an AppKit button click does not, and on
/// iOS `.keyboardType(.numberPad)` has no Return key at all, leaving focus loss as
/// the only commit trigger. A typed-then-tapped Save would therefore persist the
/// PREVIOUS value while the field still displayed the new one. The same binding
/// also leaves the bound value untouched when a parse fails, so CLEARING a field
/// would silently re-save the old value against a visibly empty box. Both break the
/// WYSIWYG contract `SettingsViewModel.save()` documents for itself — "whatever
/// value the screen shows is exactly what is written". Buffering the raw text and
/// committing explicitly at Save makes both paths deterministic. (#458 macOS,
/// #459 iOS.)
///
/// A `@FocusState`-defocus-before-save fix was considered and rejected in #458: the
/// focus resignation flushes on the next view update, so it races the
/// `Task { await save() }`.
public struct SettingsEditBuffer: Equatable, Sendable {
    public var retentionText: String
    public var graceText: String

    /// Both fields empty. Views construct this as `@State` and call `seed` from
    /// `.onAppear` once `SettingsViewModel.load()` has populated the view model.
    public init() {
        retentionText = ""
        graceText = ""
    }

    /// Render committed view-model values back into the fields as ungrouped digits.
    /// Called after `load()` and after every successful commit, so the display always
    /// matches the value that was — or is about to be — written.
    public mutating func seed(retentionDays: Int, graceMinutes: Int) {
        retentionText = String(retentionDays)
        graceText = String(graceMinutes)
    }

    /// Both fields as whole numbers, or `nil` if **either** is unparseable.
    ///
    /// Plain `Int(_:)` rather than a locale-aware `FormatStyle`: retention tops out
    /// at 3650 days, so a grouping locale could render or accept "3,650". `seed`
    /// only ever emits ungrouped digits, so a grouped value is necessarily
    /// hand-typed, and failing loudly beats silent coercion — which is the point of
    /// this whole path. Revisit if these fields are ever properly localized (#433).
    ///
    /// A sign is accepted (`Int("-5") == -5`) and absorbed by the view model's
    /// clamp. Only genuinely non-numeric text — including empty and
    /// whitespace-only — fails here.
    public func parsed() -> SettingsEdits? {
        guard let days = Int(retentionText.trimmingCharacters(in: .whitespaces)),
              let minutes = Int(graceText.trimmingCharacters(in: .whitespaces)) else {
            return nil
        }
        return SettingsEdits(retentionDays: days, graceMinutes: minutes)
    }
}
