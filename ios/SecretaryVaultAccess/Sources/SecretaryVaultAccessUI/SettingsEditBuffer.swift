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
    /// this whole path. Grouping stays rejected after the digit fold below, in every
    /// script ("٣٬٦٥٠" fails exactly as "3,650" does). Revisit if these fields are
    /// ever properly localized (#433).
    ///
    /// A sign is accepted (`Int("-5") == -5`) and absorbed by the view model's
    /// clamp. Only genuinely non-numeric text — including empty and
    /// whitespace-only — fails here.
    public func parsed() -> SettingsEdits? {
        guard let days = Int(normalizedForParsing(retentionText)),
              let minutes = Int(normalizedForParsing(graceText)) else {
            return nil
        }
        return SettingsEdits(retentionDays: days, graceMinutes: minutes)
    }
}

/// Trim surrounding whitespace and fold decimal digits from any script to ASCII,
/// leaving every other scalar untouched so non-numeric text still fails the `Int`
/// parse.
///
/// **Why the digit fold.** `Int(_:)` is ASCII-only, but iOS renders
/// `.keyboardType(.numberPad)` in the ACTIVE KEYBOARD's numeral system — an Arabic
/// or Persian keyboard emits U+0660-0669 / U+06F0-06F9. The number pad is the only
/// input affordance for these fields on iOS, so without the fold a user on such a
/// keyboard could not save at all: every attempt would refuse with a message that
/// gives no clue why, and there is no ASCII digit to reach for. (The retired
/// `TextField(value:format:)` binding parsed through a locale-aware `FormatStyle`,
/// so it accepted these; dropping to `Int(_:)` must not silently drop them too.)
///
/// The fold is scoped to Unicode general category Nd (`numericType == .decimal`),
/// which is exactly the positional-decimal digits. Non-positional numerals are still
/// refused rather than coerced: "Ⅷ", "①" and "½" are `.numeric` / `.digit`, not
/// `.decimal`, so they pass through untouched and fail the parse.
///
/// Newlines are trimmed alongside spaces, not just `.whitespaces`: a pasted "45\n"
/// would otherwise be refused on a character the user cannot see.
private func normalizedForParsing(_ text: String) -> String {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    return String(String.UnicodeScalarView(trimmed.unicodeScalars.map { scalar in
        // `.decimal` is the load-bearing check; Unicode guarantees such a scalar
        // carries an integer value 0-9. The range test is only so a violated
        // guarantee degrades to "not a digit" instead of trapping the UInt8
        // conversion — `௰` (U+0BF0) carries 10.0, and it is one category away.
        guard scalar.properties.numericType == .decimal,
              let value = scalar.properties.numericValue,
              (0...9).contains(value) else { return scalar }
        return Unicode.Scalar(UInt8(0x30 + Int(value)))
    }))
}

/// Parse `buffer`, push both values through the view model's clamping setters, then
/// re-seed `buffer` from the now-CLAMPED view-model values so the fields display
/// exactly what is about to be written.
///
/// Returns `false` — writing nothing, leaving `buffer` untouched — if either field
/// is unparseable. Callers surface that as an input error and MUST NOT go on to call
/// `SettingsViewModel.save()`.
///
/// The commit is all-or-nothing on purpose: a half-applied edit (one good field
/// written, one bad field refused) would persist a combination the user never saw.
///
/// Deliberately runs BEFORE the re-auth gate at the call site. It can only ever
/// refuse, and `RetargetableReauthGate` holds its own window rather than reading
/// `graceMinutes`, so ordering it ahead of the gate cannot affect gate strength —
/// while it does avoid raising a biometric prompt only to fail on garbage input.
///
/// Committing HERE rather than from a control binding also closes a narrow
/// authorize-then-substitute window. `SettingsViewModel.save()` reads
/// `retentionDays` / `graceMinutes` AFTER its `await gate.authorizeWrite`
/// suspension, and the retired `TextField(value:format:)` binding committed on focus
/// loss — which the biometric prompt itself triggers by dismissing the keyboard. The
/// value written could therefore differ from the one in effect when the gate was
/// entered. This function is reached only from the Save button, which is disabled
/// while `isWriting`, so the view model can no longer be mutated mid-save.
@MainActor
public func commitSettingsEdits(_ buffer: inout SettingsEditBuffer,
                                into vm: SettingsViewModel) -> Bool {
    guard let edits = buffer.parsed() else { return false }
    vm.setRetentionDays(edits.retentionDays)
    vm.setGraceMinutes(edits.graceMinutes)
    buffer.seed(retentionDays: vm.retentionDays, graceMinutes: vm.graceMinutes)
    return true
}
