import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Per-vault settings sheet (macOS): retention window (days) + re-auth grace
/// (minutes). Mirrors iOS `SettingsScreen` over the shared, host-tested
/// `SettingsViewModel`; the load-bearing gate-then-retarget save ordering lives
/// entirely in the VM (the view only binds controls and calls `save()`). macOS
/// diffs from the iOS screen: grouped `Form`, no `.keyboardType` (iOS-only), an
/// explicit Done button in a bottom bar (iOS pushes onto a NavigationStack) —
/// matching the D.5.3 sheet idiom (`MacRecordEditView`) — and text-buffered
/// numeric inputs (see `commitEdits`).
@MainActor
struct MacSettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    let onDone: () -> Void

    /// Live text for the two numeric inputs, seeded from the VM after `load()`
    /// and pushed back into the VM by `commitEdits()` at Save.
    ///
    /// These are deliberately NOT `TextField(value:format:)` bindings. That form
    /// commits its binding only on Return or focus loss, and an AppKit button
    /// click does not move first responder — so a typed-then-mouse-clicked Save
    /// would persist the PREVIOUS value while the field still displayed the new
    /// one, breaking the WYSIWYG contract `SettingsViewModel.save()` documents
    /// ("whatever value the screen shows is exactly what is written"). It would
    /// also silently save the old value when the user cleared the field, since a
    /// failed parse leaves the bound value untouched. Buffering the raw text and
    /// committing explicitly at Save makes both paths deterministic.
    @State private var retentionText = ""
    @State private var graceText = ""
    /// Set when a field doesn't hold a plain integer at Save time. View-local on
    /// purpose: unparseable text never reaches the VM, so it has no VM error to
    /// surface. Cleared on every Save attempt.
    @State private var inputError: String?

    init(viewModel: SettingsViewModel, onDone: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onDone = onDone
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                // `inputError` describes the most recent Save attempt, which was
                // refused before reaching the VM — so the VM's banner/error still
                // hold the PREVIOUS attempt's outcome and are shown only when there
                // is no input error. Without this, a bad-input Save after a good one
                // would render "Settings saved" directly above "not saved" (the VM
                // clears its own banner inside `save()`, which this path never calls,
                // and `banner` is private(set) so the view cannot clear it).
                if let inputError {
                    Text(inputError).font(.footnote).foregroundStyle(.red)
                } else {
                    if let banner = viewModel.banner {
                        Text(banner.text).font(.footnote).foregroundStyle(.secondary)
                    }
                    if let error = viewModel.error {
                        Text(settingsErrorMessage(error)).font(.footnote).foregroundStyle(.red)
                    }
                }
                Section {
                    LabeledContent("Delete trash after") {
                        HStack(spacing: 4) {
                            TextField("Days", text: $retentionText)
                                .multilineTextAlignment(.trailing).frame(maxWidth: 80)
                            Text("days").foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Trash")
                } footer: {
                    Text("Trashed items older than this are eligible for permanent purge "
                         + "(\(viewModel.retentionDaysRange.lowerBound)–\(viewModel.retentionDaysRange.upperBound) days).")
                }
                Section {
                    LabeledContent("Re-auth grace") {
                        HStack(spacing: 4) {
                            TextField("Minutes", text: $graceText)
                                .multilineTextAlignment(.trailing).frame(maxWidth: 80)
                            Text("min").foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Security")
                } footer: {
                    Text("After a Touch ID / password check, writes within this window don't re-prompt "
                         + "(\(viewModel.graceMinutesRange.lowerBound)–\(viewModel.graceMinutesRange.upperBound) min; "
                         + "0 re-authenticates every write).")
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Button("Done") { onDone() }
                Spacer()
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(viewModel.isWriting)
            }
            .padding()
        }
        .frame(minWidth: 460, minHeight: 420)
        .navigationTitle("Settings")
        .onAppear {
            viewModel.load()
            syncTextFromViewModel()
        }
    }

    /// Commit the typed text into the VM, then save. On unparseable input nothing
    /// is written — surfacing that beats persisting a value the user never typed.
    private func save() {
        inputError = nil
        guard commitEdits() else {
            inputError = "Both fields need a whole number — settings were not saved."
            return
        }
        // Re-seed from the VM so the fields show the CLAMPED values that are about
        // to be written, keeping the display and the persisted value identical.
        syncTextFromViewModel()
        Task { await viewModel.save() }
    }

    /// Parse both fields and push them through the VM's clamping setters.
    /// Returns false (writing nothing) if either field isn't a whole number.
    ///
    /// Plain `Int(_:)` rather than a locale-aware `FormatStyle`: retention tops out
    /// at 3650 days, so a grouping locale could render/accept "3,650". We emit only
    /// ungrouped digits (`syncTextFromViewModel`), and a hand-typed grouped value now
    /// fails loudly with a message instead of being silently coerced — which is the
    /// point of this whole path. Revisit if these fields ever go properly localized.
    private func commitEdits() -> Bool {
        guard let days = Int(retentionText.trimmingCharacters(in: .whitespaces)),
              let minutes = Int(graceText.trimmingCharacters(in: .whitespaces)) else {
            return false
        }
        viewModel.setRetentionDays(days)
        viewModel.setGraceMinutes(minutes)
        return true
    }

    private func syncTextFromViewModel() {
        retentionText = String(viewModel.retentionDays)
        graceText = String(viewModel.graceMinutes)
    }
}
