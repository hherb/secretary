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
    @StateObject private var deviceViewModel: DeviceSlotViewModel
    let onDone: () -> Void
    /// Called after a successful "Forget This Mac". The parent dismisses this sheet
    /// and then locks: clearing the enclave key makes the write-reauth gate a
    /// permanent no-op for the rest of the session, so the session must not continue.
    let onForgotten: () -> Void

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

    /// Drives the "Forget This Mac" confirmation dialog.
    @State private var confirmForget = false

    init(viewModel: SettingsViewModel,
         deviceViewModel: DeviceSlotViewModel,
         onDone: @escaping () -> Void,
         onForgotten: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        _deviceViewModel = StateObject(wrappedValue: deviceViewModel)
        self.onDone = onDone
        self.onForgotten = onForgotten
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
                            // `.labelsHidden()` because macOS renders a TextField's
                            // title as an attached LEADING label (iOS shows it as
                            // in-field placeholder inside a Form). Left visible it
                            // double-labels the row — "Delete trash after | Days |
                            // 7 days" — and squeezes the field enough to hyphenate
                            // "Min-utes" in the row below. The title is kept, not
                            // blanked, so the accessibility label survives.
                            //
                            // No `prompt:` either: on an empty field it renders right
                            // beside the unit suffix, reading "Days days". The row is
                            // self-describing without it (label + unit + the footer's
                            // explicit range), and empty is a transient error state.
                            TextField("Days", text: $retentionText)
                                .labelsHidden()
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
                                .labelsHidden()
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
                // Hidden entirely when this Mac is not enrolled: there is nothing to
                // forget, and a permanently-disabled destructive control is noise.
                // `isEnrolled` is a snapshot taken in the VM's init (a Keychain read
                // plus an enclave probe), so consulting it per render is free.
                if deviceViewModel.isEnrolled {
                    Section {
                        // macOS 13 floor: trailing-closure label form, not
                        // `Button(_:systemImage:action:)` (macOS 14+).
                        Button(role: .destructive) {
                            confirmForget = true
                        } label: {
                            Text("Forget This Mac")
                        }
                        .disabled(deviceViewModel.isBusy || viewModel.isWriting)
                        // Scoped to this section rather than the Form's shared
                        // message area at the top: a revocation failure is about a
                        // different action than a settings save, and keeping it here
                        // avoids interacting with the banner/inputError precedence
                        // rules documented above.
                        if let deviceError = deviceViewModel.error {
                            Text(deviceSlotErrorMessage(deviceError))
                                .font(.footnote).foregroundStyle(.red)
                        }
                    } header: {
                        Text("This Mac")
                    } footer: {
                        Text("Removes Touch ID unlock for this vault on this Mac. "
                             + "You'll need your master password to unlock, and can turn "
                             + "Touch ID back on then. Other devices are unaffected.")
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Button("Done") { onDone() }
                Spacer()
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    // Symmetric with the Forget button's `.disabled` above: both writers
                    // share the sheet's message area, and letting Save fire while a
                    // "Forget This Mac" revocation is in flight could clobber that
                    // banner/error state with a concurrent, unrelated write.
                    .disabled(viewModel.isWriting || deviceViewModel.isBusy)
            }
            .padding()
        }
        .frame(minWidth: 460, minHeight: 420)
        .navigationTitle("Settings")
        .confirmationDialog("Forget this Mac?",
                            isPresented: $confirmForget,
                            titleVisibility: .visible) {
            Button("Forget This Mac", role: .destructive) {
                Task {
                    await deviceViewModel.forget()
                    // Lock ONLY on a confirmed success. `forget()` is non-throwing
                    // and reaches `.forgotten` only when both the re-auth and the
                    // revocation succeeded, so a cancelled Touch ID prompt or a
                    // failed revocation leaves the session untouched and the error
                    // rendered in the section above.
                    if deviceViewModel.state == .forgotten { onForgotten() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You'll need your master password to unlock this vault on this Mac. "
                 + "Other devices are unaffected.")
        }
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
            // "Each" not "Both": this fires when EITHER field is unparseable, and
            // "Both fields need…" reads as a diagnosis that both are wrong, sending
            // the user hunting at the valid one. Phrased as a requirement instead.
            // Naming the offending field would be nicer still, but that is extra
            // branching on a path with no automated coverage — deliberately not done.
            inputError = "Each field needs a whole number — settings were not saved."
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
