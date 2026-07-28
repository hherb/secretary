import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Per-vault settings sheet (macOS): retention window (days) + re-auth grace
/// (minutes). Mirrors iOS `SettingsScreen` over the shared, host-tested
/// `SettingsViewModel`; the load-bearing gate-then-retarget save ordering lives
/// entirely in the VM (the view only binds controls and calls `save()`). macOS
/// diffs from the iOS screen: grouped `Form`, no `.keyboardType` (iOS-only), an
/// explicit Done button in a bottom bar (iOS pushes onto a NavigationStack) —
/// matching the D.5.3 sheet idiom (`MacRecordEditView`). Both screens now share
/// the text-buffered numeric inputs (see `SettingsEditBuffer`).
@MainActor
struct MacSettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    @StateObject private var deviceViewModel: DeviceSlotViewModel
    let onDone: () -> Void
    /// Called after a successful "Forget This Mac". The parent dismisses this sheet
    /// and then locks: clearing the enclave key makes the write-reauth gate a
    /// permanent no-op for the rest of the session, so the session must not continue.
    let onForgotten: () -> Void

    /// Live text for the two numeric inputs, seeded from the VM after `load()` and
    /// pushed back into it by `commitSettingsEdits` at Save. See `SettingsEditBuffer`
    /// for why these are buffered rather than bound with `TextField(value:format:)`.
    @State private var edits = SettingsEditBuffer()
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
                        // Same identifier as the iOS screen's input error, so the
                        // #417 render assertions can be written once for both.
                        .accessibilityIdentifier("settings-input-error")
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
                            TextField("Days", text: $edits.retentionText)
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
                            TextField("Minutes", text: $edits.graceText)
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
                    // Lock whenever this device's credential is gone — which is
                    // exactly what `.forgotten` means, NOT "the revocation
                    // succeeded". `forget()` is non-throwing and reaches
                    // `.forgotten` on full success AND on a partial failure that
                    // already tore down the enclave key, because in that second
                    // case the write-reauth gate is already a permanent no-op and
                    // continuing the session would leave every later write
                    // silently ungated. A cancelled Touch ID prompt (no teardown)
                    // and a failed slot removal (credential intact) both stay
                    // `.idle`, leaving the session untouched with the error
                    // rendered in the section above.
                    //
                    // Do NOT "simplify" this to lock only on a fully successful
                    // revocation — that reinstates the ungated-session bug.
                    // Pinned by testPartialFailureThatTearsDownCredentialStillLocks
                    // and testPortFailureDoesNotReachForgotten, which bracket it.
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
            edits.seed(retentionDays: viewModel.retentionDays, graceMinutes: viewModel.graceMinutes)
            // The fields have just been re-seeded from disk, so a refusal left over
            // from an earlier Save no longer describes anything on screen. Cleared
            // unconditionally rather than relying on this view's `@State` being
            // fresh on every appearance.
            inputError = nil
        }
    }

    /// Commit the typed text into the VM, then save. On unparseable input nothing is
    /// written — surfacing that beats persisting a value the user never typed.
    /// `commitSettingsEdits` re-seeds the fields to the clamped values on success, so
    /// the display and the value being written stay identical.
    private func save() {
        inputError = nil
        guard commitSettingsEdits(&edits, into: viewModel) else {
            inputError = settingsInputErrorMessage()
            return
        }
        Task { await viewModel.save() }
    }
}
