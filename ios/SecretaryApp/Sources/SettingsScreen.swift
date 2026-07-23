import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Per-vault settings: retention window (days) + re-auth grace (minutes), plus a
/// "This Device" section that revokes this device's biometric wrap slot. Save is
/// gated by the shared re-auth gate (a settings change is a vault write) and, on
/// success, retargets the live gate to the new grace window. Mirrors the macOS
/// `MacSettingsView`. Render is host-untested (#417); the `accessibilityIdentifier`
/// hooks back a future instrumented assertion.
struct SettingsScreen: View {
    @StateObject private var viewModel: SettingsViewModel
    @StateObject private var deviceViewModel: DeviceSlotViewModel
    /// Called after a successful "Forget This Device". The parent dismisses this
    /// screen and locks: clearing the enclave key makes the write-reauth gate a
    /// permanent no-op for the rest of the session, so it must not continue.
    let onForgotten: () -> Void

    /// Drives the "Forget This Device" confirmation dialog.
    @State private var confirmForget = false

    init(viewModel: SettingsViewModel,
         deviceViewModel: DeviceSlotViewModel,
         onForgotten: @escaping () -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self._deviceViewModel = StateObject(wrappedValue: deviceViewModel)
        self.onForgotten = onForgotten
    }

    private var retentionBinding: Binding<Int> {
        Binding(get: { viewModel.retentionDays }, set: { viewModel.setRetentionDays($0) })
    }
    private var graceBinding: Binding<Int> {
        Binding(get: { viewModel.graceMinutes }, set: { viewModel.setGraceMinutes($0) })
    }

    var body: some View {
        Form {
            if let banner = viewModel.banner {
                Text(banner.text)
                    .font(.footnote).foregroundStyle(Color.secondary)
                    .accessibilityIdentifier("settings-notice")
            }
            if let error = viewModel.error {
                Text(settingsErrorMessage(error))
                    .font(.footnote).foregroundStyle(Color.red)
                    .accessibilityIdentifier("settings-error")
            }

            Section {
                LabeledContent("Delete trash after") {
                    HStack(spacing: 4) {
                        TextField("Days", value: retentionBinding, format: .number)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: 80)
                            .accessibilityIdentifier("settings-retention-days")
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
                        TextField("Minutes", value: graceBinding, format: .number)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: 80)
                            .accessibilityIdentifier("settings-grace-minutes")
                        Text("min").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Security")
            } footer: {
                Text("After a Face ID / passcode check, writes within this window don't re-prompt "
                     + "(\(viewModel.graceMinutesRange.lowerBound)–\(viewModel.graceMinutesRange.upperBound) min; "
                     + "0 re-authenticates every write).")
            }

            // Grouped with "Security" (both are this-device security concerns) and
            // placed above Save, which commits only the two numeric fields. Hidden
            // entirely when this device is not enrolled: nothing to forget, and a
            // permanently-disabled destructive control is noise. `isEnrolled` is a
            // snapshot from the VM's init, so consulting it per render is free.
            if deviceViewModel.isEnrolled {
                Section {
                    Button(role: .destructive) {
                        confirmForget = true
                    } label: {
                        Text("Forget This Device")
                    }
                    .disabled(deviceViewModel.isBusy || viewModel.isWriting)
                    .accessibilityIdentifier("settings-forget-device")
                    // Scoped to this section (not the shared banner/error area at
                    // top): a revocation failure is a different action than a
                    // settings save.
                    if let deviceError = deviceViewModel.error {
                        Text(deviceSlotErrorMessage(deviceError))
                            .font(.footnote).foregroundStyle(.red)
                            .accessibilityIdentifier("settings-forget-error")
                    }
                } header: {
                    Text("This Device")
                } footer: {
                    Text("Removes Face ID unlock for this vault on this device. "
                         + "You'll need your master password to unlock, and can turn "
                         + "Face ID back on then. Other devices are unaffected.")
                }
            }

            Section {
                Button {
                    Task { await viewModel.save() }
                } label: {
                    Text("Save")
                }
                // Symmetric with the Forget button: both writers share this screen,
                // so a settings save must not fire while a revocation is in flight.
                .disabled(viewModel.isWriting || deviceViewModel.isBusy)
                .accessibilityIdentifier("settings-save")
            }
        }
        .navigationTitle("Settings")
        .confirmationDialog("Forget this device?",
                            isPresented: $confirmForget,
                            titleVisibility: .visible) {
            Button("Forget This Device", role: .destructive) {
                Task {
                    await deviceViewModel.forget()
                    // Lock whenever this device's credential is gone — which is
                    // exactly what `.forgotten` means, NOT "the revocation
                    // succeeded". `forget()` reaches `.forgotten` on full success
                    // AND on a partial failure that already tore down the enclave
                    // key (leaving the write-reauth gate a permanent no-op);
                    // continuing then would silently ungate every later write. A
                    // cancelled Face ID prompt (no teardown) and a failed slot
                    // removal (credential intact) both stay `.idle`, leaving the
                    // session untouched with the error rendered in the section above.
                    //
                    // Do NOT "simplify" this to lock only on a fully successful
                    // revocation — that reinstates the ungated-session bug. Pinned
                    // cross-platform by testPartialFailureThatTearsDownCredentialStillLocks
                    // and testPortFailureDoesNotReachForgotten in DeviceSlotViewModelTests.
                    if deviceViewModel.state == .forgotten { onForgotten() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You'll need your master password to unlock this vault on this device. "
                 + "Other devices are unaffected.")
        }
        .onAppear { viewModel.load() }
    }
}
