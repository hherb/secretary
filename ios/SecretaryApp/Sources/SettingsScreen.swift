import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Per-vault settings: retention window (days) + re-auth grace (minutes). Save is
/// gated by the shared re-auth gate (a settings change is a vault write) and, on
/// success, retargets the live gate to the new grace window. Mirrors the desktop
/// `SettingsDialog` controls (days / minutes). Render is host-untested (#417);
/// the `accessibilityIdentifier` hooks back a future instrumented assertion.
struct SettingsScreen: View {
    @StateObject private var viewModel: SettingsViewModel

    init(viewModel: SettingsViewModel) {
        self._viewModel = StateObject(wrappedValue: viewModel)
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

            Section {
                Button {
                    Task { await viewModel.save() }
                } label: {
                    Text("Save")
                }
                .disabled(viewModel.isWriting)
                .accessibilityIdentifier("settings-save")
            }
        }
        .navigationTitle("Settings")
        .onAppear { viewModel.load() }
    }
}

/// Short user-facing message for a settings-save failure. Re-auth cancellation is
/// the common case, but a non-cancel biometric failure maps to the same
/// `reauthFailed` case, so the copy stays neutral rather than asserting "cancelled".
/// The anti-oracle "…OrCorrupt" cases are folded upstream.
private func settingsErrorMessage(_ e: VaultAccessError) -> String {
    switch e {
    case .reauthFailed:
        return "Re-authentication didn’t complete — settings were not saved."
    case .invalidArgument:
        return "That value is out of range — settings were not saved."
    default:
        return "Couldn’t save settings. Please try again."
    }
}
