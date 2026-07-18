import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Per-vault settings sheet (macOS): retention window (days) + re-auth grace
/// (minutes). Mirrors iOS `SettingsScreen` over the shared, host-tested
/// `SettingsViewModel`; the load-bearing gate-then-retarget save ordering lives
/// entirely in the VM (the view only binds controls and calls `save()`). macOS
/// diffs from the iOS screen: grouped `Form`, no `.keyboardType` (iOS-only), and an
/// explicit Done button in a bottom bar (iOS pushes onto a NavigationStack) —
/// matching the D.5.3 sheet idiom (`MacRecordEditView`).
@MainActor
struct MacSettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    let onDone: () -> Void

    init(viewModel: SettingsViewModel, onDone: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onDone = onDone
    }

    private var retentionBinding: Binding<Int> {
        Binding(get: { viewModel.retentionDays }, set: { viewModel.setRetentionDays($0) })
    }
    private var graceBinding: Binding<Int> {
        Binding(get: { viewModel.graceMinutes }, set: { viewModel.setGraceMinutes($0) })
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if let banner = viewModel.banner {
                    Text(banner.text).font(.footnote).foregroundStyle(.secondary)
                }
                if let error = viewModel.error {
                    Text(settingsErrorMessage(error)).font(.footnote).foregroundStyle(.red)
                }
                Section {
                    LabeledContent("Delete trash after") {
                        HStack(spacing: 4) {
                            TextField("Days", value: retentionBinding, format: .number)
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
                            TextField("Minutes", value: graceBinding, format: .number)
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
                Button("Save") { Task { await viewModel.save() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(viewModel.isWriting)
            }
            .padding()
        }
        .frame(minWidth: 460, minHeight: 420)
        .navigationTitle("Settings")
        .onAppear { viewModel.load() }
    }
}
