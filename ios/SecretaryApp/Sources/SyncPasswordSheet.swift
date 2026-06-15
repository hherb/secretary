// SyncPasswordSheet.swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Centered password re-prompt for an interactive sync. The password lives only
/// in this view's `@State` and is reused for `resolve` via the conflict sheet
/// when the pass surfaces a conflict; it is replaced with "" on every dismissal.
struct SyncPasswordSheet: View {
    @ObservedObject var model: VaultSyncViewModel
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Master password") {
                    SecureField("password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                if let err = model.lastError {
                    Section("Error") {
                        Text(String(describing: err))
                            .font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Sync now")
            .overlay { if model.isSyncing { ProgressView() } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        password = ""
                        model.dismissPasswordSheet()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Sync") {
                        let pw = Array(password.utf8)
                        password = ""              // drop the view copy ASAP
                        Task { await model.runInteractivePass(password: pw) }
                    }
                    .disabled(model.isSyncing || password.isEmpty)
                }
            }
        }
    }
}
