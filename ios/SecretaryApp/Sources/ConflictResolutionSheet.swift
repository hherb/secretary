// ConflictResolutionSheet.swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Metadata-only conflict resolution. One row per veto with Keep-mine (default) /
/// Accept-delete; a read-only disclosure lists auto-merged collisions. Apply
/// re-prompts for the password (short-lived) and commits the decisions.
struct ConflictResolutionSheet: View {
    @ObservedObject var model: VaultSyncViewModel
    let conflict: PendingConflict

    /// Per-record choice; true = keep local (default, no data loss).
    @State private var keepLocal: [String: Bool] = [:]
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("These records were deleted on another device but you still have them. Choose what to keep — nothing is written until you tap Apply.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(conflict.vetoes, id: \.recordUuidHex) { veto in
                    Section(summary(veto)) {
                        if !veto.fieldNames.isEmpty {
                            Text("fields: \(veto.fieldNames.joined(separator: " · "))")
                                .font(.footnote.monospaced())
                        }
                        Text("deleted on device \(veto.peerDeviceHex.prefix(8))…")
                            .font(.caption).foregroundStyle(.secondary)
                        Picker("Resolution", selection: choiceBinding(veto.recordUuidHex)) {
                            Text("Keep mine").tag(true)
                            Text("Accept delete").tag(false)
                        }
                        .pickerStyle(.segmented)
                    }
                }
                if !conflict.collisions.isEmpty {
                    Section {
                        DisclosureGroup("\(conflict.collisions.count) field group(s) auto-merged — no action needed") {
                            ForEach(conflict.collisions, id: \.recordUuidHex) { c in
                                Text("\(c.recordUuidHex.prefix(8))…: \(c.fieldNames.joined(separator: ", "))")
                                    .font(.caption.monospaced())
                            }
                        }
                    }
                }
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
            .navigationTitle("Resolve conflicts")
            .overlay { if model.isSyncing { ProgressView() } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { password = ""; model.cancelConflict() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Apply") {
                        let decisions = conflict.vetoes.map {
                            SyncVetoDecision(recordUuidHex: $0.recordUuidHex,
                                             keepLocal: keepLocal[$0.recordUuidHex] ?? true)
                        }
                        let pw = Array(password.utf8)
                        password = ""
                        Task { await model.resolve(decisions: decisions, password: pw) }
                    }
                    .disabled(model.isSyncing || password.isEmpty)
                }
            }
        }
    }

    private func choiceBinding(_ uuid: String) -> Binding<Bool> {
        Binding(get: { keepLocal[uuid] ?? true }, set: { keepLocal[uuid] = $0 })
    }

    private func summary(_ v: SyncVeto) -> String {
        v.tags.isEmpty ? v.recordType : "\(v.recordType) · \(v.tags.joined(separator: " · "))"
    }
}
