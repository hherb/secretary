import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Read-only browse: block list → record list → tap-to-reveal field. Redacts
/// revealed values when the app is not active; the parent (RootView) locks the
/// session on background.
struct VaultBrowseScreen: View {
    @StateObject private var viewModel: VaultBrowseViewModel
    @Environment(\.scenePhase) private var scenePhase

    // MARK: - add / edit sheet state

    /// Thin Identifiable wrapper so `.sheet(item:)` drives presentation.
    private struct EditSession: Identifiable {
        let id = UUID()
        let editVM: RecordEditViewModel
        let title: String
    }

    @State private var editSession: EditSession?

    // The currently-selected BlockSummary, kept so `onDone` can re-select it
    // to refresh the list after an add or edit.
    @State private var selectedBlock: BlockSummary?

    // Delete-confirmation state
    @State private var recordPendingDelete: RecordView?

    init(viewModel: VaultBrowseViewModel) {
        self._viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Vault") {
                    Text("uuid=\(viewModel.vaultUuidHex)").font(.footnote.monospaced())
                }
                Section("Blocks") {
                    ForEach(viewModel.blocks, id: \.uuidHex) { block in
                        Button(block.name) {
                            selectedBlock = block
                            viewModel.selectBlock(block)
                        }
                    }
                }
                if viewModel.records != nil {
                    Section {
                        Toggle("Show deleted", isOn: $viewModel.showDeleted)
                    } header: {
                        Text("Records")
                    }
                    Section {
                        ForEach(viewModel.visibleRecords, id: \.uuidHex) { record in
                            recordView(record)
                        }
                    }
                }
                if let error = viewModel.error {
                    Section("Error") {
                        Text(String(describing: error)).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Browse")
            .toolbar {
                if selectedBlock != nil {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            guard let vm = viewModel.makeEditViewModel(mode: .add) else { return }
                            editSession = EditSession(editVM: vm, title: "Add Record")
                        } label: {
                            Label("Add record", systemImage: "plus")
                        }
                    }
                }
            }
            .onAppear { viewModel.loadBlocks() }
            // Drop any revealed plaintext the moment we leave the foreground.
            .onChange(of: scenePhase) { _, phase in
                if phase != .active { viewModel.hideAll() }
            }
            .sheet(item: $editSession) { session in
                RecordEditScreen(
                    viewModel: session.editVM,
                    title: session.title,
                    onDone: {
                        editSession = nil
                        // Re-select the block to refresh visibleRecords.
                        if let block = selectedBlock {
                            viewModel.selectBlock(block)
                        }
                    }
                )
            }
            .confirmationDialog(
                "Delete record?",
                isPresented: Binding(
                    get: { recordPendingDelete != nil },
                    set: { if !$0 { recordPendingDelete = nil } }
                ),
                titleVisibility: .visible
            ) {
                if let record = recordPendingDelete {
                    Button("Delete", role: .destructive) {
                        viewModel.delete(record: record)
                        recordPendingDelete = nil
                    }
                }
                Button("Cancel", role: .cancel) { recordPendingDelete = nil }
            }
        }
    }

    // MARK: - record row

    @ViewBuilder
    private func recordView(_ record: RecordView) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(record.type.isEmpty ? "record" : record.type)
                    .font(.headline)
                if record.tombstone {
                    Text("deleted")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                }
            }
            ForEach(record.fields, id: \.name) { field in
                fieldRow(record: record, field: field)
            }
        }
        // Live records: swipe-to-delete + edit context menu.
        // Deleted records (shown when showDeleted is on): restore only.
        .swipeActions(edge: .trailing) {
            if record.tombstone {
                Button {
                    viewModel.restore(record: record)
                } label: {
                    Label("Restore", systemImage: "arrow.uturn.backward")
                }
                .tint(.blue)
            } else {
                Button(role: .destructive) {
                    recordPendingDelete = record
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
        .swipeActions(edge: .leading) {
            if !record.tombstone {
                Button {
                    guard let vm = viewModel.makeEditViewModel(
                        mode: .edit(recordUuid: record.uuid)) else { return }
                    try? vm.loadForEdit(record: record)
                    editSession = EditSession(editVM: vm, title: "Edit Record")
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .tint(.orange)
            }
        }
    }

    // MARK: - field row

    @ViewBuilder
    private func fieldRow(record: RecordView, field: FieldView) -> some View {
        let revealed = viewModel.revealedValue(recordUuidHex: record.uuidHex, fieldName: field.name)
        HStack {
            Text(field.name).font(.subheadline)
            Spacer()
            if let revealed {
                Text(display(revealed))
                    .font(.subheadline.monospaced())
                    .redacted(reason: scenePhase == .active ? [] : .privacy)
                    // Auto-hide: a revealed secret must not linger on screen
                    // indefinitely. This task exists only while the field is
                    // revealed (the `if let` branch); tapping Hide, switching
                    // block, backgrounding, or locking removes the branch and
                    // cancels the sleep. Keyed on the reveal key so it is a single
                    // timer across redraws and restarts on a fresh reveal. The
                    // interval is the named `RevealPolicy.autoHideSeconds`; the
                    // drop goes through the unit-tested `hide` seam.
                    .task(id: "\(record.uuidHex)/\(field.name)") {
                        try? await Task.sleep(for: .seconds(RevealPolicy.autoHideSeconds))
                        guard !Task.isCancelled else { return }
                        viewModel.hide(recordUuidHex: record.uuidHex, fieldName: field.name)
                    }
                Button("Hide") { viewModel.hide(recordUuidHex: record.uuidHex, fieldName: field.name) }
            } else {
                Button("Reveal") { viewModel.reveal(record: record, field: field) }
            }
        }
    }

    private func display(_ value: RevealedValue) -> String {
        switch value {
        case .text(let s): return s
        case .bytes(let b): return "\(b.count) bytes"
        }
    }
}
