import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Read-only browse: block list → record list → tap-to-reveal field. Redacts
/// revealed values when the app is not active; the parent (RootView) locks the
/// session on background.
struct VaultBrowseScreen: View {
    @StateObject private var viewModel: VaultBrowseViewModel
    @ObservedObject private var syncModel: VaultSyncViewModel
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

    // Block-name alert field (create/rename share the one prompt).
    @State private var blockNameField = ""
    // Identifiable wrapper bridging viewModel.movingRecord → .sheet(item:).
    @State private var movingItem: MovingRecordItem?

    init(viewModel: VaultBrowseViewModel, syncModel: VaultSyncViewModel) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.syncModel = syncModel
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
                        .swipeActions(edge: .trailing) {
                            Button {
                                blockNameField = block.name
                                viewModel.startRenameBlock(block)
                            } label: {
                                Label("Rename", systemImage: "pencil")
                            }
                            .tint(.orange)
                            .disabled(viewModel.isWriting)
                            .accessibilityIdentifier("rename-\(block.uuidHex)")
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
                ToolbarItem(placement: .topBarLeading) {
                    SyncBadgeView(state: syncModel.badge,
                                  nowMs: UInt64(Date().timeIntervalSince1970 * 1_000),
                                  onTap: { syncModel.beginInteractiveSync() })
                }
                if selectedBlock != nil {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            guard let vm = viewModel.makeEditViewModel(mode: .add) else { return }
                            editSession = EditSession(editVM: vm, title: "Add Record")
                        } label: {
                            Label("Add record", systemImage: "plus")
                        }
                        .disabled(viewModel.isWriting)
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        blockNameField = ""
                        viewModel.startCreateBlock()
                    } label: {
                        Label("New block", systemImage: "folder.badge.plus")
                    }
                    .disabled(viewModel.isWriting)
                    .accessibilityIdentifier("new-block")
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
                        // Refresh the record list using the VM's own selection,
                        // avoiding the screen's cached selectedBlock as a source of truth.
                        viewModel.refresh()
                    }
                )
            }
            .sheet(isPresented: $syncModel.passwordSheetPresented) {
                SyncPasswordSheet(model: syncModel)
            }
            .sheet(isPresented: $syncModel.conflictSheetPresented) {
                if let conflict = syncModel.pendingConflict {
                    ConflictResolutionSheet(model: syncModel, conflict: conflict)
                }
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
                    .disabled(viewModel.isWriting)
                }
                Button("Cancel", role: .cancel) { recordPendingDelete = nil }
            }
            .alert(
                blockNameAlertTitle,
                isPresented: Binding(
                    get: { viewModel.blockNameDialog != nil },
                    set: { if !$0 { viewModel.cancelBlockNameDialog() } }
                )
            ) {
                TextField("Block name", text: $blockNameField)
                    .accessibilityIdentifier("block-name-field")
                Button("Save") { viewModel.confirmBlockName(blockNameField) }
                    .accessibilityIdentifier("block-name-confirm")
                Button("Cancel", role: .cancel) { viewModel.cancelBlockNameDialog() }
                    .accessibilityIdentifier("block-name-cancel")
            }
            .sheet(item: $movingItem) { item in
                if let source = selectedBlock?.uuid {
                    MoveTargetPickerSheet(viewModel: viewModel, record: item.record, sourceBlockUuid: source)
                }
            }
            .onChange(of: viewModel.movingRecord?.uuidHex) { _, _ in
                // Bridge the VM's movingRecord → the Identifiable sheet item.
                movingItem = viewModel.movingRecord.map { MovingRecordItem(record: $0) }
            }
        }
    }

    private var blockNameAlertTitle: String {
        switch viewModel.blockNameDialog {
        case .rename: return "Rename block"
        case .create, .none: return "New block"
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
                .disabled(viewModel.isWriting)
            } else {
                Button(role: .destructive) {
                    recordPendingDelete = record
                } label: {
                    Label("Delete", systemImage: "trash")
                }
                .disabled(viewModel.isWriting)
            }
        }
        .swipeActions(edge: .leading) {
            if !record.tombstone {
                Button {
                    guard let vm = viewModel.makeEditViewModel(
                        mode: .edit(recordUuid: record.uuid)) else { return }
                    vm.load(record: record)
                    editSession = EditSession(editVM: vm, title: "Edit Record")
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .tint(.orange)
                Button {
                    viewModel.startMoveRecord(record)
                } label: {
                    Label("Move", systemImage: "folder")
                }
                .tint(.indigo)
                .disabled(viewModel.isWriting)
                .accessibilityIdentifier("move-\(record.uuidHex)")
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
