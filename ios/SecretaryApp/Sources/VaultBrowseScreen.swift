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

    /// This device's slot port, injected from `RootView` (which holds the
    /// `ScopedVaultPath`; this view has no vault path). Typed as the pure
    /// `DeviceSlotPort` so this file stays free of coordinator/enclave imports.
    private let deviceSlotPort: DeviceSlotPort
    /// Locks the session (RootView flips `route = .select`). iOS has no manual-lock
    /// affordance; this exists for the "Forget This Device" path.
    private let onLock: () -> Void

    /// Bridges a freshly-built SettingsViewModel + DeviceSlotViewModel to the pushed
    /// Settings screen. Built at tap (not per render) so `DeviceSlotViewModel.init`'s
    /// `isEnrolled` snapshot — a Keychain read + enclave probe — runs once, not on
    /// every toolbar re-render.
    private struct SettingsRoute: Identifiable, Hashable {
        let id = UUID()
        let settingsVM: SettingsViewModel
        let deviceVM: DeviceSlotViewModel

        // `navigationDestination(item:)` requires Hashable; the payload is view-model
        // reference types, so hash/compare by the per-instance `id` (each route is
        // built fresh at tap with a unique UUID, so identity equality is exact).
        static func == (lhs: SettingsRoute, rhs: SettingsRoute) -> Bool { lhs.id == rhs.id }
        func hash(into hasher: inout Hasher) { hasher.combine(id) }
    }
    @State private var settingsRoute: SettingsRoute?

    init(viewModel: VaultBrowseViewModel, syncModel: VaultSyncViewModel,
         deviceSlotPort: DeviceSlotPort, onLock: @escaping () -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.syncModel = syncModel
        self.deviceSlotPort = deviceSlotPort
        self.onLock = onLock
    }

    /// Extracted from `body` into its own `@ToolbarContentBuilder` so the main view
    /// body stays under the Swift type-checker's complexity limit ("unable to
    /// type-check this expression in reasonable time"). Behaviourally identical to
    /// an inline `.toolbar { … }`.
    @ToolbarContentBuilder
    private var browseToolbar: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            SyncBadgeView(state: syncModel.badge,
                          nowMs: UInt64(Date().timeIntervalSince1970 * 1_000),
                          onTap: { syncModel.beginInteractiveSync() })
        }
        // Manual lock: wipe the session, release the scope, and return to the vault
        // selection screen — the same `onLock` RootView threads for the "Forget This
        // Device" path (iOS otherwise only locks on scenePhase background). Leading
        // placement keeps this security control always visible rather than letting a
        // crowded trailing cluster collapse it into an overflow menu. Mirrors the
        // macOS `MacBrowseView` Lock toolbar button.
        ToolbarItem(placement: .topBarLeading) {
            Button {
                onLock()
            } label: {
                Label("Lock", systemImage: "lock.fill")
            }
            .accessibilityIdentifier("lock-vault")
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
        ToolbarItem(placement: .primaryAction) {
            if let trashVM = viewModel.makeTrashViewModel() {
                NavigationLink {
                    TrashScreen(viewModel: trashVM)
                } label: {
                    Label("Trash", systemImage: "trash")
                }
                .disabled(viewModel.isWriting)
                .accessibilityIdentifier("open-trash")
            }
        }
        ToolbarItem(placement: .primaryAction) {
            Button {
                // Build both VMs at tap, not per render: SettingsViewModel.init
                // calls the FFI settingsBounds(), and DeviceSlotViewModel.init
                // snapshots port.isEnrolled (a Keychain read + enclave probe).
                // The `guard` handles the production-impossible nil settings
                // port rather than hiding the control.
                guard let settingsVM = viewModel.makeSettingsViewModel() else { return }
                settingsRoute = SettingsRoute(
                    settingsVM: settingsVM,
                    deviceVM: viewModel.makeDeviceSlotViewModel(port: deviceSlotPort))
            } label: {
                Label("Settings", systemImage: "gear")
            }
            .disabled(viewModel.isWriting)
            .accessibilityIdentifier("open-settings")
        }
    }

    /// Extracted from `body` for the same type-checker-complexity reason as
    /// `browseToolbar`: the `List` content (nested `ForEach` + `recordView`) plus the
    /// long modifier chain on the `List` (sheets, dialogs, navigationDestination)
    /// together exceed the Swift inference budget. Behaviourally identical to inline.
    @ViewBuilder
    private var listContent: some View {
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
                Text(error.localizedDescription).font(.footnote).foregroundStyle(.red)
            }
        }
    }

    var body: some View {
        NavigationStack {
            List { listContent }
            .navigationTitle("Browse")
            .toolbar { browseToolbar }
            .onAppear { viewModel.loadBlocks() }
            .navigationDestination(item: $settingsRoute) { route in
                // On `.forgotten`, SettingsScreen calls onForgotten → RootView sets
                // route = .select, unmounting this whole NavigationStack (and this
                // pushed screen). That IS the iOS "dismiss then lock" — no explicit
                // pop, which would double-animate against the route change. Trash
                // stays a NavigationLink; only Settings needs build-at-tap because
                // only it carries the enrollment-probe VM. `settingsRoute` is
                // view-local @State; it needs no teardown on lock — the route change
                // unmounts this view and destroys its state.
                SettingsScreen(viewModel: route.settingsVM,
                               deviceViewModel: route.deviceVM,
                               onForgotten: onLock)
            }
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
                        Task { await viewModel.delete(record: record) }
                        recordPendingDelete = nil
                    }
                    .disabled(viewModel.isWriting)
                }
                Button("Cancel", role: .cancel) { recordPendingDelete = nil }
            }
            .sheet(isPresented: Binding(
                get: { viewModel.blockNameDialog != nil },
                set: { if !$0 { viewModel.cancelBlockNameDialog() } }
            )) {
                BlockNameSheet(viewModel: viewModel, name: $blockNameField, title: blockNameSheetTitle)
            }
            .sheet(item: $movingItem, onDismiss: { viewModel.cancelMove() }) { item in
                MoveTargetPickerSheet(viewModel: viewModel, record: item.record, sourceBlockUuid: item.sourceBlockUuid)
            }
            .onChange(of: viewModel.movingRecord?.uuidHex) { _, _ in
                // Bridge the VM's movingRecord → the Identifiable sheet item.
                // Both the record AND the source block uuid must be known at
                // creation time; if either is missing we clear the item instead
                // of presenting a broken sheet.
                if let rec = viewModel.movingRecord, let src = selectedBlock?.uuid {
                    movingItem = MovingRecordItem(record: rec, sourceBlockUuid: src)
                } else {
                    movingItem = nil
                }
            }
        }
    }

    private var blockNameSheetTitle: String {
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
                    Task { await viewModel.restore(record: record) }
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
                // #429: hide Move when the vault has no other block to move into
                // (parity with desktop #273). Gated on the host-tested VM property.
                if viewModel.hasMoveTargets {
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
