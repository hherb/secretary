import SwiftUI
import AppKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Three-column browse (macOS): blocks sidebar | records list | field detail.
/// Reveal is explicit and short-lived — dropped on hide, on resign-active, and on
/// Lock. Mutation (D.5.3) is driven through the shared, host-tested
/// `VaultBrowseViewModel` / `RecordEditViewModel` via native macOS idioms:
/// right-click context menus for per-row actions + the window toolbar for create
/// actions. No mutation logic lives here — the views only present the VM's surface.
@MainActor
struct MacBrowseView: View {
    @StateObject private var viewModel: VaultBrowseViewModel
    let onLock: () -> Void

    @State private var selectedBlockHex: String?
    @State private var selectedRecordHex: String?
    @State private var isActive = true
    /// Identity of the `NSWindow` hosting this view, resolved once it is shown.
    /// The `willClose` handler compares against it so only THIS window's close
    /// wipes the session — never an unrelated panel (e.g. the standard About
    /// window). Stored as an `ObjectIdentifier` rather than the window itself to
    /// avoid holding a strong reference to it.
    @State private var browseWindowID: ObjectIdentifier?

    /// Thin Identifiable wrapper so `.sheet(item:)` drives the add/edit sheet.
    private struct EditSession: Identifiable {
        let id = UUID()
        let editVM: RecordEditViewModel
        let title: String
    }
    @State private var editSession: EditSession?
    /// Record awaiting delete confirmation (drives the `.confirmationDialog`). nil = none.
    @State private var recordPendingDelete: RecordView?
    /// Bridges the VM's `movingRecord` to the `.sheet(item:)` move picker. nil = closed.
    @State private var movingItem: MovingRecordItem?
    /// Editable block-name text shared by the create/rename sheet (`blockNameDialog`).
    @State private var blockNameField = ""

    init(viewModel: VaultBrowseViewModel, onLock: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onLock = onLock
    }

    private var selectedRecord: RecordView? {
        viewModel.visibleRecords.first { $0.uuidHex == selectedRecordHex }
    }

    /// Title for the shared create/rename block sheet, keyed on the active dialog.
    private var blockNameSheetTitle: String {
        switch viewModel.blockNameDialog {
        case .rename: return "Rename block"
        case .create, .none: return "New block"
        }
    }

    var body: some View {
        NavigationSplitView {
            List(viewModel.blocks, id: \.uuidHex, selection: $selectedBlockHex) { block in
                Text(block.name)
                    .tag(block.uuidHex)
                    .contextMenu {
                        Button {
                            blockNameField = block.name
                            viewModel.startRenameBlock(block)
                        } label: {
                            Label("Rename…", systemImage: "pencil")
                        }
                        .disabled(viewModel.isWriting)
                    }
            }
            .navigationTitle("Blocks")
        } content: {
            if viewModel.records != nil {
                List(viewModel.visibleRecords, id: \.uuidHex, selection: $selectedRecordHex) { record in
                    VStack(alignment: .leading) {
                        HStack {
                            Text(record.type.isEmpty ? "(untyped)" : record.type)
                            if record.tombstone {
                                Text("deleted")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(.quaternary, in: Capsule())
                            }
                        }
                        if !record.tags.isEmpty {
                            Text(record.tags.joined(separator: ", "))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .tag(record.uuidHex)
                    .contextMenu {
                        if record.tombstone {
                            Button {
                                Task { await viewModel.restore(record: record) }
                            } label: {
                                Label("Restore", systemImage: "arrow.uturn.backward")
                            }
                            .disabled(viewModel.isWriting)
                        } else {
                            Button {
                                guard let vm = viewModel.makeEditViewModel(
                                    mode: .edit(recordUuid: record.uuid)) else { return }
                                vm.load(record: record)
                                editSession = EditSession(editVM: vm, title: "Edit Record")
                            } label: {
                                Label("Edit", systemImage: "pencil")
                            }
                            .disabled(viewModel.isWriting)
                            // Hidden when the vault has no other block to move into
                            // (parity with iOS #429 / desktop #273). Gated on the
                            // host-tested VM property.
                            if viewModel.hasMoveTargets {
                                Button {
                                    viewModel.startMoveRecord(record)
                                } label: {
                                    Label("Move…", systemImage: "folder")
                                }
                                .disabled(viewModel.isWriting)
                            }
                            Button(role: .destructive) {
                                recordPendingDelete = record
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                            .disabled(viewModel.isWriting)
                        }
                    }
                }
                .navigationTitle("Records")
            } else {
                Text("Select a block").foregroundStyle(.secondary)
            }
        } detail: {
            if let record = selectedRecord {
                fieldList(record)
            } else {
                Text("Select a record").foregroundStyle(.secondary)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                // Only meaningful once a block's records are loaded. Toggling re-reads
                // the block through the VM (the Rust gate withholds tombstoned records
                // unless this is on — the client never filters withheld data).
                if viewModel.records != nil {
                    Toggle("Show deleted", isOn: $viewModel.showDeleted)
                        .toggleStyle(.checkbox)
                }
            }
            ToolbarItem(placement: .primaryAction) {
                // "Add record" is only meaningful once a block is selected (the VM
                // appends into the selected block); hidden otherwise.
                if selectedBlockHex != nil {
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
            }
            ToolbarItem(placement: .primaryAction) {
                // `Button(_:systemImage:action:)` is macOS 14+; the app's
                // deploymentTarget is macOS 13.0, so use the trailing-closure
                // label form instead (same floor as the onChange note below).
                Button {
                    onLock()
                } label: {
                    Label("Lock", systemImage: "lock.fill")
                }
            }
        }
        .overlay(alignment: .bottom) {
            if let error = viewModel.error {
                Text(error.localizedDescription).foregroundStyle(.red).padding(8)
            }
        }
        .onAppear { viewModel.loadBlocks() }
        .sheet(item: $editSession) { session in
            MacRecordEditView(
                viewModel: session.editVM,
                title: session.title,
                onDone: {
                    editSession = nil
                    // Re-read via the VM's own selection (not a screen-cached block).
                    viewModel.refresh()
                },
                onCancel: { editSession = nil }
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
                    Task { await viewModel.delete(record: record) }
                    recordPendingDelete = nil
                }
                .disabled(viewModel.isWriting)
            }
            Button("Cancel", role: .cancel) { recordPendingDelete = nil }
        }
        .sheet(item: $movingItem, onDismiss: { viewModel.cancelMove() }) { item in
            MacMoveTargetPicker(
                viewModel: viewModel,
                record: item.record,
                sourceBlockUuid: item.sourceBlockUuid,
                onCancel: { viewModel.cancelMove() }
            )
        }
        // Bridge the VM's movingRecord → the Identifiable sheet item. Both the
        // record AND the source-block uuid must be known at creation time; if
        // either is missing, clear the item instead of presenting a broken sheet.
        // `confirmMove` clears movingRecord on success, which flips movingItem back
        // to nil here, dismissing the sheet.
        .onChange(of: viewModel.movingRecord?.uuidHex) { _ in
            if let rec = viewModel.movingRecord,
               let src = viewModel.blocks.first(where: { $0.uuidHex == selectedBlockHex })?.uuid {
                movingItem = MovingRecordItem(record: rec, sourceBlockUuid: src)
            } else {
                movingItem = nil
            }
        }
        .sheet(isPresented: Binding(
            get: { viewModel.blockNameDialog != nil },
            set: { if !$0 { viewModel.cancelBlockNameDialog() } }
        )) {
            MacBlockNameSheet(viewModel: viewModel, name: $blockNameField, title: blockNameSheetTitle)
        }
        // Capture the hosting window's identity (once it is non-nil) so the
        // willClose handler can scope its wipe to this exact window. Closure form
        // of `.background` (macOS 12+) to avoid the deprecated positional overload.
        .background {
            WindowAccessor { window in
                if let window { browseWindowID = ObjectIdentifier(window) }
            }
        }
        // Single-param overload (macOS 11+): the app's deploymentTarget is
        // macOS 13.0, below the macOS 14.0 floor for the two-param
        // `onChange(of:initial:_:)` used elsewhere on iOS 17+ (see MacUnlockView).
        .onChange(of: selectedBlockHex) { hex in
            selectedRecordHex = nil
            if let block = viewModel.blocks.first(where: { $0.uuidHex == hex }) {
                viewModel.selectBlock(block)
            }
        }
        // macOS analogue of the iOS scenePhase privacy behavior: drop revealed
        // plaintext when the app loses focus, and redact revealed values while
        // inactive. Does not wipe the session (that is Lock / window-close).
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            isActive = false
            viewModel.hideAll()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            isActive = true
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)) { note in
            // Wipe the session + release the scope when THIS browse window closes
            // (or the app quits — AppKit posts willClose for each window during
            // termination too) — deterministic zeroize rather than waiting on ARC.
            // Filtering on window identity stops an unrelated panel (e.g. the
            // standard About window) closing from wiping a live session. Routed
            // through `onLock` so the scope is ended too, not just the session
            // wiped. Design §7 "wipe on window close".
            guard let closing = note.object as? NSWindow,
                  ObjectIdentifier(closing) == browseWindowID else { return }
            onLock()
        }
    }

    @ViewBuilder
    private func fieldList(_ record: RecordView) -> some View {
        List {
            Section("uuid=\(record.uuidHex)") {
                ForEach(record.fields, id: \.name) { field in
                    fieldRow(record: record, field: field)
                }
            }
        }
        .navigationTitle(record.type.isEmpty ? "Record" : record.type)
    }

    @ViewBuilder
    private func fieldRow(record: RecordView, field: FieldView) -> some View {
        let revealed = viewModel.revealedValue(recordUuidHex: record.uuidHex, fieldName: field.name)
        HStack {
            Text(field.name)
            Spacer()
            if let revealed {
                Text(display(revealed))
                    .textSelection(.enabled)
                    // Defensive / currently unreachable: `hideAll()` runs in the same
                    // didResignActive handler above, so no revealed value survives into
                    // an inactive render today. Kept as belt-and-suspenders against a
                    // future handler reorder.
                    .redacted(reason: isActive ? [] : .privacy)
                Button("Copy") { copyToPasteboard(revealed) }
                Button("Hide") { viewModel.hide(recordUuidHex: record.uuidHex, fieldName: field.name) }
                    // Auto-hide after the shared reveal window.
                    .task(id: "\(record.uuidHex)/\(field.name)") {
                        try? await Task.sleep(for: .seconds(RevealPolicy.autoHideSeconds))
                        guard !Task.isCancelled else { return }
                        viewModel.hide(recordUuidHex: record.uuidHex, fieldName: field.name)
                    }
            } else {
                Text("••••••").foregroundStyle(.secondary)
                Button("Reveal") { viewModel.reveal(record: record, field: field) }
            }
        }
    }

    private func display(_ value: RevealedValue) -> String {
        switch value {
        case .text(let s): return s
        case .bytes(let b): return b.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// Copy revealed plaintext to the pasteboard, hinting clipboard managers not to
    /// persist it (macOS `org.nspasteboard.ConcealedType` convention), and clear it
    /// after the reveal window unless a newer copy has since replaced it.
    private func copyToPasteboard(_ value: RevealedValue) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.declareTypes([.string, NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")], owner: nil)
        pb.setString(display(value), forType: .string)
        let generation = pb.changeCount
        // RevealPolicy.autoHideSeconds is already a TimeInterval (Double); no
        // numeric cast needed before adding it to a DispatchTime deadline.
        DispatchQueue.main.asyncAfter(deadline: .now() + RevealPolicy.autoHideSeconds) {
            if NSPasteboard.general.changeCount == generation { NSPasteboard.general.clearContents() }
        }
    }
}

/// Resolves the `NSWindow` hosting a SwiftUI view. Used so the browse view can
/// scope its `willClose` session-wipe to its own window (see `browseWindowID`),
/// rather than reacting to every window's close. `viewDidMoveToWindow` is the
/// canonical hook: it fires with a non-nil `window` once the view is attached.
private struct WindowAccessor: NSViewRepresentable {
    let onResolve: (NSWindow?) -> Void

    func makeNSView(context: Context) -> NSView { ResolvingView(onResolve: onResolve) }
    func updateNSView(_ nsView: NSView, context: Context) {}

    private final class ResolvingView: NSView {
        private let onResolve: (NSWindow?) -> Void
        init(onResolve: @escaping (NSWindow?) -> Void) {
            self.onResolve = onResolve
            super.init(frame: .zero)
        }
        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            onResolve(window)
        }
    }
}
