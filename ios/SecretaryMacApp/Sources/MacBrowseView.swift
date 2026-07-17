import SwiftUI
import AppKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Read-only three-column browse (macOS): blocks sidebar | records list | field
/// detail. Reveal is explicit and short-lived — dropped on hide, on resign-active,
/// and on Lock. No mutation controls (read-only slice).
@MainActor
struct MacBrowseView: View {
    @StateObject private var viewModel: VaultBrowseViewModel
    let onLock: () -> Void

    @State private var selectedBlockHex: String?
    @State private var selectedRecordHex: String?
    @State private var isActive = true

    init(viewModel: VaultBrowseViewModel, onLock: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onLock = onLock
    }

    private var selectedRecord: RecordView? {
        viewModel.visibleRecords.first { $0.uuidHex == selectedRecordHex }
    }

    var body: some View {
        NavigationSplitView {
            List(viewModel.blocks, id: \.uuidHex, selection: $selectedBlockHex) { block in
                Text(block.name).tag(block.uuidHex)
            }
            .navigationTitle("Blocks")
        } content: {
            if viewModel.records != nil {
                List(viewModel.visibleRecords, id: \.uuidHex, selection: $selectedRecordHex) { record in
                    VStack(alignment: .leading) {
                        Text(record.type.isEmpty ? "(untyped)" : record.type)
                        if !record.tags.isEmpty {
                            Text(record.tags.joined(separator: ", "))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }.tag(record.uuidHex)
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
                Text(String(describing: error)).foregroundStyle(.red).padding(8)
            }
        }
        .onAppear { viewModel.loadBlocks() }
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
