import SwiftUI
import AppKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// The third column of `MacBrowseView`'s split view: the selected record's field
/// list with per-field reveal / copy / hide. Extracted from `MacBrowseView` (D.5.4)
/// to keep that file within the size-discipline threshold; behaviour is unchanged.
/// Takes the shared `VaultBrowseViewModel` as `@ObservedObject` so a reveal/hide
/// re-renders the affected row (the state lives on the VM, owned by `MacBrowseView`).
@MainActor
struct MacFieldDetailView: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    let record: RecordView
    let isActive: Bool

    var body: some View {
        List {
            Section("uuid=\(record.uuidHex)") {
                ForEach(record.fields, id: \.name) { field in
                    fieldRow(field: field)
                }
            }
        }
        .navigationTitle(record.type.isEmpty ? "Record" : record.type)
    }

    @ViewBuilder
    private func fieldRow(field: FieldView) -> some View {
        let revealed = viewModel.revealedValue(recordUuidHex: record.uuidHex, fieldName: field.name)
        HStack {
            Text(field.name)
            Spacer()
            if let revealed {
                Text(display(revealed))
                    .textSelection(.enabled)
                    // Defensive / currently unreachable: `hideAll()` runs in the same
                    // didResignActive handler in MacBrowseView, so no revealed value
                    // survives into an inactive render today. Kept belt-and-suspenders
                    // against a future handler reorder.
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
        // RevealPolicy.autoHideSeconds is already a TimeInterval (Double); no numeric
        // cast needed before adding it to a DispatchTime deadline.
        DispatchQueue.main.asyncAfter(deadline: .now() + RevealPolicy.autoHideSeconds) {
            if NSPasteboard.general.changeCount == generation { NSPasteboard.general.clearContents() }
        }
    }
}
