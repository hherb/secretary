import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Identifiable wrapper so `.sheet(item:)` can drive the move-target picker.
/// `sourceBlockUuid` is captured at creation time so the sheet body never needs
/// to re-read the current selection (which may be nil mid-dismiss).
struct MovingRecordItem: Identifiable {
    let id = UUID()
    let record: RecordView
    let sourceBlockUuid: [UInt8]
}

/// Lists the blocks a record can be moved INTO — every block except the source.
/// A row calls `confirmMove`; Cancel calls the injected `onCancel`. macOS analogue
/// of the iOS `MoveTargetPickerSheet`.
@MainActor
struct MacMoveTargetPicker: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    let record: RecordView
    let sourceBlockUuid: [UInt8]
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Text("Move \(record.type.isEmpty ? "record" : record.type)")
                .font(.headline).padding()
            Divider()
            List {
                ForEach(viewModel.blocks.filter { $0.uuid != sourceBlockUuid }, id: \.uuidHex) { block in
                    Button(block.name) { Task { await viewModel.confirmMove(target: block) } }
                }
            }
            if let error = viewModel.error {
                Text(error.localizedDescription)
                    .font(.footnote).foregroundStyle(.red)
                    .padding(.horizontal)
            }
            Divider()
            HStack {
                Button("Cancel", role: .cancel) { onCancel() }
                Spacer()
            }
            .padding()
        }
        .frame(minWidth: 320, minHeight: 320)
    }
}

/// Create / rename a block: one text field + Cancel / Save. Warns (but still
/// allows — #269/#434) when the entered name collides case-insensitively with an
/// existing block; the confirm button relabels "Save" → "Save anyway". Live-
/// reactive: the collision check re-runs every keystroke (a sheet body rebuilds
/// as the binding changes). macOS analogue of the iOS `BlockNameSheet`.
@MainActor
struct MacBlockNameSheet: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    @Binding var name: String
    let title: String

    var body: some View {
        // Evaluate once per render: drives both the warning AND the confirm relabel.
        let collides = viewModel.blockNameCollides(name)
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.headline)
            TextField("Block name", text: $name)
                .textFieldStyle(.roundedBorder)
            if collides {
                Text("A block named \"\(name.trimmingCharacters(in: .whitespacesAndNewlines))\" already exists.")
                    .font(.footnote).foregroundStyle(.red)
            }
            if let error = viewModel.error {
                Text(error.localizedDescription)
                    .font(.footnote).foregroundStyle(.red)
            }
            HStack {
                Button("Cancel", role: .cancel) { viewModel.cancelBlockNameDialog() }
                Spacer()
                Button(collides ? "Save anyway" : "Save") {
                    Task { await viewModel.confirmBlockName(name) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(viewModel.isWriting)
            }
        }
        .padding()
        .frame(minWidth: 380)
    }
}
