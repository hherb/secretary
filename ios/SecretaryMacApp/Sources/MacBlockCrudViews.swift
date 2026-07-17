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
