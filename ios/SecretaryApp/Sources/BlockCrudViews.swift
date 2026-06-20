import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Identifiable wrapper so `.sheet(item:)` can drive the move-target picker.
struct MovingRecordItem: Identifiable {
    let id = UUID()
    let record: RecordView
}

/// Lists the blocks a record can be moved INTO — every block except the source.
/// Tapping a row calls `confirmMove`; Cancel calls `cancelMove`.
struct MoveTargetPickerSheet: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    let record: RecordView
    let sourceBlockUuid: [UInt8]

    var body: some View {
        NavigationStack {
            List {
                ForEach(viewModel.blocks.filter { $0.uuid != sourceBlockUuid }, id: \.uuidHex) { block in
                    Button(block.name) { viewModel.confirmMove(target: block) }
                        .accessibilityIdentifier("move-target-\(block.uuidHex)")
                }
            }
            .navigationTitle("Move \(record.type.isEmpty ? "record" : record.type)")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { viewModel.cancelMove() }
                        .accessibilityIdentifier("move-cancel")
                }
            }
        }
    }
}
