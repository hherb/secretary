import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Identifiable wrapper so `.sheet(item:)` can drive the move-target picker.
/// `sourceBlockUuid` is captured at item-creation time so the sheet body does
/// not need to read `selectedBlock` at render time (which may be nil on dismiss).
struct MovingRecordItem: Identifiable {
    let id = UUID()
    let record: RecordView
    let sourceBlockUuid: [UInt8]
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
                    Button(block.name) { Task { await viewModel.confirmMove(target: block) } }
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

/// Create/rename a block: one text field + Cancel/Save. Warns (but still allows —
/// #269/#434) when the entered name collides case-insensitively with an existing
/// block; the confirm button relabels "Save" → "Save anyway". Live-reactive by
/// design — a `.sheet` (unlike the UIKit-backed `.alert`) rebuilds as the user
/// types, so the warning and relabel update on every keystroke. The write path is
/// unchanged; a single "Save anyway" tap commits the duplicate.
struct BlockNameSheet: View {
    @ObservedObject var viewModel: VaultBrowseViewModel
    @Binding var name: String
    let title: String
    @FocusState private var nameFocused: Bool

    var body: some View {
        // Evaluate the collision once per render: it drives both the inline warning
        // AND the confirm-button relabel, so hoisting it keeps the two in lockstep
        // (and avoids a redundant O(n) scan of the block list on every keystroke).
        let collides = viewModel.blockNameCollides(name)
        NavigationStack {
            Form {
                TextField("Block name", text: $name)
                    .accessibilityIdentifier("block-name-field")
                    .focused($nameFocused)
                if collides {
                    Text("A block named \"\(name.trimmingCharacters(in: .whitespacesAndNewlines))\" already exists.")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("block-name-warning")
                }
                if let error = viewModel.error {
                    // A full-screen sheet hides the parent list's error section, so
                    // surface a failed write here (the old .alert left it merely behind).
                    Text(String(describing: error))
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { viewModel.cancelBlockNameDialog() }
                        .accessibilityIdentifier("block-name-cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(collides ? "Save anyway" : "Save") {
                        Task { await viewModel.confirmBlockName(name) }
                    }
                    .accessibilityIdentifier("block-name-confirm")
                    .disabled(viewModel.isWriting)
                }
            }
        }
        // Keep the light footprint the old .alert had, while allowing an expand.
        .presentationDetents([.medium, .large])
        // Restore the .alert's tap-and-type immediacy: focus the field on present
        // so the keyboard is up without an extra tap.
        .onAppear { nameFocused = true }
        // A .sheet (unlike a modal .alert) can be swipe-dismissed mid-write; block
        // that while a save is in flight so a dismiss can't race the confirm.
        .interactiveDismissDisabled(viewModel.isWriting)
    }
}
