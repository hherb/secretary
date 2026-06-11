import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Read-only browse: block list → record list → tap-to-reveal field. Redacts
/// revealed values when the app is not active; the parent (RootView) locks the
/// session on background.
struct VaultBrowseScreen: View {
    @StateObject private var viewModel: VaultBrowseViewModel
    @Environment(\.scenePhase) private var scenePhase

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
                        Button(block.name) { viewModel.selectBlock(block) }
                    }
                }
                if let records = viewModel.records {
                    Section("Records") {
                        ForEach(records, id: \.uuidHex) { record in
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
            .onAppear { viewModel.loadBlocks() }
            // Drop any revealed plaintext the moment we leave the foreground.
            .onChange(of: scenePhase) { _, phase in
                if phase != .active { viewModel.hideAll() }
            }
        }
    }

    @ViewBuilder
    private func recordView(_ record: RecordView) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(record.type.isEmpty ? "record" : record.type).font(.headline)
            ForEach(record.fields, id: \.name) { field in
                fieldRow(record: record, field: field)
            }
        }
    }

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
